/* channels.inc — 0x000a channels, 0x00b7 set, vapid allocation
 * Part of capagent.c (single translation unit; included in order). */

static void dp_vap_open(struct vap *v);
static void mgmt_vap_add(int ifindex);
static int ext_auth_bind(struct vap *v, const char *dir);
static int vap_netdev_create(int phy, const char *ifname, const uint8_t mac[6]);
static void cap_vap_ready(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t mac[6], const struct cfg *c);
static void vap_destroy(int port, const struct cfg *c);

static uint32_t ccfi80(uint32_t f)
{
    if (f >= 5180 && f <= 5240) return 5210;
    if (f >= 5260 && f <= 5320) return 5290;
    if (f >= 5500 && f <= 5560) return 5530;
    if (f >= 5580 && f <= 5640) return 5610;
    if (f >= 5660 && f <= 5720) return 5690;
    if (f >= 5745 && f <= 5805) return 5775;
    if (f >= 5825 && f <= 5885) return 5855;
    return f;
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The manager keeps one row per (frequency, band, width) and echoes the
   chosen descriptor verbatim in 0x6016.  A profile channel is available
   only when a descriptor with the profile's band and frequency exists in
   the width the profile asks for, so every supported combination is
   emitted.  Widths: 1 = 20, 2 = 40, 3 = 80 MHz; 0x0d is the centre
   frequency and is required for widths > 20 MHz. */
static size_t add_chan_desc(uint8_t *b, size_t n, uint32_t freq,
                            uint8_t width, uint8_t band, uint32_t ccfi)
{
    uint8_t sub[48], f[4], c[4];
    size_t sn = 0;
    put32(f, freq);
    sn += put_el(sub + sn, 0x0b, f, 4);
    sn += put_el(sub + sn, 0x0c, &width, 1);
    if (width > 1) {
        put32(c, ccfi);
        sn += put_el(sub + sn, 0x0d, c, 4);
    }
    sn += put_el(sub + sn, 0x10, &band, 1);
    return n + put_el(b + n, 0x0a, sub, (uint16_t)sn);
}

/* Centre of the 40 MHz block that contains a 20 MHz primary. */
static uint32_t c40_for(uint32_t f)
{
    if (f < 3000) {
        if (f + 10 > 2462) return f - 10;   /* top of the band */
        if (f - 10 < 2412) return f + 10;   /* bottom of the band */
        return ((((f - 2407) / 5) & 1) ? f + 10 : f - 10);
    }
    uint32_t ch = (f - 5000) / 5;
    return (((ch - 36) % 8) < 4) ? f + 10 : f - 10;
}

static size_t add_channel_tlvs(uint8_t *b, size_t n, int phy)
{
    struct phy_bands pb;
    read_phy_bands(phy, &pb);
    for (int i = 0; i < pb.nfreq; i++) {
        uint32_t f = pb.freq[i];
        if (f < 3000) {                                   /* 2.4 GHz */
            n = add_chan_desc(b, n, f, 1, 0x81, f);       /* g  20 */
            n = add_chan_desc(b, n, f, 1, 0x82, f);       /* n  20 */
            if (f >= 2412 && f <= 2472)                   /* n  40 */
                n = add_chan_desc(b, n, f, 2, 0x82, c40_for(f));
        } else if (f < 5925) {                            /* 5 GHz */
            n = add_chan_desc(b, n, f, 1, 0x01, f);       /* a  20 */
            n = add_chan_desc(b, n, f, 1, 0x02, f);       /* n  20 */
            n = add_chan_desc(b, n, f, 1, 0x03, f);       /* ac 20 */
            if (f >= 5180 && f <= 5885) {
                n = add_chan_desc(b, n, f, 2, 0x02, c40_for(f)); /* n 40 */
                n = add_chan_desc(b, n, f, 2, 0x03, c40_for(f)); /* ac 40 */
            }
            if (ccfi80(f) != f)                           /* ac 80 */
                n = add_chan_desc(b, n, f, 3, 0x03, ccfi80(f));
        } else {                                          /* 6 GHz */
            n = add_chan_desc(b, n, f, 1, 0x06, f);
        }
    }
    return n;
}

/* Per-radio vapid allocation: the manager never tells the CAP which vapid to
   use, it only sends the (virtual) MAC in TLV 0x08.  We must return a unique
   0..15 per interface and keep it stable for the same MAC, otherwise the
   manager rejects the reply as a duplicate ("CREATEVAP bad response") and the
   virtual user stays in CreatingVap forever.

   W25/W28/W52: the slot is a real resource.  It is released on 0x600c only
   after the netdev is gone, and allocation never falls back to slot 0 (the
   old bug that wedged the second create cycle).  16/16 taken returns -1 and
   the caller sends no 0xd00b, so the manager retries instead of accepting a
   duplicate id.  A total cap is a second line of defence against a manager
   that keeps creating BSSes without ever destroying them. */
#define VAP_TOTAL_MAX 64

static int vap_total_limit(void)
{
    const char *s = getenv("CAPAGENT_MAX_VAPS");
    long v = s ? strtol(s, NULL, 0) : 0;
    if (v >= 1 && v <= MAX_RADIOS * 16) return (int)v;
    return VAP_TOTAL_MAX;
}

static int vap_total_live(void)
{
    int n = 0;
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_vap[r][w].used) n++;
    return n;
}

static struct { int used; uint8_t mac[6]; } g_vmap[MAX_RADIOS][16];

static int vapid_lookup(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            return i;
    return -1;
}

static void vapid_claim(int phy, int vapid, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    if (vapid < 0 || vapid > 15) return;
    g_vmap[r][vapid].used = 1;
    memcpy(g_vmap[r][vapid].mac, mac, 6);
}

/* A slot is free only when no allocation and no (possibly not-yet-journaled)
   VAP registry row owns it.  Returns -1 when all 16 slots are taken. */
static int vapid_for(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    int id = vapid_lookup(phy, mac);
    if (id >= 0) return id;
    /* A registry row may exist without a g_vmap allocation (reconnect or a
       create whose reply was lost): the MAC still owns that id. */
    for (int i = 0; i < 16; i++)
        if (g_vap[r][i].used && !memcmp(g_vap[r][i].bssid, mac, 6)) {
            vapid_claim(phy, i, mac);
            return i;
        }
    for (int i = 0; i < 16; i++)
        if (!g_vmap[r][i].used && !g_vap[r][i].used) {
            vapid_claim(phy, i, mac);
            return i;
        }
    return -1;
}

static void vapid_release(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            memset(&g_vmap[r][i], 0, sizeof(g_vmap[r][i]));
}

/* The 0x600c path releases by id: after a reconnect the registry may have
   been cleared, so the MAC is not always available. */
static void vapid_release_slot(int phy, int vapid)
{
    int r = phy % MAX_RADIOS;
    if (vapid >= 0 && vapid < 16)
        memset(&g_vmap[r][vapid], 0, sizeof(g_vmap[r][vapid]));
}

/* First 0x0A record of a create-vap request, as {freq,width,band}. */
static int req_channel(const uint8_t *req, uint16_t reqlen,
                       uint32_t *freq, uint8_t *width, uint8_t *band)
{
    const uint8_t *ch = NULL; uint16_t cl = 0;
    if (!find_el(req, reqlen, 0x0a, &ch, &cl) || cl < 4) return 0;
    const uint8_t *v = NULL; uint16_t l = 0;
    if (find_el(ch, cl, 0x0b, &v, &l) && l == 4) *freq = rd32(v);
    if (find_el(ch, cl, 0x0c, &v, &l) && l == 1) *width = v[0];
    if (find_el(ch, cl, 0x10, &v, &l) && l == 1) *band = v[0];
    return *freq >= 2000 && *freq <= 7125;
}

/* W33: drop only the allocations whose netdev is really gone.  After a
 * manager reconnect the same MACs come back and must keep their vapid
 * (and therefore the phy<N>-ap<M> name and the 0xd00b ifindex); a freed
 * slot is what the next create needs. */
static void vapid_gc(void)
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int i = 0; i < 16; i++)
            if (g_vmap[r][i].used &&
                ifindex_by_mac_ap(g_vmap[r][i].mac, r, NULL, 0) <= 0)
                g_vmap[r][i].used = 0;
}

static void createvap_response(mbedtls_ssl_context *ssl, const uint8_t hdr[10],
                               int phy, int vap, const struct cfg *c,
                               const uint8_t *req, uint16_t reqlen)
{
    uint8_t body[BODY_MAX], v[4], mac[6] = {0};
    char ifname[32];
    size_t n = 0;
    uint32_t curfreq = 0;
    /* The manager identifies each interface only by the MAC in 0x08. */
    const uint8_t *rm = NULL; uint16_t rml = 0;
    int have_mac = find_el(req, reqlen, 0x08, &rm, &rml) && rml == 6;
    if (have_mac)
        memcpy(mac, rm, 6);
    else if (phy < c->nradios)
        memcpy(mac, c->macs[phy], 6);
    /* W25/W52: allocate or rebind the slot before touching any resource.  A
       duplicate create for a live MAC is idempotent; a stale mapping is torn
       down first.  If the radio has no free id we send no reply at all. */
    int vapid = vapid_lookup(phy, mac);
    struct vap *vp = NULL;
    if (vapid >= 0) {
        vp = &g_vap[phy % MAX_RADIOS][vapid];
        if (!vp->used || memcmp(vp->bssid, mac, 6) != 0) {
            if (vp->used)
                vap_destroy((phy << 8) | vapid, c);
            else
                vapid_release_slot(phy, vapid);
            vapid = -1;
            vp = NULL;
        }
    }
    if (vapid < 0) {
        if (vap_total_live() >= vap_total_limit()) {
            fprintf(stderr, "vap: total VAP cap %d reached; refusing create "
                    "phy=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    vap_total_limit(), phy, mac[0], mac[1], mac[2], mac[3],
                    mac[4], mac[5]);
            fflush(stderr);
            return;
        }
        vapid = vapid_for(phy, mac);
        if (vapid < 0) {
            fprintf(stderr, "vap: no free vapid on phy%d; refusing create "
                    "mac=%02x:%02x:%02x:%02x:%02x:%02x\n", phy, mac[0],
                    mac[1], mac[2], mac[3], mac[4], mac[5]);
            fflush(stderr);
            return;
        }
        vp = &g_vap[phy % MAX_RADIOS][vapid];
        if (vp->used) {
            /* g_vmap and g_vap disagreed: clean the old owner first. */
            vap_destroy((phy << 8) | vapid, c);
            vapid_claim(phy, vapid, mac);
        }
    }
    if (!vp) return;
    {   /* remember which vapid owns this VLAN (needed for a2=1 keys) */
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vlan_wid_set(phy, rd16(vv), vapid);
    }
    char pref[32];
    snprintf(pref, sizeof(pref), "phy%d-ap%d", phy, vapid);
    /* W34: one ownership decision for 0x500b and 0x6016.  netifd wins its
     * names; the manager VAP moves to cap<phy>-<vapid> instead. */
    const char *preferred = NULL;
    if (vapid == 0 && phy < MAX_RADIOS && c->ifnames[phy][0] &&
        strcmp(c->ifnames[phy], pref) != 0)
        preferred = c->ifnames[phy];
    int managed = 0;
    int ifindex = 0;
    own_claim(c, phy, vapid, preferred, mac, ifname, sizeof(ifname),
              &ifindex, &managed);
    if (ifindex < 0)
        ifindex = 0;
    if (!ifname[0])
        snprintf(ifname, sizeof(ifname), "%s", pref);
    if (ifindex <= 0)
        printf("vap: phy=%d vapid=%d has no netdev and no name is available "
               "(owned=%d)\n", phy, vapid, managed);

    /* P0: bind the VAP to its netdev, VLAN and channel. */
    {
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (!vp->used) {
            memset(vp, 0, sizeof(*vp));
            vp->l2fd = -1;
            vp->extfd = -1;
        }
        vp->used = 1;
        vp->rid = phy;
        vp->wid = vapid;
        vp->vlan = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vp->vlan = rd16(vv);
        vp->freq = 0;
        {   /* The request's own 0x0A is authoritative (T13).  Never read a
               different VAP's slot: on this manager every 0x500b for a radio
               carries port=(phy<<8)|0, so the canonical slot is the only one
               that belongs to the VAP being created. */
            uint32_t rf = 0; uint8_t rw = 0, rb = 0;
            if (req_channel(req, reqlen, &rf, &rw, &rb))
                vp->freq = rf;
        }
        if (!vp->freq) {
            uint32_t vf = 0;
            if (vchan_get((phy << 8) | vapid, &vf, NULL, NULL) && vf)
                vp->freq = vf;
        }
        if (!vp->freq) {
            /* Never invent 2437/5180 for a netdev that already exists: its
               own channel is the only value hostapd can adopt. */
            unsigned f = 0, w = 0;
            if (ifindex > 0) iface_chan(ifname, &f, &w);
            vp->freq = f;
        }
        if (!vp->freq) vp->freq = phy_freq_hint(phy);
        if (!vp->freq) vp->freq = (phy & 1) ? 5180u : 2437u;
        curfreq = vp->freq;
        memcpy(vp->bssid, mac, 6);
        vp->ifindex = ifindex;
        if (vp->ifname[0] && strcmp(vp->ifname, ifname)) {
            if (vp->extfd >= 0) { close(vp->extfd); vp->extfd = -1; }
        }
        snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);
        vp->mode = 0;                   /* ACCESS (default) */
        vp->napvlan = 0;
        if (managed && own_created_port((phy << 8) | vapid)) {
            vp->we_created = 1;
            vp->own_netdev = 1;
        }
        vchan_set((phy << 8) | vapid, vp->freq, 1,
                  band_code_for_freq(vp->freq));
        /* The manager sends vapid=0 in every 0x500b, so only alias the
           request port when it really is this VAP; otherwise VAP0's slot
           would be overwritten by every later create. */
        if (vap_port_alias_ok(vap, vapid))
            vchan_set((phy << 8) | vap, vp->freq, 1,
                      band_code_for_freq(vp->freq));
        printf("vap: rid=%d wid=%d vlan=%u freq=%u bssid=%02x:%02x:%02x:%02x:"
               "%02x:%02x ifindex=%d ifname=%s\n", phy, vapid, vp->vlan,
               vp->freq, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               ifindex, ifname);
        fflush(stdout);
        if (managed && c->datapath_bridge) dp_vap_open(vp);
        if (managed && (c->mgmt_relay || c->mgmt_source))
            mgmt_vap_add(ifindex);
        cap_vap_ready(phy, vapid, ifindex, ifname, mac, c);
    }

    if (c->no_ack) {
        /* A genuine CAP sends nothing when the data channel is created OK;
           0xD00B is only the failure path. */
        if (ifindex > 0) {
            pmap_set(phy << 8 | vapid, ifindex, mac);
            if (vap_port_alias_ok(vap, vapid))
                pmap_set(phy << 8 | vap, ifindex, mac);
        }
        printf("0xd00b phy=%d ifname=%s (no-ack: success reply suppressed)\n",
               phy, ifname);
        fflush(stdout);
        return;
    }
    if (ifindex > 0) {
        pmap_set(phy << 8 | vapid, ifindex, mac);
        if (vap_port_alias_ok(vap, vapid))
            pmap_set(phy << 8 | vap, ifindex, mac);
    }

    n += put_el(body+n, 0x08, mac, 6);
    put32(v, (uint32_t)vapid);
    n += put_el(body+n, 0x47, v, 4);
    put32(v, (uint32_t)ifindex);
    n += put_el(body+n, 0x48, v, 4);
    /* 0x49 is the raw interface name.  The manager stores the whole payload
       verbatim as the VAP's name (W1); a nested 0x9e blob becomes garbage. */
    n += put_el(body+n, 0x49, ifname, (uint16_t)strlen(ifname));

    /* Advertise this radio's channels so the stock manager can run chansel. */
    size_t nb = n;
    n = add_channel_tlvs(body, n, phy);   /* returns the absolute offset */
    size_t nc = n;

    /* 0x0061 = current operating frequency (BE32).  The manager stores it in
       phy+0x30 and sets "current freq known" (phy+0x34), which chansel uses. */
    {
        uint8_t cf[4];
        uint32_t hf = curfreq;
        if (hf) {
            put32(cf, hf);
            n += put_el(body + n, 0x61, cf, 4);
        }
    }
    size_t n61 = n;

    /* 0x00B7 = u32 key set used by ActAp::chansel (actman+0x220).  Send the
       same frequency list as BE32 values. */
    {
        struct phy_bands pb;
        uint8_t list[PHY_MAX_FREQ * 4];
        read_phy_bands(phy, &pb);
        for (int i = 0; i < pb.nfreq; i++) {
            uint32_t ch = (pb.freq[i] - chan_base_for_freq(pb.freq[i])) / 5;
            put32(list + i * 4, ch);
        }
        n += put_el(body + n, 0xb7, list, (uint16_t)(pb.nfreq * 4));
    }

    if (getenv("CAPAGENT_DEBUG"))
        printf("d00b build base=%zu chan=%zu(delta=%zu) c61=%zu b7=%zu\n",
               nb, nc, nc - nb, n61, n);

    {   /* dump the exact reply body for offline verification */
        char dp[64];
        snprintf(dp, sizeof(dp), "/tmp/capagent-d00b-%d.bin", phy);
        int dfd = getenv("CAPAGENT_DEBUG")
                  ? open(dp, O_CREAT | O_WRONLY | O_TRUNC, 0600) : -1;
        FILE *df = dfd >= 0 ? fdopen(dfd, "wb") : NULL;
        if (df) { fwrite(body, 1, n, df); fclose(df); }
    }

    uint8_t pkt[BODY_MAX + 16];
    size_t pn = put_msg(pkt, TYPE_CREATEVAP_RESP, 0, body, (uint16_t)n);
    memcpy(pkt + 2, hdr, 10);   /* same 10-byte header/sequence */
    (void)pn;
    /* send manually with the custom header */
    uint16_t len = (uint16_t)n;
    uint8_t out[BODY_MAX + 16];
    put16(out, TYPE_CREATEVAP_RESP);
    memcpy(out + 2, hdr, 10);
    put16(out + 12, len);
    memcpy(out + 14, body, len);
    size_t total = 14 + len, off = 0;
    while (off < total) {
        int r = mbedtls_ssl_write(ssl, out + off, total - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) break;
        off += r;
    }
    printf("0xd00b phy=%d vapid=%d ifindex=%d ifname=%s\n", phy, vapid, ifindex, ifname);
    fflush(stdout);
}

static void send_hdr_msg(mbedtls_ssl_context *ssl, uint16_t type,
                         const uint8_t hdr[10], const uint8_t *body, uint16_t len)
{
    uint8_t out[BODY_MAX + 16];
    put16(out, type);
    memcpy(out + 2, hdr, 10);
    put16(out + 12, len);
    if (len && body) memcpy(out + 14, body, len);
    size_t total = 14 + len, off = 0;
    while (off < total) {
        int r = mbedtls_ssl_write(ssl, out + off, total - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) break;
        off += r;
    }
}

/* ---- 0x201C / 0x201B: EAPOL relay ------------------------------- */

/* The control port ABI wants a bare EAPOL frame (EAPOL header first).
   Some builds/drivers hand us 802.3 or 802.11 framing; strip it. */
