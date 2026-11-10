/* channels.inc — 0x000a channels, 0x00b7 set, vapid allocation
 * Part of capagent.c (single translation unit; included in order). */

static void dp_vap_open(struct vap *v);
static void mgmt_vap_add(int ifindex);
static int ext_auth_bind(struct vap *v, const char *dir);
static int vap_netdev_create(int phy, const char *ifname, const uint8_t mac[6]);
static void cap_vap_ready(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t mac[6], const struct cfg *c);

static uint32_t ccfi80(uint32_t f)
{
    if (f >= 5180 && f <= 5240) return 5210;
    if (f >= 5260 && f <= 5320) return 5290;
    if (f >= 5500 && f <= 5560) return 5530;
    if (f >= 5580 && f <= 5640) return 5610;
    if (f >= 5660 && f <= 5720) return 5690;
    if (f >= 5745 && f <= 5805) return 5775;
    if (f >= 5825 && f <= 5865) return 5855;
    return f;
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The manager's ActManBase::updateHwChans() rebuilds phy+0x20 (+0x28 row ids)
   from these.  2.4 GHz: 20 MHz, band 0x81 (2ghz-g).  5 GHz: 80 MHz (width 3)
   with ccfi1, band 0x03 (5ghz-ac), because the 5 GHz configs use 20/40/80. */
static size_t add_channel_tlvs(uint8_t *b, size_t n, int phy)
{
    struct phy_bands pb;
    read_phy_bands(phy, &pb);
    for (int i = 0; i < pb.nfreq; i++) {
        uint8_t sub[48], f[4], c[4];
        size_t sn = 0;
        uint8_t width = (pb.freq[i] < 3000) ? 1 : 3;
        uint8_t band = band_code_for_freq(pb.freq[i]);
        put32(f, pb.freq[i]);
        sn += put_el(sub + sn, 0x0b, f, 4);
        sn += put_el(sub + sn, 0x0c, &width, 1);
        if (width > 1) {
            put32(c, ccfi80(pb.freq[i]));
            sn += put_el(sub + sn, 0x0d, c, 4);
        }
        sn += put_el(sub + sn, 0x10, &band, 1);
        n += put_el(b + n, 0x0a, sub, (uint16_t)sn);
    }
    return n;
}

/* Per-radio vapid allocation: the manager never tells the CAP which vapid to
   use, it only sends the (virtual) MAC in TLV 0x08.  We must return a unique
   0..15 per interface and keep it stable for the same MAC, otherwise the
   manager rejects the reply as a duplicate ("CREATEVAP bad response") and the
   virtual user stays in CreatingVap forever. */
static struct { int used; uint8_t mac[6]; } g_vmap[MAX_RADIOS][16];

static int vapid_for(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            return i;
    for (int i = 0; i < 16; i++)
        if (!g_vmap[r][i].used) {
            g_vmap[r][i].used = 1;
            memcpy(g_vmap[r][i].mac, mac, 6);
            return i;
        }
    return 0;
}

static void vapid_release(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            g_vmap[r][i].used = 0;
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
    char ifname[32], macname[32] = "";
    size_t n = 0;
    uint32_t curfreq = 0;
    /* The manager identifies each interface only by the MAC in 0x08. */
    const uint8_t *rm = NULL; uint16_t rml = 0;
    int have_mac = find_el(req, reqlen, 0x08, &rm, &rml) && rml == 6;
    if (have_mac)
        memcpy(mac, rm, 6);
    else if (phy < c->nradios)
        memcpy(mac, c->macs[phy], 6);
    int vapid = vapid_for(phy, mac);
    {   /* remember which vapid owns this VLAN (needed for a2=1 keys) */
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vlan_wid_set(phy, rd16(vv), vapid);
    }
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    int ifindex = have_mac
                  ? ifindex_by_mac_ap(mac, phy, macname,
                                      sizeof(macname))
                  : 0;
    if (ifindex <= 0) {
        ifindex = read_sysfs_int(ifname, "ifindex");
        if (ifindex > 0) {
            int t = nl_get_iftype(ifindex);
            if (t != NL80211_IFTYPE_AP && t != NL80211_IFTYPE_AP_VLAN) {
                /* a monitor VIF called phyN-apM is not a BSS */
                ifindex = 0;
            }
        }
        snprintf(macname, sizeof(macname), "%s", ifname);
    } else if (macname[0]) {
        snprintf(ifname, sizeof(ifname), "%s", macname);
    }
    /* U3/W36: an explicit -i name for the master is authoritative.  This is
       also how a CAP avoids colliding with another radio's phyX-apY netdev
       name (device names are global). */
    if (vapid == 0 && phy < MAX_RADIOS && c->ifnames[phy][0]) {
        char conventional[32];
        snprintf(conventional, sizeof(conventional), "phy%d-ap%d", phy, vapid);
        if (strcmp(c->ifnames[phy], conventional) != 0) {
            snprintf(ifname, sizeof(ifname), "%s", c->ifnames[phy]);
            ifindex = read_sysfs_int(ifname, "ifindex");
            if (ifindex > 0) snprintf(macname, sizeof(macname), "%s", ifname);
        }
    }
    if (ifindex <= 0 && vapid == 0 && phy < MAX_RADIOS && c->ifnames[phy][0]) {
        snprintf(ifname, sizeof(ifname), "%s", c->ifnames[phy]);
        ifindex = read_sysfs_int(ifname, "ifindex");
    }

    /* W14: the manager treats the reply's ifindex as authoritative, so an
       existing netdev must be found before 0xd00b is sent.  W33: only
       capagent may create one, and only when no legacy UCI owns the radios.
       In legacy mode a missing netdev is reported as ifindex 0; we never
       create a second BSS behind netifd's back. */
    int created = 0;
    if (ifindex <= 0 && ifname[0] && wl_own()) {
        ifindex = vap_netdev_create(phy, ifname, mac);
        created = ifindex > 0;
    }
    if (ifindex <= 0 && wl_legacy()) {
        printf("vap: phy=%d vapid=%d mac=%02x:%02x:%02x:%02x:%02x:%02x has no "
               "netdev; legacy UCI owns the radios, not creating\n",
               phy, vapid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        fflush(stdout);
    }

    /* P0: bind the VAP to its netdev, VLAN and channel. */
    {
        struct vap *vp = &g_vap[phy % MAX_RADIOS][vapid & 0x0f];
        const uint8_t *vv = NULL; uint16_t vl = 0;
        vp->used = 1;
        vp->rid = phy;
        vp->wid = vapid;
        vp->vlan = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vp->vlan = rd16(vv);
        vp->freq = 0;
        {   /* 0x0a channel container is authoritative (T13).  W33: read the
               canonical port, not the (always 0) request vapid alias. */
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
        if (created) vp->we_created = 1;
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
        if (c->datapath_bridge) dp_vap_open(vp);
        if (c->mgmt_relay || c->mgmt_source) mgmt_vap_add(ifindex);
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
    /* 0x49 is a nested submessage; the manager reads the interface name
       from its 0x9e element and ignores a raw string here. */
    uint8_t sub[64];
    size_t sn = put_el(sub, 0x9e, ifname, (uint16_t)strlen(ifname));
    n += put_el(body+n, 0x49, sub, (uint16_t)sn);

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
