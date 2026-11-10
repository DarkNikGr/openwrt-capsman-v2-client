/* channels.inc — 0x000a channels, 0x00b7 set, vapid allocation
 * Part of capagent.c (single translation unit; included in order). */

static void dp_vap_open(struct vap *v);
static void mgmt_vap_add(int ifindex);
static int ext_auth_bind(struct vap *v, const char *dir);
static int vap_netdev_create(int phy, const char *ifname, const uint8_t mac[6]);
static void cap_vap_ready(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t mac[6], const struct cfg *c);
/* W25 lifecycle, defined in vap.inc (included after this file). */
static void vap_destroy(int phy, int vapid, const char *why);
static void vap_watchdog(const struct cfg *c);
static int wireless_has_bss(void);

/* The name space capagent owns.  A legacy UCI BSS with the same name is
   still possible, so callers pair this with wireless_has_bss(). */
static int vap_ifname_is_ours(const char *name)
{
    int phy = -1, id = -1;
    char tail;
    if (sscanf(name, "phy%d-ap%d%c", &phy, &id, &tail) != 2) return 0;
    return phy >= 0 && phy < MAX_RADIOS && id >= 0 && id <= 15;
}

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

/* Manager band ids (ww2 ActAp::chansel / ActManBase band table).  A profile
   whose (band,width) pair is absent from the advertised list has NO candidate
   channel, so the manager reports "no available channels" and never starts
   the BSS.  One band per frequency is therefore not enough. */
#define BAND_24_G   0x81
#define BAND_24_N   0x82
#define BAND_24_AX  0x83    /* not universally known: never advertised */
#define BAND_5_A    0x01
#define BAND_5_N    0x02
#define BAND_5_AC   0x03
#define BAND_5_AX   0x04

static uint32_t ccfi_for(uint32_t f, uint8_t width)
{
    uint32_t base = chan_base_for_freq(f), ch = (f - base) / 5;
    if (width == 2) {                     /* 40 MHz: +/- 10 MHz */
        if (ch >= 2) return f - 10;
        return f + 10;
    }
    if (width == 3) return ccfi80(f);     /* 80 MHz */
    return f;
}

/* Only advertise widths that physically exist at this frequency. */
static int width_ok(uint32_t f, uint8_t width)
{
    uint32_t base = chan_base_for_freq(f), ch = (f - base) / 5;
    if (width == 1) return 1;
    if (width == 2) return ch >= 2 || f < 3000;
    if (width == 3) {
        if (f < 3000) return 0;
        return ccfi80(f) != f;
    }
    return 0;                             /* 160 MHz: not advertised */
}

static int band_matches_freq(uint8_t band, uint32_t f)
{
    switch (band) {
    case BAND_24_G: case BAND_24_N: case BAND_24_AX: return f < 3000;
    case BAND_5_A: case BAND_5_N: case BAND_5_AC: case BAND_5_AX:
        return f >= 4900 && f < 5925;
    default: return 0;                    /* 6 GHz ids are not verified */
    }
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The manager's TLV handler (x86 0x8069581) parses each 0x0A into a 28-byte
   record {+0=0x0B MHz, +4=0x0C width, +8=0x0D ccfi, +0x14=0x10 band} with
   exact length checks, then ActAp::chansel matches (freq,width,band) against
   the profile and copies the winning record into the 0x6016 it sends back.

   Each 0xD00B reply REPLACES the whole per-phy channel list, so one record per
   profile combination is required: every frequency is advertised once per
   supported band and per supported width, 20 MHz first (cheapest coverage),
   then 40, then 80.  The list is capped so the reply always stays parseable. */
#define D00B_CHAN_BUDGET (BODY_MAX - 272)

/* Live A/B knob: CAPAGENT_D00B_CHAN_LIMIT=<bytes> shrinks the advertised list
   without a rebuild (some manager builds may cap the message size). */
static size_t d00b_chan_budget(void)
{
    const char *s = getenv("CAPAGENT_D00B_CHAN_LIMIT");
    long v = s ? strtol(s, NULL, 0) : 0;
    if (v >= 64 && v < (long)D00B_CHAN_BUDGET) return (size_t)v;
    return D00B_CHAN_BUDGET;
}

/* Optional extra band ids for the live A/B, e.g.
   CAPAGENT_D00B_EXTRA_BANDS=0x02,0x04 (5ghz-n, 5ghz-ax).  Unverified ids are
   never sent by default; advertise them only when the manager profile really
   uses that band. */
static int d00b_extra_bands(uint8_t *out, int max)
{
    const char *s = getenv("CAPAGENT_D00B_EXTRA_BANDS");
    int n = 0;
    if (!s) return 0;
    while (*s && n < max) {
        char *end = NULL;
        long v = strtol(s, &end, 0);
        if (end == s) { s++; continue; }
        if (v > 0 && v < 256) out[n++] = (uint8_t)v;
        s = end;
    }
    return n;
}

static size_t add_channel_tlvs(uint8_t *b, size_t n, int phy)
{
    struct phy_bands pb;
    uint8_t bands[10];
    int nband = 0;
    size_t budget = d00b_chan_budget();
    read_phy_bands(phy, &pb);
    for (int i = 0; i < pb.nband && nband < 8; i++)
        bands[nband++] = pb.band[i];
    {
        uint8_t extra[4];
        int ne = d00b_extra_bands(extra, 4);
        for (int i = 0; i < ne && nband < 10; i++) {
            int dup = 0;
            for (int j = 0; j < nband; j++)
                if (bands[j] == extra[i]) dup = 1;
            if (!dup) bands[nband++] = extra[i];
        }
    }
    /* 20 MHz first, then 80 MHz, then 40: every band must get its 20 and
       80 MHz records before any band gets 40, otherwise a truncated list can
       leave e.g. 5ghz-ac/80MHz with no candidate at all. */
    static const uint8_t widths[] = {1, 3, 2};
    for (unsigned wi = 0; wi < sizeof(widths); wi++) {
        uint8_t width = widths[wi];
        for (int bi = 0; bi < nband; bi++) {
            uint8_t band = bands[bi];
            for (int i = 0; i < pb.nfreq; i++) {
                uint32_t f = pb.freq[i];
                if (!band_matches_freq(band, f)) continue;
                if (!width_ok(f, width)) continue;
                if (n + 32 > budget) return n;
                uint8_t sub[24], v[4];
                size_t sn = 0;
                put32(v, f);
                sn += put_el(sub + sn, 0x0b, v, 4);
                sn += put_el(sub + sn, 0x0c, &width, 1);
                if (width > 1) {
                    put32(v, ccfi_for(f, width));
                    sn += put_el(sub + sn, 0x0d, v, 4);
                }
                sn += put_el(sub + sn, 0x10, &band, 1);
                n += put_el(b + n, 0x0a, sub, (uint16_t)sn);
            }
        }
    }
    return n;
}

/* 0x00B7 u32 list.  The manager keeps a per-phy "allowed channel" set
   (phy+0x220, ww2 0x806970a -> 0x805ffa8) and ActAp::chansel tests every
   candidate channel-record against it (0x80779ac); a candidate that is not in
   the set is marked used and silently skipped, which ends in "no available
   channels" and no 0x6016.  The key is the record's first u32, i.e. the MHz
   value (0x8077904 inserts a parsed 0x0A record's freq into the same set), but
   the live 7.25.1 run also accepted a channel-number list.  Sending the union
   of both forms satisfies either reading; extra members are harmless. */
static size_t add_b7_tlv(uint8_t *b, size_t n, int phy)
{
    struct phy_bands pb;
    uint8_t list[256];
    size_t ln = 0;
    read_phy_bands(phy, &pb);
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < pb.nfreq; i++) {
            uint32_t v = pass ? (pb.freq[i] - chan_base_for_freq(pb.freq[i])) / 5
                              : pb.freq[i];
            int dup = 0;
            for (size_t k = 0; k + 4 <= ln; k += 4)
                if (rd32(list + k) == v) { dup = 1; break; }
            if (dup || ln + 4 > sizeof(list)) continue;
            put32(list + ln, v);
            ln += 4;
        }
    }
    return n + put_el(b + n, 0xb7, list, (uint16_t)ln);
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

/* Per-radio vapid allocation: the manager never tells the CAP which vapid to
   use, it only sends the (virtual) MAC in TLV 0x08.  We must return a unique
   0..15 per interface and keep it stable for the same MAC, otherwise the
   manager rejects the reply as a duplicate ("CREATEVAP bad response") and the
   virtual user stays in CreatingVap forever.

   W25: the slot is a real resource and is released on 0x600c.  The total cap
   is a second line of defence against a manager that keeps creating VAPs
   without destroying them. */
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

/* Returns -1 when all 16 slots on the radio are taken.  Callers must treat
   that as "no reply" rather than silently reusing slot 0 (the old bug). */
static int vapid_for(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    int id = vapid_lookup(phy, mac);
    if (id >= 0) return id;
    for (int i = 0; i < 16; i++)
        if (!g_vmap[r][i].used) {
            vapid_claim(phy, i, mac);
            return i;
        }
    return -1;
}

__attribute__((unused))
static void vapid_release(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            memset(&g_vmap[r][i], 0, sizeof(g_vmap[r][i]));
}

static void vapid_release_slot(int phy, int vapid)
{
    int r = phy % MAX_RADIOS;
    if (vapid >= 0 && vapid < 16)
        memset(&g_vmap[r][vapid], 0, sizeof(g_vmap[r][vapid]));
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
    /* W25: allocate or rebind the slot before touching any resource.  A
       duplicate create for a live MAC is idempotent; a stale mapping is torn
       down first, so a recreate always starts from a clean slate. */
    int vapid = vapid_lookup(phy, mac);
    struct vap *vp = NULL;
    if (vapid >= 0) {
        vp = &g_vap[phy % MAX_RADIOS][vapid];
        if (!vp->used || memcmp(vp->bssid, mac, 6) != 0) {
            if (vp->used)
                vap_destroy(phy, vapid, "stale-id");
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
            vap_destroy(phy, vapid, "orphan-id");
            vapid_claim(phy, vapid, mac);
        }
    }
    if (!vp) return;
    {   /* remember which vapid owns this VLAN (needed for a2=1 keys) */
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vlan_wid_set(phy, rd16(vv), vapid);
    }
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    int ifindex = have_mac ? ifindex_by_mac(mac, macname, sizeof(macname)) : 0;
    if (ifindex <= 0) {
        ifindex = read_sysfs_int(ifname, "ifindex");
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

    /* W14: the manager treats the reply's ifindex as authoritative, so the
       netdev must exist before 0xd00b is sent. */
    int netdev_existed = if_nametoindex(ifname) > 0;
    int netdev_created = 0;
    if (ifindex <= 0 && ifname[0]) {
        ifindex = vap_netdev_create(phy, ifname, mac);
        if (ifindex > 0 && !netdev_existed)
            netdev_created = 1;         /* we must delete it on 0x600c */
    }
    /* Adopt a phyN-apM left by an earlier capagent run (same naming space)
       unless a legacy UCI BSS owns it.  Without this a crash would leak the
       netdev forever because own_netdev would stay 0. */
    int netdev_adopt = ifindex > 0 && vap_ifname_is_ours(ifname) &&
                       !wireless_has_bss();

    /* P0: bind the VAP to its netdev, VLAN and channel. */
    {
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (!vp->used) {
            memset(vp, 0, sizeof(*vp));
            vp->l2fd = -1;
            vp->extfd = -1;
        }
        if (netdev_created || netdev_adopt)
            vp->own_netdev = 1;
        vp->used = 1;
        vp->rid = phy;
        vp->wid = vapid;
        vp->vlan = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vp->vlan = rd16(vv);
        vp->freq = 0;
        /* The request's own 0x0A is authoritative (T13).  Never fall back to
           a different VAP's channel: on this manager every create request for
           a radio carries port=(phy<<8)|0, so vchan_get((phy<<8)|vap) would
           return the master's channel for a slave. */
        uint32_t rf = 0; uint8_t rw = 0, rb = 0;
        if (req_channel(req, reqlen, &rf, &rw, &rb))
            vp->freq = rf;
        if (!vp->freq) vp->freq = phy_freq_hint(phy);
        if (!vp->freq) vp->freq = (phy & 1) ? 5180u : 2437u;
        if (vp->freq < 2000 || vp->freq > 7125) vp->freq = phy_freq_hint(phy);
        curfreq = vp->freq;
        memcpy(vp->bssid, mac, 6);
        vp->ifindex = ifindex;
        snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);
        vp->mode = 0;                   /* ACCESS (default) */
        vchan_set((phy << 8) | vapid, vp->freq, 1,
                  band_code_for_freq(vp->freq));
        /* Only mirror the create port's key when it really is this VAP,
           otherwise every slave create would overwrite VAP 0's entry. */
        if (vap == vapid)
            vchan_set((phy << 8) | vap, vp->freq, 1,
                      band_code_for_freq(vp->freq));
        printf("vap: rid=%d wid=%d vlan=%u freq=%u bssid=%02x:%02x:%02x:%02x:"
               "%02x:%02x ifindex=%d ifname=%s hostapd=%d own=%d\n",
               phy, vapid, vp->vlan, vp->freq, mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5], ifindex, ifname,
               vp->hostapd_started, vp->own_netdev);
        fflush(stdout);
        if (c->datapath_bridge) dp_vap_open(vp);
        if (c->mgmt_relay || c->mgmt_source) mgmt_vap_add(ifindex);
        cap_vap_ready(phy, vapid, ifindex, ifname, mac, c);
    }

    if (c->no_ack) {
        /* A genuine CAP sends nothing when the data channel is created OK;
           0xD00B is only the failure path. */
        if (ifindex > 0) {
            if (vap == vapid) pmap_set(phy << 8 | vap, ifindex, mac);
            pmap_set(phy << 8 | vapid, ifindex, mac);
        }
        printf("0xd00b phy=%d ifname=%s (no-ack: success reply suppressed)\n",
               phy, ifname);
        fflush(stdout);
        return;
    }
    if (ifindex > 0) {
        if (vap == vapid) pmap_set(phy << 8 | vap, ifindex, mac);
        pmap_set(phy << 8 | vapid, ifindex, mac);
    }

    /* Body, in the order the manager's Provider::receive (x86 0x8059ae4)
       reads it.  Tag order is irrelevant to the parser, but keep the genuine
       CAP's order: 0x08, 0x47, 0x48, 0x49, [0x9E], 0x0A*, 0x61, 0xB7.
       0x08  MAC            len must be exactly 6, else the manager zero-fills
       0x47  vap id         u32, must be <= 15 AND its slot must be free
       0x48  ifindex        u32, stored only if the phy answers "has ifname"
       0x49  ifname         RAW string (the whole payload becomes the name)
       0x9e  mldlink id     optional top-level u8 (NOT nested inside 0x49) */
    n += put_el(body+n, 0x08, mac, 6);
    put32(v, (uint32_t)vapid);
    n += put_el(body+n, 0x47, v, 4);
    put32(v, (uint32_t)ifindex);
    n += put_el(body+n, 0x48, v, 4);
    n += put_el(body+n, 0x49, ifname, (uint16_t)strlen(ifname));

    /* 0xA2 = "interface enabled" (RemoteMan stores it at Vap+0x18).  Optional:
       the live 7.25.1 run created 8/8 VAPs without it, so it can be turned off
       for an A/B with CAPAGENT_D00B_A2=0. */
    {
        const char *a2 = getenv("CAPAGENT_D00B_A2");
        if (!a2 || atoi(a2) != 0) {
            uint8_t en = 1;
            n += put_el(body+n, 0xa2, &en, 1);
        }
    }

    /* Advertise this radio's channels so the stock manager can run chansel. */
    size_t nb = n;
    n = add_channel_tlvs(body, n, phy);   /* returns the absolute offset */
    size_t nc = n;

    /* 0x0061 = current operating frequency (u32 MHz).  The manager requires
       length 4 exactly (x86 0x806969b) and stores it in phy+0x30/0x34.  A
       bogus value (1 MHz) poisons the 0x2018 channel check, so omit it rather
       than send nonsense. */
    {
        uint8_t cf[4];
        uint32_t hf = curfreq;
        if (hf >= 2000 && hf <= 7125) {
            put32(cf, hf);
            n += put_el(body + n, 0x61, cf, 4);
        } else {
            fprintf(stderr, "capagent: phy%d bad current freq %u, 0x61 omitted\n",
                    phy, hf);
        }
    }
    size_t n61 = n;

    /* 0x00B7 = u32 set of allowed channels for ActAp::chansel. */
    n = add_b7_tlv(body, n, phy);

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
