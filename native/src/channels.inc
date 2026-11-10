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
   virtual user stays in CreatingVap forever. */
static struct {
    int used;
    uint8_t mac[6];             /* identity the manager uses (0x08) */
    uint8_t bssid[6];           /* address the netdev really carries (W54) */
} g_vmap[MAX_RADIOS][16];

/* ---- W54: legal BSS addresses on an MT7612E (mt76x02) ----------------
 *
 * mt76x02_add_interface() derives the hardware BSS index from the first
 * octet of the vif address:
 *      idx = (addr[0] & 0x02) ? 1 + (((base[0] ^ addr[0]) >> 2) & 7) : 0
 * and returns -EBUSY when that index is already in use (mt76x02_util.c).
 * A CAPsMAN BSSID plan that keeps byte 0 the same for every VAP (varying
 * only the last byte, as several managers and our own test peers do) makes
 * every VAP want the same index: the first BSS starts, every later one
 * fails in dev_open() with EBUSY, which hostapd reports as
 *   Could not set interface phy1-apN flags (UP): Resource busy
 * and which leaves the phy wedged (later starts block in D state).  The
 * mgmt monitor cm<N> carries the radio MAC, i.e. index 0, and collides with
 * VAP0 the same way.
 *
 * The driver publishes the legal addresses in
 * /sys/class/ieee80211/phyN/addresses.  A manager MAC that is already one
 * of them (bytes 1..5 on the radio base) is used unchanged when its index
 * is free.  Otherwise, or on a collision, we pick a free address from that
 * list: only byte 0 bits 2..4 change, so the driver never has to reprogram
 * the radio base MAC (it only allows that for the very first interface).
 */
static int g_bss_seeded[MAX_RADIOS];
static uint8_t g_bss_used[MAX_RADIOS];   /* bit n = BSS index n claimed */

static int phy_is_mt76x02(int phy)
{
    char p[96], b[128];
    snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/driver",
             real_phy(phy));
    ssize_t n = readlink(p, b, sizeof(b) - 1);
    if (n <= 0) return 0;
    b[n] = 0;
    char *s = strrchr(b, '/');
    s = s ? s + 1 : b;
    return !strcmp(s, "mt76x2e") || !strcmp(s, "mt76x0e") ||
           !strcmp(s, "mt76x2u") || !strcmp(s, "mt76x0u");
}

/* W54: how many driver interfaces the phy can hold.  MT7603E has
 * MT7603_MAX_INTERFACES = 4 (monitor included), mt76x02 has 8. */
static int phy_max_vifs(int phy)
{
    char p[96], b[128];
    snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/driver",
             real_phy(phy));
    ssize_t n = readlink(p, b, sizeof(b) - 1);
    if (n <= 0) return 0;
    b[n] = 0;
    char *s = strrchr(b, '/');
    s = s ? s + 1 : b;
    if (!strcmp(s, "mt7603e")) return 4;
    if (!strcmp(s, "mt76x2e") || !strcmp(s, "mt76x0e") ||
        !strcmp(s, "mt76x2u") || !strcmp(s, "mt76x0u")) return 8;
    return 0;
}

static int phy_base_mac(int phy, uint8_t out[6])
{
    char p[96], b[64];
    unsigned v[6];
    snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/macaddress",
             real_phy(phy));
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    if (!fgets(b, sizeof(b), f)) { fclose(f); return -1; }
    fclose(f);
    if (sscanf(b, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
    return 0;
}

/* The eight addresses the driver accepts, in index order (idx 0 first). */
static int phy_legal_addrs(int phy, uint8_t out[8][6])
{
    char p[96], line[128];
    snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/addresses",
             real_phy(phy));
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    int n = 0;
    while (n < 8 && fgets(line, sizeof(line), f)) {
        unsigned v[6];
        if (sscanf(line, "%x:%x:%x:%x:%x:%x",
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
            continue;
        for (int i = 0; i < 6; i++) out[n][i] = (uint8_t)v[i];
        n++;
    }
    fclose(f);
    return n;
}

static int bss_idx_of(const uint8_t base[6], const uint8_t mac[6])
{
    if (!(mac[0] & 0x02)) return 0;
    return 1 + (((base[0] ^ mac[0]) >> 2) & 7);
}

/* Inverse of bss_idx_of(): bytes 1..5 stay on the radio base so that the
 * driver never has to reprogram the base MAC (it only allows that for the
 * very first interface). */
static void bss_addr_of_idx(const uint8_t base[6], int idx, uint8_t out[6])
{
    memcpy(out, base, 6);
    if (idx <= 0)
        out[0] = (uint8_t)(base[0] & ~0x02);
    else
        out[0] = (uint8_t)((base[0] ^ (((idx - 1) & 7) << 2)) | 0x02);
}

/* Mark every non-station vif already on the phy (monitor, legacy APs,
 * adopted VAPs) so the first allocation does not collide with them. */
static void bss_seed(int r, int phy)
{
    uint8_t base[6];
    if (phy_base_mac(phy, base) != 0) return;
    DIR *d = opendir("/sys/class/net");
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        uint8_t m[6];
        if (de->d_name[0] == '.') continue;
        if (iface_phy_index(de->d_name) != real_phy(phy)) continue;
        int idx = read_sysfs_int(de->d_name, "ifindex");
        if (idx <= 0 || nl_get_iftype(idx) == NL80211_IFTYPE_STATION) continue;
        if (read_sysfs_mac(de->d_name, m) != 0) continue;
        g_bss_used[r] |= (uint8_t)(1u << bss_idx_of(base, m));
    }
    closedir(d);
}

/* Pick an address for a new VAP.  want = the manager's 0x08. */
static void vap_bssid_alloc(int phy, const uint8_t want[6], uint8_t out[6])
{
    memcpy(out, want, 6);
    if (!phy_is_mt76x02(phy)) return;
    int r = phy % MAX_RADIOS;
    uint8_t base[6], legal[8][6];
    if (phy_base_mac(phy, base) != 0) return;
    if (!g_bss_seeded[r]) { bss_seed(r, phy); g_bss_seeded[r] = 1; }

    int nl = phy_legal_addrs(phy, legal);
    if (nl <= 0) {                  /* older kernel: rebuild the plan */
        for (int i = 0; i < 8; i++) bss_addr_of_idx(base, i, legal[i]);
        nl = 8;
    }
    int compatible = !memcmp(want + 1, base + 1, 5);
    if (compatible) {
        int idx = bss_idx_of(base, want);
        if (!(g_bss_used[r] & (1u << idx))) {
            g_bss_used[r] |= (uint8_t)(1u << idx);
            return;                      /* manager plan is legal: keep it */
        }
    }
    for (int i = 0; i < nl; i++) {
        int idx = bss_idx_of(base, legal[i]);
        if (g_bss_used[r] & (1u << idx)) continue;
        g_bss_used[r] |= (uint8_t)(1u << idx);
        memcpy(out, legal[i], 6);
        printf("vap: phy%d bss %02x:%02x:%02x:%02x:%02x:%02x -> "
               "%02x:%02x:%02x:%02x:%02x:%02x (mt76x02 index %d)\n", phy,
               want[0], want[1], want[2], want[3], want[4], want[5],
               out[0], out[1], out[2], out[3], out[4], out[5], idx);
        fflush(stdout);
        return;
    }
    printf("vap: phy%d has no free mt76x02 BSS index for %02x:... "
           "(keeping it: expect EBUSY)\n", phy, want[0]);
    fflush(stdout);
}

static void vap_bssid_free(int phy, const uint8_t mac[6])
{
    if (!phy_is_mt76x02(phy)) return;
    int r = phy % MAX_RADIOS;
    uint8_t base[6];
    if (!g_bss_seeded[r] || phy_base_mac(phy, base) != 0) return;
    g_bss_used[r] &= (uint8_t)~(1u << bss_idx_of(base, mac));
}

/* First free legal address, for the mgmt monitor.  Returns 1 and marks the
 * index when it found one, 0 when the phy does not need the treatment, -1
 * when the phy is full. */
static int vap_bssid_pick_free(int phy, uint8_t out[6])
{
    if (!phy_is_mt76x02(phy)) return 0;
    int r = phy % MAX_RADIOS;
    uint8_t base[6], legal[8][6];
    if (phy_base_mac(phy, base) != 0) return 0;
    if (!g_bss_seeded[r]) { bss_seed(r, phy); g_bss_seeded[r] = 1; }
    int nl = phy_legal_addrs(phy, legal);
    if (nl <= 0) {                  /* older kernel: rebuild the plan */
        for (int i = 0; i < 8; i++) bss_addr_of_idx(base, i, legal[i]);
        nl = 8;
    }
    for (int i = 0; i < nl; i++) {
        int idx = bss_idx_of(base, legal[i]);
        if (g_bss_used[r] & (1u << idx)) continue;
        g_bss_used[r] |= (uint8_t)(1u << idx);
        memcpy(out, legal[i], 6);
        return 1;
    }
    return -1;
}

static int vapid_lookup(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used &&
            (!memcmp(g_vmap[r][i].mac, mac, 6) ||
             !memcmp(g_vmap[r][i].bssid, mac, 6)))
            return i;
    return -1;
}

/* W54: match either identity so a 0x6016/0x600c that echoes the manager's
 * MAC still resolves to the VAP whose hardware BSSID had to be remapped. */
static int vapid_for(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used &&
            (!memcmp(g_vmap[r][i].mac, mac, 6) ||
             !memcmp(g_vmap[r][i].bssid, mac, 6)))
            return i;
    for (int i = 0; i < 16; i++)
        if (!g_vmap[r][i].used) {
            g_vmap[r][i].used = 1;
            memcpy(g_vmap[r][i].mac, mac, 6);
            memcpy(g_vmap[r][i].bssid, mac, 6);
            return i;
        }
    return 0;
}

static void vapid_set_bssid(int phy, const uint8_t mac[6], const uint8_t bssid[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6)) {
            memcpy(g_vmap[r][i].bssid, bssid, 6);
            return;
        }
}

/* Paired with vapid_alloc(); the 0x600c destroy path (open item: VAP
   lifecycle) is expected to call it, so keep it even though the handler does
   not exist yet. */
static void __attribute__((unused)) vapid_release(int phy, const uint8_t mac[6])
{
    int r = phy % MAX_RADIOS;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used &&
            (!memcmp(g_vmap[r][i].mac, mac, 6) ||
             !memcmp(g_vmap[r][i].bssid, mac, 6))) {
            vap_bssid_free(phy, g_vmap[r][i].bssid);
            g_vmap[r][i].used = 0;
        }
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
                ifindex_by_mac_ap(g_vmap[r][i].bssid, r, NULL, 0) <= 0 &&
                ifindex_by_mac_ap(g_vmap[r][i].mac, r, NULL, 0) <= 0) {
                vap_bssid_free(r, g_vmap[r][i].bssid);
                g_vmap[r][i].used = 0;
            }
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
    int known = vapid_lookup(phy, mac);
    int vapid = known >= 0 ? known : vapid_for(phy, mac);
    /* W54: pick an address this radio can actually carry (mt76x02 BSS
     * index plan).  Both identities stay known: mac is what the manager
     * uses, bssid is what the netdev/beacon carries.  A repeated create for
     * the same VAP reuses its address instead of burning another index. */
    uint8_t bssid[6];
    if (known >= 0 && memcmp(g_vmap[phy % MAX_RADIOS][known].bssid, mac, 6)) {
        memcpy(bssid, g_vmap[phy % MAX_RADIOS][known].bssid, 6);
    } else {
        vap_bssid_alloc(phy, mac, bssid);
        vapid_set_bssid(phy, mac, bssid);
    }
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
    own_claim(c, phy, vapid, preferred, bssid, ifname, sizeof(ifname),
              &ifindex, &managed);
    if (ifindex < 0)
        ifindex = 0;
    if (!ifname[0])
        snprintf(ifname, sizeof(ifname), "%s", pref);
    if (ifindex <= 0) {
        printf("vap: phy=%d vapid=%d has no netdev and no name is available "
               "(owned=%d)\n", phy, vapid, managed);
        vap_bssid_free(phy, bssid);
    } else {
        /* A pre-existing/adopted netdev keeps its own address (and with it
         * its driver BSS index); trust sysfs over our plan. */
        uint8_t have[6];
        if (read_sysfs_mac(ifname, have) == 0 &&
            memcmp(have, bssid, 6) != 0) {
            vap_bssid_free(phy, bssid);
            memcpy(bssid, have, 6);
            uint8_t base[6];
            if (phy_is_mt76x02(phy) && phy_base_mac(phy, base) == 0)
                g_bss_used[phy % MAX_RADIOS] |=
                    (uint8_t)(1u << bss_idx_of(base, have));
        }
        vapid_set_bssid(phy, mac, bssid);
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
        memcpy(vp->bssid, bssid, 6);
        vp->ifindex = ifindex;
        if (vp->ifname[0] && strcmp(vp->ifname, ifname)) {
            if (vp->extfd >= 0) { close(vp->extfd); vp->extfd = -1; }
        }
        snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);
        vp->mode = 0;                   /* ACCESS (default) */
        vp->napvlan = 0;
        if (managed && own_created_port((phy << 8) | vapid))
            vp->we_created = 1;
        vchan_set((phy << 8) | vapid, vp->freq, 1,
                  band_code_for_freq(vp->freq));
        /* The manager sends vapid=0 in every 0x500b, so only alias the
           request port when it really is this VAP; otherwise VAP0's slot
           would be overwritten by every later create. */
        if (vap_port_alias_ok(vap, vapid))
            vchan_set((phy << 8) | vap, vp->freq, 1,
                      band_code_for_freq(vp->freq));
        printf("vap: rid=%d wid=%d vlan=%u freq=%u bssid=%02x:%02x:%02x:%02x:"
               "%02x:%02x mgr=%02x:%02x:%02x:%02x:%02x:%02x ifindex=%d "
               "ifname=%s\n", phy, vapid, vp->vlan, vp->freq,
               bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               ifindex, ifname);
        fflush(stdout);
        if (managed && c->datapath_bridge) dp_vap_open(vp);
        if (managed && (c->mgmt_relay || c->mgmt_source))
            mgmt_vap_add(ifindex);
        cap_vap_ready(phy, vapid, ifindex, ifname, bssid, c);
    }

    if (c->no_ack) {
        /* A genuine CAP sends nothing when the data channel is created OK;
           0xD00B is only the failure path. */
        if (ifindex > 0) {
            pmap_set(phy << 8 | vapid, ifindex, bssid);
            if (vap_port_alias_ok(vap, vapid))
                pmap_set(phy << 8 | vap, ifindex, bssid);
        }
        printf("0xd00b phy=%d ifname=%s (no-ack: success reply suppressed)\n",
               phy, ifname);
        fflush(stdout);
        return;
    }
    if (ifindex > 0) {
        pmap_set(phy << 8 | vapid, ifindex, bssid);
        if (vap_port_alias_ok(vap, vapid))
            pmap_set(phy << 8 | vap, ifindex, bssid);
    }

    n += put_el(body+n, 0x08, bssid, 6);
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
