/* datapath.inc — split-MAC VAP registry and AF_PACKET bridge (U11 P0-P3)
 *
 * The manager addresses a VAP as (rid, wid); every VAP shares one c2
 * datachan.  This module owns the registry, the station map, the per-VAP
 * AF_PACKET sockets and the VLAN policy.  datachan.inc decrypts a frame and
 * calls dp_rx_frame(); dp_service() encrypts client frames through
 * dc_send_frame_vap().
 *
 * Part of capagent.c (single translation unit; included in order).
 */

#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif

/* ======================================================================
 * P0/P1: VAP registry keyed by (rid, wid), bound to a netdev.
 * ==================================================================== */
struct vap {
    int used, rid, wid;
    uint16_t vlan;              /* 0x7d, 0 = untagged */
    uint8_t bssid[6];           /* 0x08 */
    int ifindex;
    char ifname[32];
    int apvlan[8];
    int napvlan;
    uint32_t freq;
    uint8_t key[DC_KEY_MAX];
    size_t klen;
    uint8_t keyidx;
    uint64_t tx_seq, rx_max, rx_bitmap;
    int rx_started;
    int mode;                   /* 0 = ACCESS, 1 = TAG */
    int l2fd;                   /* AF_PACKET RX on the VAP */
    int extfd;                  /* hostapd external-RSN dgram */
    /* W33 ownership bookkeeping.  Only a netdev we created may ever be
       deleted, and only a hostapd we started may ever be stopped. */
    int we_created;
    int ap_started;
};
static struct vap g_vap[MAX_RADIOS][16];

static struct vap *vap_get(int rid, int wid)
{
    int r;
    if (rid < 0 || wid < 0) return NULL;
    r = rid % MAX_RADIOS;
    struct vap *v = &g_vap[r][wid & 0x0f];
    return v->used ? v : NULL;
}

static struct vap *vap_by_ifindex(int ifindex)
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_vap[r][w].used && g_vap[r][w].ifindex == ifindex)
                return &g_vap[r][w];
    return NULL;
}

static struct vap *vap_by_bssid(const uint8_t mac[6])
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_vap[r][w].used && !memcmp(g_vap[r][w].bssid, mac, 6))
                return &g_vap[r][w];
    return NULL;
}

static void vap_set_key(int rid, int wid, const uint8_t *key, size_t klen,
                        uint8_t keyidx)
{
    struct vap *v;
    if (rid < 0 || wid < 0) return;
    v = &g_vap[rid % MAX_RADIOS][wid & 0x0f];
    if (key && (klen == 16 || klen == 32)) {
        memcpy(v->key, key, klen);
        v->klen = klen;
        v->keyidx = keyidx;
        v->tx_seq = 0;          /* key rotation restarts our seq space */
    }
}

/* ---- port -> VAP channel (also used by the monitor relay) ------------- */
struct vap_chan { int used; int port; uint32_t freq; uint8_t width, band; };
static struct vap_chan g_vchan[128];

static void vchan_set(int port, uint32_t freq, uint8_t width, uint8_t band)
{
    int slot = -1;
    for (int i = 0; i < 128; i++) {
        if (g_vchan[i].used && g_vchan[i].port == (int)port) { slot = i; break; }
        if (!g_vchan[i].used && slot < 0) slot = i;
    }
    if (slot < 0) return;
    g_vchan[slot].used = 1;
    g_vchan[slot].port = (int)port;
    g_vchan[slot].freq = freq;
    g_vchan[slot].width = width ? width : 1;
    g_vchan[slot].band = band;
}

static int vchan_get(int port, uint32_t *freq, uint8_t *width, uint8_t *band)
{
    for (int i = 0; i < 128; i++)
        if (g_vchan[i].used && g_vchan[i].port == (int)port) {
            if (freq) *freq = g_vchan[i].freq;
            if (width) *width = g_vchan[i].width ? g_vchan[i].width : 1;
            if (band) *band = g_vchan[i].band;
            return 1;
        }
    return 0;
}

static void vchan_del(int port)
{
    for (int i = 0; i < 128; i++)
        if (g_vchan[i].used && g_vchan[i].port == (int)port) {
            g_vchan[i].used = 0;
            return;
        }
}

/* 0x0a { 0x0b u32 freq, 0x0c u8 width, 0x10 u8 band } from 0x500b/0x6016. */
static void vchan_from_tlv(int port, const uint8_t *v, size_t len)
{
    uint32_t freq = 0;
    uint8_t width = 0, band = 0;
    size_t p = 0;
    while (p + 4 <= len) {
        uint16_t t = rd16(v + p), l = rd16(v + p + 2);
        p += 4;
        if (p + l > len) break;
        if (t == 0x0b && l == 4) freq = rd32(v + p);
        else if (t == 0x0c && l == 1) width = v[p];
        else if (t == 0x10 && l == 1) band = v[p];
        p += l;
    }
    if (freq) vchan_set(port, freq, width, band);
}

/* MAC-first: the manager may address a VAP by a MAC that is not the
   netdev's own MAC.  W33 removed the old "first match in /sys/class/net"
   version (readdir order made the same MAC resolve to phy1-ap0 or to the
   cm1 monitor VIF from one session to the next); use ifindex_by_mac_ap()
   from policy.inc, which filters on iftype and phy. */

/* ---- station map: dst MAC -> egress ifindex (T2 §4) ------------------ */
struct sta_map { int used; uint8_t mac[6]; int ifindex; };
static struct sta_map g_sta[128];

static int sta_lookup(const uint8_t mac[6])
{
    for (int i = 0; i < 128; i++)
        if (g_sta[i].used && !memcmp(g_sta[i].mac, mac, 6))
            return g_sta[i].ifindex;
    return 0;
}

static void sta_put(const uint8_t mac[6], int ifindex)
{
    int free_slot = -1;
    for (int i = 0; i < 128; i++) {
        if (g_sta[i].used && !memcmp(g_sta[i].mac, mac, 6)) {
            g_sta[i].ifindex = ifindex;
            return;
        }
        if (!g_sta[i].used && free_slot < 0) free_slot = i;
    }
    if (free_slot < 0) return;
    g_sta[free_slot].used = 1;
    memcpy(g_sta[free_slot].mac, mac, 6);
    g_sta[free_slot].ifindex = ifindex;
}

static void sta_forget_ifindex(int ifindex)
{
    for (int i = 0; i < 128; i++)
        if (g_sta[i].used && g_sta[i].ifindex == ifindex)
            g_sta[i].used = 0;
}

/* NL80211_CMD_GET_STATION dump: one entry per STA, ATTR_MAC is the peer;
   the ifindex the dump ran on is that station's egress interface. */
static void nl_sta_dump(int ifindex)
{
    struct nl_buf m;
    struct sockaddr_nl sa;
    uint8_t rbuf[NL_MAX_MSG];

    if (ifindex <= 0 || nl_cmd_open() != 0) return;
    sta_forget_ifindex(ifindex);
    nlb_init(&m, NL80211_CMD_GET_STATION, NLM_F_DUMP);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(g_nl_cmd_fd, m.buf, m.nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return;
    for (;;) {
        struct pollfd pfd = { .fd = g_nl_cmd_fd, .events = POLLIN,
                              .revents = 0 };
        if (poll(&pfd, 1, 1000) <= 0) return;
        int n = (int)recv(g_nl_cmd_fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) return;
        int done = 0;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != m.nlh->nlmsg_seq) continue;
            if (nlh->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if (nlh->nlmsg_type == NLMSG_ERROR) { done = 1; break; }
            int alen = (int)nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                                  GENL_HDRLEN);
            for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
                 x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
                 alen -= NLA_ALIGN(x->nla_len),
                 x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
                if ((x->nla_type & NLA_TYPE_MASK) == NL80211_ATTR_MAC &&
                    x->nla_len >= NLA_HDRLEN + 6)
                    sta_put((uint8_t *)x + NLA_HDRLEN, ifindex);
            }
        }
        if (done) return;
    }
}

/* ---- AF_PACKET bridge (P3) ------------------------------------------ */
struct dp_fd { int fd; int ifindex; struct vap *v; };
static struct dp_fd g_dp[64];
static int g_ndp;
static int g_dp_txfd = -1;
static int g_dp_bridge;
static int g_vap_mtu;
static int g_bcast_flood;

static int is_mcast(const uint8_t mac[6])
{
    return (mac[0] & 1) != 0;
}

static int dp_add_fd(int ifindex, struct vap *v)
{
    if (ifindex <= 0 || g_ndp >= (int)(sizeof(g_dp)/sizeof(g_dp[0]))) return -1;
    for (int i = 0; i < g_ndp; i++)
        if (g_dp[i].ifindex == ifindex) return 0;
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    /* Injected frames must not be re-read and looped back to the manager. */
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    g_dp[g_ndp].fd = fd;
    g_dp[g_ndp].ifindex = ifindex;
    g_dp[g_ndp].v = v;
    g_ndp++;
    printf("bridge: AF_PACKET ifindex=%d (rid=%d wid=%d)\n", ifindex,
           v ? v->rid : -1, v ? v->wid : -1);
    fflush(stdout);
    return 0;
}

static void set_if_mtu(const char *ifname, int mtu)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    if (fd < 0 || mtu <= 0) return;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    ifr.ifr_mtu = mtu;
    ioctl(fd, SIOCSIFMTU, &ifr);
    close(fd);
}

/* Enumerate /sys/class/net/<vap>.* and keep the AP/VLAN netdevs. */
static void dp_scan_apvlans(struct vap *v)
{
    DIR *d;
    struct dirent *de;
    size_t bl = strlen(v->ifname);

    if (!v->ifname[0]) return;
    d = opendir("/sys/class/net");
    if (!d) return;
    while ((de = readdir(d)) != NULL) {
        char ifn[64];
        int ifindex, known = 0;
        if (strncmp(de->d_name, v->ifname, bl) != 0 || de->d_name[bl] != '.')
            continue;
        snprintf(ifn, sizeof(ifn), "%.*s", (int)sizeof(ifn) - 1,
                 de->d_name);
        ifindex = read_sysfs_int(ifn, "ifindex");
        if (ifindex <= 0) continue;
        if (nl_get_iftype(ifindex) != NL80211_IFTYPE_AP_VLAN) continue;
        for (int i = 0; i < v->napvlan; i++)
            if (v->apvlan[i] == ifindex) known = 1;
        if (!known && v->napvlan < (int)(sizeof(v->apvlan)/sizeof(v->apvlan[0]))) {
            v->apvlan[v->napvlan++] = ifindex;
            printf("bridge: AP_VLAN %s ifindex=%d -> rid=%d wid=%d\n",
                   ifn, ifindex, v->rid, v->wid);
            fflush(stdout);
        }
        if (g_dp_bridge && !known)
            dp_add_fd(ifindex, v);
    }
    closedir(d);
}

static void dp_vap_open(struct vap *v)
{
    /* W33: the bridge client rewrites the VAP's MTU and takes part in the
       data path; a legacy BSS belongs to netifd/wpad, so stay out of it. */
    if (wl_legacy()) return;
    if (!g_dp_bridge || !v->used || v->ifindex <= 0) return;
    if (v->l2fd < 0) {
        if (dp_add_fd(v->ifindex, v) == 0) v->l2fd = v->ifindex;
    }
    dp_scan_apvlans(v);
    if (g_vap_mtu > 0 && v->ifname[0]) set_if_mtu(v->ifname, g_vap_mtu);
}

static int l2_send(int ifindex, const uint8_t *frame, size_t len)
{
    struct sockaddr_ll sll;
    if (ifindex <= 0 || len < 14 || len > 1560) return -1;
    if (g_dp_txfd < 0) {
        g_dp_txfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (g_dp_txfd < 0) return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);
    return sendto(g_dp_txfd, frame, len, 0,
                  (struct sockaddr *)&sll, sizeof(sll)) < 0 ? -1 : 0;
}

/* ACCESS: untagged on the wire; TAG: 0x8100 inserted/stripped. */
static int vlan_frame(const struct vap *v, const uint8_t *in, size_t len,
                      uint8_t *out, size_t outmax, int to_client)
{
    int tagged = len >= 18 && in[12] == 0x81 && in[13] == 0x00;
    uint16_t vid = 0;

    if (len < 14 || len > outmax) return -1;
    if (tagged) vid = (uint16_t)(((in[14] & 0x0f) << 8) | in[15]);
    if (to_client) {
        if (v->mode == 0) {                 /* ACCESS */
            if (!tagged) { memcpy(out, in, len); return (int)len; }
            if (v->vlan && vid != v->vlan) return -1;
            memcpy(out, in, 12);
            memcpy(out + 12, in + 16, len - 16);
            return (int)(len - 4);
        }
        if (!tagged && v->vlan) {           /* TAG */
            if (len + 4 > outmax) return -1;
            memcpy(out, in, 12);
            out[12] = 0x81; out[13] = 0x00;
            out[14] = (uint8_t)(v->vlan >> 8); out[15] = (uint8_t)v->vlan;
            memcpy(out + 16, in + 12, len - 12);
            return (int)(len + 4);
        }
        memcpy(out, in, len);
        return (int)len;
    }
    /* client -> manager */
    if (v->mode == 0) {                     /* ACCESS: strip and validate */
        if (!tagged) { memcpy(out, in, len); return (int)len; }
        if (v->vlan && vid != v->vlan) return -1;
        memcpy(out, in, 12);
        memcpy(out + 12, in + 16, len - 16);
        return (int)(len - 4);
    }
    if (!tagged && v->vlan) {               /* TAG: insert */
        if (len + 4 > outmax) return -1;
        memcpy(out, in, 12);
        out[12] = 0x81; out[13] = 0x00;
        out[14] = (uint8_t)(v->vlan >> 8); out[15] = (uint8_t)v->vlan;
        memcpy(out + 16, in + 12, len - 12);
        return (int)(len + 4);
    }
    memcpy(out, in, len);
    return (int)len;
}

/* egress ifindex for a decrypted manager frame (dst-MAC -> station map). */
static int egress_ifindex(struct vap *v, const uint8_t *frame)
{
    if (!v || !v->used) return 0;
    if (is_mcast(frame)) return v->ifindex;
    int oif = sta_lookup(frame);
    if (!oif) {
        static time_t last_dump;
        if (time(NULL) != last_dump) {
            last_dump = time(NULL);
            nl_sta_dump(v->ifindex);
            for (int i = 0; i < v->napvlan; i++)
                nl_sta_dump(v->apvlan[i]);
            oif = sta_lookup(frame);
        }
    }
    return oif ? oif : v->ifindex;
}

/* Manager -> client.  Multicast is fanned out to the AP_VLANs too; mac80211
   does not forward it from the AP netdev to AP_VLAN stations (T2 §5.2). */
static void l2_send_vap(struct vap *v, const uint8_t *frame, size_t len)
{
    if (!v || !v->used) return;
    if (is_mcast(frame)) {
        l2_send(v->ifindex, frame, len);
        for (int i = 0; i < v->napvlan; i++)
            l2_send(v->apvlan[i], frame, len);
    } else {
        int oif = egress_ifindex(v, frame);
        if (oif > 0) l2_send(oif, frame, len);
    }
}

/* 200 ms duplicate cache: the manager may send one copy per VAP/VLAN. */
struct dedup_ent {
    int used;
    uint8_t key[30];
    size_t klen;
    struct timespec t;
};
static struct dedup_ent g_dd[16];

static int dedup_seen(const uint8_t *frame, size_t len)
{
    static int head;
    struct dedup_ent *e = NULL;
    uint8_t key[30];
    size_t klen = 0;
    struct timespec now;

    if (len < 14) return 0;
    memcpy(key, frame + 6, 6); klen = 6;          /* src */
    memcpy(key + klen, frame, 6); klen += 6;      /* dst */
    key[klen++] = frame[12];
    key[klen++] = frame[13];
    {
        size_t pl = len > 14 ? len - 14 : 0;
        if (pl > 16) pl = 16;
        memcpy(key + klen, frame + 14, pl);
        klen += pl;
    }
    clock_gettime(CLOCK_MONOTONIC, &now);
    for (int i = 0; i < 16; i++) {
        struct dedup_ent *x = &g_dd[i];
        long ms;
        if (!x->used) continue;
        ms = (now.tv_sec - x->t.tv_sec) * 1000 +
             (now.tv_nsec - x->t.tv_nsec) / 1000000;
        if (ms > 200) { x->used = 0; continue; }
        if (x->klen == klen && !memcmp(x->key, key, klen)) return 1;
    }
    e = &g_dd[head];
    head = (head + 1) & 15;
    e->used = 1;
    e->klen = klen;
    memcpy(e->key, key, klen);
    e->t = now;
    return 0;
}

struct dc_ctx;
static int dc_send_frame_vap(struct dc_ctx *d, int rid, int wid,
                             const uint8_t *frame, size_t flen);

/* Unknown (rid,wid) on RX.  Unicast is always dropped; multicast goes to
   the owning VAP, or to every VAP of the radio with --bcast flood. */
static void flood_or_drop(struct dc_ctx *d, int rid, int wid,
                          const uint8_t *frame, size_t len, uint16_t et)
{
    (void)d;
    uint8_t out[DC_MAX_PAYLOAD + 4];

    if (!is_mcast(frame)) {
        printf("datachan: drop unicast for unknown wid=%d rid=%d\n", wid, rid);
        return;
    }
    if (!g_bcast_flood) {
        struct vap *v = vap_get(rid, wid);
        if (!v) {
            printf("datachan: drop bcast for unknown wid=%d rid=%d\n",
                   wid, rid);
            return;
        }
        int n = vlan_frame(v, frame, len, out, sizeof(out), 1);
        if (n > 0) l2_send_vap(v, out, (size_t)n);
        return;
    }
    for (int w = 0; w < 16; w++) {
        struct vap *v = &g_vap[rid % MAX_RADIOS][w];
        int n;
        if (!v->used) continue;
        n = vlan_frame(v, frame, len, out, sizeof(out), 1);
        if (n > 0) l2_send_vap(v, out, (size_t)n);
    }
}

/* P2: decrypt path entry — VLAN policy, EAPOL control-port, L2 inject. */
static void dp_rx_frame(struct dc_ctx *d, int rid, int wid,
                        const uint8_t *pt, size_t plen)
{
    struct vap *v = vap_get(rid, wid);
    uint8_t out[DC_MAX_PAYLOAD + 4];
    uint16_t et;
    int n;

    if (plen < 14) {
        printf("datachan: short payload %zu rid=%d wid=%d\n", plen, rid, wid);
        return;
    }
    if (!v) {
        memcpy(out, pt, plen);
        et = (uint16_t)((out[12] << 8) | out[13]);
        flood_or_drop(d, rid, wid, out, plen, et);
        return;
    }
    n = vlan_frame(v, pt, plen, out, sizeof(out), 1);
    if (n < 0) {
        printf("datachan: vlan mismatch rid=%d wid=%d vlan=%u\n",
               rid, wid, v->vlan);
        return;
    }
    et = (uint16_t)((out[12] << 8) | out[13]);
    if (et == ETH_P_EAPOL) {
        int oif = egress_ifindex(v, out);
        int rr = nl_control_port_tx(oif, out, out + 14, (size_t)n - 14);
        printf("datachan: EAPOL %dB -> STA ifindex=%d ret=%d\n",
               n - 14, oif, rr);
    } else {
        if (dedup_seen(out, (size_t)n)) return;
        l2_send_vap(v, out, (size_t)n);
    }
}

static void dp_refresh(void)
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++) {
            struct vap *v = &g_vap[r][w];
            if (!v->used) continue;
            if (g_dp_bridge) dp_scan_apvlans(v);
            nl_sta_dump(v->ifindex);
            for (int i = 0; i < v->napvlan; i++)
                nl_sta_dump(v->apvlan[i]);
        }
}

static void dp_close_all(void)
{
    for (int i = 0; i < g_ndp; i++)
        close(g_dp[i].fd);
    g_ndp = 0;
    if (g_dp_txfd >= 0) { close(g_dp_txfd); g_dp_txfd = -1; }
}

/* P3: client -> datachan.  One AF_PACKET RX socket per VAP and AP_VLAN. */
static unsigned long g_dp_tx_frames, g_dp_rx_frames;
static void dp_service(struct dc_ctx *d)
{
    uint8_t buf[2048], out[2048];

    for (int i = 0; i < g_ndp; i++) {
        for (;;) {
            ssize_t n = recv(g_dp[i].fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (n < 0) break;
            if (n == 0) continue;
            struct vap *v = g_dp[i].v;
            if (!v || !v->used) continue;
            if (n < 14 || n > 1560) continue;
            if (++g_dp_rx_frames <= 3 || g_dp_rx_frames % 500 == 0)
                printf("bridge: RX %zdB ifindex=%d rid=%d wid=%d (n=%lu)\n",
                       n, g_dp[i].ifindex, v->rid, v->wid, g_dp_rx_frames);
            int m = vlan_frame(v, buf, (size_t)n, out, sizeof(out), 0);
            if (m < 0) continue;
            if (dc_send_frame_vap(d, v->rid, v->wid, out, (size_t)m) == 0) {
                if (++g_dp_tx_frames <= 3 || g_dp_tx_frames % 500 == 0)
                    printf("bridge: %zdB -> datachan rid=%d wid=%d (n=%lu)\n",
                           n, v->rid, v->wid, g_dp_tx_frames);
            }
        }
    }
    fflush(stdout);
}
