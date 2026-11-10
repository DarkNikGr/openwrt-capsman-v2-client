/* mgmt.inc — EAPOL/key descriptors, 0x200e/0x2015/0x2018 helpers
 * Part of capagent.c (single translation unit; included in order).
 * U11 P4 (0x2018 relay), U3 monitor fallback, U11/U3 hostapd ext-auth.
 */

#ifdef CAPAGENT_LAB
static void lab_handle_mgmt(mbedtls_ssl_context *ssl, const uint8_t *f,
                            size_t len);
static void lab_monitor_frame(mbedtls_ssl_context *ssl, const uint8_t *f,
                              size_t len);
#endif

/* Defined with the extmux glue at the bottom of this module. */
static uint16_t xm_canon_port(int port);
static int  cap_hostapd_ctrl(const struct cfg *c, const char *ifname,
                             const char *cmd, char *reply, size_t rlen);
/* Defined with the VAP lifecycle in vap.inc (W33). */
static int  vap_refresh_ifindex(int port, uint8_t mac[6], int *changed);

/* W36: in-CAP MLME hooks (definitions in mlme.inc, included after this). */
static int mlme_owns_ifindex(int ifindex);
static int mlme_on_mgmt(mbedtls_ssl_context *ssl, struct nlattr *at, int alen,
                        int ifindex, const struct cfg *c);
static int mlme_on_control_port(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                                const struct cfg *c, struct nlattr *at,
                                int alen);
static int mlme_tx_mgmt(int ifindex, const uint8_t *fr, size_t len);

static void eapol_strip(const uint8_t **fr, size_t *len)
{
    const uint8_t *p = *fr;
    size_t n = *len;
    int looks_eapol = n >= 4 && (p[0] == 1 || p[0] == 2) && p[1] <= 3;
    if (looks_eapol) return;
    if (n > 14 && p[12] == 0x88 && p[13] == 0x8e) {
        p += 14; n -= 14;                 /* 802.3 */
    } else if (n > 26 && (p[0] & 0x0c) == 0x08 && p[24] == 0x88 &&
               p[25] == 0x8e) {
        p += 26; n -= 26;                 /* 802.11 data + LLC/SNAP */
    }
    *fr = p; *len = n;
}

static void eapol_log(const char *dir, const uint8_t mac[6],
                      const uint8_t *e, size_t n)
{
    const char *kind = "other";
    int msg = -1;
    if (n >= 2) {
        if (e[1] == 0) kind = "EAPOL-Start";
        else if (e[1] == 1) kind = "EAPOL-Logoff";
        else if (e[1] == 3) {
            kind = "EAPOL-Key";
            if (n >= 7) msg = (e[6] >> 3) & 0x3f;   /* key info bits */
        }
    }
    printf("[EAPOL %s] %02x:%02x:%02x:%02x:%02x:%02x len=%zu %s%s%02x%02x\n",
           dir, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], n, kind,
           msg >= 0 ? " info=" : "", msg >= 0 ? (unsigned)(e[5]) : 0,
           msg >= 0 ? (unsigned)(e[6]) : 0);
    fflush(stdout);
}

/* TX leg: manager -> CAP (0x201C) -> STA.  Body: {08=STA MAC, 3E=EAPOL}. */
static void handle_201c(mbedtls_ssl_context *ssl, int port,
                        const uint8_t *body, size_t len)
{
    (void)ssl;
    struct tlv_it it = { body, len };
    uint16_t tag;
    const uint8_t *v, *mac = NULL, *eapol = NULL;
    size_t vl, elen = 0;

    while (tlv_next(&it, &tag, &v, &vl)) {
        if (tag == 0x0008 && vl == 6) mac = v;
        else if (tag == 0x003e) { eapol = v; elen = vl; }
    }
    if (!mac || !eapol || !elen) {
        printf("0x201c: missing %s TLV (len=%zu)\n",
               !mac ? "STA-MAC" : "EAPOL", len);
        fflush(stdout);
        return;
    }
    eapol_strip(&eapol, &elen);
    eapol_log("TX", mac, eapol, elen);

    if (!wl_port_managed(xm_canon_port(port))) {
        /* netifd/wpad (or a foreign netdev) owns this BSS: injecting the
           manager's EAPOL would race its 4-way.  Read-only. */
        printf("0x201c: port 0x%04x is not capagent-owned, not relaying\n",
               port);
        fflush(stdout);
        return;
    }

    if (g_extmux) {
        /* Single TX owner: hostapd performs the control-port TX and checks
         * the reply; direct nl80211 injection is only its fallback. */
        uint16_t xp = xm_canon_port(port);
        int r = extmux_tx(g_extmux, xp, mac, eapol, elen, 0);
        printf("0x201c: relay -> %02x:%02x:%02x:%02x:%02x:%02x port=0x%04x "
               "len=%zu ret=%d\n", mac[0], mac[1], mac[2], mac[3], mac[4],
               mac[5], xp, elen, r);
        fflush(stdout);
        return;
    }

    uint8_t bssid[6] = {0};
    int ifindex = vap_ifindex(port, bssid);
    if (ifindex <= 0 || nl_cmd_open() != 0) {
        printf("0x201c: no ifindex/nl80211 for port 0x%04x\n", port);
        fflush(stdout);
        return;
    }
    int r = nl_control_port_tx(ifindex, mac, eapol, elen);
    printf("0x201c: inject -> %02x:%02x:%02x:%02x:%02x:%02x ifindex=%d "
           "len=%zu ret=%d (%s)\n", mac[0], mac[1], mac[2], mac[3], mac[4],
           mac[5], ifindex, elen, r, r ? strerror(-r) : "ok");
    fflush(stdout);
}

/* RX leg: STA -> CAP (control port) -> manager.  leg 1 = TLS 0x201B,
   leg 2 = c2 datachan Ethernet frame (S4 model), 3 = both. */
__attribute__((unused))
static void eapol_relay(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                        const struct cfg *c, int port, const uint8_t mac[6],
                        const uint8_t *eapol, size_t len)
{
    eapol_log("RX", mac, eapol, len);
    if (c->eapol_leg & 1) {
        uint8_t b[BODY_MAX];
        size_t n = 0;
        n += put_el(b + n, 0x08, mac, 6);
        n += put_el(b + n, 0x3e, eapol, (uint16_t)len);
        if (send_msg(ssl, TYPE_EAPOL_RX, (uint16_t)port, b, (uint16_t)n) == 0)
            printf("0x201b: EAPOL %zuB -> manager (control) port=0x%04x\n",
                   len, port);
        else
            printf("0x201b: control send failed\n");
    }
    if ((c->eapol_leg & 2) && dc && dc->fd >= 0) {
        uint8_t fr[14 + 1600];
        uint8_t bssid[6] = {0};
        if (len > 1600) return;
        pmap_get(port, NULL, bssid);
        memcpy(fr, bssid, 6);
        memcpy(fr + 6, mac, 6);
        fr[12] = 0x88; fr[13] = 0x8e;
        memcpy(fr + 14, eapol, len);
        int r = dc_send_frame_vap(dc, port >> 8, port & 0xff, fr, 14 + len);
        printf("0x201b: EAPOL %zuB -> manager (datachan) ret=%d\n", len, r);
    }
    fflush(stdout);
}

/* ---- P4: 0x2018 Auth/AssocReq relay ------------------------------- */

/* Exact body required by ActAp::receiveC2 case 0x2018 (W6 §2):
     0x003e <raw 802.11 frame, FC first, no FCS>
     0x000a { 0x000b u32 freq, 0x000c u8 width, 0x0010 u8 band }
     0x003f i32 RSSI in dBm (optional)
   The manager compares 0x0a's 0x0b with the VAP's provisioned frequency and
   silently drops the message when it is missing or unequal.  0x3f is RSSI,
   not frequency (W6 corrected the older T13 note); a wrong value is only
   cosmetic, so omit it when the driver did not report a signal. */
static void mgmt_send_2018(mbedtls_ssl_context *ssl, int port,
                           const uint8_t *fr, size_t flen, uint32_t freq,
                           uint8_t width, uint8_t band, int32_t rssi,
                           const char *kind)
{
    uint8_t b[BODY_MAX], ch[32], cf[4];
    size_t n = 0, cn = 0;
    unsigned char w = width ? width : 1;

    if (freq <= 0) return;
    if (!band) band = band_code_for_freq(freq);
    put32(cf, freq);
    cn += put_el(ch + cn, 0x0b, cf, 4);
    cn += put_el(ch + cn, 0x0c, &w, 1);
    cn += put_el(ch + cn, 0x10, &band, 1);
    n += put_el(b + n, 0x3e, fr, (uint16_t)flen);
    n += put_el(b + n, 0x0a, ch, (uint16_t)cn);
    if (rssi != 0) {
        put32(cf, (uint32_t)rssi);
        n += put_el(b + n, 0x3f, cf, 4);
    }
    if (send_msg(ssl, TYPE_ASSOC_FRAME, (uint16_t)port, b, (uint16_t)n) == 0) {
        printf("0x2018 %s %02x:%02x:%02x:%02x:%02x:%02x -> manager "
               "(port=0x%04x freq=%u rssi=%d len=%zu)\n", kind,
               fr[10], fr[11], fr[12], fr[13], fr[14], fr[15],
               port, freq, (int)rssi, flen);
    } else {
        printf("0x2018 %s: send failed\n", kind);
    }
    fflush(stdout);
}

static void send_2018_frame(mbedtls_ssl_context *ssl, int phy, int wid,
                            const uint8_t *fr, size_t flen, uint32_t freq,
                            int32_t rssi, const char *kind)
{
    mgmt_send_2018(ssl, (phy << 8) | (wid & 0xff), fr, flen, freq, 1,
                   band_code_for_freq(freq), rssi, kind);
}

/* One NL80211_CMD_FRAME event -> 0x2018. */
static void mgmt_handle_frame(mbedtls_ssl_context *ssl,
                              struct nlattr *at, int alen, int have_ifindex,
                              int ifindex)
{
    struct nlattr *fa = NULL, *ma = NULL, *sa = NULL;
    for (struct nlattr *a = at; alen >= (int)sizeof(struct nlattr) &&
         a->nla_len >= sizeof(struct nlattr) && a->nla_len <= alen;
         alen -= NLA_ALIGN(a->nla_len),
         a = (struct nlattr *)((uint8_t *)a + NLA_ALIGN(a->nla_len))) {
        int t = a->nla_type & NLA_TYPE_MASK;
        if (t == NL80211_ATTR_FRAME) fa = a;
        else if (t == NL80211_ATTR_MAC) ma = a;
        else if (t == NL80211_ATTR_RX_SIGNAL_DBM) sa = a;
    }
    (void)ma;
    if (!fa) return;
    const uint8_t *fr = (uint8_t *)fa + NLA_HDRLEN;
    size_t fl = fa->nla_len - NLA_HDRLEN;
    if (fl < 24) return;
    uint16_t fc = (uint16_t)(fr[0] | (fr[1] << 8));
    if ((fc & 0x0c) != 0) return;              /* management only */
    int stype = (fc >> 4) & 0xf;
    const char *kind;
    if (stype == 11) kind = "auth";
    else if (stype == 0) kind = "assoc";
    else if (stype == 2) kind = "reassoc";
    else return;

    /* W6 C7: addr1 must be the BSSID (addr3).  A frame for another BSS can
     * only be silently dropped by the manager, so do not send it. */
    if (memcmp(fr + 4, fr + 16, 6) != 0) {
        printf("0x2018 %s: addr1 != addr3, dropped\n", kind);
        fflush(stdout);
        return;
    }

    int32_t rssi = 0;
    if (sa && sa->nla_len >= NLA_HDRLEN + 4)
        memcpy(&rssi, (uint8_t *)sa + NLA_HDRLEN, 4);

    struct vap *v = have_ifindex ? vap_by_ifindex(ifindex) : NULL;
    if (!v) v = vap_by_bssid(fr + 16);          /* addr3 = BSSID */
    if (!v) {
        /* No provisioned VAP: 0x0a cannot carry the right frequency, and the
         * manager would drop it anyway.  Do not invent 2437. */
        printf("0x2018 %s: no VAP for bssid %02x:%02x:%02x:%02x:%02x:%02x, "
               "dropped\n", kind, fr[16], fr[17], fr[18], fr[19], fr[20],
               fr[21]);
        fflush(stdout);
        return;
    }
    /* Use the VAP's configured frequency, not the RX frequency (T13 §6). */
    send_2018_frame(ssl, v->rid, v->wid, fr, fl, v->freq, rssi, kind);
}

/* Resolve ifindex from a NL80211 event. */
static int mgmt_event_ifindex(struct nlattr *at, int alen)
{
    for (struct nlattr *a = at; alen >= (int)sizeof(struct nlattr) &&
         a->nla_len >= sizeof(struct nlattr) && a->nla_len <= alen;
         alen -= NLA_ALIGN(a->nla_len),
         a = (struct nlattr *)((uint8_t *)a + NLA_ALIGN(a->nla_len))) {
        if ((a->nla_type & NLA_TYPE_MASK) == NL80211_ATTR_IFINDEX)
            return (int)*(uint32_t *)((uint8_t *)a + NLA_HDRLEN);
    }
    return 0;
}

/* ======================================================================
 * Management relay source (U3).  REGISTER_FRAME only works when this
 * daemon owns the AP; with hostapd running it returns -EALREADY and the
 * frames go to hostapd.  A passive monitor VIF coexists with hostapd.
 * ==================================================================== */
enum { MSRC_AUTO, MSRC_NL80211, MSRC_MONITOR, MSRC_OFF };
static int g_msrc_cfg = MSRC_AUTO;
static int g_msrc = -1;
static int g_ap_owned;             /* we called START_AP ourselves */
static int g_mgmt_foreign;

static int mgmt_register(int ifindex, uint16_t frame_type)
{
    struct nl_buf m;
    if (ifindex <= 0) return -EINVAL;
    if (g_nl_family < 0 && nl_cmd_open() != 0) return -ENODEV;
    if (g_nl_evt_fd < 0) g_nl_evt_fd = nl_open_socket();
    if (g_nl_evt_fd < 0) return -ENODEV;
    nlb_init(&m, NL80211_CMD_REGISTER_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u16(&m, NL80211_ATTR_FRAME_TYPE, frame_type);
    nlb_put(&m, NL80211_ATTR_FRAME_MATCH, NULL, 0);
    int r = nl_send_ack(g_nl_evt_fd, &m);
    if (r == -EALREADY) g_mgmt_foreign = 1;
    return r;
}

static int mgmt_register_sta(int ifindex)
{
    int r1 = mgmt_register(ifindex, (11 << 4));   /* Auth            */
    int r2 = mgmt_register(ifindex, (0 << 4));    /* AssocReq        */
    int r3 = mgmt_register(ifindex, (2 << 4));    /* ReassocReq      */
    printf("mgmt: REGISTER_FRAME ifindex=%d auth=%d assoc=%d reassoc=%d%s\n",
           ifindex, r1, r2, r3,
           (r1 == -EALREADY || r2 == -EALREADY || r3 == -EALREADY) ?
           " (type owned by another process)" : "");
    fflush(stdout);
    if (r1 == -EALREADY || r2 == -EALREADY || r3 == -EALREADY)
        return -EALREADY;
    if (r1 && r2 && r3) return r1;
    return 0;
}

/* ---- U3 monitor fallback ------------------------------------------- */
#define MON_MAX 8
struct mon_ctx {
    int phy;
    int ifindex;
    int fd;
    char ifname[IF_NAMESIZE];
};
static struct mon_ctx g_mon[MON_MAX];
static int g_mon_n;

static int set_iface_up(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { close(fd); return -1; }
    ifr.ifr_flags |= IFF_UP;
    int r = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
    return r;
}

static int pmap_port_of_mac(const uint8_t mac[6])
{
    for (int i = 0; i < 128; i++)
        if (g_pmap[i].used && g_pmap[i].ifindex > 0 &&
            !memcmp(g_pmap[i].mac, mac, 6))
            return g_pmap[i].port;
    return -1;
}

static int mon_open(int ifindex)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) return -1;
    int rcv = 256 << 10;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    int one = 1;
    setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }
    /* Classic-BPF generated by
         tcpdump -dd -y IEEE802_11_RADIO \
           'type mgt and (subtype auth or subtype assoc-req or subtype reassoc-req)'
       (libpcap handles the variable-length radiotap header). */
    static struct sock_filter code[] = {
        { 0x30, 0, 0, 0x00000003 },
        { 0x64, 0, 0, 0x00000008 },
        { 0x07, 0, 0, 0x00000000 },
        { 0x30, 0, 0, 0x00000002 },
        { 0x4c, 0, 0, 0x00000000 },
        { 0x02, 0, 0, 0x00000000 },
        { 0x07, 0, 0, 0x00000000 },
        { 0x50, 0, 0, 0x00000000 },
        { 0x45, 6, 0, 0x0000000c },
        { 0x54, 0, 0, 0x000000fc },
        { 0x15, 5, 0, 0x000000b0 },
        { 0x50, 0, 0, 0x00000000 },
        { 0x45, 0, 3, 0x000000fc },
        { 0x54, 0, 0, 0x000000fc },
        { 0x15, 1, 0, 0x00000020 },
        { 0x06, 0, 0, 0x00000000 },
        { 0x06, 0, 0, 0x00040000 },
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
        .filter = code,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog,
                   sizeof(prog)) < 0)
        fprintf(stderr, "mon: BPF filter: %s\n", strerror(errno));
    return fd;
}

/* Create (or reuse) a monitor VIF on this wiphy. */
static int mon_create(int phy)
{
    char name[32];
    if (nl_cmd_open() != 0) return -1;
    snprintf(name, sizeof(name), "cm%d", phy % 100);
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_NEW_INTERFACE, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_WIPHY, (uint32_t)phy);
    nlb_put(&m, NL80211_ATTR_IFNAME, name, strlen(name) + 1);
    nlb_u32(&m, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
    nlb_flag(&m, NL80211_ATTR_SOCKET_OWNER);
    int r = nl_send_ack(g_nl_cmd_fd, &m);
    if (r == -EEXIST) {
        snprintf(name, sizeof(name), "cm%d_%d", phy % 100,
                 (int)(getpid() % 100));
        nlb_init(&m, NL80211_CMD_NEW_INTERFACE, NLM_F_ACK);
        nlb_u32(&m, NL80211_ATTR_WIPHY, (uint32_t)phy);
        nlb_put(&m, NL80211_ATTR_IFNAME, name, strlen(name) + 1);
        nlb_u32(&m, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
        nlb_flag(&m, NL80211_ATTR_SOCKET_OWNER);
        r = nl_send_ack(g_nl_cmd_fd, &m);
    }
    if (r) {
        fprintf(stderr, "mon: NEW_INTERFACE phy=%d %s: %d (%s)\n",
                phy, name, r, r < 0 ? strerror(-r) : "?");
        return -1;
    }
    int ifindex = if_nametoindex(name);
    if (ifindex <= 0) return -1;
    if (set_iface_up(name) < 0)
        fprintf(stderr, "mon: %s up: %s\n", name, strerror(errno));
    printf("mon: %s ifindex=%d on phy%d\n", name, ifindex, phy);
    fflush(stdout);
    return ifindex;
}

/* Find an already-existing monitor VIF on this wiphy (read-only).  Used in
 * legacy mode: observing through a monitor is allowed, creating one is not. */
static int mon_find_existing(int phy)
{
    char name[IF_NAMESIZE];
    int idx;

    snprintf(name, sizeof(name), "cm%d", phy % 100);
    idx = read_sysfs_int(name, "ifindex");
    if (idx > 0 && nl_get_iftype(idx) == NL80211_IFTYPE_MONITOR) return idx;

    DIR *d = opendir("/sys/class/net");
    struct dirent *de;
    if (!d) return -1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (iface_phy_index(de->d_name) != phy) continue;
        idx = read_sysfs_int(de->d_name, "ifindex");
        if (idx > 0 && nl_get_iftype(idx) == NL80211_IFTYPE_MONITOR) {
            closedir(d);
            return idx;
        }
    }
    closedir(d);
    return -1;
}

static void mgmt_monitor_add(int ifindex)
{
    char ifname[IF_NAMESIZE];
    if (!if_indextoname((unsigned)ifindex, ifname)) return;
    char p[128];
    snprintf(p, sizeof(p), "/sys/class/net/%s/phy80211/index", ifname);
    if (access(p, R_OK) != 0) return;
    int phy = read_sysfs_int(ifname, "phy80211/index");
    if (phy < 0) return;
    for (int i = 0; i < g_mon_n; i++)
        if (g_mon[i].phy == phy && g_mon[i].fd >= 0) return;
    int slot = -1;
    for (int i = 0; i < g_mon_n; i++)
        if (g_mon[i].phy == phy) { slot = i; break; }
    if (slot < 0 && g_mon_n < MON_MAX) slot = g_mon_n++;
    if (slot < 0) return;
    int mi;
    if (!own_any_managed()) {
        mi = mon_find_existing(phy);
        if (mi <= 0) {
            g_mon[slot].phy = phy; g_mon[slot].fd = -1;
            g_mon[slot].ifindex = -1;
            printf("mon: no capagent VAP on phy%d and no existing monitor "
                   "VIF; not creating one\n", phy);
            fflush(stdout);
            return;
        }
    } else {
        mi = mon_create(phy);
    }
    if (mi <= 0) {
        g_mon[slot].phy = phy; g_mon[slot].fd = -1;
        g_mon[slot].ifindex = -1;
        return;
    }
    int fd = mon_open(mi);
    if (fd < 0) {
        fprintf(stderr, "mon: open ifindex=%d: %s\n", mi, strerror(errno));
        return;
    }
    g_mon[slot].phy = phy;
    g_mon[slot].ifindex = mi;
    g_mon[slot].fd = fd;
    snprintf(g_mon[slot].ifname, sizeof(g_mon[slot].ifname), "%s",
             if_indextoname((unsigned)mi, ifname) ? ifname : "?");
}

/* Retransmissions are common on a monitor.  Drop byte-identical frames
   seen within 1 s. */
static struct { uint32_t h; time_t t; } g_mdedup[64];
static int g_mdedup_i;
static int mon_is_dup(const uint8_t *fr, size_t len)
{
    uint32_t h = 2166136261u;
    size_t n = len < 64 ? len : 64;
    for (size_t i = 0; i < n; i++) { h ^= fr[i]; h *= 16777619u; }
    h ^= (uint32_t)len;
    time_t now = time(NULL);
    for (int i = 0; i < 64; i++)
        if (g_mdedup[i].t && now - g_mdedup[i].t <= 1 &&
            g_mdedup[i].h == h)
            return 1;
    g_mdedup[g_mdedup_i].h = h;
    g_mdedup[g_mdedup_i].t = now;
    g_mdedup_i = (g_mdedup_i + 1) & 63;
    return 0;
}

/* Minimal radiotap walker: report the FCS-present flag and the antenna
 * signal (dBm).  Only fields before the first namespace bit are decoded. */
static void radiotap_meta(const uint8_t *rt, size_t rlen, int *fcs,
                          int *rssi)
{
    static const struct { uint8_t align, size; } f[29] = {
        {8,8}, {1,1}, {1,1}, {2,4}, {2,2}, {1,1}, {1,1}, {2,2}, {2,2},
        {2,2}, {1,1}, {1,1}, {1,1}, {1,1}, {2,2}, {2,2}, {1,1}, {1,1},
        {4,8}, {1,3}, {4,8}, {2,12}, {8,12}, {2,12}, {2,12}, {2,12},
        {1,1}, {2,4}, {2,4}
    };
    uint32_t w[8];
    int nw = 0;
    size_t off = 4, p;

    *fcs = 0;
    *rssi = 0;
    if (rlen < 8) return;
    while (nw < 8 && off + 4 <= rlen) {
        w[nw] = (uint32_t)rt[off] | ((uint32_t)rt[off + 1] << 8) |
                ((uint32_t)rt[off + 2] << 16) | ((uint32_t)rt[off + 3] << 24);
        off += 4;
        if (!(w[nw++] & 0x80000000u)) break;
    }
    p = off;
    for (int wi = 0; wi < nw; wi++) {
        for (int bit = 0; bit < 29; bit++) {
            int idx;
            if (!(w[wi] & (1u << bit))) continue;
            if (bit == 29 || bit == 30) return;   /* namespace: stop */
            idx = bit;
            p = (p + f[idx].align - 1) / f[idx].align * f[idx].align;
            if (p + f[idx].size > rlen) return;
            if (idx == 1) *fcs = (rt[p] & 0x10) != 0;
            else if (idx == 5) *rssi = (int8_t)rt[p];
            p += f[idx].size;
        }
    }
}

static void mgmt_monitor_service(mbedtls_ssl_context *ssl)
{
    for (int i = 0; i < g_mon_n; i++) {
        if (g_mon[i].fd < 0) continue;
        for (int loop = 0; loop < 64; loop++) {
            uint8_t buf[NL_MAX_MSG];
            struct sockaddr_ll from;
            socklen_t fl = sizeof(from);
            int n = (int)recvfrom(g_mon[i].fd, buf, sizeof(buf), MSG_DONTWAIT,
                                  (struct sockaddr *)&from, &fl);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == ENOBUFS) continue;
                break;
            }
            if (n < 24) continue;
            int it = (int)(buf[2] | (buf[3] << 8));   /* radiotap length */
            if (it < 8 || it > n - 24) continue;
            int fcs = 0, rt_rssi = 0;
            radiotap_meta(buf, (size_t)it, &fcs, &rt_rssi);
            const uint8_t *fr = buf + it;
            size_t len = (size_t)(n - it);
            if (fcs && len > 4) len -= 4;             /* strip trailing FCS */
            if ((fr[0] & 0x0c) != 0) continue;        /* management only */
            int st = (fr[0] >> 4) & 0xf;
            if (st != 0 && st != 2 && st != 11) continue;
            if (st == 11) {
                if (len < 30 || fr[26] != 1 || fr[27] != 0) continue;
            }
            /* addr1 == addr3 == BSSID, addr2 != BSSID. */
            if (memcmp(fr + 4, fr + 16, 6) != 0 ||
                memcmp(fr + 10, fr + 16, 6) == 0)
                continue;
            int port = pmap_port_of_mac(fr + 16);
            if (port < 0) continue;
            if (mon_is_dup(fr, len)) continue;
            uint32_t freq = 0;
            uint8_t width = 1, band = 0;
            if (!vchan_get(port, &freq, &width, &band) || !freq) {
                struct vap *v = vap_by_bssid(fr + 16);
                if (v && v->freq) {
                    freq = v->freq;
                    band = band_code_for_freq(freq);
                }
            }
            if (!freq) {
                printf("0x2018 monitor: no channel for port 0x%04x, dropped\n",
                       port);
                fflush(stdout);
                continue;
            }
            if (!band) band = band_code_for_freq(freq);
            mgmt_send_2018(ssl, port, fr, len, freq, width, band, rt_rssi,
                           "monitor");
#ifdef CAPAGENT_LAB
            lab_monitor_frame(ssl, fr, len);
#endif
        }
    }
}

static void mgmt_monitor_watchdog(void)
{
    for (int i = 0; i < g_mon_n; i++) {
        if (g_mon[i].fd < 0) continue;
        if (g_mon[i].ifindex > 0 && if_nametoindex(g_mon[i].ifname) ==
                                   (unsigned)g_mon[i].ifindex)
            continue;
        printf("mon: %s gone, closing\n", g_mon[i].ifname);
        close(g_mon[i].fd);
        g_mon[i].fd = -1;
        g_mon[i].ifindex = -1;
    }
}

/* Resolve the relay source and (re)arm it for one VAP. */
static void mgmt_vap_add(int ifindex)
{
    if (ifindex <= 0) return;
    if (g_msrc < 0) {
        if (!own_any_managed() && wl_legacy()) {
            /* No capagent VAP yet and netifd owns the radios: REGISTER_FRAME
               belongs to wpad and a new monitor VIF would be a netdev
               creation.  Observe through an existing monitor, or stay off. */
            g_msrc = (g_msrc_cfg == MSRC_OFF) ? MSRC_OFF : MSRC_MONITOR;
            printf("mgmt: source=%s (no capagent VAP: no registration, "
                   "no VIF creation)\n",
                   g_msrc == MSRC_OFF ? "off" : "monitor");
        } else if (g_msrc_cfg == MSRC_AUTO) {
            g_msrc = g_ap_owned ? MSRC_NL80211 : MSRC_MONITOR;
        } else {
            g_msrc = g_msrc_cfg;
        }
        if (own_any_managed() || !wl_legacy())
            printf("mgmt: source=%s%s\n",
                   g_msrc == MSRC_NL80211 ? "nl80211" :
                   g_msrc == MSRC_MONITOR ? "monitor" : "off",
                   g_msrc == MSRC_MONITOR && !g_ap_owned ?
                   " (hostapd owns REGISTER_FRAME)" : "");
        fflush(stdout);
    }
    if (g_msrc == MSRC_OFF) return;
    if (g_msrc == MSRC_NL80211) {
        int r = mgmt_register_sta(ifindex);
        if (r == -EALREADY || r == -EOPNOTSUPP || r == -ENODEV) {
            fprintf(stderr, "mgmt: nl80211 registration failed (%d: %s); "
                    "switching to monitor\n", r, strerror(-r));
            if (g_nl_evt_fd >= 0) { close(g_nl_evt_fd); g_nl_evt_fd = -1; }
            g_msrc = MSRC_MONITOR;
        }
    }
    if (g_msrc == MSRC_MONITOR)
        mgmt_monitor_add(ifindex);
}

/* Production nl80211 event service. */
static void mgmt_service_nl(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                            const struct cfg *c)
{
    uint8_t buf[NL_MAX_MSG];
    if (g_nl_evt_fd < 0) return;
    for (;;) {
        int n = (int)recv(g_nl_evt_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return;
        }
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type != (uint32_t)g_nl_family) continue;
            struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(nlh);
            int alen = (int)nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                                  GENL_HDRLEN);
            if (g->cmd == NL80211_CMD_FRAME) {
                int ifindex = mgmt_event_ifindex(at, alen);
                if (mlme_on_mgmt(ssl, at, alen, ifindex, c)) continue;
                mgmt_handle_frame(ssl, at, alen, 1, ifindex);
            } else if (g->cmd == NL80211_CMD_CONTROL_PORT_FRAME) {
                if (mlme_on_control_port(ssl, dc, c, at, alen)) continue;
                printf("mgmt: control-port frame (hostapd owns RX)\n");
            }
        }
    }
}

/* ---- P5: hostapd external-RSN adapter ----------------------------- */

static int parse_mac_str(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4],
               &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

static int ext_auth_bind(struct vap *v, const char *dir)
{
    struct sockaddr_un sa;
    char path[128];
    int fd;

    if (!v->used || !v->ifname[0]) return -1;
    if (v->extfd >= 0) return 0;
    snprintf(path, sizeof(path), "%s/ext-auth-%s", dir, v->ifname);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%.*s",
             (int)sizeof(sa.sun_path) - 1, path);
    unlink(path);                       /* stale socket from a previous run */
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        printf("EXT-AUTH: cannot bind %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    chmod(path, 0660);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    v->extfd = fd;
    printf("EXT-AUTH: bound %s rid=%d wid=%d\n", path, v->rid, v->wid);
    fflush(stdout);
    return 0;
}

static void ext_auth_service(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                             const struct cfg *c)
{
    for (int r = 0; r < MAX_RADIOS; r++) {
        for (int w = 0; w < 16; w++) {
            struct vap *v = &g_vap[r][w];
            if (!v->used || v->extfd < 0) continue;
            for (;;) {
                char buf[4096];
                int n = (int)recv(v->extfd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
                if (n <= 0) break;
                buf[n] = 0;
                buf[strcspn(buf, "\r\n")] = 0;
                if (!strncmp(buf, "ASSOC ", 6)) {
                    printf("EXT-AUTH: %s (ignored, 0x2018 came from mgmt)\n",
                           buf);
                } else if (!strncmp(buf, "DISCONNECT ", 11)) {
                    uint8_t mac[6];
                    uint8_t b[BODY_MAX];
                    if (parse_mac_str(buf + 11, mac) == 0) {
                        size_t z = put_el(b, 0x08, mac, 6);
                        printf("0x201a: DELSTA %02x:%02x:%02x:%02x:%02x:%02x "
                               "-> manager\n", mac[0], mac[1], mac[2],
                               mac[3], mac[4], mac[5]);
                        send_msg(ssl, TYPE_DEL_STA,
                                 (uint16_t)((v->rid << 8) | v->wid), b,
                                 (uint16_t)z);
                    }
                } else if (!strncmp(buf, "EAPOL ", 6)) {
                    char ms[32] = "", hex[3600] = "";
                    int enc = 0;
                    uint8_t mac[6];
                    uint8_t eapol[1700];
                    if (sscanf(buf + 6, "%31s %d %3599s", ms, &enc, hex) < 2)
                        continue;
                    if (parse_mac_str(ms, mac) != 0) continue;
                    size_t el = parse_hex(hex, eapol, sizeof(eapol));
                    if (!el) continue;
                    printf("EXT-AUTH: EAPOL %s enc=%d %zuB -> 0x201b\n",
                           ms, enc, el);
                    eapol_relay(ssl, dc, c,
                                (uint16_t)((v->rid << 8) | v->wid), mac,
                                eapol, el);
                } else {
                    printf("EXT-AUTH: unknown event '%s'\n", buf);
                }
            }
        }
    }
    fflush(stdout);
}

/* Drive hostapd's ieee802_1x_set_authorized() through its ctrl socket. */
static int hostapd_ctrl(const char *dir, const char *ifname, const char *cmd)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un sa;
    char path[128];
    int r;

    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(path, sizeof(path), "%s/%s", dir, ifname);
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%.*s",
             (int)sizeof(sa.sun_path) - 1, path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    r = (int)send(fd, cmd, strlen(cmd), 0);
    close(fd);
    return r < 0 ? -1 : 0;
}

static void ext_auth_authorize(const struct cfg *c, int ifindex,
                               const uint8_t mac[6])
{
    struct vap *v;
    char ifname[32], cmd[96];
    int r;

    if (!c->ext_auth_dir) return;
    v = vap_by_ifindex(ifindex);
    if (v && v->ifname[0]) snprintf(ifname, sizeof(ifname), "%s", v->ifname);
    else if (if_indextoname((unsigned)ifindex, ifname)) { /* keep name */ }
    else snprintf(ifname, sizeof(ifname), "wlan%d", ifindex);
    snprintf(cmd, sizeof(cmd), "EXT_AUTH_AUTHORIZE %02x:%02x:%02x:%02x:%02x:%02x\n",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    r = hostapd_ctrl(c->ext_auth_dir, ifname, cmd);
    if (r == 0)
        printf("EXT-AUTH: station %02x:%02x:%02x:%02x:%02x:%02x authorized\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    else
        printf("EXT-AUTH: station %02x:%02x:%02x:%02x:%02x:%02x authorize "
               "failed (hostapd socket %s/%s)\n", mac[0], mac[1], mac[2],
               mac[3], mac[4], mac[5], c->ext_auth_dir, ifname);
    fflush(stdout);
}

/* ---- 0x201F: key install + authorize (T4 exact spec) --------------- */

struct key_desc {
    int present;
    const uint8_t *key, *seq, *mac;
    size_t klen, slen, maclen;
    int idx;
    uint32_t cipher;
};

static void parse_key_desc(const uint8_t *v, size_t n, struct key_desc *d)
{
    struct tlv_it it = { v, n };
    uint16_t tag;
    const uint8_t *x;
    size_t xl;
    memset(d, 0, sizeof(*d));
    d->present = 1;
    d->cipher = 0x000fac04u;
    while (tlv_next(&it, &tag, &x, &xl)) {
        switch (tag) {
        case 0x0008: if (xl == 6) { d->mac = x; d->maclen = 6; } break;
        case 0x0053: if (xl >= 1) d->idx = x[0]; break;
        case 0x0054:
            if (xl == 4) d->cipher = ((uint32_t)x[0] << 24) |
                                     ((uint32_t)x[1] << 16) |
                                     ((uint32_t)x[2] << 8) | x[3];
            break;
        case 0x0051: d->key = x; d->klen = xl; break;
        case 0x0052: d->seq = x; d->slen = xl; break;
        default: break;
        }
    }
}

static int class_idx_from(const uint8_t *v, size_t n)
{
    struct tlv_it it = { v, n };
    uint16_t tag;
    const uint8_t *x;
    size_t xl;
    while (tlv_next(&it, &tag, &x, &xl))
        if (tag == 0x0053 && xl >= 1) return x[0];
    return -1;
}

static void handle_201f(mbedtls_ssl_context *ssl, int port,
                        const uint8_t *body, size_t len, const struct cfg *c)
{
    (void)ssl;
    struct key_desc kd[8];
    int dkind[8] = {0}, didx[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
    int dset[8] = {0};
    int nkd = 0, pending_kind = 0, pending_idx = -1;
    const uint8_t *top_mac = NULL;

    struct tlv_it it = { body, len };
    uint16_t tag;
    const uint8_t *v;
    size_t vl;
    while (tlv_next(&it, &tag, &v, &vl)) {
        if (tag == 0x0050) {
            if (nkd < (int)(sizeof(kd)/sizeof(kd[0]))) {
                /* W8: class applies per descriptor, not per message.  The
                 * class tag is emitted after the descriptor on the wire, but
                 * accept it before one as well. */
                dkind[nkd] = pending_kind;
                didx[nkd] = pending_idx;
                dset[nkd] = pending_kind || pending_idx >= 0;
                pending_kind = 0;
                pending_idx = -1;
                parse_key_desc(v, vl, &kd[nkd++]);
            }
        } else if (tag == 0x005a || tag == 0x005b) {
            int kind = (tag == 0x005b) ? 2 : 1;
            int ci = class_idx_from(v, vl);
            if (nkd > 0 && !dset[nkd - 1]) {
                dkind[nkd - 1] = kind;
                didx[nkd - 1] = ci;
                dset[nkd - 1] = 1;
            } else {
                pending_kind = kind;
                pending_idx = ci;
            }
        } else if (tag == 0x0008 && vl == 6) {
            top_mac = v;
        }
    }
    if (!nkd) {
        printf("0x201f: no 0x50 key descriptor (len=%zu)\n", len);
        fflush(stdout);
        return;
    }

    if (!wl_port_managed(xm_canon_port(port))) {
        /* A netifd/foreign BSS has its own hostapd/wpad 4-way; installing
           the manager's PTK/GTK on the same station would desynchronise it. */
        printf("0x201f: port 0x%04x is not capagent-owned, %d key(s) not "
               "installed\n", port, nkd);
        fflush(stdout);
        return;
    }

    uint8_t mac[6] = {0};
    int refreshed = 0;
    /* W33: refresh ifindex/pmap before NEW_KEY.  A netdev that hostapd or a
       reconnect recreated has a new ifindex; the cached one makes NEW_KEY
       fail with -ENODEV/-ENETDOWN (or hit a recycled, unrelated netdev). */
    int ifindex = vap_refresh_ifindex(xm_canon_port(port), mac, &refreshed);
    if (ifindex <= 0 || nl_cmd_open() != 0) {
        printf("0x201f: no ifindex/nl80211 for port 0x%04x\n", port);
        fflush(stdout);
        return;
    }

    for (int i = 0; i < nkd; i++) {
        struct key_desc *d = &kd[i];
        if (!d->key || !d->klen) {
            printf("0x201f: descriptor %d has no key bytes\n", i);
            continue;
        }
        const uint8_t *smac = d->maclen == 6 ? d->mac : top_mac;
        int ck = dkind[i], ci = didx[i];
        int pairwise = (smac && ck == 0);
        int is_igtk = (ck == 2);
        int idx = d->idx;
        if (ck && ci >= 0) idx = ci;
        uint32_t cipher = d->cipher;
        if (is_igtk && cipher == 0x000fac04u)
            cipher = 0x000fac06u;      /* BIP-CMAC-128 (T4 §3.4) */

        int r = nl_install_key(ifindex, pairwise ? smac : NULL, idx, cipher,
                               d->key, d->klen, d->seq, d->slen,
                               pairwise ? 0 : 1);
        printf("0x201f: NEW_KEY %s idx=%d cipher=%06x len=%zu ifindex=%d "
               "ret=%d (%s)\n", pairwise ? "PAIRWISE" :
               (is_igtk ? "IGTK/BIGTK" : "GROUP"), idx, cipher, d->klen,
               ifindex, r, r ? strerror(-r) : "ok");
        if (!pairwise) {
            int r2 = nl_set_default(ifindex, idx, 1, is_igtk);
            printf("0x201f: SET_KEY default idx=%d %s ret=%d (%s)\n", idx,
                   is_igtk ? (idx >= 6 ? "beacon" : "mgmt") : "group",
                   r2, r2 ? strerror(-r2) : "ok");
        } else if (r == 0 || r == -EEXIST) {
            if (g_extmux) {
                /* extmux sends EXT_AUTH_AUTHORIZE, checks the reply, retries,
                 * and drives the CAP-side 4-way timeout on failure. */
                uint16_t xp = xm_canon_port(port);
                printf("0x201f: PTK installed, authorize via extmux "
                       "port=0x%04x\n", xp);
                extmux_ptk_installed(g_extmux, xp, smac);
            } else {
                int ra = nl_sta_authorize(ifindex, smac);
                printf("0x201f: SET_STATION AUTHORIZED %02x:%02x:%02x:%02x:%02x:%02x "
                       "ret=%d (%s)\n", smac[0], smac[1], smac[2], smac[3],
                       smac[4], smac[5], ra, ra ? strerror(-ra) : "ok");
                if (ra == 0 || ra == -EEXIST)
                    ext_auth_authorize(c, ifindex, smac);
            }
        } else {
            printf("0x201f: PTK install failed, station not authorized\n");
        }
    }
    fflush(stdout);
}

/* ---- W6: 0x2019 manager Auth/Deauth/Action ------------------------- */
/* 0x2019 subtype 11 is the manager's Auth response.  With hostapd owning the
 * air it has already answered, so it is discarded.  Subtypes 12 (Deauth) and
 * 13 (Action/BTM/SA-query) are manager *commands*: they are not responses to
 * anything hostapd sent and must be transmitted. */
static void handle_2019(mbedtls_ssl_context *ssl, int port,
                        const uint8_t *body, size_t len, const struct cfg *c)
{
    const uint8_t *fr = NULL;
    uint16_t fl = 0;
    (void)ssl;

    if (!find_el(body, len, 0x3e, &fr, &fl) || fl < 24) {
        printf("0x2019: no usable 0x3e frame (len=%zu)\n", len);
        fflush(stdout);
        return;
    }
    int st = (fr[0] >> 4) & 0xf;

    /* W33: a legacy BSS belongs to netifd/wpad (or, if it were ours, to the
       in-process MLME).  Never transmit manager frames in legacy mode. */
    if (!wl_port_managed(xm_canon_port(port))) {
        printf("0x2019 subtype %d: port 0x%04x is not capagent-owned, "
               "not transmitted\n", st, port);
        fflush(stdout);
        return;
    }
    uint16_t xp = xm_canon_port(port);
    uint8_t bssid[6] = {0};
    int ifindex = vap_ifindex(xp, bssid);
    uint32_t freq = 0;
    uint8_t width = 1, band = 0;
    if (!vchan_get(xp, &freq, &width, &band) || !freq) {
        struct vap *v = vap_by_ifindex(ifindex);
        if (v) freq = v->freq;
    }
    if (ifindex <= 0) {
        printf("0x2019 subtype %d: no ifindex for port 0x%04x\n", st, xp);
        fflush(stdout);
        return;
    }
    /* W36: when the CAP owns this BSS's MLME, the manager's frame is the
     * only response on air (there is no hostapd).  Transmit it on the AP
     * vif without WIPHY_FREQ (W5). */
    int mlme_owned = mlme_owns_ifindex(ifindex);
    if (st == 11 && !mlme_owned) {
        printf("0x2019 auth-resp: discarded (hostapd answered on air)\n");
        fflush(stdout);
        return;
    }
    if (st != 11 && st != 12 && st != 13) {
        printf("0x2019 subtype %d: not transmitted (unsupported)\n", st);
        fflush(stdout);
        return;
    }
    const uint8_t *sta = fr + 4;                 /* addr1 */
    int r = mlme_owned ? mlme_tx_mgmt(ifindex, fr, fl)
                       : (nl_cmd_open() == 0 ?
                          nl_mgmt_tx(ifindex, freq, fr, fl) : -1);
    printf("0x2019 %s -> %02x:%02x:%02x:%02x:%02x:%02x port=0x%04x "
           "ifindex=%d freq=%u len=%u ret=%d (%s)\n",
           st == 11 ? "auth-resp" : (st == 12 ? "deauth" : "action"),
           sta[0], sta[1], sta[2], sta[3], sta[4], sta[5], xp, ifindex,
           freq, fl, r, r ? strerror(-r) : "ok");
    if (st == 12) {
        /* The manager has already removed the peer; drop local state too.
         * Do not send 0x201a back for a manager-initiated deauth. */
        if (g_extmux) {
            struct extmux_vap *v = extmux_vap_by_port(g_extmux, xp);
            extmux_forget(g_extmux, xp, sta, 0);
            if (r && v) {
                char cmd[96], reply[64];
                snprintf(cmd, sizeof(cmd),
                         "DEAUTHENTICATE %02x:%02x:%02x:%02x:%02x:%02x 15\n",
                         sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
                if (cap_hostapd_ctrl(c, v->ifname, cmd, reply,
                                     sizeof(reply)) == 0)
                    printf("0x2019 deauth: hostapd fallback -> %s\n", reply);
            }
        }
    }
    fflush(stdout);
}

/* ======================================================================
 * W8: extmux glue — one AF_UNIX ext-auth socket per BSS, sessions keyed
 * by (port, STA MAC), hostapd ctrl transaction checking, CAP-side 4-way
 * deadline/retry, restart journal and resync.
 * ==================================================================== */

struct xm_ctx {
    mbedtls_ssl_context *ssl;
    struct dc_ctx *dc;
    const struct cfg *c;
};
static struct xm_ctx g_xmctx;

static void xm_log(void *ctx, const char *msg)
{
    (void)ctx;
    printf("EXTMUX: %s\n", msg);
    fflush(stdout);
}

/* Blocking one-shot hostapd ctrl command, used only on timeout/deauth and
 * resync paths — never in the EAPOL hot path. */
static int cap_hostapd_ctrl(const struct cfg *c, const char *ifname,
                            const char *cmd, char *reply, size_t rlen)
{
    struct sockaddr_un sa, src;
    char path[108], aname[80];
    int fd, n, r = -1;
    const char *dir = c->ext_ctrl_dir ? c->ext_ctrl_dir : c->ext_auth_dir;

    if (!dir || !ifname || !cmd || !reply || rlen < 2) return -1;
    snprintf(path, sizeof(path), "%s/%s", dir, ifname);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&src, 0, sizeof(src));
    src.sun_family = AF_UNIX;
    n = snprintf(aname, sizeof(aname), "capagent.%ld.%s", (long)getpid(),
                 ifname);
    if (n < 0 || (size_t)n >= sizeof(aname)) goto out;
    src.sun_path[0] = 0;
    memcpy(src.sun_path + 1, aname, (size_t)n);
    if (bind(fd, (struct sockaddr *)&src,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n)) != 0)
        goto out;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (sendto(fd, cmd, strlen(cmd), 0, (struct sockaddr *)&sa,
               (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                           strlen(path) + 1)) < 0)
        goto out;
    {
        struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pf, 1, 300) <= 0) goto out;
        n = (int)recv(fd, reply, rlen - 1, 0);
        if (n < 0) goto out;
        reply[n] = 0;
        reply[strcspn(reply, "\r\n")] = 0;
        r = 0;
    }
out:
    close(fd);
    return r;
}

static int xm_on_eapol(void *ctx, const struct extmux_vap *v,
                       const uint8_t mac[6], const uint8_t *eapol, size_t len,
                       int encrypted)
{
    struct xm_ctx *x = ctx;
    eapol_relay(x->ssl, x->dc, x->c, v->port, mac, eapol, len);
    (void)encrypted;
    return 0;
}

static int xm_on_delsta(void *ctx, const struct extmux_vap *v,
                        const uint8_t mac[6])
{
    struct xm_ctx *x = ctx;
    uint8_t b[BODY_MAX];
    size_t z = put_el(b, 0x08, mac, 6);
    printf("EXTMUX: 0x201a DELSTA %02x:%02x:%02x:%02x:%02x:%02x "
           "port=0x%04x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           v->port);
    fflush(stdout);
    return send_msg(x->ssl, TYPE_DEL_STA, v->port, b, (uint16_t)z);
}

static int xm_on_deauth(void *ctx, const struct extmux_vap *v,
                        const uint8_t mac[6], int reason)
{
    struct xm_ctx *x = ctx;
    char cmd[96], reply[64];
    snprintf(cmd, sizeof(cmd),
             "DEAUTHENTICATE %02x:%02x:%02x:%02x:%02x:%02x %d\n",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reason);
    if (cap_hostapd_ctrl(x->c, v->ifname, cmd, reply, sizeof(reply)) == 0)
        printf("EXTMUX: DEAUTH %02x:%02x:%02x:%02x:%02x:%02x -> %s\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], reply);
    fflush(stdout);
    return 0;
}

static int xm_on_direct(void *ctx, const struct extmux_vap *v,
                        const uint8_t mac[6], const uint8_t *eapol, size_t len)
{
    (void)ctx;
    if (nl_cmd_open() != 0) return -1;
    return nl_control_port_tx(v->ifindex, mac, eapol, len);
}

static void xm_on_authorized(void *ctx, const struct extmux_vap *v,
                             const uint8_t mac[6])
{
    (void)ctx;
    printf("EXTMUX: authorized port=0x%04x %02x:%02x:%02x:%02x:%02x:%02x "
           "if=%s\n", v->port, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           v->ifname);
    fflush(stdout);
}

/* Map any manager-side port alias for a VAP onto extmux's canonical port. */
static uint16_t xm_canon_port(int port)
{
    struct extmux_vap *v;
    if (!g_extmux) return (uint16_t)port;
    v = extmux_vap_by_port(g_extmux, (uint16_t)port);
    if (v) return v->port;
    {
        int ifindex = 0;
        char name[IF_NAMESIZE];
        pmap_get(port, &ifindex, NULL);
        if (ifindex > 0 && if_indextoname((unsigned)ifindex, name)) {
            v = extmux_vap_by_ifname(g_extmux, name);
            if (v) return v->port;
        }
    }
    return (uint16_t)port;
}

/* Register one provisioned VAP with the relay (idempotent).  Called from
 * 0x500b (netdev created) and 0x6016 (start). */
static void cap_vap_ready(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t mac[6], const struct cfg *c)
{
    struct vap *vp;
    uint16_t port;
    unsigned freq = 0, width = 0;

    if (ifindex <= 0 || !ifname || !*ifname) return;
    port = (uint16_t)((phy << 8) | (vapid & 0xff));
    pmap_set(port, ifindex, mac);
    if (!vchan_get(port, NULL, NULL, NULL)) {
        iface_chan(ifname, &freq, &width);
        if (freq)
            vchan_set(port, freq, (uint8_t)(width ? width : 1),
                      band_code_for_freq(freq));
    }

    /* Only a capagent-owned port may bind a relay socket.  A netifd/foreign
       BSS keeps the pmap entry as read-only addressing knowledge. */
    if (!wl_port_managed(port)) {
        printf("wl: %s is not capagent-owned (no relay)\n", ifname);
        fflush(stdout);
        return;
    }

    vp = vap_get(phy, vapid);
    if (g_extmux) {
        if (extmux_vap_by_port(g_extmux, port) ||
            extmux_vap_by_ifname(g_extmux, ifname))
            return;
        if (extmux_add_vap(g_extmux, port, ifname, ifindex,
                           mac ? mac : (vp ? vp->bssid : NULL)) == 0) {
            printf("EXTMUX: registered %s port=0x%04x ifindex=%d\n",
                   ifname, port, ifindex);
            fflush(stdout);
        }
    } else if (c->ext_auth_dir && vp) {
        ext_auth_bind(vp, c->ext_auth_dir);
    }
}

/* Re-adoption is ownership-driven now (W34): the journal says which names
 * are ours and own_restore_vaps() registers exactly those with extmux. */
static void cap_extmux_restore(const struct cfg *c)
{
    own_restore_vaps(c);
}

/* Enumerate the stations hostapd still has and adopt them.  Authorized
 * stations keep the data path; the rest are forced to reauthenticate. */
static void cap_extmux_resync(void)
{
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++) {
        struct extmux_vap *v = extmux_vap_at(g_extmux, i);
        char cmd[160], line[256], macs[40];
        uint8_t pending[6];
        int have = 0, auth = 0;
        FILE *p;

        if (!v) continue;
        snprintf(cmd, sizeof(cmd), "iw dev %s station dump 2>/dev/null",
                 v->ifname);
        p = popen(cmd, "r");
        if (!p) continue;
        while (fgets(line, sizeof(line), p)) {
            unsigned m[6];
            if (sscanf(line, "Station %39s", macs) == 1 &&
                sscanf(macs, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2],
                       &m[3], &m[4], &m[5]) == 6) {
                if (have)
                    extmux_adopt(g_extmux, v->port, pending, v->ifindex, auth);
                for (int k = 0; k < 6; k++) pending[k] = (uint8_t)m[k];
                have = 1;
                auth = 0;
                continue;
            }
            if (strstr(line, "authorized:"))
                auth = strstr(line, "yes") != NULL;
        }
        if (have)
            extmux_adopt(g_extmux, v->port, pending, v->ifindex, auth);
        pclose(p);
    }
}

static void cap_extmux_start(struct cfg *c, mbedtls_ssl_context *ssl,
                             struct dc_ctx *dc)
{
    struct extmux_cb cb = {
        .ctx = &g_xmctx,
        .log = xm_log,
        .on_eapol = xm_on_eapol,
        .on_delsta = xm_on_delsta,
        .on_deauth = xm_on_deauth,
        .on_direct_tx = xm_on_direct,
        .on_authorized = xm_on_authorized,
    };
    struct extmux_stats st;

    if (!c->ext_auth_dir || g_extmux || c->no_extmux) return;
    memset(&g_xmctx, 0, sizeof(g_xmctx));
    g_xmctx.ssl = ssl;
    g_xmctx.dc = dc;
    g_xmctx.c = c;
    g_extmux = extmux_new(c->ext_auth_dir,
                          c->ext_ctrl_dir ? c->ext_ctrl_dir
                                          : c->ext_auth_dir, &cb);
    if (!g_extmux) {
        printf("EXTMUX: init failed for %s\n", c->ext_auth_dir);
        fflush(stdout);
        return;
    }
    extmux_set_timeouts(g_extmux,
                        (unsigned)(c->fourway_ms > 0 ? c->fourway_ms : 10000),
                        (unsigned)(c->m1_retry_ms > 0 ? c->m1_retry_ms : 3000),
                        1000);
    if (c->state_file) extmux_load(g_extmux, c->state_file);
    cap_extmux_restore(c);
    extmux_resync_begin(g_extmux);
    cap_extmux_resync();
    extmux_resync_finish(g_extmux);
    extmux_stats(g_extmux, &st);
    printf("EXTMUX: ready vaps=%u sessions=%u authorized=%u dir=%s\n",
           st.vaps, st.sessions, st.authorized, c->ext_auth_dir);
    fflush(stdout);
}

static void cap_extmux_stop(const struct cfg *c)
{
    if (!g_extmux) return;
    if (c->state_file) extmux_save(g_extmux, c->state_file);
    extmux_free(g_extmux);
    g_extmux = NULL;
    printf("EXTMUX: stopped\n");
    fflush(stdout);
}

/* Restored from 5364e76: used by the in-CAP MLME path (mlme.inc). */
static int mgmt_open(void)
{
    static int joined;
    int grp;
    if (g_nl_evt_fd < 0) {
        if (nl_cmd_open() != 0) return -1;
        g_nl_evt_fd = nl_open_socket();
        if (g_nl_evt_fd < 0) return -1;
    }
    if (joined) return 0;
    grp = nl_resolve_group(g_nl_evt_fd, "mlme");
    if (grp >= 0)
        setsockopt(g_nl_evt_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                   &grp, sizeof(grp));
    joined = 1;
    printf("mgmt: event socket=%d mlme-group=%d\n", g_nl_evt_fd, grp);
    fflush(stdout);
    return 0;
}
