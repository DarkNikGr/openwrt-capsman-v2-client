/* lab.inc — CAPAGENT_LAB: hwsim AP, mgmt relay, test injection
 * Part of capagent.c (single translation unit; included in order). */

/* ======================================================================
 * Lab harness (compile with -DCAPAGENT_LAB): a minimal in-process AP so
 * the full chain can be exercised on mac80211_hwsim without hostapd.
 * Production builds leave this out; hostapd owns the AP then.
 * ==================================================================== */
#ifdef CAPAGENT_LAB
static int g_lab_ifindex;
static uint8_t g_lab_bssid[6];
static char g_lab_ifname[32];




static int lab_ack(struct nl_buf *m)
{
    if (g_nl_evt_fd < 0) return -ENODEV;
    return nl_send_ack(g_nl_evt_fd, m);
}

static int lab_set_iftype_ap(int ifindex)
{
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_SET_INTERFACE, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u32(&m, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
    return lab_ack(&m);
}

static int lab_stop_ap(int ifindex)
{
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_STOP_AP, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    return lab_ack(&m);
}

static const uint8_t lab_rates[8] =
    { 0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24 };
static const uint8_t lab_xrates[4] = { 0x30,0x48,0x60,0x6c };

static void lab_beacon(const char *ssid, int chan, uint8_t *head,
                       uint8_t *tail, int *hl, int *tl)
{
    static const uint8_t bcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
    uint8_t *p = head;
    int sl = (int)strlen(ssid);
    *p++ = 0x80; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    memcpy(p, bcast, 6); p += 6;
    memcpy(p, g_lab_bssid, 6); p += 6;
    memcpy(p, g_lab_bssid, 6); p += 6;
    *p++ = 0x00; *p++ = 0x00;
    memset(p, 0, 8); p += 8;
    *p++ = 0x00; *p++ = 0x64;
    *p++ = 0x31; *p++ = 0x04;                 /* ESS|Privacy|ShortPreamble|ShortSlot */
    *p++ = 0; *p++ = (uint8_t)sl;
    memcpy(p, ssid, sl); p += sl;
    *p++ = 1; *p++ = 8; memcpy(p, lab_rates, 8); p += 8;
    *p++ = 3; *p++ = 1; *p++ = (uint8_t)chan;
    *p++ = 5; *p++ = 4; *p++ = 0; *p++ = 2; *p++ = 0; *p++ = 0;
    *hl = (int)(p - head);

    p = tail;
    *p++ = 42; *p++ = 1; *p++ = 0x00;
    *p++ = 50; *p++ = 4; memcpy(p, lab_xrates, 4); p += 4;
    *p++ = 48; *p++ = 20;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x0f; *p++ = 0xac; *p++ = 0x04;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x0f; *p++ = 0xac; *p++ = 0x04;
    *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x0f; *p++ = 0xac; *p++ = 0x02;
    *p++ = 0x00; *p++ = 0x00;
    *tl = (int)(p - tail);
}

static int lab_start_ap(int ifindex, const char *ssid, int chan)
{
    struct nl_buf m;
    uint8_t head[512], tail[256];
    int hl, tl;
    uint32_t ciphers[1] = { 0x000fac04 };
    uint32_t akm[1] = { 0x000fac02 };
    lab_beacon(ssid, chan, head, tail, &hl, &tl);
    nlb_init(&m, NL80211_CMD_START_AP, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_put(&m, NL80211_ATTR_SSID, ssid, strlen(ssid));
    nlb_u32(&m, NL80211_ATTR_BEACON_INTERVAL, 100);
    nlb_u32(&m, NL80211_ATTR_DTIM_PERIOD, 2);
    nlb_put(&m, NL80211_ATTR_BEACON_HEAD, head, (size_t)hl);
    nlb_put(&m, NL80211_ATTR_BEACON_TAIL, tail, (size_t)tl);
    nlb_u32(&m, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
    nlb_u32(&m, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    nlb_flag(&m, NL80211_ATTR_PRIVACY);
    nlb_u32(&m, NL80211_ATTR_WIPHY_FREQ, (uint32_t)(2407 + chan * 5));
    nlb_u32(&m, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);
    nlb_flag(&m, NL80211_ATTR_CONTROL_PORT);
    nlb_u16(&m, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_EAPOL);
    /* These two make cfg80211 unicast control-port frames to this socket. */
    nlb_flag(&m, NL80211_ATTR_CONTROL_PORT_OVER_NL80211);
    nlb_flag(&m, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    nlb_flag(&m, NL80211_ATTR_SOCKET_OWNER);
    nlb_put(&m, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, ciphers, 4);
    nlb_u32(&m, NL80211_ATTR_CIPHER_SUITE_GROUP, 0x000fac04);
    nlb_u32(&m, NL80211_ATTR_WPA_VERSIONS, 2);
    nlb_put(&m, NL80211_ATTR_AKM_SUITES, akm, 4);
    return lab_ack(&m);
}

static int lab_register_mgmt(int ifindex, uint16_t fc)
{
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_REGISTER_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u16(&m, NL80211_ATTR_FRAME_TYPE, fc);
    nlb_put(&m, NL80211_ATTR_FRAME_MATCH, NULL, 0);
    return lab_ack(&m);
}

static int lab_send_mgmt(int ifindex, const uint8_t *fr, size_t len, int freq)
{
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u32(&m, NL80211_ATTR_WIPHY_FREQ, (uint32_t)freq);
    nlb_put(&m, NL80211_ATTR_FRAME, fr, len);
    return lab_ack(&m);
}

static int lab_add_station(int ifindex, const uint8_t mac[6], uint16_t capab,
                           const uint8_t *rates, int rl)
{
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_NEW_STATION, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    nlb_u16(&m, NL80211_ATTR_STA_AID, 1);
    nlb_u16(&m, NL80211_ATTR_STA_LISTEN_INTERVAL, 1);
    nlb_u16(&m, NL80211_ATTR_STA_CAPABILITY, capab);
    nlb_put(&m, NL80211_ATTR_STA_SUPPORTED_RATES, rates, (size_t)rl);
    return lab_ack(&m);
}

static int lab_ap_setup(const struct cfg *c)
{
    if (!c->lab_iface) return -1;
    snprintf(g_lab_ifname, sizeof(g_lab_ifname), "%s", c->lab_iface);
    g_lab_ifindex = if_nametoindex(g_lab_ifname);
    if (g_lab_ifindex <= 0) {
        fprintf(stderr, "lab: no interface %s\n", g_lab_ifname);
        return -1;
    }
    if (nl_cmd_open() != 0) return -1;
    g_nl_evt_fd = nl_open_socket();
    if (g_nl_evt_fd < 0) return -1;

    read_sysfs_mac(g_lab_ifname, g_lab_bssid);
    int r = lab_set_iftype_ap(g_lab_ifindex);
    printf("lab: SET_INTERFACE AP ret=%d\n", r);
    lab_stop_ap(g_lab_ifindex);
    read_sysfs_mac(g_lab_ifname, g_lab_bssid);
    r = lab_start_ap(g_lab_ifindex, c->lab_ssid, c->lab_chan);
    printf("lab: START_AP %s chan=%d bssid=%02x:%02x:%02x:%02x:%02x:%02x "
           "ret=%d\n", c->lab_ssid, c->lab_chan, g_lab_bssid[0],
           g_lab_bssid[1], g_lab_bssid[2], g_lab_bssid[3], g_lab_bssid[4],
           g_lab_bssid[5], r);
    if (r) return r;
    r = lab_register_mgmt(g_lab_ifindex, (11 << 4));      /* auth       */
    printf("lab: REGISTER_FRAME auth ret=%d\n", r);
    r = lab_register_mgmt(g_lab_ifindex, (0 << 4));       /* assoc req  */
    printf("lab: REGISTER_FRAME assoc ret=%d\n", r);
    /* The lab manager sends port 0x0000; map it to this interface. */
    pmap_set(0, g_lab_ifindex, g_lab_bssid);
    fflush(stdout);
    return 0;
}

static void lab_assoc_event(mbedtls_ssl_context *ssl, const uint8_t *fr,
                            size_t len)
{
    uint8_t b[BODY_MAX];
    size_t n = 0;
    uint8_t freq[4];
    put32(freq, 2412u);
    n += put_el(b + n, 0x3e, fr, (uint16_t)len);
    n += put_el(b + n, 0x3f, freq, 4);
    if (send_msg(ssl, TYPE_ASSOC_FRAME, 0, b, (uint16_t)n) == 0)
        printf("0x2018: assoc frame %zuB -> manager\n", len);
    else
        printf("0x2018: send failed\n");
    fflush(stdout);
}

static void lab_handle_mgmt(mbedtls_ssl_context *ssl, const uint8_t *f,
                            size_t len)
{
    if (len < 24) return;
    uint16_t fc = (uint16_t)(f[0] | (f[1] << 8));
    int stype = (fc >> 4) & 0xf;
    const uint8_t *sta = f + 10;
    uint8_t out[256];
    int n = 0;

    if (stype == 11) {                       /* authentication */
        if (len < 30) return;
        uint16_t alg = (uint16_t)(f[24] | (f[25] << 8));
        uint16_t tr = (uint16_t)(f[26] | (f[27] << 8));
        if (alg != 0 || tr != 1) return;
        out[n++] = 0xb0; out[n++] = 0x00; out[n++] = 0; out[n++] = 0;
        memcpy(out + n, sta, 6); n += 6;
        memcpy(out + n, g_lab_bssid, 6); n += 6;
        memcpy(out + n, g_lab_bssid, 6); n += 6;
        out[n++] = 0; out[n++] = 0;
        out[n++] = 0; out[n++] = 0;
        out[n++] = 2; out[n++] = 0;
        out[n++] = 0; out[n++] = 0;
        lab_send_mgmt(g_lab_ifindex, out, (size_t)n, 2412);
    } else if (stype == 0) {                 /* association request */
        if (len < 28) return;
        uint16_t capab = (uint16_t)(f[24] | (f[25] << 8));
        uint8_t rates[16];
        int rl = 0;
        for (size_t i = 28; i + 1 < len; i += 2 + f[i + 1]) {
            if (i + 2 + f[i + 1] > len) break;
            if (f[i] == 1 && rl == 0) {
                rl = f[i + 1] < sizeof(rates) ? f[i + 1] : (int)sizeof(rates);
                memcpy(rates, f + i + 2, (size_t)rl);
            }
        }
        printf("lab: ASSOC-REQ %02x:%02x:%02x:%02x:%02x:%02x\n",
               sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
        out[n++] = 0x10; out[n++] = 0x00; out[n++] = 0; out[n++] = 0;
        memcpy(out + n, sta, 6); n += 6;
        memcpy(out + n, g_lab_bssid, 6); n += 6;
        memcpy(out + n, g_lab_bssid, 6); n += 6;
        out[n++] = 0; out[n++] = 0;
        out[n++] = 0x31; out[n++] = 0x04;
        out[n++] = 0; out[n++] = 0;
        out[n++] = 0x01; out[n++] = 0xc0;
        out[n++] = 1; out[n++] = 8; memcpy(out + n, lab_rates, 8); n += 8;
        out[n++] = 50; out[n++] = 4; memcpy(out + n, lab_xrates, 4); n += 4;
        out[n++] = 48; out[n++] = 20;
        out[n++] = 0x01; out[n++] = 0x00;
        out[n++] = 0x00; out[n++] = 0x0f; out[n++] = 0xac; out[n++] = 0x04;
        out[n++] = 0x01; out[n++] = 0x00;
        out[n++] = 0x00; out[n++] = 0x0f; out[n++] = 0xac; out[n++] = 0x04;
        out[n++] = 0x01; out[n++] = 0x00;
        out[n++] = 0x00; out[n++] = 0x0f; out[n++] = 0xac; out[n++] = 0x02;
        out[n++] = 0x00; out[n++] = 0x00;
        lab_send_mgmt(g_lab_ifindex, out, (size_t)n, 2412);
        int r = lab_add_station(g_lab_ifindex, sta, capab,
                                rl ? rates : lab_rates, rl ? rl : 8);
        printf("lab: NEW_STATION ret=%d (%s)\n", r, r ? strerror(-r) : "ok");
        lab_assoc_event(ssl, f, len);
    }
    fflush(stdout);
}

static struct nlattr *lab_attr(struct nlattr *head, int len, int type)
{
    for (struct nlattr *a = head;
         len >= (int)sizeof(struct nlattr) && a->nla_len >= sizeof(struct nlattr) &&
         a->nla_len <= len;
         len -= NLA_ALIGN(a->nla_len),
         a = (struct nlattr *)((uint8_t *)a + NLA_ALIGN(a->nla_len))) {
        if ((a->nla_type & NLA_TYPE_MASK) == type) return a;
    }
    return NULL;
}

static void lab_service_nl(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                           const struct cfg *c)
{
    uint8_t buf[NL_MAX_MSG];
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
                struct nlattr *fa = lab_attr(at, alen, NL80211_ATTR_FRAME);
                if (fa)
                    lab_handle_mgmt(ssl, (uint8_t *)fa + NLA_HDRLEN,
                                    fa->nla_len - NLA_HDRLEN);
            } else if (g->cmd == NL80211_CMD_CONTROL_PORT_FRAME) {
                struct nlattr *ma = lab_attr(at, alen, NL80211_ATTR_MAC);
                struct nlattr *fa = lab_attr(at, alen, NL80211_ATTR_FRAME);
                struct nlattr *ea = lab_attr(at, alen,
                                             NL80211_ATTR_CONTROL_PORT_ETHERTYPE);
                uint16_t et = ETH_P_EAPOL;
                if (ea) et = *(uint16_t *)((uint8_t *)ea + NLA_HDRLEN);
                if (!ma || !fa || et != ETH_P_EAPOL) continue;
                const uint8_t *sta = (uint8_t *)ma + NLA_HDRLEN;
                const uint8_t *fr = (uint8_t *)fa + NLA_HDRLEN;
                size_t fl = fa->nla_len - NLA_HDRLEN;
                eapol_strip(&fr, &fl);
                eapol_relay(ssl, dc, c, 0, sta, fr, fl);
            }
        }
    }
}

static void lab_shutdown(void)
{
    if (g_nl_evt_fd >= 0 && g_lab_ifindex > 0)
        lab_stop_ap(g_lab_ifindex);
}
#endif /* CAPAGENT_LAB */

/* ---- lab/test: inject 802.11 Auth+AssocReq as 0x2018 ------------------ */
static void put16le(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }

static size_t mkinfo_ie(uint8_t *p, uint8_t id, const uint8_t *d, uint8_t n)
{
    p[0] = id; p[1] = n;
    if (n) memcpy(p + 2, d, n);
    return 2 + n;
}

static size_t mkauth(uint8_t *f, const uint8_t *bssid, const uint8_t *sta)
{
    uint8_t *p = f;
    put16le(p, 0x00b0); p += 2;          /* mgmt, subtype 11 (Auth) */
    put16le(p, 0); p += 2;
    memcpy(p, bssid, 6); p += 6;
    memcpy(p, sta, 6); p += 6;
    memcpy(p, bssid, 6); p += 6;
    put16le(p, 0); p += 2;               /* seq */
    put16le(p, 0); p += 2;               /* alg open */
    put16le(p, 1); p += 2;               /* seq 1 */
    put16le(p, 0); p += 2;               /* status */
    return (size_t)(p - f);
}

static size_t mkassoc(uint8_t *f, const uint8_t *bssid, const uint8_t *sta,
                      const char *ssid)
{
    static const uint8_t rates[4] = { 0x82, 0x84, 0x8b, 0x96 };
    static const uint8_t extcap[4] = { 0x00, 0x00, 0x40, 0x00 };
    static const uint8_t rsn[20] = {
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f,
        0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00
    };
    uint8_t *p = f;
    put16le(p, 0x0000); p += 2;          /* mgmt, subtype 0 (AssocReq) */
    put16le(p, 0); p += 2;
    memcpy(p, bssid, 6); p += 6;
    memcpy(p, sta, 6); p += 6;
    memcpy(p, bssid, 6); p += 6;
    put16le(p, 0); p += 2;
    put16le(p, 0x0431); p += 2;          /* capab */
    put16le(p, 10); p += 2;              /* listen */
    p += mkinfo_ie(p, 0, (const uint8_t *)ssid, (uint8_t)strlen(ssid));
    p += mkinfo_ie(p, 1, rates, sizeof(rates));
    p += mkinfo_ie(p, 0x30, rsn, sizeof(rsn));
    p += mkinfo_ie(p, 0x7f, extcap, sizeof(extcap));
    return (size_t)(p - f);
}

static void send_2018(mbedtls_ssl_context *ssl, int phy, int vap,
                      const uint8_t *bssid, const uint8_t *sta,
                      int freq, const char *ssid)
{
    uint8_t fr[256], b[BODY_MAX], ch[32];
    size_t fl, n = 0, cn = 0;
    uint8_t w = (phy & 1) ? 3 : 1, band = (phy & 1) ? 0x03 : 0x81;
    fl = mkauth(fr, bssid, sta);
    uint8_t cf[4];
    cf[0] = freq >> 24; cf[1] = freq >> 16; cf[2] = freq >> 8; cf[3] = freq;
    cn += put_el(ch + cn, 0x0b, cf, 4);
    cn += put_el(ch + cn, 0x0c, &w, 1);
    cn += put_el(ch + cn, 0x10, &band, 1);
    n += put_el(b + n, 0x3e, fr, (uint16_t)fl);
    uint8_t sig[4] = { 0xff, 0xff, 0xff, 0xce };   /* -50 dBm */
    n += put_el(b + n, 0x0a, ch, (uint16_t)cn);
    n += put_el(b + n, 0x3f, sig, 4);
    send_msg(ssl, 0x2018, (uint16_t)((phy << 8) | vap), b, (uint16_t)n);
    fl = mkassoc(fr, bssid, sta, ssid);
    n = 0;
    n += put_el(b + n, 0x3e, fr, (uint16_t)fl);
    n += put_el(b + n, 0x0a, ch, (uint16_t)cn);
    n += put_el(b + n, 0x3f, sig, 4);
    send_msg(ssl, 0x2018, (uint16_t)((phy << 8) | vap), b, (uint16_t)n);
    printf("inject: phy=%d vap=%d sta=%02x:%02x:%02x:%02x:%02x:%02x "
           "bssid=%02x:%02x:%02x:%02x:%02x:%02x freq=%d\n",
           phy, vap, sta[0], sta[1], sta[2], sta[3], sta[4], sta[5],
           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], freq);
    fflush(stdout);
}

static void maybe_inject_assoc(mbedtls_ssl_context *ssl, const struct cfg *c)
{
    static int done;
    if (!c->inject_assoc || done) return;
    done = 1;
    for (int phy = 0; phy < c->nradios; phy++) {
        for (int vap = 0; vap < 8; vap++) {
            char ifn[32], cmd[96], line[256], ssid[33] = "test";
            uint8_t bssid[6] = {0};
            int freq = (phy & 1) ? 5180 : 2437, have_bssid = 0;
            snprintf(ifn, sizeof(ifn), "phy%d-ap%d", phy, vap);
            snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s info 2>/dev/null", ifn);
            FILE *fp = popen(cmd, "r");
            if (!fp) continue;
            while (fgets(line, sizeof(line), fp)) {
                unsigned int m[6]; int ch, f2;
                if (sscanf(line, " addr %x:%x:%x:%x:%x:%x",
                           &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                    for (int k = 0; k < 6; k++) bssid[k] = (uint8_t)m[k];
                    have_bssid = 1;
                } else if (sscanf(line, " channel %d (%d MHz)", &ch, &f2) == 2) {
                    freq = f2;
                }
            }
            pclose(fp);
            if (!have_bssid) continue;
            snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s station dump 2>/dev/null", ifn);
            fp = popen(cmd, "r");
            int sent_vap = 0;
            if (fp) {
                while (fgets(line, sizeof(line), fp)) {
                    unsigned int m[6];
                    if (sscanf(line, "Station %x:%x:%x:%x:%x:%x",
                               &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                        uint8_t sta[6];
                        for (int k = 0; k < 6; k++) sta[k] = (uint8_t)m[k];
                        send_2018(ssl, phy, vap, bssid, sta, freq, ssid);
                        sent_vap = 1;
                    }
                }
                pclose(fp);
            }
            if (!sent_vap) {   /* lab: no local station, manager accepts synthetic */
                uint8_t syn[6] = { 0x02, 0x00, 0x00, 0x00, 0x12, 0x34 };
                send_2018(ssl, phy, vap, bssid, syn, freq, ssid);
            }
        }
    }
}

