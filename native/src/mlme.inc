/* mlme.inc — in-CAP MLME for one manager-provisioned VAP (W36)
 *
 * Replaces hostapd for the selected BSS on the CAP:
 *   0x6016  -> build beacon head/tail (SSID + manager IEs) -> START_AP
 *   Auth    -> answered locally (open system)
 *   Assoc   -> NEW_STATION, then the real frame is relayed as 0x2018
 *   0x6019  -> manager's AssocResp is completed (rates/capab/AID) and TX'd
 *   0x2019  -> manager Auth/Deauth/Action frames are TX'd
 *   EAPOL   -> control-port RX/TX over nl80211, relayed to 0x201B/0x201C
 *   0x201F  -> existing NEW_KEY + SET_STATION(AUTHORIZED) path
 *
 * Part of capagent.c (single translation unit).  Included after mgmt.inc so
 * the EAPOL relay helpers and the VAP registry are already visible.
 */

#define MLME_MAX_FRAME 2048

struct mlme_vap {
    int used;
    int ifindex;
    int port;
    int started;
    uint8_t bssid[6];
    uint32_t freq;
    uint8_t width;
    char ssid[33];
    uint8_t ies[512];
    size_t ielen;
    int has_rsn;
    uint32_t pair;
    uint32_t group;
    uint32_t akm[8];
    int nakm;
};

static struct mlme_vap g_mlme[MAX_RADIOS][16];
static int g_mlme_on;
static int g_mlme_port = -1;

static void mlme_init(const struct cfg *c)
{
    g_mlme_on = c->mlme;
    g_mlme_port = c->mlme_port;
    memset(g_mlme, 0, sizeof(g_mlme));
    if (g_mlme_on)
        printf("mlme: enabled for port 0x%04x (no hostapd)\n",
               (unsigned)(g_mlme_port & 0xffff));
    fflush(stdout);
}

static int mlme_owns_port(int port)
{
    return g_mlme_on && (g_mlme_port < 0 ||
                         ((port & 0xffff) == (g_mlme_port & 0xffff)));
}

static struct mlme_vap *mlme_by_ifindex(int ifindex)
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_mlme[r][w].used && g_mlme[r][w].ifindex == ifindex)
                return &g_mlme[r][w];
    return NULL;
}

static int mlme_owns_ifindex(int ifindex)
{
    return mlme_by_ifindex(ifindex) != NULL;
}

/* Deterministic AID: NEW_STATION and the AssocResp use the same value. */
static uint16_t mlme_aid_for(const uint8_t mac[6])
{
    return (uint16_t)(1 + ((((uint16_t)mac[4] << 8) | mac[5]) % 2006));
}

static uint32_t mlme_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* Parse the manager's IE blob (0x04): RSN IE only; everything is also kept
 * verbatim for the beacon tail. */
static void mlme_parse_rsn(struct mlme_vap *m)
{
    size_t p = 0;
    m->has_rsn = 0;
    m->nakm = 0;
    m->pair = 0x000fac04u;
    m->group = 0x000fac04u;
    while (p + 2 <= m->ielen) {
        uint8_t id = m->ies[p], l = m->ies[p + 1];
        if (p + 2 + l > m->ielen) break;
        if (id == 48 && l >= 18) {                 /* RSN IE */
            const uint8_t *r = m->ies + p + 2;
            size_t n = l, k = 6;
            m->has_rsn = 1;
            m->group = mlme_be32(r + 2);
            int pc = r[k] | (r[k + 1] << 8);
            if (pc >= 1 && k + 6 <= n) m->pair = mlme_be32(r + k + 2);
            k += 2 + 4 * (size_t)pc;
            if (k + 2 <= n) {
                int ac = r[k] | (r[k + 1] << 8);
                for (int i = 0; i < ac && k + 2 + 4 * (size_t)i + 4 <= n &&
                     m->nakm < (int)(sizeof(m->akm) / sizeof(m->akm[0]));
                     i++) {
                    m->akm[m->nakm++] = mlme_be32(r + k + 2 + 4 * (size_t)i);
                }
            }
            return;
        }
        p += 2 + l;
    }
}

static const uint8_t mlme_rates2[8] =
    { 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };
static const uint8_t mlme_xrates[4] = { 0x30, 0x48, 0x60, 0x6c };
static const uint8_t mlme_rates5[8] =
    { 0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c };

/* 24-byte header + fixed fields + SSID/rates/DS in the head; the manager's
 * IE blob (RSN/RRM/...) in the tail.  mac80211 adds the TIM element. */
static int mlme_build_beacon(struct mlme_vap *m, uint8_t *head, int *hl,
                             uint8_t *tail, int *tl)
{
    static const uint8_t bcast[6] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint8_t *rates = (m->freq < 3000) ? mlme_rates2 : mlme_rates5;
    int sl = (int)strlen(m->ssid);
    int chan = (m->freq < 3000) ? (int)((m->freq - 2407) / 5)
                                : (int)(m->freq / 5 - 1000);
    uint8_t *p = head;

    if (sl <= 0 || sl > 32 || chan <= 0 || chan > 255) return -EINVAL;

    *p++ = 0x80; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
    memcpy(p, bcast, 6); p += 6;
    memcpy(p, m->bssid, 6); p += 6;
    memcpy(p, m->bssid, 6); p += 6;
    *p++ = 0x00; *p++ = 0x00;                  /* sequence control */
    memset(p, 0, 8); p += 8;                   /* timestamp */
    *p++ = 0x00; *p++ = 0x64;                  /* beacon interval 100 */
    {
        uint16_t cap = (uint16_t)(0x0001 | 0x0020 | 0x0400);
        if (m->has_rsn) cap |= 0x0010;         /* Privacy */
        *p++ = (uint8_t)(cap & 0xff);
        *p++ = (uint8_t)(cap >> 8);
    }
    *p++ = 0; *p++ = (uint8_t)sl;
    memcpy(p, m->ssid, (size_t)sl); p += sl;
    *p++ = 1; *p++ = 8; memcpy(p, rates, 8); p += 8;
    *p++ = 3; *p++ = 1; *p++ = (uint8_t)chan;
    *hl = (int)(p - head);

    p = tail;
    *p++ = 50; *p++ = 4; memcpy(p, mlme_xrates, 4); p += 4;
    if (m->ielen) {
        memcpy(p, m->ies, m->ielen);
        p += m->ielen;
    }
    *tl = (int)(p - tail);
    return 0;
}

/* START_AP with control-port-over-nl80211 (attrs/order per W5 §3.2). */
static int mlme_start_ap(struct mlme_vap *m)
{
    struct nl_buf b;
    uint8_t head[512], tail[768];
    int hl = 0, tl = 0;
    uint16_t width = NL80211_CHAN_WIDTH_20_NOHT;

    if (mlme_build_beacon(m, head, &hl, tail, &tl) != 0) return -EINVAL;
    if (nl_cmd_open() != 0) return -ENODEV;
    if (g_nl_evt_fd < 0) g_nl_evt_fd = nl_open_socket();
    if (g_nl_evt_fd < 0) return -ENODEV;

    nlb_init(&b, NL80211_CMD_START_AP, NLM_F_ACK);
    nlb_u32(&b, NL80211_ATTR_IFINDEX, (uint32_t)m->ifindex);
    nlb_put(&b, NL80211_ATTR_SSID, m->ssid, strlen(m->ssid));
    nlb_u32(&b, NL80211_ATTR_BEACON_INTERVAL, 100);
    nlb_u32(&b, NL80211_ATTR_DTIM_PERIOD, 2);
    nlb_put(&b, NL80211_ATTR_BEACON_HEAD, head, (size_t)hl);
    nlb_put(&b, NL80211_ATTR_BEACON_TAIL, tail, (size_t)tl);
    nlb_u32(&b, NL80211_ATTR_HIDDEN_SSID, NL80211_HIDDEN_SSID_NOT_IN_USE);
    nlb_u32(&b, NL80211_ATTR_AUTH_TYPE, NL80211_AUTHTYPE_OPEN_SYSTEM);
    if (m->has_rsn) nlb_flag(&b, NL80211_ATTR_PRIVACY);
    nlb_u32(&b, NL80211_ATTR_WIPHY_FREQ, m->freq);
    if (m->width >= 3) width = NL80211_CHAN_WIDTH_80;
    else if (m->width == 2) width = NL80211_CHAN_WIDTH_40;
    else if (m->width == 1 && m->freq >= 3000)
        width = NL80211_CHAN_WIDTH_20;
    nlb_u32(&b, NL80211_ATTR_CHANNEL_WIDTH, width);
    nlb_flag(&b, NL80211_ATTR_CONTROL_PORT);
    nlb_u16(&b, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_EAPOL);
    nlb_flag(&b, NL80211_ATTR_CONTROL_PORT_OVER_NL80211);
    nlb_flag(&b, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    nlb_flag(&b, NL80211_ATTR_SOCKET_OWNER);
    if (m->has_rsn) {
        nlb_put(&b, NL80211_ATTR_CIPHER_SUITES_PAIRWISE, &m->pair, 4);
        nlb_u32(&b, NL80211_ATTR_CIPHER_SUITE_GROUP, m->group);
        nlb_u32(&b, NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2);
        if (m->nakm)
            nlb_put(&b, NL80211_ATTR_AKM_SUITES, m->akm,
                    (size_t)m->nakm * 4);
    }
    /* START_AP must run on the event socket: with CONTROL_PORT_OVER_NL80211
     * cfg80211 unicasts control-port frames to the owning nlportid, i.e. the
     * socket that started the AP (W5 §3.2). */
    return nl_send_ack(g_nl_evt_fd, &b);
}

/* CMD_FRAME on an AP vif: never pass WIPHY_FREQ (W5: off-channel -EBUSY). */
static int mlme_tx_mgmt(int ifindex, const uint8_t *fr, size_t len)
{
    struct nl_buf b;
    if (ifindex <= 0 || !fr || len < 24 || len > MLME_MAX_FRAME)
        return -EINVAL;
    if (nl_cmd_open() != 0) return -ENODEV;
    nlb_init(&b, NL80211_CMD_FRAME, NLM_F_ACK);
    nlb_u32(&b, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_put(&b, NL80211_ATTR_MAC, fr + 4, 6);
    nlb_put(&b, NL80211_ATTR_FRAME, fr, len);
    return nl_send_ack(g_nl_cmd_fd, &b);
}

static int mlme_new_station(struct mlme_vap *m, const uint8_t mac[6],
                            uint16_t capab, const uint8_t *rates, int rl)
{
    struct nl_buf b;
    if (nl_cmd_open() != 0) return -ENODEV;
    nlb_init(&b, NL80211_CMD_NEW_STATION, NLM_F_ACK);
    nlb_u32(&b, NL80211_ATTR_IFINDEX, (uint32_t)m->ifindex);
    nlb_put(&b, NL80211_ATTR_MAC, mac, 6);
    nlb_u16(&b, NL80211_ATTR_STA_AID, mlme_aid_for(mac));
    nlb_u16(&b, NL80211_ATTR_STA_LISTEN_INTERVAL, 1);
    nlb_u16(&b, NL80211_ATTR_STA_CAPABILITY, capab);
    if (rates && rl > 0)
        nlb_put(&b, NL80211_ATTR_STA_SUPPORTED_RATES, rates, (size_t)rl);
    return nl_send_ack(g_nl_cmd_fd, &b);
}

/* Open-system Auth response, built and emitted by the CAP itself. */
static int mlme_answer_auth(struct mlme_vap *m, const uint8_t *req, size_t len)
{
    uint8_t out[64];
    size_t n = 0;
    if (len < 30) return -EINVAL;
    out[n++] = 0xb0; out[n++] = 0x00; out[n++] = 0; out[n++] = 0;
    memcpy(out + n, req + 10, 6); n += 6;      /* DA = STA */
    memcpy(out + n, m->bssid, 6); n += 6;      /* SA */
    memcpy(out + n, m->bssid, 6); n += 6;      /* BSSID */
    out[n++] = 0; out[n++] = 0;                /* seq */
    out[n++] = req[24]; out[n++] = req[25];    /* algorithm */
    out[n++] = 2; out[n++] = 0;                /* transaction seq 2 */
    out[n++] = 0; out[n++] = 0;                /* status success */
    return mlme_tx_mgmt(m->ifindex, out, n);
}

/* Manager AssocResp (0x6019) is a template: CAP owns capab/status/AID and
 * must add Supported Rates or mac80211 drops the frame (W13 §3.1). */
static int mlme_handle_assoc_resp(mbedtls_ssl_context *ssl, int port,
                                  const uint8_t *body, size_t len,
                                  const struct cfg *c)
{
    const uint8_t *fr = NULL;
    uint16_t fl = 0;
    int ifindex, st;
    struct mlme_vap *m;
    uint8_t out[MLME_MAX_FRAME];
    size_t n = 30;
    (void)ssl; (void)c;

    if (!g_mlme_on) return 0;
    if (!find_el(body, len, 0x3e, &fr, &fl) || fl < 30) return 0;
    st = (fr[0] >> 4) & 0xf;
    if (st != 1 && st != 3) return 0;
    ifindex = vap_ifindex(port, NULL);
    m = mlme_by_ifindex(ifindex);
    if (!m) return 0;
    if (fl > sizeof(out) - 16) return -EINVAL;

    memcpy(out, fr, 30);
    out[24] = 0x31; out[25] = 0x04;            /* capab: ESS|Priv|Short* */
    out[26] = 0x00; out[27] = 0x00;            /* status: success */
    {
        uint16_t aid = mlme_aid_for(fr + 4);
        out[28] = (uint8_t)(0xc0 | (aid >> 8));
        out[29] = (uint8_t)(aid & 0xff);
    }
    out[n++] = 1; out[n++] = 8;
    memcpy(out + n, mlme_rates2, 8); n += 8;
    out[n++] = 50; out[n++] = 4;
    memcpy(out + n, mlme_xrates, 4); n += 4;
    memcpy(out + n, fr + 30, (size_t)fl - 30); n += (size_t)fl - 30;

    int r = mlme_tx_mgmt(m->ifindex, out, n);
    printf("mlme: 0x6019 %s len=%zu -> TX %zu ret=%d (%s)\n",
           st == 1 ? "assoc-resp" : "reassoc-resp", (size_t)fl, n, r,
           r ? strerror(-r) : "ok");
    fflush(stdout);
    return 1;
}

/* 0x6016 handler hook: create the BSS, then register Auth/Assoc/Probe. */
static int mlme_vap_start(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t *body, uint16_t len,
                          const struct cfg *c)
{
    int port = (phy << 8) | (vapid & 0xff);
    const uint8_t *ssid = NULL, *ies = NULL, *chv = NULL;
    uint16_t sl = 0, il = 0, cl = 0;
    struct mlme_vap *m;
    uint32_t freq = 0;
    uint8_t width = 1, band = 0;
    uint8_t mac[6];
    int r;
    (void)c;

    if (!mlme_owns_port(port)) return 0;
    if (ifindex <= 0) return -EINVAL;
    m = &g_mlme[phy % MAX_RADIOS][vapid & 0x0f];
    if (m->started && m->ifindex == ifindex) {
        printf("mlme: port 0x%04x already started on %s\n", port, ifname);
        fflush(stdout);
        return 0;
    }
    memset(m, 0, sizeof(*m));
    m->used = 1;
    m->ifindex = ifindex;
    m->port = port;

    if (!find_el(body, len, 0x03, &ssid, &sl) || sl == 0 || sl > 32) {
        fprintf(stderr, "mlme: 0x6016 port 0x%04x has no SSID\n", port);
        return -EINVAL;
    }
    memcpy(m->ssid, ssid, sl); m->ssid[sl] = 0;
    if (find_el(body, len, 0x04, &ies, &il) && il) {
        m->ielen = il > sizeof(m->ies) ? sizeof(m->ies) : il;
        memcpy(m->ies, ies, m->ielen);
    }
    if (find_el(body, len, 0x0a, &chv, &cl) && cl)
        vchan_from_tlv(port, chv, cl);
    if (!vchan_get(port, &freq, &width, &band)) {
        struct vap *vp = vap_get(phy, vapid);
        if (vp) freq = vp->freq;
    }
    if (!freq) freq = phy_freq_hint(phy);
    if (!freq) freq = 2412;
    m->freq = freq;
    m->width = width ? width : 1;
    /* 0x2018 must carry the VAP's provisioned frequency: the manager drops
     * an assoc report whose 0x0a/0x0b does not match its configuration. */
    {
        struct vap *vp = vap_get(phy, vapid);
        if (vp) {
            vp->freq = freq;
            vchan_set(port, freq, m->width, band_code_for_freq(freq));
        }
    }
    if (read_sysfs_mac(ifname, mac) == 0) memcpy(m->bssid, mac, 6);
    else if (vap_get(phy, vapid)) memcpy(m->bssid, vap_get(phy, vapid)->bssid, 6);
    mlme_parse_rsn(m);

    printf("mlme: start %s port=0x%04x ssid=%s freq=%u width=%u rsn=%d "
           "pair=%06x group=%06x akm0=%06x ies=%zu\n",
           ifname, port, m->ssid, freq, m->width, m->has_rsn, m->pair,
           m->group, m->nakm ? m->akm[0] : 0, m->ielen);
    fflush(stdout);

    g_ap_owned = 1;
    g_msrc = MSRC_NL80211;
    if (mgmt_open() != 0) {
        fprintf(stderr, "mlme: cannot open event socket\n");
        return -ENODEV;
    }
    r = mlme_start_ap(m);
    printf("mlme: START_AP ret=%d (%s) iftype=%d\n", r,
           r ? strerror(-r) : "ok", nl_get_iftype(ifindex));
    fflush(stdout);
    if (r == -EALREADY) r = 0;
    if (r) {
        fprintf(stderr, "mlme: START_AP %s ret=%d (%s)\n", ifname, r,
                r ? strerror(-r) : "ok");
        m->used = 0;
        return r;
    }
    mgmt_vap_add(ifindex);
    m->started = 1;
    printf("mlme: AP up %s bssid=%02x:%02x:%02x:%02x:%02x:%02x no hostapd\n",
           ifname, m->bssid[0], m->bssid[1], m->bssid[2], m->bssid[3],
           m->bssid[4], m->bssid[5]);
    fflush(stdout);
    return 1;
}

/* A received NL80211_CMD_FRAME event for the MLME-owned BSS.
 * Return 1 when handled locally, 0 to let the generic 0x2018 relay run. */
static int mlme_on_mgmt(mbedtls_ssl_context *ssl, struct nlattr *at, int alen,
                        int ifindex, const struct cfg *c)
{
    struct nlattr *fa = NULL;
    struct mlme_vap *m = mlme_by_ifindex(ifindex);
    const uint8_t *fr;
    size_t fl;
    int st, vt;
    (void)ssl; (void)c;

    if (!m) return 0;
    for (struct nlattr *a = at; alen >= (int)sizeof(struct nlattr) &&
         a->nla_len >= sizeof(struct nlattr) && a->nla_len <= alen;
         alen -= NLA_ALIGN(a->nla_len),
         a = (struct nlattr *)((uint8_t *)a + NLA_ALIGN(a->nla_len))) {
        if ((a->nla_type & NLA_TYPE_MASK) == NL80211_ATTR_FRAME) {
            fa = a;
            break;
        }
    }
    if (!fa) return 0;
    fr = (uint8_t *)fa + NLA_HDRLEN;
    fl = fa->nla_len - NLA_HDRLEN;
    if (fl < 24) return 0;
    vt = (fr[0] >> 2) & 0x3;
    st = (fr[0] >> 4) & 0xf;
    if (vt != 0 || memcmp(fr + 16, m->bssid, 6) != 0) return 0;

    if (st == 11) {                            /* authentication */
        uint16_t alg = (uint16_t)(fr[24] | (fr[25] << 8));
        uint16_t seq = (uint16_t)(fr[26] | (fr[27] << 8));
        if (alg == 0 && seq == 1) {             /* open system */
            int r = mlme_answer_auth(m, fr, fl);
            printf("mlme: auth %02x:%02x:%02x:%02x:%02x:%02x -> local "
                   "answer ret=%d (%s), relaying 0x2018\n", fr[10], fr[11],
                   fr[12], fr[13], fr[14], fr[15], r,
                   r ? strerror(-r) : "ok");
            fflush(stdout);
            /* The manager also needs to see the Auth frame to move its own
             * peer FSM to authenticated; our local response is the air copy. */
            return 0;
        }
        return 0;                              /* SAE etc.: manager answers */
    }
    if (st == 0 || st == 2) {                  /* AssocReq / ReassocReq */
        uint16_t capab = (uint16_t)(fr[24] | (fr[25] << 8));
        uint8_t rates[16];
        int rl = 0;
        for (size_t i = 28; i + 2 <= fl; i += 2 + fr[i + 1]) {
            if (i + 2 + fr[i + 1] > fl) break;
            if (fr[i] == 1 && !rl) {
                rl = fr[i + 1];
                if (rl > (int)sizeof(rates)) rl = (int)sizeof(rates);
                memcpy(rates, fr + i + 2, (size_t)rl);
            }
        }
        int r = mlme_new_station(m, fr + 10, capab, rates, rl);
        if (r == -EEXIST) r = 0;
        printf("mlme: %s %02x:%02x:%02x:%02x:%02x:%02x NEW_STATION ret=%d "
               "(%s), relaying 0x2018\n",
               st == 2 ? "reassoc" : "assoc", fr[10], fr[11], fr[12], fr[13],
               fr[14], fr[15], r, r ? strerror(-r) : "ok");
        fflush(stdout);
        return 0;
    }
    return 0;
}

/* A control-port EAPOL frame from the station -> manager (0x201B). */
static int mlme_on_control_port(mbedtls_ssl_context *ssl, struct dc_ctx *dc,
                                const struct cfg *c, struct nlattr *at,
                                int alen)
{
    struct nlattr *ma = NULL, *fa = NULL, *ea = NULL;
    struct mlme_vap *m;
    const uint8_t *fr, *mac;
    size_t fl;
    uint16_t et = ETH_P_EAPOL;
    int ifindex = 0;

    if (!g_mlme_on) return 0;
    for (struct nlattr *a = at; alen >= (int)sizeof(struct nlattr) &&
         a->nla_len >= sizeof(struct nlattr) && a->nla_len <= alen;
         alen -= NLA_ALIGN(a->nla_len),
         a = (struct nlattr *)((uint8_t *)a + NLA_ALIGN(a->nla_len))) {
        int t = a->nla_type & NLA_TYPE_MASK;
        if (t == NL80211_ATTR_MAC) ma = a;
        else if (t == NL80211_ATTR_FRAME) fa = a;
        else if (t == NL80211_ATTR_CONTROL_PORT_ETHERTYPE) ea = a;
        else if (t == NL80211_ATTR_IFINDEX && a->nla_len >= NLA_HDRLEN + 4)
            ifindex = (int)*(uint32_t *)((uint8_t *)a + NLA_HDRLEN);
    }
    if (ea && ea->nla_len >= NLA_HDRLEN + 2)
        et = *(uint16_t *)((uint8_t *)ea + NLA_HDRLEN);
    if (!ma || !fa || et != ETH_P_EAPOL) return 0;
    m = mlme_by_ifindex(ifindex);
    if (!m) return 0;
    mac = (uint8_t *)ma + NLA_HDRLEN;
    fr = (uint8_t *)fa + NLA_HDRLEN;
    fl = fa->nla_len - NLA_HDRLEN;
    eapol_strip(&fr, &fl);
    if (fl < 4) return 1;
    printf("mlme: EAPOL RX %02x:%02x:%02x:%02x:%02x:%02x len=%zu -> 0x201b\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], fl);
    fflush(stdout);
    eapol_relay(ssl, dc, c, (uint16_t)m->port, mac, fr, fl);
    return 1;
}
