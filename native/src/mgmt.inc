/* mgmt.inc — EAPOL/key descriptors, 0x200e/0x2015/0x2018 helpers
 * Part of capagent.c (single translation unit; included in order). */

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
        int r = dc_send_frame(dc, fr, 14 + len);
        printf("0x201b: EAPOL %zuB -> manager (datachan) ret=%d\n", len, r);
    }
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
                        const uint8_t *body, size_t len)
{
    (void)ssl;
    struct key_desc kd[8];
    int nkd = 0, class_kind = 0, class_idx = -1;
    const uint8_t *top_mac = NULL;

    struct tlv_it it = { body, len };
    uint16_t tag;
    const uint8_t *v;
    size_t vl;
    while (tlv_next(&it, &tag, &v, &vl)) {
        if (tag == 0x0050) {
            if (nkd < (int)(sizeof(kd)/sizeof(kd[0])))
                parse_key_desc(v, vl, &kd[nkd++]);
        } else if (tag == 0x005a || tag == 0x005b) {
            class_kind = (tag == 0x005b) ? 2 : 1;
            int ci = class_idx_from(v, vl);
            if (ci >= 0) class_idx = ci;
        } else if (tag == 0x0008 && vl == 6) {
            top_mac = v;
        }
    }
    if (!nkd) {
        printf("0x201f: no 0x50 key descriptor (len=%zu)\n", len);
        fflush(stdout);
        return;
    }

    uint8_t mac[6] = {0};
    int ifindex = vap_ifindex(port, mac);
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
        int pairwise = (smac && class_kind == 0);
        int is_igtk = (class_kind == 2);
        int idx = d->idx;
        if (class_kind && class_idx >= 0) idx = class_idx;
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
            int ra = nl_sta_authorize(ifindex, smac);
            printf("0x201f: SET_STATION AUTHORIZED %02x:%02x:%02x:%02x:%02x:%02x "
                   "ret=%d (%s)\n", smac[0], smac[1], smac[2], smac[3],
                   smac[4], smac[5], ra, ra ? strerror(-ra) : "ok");
        } else {
            printf("0x201f: PTK install failed, station not authorized\n");
        }
    }
    fflush(stdout);
}

