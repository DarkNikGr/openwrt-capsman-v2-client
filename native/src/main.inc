/* main.inc — run loop, options, main
 * Part of capagent.c (single translation unit; included in order). */

/* W14: every connection starts from a clean session.  A manager reboot or a
 * CAP reconnect must not keep the previous vapid/ifindex/key map, otherwise
 * the manager's fresh 0x500b/0x6016 sequence lands on stale state.  Kernel
 * objects (netdevs, hostapd, keys) are untouched; they are re-adopted. */
static void cap_reset_session(void)
{
    if (g_extmux) {
        extmux_free(g_extmux);
        g_extmux = NULL;
    }
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_vap[r][w].used && g_vap[r][w].extfd >= 0)
                close(g_vap[r][w].extfd);
    memset(g_vap, 0, sizeof(g_vap));
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++) {
            g_vap[r][w].extfd = -1;
            g_vap[r][w].l2fd = -1;
        }
    memset(g_pmap, 0, sizeof(g_pmap));
    memset(g_vchan, 0, sizeof(g_vchan));
    memset(g_vmap, 0, sizeof(g_vmap));
    g_sta_ident = 0;
}

static int run_once(struct cfg *c)
{
    mbedtls_net_context fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context ctr;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    uint8_t body[BODY_MAX];
    size_t join_len;
    uint8_t hdr[14];
    struct dc_ctx dc;
    char mgr[160];

    memset(&dc, 0, sizeof(dc));
    dc.fd = -1;
    dc.id = c->dc_id;
    dc.port = c->dc_port;
    dc.keyidx = c->dc_keyidx;
    dc.cfg = c;
    dc.active = -1;
    dc.pending_del = -1;
    dc.variant = 0;             /* legacy/no a2: AES-CCM */
    dc.secure = 1;

    g_dp_bridge = c->datapath_bridge;
    g_vap_mtu = c->vap_mtu;
    g_bcast_flood = c->bcast_flood;
    g_msrc_cfg = c->mgmt_source;

    /* W14: discover on every attempt.  At boot S95 runs ~130 s before the
     * WAN lease, so a single discovery can only cache an empty address. */
    cap_reset_session();
    c->manager = choose_manager(c, mgr, sizeof(mgr));
    if (!c->manager || !*c->manager) {
        fprintf(stderr, "capagent: no manager available; retrying\n");
        return -1;
    }
    printf("capagent: manager=%s:%s radios=%d discovery=%s verify=%s\n",
           c->manager, c->port, c->nradios,
           c->discovery_if ? c->discovery_if : "-",
           (c->dont_verify || !c->ca_cert) ? "no" : "ca");
    fflush(stdout);

    if (connect_tls(&fd, &ssl, &conf, &ent, &ctr, &crt, &pk, c) != 0)
        goto out;

    /* W8: bind one ext-auth socket per BSS before the manager provisions any
     * VAP, and adopt anything that survived the previous connection. */
    cap_extmux_start(c, &ssl, &dc);

    /* Test override: listen before the manager sends a create. */
    if (c->datachan && c->dc_key_len) {
        dc_set_peer(&dc, fd.fd, c->dc_port);
        if (dc_open(&dc, c->dc_port) == 0) {
            dc_install(&dc, c->dc_key, c->dc_key_len, c->dc_cookie,
                       c->dc_cookie_len, c->dc_id, c->dc_port,
                       c->dc_keyidx, 0, 0);
            dc_send_keepalive(&dc);
            printf("datachan: listening on UDP %u (test key), id %u\n",
                   c->dc_port, c->dc_id);
            fflush(stdout);
        }
    }

    build_join(body, c, &join_len);
    if (send_msg(&ssl, TYPE_JOIN, 0, body, (uint16_t)join_len) != 0) goto out;

    for (int phy = 0; phy < c->nradios; phy++) {
        size_t n;
        build_newphy(body, c->macs[phy], phy, &n);
        if (send_msg(&ssl, TYPE_NEWPHY, (uint16_t)(phy << 8), body,
                     (uint16_t)n) != 0) goto out;
        printf("NEWPHY phy=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               phy, c->macs[phy][0], c->macs[phy][1], c->macs[phy][2],
               c->macs[phy][3], c->macs[phy][4], c->macs[phy][5]);
        fflush(stdout);
        usleep(300000);
    }

    time_t last_echo = time(NULL);
    time_t last_stats = 0;
    time_t last_dc_ka = 0;
    time_t last_refresh = 0;
#ifdef CAPAGENT_LAB
    if (c->lab_iface && lab_ap_setup(c) != 0) {
        fprintf(stderr, "lab: AP setup failed\n");
        goto out;
    }
#endif
    for (;;) {
        struct pollfd pfd[64];
        int nfd = 0, tls_i, nl_i = -1, dci = -1;
        int dp_first = -1, dp_count = 0, ext_any = 0;
        int mon_i[MON_MAX];
        int have_tls = mbedtls_ssl_get_bytes_avail(&ssl) > 0;
        for (int i = 0; i < MON_MAX; i++) mon_i[i] = -1;

        pfd[nfd].fd = fd.fd;
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        tls_i = nfd++;
        if (g_nl_evt_fd >= 0 && nfd < 64) {
            pfd[nfd].fd = g_nl_evt_fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            nl_i = nfd++;
        }
        if (dc.fd >= 0 && nfd < 64) {
            pfd[nfd].fd = dc.fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            dci = nfd++;
        }
        for (int i = 0; i < g_ndp && nfd < 64; i++) {
            pfd[nfd].fd = g_dp[i].fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            if (dp_first < 0) dp_first = nfd;
            dp_count++;
            nfd++;
        }
        for (int r = 0; r < MAX_RADIOS; r++)
            for (int w = 0; w < 16; w++) {
                struct vap *v = &g_vap[r][w];
                if (!v->used || v->extfd < 0 || nfd >= 64) continue;
                pfd[nfd].fd = v->extfd;
                pfd[nfd].events = POLLIN;
                pfd[nfd].revents = 0;
                ext_any = 1;
                nfd++;
            }
        for (int i = 0; i < g_mon_n && nfd < 64; i++) {
            if (g_mon[i].fd < 0) continue;
            pfd[nfd].fd = g_mon[i].fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            mon_i[i] = nfd++;
        }
        int pr = poll(pfd, (nfds_t)nfd,
                      have_tls ? 0 : (g_extmux ? 50 : 200));
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (nl_i >= 0 && (pfd[nl_i].revents & POLLNVAL)) {
            close(g_nl_evt_fd);
            g_nl_evt_fd = -1;
        } else if (nl_i >= 0 &&
                   (pfd[nl_i].revents & (POLLIN | POLLERR))) {
#ifdef CAPAGENT_LAB
            if (c->lab_iface) lab_service_nl(&ssl, &dc, c);
            else
#endif
            if (g_msrc != MSRC_MONITOR) mgmt_service_nl(&ssl);
        }
        {
            int mon_hit = 0;
            for (int i = 0; i < g_mon_n; i++) {
                if (mon_i[i] < 0) continue;
                if (pfd[mon_i[i]].revents & POLLNVAL) {
                    close(g_mon[i].fd);
                    g_mon[i].fd = -1;
                } else if (pfd[mon_i[i]].revents & (POLLIN | POLLERR)) {
                    mon_hit = 1;
                }
            }
            if (mon_hit) mgmt_monitor_service(&ssl);
        }
        if (g_extmux) {
            /* Drives per-BSS ext-auth RX, ctrl replies and the 4-way timers */
            extmux_service(g_extmux, 0);
        } else if (ext_any) {
            for (int i = 0; i < nfd; i++)
                if (pfd[i].revents & POLLIN) { ext_auth_service(&ssl, &dc, c);
                                               break; }
        }
        if (dci >= 0 && (pfd[dci].revents & POLLIN)) dc_service(&dc);
        if (dp_count) {
            for (int i = dp_first; i < dp_first + dp_count; i++)
                if (pfd[i].revents & POLLIN) { dp_service(&dc); break; }
        }
        if (dc.fd >= 0 && time(NULL) - last_dc_ka >= DC_KEEPALIVE_MS / 1000) {
            dc_send_keepalive(&dc);
            last_dc_ka = time(NULL);
        }
        if (time(NULL) != last_stats) {
            last_stats = time(NULL);
            send_station_stats(&ssl, c);
        }
        if (time(NULL) - last_refresh >= 5) {
            last_refresh = time(NULL);
            if (c->mgmt_relay || c->mgmt_source) mgmt_monitor_watchdog();
            if (g_dp_bridge) dp_refresh();
        }
        if (time(NULL) - last_echo > 5) {
            send_msg(&ssl, TYPE_ECHO, 0, NULL, 0);
            last_echo = time(NULL);
        }
        (void)nl_i;
        if (!have_tls && !(pfd[tls_i].revents & (POLLIN | POLLHUP | POLLERR)))
            continue;

        int r = read_exact(&ssl, fd.fd, hdr, 14);
        if (r == 0) continue;
        if (r < 0) break;

        uint16_t type = rd16(hdr);
        uint16_t port = rd16(hdr + 2);
        uint16_t len  = rd16(hdr + 12);
        if (type == TYPE_PROVISION || type == 0x6016 || type == 0x2019 ||
            type == 0x6019 || type == 0x6014)
            g_sta_ident = ((uint64_t)rd32(hdr + 4) << 32) | rd32(hdr + 8);
        if (len > BODY_MAX) break;
        if (len && read_exact(&ssl, fd.fd, body, len) != 1) break;

        if (type == TYPE_PROVISION) {
            int phy = port >> 8;
            dump_raw("prov", type, port, body, len);
            int vap = port & 0xff;
            const uint8_t *a2v = NULL; uint16_t a2l = 0;
            const uint8_t *cv = NULL; uint16_t cl = 0;
            int a2 = find_el(body, len, 0xa2, &a2v, &a2l) && a2l ? a2v[0] : -1;
            if (find_el(body, len, 0x0a, &cv, &cl) && cl)
                vchan_from_tlv((phy << 8) | vap, cv, cl);
            printf("RX 0x500b phy=%d vap=%d a2=%d len=%d\n", phy, vap, a2, len);
            fflush(stdout);
            if (phy >= 0 && phy < c->nradios)
                createvap_response(&ssl, hdr + 2, phy, vap, c, body, len);
            dc_handle_create(&dc, c, &fd, port, body, len);
        } else if (type == TYPE_DESTROY) {
            printf("RX 0x600c destroy\n");
            fflush(stdout);
            send_hdr_msg(&ssl, TYPE_DESTROY_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_JOIN_RESP) {
            dump_raw("joinresp", type, port, body, len);
            handle_c029(body, len);
        } else if (type == TYPE_POLL) {   /* periodic status poll */
            static int n27;
            /* The genuine CAP answers with MAC/vapid/ifindex/ifname/current
               freq; the manager only reads 0x61. */
            int p27 = port >> 8, v27 = port & 0xff;
            char in27[32];
            uint8_t m27[6] = {0}, b27[BODY_MAX], x27[4];
            size_t z27 = 0;
            snprintf(in27, sizeof(in27), "phy%d-ap%d", p27, v27);
            read_sysfs_mac(in27, m27);
            int i27 = read_sysfs_int(in27, "ifindex");
            z27 += put_el(b27 + z27, 0x08, m27, 6);
            put32(x27, (uint32_t)v27);
            z27 += put_el(b27 + z27, 0x47, x27, 4);
            put32(x27, (uint32_t)i27);
            z27 += put_el(b27 + z27, 0x48, x27, 4);
            z27 += put_el(b27 + z27, 0x49, in27, (uint16_t)strlen(in27));
            {
                uint32_t hf = phy_freq_hint(p27 >> 8);
                if (hf) {
                    put32(x27, hf);
                    z27 += put_el(b27 + z27, 0x61, x27, 4);
                }
            }
            send_hdr_msg(&ssl, 0xE027, hdr + 2, b27, (uint16_t)z27);
            maybe_inject_assoc(&ssl, c);
            if ((++n27 % 100) == 1) {
                printf("RX 0x6027 poll (count=%d) -> 0xE027 len=%zu\n",
                       n27, z27);
                fflush(stdout);
            }
        } else if (type == TYPE_EAPOL_TX) {   /* 0x201C manager -> STA */
            dump_raw("eapol201c", type, port, body, len);
            printf("RX 0x201c eapol-tx port=0x%04x len=%u\n", port, len);
            fflush(stdout);
            handle_201c(&ssl, port, body, len);
            send_hdr_msg(&ssl, TYPE_EAPOL_TX_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_KEY_INSTALL) { /* 0x201F PTK/GTK/IGTK */
            dump_raw("sec201f", type, port, body, len);
            printf("RX 0x201f key-install port=0x%04x len=%u\n", port, len);
            fflush(stdout);
            handle_201f(&ssl, port, body, len, c);
            send_hdr_msg(&ssl, TYPE_KEY_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_ASSOC_FRAME) { /* 0x2018, manager side only */
            dump_raw("assoc2018", type, port, body, len);
            printf("RX 0x2018 from manager (ignored)\n");
            fflush(stdout);
        } else if (type == TYPE_ASSOC_RESP2) {  /* 0x2019 auth/deauth/action */
            /* W6: subtype 11 is the Auth response (discard, hostapd already
             * answered); subtypes 12/13 are manager commands (transmit). */
            dump_raw("mgmt2019", type, port, body, len);
            handle_2019(&ssl, port, body, len, c);
            send_hdr_msg(&ssl, TYPE_MGMT_TX_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_ASSOC_RESP) {   /* 0x6019 assoc-resp template */
            /* The template has capab 0 / AID 0 / no RSN IE and must never be
             * sent verbatim; hostapd answered the real AssocResp on air. */
            dump_raw("assocresp", type, port, body, len);
            printf("0x6019 from manager (template discarded, hostapd answered "
                   "on air)\n");
            fflush(stdout);
            send_hdr_msg(&ssl, TYPE_MGMT_TX_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_DEL_STA) {
            const uint8_t *dm = NULL; uint16_t dl = 0;
            dump_raw("delsta201a", type, port, body, len);
            if (find_el(body, len, 0x08, &dm, &dl) && dl == 6)
                printf("0x201a: DELSTA %02x:%02x:%02x:%02x:%02x:%02x from "
                       "manager (hostapd owns teardown)\n", dm[0], dm[1],
                       dm[2], dm[3], dm[4], dm[5]);
            fflush(stdout);
        } else if (type == TYPE_EAPOL_RX) {    /* 0x201B, manager side only */
            dump_raw("eapol201b", type, port, body, len);
            printf("RX 0x201b from manager (ignored)\n");
            fflush(stdout);
        } else if (type == TYPE_START) {   /* ActAp start/config push (SSID/RSN/chan) */
            dump_raw("start", type, port, body, len);
            const uint8_t *cv = NULL; uint16_t cl = 0;
            if (find_el(body, len, 0x0a, &cv, &cl) && cl)
                vchan_from_tlv(port, cv, cl);
            printf("RX 0x6016 start port=0x%04x len=%u -> ack 0xE016\n", port, len);
            fflush(stdout);
            if (c->mgmt_relay || c->mgmt_source) {
                const uint8_t *iv = NULL; uint16_t il = 0;
                if (find_el(body, len, 0x48, &iv, &il) && il == 4)
                    mgmt_vap_add((int)rd32(iv));
            }
            vap_provision(port, body, len, c);
            send_hdr_msg(&ssl, TYPE_START_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_ECHO) {
            const uint8_t *k = NULL, *iv = NULL;
            uint16_t kl = 0, il = 0;
            int has_a8 = find_el(body, len, 0xa8, &k, &kl);
            int has_a9 = find_el(body, len, 0xa9, &iv, &il);
            int rc = -1;
            if (len)
                printf("RX 0x402b echo/rekey len=%u a8=%d(%uB) a9=%d\n",
                       len, has_a8, kl, has_a9);
            if (has_a8 && (kl == 16 || kl == 32)) {
                int idx = (has_a9 && il) ? (iv[0] & 1) : 0;
                rc = dc_rekey(&dc, idx, k, kl);
                printf("datachan: rekey slot=%d %s\n", idx,
                       rc == 0 ? "installed" : "FAILED");
            }
            if (rc == 0 || !has_a8)
                send_hdr_msg(&ssl, TYPE_ECHO_RESP, hdr + 2, NULL, 0);
            else {
                uint8_t eb[64]; size_t en = 0;
                uint8_t two[4] = {0, 0, 0, 2};
                en += put_el(eb + en, 1, two, 4);
                en += put_el(eb + en, 2, "Failed to rekey data channel", 28);
                send_hdr_msg(&ssl, TYPE_ECHO_RESP, hdr + 2, eb, (uint16_t)en);
            }
            fflush(stdout);
        } else if (type == TYPE_DISCONNECT) {
            printf("disconnected\n");
            fflush(stdout);
            break;
        } else if (type != TYPE_ECHO_RESP && type != TYPE_JOIN_RESP) {
            dump_raw("other", type, port, body, len);
            printf("RX type=0x%04x len=%d\n", type, len);
            fflush(stdout);
        }
    }

out:
    cap_extmux_stop(c);
    dp_close_all();
#ifdef CAPAGENT_LAB
    lab_shutdown();
#endif
    if (dc.fd >= 0) close(dc.fd);
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&ent);
    return -1;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s --cert cert.pem --key key.pem [options]\n"
        "  --manager ADDR[,ADDR]|auto   caps-man-addresses (default: auto)\n"
        "  --discovery-interfaces IF    discovery interface (default: br-lan)\n"
        "  --lock-to-caps-man           remember the discovered manager\n"
        "  --caps-man-certificate-common-names CN[,CN]\n"
        "  --ca-cert FILE               verify the manager certificate\n"
        "  --dont-verify-certificate    disable TLS verification\n"
        "  --slaves-datapath NAME       accepted for WinBox parity\n"
        "  --slaves-static              accepted for WinBox parity\n"
        "  --macs MAC[,MAC]|auto        radio MACs (default: from phy sysfs)\n"
        "  --crypto-selftest            run AES-CCM known-answer tests and exit\n"
        "  --datachan                   receive the CAPsMAN datachan on UDP\n"
        "  --dc-listen PORT             datachan UDP port (default: 5248)\n"
        "  --dc-peer-port PORT          lab: manager datachan UDP port\n"
        "  --dc-key HEX                 16/32-byte datachan key (test override)\n"
        "  --dc-cookie HEX              <=16-byte datachan cookie (test override)\n"
        "  --dc-id N                    datachan id (default: 428)\n"
        "  --apply                      write 0x77 SSID/VLAN/key to UCI (all radios)\n"
        "  --eapol-leg tls|datachan|both\n"
        "                               STA EAPOL -> manager leg (default tls = 0x201B)\n"
        "  --datapath-bridge            AF_PACKET bridge client <-> datachan (P2/P3)\n"
        "  --vap-mtu N                  pin the VAP/AP_VLAN MTU (runbook: 1474)\n"
        "  --bcast wid|flood            unknown-wid broadcast: owning VAP or all\n"
        "  --mgmt-relay                 relay real Auth/AssocReq as 0x2018 (P4)\n"
        "  --mgmt-source auto|nl80211|monitor|off\n"
        "                               Auth/AssocReq source (auto: nl80211 when we\n"
        "                               own the AP, monitor when hostapd owns it)\n"
        "  --ext-auth-dir DIR           hostapd external-RSN dgram dir (P5)\n"
        "  --ext-ctrl-dir DIR           hostapd ctrl_interface dir (default: dir above)\n"
        "  --state-file FILE            key-free extmux restart journal\n"
        "  --fourway-timeout MS         CAP-side 4-way deadline (default 10000)\n"
        "  --m1-retry MS                M1 retransmit interval (default 3000)\n"
        "  --lab-ap IFACE               lab only: bring up a minimal AP on IFACE\n"
        "  --lab-ssid SSID              lab SSID (default T14-CAP)\n"
        "  --lab-chan N                 lab channel (default 1)\n"
        "  --version                    print the version and exit\n",
        p);
}

int main(int argc, char **argv)
{
    struct cfg c;
    memset(&c, 0, sizeof(c));
    c.manager = "auto";
    c.port = "5246";
    c.cert = "/etc/cap/client.pem";
    c.key = "/etc/cap/client.key";
    c.ca_cert = "/etc/cap/ca.pem";
    c.discovery_if = "br-lan";
    c.identity = NULL;
    c.serial = NULL;
    c.a1[0]=0x00; c.a1[1]=0x00; c.a1[2]=0x02; c.a1[3]=0x32;
    c.e70[0]=0x00; c.e70[1]=0x00; c.e70[2]=0x00; c.e70[3]=0x02;
    c.vap_auto = 1;
    c.dc_port = DC_PORT_DEFAULT;
    c.dc_id = DC_ID_DEFAULT;
    c.fourway_ms = 10000;
    c.m1_retry_ms = 3000;
    parse_ifnames(&c, "phy0-ap0,phy1-ap0");
    parse_macs(&c, "auto");

    enum { OPT_DISC = 1000, OPT_LOCK, OPT_CN, OPT_CA, OPT_NOVERIFY,
           OPT_SDP, OPT_SSTATIC, OPT_IDENTITY, OPT_SERIAL, OPT_A1, OPT_E70,
           OPT_SELFTEST, OPT_DATACHAN, OPT_DC_LISTEN, OPT_DC_KEY,
           OPT_DC_COOKIE, OPT_DC_ID, OPT_DC_PEER, OPT_APPLY, OPT_NOACK,
           OPT_EAPOL_LEG, OPT_LAB_AP, OPT_LAB_SSID, OPT_LAB_CHAN, OPT_INJECT,
           OPT_PHYS, OPT_DP_BRIDGE, OPT_VAP_MTU, OPT_BCAST, OPT_MGMT_RELAY,
           OPT_MGMT_SOURCE, OPT_EXTAUTH, OPT_VAPAUTO, OPT_NOVAPAUTO,
           OPT_EXTCTRL, OPT_STATE, OPT_FOURWAY, OPT_M1RETRY };

    static struct option opts[] = {
        {"manager", required_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"ifnames", required_argument, 0, 'i'},
        {"macs", required_argument, 0, 'a'},
        {"discovery-interfaces", required_argument, 0, OPT_DISC},
        {"lock-to-caps-man", no_argument, 0, OPT_LOCK},
        {"caps-man-certificate-common-names", required_argument, 0, OPT_CN},
        {"ca-cert", required_argument, 0, OPT_CA},
        {"dont-verify-certificate", no_argument, 0, OPT_NOVERIFY},
        {"slaves-datapath", required_argument, 0, OPT_SDP},
        {"slaves-static", no_argument, 0, OPT_SSTATIC},
        {"identity", required_argument, 0, OPT_IDENTITY},
        {"serial", required_argument, 0, OPT_SERIAL},
        {"a1", required_argument, 0, OPT_A1},
        {"e70", required_argument, 0, OPT_E70},
        {"crypto-selftest", no_argument, 0, OPT_SELFTEST},
        {"datachan", no_argument, 0, OPT_DATACHAN},
        {"dc-listen", required_argument, 0, OPT_DC_LISTEN},
        {"dc-key", required_argument, 0, OPT_DC_KEY},
        {"dc-cookie", required_argument, 0, OPT_DC_COOKIE},
        {"dc-id", required_argument, 0, OPT_DC_ID},
        {"dc-peer-port", required_argument, 0, OPT_DC_PEER},
        {"apply", no_argument, 0, OPT_APPLY},
        {"no-ack", no_argument, 0, OPT_NOACK},
        {"inject-assoc", no_argument, 0, OPT_INJECT},
        {"phys", required_argument, 0, OPT_PHYS},
        {"eapol-leg", required_argument, 0, OPT_EAPOL_LEG},
        {"datapath-bridge", no_argument, 0, OPT_DP_BRIDGE},
        {"vap-mtu", required_argument, 0, OPT_VAP_MTU},
        {"bcast", required_argument, 0, OPT_BCAST},
        {"mgmt-relay", no_argument, 0, OPT_MGMT_RELAY},
        {"mgmt-source", required_argument, 0, OPT_MGMT_SOURCE},
        {"ext-auth-dir", required_argument, 0, OPT_EXTAUTH},
        {"ext-ctrl-dir", required_argument, 0, OPT_EXTCTRL},
        {"state-file", required_argument, 0, OPT_STATE},
        {"fourway-timeout", required_argument, 0, OPT_FOURWAY},
        {"m1-retry", required_argument, 0, OPT_M1RETRY},
        {"vap-auto", no_argument, 0, OPT_VAPAUTO},
        {"no-vap-auto", no_argument, 0, OPT_NOVAPAUTO},
        {"lab-ap", required_argument, 0, OPT_LAB_AP},
        {"lab-ssid", required_argument, 0, OPT_LAB_SSID},
        {"lab-chan", required_argument, 0, OPT_LAB_CHAN},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0,0,0,0}
    };
    int o;
    while ((o = getopt_long(argc, argv, "m:p:c:k:i:a:hV", opts, NULL)) != -1) {
        switch (o) {
        case 'm': c.manager = optarg; break;
        case 'p': c.port = optarg; break;
        case 'c': c.cert = optarg; break;
        case 'k': c.key = optarg; break;
        case 'i': parse_ifnames(&c, optarg); break;
        case 'a': parse_macs(&c, optarg); break;
        case OPT_DISC: c.discovery_if = optarg; break;
        case OPT_LOCK: c.lock_to_manager = 1; break;
        case OPT_CN: c.manager_cn = optarg; break;
        case OPT_CA: c.ca_cert = optarg; break;
        case OPT_NOVERIFY: c.dont_verify = 1; break;
        case OPT_SDP: c.slaves_datapath = optarg; break;
        case OPT_SSTATIC: c.slaves_static = 1; break;
        case OPT_IDENTITY: c.identity = optarg; break;
        case OPT_SERIAL: c.serial = optarg; break;
        case OPT_A1: parse_hex(optarg, c.a1, 4); break;
        case OPT_E70: parse_hex(optarg, c.e70, 4); break;
        case OPT_SELFTEST: c.crypto_selftest = 1; break;
        case OPT_DATACHAN: c.datachan = 1; break;
        case OPT_DC_LISTEN: c.dc_port = (uint16_t)atoi(optarg); break;
        case OPT_DC_KEY:
            c.dc_key_len = parse_hex(optarg, c.dc_key, sizeof(c.dc_key));
            break;
        case OPT_DC_COOKIE:
            c.dc_cookie_len = parse_hex(optarg, c.dc_cookie,
                                        sizeof(c.dc_cookie));
            break;
        case OPT_DC_ID: c.dc_id = (uint16_t)atoi(optarg); break;
        case OPT_DC_PEER: c.dc_peer_port = (uint16_t)atoi(optarg); break;
        case OPT_APPLY: g_apply = 1; break;
        case OPT_VAPAUTO: c.vap_auto = 1; break;
        case OPT_NOVAPAUTO: c.vap_auto = 0; break;
        case OPT_NOACK: c.no_ack = 1; break;
        case OPT_INJECT: c.inject_assoc = 1; break;
        case OPT_DP_BRIDGE: c.datapath_bridge = 1; break;
        case OPT_VAP_MTU: c.vap_mtu = atoi(optarg); break;
        case OPT_BCAST: c.bcast_flood = !strcmp(optarg, "flood"); break;
        case OPT_MGMT_RELAY: c.mgmt_relay = 1; break;
        case OPT_MGMT_SOURCE:
            if (!strcmp(optarg, "auto")) c.mgmt_source = MSRC_AUTO;
            else if (!strcmp(optarg, "nl80211")) c.mgmt_source = MSRC_NL80211;
            else if (!strcmp(optarg, "monitor")) c.mgmt_source = MSRC_MONITOR;
            else if (!strcmp(optarg, "off")) c.mgmt_source = MSRC_OFF;
            else { usage(argv[0]); return 1; }
            break;
        case OPT_EXTAUTH: c.ext_auth_dir = optarg; break;
        case OPT_EXTCTRL: c.ext_ctrl_dir = optarg; break;
        case OPT_STATE: c.state_file = optarg; break;
        case OPT_FOURWAY: c.fourway_ms = atoi(optarg); break;
        case OPT_M1RETRY: c.m1_retry_ms = atoi(optarg); break;
        case OPT_PHYS: {
            char *tmp = strdup(optarg), *save = NULL, *tok;
            int i = 0;
            tok = strtok_r(tmp, ",", &save);
            while (tok && i < MAX_RADIOS) {
                g_phy_map[i++] = atoi(tok);
                tok = strtok_r(NULL, ",", &save);
            }
            free(tmp);
            break;
        }
        case OPT_EAPOL_LEG:
            if (!strcmp(optarg, "tls")) c.eapol_leg = 1;
            else if (!strcmp(optarg, "datachan")) c.eapol_leg = 2;
            else if (!strcmp(optarg, "both")) c.eapol_leg = 3;
            else { usage(argv[0]); return 1; }
            break;
        case OPT_LAB_AP: c.lab_iface = optarg; break;
        case OPT_LAB_SSID: c.lab_ssid = optarg; break;
        case OPT_LAB_CHAN: c.lab_chan = atoi(optarg); break;
        case 'V':
            printf("capagent %s\n", CAPAGENT_VERSION);
            return 0;
        default: usage(argv[0]); return 1;
        }
    }
#ifndef CAPAGENT_LAB
    if (c.lab_iface) {
        fprintf(stderr, "capagent: --lab-ap needs a -DCAPAGENT_LAB build\n");
        return 1;
    }
#endif
    if (!c.eapol_leg) c.eapol_leg = 1;
    if (!c.lab_ssid) c.lab_ssid = "T14-CAP";
    if (!c.lab_chan) c.lab_chan = 1;
    if (c.crypto_selftest) return dc_selftest();
    if (c.nradios == 0) resolve_phy_macs(&c);
    if (c.nradios == 0) {
        fprintf(stderr, "no valid radio MACs\n");
        return 1;
    }
    /* W14: discovery and session setup are per attempt; run_once() owns both
     * so an early failure (no WAN lease yet) is never permanent. */
    c.manager_spec = c.manager;
    for (;;) {
        run_once(&c);
        fprintf(stderr, "reconnect in 5s\n");
        sleep(5);
    }
    return 0;
}
