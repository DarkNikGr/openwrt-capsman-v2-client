/* main.inc — run loop, options, main
 * Part of capagent.c (single translation unit; included in order). */

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

    memset(&dc, 0, sizeof(dc));
    dc.fd = -1;
    dc.id = c->dc_id;
    dc.port = c->dc_port;
    dc.keyidx = c->dc_keyidx;

    if (connect_tls(&fd, &ssl, &conf, &ent, &ctr, &crt, &pk, c) != 0)
        goto out;

    /* Test override: listen before the manager sends a create. */
    if (c->datachan && c->dc_key_len) {
        dc_set_peer(&dc, fd.fd, c->dc_port);
        if (dc_open(&dc, c->dc_port) == 0) {
            dc_install(&dc, c->dc_key, c->dc_key_len, c->dc_cookie,
                       c->dc_cookie_len, c->dc_id, c->dc_port,
                       c->dc_keyidx);
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
    time_t last_dc_ka = 0;
#ifdef CAPAGENT_LAB
    if (c->lab_iface && lab_ap_setup(c) != 0) {
        fprintf(stderr, "lab: AP setup failed\n");
        goto out;
    }
#endif
    for (;;) {
        struct pollfd pfd[3];
        int nfd = 0, tls_i, nl_i = -1, dci = -1;
        int have_tls = mbedtls_ssl_get_bytes_avail(&ssl) > 0;

        pfd[nfd].fd = fd.fd;
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        tls_i = nfd++;
#ifdef CAPAGENT_LAB
        if (g_nl_evt_fd >= 0) {
            pfd[nfd].fd = g_nl_evt_fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            nl_i = nfd++;
        }
#endif
        if (dc.fd >= 0) {
            pfd[nfd].fd = dc.fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            dci = nfd++;
        }
        int pr = poll(pfd, (nfds_t)nfd, have_tls ? 0 : 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }

#ifdef CAPAGENT_LAB
        if (nl_i >= 0 && (pfd[nl_i].revents & POLLIN))
            lab_service_nl(&ssl, &dc, c);
#endif
        if (dci >= 0 && (pfd[dci].revents & POLLIN)) dc_service(&dc);
        if (dc.fd >= 0 && time(NULL) - last_dc_ka >= DC_KEEPALIVE_MS / 1000) {
            dc_send_keepalive(&dc);
            last_dc_ka = time(NULL);
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
        if (len > BODY_MAX) break;
        if (len && read_exact(&ssl, fd.fd, body, len) != 1) break;

        if (type == TYPE_PROVISION) {
            int phy = port >> 8;
            dump_raw("prov", type, port, body, len);
            int vap = port & 0xff;
            const uint8_t *a2v = NULL; uint16_t a2l = 0;
            int a2 = find_el(body, len, 0xa2, &a2v, &a2l) && a2l ? a2v[0] : -1;
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
            put32(x27, (p27 & 1) ? 5180u : 2437u);
            z27 += put_el(b27 + z27, 0x61, x27, 4);
            send_hdr_msg(&ssl, 0xE027, hdr + 2, b27, (uint16_t)z27);
            static time_t last_stats;
            if (time(NULL) != last_stats) {
                last_stats = time(NULL);
                send_station_stats(&ssl, c);
            }
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
            handle_201f(&ssl, port, body, len);
            send_hdr_msg(&ssl, TYPE_KEY_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_ASSOC_FRAME) { /* 0x2018, manager side only */
            dump_raw("assoc2018", type, port, body, len);
            printf("RX 0x2018 from manager (ignored)\n");
            fflush(stdout);
        } else if (type == TYPE_EAPOL_RX) {    /* 0x201B, manager side only */
            dump_raw("eapol201b", type, port, body, len);
            printf("RX 0x201b from manager (ignored)\n");
            fflush(stdout);
        } else if (type == TYPE_START) {   /* ActAp start/config push (SSID/RSN/chan) */
            dump_raw("start", type, port, body, len);
            printf("RX 0x6016 start port=0x%04x len=%u -> ack 0xE016\n", port, len);
            fflush(stdout);
            send_hdr_msg(&ssl, TYPE_START_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_ECHO) {
            if (len) {
                const uint8_t *av = NULL; uint16_t al = 0;
                int has_a8 = find_el(body, len, 0xa8, &av, &al);
                int has_a9 = find_el(body, len, 0xa9, &av, &al);
                printf("RX echo len=%u a8=%d a9=%d\n", len, has_a8, has_a9);
                fflush(stdout);
            }
            send_hdr_msg(&ssl, TYPE_ECHO_RESP, hdr + 2, NULL, 0);
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
        "  --dc-key HEX                 16/32-byte datachan key (test override)\n"
        "  --dc-cookie HEX              <=16-byte datachan cookie (test override)\n"
        "  --dc-id N                    datachan id (default: 428)\n"
        "  --apply                      write 0x77 SSID/VLAN/key to UCI (radio1)\n"
        "  --eapol-leg tls|datachan|both\n"
        "                               STA EAPOL -> manager leg (default tls = 0x201B)\n"
        "  --lab-ap IFACE               lab only: bring up a minimal AP on IFACE\n"
        "  --lab-ssid SSID              lab SSID (default T14-CAP)\n"
        "  --lab-chan N                 lab channel (default 1)\n",
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
    c.dc_port = DC_PORT_DEFAULT;
    c.dc_id = DC_ID_DEFAULT;
    parse_ifnames(&c, "phy0-ap0,phy1-ap0");
    parse_macs(&c, "auto");

    enum { OPT_DISC = 1000, OPT_LOCK, OPT_CN, OPT_CA, OPT_NOVERIFY,
           OPT_SDP, OPT_SSTATIC, OPT_IDENTITY, OPT_SERIAL, OPT_A1, OPT_E70,
           OPT_SELFTEST, OPT_DATACHAN, OPT_DC_LISTEN, OPT_DC_KEY,
           OPT_DC_COOKIE, OPT_DC_ID, OPT_APPLY, OPT_NOACK,
           OPT_EAPOL_LEG, OPT_LAB_AP, OPT_LAB_SSID, OPT_LAB_CHAN, OPT_INJECT };
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
        {"apply", no_argument, 0, OPT_APPLY},
        {"no-ack", no_argument, 0, OPT_NOACK},
        {"inject-assoc", no_argument, 0, OPT_INJECT},
        {"eapol-leg", required_argument, 0, OPT_EAPOL_LEG},
        {"lab-ap", required_argument, 0, OPT_LAB_AP},
        {"lab-ssid", required_argument, 0, OPT_LAB_SSID},
        {"lab-chan", required_argument, 0, OPT_LAB_CHAN},
        {"help", no_argument, 0, 'h'},
        {0,0,0,0}
    };
    int o;
    while ((o = getopt_long(argc, argv, "m:p:c:k:i:a:h", opts, NULL)) != -1) {
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
        case OPT_APPLY: g_apply = 1; break;
        case OPT_NOACK: c.no_ack = 1; break;
        case OPT_INJECT: c.inject_assoc = 1; break;
        case OPT_EAPOL_LEG:
            if (!strcmp(optarg, "tls")) c.eapol_leg = 1;
            else if (!strcmp(optarg, "datachan")) c.eapol_leg = 2;
            else if (!strcmp(optarg, "both")) c.eapol_leg = 3;
            else { usage(argv[0]); return 1; }
            break;
        case OPT_LAB_AP: c.lab_iface = optarg; break;
        case OPT_LAB_SSID: c.lab_ssid = optarg; break;
        case OPT_LAB_CHAN: c.lab_chan = atoi(optarg); break;
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
    char mgr[64];
    c.manager = choose_manager(&c, mgr, sizeof(mgr));
    printf("capagent: manager=%s:%s radios=%d discovery=%s verify=%s\n",
           c.manager, c.port, c.nradios,
           c.discovery_if ? c.discovery_if : "-",
           (c.dont_verify || !c.ca_cert) ? "no" : "ca");
    fflush(stdout);
    for (;;) {
        run_once(&c);
        fprintf(stderr, "reconnect in 5s\n");
        sleep(5);
    }
    return 0;
}
