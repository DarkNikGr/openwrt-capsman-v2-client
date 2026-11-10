/* discovery.inc — manager discovery and MAC/ifname resolution
 * Part of capagent.c (single translation unit; included in order). */

static int discover_manager(const char *iface, int port, char *out, size_t outlen)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (iface && *iface)
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, (socklen_t)strlen(iface));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons((uint16_t)port);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    if (iface && *iface) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFBRDADDR, &ifr) == 0)
            dst.sin_addr = ((struct sockaddr_in *)&ifr.ifr_broadaddr)->sin_addr;
    }
    static const uint8_t req[10] = {0x30,0x00,0x00,0x06,0x00,0x6e,0x00,0x02,0x00,0x01};
    sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst));

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    time_t end = time(NULL) + 3;
    while (time(NULL) < end) {
        if (poll(&pfd, 1, 500) <= 0) continue;
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        uint8_t buf[512];
        ssize_t r = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &sl);
        if (r > 0 && buf[0] == 0x31) {
            inet_ntop(AF_INET, &src.sin_addr, out, (socklen_t)outlen);
            close(fd);
            return 0;
        }
    }
    close(fd);
    return -1;
}

static const char *choose_manager(struct cfg *c, char *buf, size_t n)
{
    if (c->lock_to_manager) {
        FILE *f = fopen("/etc/cap/manager.lock", "r");
        if (f) {
            if (fgets(buf, (int)n, f)) {
                buf[strcspn(buf, "\r\n")] = 0;
                fclose(f);
                if (buf[0]) return buf;
            } else fclose(f);
        }
    }
    if (!c->manager || !*c->manager || !strcmp(c->manager, "auto")) {
        if (discover_manager(c->discovery_if, atoi(c->port), buf, n) == 0) {
            if (c->lock_to_manager) {
                FILE *f = fopen("/etc/cap/manager.lock", "w");
                if (f) { fprintf(f, "%s\n", buf); fclose(f); }
            }
            return buf;
        }
        snprintf(buf, n, "10.0.0.1");
        return buf;
    }
    snprintf(buf, n, "%s", c->manager);
    char *comma = strchr(buf, ',');
    if (comma) *comma = 0;
    return buf;
}

static int connect_tls(mbedtls_net_context *fd, mbedtls_ssl_context *ssl,
                       mbedtls_ssl_config *conf, mbedtls_entropy_context *ent,
                       mbedtls_ctr_drbg_context *ctr, mbedtls_x509_crt *crt,
                       mbedtls_pk_context *pk, const struct cfg *c)
{
    char err[128];
    int r;

    mbedtls_net_init(fd);
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_entropy_init(ent);
    mbedtls_ctr_drbg_init(ctr);
    mbedtls_x509_crt_init(crt);
    mbedtls_pk_init(pk);

    if ((r = mbedtls_ctr_drbg_seed(ctr, mbedtls_entropy_func, ent,
                                   (const unsigned char *)"capagent", 8)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "ctr_drbg_seed: %s\n", err);
        return -1;
    }
    if ((r = mbedtls_x509_crt_parse_file(crt, c->cert)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "cert %s: %s\n", c->cert, err);
        return -1;
    }
    if ((r = mbedtls_pk_parse_keyfile(pk, c->key, NULL,
                                      mbedtls_ctr_drbg_random, ctr)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "key %s: %s\n", c->key, err);
        return -1;
    }
    if ((r = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "ssl_config_defaults: %s\n", err);
        return -1;
    }
    int verify = 0;
    if (!c->dont_verify && c->ca_cert && *c->ca_cert) {
        FILE *cf = fopen(c->ca_cert, "r");
        if (cf) {
            fclose(cf);
            if (!g_ca_loaded) {
                mbedtls_x509_crt_init(&g_ca);
                if ((r = mbedtls_x509_crt_parse_file(&g_ca, c->ca_cert)) != 0) {
                    mbedtls_strerror(r, err, sizeof(err));
                    fprintf(stderr, "ca %s: %s\n", c->ca_cert, err);
                    return -1;
                }
                g_ca_loaded = 1;
            }
            verify = 1;
        }
    }
    if (verify) {
        mbedtls_ssl_conf_ca_chain(conf, &g_ca, NULL);
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    }
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr);
    mbedtls_ssl_conf_own_cert(conf, crt, pk);
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);

    if ((r = mbedtls_net_connect(fd, c->manager, c->port,
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "connect %s:%s: %s\n", c->manager, c->port, err);
        return -1;
    }

    if ((r = mbedtls_ssl_setup(ssl, conf)) != 0) {
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "ssl_setup: %s\n", err);
        return -1;
    }
    if (verify && c->manager_cn && *c->manager_cn) {
        char cn[128];
        snprintf(cn, sizeof(cn), "%s", c->manager_cn);
        char *comma = strchr(cn, ',');
        if (comma) *comma = 0;
        mbedtls_ssl_set_hostname(ssl, cn);
    } else if (verify) {
        mbedtls_ssl_set_hostname(ssl, NULL);   /* chain check only */
    } else {
        mbedtls_ssl_set_hostname(ssl, c->manager);
    }
    mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((r = mbedtls_ssl_handshake(ssl)) != 0) {
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        mbedtls_strerror(r, err, sizeof(err));
        fprintf(stderr, "handshake: %s\n", err);
        return -1;
    }
    printf("joined TLS to %s:%s\n", c->manager, c->port);
    fflush(stdout);
    return 0;
}

static void parse_macs(struct cfg *c, const char *s)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", s);
    char *save = NULL, *tok = strtok_r(buf, ",", &save);
    c->nradios = 0;
    while (tok && c->nradios < MAX_RADIOS) {
        unsigned v[6];
        if (sscanf(tok, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) {
            for (int i = 0; i < 6; i++) c->macs[c->nradios][i] = (uint8_t)v[i];
            c->nradios++;
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

static void resolve_phy_macs(struct cfg *c)
{
    int n = 0;
    for (int i = 0; i < MAX_RADIOS; i++) {
        char path[128], b[64];
        snprintf(path, sizeof(path), "/sys/class/ieee80211/phy%d/macaddress", i);
        FILE *f = fopen(path, "r");
        if (!f) break;
        if (!fgets(b, sizeof(b), f)) { fclose(f); break; }
        fclose(f);
        unsigned v[6];
        if (sscanf(b, "%x:%x:%x:%x:%x:%x",
                   &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6) break;
        for (int k = 0; k < 6; k++) c->macs[n][k] = (uint8_t)v[k];
        n++;
    }
    if (n) c->nradios = n;
}

static void parse_ifnames(struct cfg *c, const char *s)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", s);
    char *save = NULL, *tok = strtok_r(buf, ",", &save);
    int i = 0;
    while (tok && i < MAX_RADIOS) {
        snprintf(c->ifnames[i], sizeof(c->ifnames[i]), "%s", tok);
        i++;
        tok = strtok_r(NULL, ",", &save);
    }
}

/* ---- station statistics reported to the manager (0x200E / 0x2015) ------ */
