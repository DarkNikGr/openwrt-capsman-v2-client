/* util.inc — TLV/hex/sysfs helpers, join/NEWPHY builders
 * Part of capagent.c (single translation unit; included in order). */

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static size_t put_el(uint8_t *p, uint16_t id, const void *data, uint16_t len)
{
    put16(p, id);
    put16(p + 2, len);
    if (len && data) memcpy(p + 4, data, len);
    return 4 + len;
}

static size_t put_msg(uint8_t *p, uint16_t type, uint16_t port,
                      const uint8_t *body, uint16_t len)
{
    put16(p, type);
    put16(p + 2, port);
    memset(p + 4, 0, 8);
    put16(p + 12, len);
    if (len && body) memcpy(p + 14, body, len);
    return 14 + len;
}

static int send_msg(mbedtls_ssl_context *ssl, uint16_t type, uint16_t port,
                    const uint8_t *body, uint16_t len)
{
    uint8_t buf[BODY_MAX + 16];
    size_t n = put_msg(buf, type, port, body, len);
    size_t off = 0;
    while (off < n) {
        int r = mbedtls_ssl_write(ssl, buf + off, n - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

static int send_msg_id(mbedtls_ssl_context *ssl, uint16_t type, uint16_t port,
                       uint64_t id, const uint8_t *body, uint16_t len)
{
    uint8_t buf[BODY_MAX + 16];
    put16(buf, type);
    put16(buf + 2, port);
    put32(buf + 4, (uint32_t)(id >> 32));
    put32(buf + 8, (uint32_t)id);
    put16(buf + 12, len);
    if (len && body) memcpy(buf + 14, body, len);
    size_t n = 14 + (size_t)len, off = 0;
    while (off < n) {
        int r = mbedtls_ssl_write(ssl, buf + off, n - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

/* returns 1 = full message, 0 = timeout with no data, -1 = error */
static int read_exact(mbedtls_ssl_context *ssl, int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        if (mbedtls_ssl_get_bytes_avail(ssl) == 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
            int pr = poll(&pfd, 1, 1000);
            if (pr == 0) {
                if (got == 0) return 0;
                continue;
            }
            if (pr < 0) {
                if (errno == EINTR) continue;
                return -1;
            }
            if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
        }
        int r = mbedtls_ssl_read(ssl, buf + got, len - got);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 1;
}

static int read_sysfs_int(const char *ifname, const char *leaf)
{
    char path[128], b[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", ifname, leaf);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(b, sizeof(b), f)) { fclose(f); return 0; }
    fclose(f);
    return atoi(b);
}

static int read_sysfs_mac(const char *ifname, uint8_t mac[6])
{
    char path[128], b[64];
    unsigned v[6];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(b, sizeof(b), f)) { fclose(f); return -1; }
    fclose(f);
    if (sscanf(b, "%x:%x:%x:%x:%x:%x", &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

static void read_trim(const char *path, char *out, size_t n)
{
    out[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(out, (int)n, f))
        out[strcspn(out, "\r\n")] = 0;
    fclose(f);
}

static void make_serial(const struct cfg *c, char *serial, size_t n)
{
    serial[0] = 0;
    if (c->serial && *c->serial) { snprintf(serial, n, "%s", c->serial); return; }
    read_trim("/proc/device-tree/serial-number", serial, n);
    if (!serial[0]) read_trim("/sys/firmware/devicetree/base/serial-number", serial, n);
    if (!serial[0]) {
        /* fall back to the base MAC as the hardware identifier */
        char mac[32] = "";
        read_trim("/sys/class/net/br-lan/address", mac, sizeof(mac));
        if (!mac[0])
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     c->macs[0][0], c->macs[0][1], c->macs[0][2],
                     c->macs[0][3], c->macs[0][4], c->macs[0][5]);
        size_t j = 0;
        for (size_t i = 0; mac[i] && j + 1 < n; i++) {
            char ch = mac[i];
            if (ch == ':') continue;
            if (ch >= 'a' && ch <= 'z') ch -= 32;
            serial[j++] = ch;
        }
        serial[j] = 0;
    }
}

static size_t parse_hex(const char *s, uint8_t *out, size_t max)
{
    size_t n = 0;
    while (s && *s && n < max) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

static void build_join(uint8_t *b, const struct cfg *c, size_t *out)
{
    static const uint8_t e6e[2] = {0x00,0x01};
    char identity[64] = "";
    char board[64] = "";
    char serial[64] = "";
    if (c->identity && *c->identity) {
        snprintf(identity, sizeof(identity), "%s", c->identity);
    } else {
        read_trim("/etc/cap/identity", identity, sizeof(identity));
        if (!identity[0]) read_trim("/proc/sys/kernel/hostname", identity, sizeof(identity));
        if (!identity[0]) snprintf(identity, sizeof(identity), "OpenWrt-CAP");
    }
    make_serial(c, serial, sizeof(serial));
    read_trim("/tmp/sysinfo/model", board, sizeof(board));
    if (!board[0]) read_trim("/proc/device-tree/model", board, sizeof(board));
    if (!board[0]) snprintf(board, sizeof(board), "OpenWrt");
    static const uint8_t c46[8] = {0xce,0x9e,0x1a,0x17,0x27,0x34,0x73,0x26};
    static const uint8_t c73[4] = {0x07,0x19,0x66,0x01};
    static const uint8_t c74[4] = {0x6a,0xe8,0x84,0x99};
    size_t n = 0;
    n += put_el(b+n, 0x6e, e6e, sizeof(e6e));
    n += put_el(b+n, 0x6f, identity, (uint16_t)strlen(identity));
    n += put_el(b+n, 0x46, c46, sizeof(c46));
    n += put_el(b+n, 0x70, c->e70, 4);
    n += put_el(b+n, 0xa7, "\x01\x00\x07", 3);
    n += put_el(b+n, 0x71, board, (uint16_t)strlen(board));
    n += put_el(b+n, 0x72, serial, (uint16_t)strlen(serial));
    n += put_el(b+n, 0x73, c73, sizeof(c73));
    n += put_el(b+n, 0x74, c74, sizeof(c74));
    n += put_el(b+n, 0x75, c->macs[0], 6);
    n += put_el(b+n, 0xa1, c->a1, 4);
    *out = n;
}

/* 0x83 hw-type is a plain driver/module name; the manager stores it as a
   string and prints it as hw-type.  Read it from the wiphy, with the module
   names of the target board as a fallback. */
static const char *phy_hwtype(int phy)
{
    phy = real_phy(phy);
    static char name[32];
    char path[128], link[160];
    ssize_t n;

    snprintf(path, sizeof(path),
             "/sys/class/ieee80211/phy%d/device/driver/module", phy);
    n = readlink(path, link, sizeof(link) - 1);
    if (n > 0) {
        char *base;
        link[n] = 0;
        base = strrchr(link, '/');
        snprintf(name, sizeof(name), "%.*s", (int)sizeof(name) - 1,
                 base ? base + 1 : link);
        return name;
    }
    return "unknown";
}

struct phy_caps {
    uint8_t ciphers[32];
    int nciphers;
    uint32_t tx_chain;
    uint32_t rx_chain;
    int max_ap;
    int has_he;
    int has_eht;
};

static int parse_sel(const char *p, uint8_t out[4])
{
    unsigned a, b, c, d;
    if (!p || sscanf(p, "%2x-%2x-%2x-%2x", &a, &b, &c, &d) != 4) return 0;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b;
    out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return 1;
}

/* Ciphers, chain masks and AP-interface limit from `iw phy phyN info`. */
static int nl_get_wiphy_ciphers(int phy, uint8_t *out, int outmax);

/* W46: resolve a phy index to the name `iw phy <name>` accepts.  A wiphy can
 * be renamed (mac80211_hwsim, consistent naming, udev); `iw phy phyN` then
 * fails even though the index exists, so the CAP advertises no channels and
 * the manager never selects a channel / sends 0x6016.  Resolve the index
 * through /sys/class/ieee80211/<name>/index. */
static void phy_iw_name(int phy, char *out, size_t n)
{
    DIR *d;
    struct dirent *de;

    snprintf(out, n, "phy%d", phy);
    d = opendir("/sys/class/ieee80211");
    if (!d) return;
    while ((de = readdir(d)) != NULL) {
        char p[300], b[32];
        FILE *f;
        if (de->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), "/sys/class/ieee80211/%.200s/index",
                 de->d_name);
        f = fopen(p, "r");
        if (!f) continue;
        if (fgets(b, sizeof(b), f) && atoi(b) == phy) {
            fclose(f);
            snprintf(out, n, "%.*s", (int)(n ? n - 1 : 0), de->d_name);
            closedir(d);
            return;
        }
        fclose(f);
    }
    closedir(d);
}

static void read_phy_caps(int phy, struct phy_caps *pc)
{
    phy = real_phy(phy);
    char cmd[160], line[256], pn[64];
    int in_ciph = 0;
    memset(pc, 0, sizeof(*pc));
    phy_iw_name(phy, pn, sizeof(pn));
    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw phy %s info 2>/dev/null", pn);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p;
            unsigned tx, rx;
            if (sscanf(line, " Available Antennas: TX 0x%x RX 0x%x",
                       &tx, &rx) == 2) {
                pc->tx_chain = tx;
                pc->rx_chain = rx;
            }
            if (strstr(line, "HE Iftypes:") && strstr(line, "AP"))
                pc->has_he = 1;
            if (strstr(line, "EHT Iftypes:") && strstr(line, "AP"))
                pc->has_eht = 1;
            if (strstr(line, "Supported Ciphers:")) { in_ciph = 1; continue; }
            if (in_ciph) {
                if ((p = strchr(line, '(')) != NULL) {
                    uint8_t sel[4];
                    if (parse_sel(p + 1, sel) && sel[0] == 0x00 &&
                        sel[1] == 0x0f && sel[2] == 0xac &&
                        sel[3] >= 0x02 && sel[3] <= 0x0a &&
                        pc->nciphers < 8) {
                        memcpy(pc->ciphers + pc->nciphers * 4, sel, 4);
                        pc->nciphers++;
                    }
                } else if (line[0] != '\t' && line[0] != ' ') {
                    in_ciph = 0;
                }
            }
            p = strstr(line, "AP");
            if (p) {
                char *q = strstr(p, "<=");
                if (q) {
                    int n = atoi(q + 2);
                    if (n > 0 && (pc->max_ap == 0 || n < pc->max_ap))
                        pc->max_ap = n;
                }
            }
        }
        pclose(fp);
    }
    if (pc->nciphers == 0) {
        int nb = nl_get_wiphy_ciphers(phy, pc->ciphers, 8);
        pc->nciphers = nb / 4;
    }
    if (pc->nciphers == 0)
        fprintf(stderr, "capagent: phy%d reports no ciphers\n", phy);
    if (pc->tx_chain == 0)
        fprintf(stderr, "capagent: phy%d reports no tx chains\n", phy);
    if (pc->max_ap == 0)
        fprintf(stderr, "capagent: phy%d reports no AP interface limit\n", phy);
}

#define PHY_MAX_FREQ 96

struct phy_bands {
    uint32_t freq[PHY_MAX_FREQ];
    int nfreq;
    uint8_t band[8];
    int nband;
};

static void iface_chan(const char *ifn, unsigned *freq, unsigned *width);

/* Supported frequencies/bands of a radio, from `iw phy phyN info`.  Falls
   back to the legacy 2.4/5 GHz tables only when iw gives nothing. */
static void read_phy_bands(int phy, struct phy_bands *pb)
{
    phy = real_phy(phy);
    char cmd[160], line[256], pn[64];
    int have2 = 0, have5 = 0, have6 = 0;
    memset(pb, 0, sizeof(*pb));
    phy_iw_name(phy, pn, sizeof(pn));
    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw phy %s info 2>/dev/null", pn);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            unsigned f;
            if (strstr(line, "disabled")) continue;
            if (sscanf(line, " * %u MHz", &f) == 1) {
                int dup = 0;
                for (int i = 0; i < pb->nfreq; i++)
                    if (pb->freq[i] == f) dup = 1;
                if (!dup && pb->nfreq < PHY_MAX_FREQ)
                    pb->freq[pb->nfreq++] = f;
            }
        }
        pclose(fp);
    }
    if (pb->nfreq == 0)
        fprintf(stderr, "capagent: phy%d reports no frequencies\n", phy);
    for (int i = 0; i < pb->nfreq; i++) {
        uint32_t f = pb->freq[i];
        if (f < 3000) have2 = 1;
        else if (f < 5925) have5 = 1;
        else have6 = 1;
    }
    if (have2) { pb->band[pb->nband++] = 0x81; pb->band[pb->nband++] = 0x82; }
    if (have5) { pb->band[pb->nband++] = 0x01; pb->band[pb->nband++] = 0x03; }
    if (have6) { pb->band[pb->nband++] = 0x06; }
}

static uint8_t band_code_for_freq(uint32_t f)
{
    if (f < 3000) return 0x81;      /* 2ghz-g */
    if (f < 5925) return 0x03;      /* 5ghz-ac */
    return 0x06;                    /* 6ghz */
}

static uint32_t chan_base_for_freq(uint32_t f)
{
    if (f < 3000) return 2407;
    if (f < 5925) return 5000;
    return 5950;
}

/* Current operating frequency of a radio (first VAP), else its first
   supported frequency, else a safe default. */
static uint32_t phy_freq_hint(int phy)
{
    char ifn[32];
    unsigned f = 0, w = 0;
    snprintf(ifn, sizeof(ifn), "phy%d-ap0", real_phy(phy));
    iface_chan(ifn, &f, &w);
    if (f) return f;
    struct phy_bands pb;
    read_phy_bands(phy, &pb);
    if (pb.nfreq) return pb.freq[0];
    return 0;
}

static void build_newphy(uint8_t *b, const uint8_t mac[6], int phy, size_t *out)
{
    uint8_t v16[2], v32[4];
    /* MT7603E/MT7612E support TKIP and CCMP-128 only: no GCMP/GCMP-256 and
       no CCMP-256.  5ghz-ax is not advertised either (no HE). */
    struct phy_caps pc;
    struct phy_bands pb;
    uint8_t fbuf[PHY_MAX_FREQ * 4];
    const char *hw = phy_hwtype(phy);
    size_t n = 0;

    read_phy_bands(phy, &pb);
    read_phy_caps(phy, &pc);
    for (int i = 0; i < pb.nfreq; i++)
        put32(fbuf + i * 4, pb.freq[i]);

    n += put_el(b+n, 0x08, mac, 6);

    /* Interface/peer limits: 8 is the manager-side ceiling we advertise;
       the driver still enforces its own limit. */
    if (pc.max_ap > 0) {
        put16(v16, (uint16_t)pc.max_ap);
        n += put_el(b+n, 0x7e, v16, 2);
        n += put_el(b+n, 0x7f, v16, 2);
        n += put_el(b+n, 0x80, v16, 2);
    }

    /* 0x83 is a string (hw-type), not the old 8-byte capability blob. */
    n += put_el(b+n, 0x83, hw, (uint16_t)strlen(hw));

    put32(v32, 1);
    n += put_el(b+n, 0x8a, v32, 4);

    if (pc.nciphers > 0)
        n += put_el(b+n, 0x5e, pc.ciphers, (uint16_t)(pc.nciphers * 4));
    n += put_el(b+n, 0x05, fbuf, (uint16_t)(pb.nfreq * 4));

    if (pc.tx_chain) {
        put32(v32, pc.tx_chain);
        n += put_el(b+n, 0x4b, v32, 4);   /* tx chains */
    }
    if (pc.rx_chain) {
        put32(v32, pc.rx_chain);
        n += put_el(b+n, 0x4c, v32, 4);   /* rx chains */
    }
    for (int i = 0; i < pb.nband; i++) {
        uint8_t bd[5] = { pb.band[i], 0, 0, 0, 0x01 };
        if (pb.band[i] == 0x82 || pb.band[i] == 0x03) bd[4] = 0x03;
        if (pb.band[i] == 0x03 || pb.band[i] == 0x06) bd[4] = 0x07;
        n += put_el(b+n, 0x4d, bd, 5);
    }

    /* WiFi 6/7 band ids, only when the phy reports HE/EHT AP support. */
    {
        int have5 = 0, have6 = 0;
        for (int i = 0; i < pb.nfreq; i++) {
            if (pb.freq[i] >= 4900 && pb.freq[i] < 5925) have5 = 1;
            if (pb.freq[i] >= 5925) have6 = 1;
        }
        if (have5 && pc.has_he) {
            uint8_t bd[5] = { 0x04, 0, 0, 0, 0x07 };
            n += put_el(b+n, 0x4d, bd, 5);
        }
        if (have5 && pc.has_eht) {
            uint8_t bd[5] = { 0x06, 0, 0, 0, 0x07 };
            n += put_el(b+n, 0x4d, bd, 5);
        }
        if (have6 && pc.has_eht) {
            uint8_t bd[5] = { 0x06, 0, 0, 0, 0x07 };
            n += put_el(b+n, 0x4d, bd, 5);
        }
    }

    /* 0x84 = little-endian capability bitset.  Bit 6 (0x40) tells the
       manager the CAP supports the data channel; without it a
       datapath.traffic-processing=on-capsman VAP is refused with
       "data channel not supported".  Keep bit 7 (MLO) clear. */
    {
        uint8_t caps84[4] = { 0x40, 0x00, 0x00, 0x00 };
        n += put_el(b+n, 0x84, caps84, sizeof(caps84));
    }
    *out = n;
}

static int find_el(const uint8_t *b, size_t n, uint16_t id,
                   const uint8_t **val, uint16_t *len)
{
    size_t i = 0;
    while (i + 4 <= n) {
        uint16_t t = rd16(b + i), l = rd16(b + i + 2);
        if (i + 4 + l > n) break;
        if (t == id) { *val = b + i + 4; *len = l; return 1; }
        i += 4 + l;
    }
    return 0;
}

