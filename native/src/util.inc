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

/* Set a netdev's MAC address.  Most drivers require the interface to be down,
 * so take it down and restore its flags.  Used for the manager-assigned BSSID
 * of an AP netdev we own. */
static int set_if_mac(const char *name, const uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    unsigned flags = 0;
    memset(&ifr, 0, sizeof(ifr));
    { size_t nl = strlen(name);
      if (nl >= IFNAMSIZ) nl = IFNAMSIZ - 1;
      memcpy(ifr.ifr_name, name, nl); ifr.ifr_name[nl] = 0; }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        flags = (unsigned)ifr.ifr_flags;
        if (flags & IFF_UP) {
            ifr.ifr_flags = (short)(flags & ~IFF_UP);
            ioctl(fd, SIOCSIFFLAGS, &ifr);
        }
    }
    memset(&ifr, 0, sizeof(ifr));
    { size_t nl = strlen(name);
      if (nl >= IFNAMSIZ) nl = IFNAMSIZ - 1;
      memcpy(ifr.ifr_name, name, nl); ifr.ifr_name[nl] = 0; }
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    int r = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (flags & IFF_UP) {
        memset(&ifr, 0, sizeof(ifr));
        { size_t nl = strlen(name);
      if (nl >= IFNAMSIZ) nl = IFNAMSIZ - 1;
      memcpy(ifr.ifr_name, name, nl); ifr.ifr_name[nl] = 0; }
        ifr.ifr_flags = (short)flags;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);
    return r;
}

/* Optional per-process tag (CAPAGENT_RUN_TAG).  A second capagent instance on
 * the same wiphy (a distinct CAP identity, see F63) must not use the same
 * netdev names as the first, or the two would adopt each other's interfaces
 * and the phy-wide cleanup would delete them. */
static const char *ap_tag(void)
{
    const char *t = getenv("CAPAGENT_RUN_TAG");
    return (t && *t) ? t : "";
}

static void ap_ifname(char *out, size_t n, int phy, int vapid)
{
    const char *t = ap_tag();
    if (*t)
        snprintf(out, n, "phy%d-%sap%d", phy, t, vapid);
    else
        snprintf(out, n, "phy%d-ap%d", phy, vapid);
}

/* 1 when `name` is an AP interface name for this process (tag included),
 * filling phy/vapid. */
static int ap_parse_name(const char *name, int *phy, int *vapid)
{
    const char *t = ap_tag();
    for (int p = 0; p < 16; p++) {
        char pre[40];
        int w = -1;
        char tail = 0;
        if (*t) snprintf(pre, sizeof(pre), "phy%d-%sap", p, t);
        else    snprintf(pre, sizeof(pre), "phy%d-ap", p);
        size_t l = strlen(pre);
        if (strncmp(name, pre, l) == 0 &&
            sscanf(name + l, "%d%c", &w, &tail) == 1 && w >= 0) {
            if (phy) *phy = p;
            if (vapid) *vapid = w;
            return 1;
        }
    }
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

static void build_join(uint8_t *b, const struct cfg *c, size_t *out,
                       const uint8_t *csr, size_t csrlen)
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
    /* 0xa7 = the CAP's protocol/capability vector we advertise at join.  The
     * default is what a genuine CAP sends in our captures; CAPAGENT_A7 lets a
     * test sweep the value without rebuilding (the secure-datachan probe). */
    {
        static uint8_t a7[8];
        const char *e = getenv("CAPAGENT_A7");
        size_t al = 3;
        memcpy(a7, "\x01\x00\x07", 3);
        if (e && *e) {
            size_t k = 0;
            while (e[0] && e[1] && k < sizeof(a7)) {
                unsigned v;
                if (sscanf(e, "%2x", &v) != 1) break;
                a7[k++] = (uint8_t)v;
                e += 2;
            }
            if (k) al = k;
        }
        n += put_el(b+n, 0xa7, a7, (uint16_t)al);
    }
    n += put_el(b+n, 0x71, board, (uint16_t)strlen(board));
    n += put_el(b+n, 0x72, serial, (uint16_t)strlen(serial));
    n += put_el(b+n, 0x73, c73, sizeof(c73));
    {
        const char *e8 = getenv("CAPAGENT_JOIN_A8");
        if (e8 && *e8) {
            uint8_t a8[64];
            size_t k = 0;
            while (e8[0] && e8[1] && k < sizeof(a8)) {
                unsigned v;
                if (sscanf(e8, "%2x", &v) != 1) break;
                a8[k++] = (uint8_t)v;
                e8 += 2;
            }
            if (k) n += put_el(b+n, 0xa8, a8, (uint16_t)k);
        }
    }
    n += put_el(b+n, 0x74, c74, sizeof(c74));
    n += put_el(b+n, 0x75, c->macs[0], 6);
    n += put_el(b+n, 0xa1, c->a1, 4);
    /* W16: 0x76 = PKCS#10 CSR (DER).  The manager answers with 0x77/0x78.
       It is accepted at any position; keep it last, as a genuine CAP does. */
    if (csr && csrlen)
        n += put_el(b+n, 0x76, csr, (uint16_t)csrlen);
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

/* iw addresses a wiphy by its sysfs name, not by its numeric index.  On a
 * stock OpenWrt image the two happen to be equal (phy0, phy1); on a test
 * host / hwsim they are not (w36ap0 with index 1328), so resolve the name. */
static const char *phy_name_by_index(int idx, char *buf, size_t n)
{
    DIR *d = opendir("/sys/class/ieee80211");
    snprintf(buf, n, "phy%d", idx);
    if (!d) return buf;
    struct dirent *e;
    while ((e = readdir(d))) {
        /* "/sys/class/ieee80211/" (21) + d_name (NAME_MAX 255) + "/index" (6). */
        char path[320], line[32];
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/sys/class/ieee80211/%s/index",
                 e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (!fgets(line, sizeof(line), f)) { fclose(f); continue; }
        fclose(f);
        if (atoi(line) == idx) {
            if (n) snprintf(buf, n, "%.*s", (int)(n - 1), e->d_name);
            break;
        }
    }
    closedir(d);
    return buf;
}

/* `iw` used for capability probes.  On OpenWrt it is /usr/sbin/iw; a host
 * or lab build may need a different binary (or a shim that trims a radio's
 * huge virtual channel list), so allow an explicit override. */
static const char *iw_exe(void)
{
    const char *p = getenv("CAPAGENT_IW");
    return (p && *p) ? p : "/usr/sbin/iw";
}

/* Ciphers, chain masks and AP-interface limit from `iw phy phyN info`. */
static int nl_get_wiphy_ciphers(int phy, uint8_t *out, int outmax);

static void read_phy_caps(int phy, struct phy_caps *pc)
{
    phy = real_phy(phy);
    char cmd[128], line[256], pname[32];
    int in_ciph = 0;
    memset(pc, 0, sizeof(*pc));
    phy_name_by_index(phy, pname, sizeof(pname));
    snprintf(cmd, sizeof(cmd), "%s phy %s info 2>/dev/null", iw_exe(), pname);
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

#include "iw_freq.inc"

/* Supported frequencies/bands of a radio, from `iw phy phyN info`.  Falls
   back to the legacy 2.4/5 GHz tables only when iw gives nothing. */
static void read_phy_bands(int phy, struct phy_bands *pb)
{
    phy = real_phy(phy);
    char cmd[128], line[256], pname[32];
    int have2 = 0, have5 = 0, have6 = 0;
    memset(pb, 0, sizeof(*pb));
    phy_name_by_index(phy, pname, sizeof(pname));
    snprintf(cmd, sizeof(cmd), "%s phy %s info 2>/dev/null", iw_exe(), pname);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            uint32_t f;
            if (parse_iw_frequency(line, &f)) {
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
       "data channel not supported".  Keep bit 7 (MLO) clear.
       CAPAGENT_NEWPHY_84 / CAPAGENT_NEWPHY_86 / CAPAGENT_JOIN_A8 let a test
       sweep the capability fields the manager reads at join. */
    {
        uint8_t caps84[8] = { 0x40, 0x00, 0x00, 0x00 };
        size_t cl = 4;
        const char *e = getenv("CAPAGENT_NEWPHY_84");
        if (e && *e) {
            size_t k = 0;
            while (e[0] && e[1] && k < sizeof(caps84)) {
                unsigned v;
                if (sscanf(e, "%2x", &v) != 1) break;
                caps84[k++] = (uint8_t)v;
                e += 2;
            }
            if (k) cl = k;
        }
        n += put_el(b+n, 0x84, caps84, (uint16_t)cl);
        const char *e86 = getenv("CAPAGENT_NEWPHY_86");
        if (e86 && *e86) {
            uint8_t caps86[8];
            size_t k = 0;
            while (e86[0] && e86[1] && k < sizeof(caps86)) {
                unsigned v;
                if (sscanf(e86, "%2x", &v) != 1) break;
                caps86[k++] = (uint8_t)v;
                e86 += 2;
            }
            if (k) n += put_el(b+n, 0x86, caps86, (uint16_t)k);
        }
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
