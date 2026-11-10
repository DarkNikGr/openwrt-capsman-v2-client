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
    return (phy & 1) ? "mt76x2e" : "mt7603e";
}

/* 2.4 GHz channels 1-13 (channel 14 is disabled). */
static const uint32_t freqs_2g[] = {
    2412, 2417, 2422, 2427, 2432, 2437, 2442,
    2447, 2452, 2457, 2462, 2467, 2472
};
/* 5 GHz: 36-48, 52-64 (DFS), 100-144 (DFS), 149-177.  DFS channels are
   advertised: CAPsMAN may select them and the CAP runs CAC in hostapd. */
static const uint32_t freqs_5g[] = {
    5180, 5200, 5220, 5240,
    5260, 5280, 5300, 5320,
    5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640,
    5660, 5680, 5700, 5720,
    5745, 5765, 5785, 5805, 5825, 5845, 5865
};

static void build_newphy(uint8_t *b, const uint8_t mac[6], int phy, size_t *out)
{
    uint8_t v16[2], v32[4];
    /* MT7603E/MT7612E support TKIP and CCMP-128 only: no GCMP/GCMP-256 and
       no CCMP-256.  5ghz-ax is not advertised either (no HE). */
    static const uint8_t ciphers[8] = {
        0x00,0x0f,0xac,0x02,   /* TKIP */
        0x00,0x0f,0xac,0x04    /* CCMP-128 */
    };
    /* 0x4d = band id (1 byte) + supported-width bitmask (4-byte BE).
       mask: 1=20, 3=20/40, 7=20/40/80. */
    static const uint8_t bands_2g[][5] = {
        {0x81,0,0,0,0x01},     /* 2ghz-g: 20 MHz */
        {0x82,0,0,0,0x03}      /* 2ghz-n: 20/40 */
    };
    static const uint8_t bands_5g[][5] = {
        {0x01,0,0,0,0x01},     /* 5ghz-a: 20 MHz */
        {0x03,0,0,0,0x07}      /* 5ghz-ac: 20/40/80 */
    };
    const uint32_t *freqs = (phy & 1) ? freqs_5g : freqs_2g;
    size_t nfreq = (phy & 1) ? sizeof(freqs_5g)/sizeof(freqs_5g[0])
                             : sizeof(freqs_2g)/sizeof(freqs_2g[0]);
    const uint8_t (*bands)[5] = (phy & 1) ? bands_5g : bands_2g;
    size_t nbands = (phy & 1) ? sizeof(bands_5g)/sizeof(bands_5g[0])
                              : sizeof(bands_2g)/sizeof(bands_2g[0]);
    uint8_t fbuf[sizeof(freqs_5g) / sizeof(freqs_5g[0]) * 4];
    const char *hw = phy_hwtype(phy);
    size_t n = 0;

    for (size_t i = 0; i < nfreq; i++)
        put32(fbuf + i * 4, freqs[i]);

    n += put_el(b+n, 0x08, mac, 6);

    /* phy0 (MT7603E) allows 4 AP interfaces, phy1 (MT7612E) 8; max-peers
       defaults to 120 on both. */
    put16(v16, (phy & 1) ? 8 : 4);
    n += put_el(b+n, 0x7e, v16, 2);
    n += put_el(b+n, 0x7f, v16, 2);
    n += put_el(b+n, 0x80, v16, 2);
    put16(v16, 120);
    n += put_el(b+n, 0x81, v16, 2);

    /* 0x83 is a string (hw-type), not the old 8-byte capability blob. */
    n += put_el(b+n, 0x83, hw, (uint16_t)strlen(hw));

    put32(v32, 1);
    n += put_el(b+n, 0x8a, v32, 4);

    n += put_el(b+n, 0x5e, ciphers, sizeof(ciphers));
    n += put_el(b+n, 0x05, fbuf, (uint16_t)(nfreq * 4));

    /* Both radios are 2x2: chains 0 and 1. */
    put32(v32, 0x00000003);
    n += put_el(b+n, 0x4b, v32, 4);   /* tx chains */
    n += put_el(b+n, 0x4c, v32, 4);   /* rx chains */
    for (size_t i = 0; i < nbands; i++)
        n += put_el(b+n, 0x4d, bands[i], 5);

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

