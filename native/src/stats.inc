/* stats.inc — 0x200e signal + 0x2015 counters/rates
 * Part of capagent.c (single translation unit; included in order). */

static void put64(uint8_t *p, uint64_t v)
{
    put32(p, (uint32_t)(v >> 32));
    put32(p + 4, (uint32_t)v);
}

struct st_prev { int used; uint8_t mac[6]; uint64_t rx, tx; time_t t; };
static struct st_prev g_stprev[32];

static struct st_prev *st_prev_slot(const uint8_t *mac)
{
    int free_i = -1;
    for (int i = 0; i < 32; i++) {
        if (g_stprev[i].used && !memcmp(g_stprev[i].mac, mac, 6))
            return &g_stprev[i];
        if (!g_stprev[i].used && free_i < 0) free_i = i;
    }
    if (free_i >= 0) {
        memset(&g_stprev[free_i], 0, sizeof(g_stprev[free_i]));
        g_stprev[free_i].used = 1;
        memcpy(g_stprev[free_i].mac, mac, 6);
        return &g_stprev[free_i];
    }
    return NULL;
}

/* RouterOS 0x200e width code from the channel width in MHz. */
static unsigned chan_width_code(unsigned mhz)
{
    if (mhz >= 160) return 4;
    if (mhz >= 80)  return 3;
    if (mhz >= 40)  return 2;
    return 1;                           /* 20 MHz (also 5/10 MHz) */
}

/* Operating channel of an AP interface, from `iw dev <if> info`:
 *   channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
 * Leaves *freq / *width at 0 when the interface is down or absent. */
static void iface_chan(const char *ifn, unsigned *freq, unsigned *width)
{
    char cmd[96], line[256];
    *freq = 0;
    *width = 0;
    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s info 2>/dev/null", ifn);
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "channel ");
        if (p) sscanf(p, "channel %*d (%u MHz)", freq);
        p = strstr(line, "width: ");
        if (p) sscanf(p, "width: %u MHz", width);
    }
    pclose(fp);
}

/* "tx bitrate:\t866.7 MBit/s ..." -> kbit/s; the manager multiplies the
 * wire value by 1000 (work-T7 §4).  0 when absent or the rate is 0. */
static uint32_t iw_bitrate_kbps(const char *line, const char *tag)
{
    const char *p = strstr(line, tag);
    double v;
    if (!p || sscanf(p + strlen(tag), " %lf", &v) != 1 || v <= 0.0)
        return 0;
    if (strstr(p + strlen(tag), "GBit/s"))
        return (uint32_t)(v * 1000000.0 + 0.5);
    return (uint32_t)(v * 1000.0 + 0.5);
}

static void emit_station(mbedtls_ssl_context *ssl, int phy, int vap,
                         const uint8_t *mac, int sig,
                         uint64_t rx, uint64_t tx, uint64_t rxp, uint64_t txp,
                         unsigned freq, unsigned width,
                         uint32_t tx_kbps, uint32_t rx_kbps,
                         unsigned long inact_ms, unsigned long conn_s)
{
    uint8_t b[BODY_MAX], v2[2], v4[4], ch[40], st[44], rt[8], w;
    size_t n = 0, cn = 0;
    uint16_t port = (uint16_t)((phy << 8) | vap);
    time_t now = time(NULL);

    if (!freq) freq = (phy & 1) ? 5180 : 2437;          /* fallback */
    if (!width) width = (freq < 3000) ? 20 : 80;        /* fallback */

    /* 0x200E: station appeared/updated; this is the signal source. */
    n += put_el(b + n, 0x07, mac, 6);
    put16(v2, (uint16_t)freq);
    cn += put_el(ch + cn, 0x0b, v2, 2);
    w = (uint8_t)chan_width_code(width);
    cn += put_el(ch + cn, 0x0c, &w, 1);
    w = (freq < 3000) ? 0x81 : 0x03;
    cn += put_el(ch + cn, 0x10, &w, 1);
    n += put_el(b + n, 0x0a, ch, (uint16_t)cn);
    {   /* opaque station-info blob (24 dwords) copied into sta+0x18 */
        uint8_t si[96];
        memset(si, 0, sizeof(si));
        n += put_el(b + n, 0x16, si, sizeof(si));
    }
    put32(v4, (uint32_t)inact_ms);
    n += put_el(b + n, 0x15, v4, 4);
    put16(v2, 0);
    n += put_el(b + n, 0x17, v2, 2);
    n += put_el(b + n, 0x18, v2, 2);
    put32(v4, (uint32_t)(int32_t)sig);
    n += put_el(b + n, 0x19, v4, 4);
    put32(v4, 0);
    n += put_el(b + n, 0x1a, v4, 4);
    send_msg(ssl, 0x200e, port, b, (uint16_t)n);
    static time_t last_dbg;
    if (time(NULL) != last_dbg) {
        last_dbg = time(NULL);
        printf("stats tx %02x:%02x:%02x:%02x:%02x:%02x phy=%d vap=%d "
               "sig=%d freq=%u txr=%u rxr=%u rx=%llu tx=%llu rxp=%llu txp=%llu\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               phy, vap, sig, freq, tx_kbps, rx_kbps, rx, tx, rxp, txp);
        fflush(stdout);
    }

    /* 0x2015 PEERSTATSRESULT, corrected layout (work-T7/T15):
     *   0x3d +0x00 u32 freq (MHz)       +0x04 u32 tx PHY rate (kbit/s)
     *        +0x08 u32 rx PHY rate       +0x0c u64 tx-packets
     *        +0x14 u64 rx-packets        +0x1c u64 tx-bytes
     *        +0x24 u64 rx-bytes
     *   0x40 +0x00 u32 tx bytes/s       +0x04 u32 rx bytes/s
     * Uptime/last-activity are manager-local and are not sent. */
    n = 0;
    n += put_el(b + n, 0x08, mac, 6);
    struct st_prev *p = st_prev_slot(mac);
    uint32_t ta = 0, ra = 0;
    if (p && p->t && now > p->t) {
        uint32_t dt = (uint32_t)(now - p->t);
        if (tx >= p->tx) ta = (uint32_t)((tx - p->tx) / dt);
        if (rx >= p->rx) ra = (uint32_t)((rx - p->rx) / dt);
    }
    if (p) { p->rx = rx; p->tx = tx; p->t = now; }
    put32(st + 0, freq);
    put32(st + 4, tx_kbps);
    put32(st + 8, rx_kbps);
    put64(st + 12, txp);
    put64(st + 20, rxp);
    put64(st + 28, tx);
    put64(st + 36, rx);
    n += put_el(b + n, 0x3d, st, 44);
    put32(rt, ta);
    put32(rt + 4, ra);
    n += put_el(b + n, 0x40, rt, 8);
    send_msg(ssl, 0x2015, port, b, (uint16_t)n);
    (void)conn_s;                       /* manager derives uptime itself */
}

static void send_station_stats(mbedtls_ssl_context *ssl, const struct cfg *c)
{
    for (int phy = 0; phy < c->nradios; phy++) {
        for (int vap = 0; vap < 8; vap++) {
            char ifn[32], cmd[96], line[256];
            unsigned freq = 0, width = 0;
            uint32_t tx_kbps = 0, rx_kbps = 0, v;
            /* Production: phyN-apM.  Lab builds may pass the real netdev. */
            if (vap == 0 && phy < MAX_RADIOS && c->ifnames[phy][0])
                snprintf(ifn, sizeof(ifn), "%s", c->ifnames[phy]);
            else
                snprintf(ifn, sizeof(ifn), "phy%d-ap%d", phy, vap);
            iface_chan(ifn, &freq, &width);
            snprintf(cmd, sizeof(cmd),
                     "/usr/sbin/iw dev %s station dump 2>/dev/null", ifn);
            FILE *fp = popen(cmd, "r");
            if (!fp) continue;
            uint8_t mac[6]; int have = 0, sig = 0;
            unsigned long long rx = 0, tx = 0, rxp = 0, txp = 0;
            unsigned long inact = 0, conn = 0;
            while (fgets(line, sizeof(line), fp)) {
                unsigned int m[6];
                if (sscanf(line, "Station %x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    if (have)
                        emit_station(ssl, phy, vap, mac, sig, rx, tx, rxp,
                                     txp, freq, width, tx_kbps, rx_kbps,
                                     inact, conn);
                    for (int k = 0; k < 6; k++) mac[k] = (uint8_t)m[k];
                    have = 1; sig = 0;
                    rx = tx = rxp = txp = 0; inact = conn = 0;
                    tx_kbps = rx_kbps = 0;
                } else if (sscanf(line, " signal: %d", &sig) == 1) {
                } else if (sscanf(line, " rx bytes: %llu", &rx) == 1) {
                } else if (sscanf(line, " tx bytes: %llu", &tx) == 1) {
                } else if (sscanf(line, " rx packets: %llu", &rxp) == 1) {
                } else if (sscanf(line, " tx packets: %llu", &txp) == 1) {
                } else if (sscanf(line, " inactive time: %lu", &inact) == 1) {
                } else if (sscanf(line, " connected time: %lu", &conn) == 1) {
                } else if ((v = iw_bitrate_kbps(line, "tx bitrate:")) != 0) {
                    tx_kbps = v;
                } else if ((v = iw_bitrate_kbps(line, "rx bitrate:")) != 0) {
                    rx_kbps = v;
                }
            }
            if (have)
                emit_station(ssl, phy, vap, mac, sig, rx, tx, rxp, txp,
                             freq, width, tx_kbps, rx_kbps, inact, conn);
            pclose(fp);
        }
    }
}
