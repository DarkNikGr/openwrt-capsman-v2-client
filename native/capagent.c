// capagent - native MikroTik CAPsMAN v2 CAP agent for OpenWrt (mipsel)
// Speaks the CAPsMAN control protocol over TLS 1.2 (TCP 5246):
//   join 0x4029, NEWPHY 0x001d, create-vap 0x500b -> 0xd00b, destroy 0x600c -> 0xe00c,
//   echo 0x402b -> 0xc02b.
// Uses mbedTLS (already present on OpenWrt as libmbedtls).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <linux/if_ether.h>
#ifndef NLA_F_NESTED
#define NLA_F_NESTED (1 << 15)
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/build_info.h"

/* The CAPsMAN v2 datachan is AES-256-CCM (RFC 3610); fail early if the
   mbedTLS build cannot do it instead of at the first create. */
#if !defined(MBEDTLS_CCM_C)
#error "mbedTLS was built without MBEDTLS_CCM_C (datachan AES-CCM)"
#endif
#include "mbedtls/ccm.h"

#define TYPE_JOIN              0x4029
#define TYPE_JOIN_RESP         0xC029
#define TYPE_ECHO              0x402B
#define TYPE_ECHO_RESP         0xC02B
#define TYPE_NEWPHY            0x001D
#define TYPE_PROVISION         0x500B
#define TYPE_CREATEVAP_RESP    0xD00B
#define TYPE_DESTROY           0x600C
#define TYPE_DESTROY_RESP      0xE00C
#define TYPE_DISCONNECT        0x002A

/* CAPsMAN v2 station/RSN messages (T4/T5):
   0x2018 CAP->MGR  {3E = raw 802.11 assoc/reassoc request, 3F = freq u32}
   0x201B CAP->MGR  {08 = STA MAC, 3E = EAPOL frame}      (STA -> authenticator)
   0x201C MGR->CAP  {08 = STA MAC, 3E = EAPOL frame}      (authenticator -> STA)
   0x201F MGR->CAP  key descriptors (0050/005A/005B)      (PTK/GTK/IGTK)
   0x201A MGR->CAP  {08 = STA MAC}                        (DELSTA)
   Acks 0xE01C / 0xE01F. */
#define TYPE_ASSOC_FRAME       0x2018
#define TYPE_EAPOL_RX          0x201B
#define TYPE_EAPOL_TX          0x201C
#define TYPE_KEY_INSTALL       0x201F
#define TYPE_DEL_STA           0x201A
#define TYPE_EAPOL_TX_RESP     0xE01C
#define TYPE_KEY_RESP          0xE01F
#define TYPE_START             0x6016
#define TYPE_START_RESP        0xE016
#define TYPE_POLL              0x6027

#define ETH_P_EAPOL            0x888E
#define NL_MAX_MSG             8192

/* CAPsMAN v2 data channel (optional, UDP). The manager hands the id, port,
   cookie and AES-256 key to the CAP in the 0x500b create. */
#define DC_PORT_DEFAULT    5248
#define DC_ID_DEFAULT      428
#define DC_PFX_LEN         2    /* cleartext frame header: 0x10, flags    */
#define DC_HDR_LEN         8    /* c2 datachan header ("cdh")             */
#define DC_TAG_LEN         16
#define DC_NONCE_LEN       13
#define DC_COOKIE_MAX      16
#define DC_KEY_MAX         32
#define DC_MAX_PAYLOAD     2048
#define DC_KEEPALIVE_MS    2000     /* c2.ko manager keepalive timer */

/* frame header (pfx[0..1]), prepended by c2.ko cm_frag() */
#define DC_PFX_MAGIC       0x10     /* must be 0x10                         */
#define DC_PFX_FRAG        0x01     /* fragmented: 4 more header bytes      */
#define DC_PFX_KEEPALIVE   0x02     /* cookie keepalive, no cdh, no crypto  */

#define MAX_RADIOS 4
#define BODY_MAX   4096

struct cfg {
    const char *manager;        /* caps-man-addresses ("auto" = discover) */
    const char *port;
    const char *cert;
    const char *key;
    const char *ca_cert;        /* ca-certificate */
    const char *manager_cn;     /* caps-man-certificate-common-names */
    const char *identity;       /* CAP identity (WinBox "identity") */
    const char *serial;         /* CAP serial (WinBox "serial") */
    const char *discovery_if;   /* discovery-interfaces */
    const char *slaves_datapath;
    uint8_t a1[4];
    uint8_t e70[4];
    int lock_to_manager;
    int dont_verify;
    int slaves_static;
    int nradios;
    char ifnames[MAX_RADIOS][32];
    uint8_t macs[MAX_RADIOS][6];
    uint8_t dc_keyidx;          /* 0x500b TLV 0xa9, default 0 */
    int crypto_selftest;
    int datachan;
    int apply;
    int no_ack;
    int inject_assoc;
    uint16_t dc_port;
    uint16_t dc_id;
    uint8_t dc_key[DC_KEY_MAX];
    size_t dc_key_len;
    uint8_t dc_cookie[DC_COOKIE_MAX];
    size_t dc_cookie_len;
    /* EAPOL relay leg: 0 = control channel 0x201B, 1 = c2 datachan,
       2 = both.  See REPORT.md §3. */
    int eapol_leg;
    /* Lab/hwsim harness: bring up a minimal AP and drive the MLME locally. */
    const char *lab_iface;
    const char *lab_ssid;
    int lab_chan;
};

static mbedtls_x509_crt g_ca;
static int g_ca_loaded = 0;

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void put32(uint8_t *p, uint32_t v) { p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
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

/* ======================================================================
 * nl80211: 0x201C control-port injection, 0x201F key install, authorize.
 * T4's constants: NEW_KEY=11 SET_KEY=10 SET_STATION=18; ATTR_KEY=80,
 * KEY_DATA=1, KEY_IDX=2, KEY_CIPHER=3, KEY_SEQ=4, KEY_DEFAULT=5,
 * KEY_DEFAULT_MGMT=6, KEY_TYPE=7, KEY_DEFAULT_TYPES=8,
 * KEY_DEFAULT_TYPE_MULTICAST=2, STA_FLAGS2=67, AUTHORIZED=BIT(1).
 * ==================================================================== */

static int g_nl_family = -1;
static int g_nl_cmd_fd = -1;       /* synchronous commands            */
#ifdef CAPAGENT_LAB
static int g_nl_evt_fd = -1;       /* lab: mgmt + control-port events */
#endif
static uint32_t g_nl_seq;

struct nl_buf { struct nlmsghdr *nlh; uint8_t buf[NL_MAX_MSG]; };

static void nlb_init(struct nl_buf *m, uint16_t cmd, uint16_t flags)
{
    memset(m, 0, sizeof(*m));
    m->nlh = (struct nlmsghdr *)m->buf;
    m->nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    m->nlh->nlmsg_type = (uint16_t)g_nl_family;
    m->nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    m->nlh->nlmsg_seq = ++g_nl_seq;
    struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(m->nlh);
    g->cmd = cmd;
    g->version = 1;
}

static struct nlattr *nlb_put(struct nl_buf *m, uint16_t type,
                              const void *data, size_t len)
{
    size_t off = NLMSG_ALIGN(m->nlh->nlmsg_len);
    size_t alen = NLA_HDRLEN + len;
    if (off + NLA_ALIGN(alen) > sizeof(m->buf)) {
        fprintf(stderr, "nl80211: message overflow\n");
        return NULL;
    }
    struct nlattr *a = (struct nlattr *)(m->buf + off);
    a->nla_type = type;
    a->nla_len = (uint16_t)alen;
    if (len && data) memcpy((uint8_t *)a + NLA_HDRLEN, data, len);
    memset((uint8_t *)a + alen, 0, NLA_ALIGN(alen) - alen);
    m->nlh->nlmsg_len = off + NLA_ALIGN(alen);
    return a;
}
static void nlb_u8 (struct nl_buf *m, uint16_t t, uint8_t v)  { nlb_put(m,t,&v,1); }
static void nlb_u16(struct nl_buf *m, uint16_t t, uint16_t v) { nlb_put(m,t,&v,2); }
static void nlb_u32(struct nl_buf *m, uint16_t t, uint32_t v) { nlb_put(m,t,&v,4); }
static void nlb_flag(struct nl_buf *m, uint16_t t)            { nlb_put(m,t,NULL,0); }
static struct nlattr *nlb_nest(struct nl_buf *m, uint16_t t)
{
    return nlb_put(m, (uint16_t)(t | NLA_F_NESTED), NULL, 0);
}
static void nlb_nest_end(struct nl_buf *m, struct nlattr *a)
{
    a->nla_len = (uint16_t)((uint8_t *)m->buf + m->nlh->nlmsg_len -
                            (uint8_t *)a);
}

static int nl_send_ack(int fd, struct nl_buf *m)
{
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, m->buf, m->nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -errno;

    uint8_t rbuf[NL_MAX_MSG];
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 2000);
        if (pr == 0) return -ETIMEDOUT;
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        int n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != m->nlh->nlmsg_seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);
                return e->error;              /* 0 = ack */
            }
            if (nlh->nlmsg_type == NLMSG_DONE) return 0;
        }
    }
}

static int nl_open_socket(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) return -1;
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int nl_resolve_family(int fd)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        uint8_t buf[64];
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 0x5443;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;
    struct nlattr *a = (struct nlattr *)((uint8_t *)&req +
                                         NLMSG_ALIGN(req.n.nlmsg_len));
    a->nla_type = CTRL_ATTR_FAMILY_NAME;
    a->nla_len = NLA_HDRLEN + 8;
    memcpy((uint8_t *)a + NLA_HDRLEN, "nl80211", 8);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + NLA_ALIGN(a->nla_len);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.n.nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;

    uint8_t rbuf[4096];
    int n = recv(fd, rbuf, sizeof(rbuf), 0);
    if (n <= 0) return -1;
    for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
         nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        int alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
        struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                              GENL_HDRLEN);
        for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
             x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
             alen -= NLA_ALIGN(x->nla_len),
             x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
            if ((x->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID)
                return *(uint16_t *)((uint8_t *)x + NLA_HDRLEN);
        }
    }
    return -1;
}

static int nl_cmd_open(void)
{
    if (g_nl_cmd_fd >= 0) return 0;
    g_nl_family = -1;
    int fd = nl_open_socket();
    if (fd < 0) return -1;
    int fam = nl_resolve_family(fd);
    if (fam < 0) {
        close(fd);
        return -1;
    }
    g_nl_family = fam;
    g_nl_cmd_fd = fd;
    printf("nl80211: family=%d cmd-socket=%d\n", fam, fd);
    fflush(stdout);
    return 0;
}

/* port -> netdev.  The manager addresses a VAP as (phy<<8)|vapid; the
   interface created for it is phy<N>-ap<M> (see createvap_response). */
struct port_map {
    int used;
    int port;
    int ifindex;
    uint8_t mac[6];
};
static struct port_map g_pmap[16];

static void pmap_set(int port, int ifindex, const uint8_t mac[6])
{
    int slot = -1;
    for (int i = 0; i < 16; i++) {
        if (g_pmap[i].used && g_pmap[i].port == port) { slot = i; break; }
        if (!g_pmap[i].used && slot < 0) slot = i;
    }
    if (slot < 0) return;
    g_pmap[slot].used = 1;
    g_pmap[slot].port = port;
    g_pmap[slot].ifindex = ifindex;
    if (mac) memcpy(g_pmap[slot].mac, mac, 6);
}

static int pmap_get(int port, int *ifindex, uint8_t mac[6])
{
    for (int i = 0; i < 16; i++)
        if (g_pmap[i].used && g_pmap[i].port == port) {
            if (ifindex) *ifindex = g_pmap[i].ifindex;
            if (mac) memcpy(mac, g_pmap[i].mac, 6);
            return 1;
        }
    return 0;
}

/* Resolve (phy<<8)|vap to an ifindex, falling back to sysfs. */
static int vap_ifindex(int port, uint8_t mac[6])
{
    int ifindex = 0;
    if (pmap_get(port, &ifindex, mac) && ifindex > 0)
        return ifindex;
    char ifname[32];
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", port >> 8, port & 0xff);
    ifindex = read_sysfs_int(ifname, "ifindex");
    if (ifindex <= 0) {
        char alt[32];
        snprintf(alt, sizeof(alt), "wlan%d", (port >> 8) * 2 + (port & 1));
        ifindex = read_sysfs_int(alt, "ifindex");
        if (ifindex > 0) snprintf(ifname, sizeof(ifname), "%s", alt);
    }
    if (ifindex > 0) {
        if (mac) read_sysfs_mac(ifname, mac);
        pmap_set(port, ifindex, mac);
    }
    return ifindex;
}

/* One key.  group=0 -> PAIRWISE with ATTR_MAC; group=1 -> GTK/IGTK. */
static int nl_install_key(int ifindex, const uint8_t *mac, int idx,
                          uint32_t cipher, const uint8_t *key, size_t klen,
                          const uint8_t *seq, size_t slen, int group)
{
    if (ifindex <= 0 || !key || !klen) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_NEW_KEY, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    if (mac && !group) nlb_put(&m, NL80211_ATTR_MAC, mac, 6);

    struct nlattr *k = nlb_nest(&m, NL80211_ATTR_KEY);
    nlb_put(&m, NL80211_KEY_DATA, key, klen);
    nlb_u32(&m, NL80211_KEY_CIPHER, cipher);
    nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
    if (seq && slen) nlb_put(&m, NL80211_KEY_SEQ, seq, slen);
    nlb_u32(&m, NL80211_KEY_TYPE,
            group ? NL80211_KEYTYPE_GROUP : NL80211_KEYTYPE_PAIRWISE);
    nlb_nest_end(&m, k);
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* Make idx the default RX key.  GTK -> DEFAULT(+MULTICAST), IGTK ->
   DEFAULT_MGMT, BIGTK -> DEFAULT_BEACON (T4 §3.2). */
static int nl_set_default(int ifindex, int idx, int group, int is_igtk)
{
    if (ifindex <= 0) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_SET_KEY, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    struct nlattr *k = nlb_nest(&m, NL80211_ATTR_KEY);
    nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
    if (is_igtk && idx >= 4 && idx <= 5) {
        nlb_flag(&m, NL80211_KEY_DEFAULT_MGMT);
    } else if (is_igtk) {
        nlb_flag(&m, NL80211_KEY_DEFAULT_BEACON);
    } else {
        nlb_flag(&m, NL80211_KEY_DEFAULT);
        if (group) {
            struct nlattr *t = nlb_nest(&m, NL80211_KEY_DEFAULT_TYPES);
            nlb_flag(&m, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
            nlb_nest_end(&m, t);
        }
    }
    nlb_nest_end(&m, k);
    int r = nl_send_ack(g_nl_cmd_fd, &m);
    if (r == -EINVAL && !is_igtk) {
        /* Older kernels take the plain flag only. */
        nlb_init(&m, NL80211_CMD_SET_KEY, NLM_F_ACK);
        nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
        k = nlb_nest(&m, NL80211_ATTR_KEY);
        nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
        nlb_flag(&m, NL80211_KEY_DEFAULT);
        nlb_nest_end(&m, k);
        r = nl_send_ack(g_nl_cmd_fd, &m);
    }
    return r;
}

/* 4-way complete: exactly hostapd's SET_STATION STA_FLAGS2 AUTHORIZED. */
static int nl_sta_authorize(int ifindex, const uint8_t mac[6])
{
    if (ifindex <= 0) return -EINVAL;
    struct nl_buf m;
    struct nl80211_sta_flag_update upd;
    memset(&upd, 0, sizeof(upd));
    upd.mask = 1u << NL80211_STA_FLAG_AUTHORIZED;
    upd.set  = 1u << NL80211_STA_FLAG_AUTHORIZED;
    nlb_init(&m, NL80211_CMD_SET_STATION, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    nlb_put(&m, NL80211_ATTR_STA_FLAGS2, &upd, sizeof(upd));
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* Inject a bare EAPOL frame (EAPOL header first) to one station. */
static int nl_control_port_tx(int ifindex, const uint8_t mac[6],
                              const uint8_t *eapol, size_t len)
{
    if (ifindex <= 0 || !mac || !eapol || len < 4) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_CONTROL_PORT_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u16(&m, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_EAPOL);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    nlb_put(&m, NL80211_ATTR_FRAME, eapol, len);
    nlb_flag(&m, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* ---------------- TLV iterator (u16 tag | u16 len | value) ------------- */
struct tlv_it { const uint8_t *p; size_t len; };
static int tlv_next(struct tlv_it *it, uint16_t *tag,
                    const uint8_t **val, size_t *vlen)
{
    if (it->len < 4) return 0;
    uint16_t t = rd16(it->p), l = rd16(it->p + 2);
    if ((size_t)l > it->len - 4) return 0;
    *tag = t;
    *val = it->p + 4;
    *vlen = l;
    it->p += 4 + l;
    it->len -= 4 + l;
    return 1;
}

static void dump_raw(const char *tag, uint16_t type, uint16_t port,
                     const uint8_t *b, size_t n)
{
    int fd = open("/tmp/capagent-msgs.log",
                  O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;
    FILE *f = fdopen(fd, "a");
    if (!f) { close(fd); return; }
    fprintf(f, "%ld %s type=0x%04x port=0x%04x len=%zu ",
            (long)time(NULL), tag, type, port, n);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fprintf(f, "\n");
    fclose(f);
}

/* ---- 0xC029 config sync: optional 0x77 nested config tree ------------ */
/* Log/dump only: the tree is not applied yet.  Leaf keys are the ones
   recovered from the CAP config-apply path (arm ww2 0x41c18/0x422c0);
   the nesting above them is not decoded, so recurse into any element that
   looks like another TLV list. */

enum { CFG_STR, CFG_U32, CFG_U8 };

struct cfg_key {
    uint16_t id;
    const char *name;
    int kind;
};

static const struct cfg_key cfg_keys[] = {
    {0x1004, "ssid", CFG_STR},
    {0x200d, "iface-field", CFG_U32},
    {0xbb06, "vlan-id", CFG_U32},
    {0x6002, "datapath/security", CFG_U32},
    {0xd000, "authentication-types", CFG_U32},
    {0xd001, "cipher/pmf", CFG_U8},
    {0xd002, "security-field", CFG_U32},
    {0xd003, "cipher/pmf", CFG_U8},
    {0xd004, "cipher/pmf", CFG_U8},
    {0xd005, "security-field", CFG_U32},
    {0xd006, "security-field", CFG_U32},
    {0xd007, "security-field", CFG_U32},
    {0xd008, "security-field", CFG_U32},
    {0xd90f, "passphrase/dpp", CFG_STR},
    {0x2014, "pmf", CFG_U8},
    {0x2015, "key-holder", CFG_U32},
    {0x2017, "pmf", CFG_U8},
    {0x2018, "ptk", CFG_U32},
    {0x2019, "pmk-r0-key-holder-id", CFG_STR},
    {0x2021, "reassoc-timeout", CFG_U32},
    {0x2023, "pmf", CFG_U8},
};

struct cfg_seen {
    int have_ssid, have_vlan, have_auth, have_pass;
    char ssid[33];
    uint32_t vlan;
    uint32_t auth;
    char passphrase[64];
};

static struct cfg_seen g_cfg_seen;
static int g_cfg_lines;

static const struct cfg_key *cfg_key_find(uint16_t id)
{
    for (size_t i = 0; i < sizeof(cfg_keys)/sizeof(cfg_keys[0]); i++)
        if (cfg_keys[i].id == id) return &cfg_keys[i];
    return NULL;
}

static int tlv_walkable(const uint8_t *b, size_t n)
{
    size_t i = 0;
    int cnt = 0;

    while (i + 4 <= n) {
        uint16_t l = rd16(b + i + 2);
        if (i + 4 + l > n) return 0;
        i += 4 + l;
        cnt++;
    }
    return i == n && cnt > 0;
}

static void cfg_note(uint16_t id, const uint8_t *v, uint16_t len)
{
    size_t n;

    switch (id) {
    case 0x1004:
        n = len < sizeof(g_cfg_seen.ssid) - 1
              ? len : sizeof(g_cfg_seen.ssid) - 1;
        memcpy(g_cfg_seen.ssid, v, n);
        g_cfg_seen.ssid[n] = 0;
        g_cfg_seen.have_ssid = 1;
        break;
    case 0xbb06:
        if (len == 4) { g_cfg_seen.vlan = rd32(v); g_cfg_seen.have_vlan = 1; }
        break;
    case 0xd000:
        if (len == 4) { g_cfg_seen.auth = rd32(v); g_cfg_seen.have_auth = 1; }
        break;
    case 0xd90f:
        n = len < sizeof(g_cfg_seen.passphrase) - 1
              ? len : sizeof(g_cfg_seen.passphrase) - 1;
        memcpy(g_cfg_seen.passphrase, v, n);
        g_cfg_seen.passphrase[n] = 0;
        g_cfg_seen.have_pass = 1;
        break;
    }
}

static void cfg_leaf(const struct cfg_key *k, const uint8_t *v, uint16_t len,
                     int depth)
{
    char s[80];

    if (k->kind == CFG_STR) {
        size_t n = len < sizeof(s) - 1 ? len : sizeof(s) - 1;
        memcpy(s, v, n);
        s[n] = 0;
        for (size_t i = 0; i < n; i++)
            if (s[i] < 0x20 || s[i] > 0x7e) s[i] = '.';
        printf("%*s0x%04x %-24s \"%s\"\n", depth * 2, "", k->id, k->name, s);
    } else if (k->kind == CFG_U32) {
        uint32_t u = len >= 4 ? rd32(v) : 0;
        printf("%*s0x%04x %-24s %u (0x%08x)\n", depth * 2, "",
               k->id, k->name, u, u);
    } else {
        printf("%*s0x%04x %-24s %u\n", depth * 2, "", k->id, k->name,
               len ? v[0] : 0);
    }
    cfg_note(k->id, v, len);
}

static void cfg_walk(const uint8_t *b, size_t n, int depth)
{
    size_t i = 0;

    while (i + 4 <= n && g_cfg_lines < 512) {
        uint16_t id = rd16(b + i), len = rd16(b + i + 2);
        const uint8_t *v = b + i + 4;
        const struct cfg_key *k;

        if (i + 4 + len > n) break;
        g_cfg_lines++;
        k = cfg_key_find(id);
        if (k) {
            cfg_leaf(k, v, len, depth);
        } else {
            printf("%*s0x%04x %-24s len=%u%s\n", depth * 2, "", id,
                   "(container)", len, depth >= 4 ? " (max depth)" : "");
            if (depth < 4 && len >= 4 && tlv_walkable(v, len))
                cfg_walk(v, len, depth + 1);
        }
        i += 4 + len;
    }
}

/* ---- nv::flat_message ("M2") parser for the 0x77 config tree ---------- */
struct vapcfg {
    int have_ssid, have_vlan, have_auth, have_pass;
    char ssid[33];
    char pass[64];
    uint32_t vlan;
    uint32_t auth;
};

static struct vapcfg g_vaps[4];
static int g_nvap;
static int g_apply;

static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int parse_m2(const uint8_t *b, size_t n)
{
    if (n < 8 || b[4] != 'M' || b[5] != '2')
        return -1;
    uint32_t mlen = rd32le(b);
    size_t end = 4u + mlen;
    if (end > n) end = n;
    size_t p = 6;
    g_nvap = 0;
    while (p + 4 <= end) {
        uint32_t h = rd32le(b + p);
        uint32_t id = h & 0x00ffffffu;
        p += 4;
        if ((h & 0xff000000u) == 0x21000000u) {      /* bytes element */
            if (p >= end) break;
            uint8_t l = b[p++];
            if (p + l > end) break;
            if (id == 0x1004) {
                if (g_nvap < (int)(sizeof(g_vaps)/sizeof(g_vaps[0]))) {
                    struct vapcfg *v = &g_vaps[g_nvap];
                    memset(v, 0, sizeof(*v));
                    size_t k = l < sizeof(v->ssid) - 1 ? l : sizeof(v->ssid) - 1;
                    memcpy(v->ssid, b + p, k);
                    v->ssid[k] = 0;
                    v->have_ssid = 1;
                    g_nvap++;
                }
            } else if (id == 0x2000 && g_nvap > 0) {  /* passphrase */
                struct vapcfg *v = &g_vaps[g_nvap - 1];
                size_t k = l < sizeof(v->pass) - 1 ? l : sizeof(v->pass) - 1;
                memcpy(v->pass, b + p, k);
                v->pass[k] = 0;
                v->have_pass = 1;
            }
            p += l;
        } else if ((h & 0xff000000u) == 0x88000000u) { /* u32 array */
            if (p + 2 > end) break;
            uint16_t cnt = rd16le(b + p);
            p += 2;
            if (p + (size_t)cnt * 4 > end) break;
            if (g_nvap > 0 && cnt) {
                struct vapcfg *v = &g_vaps[g_nvap - 1];
                if (id == 0xbb06) { v->vlan = rd32le(b + p); v->have_vlan = 1; }
                else if (id == 0xd000) { v->auth = rd32le(b + p); v->have_auth = 1; }
            }
            p += (size_t)cnt * 4;
        } else {
            break;
        }
    }
    return g_nvap;
}

static int run_argv(char *const av[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(av[0], av);
        _exit(127);
    }
    if (pid < 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Set a UCI option without a shell: the value is passed as a single argv
   element, so quotes/semicolons in an SSID or passphrase cannot inject. */
static void uci_set_opt(const char *sec, const char *opt, const char *val)
{
    char kv[512];
    snprintf(kv, sizeof(kv), "wireless.%s.%s=%s", sec, opt, val);
    char *av[] = { "uci", "-q", "set", kv, NULL };
    if (run_argv(av) != 0)
        printf("apply: uci set wireless.%s.%s failed\n", sec, opt);
}

static void apply_vaps(void)
{
    if (!g_apply || g_nvap <= 0)
        return;

    FILE *p = popen("uci -q show wireless", "r");
    if (!p) {
        printf("apply: cannot read wireless config\n");
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), p)) {
        /* wireless.<sec>.network='wifi<vlan>' */
        char *d1 = strchr(line, '.');
        if (!d1) continue;
        char *d2 = strchr(d1 + 1, '.');
        if (!d2) continue;
        char *eq = strchr(d2, '=');
        if (!eq) continue;
        char *val = eq + 1;
        while (*val == '\'' || *val == '"') val++;
        if (strncmp(val, "wifi", 4) != 0) continue;
        unsigned vlan = (unsigned)atoi(val + 4);
        char sec[64];
        size_t sl = (size_t)(d2 - d1 - 1);
        if (sl == 0 || sl >= sizeof(sec)) continue;
        memcpy(sec, d1 + 1, sl);
        sec[sl] = 0;
        int ok = 1;
        for (size_t k = 0; k < sl; k++)
            if (!isalnum((unsigned char)sec[k]) && sec[k] != '_') ok = 0;
        if (!ok) continue;

        for (int i = 0; i < g_nvap; i++) {
            struct vapcfg *v = &g_vaps[i];
            if (!v->have_ssid || !v->have_pass) continue;
            unsigned vv = v->have_vlan && v->vlan ? v->vlan : 1;
            if (vv != vlan) continue;
            const char *sec_type =
                (v->have_auth && v->auth == 2) ? "sae" : "psk2";
            uci_set_opt(sec, "ssid", v->ssid);
            uci_set_opt(sec, "encryption", sec_type);
            uci_set_opt(sec, "key", v->pass);
            printf("apply: vlan=%u ssid=%s sec=%s (key not logged)\n",
                   vlan, v->ssid, sec_type);
        }
    }
    pclose(p);

    char *del1[] = { "uci", "-q", "delete", "wireless.capdyn_20", NULL };
    char *del2[] = { "uci", "-q", "delete", "wireless.capdyn_30", NULL };
    run_argv(del1);
    run_argv(del2);
    char *commit[] = { "uci", "-q", "commit", "wireless", NULL };
    run_argv(commit);
    char *r0[] = { "ubus", "call", "network.wireless", "reconf",
                   "{\"device\":\"radio0\"}", NULL };
    char *r1[] = { "ubus", "call", "network.wireless", "reconf",
                   "{\"device\":\"radio1\"}", NULL };
    run_argv(r0);
    run_argv(r1);
    printf("apply: wifi-iface sections updated (argv, no shell)\n");
}

static void handle_c029(const uint8_t *body, uint16_t len)
{
    const uint8_t *v = NULL, *tree = NULL;
    uint16_t vl = 0, tlen = 0;
    unsigned version = 0;

    if (find_el(body, len, 0xa7, &v, &vl) && vl)
        version = v[0];
    printf("RX 0xc029 joinresp len=%u version=%u\n", len, version);

    if (!find_el(body, len, 0x77, &tree, &tlen) || !tlen) {
        printf("0xc029: no 0x77 config tree (SSID/VLAN/security not "
               "delivered yet)\n");
        fflush(stdout);
        return;
    }

    dump_raw("cfg77", TYPE_JOIN_RESP, 0, tree, tlen);
    int cfd = open("/tmp/capagent-cfg77.bin",
                   O_CREAT | O_WRONLY | O_TRUNC, 0600);
    FILE *f = cfd >= 0 ? fdopen(cfd, "wb") : NULL;
    if (f) { fwrite(tree, 1, tlen, f); fclose(f); }
    printf("0xc029: 0x77 payload len=%u -> /tmp/capagent-cfg77.bin\n",
           tlen);

    memset(&g_cfg_seen, 0, sizeof(g_cfg_seen));
    g_cfg_lines = 0;
    if (parse_m2(tree, tlen) > 0) {
        printf("0xc029: parsed %d VAP(s) from M2 tree\n", g_nvap);
        for (int i = 0; i < g_nvap; i++)
            printf("  vap%d ssid=%s vlan=%u auth=%u pass=%s\n",
                   i, g_vaps[i].ssid, g_vaps[i].vlan,
                   g_vaps[i].auth, g_vaps[i].pass);
        apply_vaps();
    } else if (!tlv_walkable(tree, tlen)) {
        printf("0xc029: 0x77 is not an M2/nv::message tree, raw dump only\n");
    } else {
        printf("0xc029: parsing 0x77 as a TLV tree\n");
        cfg_walk(tree, tlen, 0);
        printf("0xc029: seen ssid=%s vlan=%u auth=0x%08x passphrase=%s\n",
               g_cfg_seen.have_ssid ? g_cfg_seen.ssid : "-",
               g_cfg_seen.have_vlan ? g_cfg_seen.vlan : 0,
               g_cfg_seen.have_auth ? g_cfg_seen.auth : 0,
               g_cfg_seen.have_pass ? g_cfg_seen.passphrase : "-");
    }
    printf("0xc029: %s\n", g_apply ? "applied to UCI" : "log/dump only");
    fflush(stdout);
}

static int vapid_for(int phy, const uint8_t mac[6]);

/* VLAN -> vapid map, learned from the a2=0 virtual creates.  The a2=1
   datachan creates carry the master MAC for every VLAN, so the MAC alone
   cannot identify the VAP. */
struct vlan_wid { int used; uint16_t vlan; int wid; };
static struct vlan_wid g_vw[2][16];

static void vlan_wid_set(int phy, uint16_t vlan, int wid)
{
    int r = phy & 1;
    for (int i = 0; i < 16; i++) {
        if (g_vw[r][i].used && g_vw[r][i].vlan == vlan) {
            g_vw[r][i].wid = wid;
            return;
        }
    }
    for (int i = 0; i < 16; i++) {
        if (!g_vw[r][i].used) {
            g_vw[r][i].used = 1;
            g_vw[r][i].vlan = vlan;
            g_vw[r][i].wid = wid;
            return;
        }
    }
}

static int vlan_wid_get(int phy, uint16_t vlan)
{
    int r = phy & 1;
    for (int i = 0; i < 16; i++)
        if (g_vw[r][i].used && g_vw[r][i].vlan == vlan)
            return g_vw[r][i].wid;
    return -1;
}

/* ---- optional datachan receiver (UDP 5248, AES-256-CCM) -------------- */

struct dc_ctx {
    int fd;
    int af;
    uint16_t id;
    uint16_t port;
    uint8_t cookie[DC_COOKIE_MAX];
    size_t cookie_len;
    uint8_t key[DC_KEY_MAX];
    size_t key_len;
    int have_key;
    uint8_t keyidx;             /* cdh[1] bit 7 */
    uint8_t rid, wid, flags;    /* cdh[0]; cdh[1] bits 3..0 / 6..4 */
    int have_hdr;
    uint64_t tx_seq;
    uint64_t rx_max;
    uint64_t rx_bitmap;
    int rx_started;
    struct sockaddr_storage peer;
    socklen_t peer_len;
};

/* One c2 key/cookie per (radio, wlan id): the manager sends a separate
   0x500b a2=1 for every VAP, all on the same datachan. */
struct dc_keyent {
    int used;
    uint8_t key[DC_KEY_MAX];
    size_t key_len;
    uint8_t cookie[DC_COOKIE_MAX];
    size_t cookie_len;
};
static struct dc_keyent g_dckey[2][16];

/* c2 datachan header ("cdh"), exactly as c2.ko cm_datachan_xmit() writes it:
     [0]      radio id (rid; 0x500b message port >> 8)
     [1]      bit7 keyidx | bits 6..4 flags | bits 3..0 wlan id (port & 0xff)
     [2..7]   48-bit sequence number, LITTLE-endian                        */
static void dc_hdr_write(uint8_t h[DC_HDR_LEN], uint8_t rid, uint8_t wid,
                         uint8_t flags, uint8_t keyidx, uint64_t seq)
{
    h[0] = rid;
    h[1] = (uint8_t)(((keyidx & 1) << 7) | ((flags & 7) << 4) | (wid & 0x0f));
    for (int i = 0; i < 6; i++)
        h[2 + i] = (uint8_t)(seq >> (8 * i));
}

static void dc_hdr_read(const uint8_t h[DC_HDR_LEN], uint8_t *rid,
                        uint8_t *wid, uint8_t *flags, uint8_t *keyidx,
                        uint64_t *seq)
{
    *rid = h[0];
    *keyidx = (uint8_t)((h[1] >> 7) & 1);
    *flags = (uint8_t)((h[1] >> 4) & 7);
    *wid = (uint8_t)(h[1] & 0x0f);
    *seq = 0;
    for (int i = 5; i >= 0; i--)
        *seq = (*seq << 8) | h[2 + i];
}

/* AES-CCM nonce.  c2.ko builds a 16-byte Linux ccm(aes) IV as
       { 0x01, cdh[0..7], 0,0,0,0,0,0,0 }      (iv[0] = L-1, so L = 2)
   i.e. the 13-byte CCM nonce is cdh[0..7] followed by five zero bytes.
   The cookie is NOT part of the nonce; it is only a keepalive token. */
static void dc_build_nonce(const uint8_t hdr[DC_HDR_LEN],
                           uint8_t nonce[DC_NONCE_LEN])
{
    memset(nonce, 0, DC_NONCE_LEN);
    memcpy(nonce, hdr, DC_HDR_LEN);
    /* nonce[8..12] stay zero */
}

static int dc_replay_ok(struct dc_ctx *d, uint64_t seq)
{
    uint64_t bit, dist;

    if (!d->rx_started) {
        d->rx_started = 1;
        d->rx_max = seq;
        d->rx_bitmap = 1;
        return 1;
    }
    if (seq > d->rx_max) {
        dist = seq - d->rx_max;
        d->rx_bitmap = dist >= 64 ? 0 : d->rx_bitmap << dist;
        d->rx_bitmap |= 1;
        d->rx_max = seq;
        return 1;
    }
    dist = d->rx_max - seq;
    if (dist >= 64) return 0;
    bit = 1ULL << dist;
    if (d->rx_bitmap & bit) return 0;
    d->rx_bitmap |= bit;
    return 1;
}

static int dc_open(struct dc_ctx *d, uint16_t port)
{
    int one = 1;

    d->af = (d->peer_len && d->peer.ss_family == AF_INET) ? AF_INET : AF_INET6;
    d->fd = socket(d->af, SOCK_DGRAM, 0);
    if (d->fd < 0) return -1;
    setsockopt(d->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (d->af == AF_INET6) {
        int off = 0;
        struct sockaddr_in6 sa;
        setsockopt(d->fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        sa.sin6_addr = in6addr_any;
        if (bind(d->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) goto fail;
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(d->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) goto fail;
    }
    fcntl(d->fd, F_SETFL, fcntl(d->fd, F_GETFL) | O_NONBLOCK);
    return 0;

fail:
    close(d->fd);
    d->fd = -1;
    return -1;
}

static void dc_set_peer(struct dc_ctx *d, int tls_fd, uint16_t port)
{
    d->peer_len = sizeof(d->peer);
    if (getpeername(tls_fd, (struct sockaddr *)&d->peer, &d->peer_len) != 0) {
        d->peer_len = 0;
        return;
    }
    if (d->peer.ss_family == AF_INET)
        ((struct sockaddr_in *)&d->peer)->sin_port = htons(port);
    else if (d->peer.ss_family == AF_INET6)
        ((struct sockaddr_in6 *)&d->peer)->sin6_port = htons(port);
}

static void dc_install(struct dc_ctx *d, const uint8_t *key, size_t key_len,
                       const uint8_t *cookie, size_t cookie_len,
                       uint16_t id, uint16_t port, uint8_t keyidx)
{
    d->id = id;
    d->port = port;
    d->have_key = 0;
    d->have_hdr = 0;
    d->rid = (uint8_t)(port >> 8);
    d->wid = (uint8_t)(port & 0xff);
    d->flags = 0;
    d->keyidx = keyidx;
    if (key && (key_len == 16 || key_len == 32)) {
        memcpy(d->key, key, key_len);
        d->key_len = key_len;
        d->have_key = 1;
    }
    if (cookie && cookie_len <= DC_COOKIE_MAX) {
        memcpy(d->cookie, cookie, cookie_len);
        d->cookie_len = cookie_len;
    }
}

/* Keepalive frame, exactly as c2.ko cm_datachan_keepalive() emits it once
   cm_frag() has prepended the frame header:  0x10 | 0x02 | cookie.
   There is no cdh and no encryption.  It is what teaches the manager our UDP
   source port (cm_datachan_match_keepalive: len-2 == cookielen, cookie at +2). */
static void dc_send_keepalive(struct dc_ctx *d)
{
    uint8_t pkt[DC_PFX_LEN + DC_COOKIE_MAX];

    if (d->fd < 0 || !d->peer_len) return;
    for (int r = 0; r < 2; r++) {
        for (int w = 0; w < 16; w++) {
            struct dc_keyent *e = &g_dckey[r][w];
            size_t n = 0;
            if (!e->used || !e->cookie_len) continue;
            pkt[n++] = DC_PFX_MAGIC;
            pkt[n++] = DC_PFX_KEEPALIVE;
            memcpy(pkt + n, e->cookie, e->cookie_len);
            n += e->cookie_len;
            sendto(d->fd, pkt, n, 0,
                   (struct sockaddr *)&d->peer, d->peer_len);
        }
    }
}

static int dc_decrypt_key(const uint8_t *key, size_t key_len,
                           const uint8_t hdr[DC_HDR_LEN],
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[DC_TAG_LEN], uint8_t *pt)
{
    mbedtls_ccm_context ccm;
    int ret = MBEDTLS_ERR_CCM_AUTH_FAILED;
    uint8_t nonce[DC_NONCE_LEN];

    mbedtls_ccm_init(&ccm);
    if (mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key,
                           (unsigned)key_len * 8) != 0) {
        mbedtls_ccm_free(&ccm);
        return -1;
    }
    dc_build_nonce(hdr, nonce);
    ret = mbedtls_ccm_auth_decrypt(&ccm, ct_len, nonce, sizeof(nonce),
                                   hdr, DC_HDR_LEN, ct, pt, tag, DC_TAG_LEN);
    mbedtls_ccm_free(&ccm);
    return ret == 0 ? 0 : -1;
}

static void dc_service(struct dc_ctx *d)
{
    uint8_t buf[DC_PFX_LEN + DC_HDR_LEN + DC_MAX_PAYLOAD + DC_TAG_LEN];
    uint8_t pt[DC_MAX_PAYLOAD];

    if (d->fd < 0) return;
    for (;;) {
        uint8_t rid, wid, flags, keyidx;
        uint64_t seq;
        const uint8_t *ct, *tag;
        size_t plen, ct_len;
        struct sockaddr_storage src;
        socklen_t slen = sizeof(src);
        ssize_t r = recvfrom(d->fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &slen);

        if (r < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (r < DC_PFX_LEN) continue;
        if (buf[0] != DC_PFX_MAGIC) {
            printf("datachan: bad frame magic 0x%02x\n", buf[0]);
            continue;
        }
        /* cm_datachan_match_keepalive(): len-2 == cookielen, cookie at +2.
           Take it from any source port and latch that port as the peer. */
        if (buf[1] & DC_PFX_KEEPALIVE) {
            int matched = 0;
            for (int r2 = 0; r2 < 2 && !matched; r2++)
                for (int w2 = 0; w2 < 16 && !matched; w2++) {
                    struct dc_keyent *e = &g_dckey[r2][w2];
                    if (e->used && e->cookie_len &&
                        (size_t)r == e->cookie_len + DC_PFX_LEN &&
                        !memcmp(buf + DC_PFX_LEN, e->cookie, e->cookie_len))
                        matched = 1;
                }
            if (!matched && d->cookie_len &&
                (size_t)r == d->cookie_len + DC_PFX_LEN &&
                !memcmp(buf + DC_PFX_LEN, d->cookie, d->cookie_len))
                matched = 1;
            if (matched) {
                if (!d->peer_len || memcmp(&src, &d->peer, sizeof(src)) != 0) {
                    memcpy(&d->peer, &src, sizeof(src));
                    d->peer_len = slen;
                    printf("datachan: peer learned from keepalive\n");
                }
                printf("datachan keepalive len=%d\n", (int)r);
                continue;
            }
        }
        if (buf[1] & DC_PFX_FRAG) {
            printf("datachan: fragmented frame, unsupported\n");
            continue;
        }
        if ((size_t)r < DC_PFX_LEN + DC_HDR_LEN + DC_TAG_LEN) continue;
        dc_hdr_read(buf + DC_PFX_LEN, &rid, &wid, &flags, &keyidx, &seq);
        if (!d->have_hdr) {
            d->rid = rid;
            d->wid = wid;
            d->keyidx = keyidx;     /* answer with the key the manager uses */
            d->have_hdr = 1;
        }
        plen = (size_t)r - DC_PFX_LEN - DC_HDR_LEN;
        ct = buf + DC_PFX_LEN + DC_HDR_LEN;
        {
            struct dc_keyent *ke = &g_dckey[rid & 1][wid & 0x0f];
            const uint8_t *kk = ke->used ? ke->key : d->key;
            size_t kkl = ke->used ? ke->key_len : d->key_len;
            if (!kkl || plen < DC_TAG_LEN) {
                printf("datachan frame rid=%u wid=%u len=%zu (no key)\n",
                       rid, wid, plen);
                continue;
            }
            ct_len = plen - DC_TAG_LEN;
            if (ct_len > sizeof(pt)) continue;
            tag = ct + ct_len;
            if (dc_decrypt_key(kk, kkl, buf + DC_PFX_LEN, ct, ct_len,
                               tag, pt) != 0) {
                printf("datachan auth failed rid=%u wid=%u keyidx=%u "
                       "flags=%u seq=%llu len=%zu\n", rid, wid, keyidx,
                       flags, (unsigned long long)seq, plen);
                continue;
            }
        }
        if (!dc_replay_ok(d, seq)) {
            printf("datachan replay dropped seq=%llu\n",
                   (unsigned long long)seq);
            continue;
        }
        printf("datachan rid=%u wid=%u seq=%llu payload=%zu\n",
               rid, wid, (unsigned long long)seq, ct_len);
        fflush(stdout);
    }
}

/* Transmit one Ethernet frame on the datachan, c2.ko layout:
       UDP payload = 10 | flags | cdh[8] | AES-CCM(ct||tag16)
   assoclen/AAD = cdh, nonce = cdh||0*5, seq increments per frame from 1. */
static int dc_send_frame(struct dc_ctx *d, const uint8_t *frame, size_t flen)
{
    uint8_t cdh[DC_HDR_LEN];
    uint8_t pkt[DC_PFX_LEN + DC_HDR_LEN + DC_MAX_PAYLOAD + DC_TAG_LEN];
    mbedtls_ccm_context ccm;
    int ret;

    if (d->fd < 0 || !d->have_key || !d->peer_len) return -1;
    if (flen > DC_MAX_PAYLOAD) return -1;

    pkt[0] = DC_PFX_MAGIC;
    pkt[1] = 0x00;                  /* unfragmented, not keepalive */
    dc_hdr_write(cdh, d->rid, d->wid, d->flags, d->keyidx, ++d->tx_seq);
    memcpy(pkt + DC_PFX_LEN, cdh, sizeof(cdh));

    mbedtls_ccm_init(&ccm);
    if (mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, d->key,
                           (unsigned)d->key_len * 8) != 0) {
        mbedtls_ccm_free(&ccm);
        return -1;
    }
    uint8_t nonce[DC_NONCE_LEN];
    dc_build_nonce(cdh, nonce);
    ret = mbedtls_ccm_encrypt_and_tag(&ccm, flen, nonce, sizeof(nonce),
                                      cdh, DC_HDR_LEN, frame,
                                      pkt + DC_PFX_LEN + DC_HDR_LEN,
                                      pkt + DC_PFX_LEN + DC_HDR_LEN + flen,
                                      DC_TAG_LEN);
    mbedtls_ccm_free(&ccm);
    if (ret != 0) return -1;
    return sendto(d->fd, pkt, DC_PFX_LEN + DC_HDR_LEN + flen + DC_TAG_LEN, 0,
                  (struct sockaddr *)&d->peer, d->peer_len) < 0 ? -1 : 0;
}

/* Install the id/port/cookie/key from a 0x500b create and start listening.
   The datachan is opt-in: without --datachan the fields are only logged. */
static void dc_handle_create(struct dc_ctx *d, const struct cfg *c,
                             mbedtls_net_context *tls, uint16_t create_port,
                             const uint8_t *body, uint16_t len)
{
    const uint8_t *v = NULL, *key = NULL, *cookie = NULL;
    uint16_t l = 0;
    uint16_t id = c->dc_id, port = c->dc_port;
    size_t key_len = 0, cookie_len = 0;
    uint8_t keyidx = c->dc_keyidx;

    if (find_el(body, len, 0x4a, &v, &l) && l == 4) id = (uint16_t)rd32(v);
    if (find_el(body, len, 0xa6, &v, &l) && l == 2) port = rd16(v);
    if (find_el(body, len, 0xa8, &v, &l) && (l == 16 || l == 32)) {
        key = v;
        key_len = l;
    }
    if (find_el(body, len, 0xaa, &v, &l) && l && l <= DC_COOKIE_MAX) {
        cookie = v;
        cookie_len = l;
    }
    /* 0xa9 = key index (c2.ko cm_datachan_key_add takes 0/1) */
    if (find_el(body, len, 0xa9, &v, &l) && l == 1) keyidx = (uint8_t)(v[0] & 1);
    if (!key && !cookie && !c->dc_key_len && !c->dc_cookie_len) return;

    if (c->dc_key_len) { key = c->dc_key; key_len = c->dc_key_len; }
    if (c->dc_cookie_len) {
        cookie = c->dc_cookie;
        cookie_len = c->dc_cookie_len;
    }

    /* Every VAP has its own a2=1 key/cookie on the shared datachan. */
    if (key) {
        const uint8_t *m = NULL; uint16_t ml = 0;
        if (find_el(body, len, 0x08, &m, &ml) && ml == 6) {
            int rid = create_port >> 8;
            uint16_t vlan = 0;
            int wid = -1;
            if (find_el(body, len, 0x7d, &v, &l) && l == 2) {
                vlan = rd16(v);
                wid = vlan_wid_get(rid, vlan);
            }
            if (wid < 0)
                wid = vapid_for(rid, m);
            struct dc_keyent *e = &g_dckey[rid & 1][wid & 0x0f];
            e->used = 1;
            memcpy(e->key, key, key_len);
            e->key_len = key_len;
            if (cookie && cookie_len) {
                memcpy(e->cookie, cookie, cookie_len);
                e->cookie_len = cookie_len;
            }
            printf("datachan: key rid=%d wid=%d vlan=%u keyidx=%u "
                   "cookie=%zuB\n", rid, wid, vlan, keyidx, cookie_len);
        }
    }

    printf("0x500b datachan id=%u port=%u key=%zuB cookie=%zuB\n",
           id, port, key_len, cookie_len);
    if (!c->datachan) {
        printf("datachan: disabled (use --datachan to receive)\n");
        fflush(stdout);
        return;
    }

    if (d->fd < 0) {
        dc_set_peer(d, tls->fd, port);
        if (dc_open(d, port) != 0) {
            fprintf(stderr, "datachan: cannot bind UDP %u\n", port);
            return;
        }
    } else {
        port = d->port;     /* already bound (test override): keep it */
    }
    dc_install(d, key, key_len, cookie, cookie_len, id, port, keyidx);
    dc_send_keepalive(d);
    printf("datachan: listening on UDP %u, id %u rid %u wid %u keyidx %u\n",
           port, id, d->rid, d->wid, d->keyidx);
    fflush(stdout);
}

/* Known-answer tests for the datachan crypto (--crypto-selftest). */
static int dc_selftest(void)
{
    uint8_t key[32], nonce[DC_NONCE_LEN], aad[16], pt[64];
    uint8_t out[64], dec[64], exp[64], tag[DC_TAG_LEN];
    mbedtls_ccm_context ccm;
    size_t n, en;
    int fail = 0, ret;

    /* RFC 3610 packet vector #1: AES-128, 13-byte nonce, 8-byte AAD,
       8-byte tag (not 16). */
    parse_hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF", key, sizeof(key));
    parse_hex("00000003020100A0A1A2A3A4A5", nonce, sizeof(nonce));
    parse_hex("0001020304050607", aad, sizeof(aad));
    n = parse_hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
                  pt, sizeof(pt));
    en = parse_hex("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"
                   "17E8D12CFDF926E0", exp, sizeof(exp));
    mbedtls_ccm_init(&ccm);
    ret = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 128);
    if (ret == 0)
        ret = mbedtls_ccm_encrypt_and_tag(&ccm, n, nonce, sizeof(nonce),
                                          aad, 8, pt, out, out + n, 8);
    mbedtls_ccm_free(&ccm);
    if (ret != 0 || en != n + 8 || memcmp(out, exp, en) != 0) fail++;
    printf("crypto-selftest: RFC 3610 #1 (AES-128/8-byte tag): %s\n",
           (ret == 0 && en == n + 8 && !memcmp(out, exp, en)) ? "ok"
                                                              : "FAIL");

    /* AES-256-CCM golden vector in the exact c2.ko layout: cdh =
       00 80 01 00 00 00 00 00 (rid 0, wid 0, keyidx 1, seq 1 LE),
       nonce = cdh || 00*5, 16-byte tag, AAD = the 8-byte cdh. */
    parse_hex("000102030405060708090A0B0C0D0E0F"
              "101112131415161718191A1B1C1D1E1F", key, sizeof(key));
    parse_hex("00800100000000000000000000", nonce, sizeof(nonce));
    parse_hex("0080010000000000", aad, sizeof(aad));
    n = parse_hex("434150734D414E2D763220646174616368616E2073656C6674657374",
                  pt, sizeof(pt));
    en = parse_hex("D60D4AEA0E6F89DF2031FB5AAA236B54C81277ADB33C41B0A3378451"
                   "3706BE545AFF87914C8D3E1B5ECDA7CD", exp, sizeof(exp));

    mbedtls_ccm_init(&ccm);
    ret = mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0)
        ret = mbedtls_ccm_encrypt_and_tag(&ccm, n, nonce, sizeof(nonce),
                                          aad, 8, pt, out, tag, DC_TAG_LEN);
    int enc_ok = ret == 0 && en == n + DC_TAG_LEN &&
                 !memcmp(out, exp, n) && !memcmp(tag, exp + n, DC_TAG_LEN);
    if (!enc_ok) fail++;
    printf("crypto-selftest: AES-256-CCM encrypt (c2.ko cdh, seq 1): %s\n",
           enc_ok ? "ok" : "FAIL");

    ret = mbedtls_ccm_auth_decrypt(&ccm, n, nonce, sizeof(nonce), aad, 8,
                                   out, dec, tag, DC_TAG_LEN);
    if (ret != 0 || memcmp(dec, pt, n) != 0) fail++;
    printf("crypto-selftest: AES-256-CCM decrypt: %s\n",
           (ret == 0 && !memcmp(dec, pt, n)) ? "ok" : "FAIL");

    tag[0] ^= 0x01;
    ret = mbedtls_ccm_auth_decrypt(&ccm, n, nonce, sizeof(nonce), aad, 8,
                                   out, dec, tag, DC_TAG_LEN);
    if (ret != MBEDTLS_ERR_CCM_AUTH_FAILED) fail++;
    printf("crypto-selftest: corrupted tag rejected: %s\n",
           ret == MBEDTLS_ERR_CCM_AUTH_FAILED ? "ok" : "FAIL");
    mbedtls_ccm_free(&ccm);

    printf("crypto-selftest: %s\n", fail ? "FAILED" : "all tests passed");
    return fail ? 1 : 0;
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The official manager's ActManBase::updateHwChans() rebuilds its supported
   channel vector (phy+0x20) and the matched regulatory rows (phy+0x28) from
   these.  Without them provisioning fails with "no available channels".
   Layout: 0x000A { 0x000B freq(BE32), 0x000C width=1, [0x0010 band=0x80] } */
static uint32_t ccfi80(uint32_t f)
{
    if (f >= 5180 && f <= 5240) return 5210;
    if (f >= 5260 && f <= 5320) return 5290;
    if (f >= 5500 && f <= 5560) return 5530;
    if (f >= 5580 && f <= 5640) return 5610;
    if (f >= 5660 && f <= 5720) return 5690;
    if (f >= 5745 && f <= 5805) return 5775;
    if (f >= 5825 && f <= 5865) return 5855;
    return f;
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The manager's ActManBase::updateHwChans() rebuilds phy+0x20 (+0x28 row ids)
   from these.  2.4 GHz: 20 MHz, band 0x81 (2ghz-g).  5 GHz: 80 MHz (width 3)
   with ccfi1, band 0x03 (5ghz-ac), because the 5 GHz configs use 20/40/80. */
static size_t add_channel_tlvs(uint8_t *b, size_t n, int phy)
{
    const uint32_t *freqs = (phy & 1) ? freqs_5g : freqs_2g;
    size_t nfreq = (phy & 1) ? sizeof(freqs_5g) / sizeof(freqs_5g[0])
                             : sizeof(freqs_2g) / sizeof(freqs_2g[0]);
    for (size_t i = 0; i < nfreq; i++) {
        uint8_t sub[40], f[4], c[4];
        size_t sn = 0;
        uint8_t width = (phy & 1) ? 3 : 1;
        uint8_t band = (phy & 1) ? 0x03 : 0x81;
        put32(f, freqs[i]);
        sn += put_el(sub + sn, 0x0b, f, 4);
        sn += put_el(sub + sn, 0x0c, &width, 1);
        if (phy & 1) {
            put32(c, ccfi80(freqs[i]));
            sn += put_el(sub + sn, 0x0d, c, 4);
        }
        sn += put_el(sub + sn, 0x10, &band, 1);
        n += put_el(b + n, 0x0a, sub, (uint16_t)sn);
    }
    return n;
}

/* Per-radio vapid allocation: the manager never tells the CAP which vapid to
   use, it only sends the (virtual) MAC in TLV 0x08.  We must return a unique
   0..15 per interface and keep it stable for the same MAC, otherwise the
   manager rejects the reply as a duplicate ("CREATEVAP bad response") and the
   virtual user stays in CreatingVap forever. */
static struct { int used; uint8_t mac[6]; } g_vmap[2][16];

static int vapid_for(int phy, const uint8_t mac[6])
{
    int r = phy & 1;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            return i;
    for (int i = 0; i < 16; i++)
        if (!g_vmap[r][i].used) {
            g_vmap[r][i].used = 1;
            memcpy(g_vmap[r][i].mac, mac, 6);
            return i;
        }
    return 0;
}

static void vapid_release(int phy, const uint8_t mac[6])
{
    int r = phy & 1;
    for (int i = 0; i < 16; i++)
        if (g_vmap[r][i].used && !memcmp(g_vmap[r][i].mac, mac, 6))
            g_vmap[r][i].used = 0;
}

static void createvap_response(mbedtls_ssl_context *ssl, const uint8_t hdr[10],
                               int phy, int vap, const struct cfg *c,
                               const uint8_t *req, uint16_t reqlen)
{
    uint8_t body[BODY_MAX], v[4], mac[6] = {0};
    char ifname[32];
    size_t n = 0;
    /* The manager identifies each interface only by the MAC in 0x08. */
    const uint8_t *rm = NULL; uint16_t rml = 0;
    int have_mac = find_el(req, reqlen, 0x08, &rm, &rml) && rml == 6;
    if (have_mac)
        memcpy(mac, rm, 6);
    else if (phy < c->nradios)
        memcpy(mac, c->macs[phy], 6);
    int vapid = vapid_for(phy, mac);
    {   /* remember which vapid owns this VLAN (needed for a2=1 keys) */
        const uint8_t *vv = NULL; uint16_t vl = 0;
        if (find_el(req, reqlen, 0x7d, &vv, &vl) && vl == 2)
            vlan_wid_set(phy, rd16(vv), vapid);
    }
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    if (c->no_ack) {
        /* A genuine CAP sends nothing when the data channel is created OK;
           0xD00B is only the failure path. */
        int ni = read_sysfs_int(ifname, "ifindex");
        if (ni > 0) pmap_set(phy << 8 | vap, ni, mac);
        printf("0xd00b phy=%d ifname=%s (no-ack: success reply suppressed)\n",
               phy, ifname);
        fflush(stdout);
        return;
    }
    int ifindex = read_sysfs_int(ifname, "ifindex");
    if (ifindex > 0) pmap_set(phy << 8 | vap, ifindex, mac);

    n += put_el(body+n, 0x08, mac, 6);
    put32(v, (uint32_t)vapid);
    n += put_el(body+n, 0x47, v, 4);
    put32(v, (uint32_t)ifindex);
    n += put_el(body+n, 0x48, v, 4);
    /* 0x49 is a nested submessage; the manager reads the interface name
       from its 0x9e element and ignores a raw string here. */
    uint8_t sub[64];
    size_t sn = put_el(sub, 0x9e, ifname, (uint16_t)strlen(ifname));
    n += put_el(body+n, 0x49, sub, (uint16_t)sn);

    /* Advertise this radio's channels so the stock manager can run chansel. */
    size_t nb = n;
    n = add_channel_tlvs(body, n, phy);   /* returns the absolute offset */
    size_t nc = n;

    /* 0x0061 = current operating frequency (BE32).  The manager stores it in
       phy+0x30 and sets "current freq known" (phy+0x34), which chansel uses. */
    {
        uint8_t cf[4];
        put32(cf, (phy & 1) ? 5180u : 2437u);
        n += put_el(body + n, 0x61, cf, 4);
    }
    size_t n61 = n;

    /* 0x00B7 = u32 key set used by ActAp::chansel (actman+0x220).  Send the
       same frequency list as BE32 values. */
    {
        const uint32_t *freqs = (phy & 1) ? freqs_5g : freqs_2g;
        size_t nfreq = (phy & 1) ? sizeof(freqs_5g) / sizeof(freqs_5g[0])
                                 : sizeof(freqs_2g) / sizeof(freqs_2g[0]);
        uint8_t list[sizeof(freqs_5g)];
        for (size_t i = 0; i < nfreq; i++) {
            uint32_t ch = (phy & 1) ? (freqs[i] - 5000) / 5
                                    : (freqs[i] - 2407) / 5;
            put32(list + i * 4, ch);
        }
        n += put_el(body + n, 0xb7, list, (uint16_t)(nfreq * 4));
    }

    printf("d00b build base=%zu chan=%zu(delta=%zu) c61=%zu b7=%zu\n",
           nb, nc, nc - nb, n61, n);

    {   /* dump the exact reply body for offline verification */
        char dp[64];
        snprintf(dp, sizeof(dp), "/tmp/capagent-d00b-%d.bin", phy);
        int dfd = open(dp, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        FILE *df = dfd >= 0 ? fdopen(dfd, "wb") : NULL;
        if (df) { fwrite(body, 1, n, df); fclose(df); }
    }

    uint8_t pkt[BODY_MAX + 16];
    size_t pn = put_msg(pkt, TYPE_CREATEVAP_RESP, 0, body, (uint16_t)n);
    memcpy(pkt + 2, hdr, 10);   /* same 10-byte header/sequence */
    (void)pn;
    /* send manually with the custom header */
    uint16_t len = (uint16_t)n;
    uint8_t out[BODY_MAX + 16];
    put16(out, TYPE_CREATEVAP_RESP);
    memcpy(out + 2, hdr, 10);
    put16(out + 12, len);
    memcpy(out + 14, body, len);
    size_t total = 14 + len, off = 0;
    while (off < total) {
        int r = mbedtls_ssl_write(ssl, out + off, total - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) break;
        off += r;
    }
    printf("0xd00b phy=%d vapid=%d ifindex=%d ifname=%s\n", phy, vapid, ifindex, ifname);
    fflush(stdout);
}

static void send_hdr_msg(mbedtls_ssl_context *ssl, uint16_t type,
                         const uint8_t hdr[10], const uint8_t *body, uint16_t len)
{
    uint8_t out[BODY_MAX + 16];
    put16(out, type);
    memcpy(out + 2, hdr, 10);
    put16(out + 12, len);
    if (len && body) memcpy(out + 14, body, len);
    size_t total = 14 + len, off = 0;
    while (off < total) {
        int r = mbedtls_ssl_write(ssl, out + off, total - off);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (r <= 0) break;
        off += r;
    }
}

/* ---- 0x201C / 0x201B: EAPOL relay ------------------------------- */

/* The control port ABI wants a bare EAPOL frame (EAPOL header first).
   Some builds/drivers hand us 802.3 or 802.11 framing; strip it. */
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
