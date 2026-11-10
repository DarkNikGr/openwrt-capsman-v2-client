// capagent - native MikroTik CAPsMAN v2 CAP agent for OpenWrt (mipsel)
// Speaks the CAPsMAN control protocol over TLS 1.2 (TCP 5246):
//   join 0x4029, NEWPHY 0x001d, create-vap 0x500b -> 0xd00b, destroy 0x600c -> 0xe00c,
//   echo 0x402b -> 0xc02b.
// Uses mbedTLS (already present on OpenWrt as libmbedtls).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

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
    uint16_t dc_port;
    uint16_t dc_id;
    uint8_t dc_key[DC_KEY_MAX];
    size_t dc_key_len;
    uint8_t dc_cookie[DC_COOKIE_MAX];
    size_t dc_cookie_len;
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

static void dump_raw(const char *tag, uint16_t type, uint16_t port,
                     const uint8_t *b, size_t n)
{
    FILE *f = fopen("/tmp/capagent-msgs.log", "a");
    if (!f) return;
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

static void apply_vaps(void)
{
    if (!g_apply || g_nvap <= 0)
        return;
    FILE *f = fopen("/tmp/capapply.sh", "w");
    if (!f) {
        printf("apply: cannot create /tmp/capapply.sh\n");
        return;
    }
    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "uci -q delete wireless.capdyn_20; "
               "uci -q delete wireless.capdyn_30\n");
    for (int i = 0; i < g_nvap; i++) {
        struct vapcfg *v = &g_vaps[i];
        if (!v->have_ssid || !v->have_pass)
            continue;
        unsigned vlan = v->have_vlan && v->vlan ? v->vlan : 1;
        const char *sec = (v->have_auth && v->auth == 2) ? "sae" : "psk2";
        fprintf(f, "for s in $(uci -q show wireless | "
                   "grep \"network='wifi%u'\" | cut -d. -f2 | sort -u); do\n",
                vlan);
        fprintf(f, "  uci -q set wireless.$s.ssid='%s'\n", v->ssid);
        fprintf(f, "  uci -q set wireless.$s.encryption='%s'\n", sec);
        fprintf(f, "  uci -q set wireless.$s.key='%s'\n", v->pass);
        fprintf(f, "done\n");
        printf("apply: vlan=%u ssid=%s sec=%s key=%s\n",
               vlan, v->ssid, sec, v->pass);
    }
    fprintf(f, "uci -q commit wireless\n");
    fprintf(f, "ubus call network.wireless reconf '{\"device\":\"radio0\"}'\n");
    fprintf(f, "ubus call network.wireless reconf '{\"device\":\"radio1\"}'\n");
    fclose(f);
    system("sh /tmp/capapply.sh");
    printf("apply: existing wifi-iface sections updated, reconf done\n");
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
    FILE *f = fopen("/tmp/capagent-cfg77.bin", "wb");
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
    size_t n = 0;

    if (d->fd < 0 || !d->cookie_len || !d->peer_len) return;
    pkt[n++] = DC_PFX_MAGIC;
    pkt[n++] = DC_PFX_KEEPALIVE;
    memcpy(pkt + n, d->cookie, d->cookie_len);
    n += d->cookie_len;
    sendto(d->fd, pkt, n, 0, (struct sockaddr *)&d->peer, d->peer_len);
}

static int dc_decrypt(struct dc_ctx *d, const uint8_t hdr[DC_HDR_LEN],
                      const uint8_t *ct, size_t ct_len,
                      const uint8_t tag[DC_TAG_LEN], uint8_t *pt)
{
    mbedtls_ccm_context ccm;
    int ret = MBEDTLS_ERR_CCM_AUTH_FAILED;
    uint8_t nonce[DC_NONCE_LEN];

    mbedtls_ccm_init(&ccm);
    if (mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, d->key,
                           (unsigned)d->key_len * 8) != 0) {
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
        if ((buf[1] & DC_PFX_KEEPALIVE) && d->cookie_len &&
            (size_t)r == d->cookie_len + DC_PFX_LEN &&
            !memcmp(buf + DC_PFX_LEN, d->cookie, d->cookie_len)) {
            if (!d->peer_len || memcmp(&src, &d->peer, sizeof(src)) != 0) {
                memcpy(&d->peer, &src, sizeof(src));
                d->peer_len = slen;
                printf("datachan: peer learned from keepalive\n");
            }
            printf("datachan keepalive len=%d\n", (int)r);
            continue;
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
        if (!d->have_key || plen < DC_TAG_LEN) {
            printf("datachan frame rid=%u wid=%u len=%zu (no key)\n",
                   rid, wid, plen);
            continue;
        }
        ct_len = plen - DC_TAG_LEN;
        if (ct_len > sizeof(pt)) continue;
        tag = ct + ct_len;
        if (dc_decrypt(d, buf + DC_PFX_LEN, ct, ct_len, tag, pt) != 0) {
            printf("datachan auth failed rid=%u wid=%u flags=%u seq=%llu "
                   "len=%zu\n", rid, wid, flags, (unsigned long long)seq, plen);
            continue;
        }
        if (!dc_replay_ok(d, seq)) {
            printf("datachan replay dropped seq=%llu\n",
                   (unsigned long long)seq);
            continue;
        }
        char path[64];
        snprintf(path, sizeof(path), "/tmp/capagent-dc-%llu.bin",
                 (unsigned long long)seq);
        FILE *f = fopen(path, "wb");
        if (f) { fwrite(pt, 1, ct_len, f); fclose(f); }
        printf("datachan rid=%u wid=%u seq=%llu payload=%zu -> %s\n",
               rid, wid, (unsigned long long)seq, ct_len, path);
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
                             mbedtls_net_context *tls,
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
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    if (c->no_ack) {
        /* A genuine CAP sends nothing when the data channel is created OK;
           0xD00B is only the failure path. */
        printf("0xd00b phy=%d ifname=%s (no-ack: success reply suppressed)\n",
               phy, ifname);
        fflush(stdout);
        return;
    }
    int ifindex = read_sysfs_int(ifname, "ifindex");

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
        FILE *df = fopen(dp, "wb");
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
    for (;;) {
        int r = read_exact(&ssl, fd.fd, hdr, 14);
        if (dc.fd >= 0) {
            dc_service(&dc);
            if (time(NULL) - last_dc_ka >= DC_KEEPALIVE_MS / 1000) {
                dc_send_keepalive(&dc);
                last_dc_ka = time(NULL);
            }
        }
        if (r == 0) {
            if (time(NULL) - last_echo > 5) {
                send_msg(&ssl, TYPE_ECHO, 0, NULL, 0);
                last_echo = time(NULL);
            }
            continue;
        }
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
            dc_handle_create(&dc, c, &fd, body, len);
        } else if (type == TYPE_DESTROY) {
            printf("RX 0x600c destroy\n");
            fflush(stdout);
            send_hdr_msg(&ssl, TYPE_DESTROY_RESP, hdr + 2, NULL, 0);
        } else if (type == TYPE_JOIN_RESP) {
            dump_raw("joinresp", type, port, body, len);
            handle_c029(body, len);
        } else if (type == 0x6027) {   /* periodic status poll */
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
            if ((++n27 % 100) == 1) {
                printf("RX 0x6027 poll (count=%d) -> 0xE027 len=%zu\n",
                       n27, z27);
                fflush(stdout);
            }
        } else if (type == 0x201f) {   /* security key material per VAP */
            dump_raw("sec201f", type, port, body, len);
            printf("RX 0x201f security port=0x%04x len=%u -> ack 0xE01F\n",
                   port, len);
            fflush(stdout);
            send_hdr_msg(&ssl, 0xE01F, hdr + 2, NULL, 0);
        } else if (type == 0x6016) {   /* ActAp start/config push (SSID/RSN/chan) */
            dump_raw("start", type, port, body, len);
            printf("RX 0x6016 start port=0x%04x len=%u -> ack 0xE016\n", port, len);
            fflush(stdout);
            send_hdr_msg(&ssl, 0xE016, hdr + 2, NULL, 0);
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
        if (time(NULL) - last_echo > 5) {
            send_msg(&ssl, TYPE_ECHO, 0, NULL, 0);
            last_echo = time(NULL);
        }
    }

out:
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
        "  --apply                      write 0x77 SSID/VLAN/key to UCI (radio1)\n",
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
           OPT_DC_COOKIE, OPT_DC_ID, OPT_APPLY, OPT_NOACK };
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
        default: usage(argv[0]); return 1;
        }
    }
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
