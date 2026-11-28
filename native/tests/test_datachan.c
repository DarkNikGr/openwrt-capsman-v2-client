/* Host unit tests for the c2 datachan's per-VAP state.
 *
 * The datachan module is normally part of the single capagent translation
 * unit.  This test provides the small set of VAP/registry helpers it needs,
 * then includes src/datachan.inc unchanged so the shipped code is what is
 * exercised.  No radio, AF_PACKET socket or manager is touched.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "mbedtls/ccm.h"
#include "mbedtls/net_sockets.h"

#define MAX_RADIOS 8
#define DC_PFX_LEN       2
#define DC_HDR_LEN       8
#define DC_TAG_LEN       16
#define DC_NONCE_LEN     13
#define DC_COOKIE_MAX    16
#define DC_KEY_MAX       32
#define DC_MAX_PAYLOAD   2048
#define DC_PFX_MAGIC     0x10
#define DC_PFX_FRAG      0x01
#define DC_PFX_KEEPALIVE 0x02

struct cfg {
    int dc_peer_port;
    int datachan;
    uint16_t dc_id;
    uint16_t dc_port;
    uint8_t dc_key[DC_KEY_MAX];
    size_t dc_key_len;
    uint8_t dc_cookie[DC_COOKIE_MAX];
    size_t dc_cookie_len;
    uint8_t dc_keyidx;
};

struct vap {
    int used;
    int rid, wid;
    uint8_t key[DC_KEY_MAX];
    size_t klen;
    uint8_t keyidx;
    uint8_t slot_key[2][DC_KEY_MAX];
    size_t slot_keylen[2];
    int slot_valid[2];
    uint64_t tx_seq, rx_max, rx_bitmap;
    int rx_started;
    int dc_variant;
    int dc_variant_set;
};
static struct vap g_vap[MAX_RADIOS][16];

static struct vap *vap_get(int rid, int wid)
{
    if (rid < 0 || wid < 0) return NULL;
    struct vap *v = &g_vap[rid % MAX_RADIOS][wid & 0x0f];
    return v->used ? v : NULL;
}

struct dc_ctx;

/* Mirrors datapath.inc's vap_set_key (including the new per-VAP slot). */
static void vap_set_key(int rid, int wid, const uint8_t *key, size_t klen,
                        uint8_t keyidx)
{
    if (rid < 0 || wid < 0) return;
    struct vap *v = &g_vap[rid % MAX_RADIOS][wid & 0x0f];
    if (key && (klen == 16 || klen == 32)) {
        memcpy(v->slot_key[keyidx & 1], key, klen);
        v->slot_keylen[keyidx & 1] = klen;
        v->slot_valid[keyidx & 1] = 1;
        memcpy(v->key, key, klen);
        v->klen = klen;
        v->keyidx = keyidx;
        v->tx_seq = 0;
    }
}

static void dp_rx_frame(struct dc_ctx *d, int rid, int wid,
                        const uint8_t *pt, size_t plen)
{
    (void)d; (void)rid; (void)wid; (void)pt; (void)plen;
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
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

struct vlan_wid { int used; uint16_t vlan; int wid; };
static struct vlan_wid g_vw[MAX_RADIOS][16];
static int vapid_for(int phy, const uint8_t mac[6])
{
    (void)phy; (void)mac;
    return -1;
}

#include "../src/datachan.inc"

static size_t put_el(uint8_t *p, uint16_t id, const void *data, uint16_t len)
{
    p[0] = (uint8_t)(id >> 8); p[1] = (uint8_t)id;
    p[2] = (uint8_t)(len >> 8); p[3] = (uint8_t)len;
    if (len && data) memcpy(p + 4, data, len);
    return 4 + len;
}

static void reset_state(void)
{
    memset(g_vap, 0, sizeof(g_vap));
    memset(g_dckey, 0, sizeof(g_dckey));
    memset(g_vw, 0, sizeof(g_vw));
}

static void test_variant_per_vap(void)
{
    struct dc_ctx d;
    struct vap *v;

    reset_state();
    memset(&d, 0, sizeof(d));
    d.variant = 2;
    v = &g_vap[0][1];
    v->used = 1;
    assert(dc_variant_for(v, &d) == 2);     /* never seen a2: fallback */
    v->dc_variant = 1;
    v->dc_variant_set = 1;
    assert(dc_variant_for(v, &d) == 1);     /* explicit a2=1 wins */
    v->dc_variant = 0;
    assert(dc_variant_for(v, &d) == 0);     /* a2=0 is a real value */
    v->dc_variant = 2;
    assert(dc_variant_for(v, &d) == 2);
    /* A create may arrive before the VAP is registered. */
    dc_store_variant(0, 3, 2);
    assert(g_vap[0][3].dc_variant_set && g_vap[0][3].dc_variant == 2);
    puts("ok: per-VAP a2 (0/1/2) selection");
}

static void test_tx_key_per_vap(void)
{
    struct dc_ctx d;
    struct vap *v;
    const uint8_t *key;
    size_t klen;
    uint8_t keyidx;
    uint8_t ka[16], kb[16];

    reset_state();
    memset(&d, 0, sizeof(d));
    memset(ka, 0xaa, sizeof(ka));
    memset(kb, 0xbb, sizeof(kb));
    /* Another VAP's create left slot 0 of the shared dc_ctx pointing at kb. */
    memcpy(d.slot_key[0], kb, sizeof(kb));
    d.slot_keylen[0] = sizeof(kb);
    d.slot_valid[0] = 1;
    d.active = 0;
    memcpy(d.key, kb, sizeof(kb));
    d.key_len = sizeof(kb);
    d.have_key = 1;
    d.rid = 0;
    d.wid = 0;

    v = &g_vap[0][1];
    memcpy(v->slot_key[0], ka, sizeof(ka));
    v->slot_keylen[0] = sizeof(ka);
    v->slot_valid[0] = 1;
    memcpy(v->key, ka, sizeof(ka));
    v->klen = sizeof(ka);
    v->keyidx = 0;

    assert(dc_select_tx_key(v, &d, 0, 1, &key, &klen, &keyidx) == 0);
    assert(klen == sizeof(ka));
    assert(!memcmp(key, ka, sizeof(ka)));
    assert(memcmp(key, kb, sizeof(kb)) != 0);
    assert(keyidx == 0);

    /* A VAP with no per-VAP key may use the matching global override only. */
    memset(v->slot_valid, 0, sizeof(v->slot_valid));
    v->klen = 0;
    key = NULL;
    assert(dc_select_tx_key(v, &d, 1, 2, &key, &klen, &keyidx) != 0);
    puts("ok: TX picks the per-VAP key, not the global active slot");
}

static void test_rx_key_per_vap(void)
{
    struct dc_ctx d;
    struct dc_keyent *ke;
    struct vap *v;
    const uint8_t *keys[8];
    size_t lens[8];
    uint8_t ka[16], kb[16];
    int n, i, leaked = 0;

    reset_state();
    memset(&d, 0, sizeof(d));
    memset(ka, 0xaa, sizeof(ka));
    memset(kb, 0xbb, sizeof(kb));
    memcpy(d.slot_key[0], kb, sizeof(kb));
    d.slot_keylen[0] = sizeof(kb);
    d.slot_valid[0] = 1;
    d.active = 0;
    memcpy(d.key, kb, sizeof(kb));
    d.key_len = sizeof(kb);
    d.have_key = 1;

    v = &g_vap[0][1];
    memcpy(v->slot_key[0], ka, sizeof(ka));
    v->slot_keylen[0] = sizeof(ka);
    v->slot_valid[0] = 1;
    memcpy(v->key, ka, sizeof(ka));
    v->klen = sizeof(ka);
    v->keyidx = 0;

    ke = &g_dckey[0][1];
    memset(ke, 0, sizeof(*ke));
    ke->used = 1;
    memcpy(ke->key, ka, sizeof(ka));
    ke->key_len = sizeof(ka);

    n = dc_rx_key_candidates(v, &d, ke, 0, keys, lens, 8);
    assert(n > 0);
    assert(lens[0] == sizeof(ka));
    assert(!memcmp(keys[0], ka, sizeof(ka)));

    /* keyidx=1 is not installed on this VAP: the per-VAP key still wins. */
    n = dc_rx_key_candidates(v, &d, ke, 1, keys, lens, 8);
    assert(n > 0);
    assert(lens[0] == sizeof(ka));
    assert(!memcmp(keys[0], ka, sizeof(ka)));
    /* The unrelated global key may remain as a last-resort fallback. */
    for (i = 0; i < n; i++)
        if (lens[i] == sizeof(kb) && !memcmp(keys[i], kb, sizeof(kb)))
            leaked = i;
    assert(leaked == 0 || leaked == n - 1);
    puts("ok: RX candidates prefer the VAP key/slots over global slots");
}

static void test_replay_window(void)
{
    uint64_t max = 0, bitmap = 0;
    int started = 0;

    assert(dc_replay_window(&max, &bitmap, &started, 1) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 2) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 4) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 3) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 3) == 0); /* dup */
    assert(dc_replay_window(&max, &bitmap, &started, 1) == 0); /* old */
    assert(dc_replay_window(&max, &bitmap, &started, 100) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 30) == 0); /* < window */
    assert(dc_replay_window(&max, &bitmap, &started, 99) == 1);
    assert(dc_replay_window(&max, &bitmap, &started, 100) == 0);
    puts("ok: 64-packet replay window");
}

static void test_rekey_skips_plain_vap(void)
{
    struct dc_ctx d;
    struct vap *sec, *plain;
    uint8_t kold[16], knew[32], kplain[16];
    struct dc_keyent *es, *ep;

    reset_state();
    memset(&d, 0, sizeof(d));
    memset(kold, 0x11, sizeof(kold));
    memset(knew, 0x22, sizeof(knew));
    memset(kplain, 0x33, sizeof(kplain));
    d.active = 0;
    memcpy(d.slot_key[0], kold, sizeof(kold));
    d.slot_keylen[0] = sizeof(kold);
    d.slot_valid[0] = 1;

    sec = &g_vap[0][0];
    sec->used = 1;
    sec->dc_variant = 2;
    sec->dc_variant_set = 1;
    memcpy(sec->slot_key[0], kold, sizeof(kold));
    sec->slot_keylen[0] = sizeof(kold);
    sec->slot_valid[0] = 1;
    memcpy(sec->key, kold, sizeof(kold));
    sec->klen = sizeof(kold);
    sec->keyidx = 0;
    sec->tx_seq = 42;
    sec->rx_started = 1;
    sec->rx_max = 500;

    plain = &g_vap[0][1];
    plain->used = 1;
    plain->dc_variant = 1;
    plain->dc_variant_set = 1;
    memcpy(plain->key, kplain, sizeof(kplain));
    plain->klen = sizeof(kplain);
    plain->keyidx = 0;
    plain->tx_seq = 7;
    plain->rx_started = 1;
    plain->rx_max = 9;

    es = &g_dckey[0][0];
    es->used = 1;
    memcpy(es->key, kold, sizeof(kold));
    es->key_len = sizeof(kold);
    ep = &g_dckey[0][1];
    ep->used = 1;
    memcpy(ep->key, kplain, sizeof(kplain));
    ep->key_len = sizeof(kplain);

    assert(dc_rekey(&d, 1, knew, sizeof(knew)) == 0);

    /* Secure VAP: new slot, active moved, both directions restarted. */
    assert(sec->slot_valid[1]);
    assert(sec->slot_keylen[1] == sizeof(knew));
    assert(!memcmp(sec->slot_key[1], knew, sizeof(knew)));
    assert(sec->keyidx == 1);
    assert(sec->tx_seq == 0);
    assert(sec->rx_started == 0);
    assert(!memcmp(sec->key, knew, sizeof(knew)));

    /* Plain VAP: untouched, including its sequence and replay state. */
    assert(!plain->slot_valid[1]);
    assert(plain->keyidx == 0);
    assert(plain->tx_seq == 7);
    assert(plain->rx_started == 1);
    assert(plain->rx_max == 9);
    assert(!memcmp(plain->key, kplain, sizeof(kplain)));
    assert(!memcmp(ep->key, kplain, sizeof(kplain)));
    puts("ok: 0x402b rekey only touches a2=2 VAPs");
}

static void test_create_variant_uses_resolved_vap(void)
{
    struct dc_ctx d;
    struct cfg c;
    mbedtls_net_context tls;
    uint8_t body[128];
    size_t n = 0;
    uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 1 };
    uint8_t key[32], cookie[16] = { 0 };
    uint8_t vlan[2] = { 0x00, 0x28 };      /* VLAN 40 */
    uint8_t a2 = 2, ki = 1;

    reset_state();
    memset(&d, 0, sizeof(d));
    memset(&c, 0, sizeof(c));
    memset(&tls, 0, sizeof(tls));
    memset(key, 0x44, sizeof(key));
    g_vw[0][0].used = 1;
    g_vw[0][0].vlan = 40;
    g_vw[0][0].wid = 3;                     /* VLAN 40 lives at wid 3 */
    n += put_el(body + n, 0x08, mac, 6);
    n += put_el(body + n, 0x7d, vlan, 2);
    n += put_el(body + n, 0xa8, key, 32);
    n += put_el(body + n, 0xa9, &ki, 1);
    n += put_el(body + n, 0xaa, cookie, 16);
    n += put_el(body + n, 0xa2, &a2, 1);

    /* Request port names wid 0 (the master), but the VLAN resolves to wid 3. */
    dc_handle_create(&d, &c, &tls, 0x0000, body, (uint16_t)n);
    assert(g_vap[0][3].dc_variant_set);
    assert(g_vap[0][3].dc_variant == 2);
    assert(!g_vap[0][0].dc_variant_set);
    assert(g_vap[0][3].klen == 32);
    assert(g_vap[0][3].slot_valid[1]);

    /* a2=0 has no key/cookie: it must still be recorded, on the request VAP. */
    reset_state();
    memset(&d, 0, sizeof(d));
    memset(&c, 0, sizeof(c));
    a2 = 0;
    n = 0;
    n += put_el(body + n, 0xa2, &a2, 1);
    dc_handle_create(&d, &c, &tls, 0x0102, body, (uint16_t)n);
    assert(g_vap[1][2].dc_variant_set);
    assert(g_vap[1][2].dc_variant == 0);
    puts("ok: a2 stored on the VLAN-resolved VAP (and a2=0 kept)");
}

int main(void)
{
    test_variant_per_vap();
    test_tx_key_per_vap();
    test_rx_key_per_vap();
    test_replay_window();
    test_rekey_skips_plain_vap();
    test_create_variant_uses_resolved_vap();
    puts("test_datachan: all tests passed");
    return 0;
}
