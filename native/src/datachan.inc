/* datachan.inc — c2 datachan: AES-CCM/plain, keepalive, per-VAP keys, rekey
 * Part of capagent.c (single translation unit; included in order).
 * Merges U11 P1/P2 (per-VAP key/seq/replay) with U16 (a2=1 plain vs a2=2
 * secure, 0x402b two-slot rekey).
 */

static void vlan_wid_set(int phy, uint16_t vlan, int wid)
{
    int r = phy % MAX_RADIOS;
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
    int r = phy % MAX_RADIOS;
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
    int variant;                /* 0x500b TLV 0xa2: 1 plain, 2 AES-CCM */
    int secure;                 /* variant != 1 */
    int slot_valid[2];          /* c2 key slots, selected by cdh[1] bit 7 */
    uint8_t slot_key[2][DC_KEY_MAX];
    size_t slot_keylen[2];
    int active;                 /* c2 ch+0x48 */
    int pending_del;            /* old slot deleted 1 s after a rotation */
    uint64_t pending_ms;
    uint64_t rx_max;
    uint64_t rx_bitmap;
    int rx_started;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    const struct cfg *cfg;      /* for the lab --dc-peer-port override */
};

/* One c2 key/cookie per (radio, wlan id): the manager sends a separate
   0x500b per VAP, all on the same datachan. */
struct dc_keyent {
    int used;
    uint8_t key[DC_KEY_MAX];
    size_t key_len;
    uint8_t cookie[DC_COOKIE_MAX];
    size_t cookie_len;
};
static struct dc_keyent g_dckey[MAX_RADIOS][16];

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

static uint64_t dc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int dc_replay_window(uint64_t *max, uint64_t *bitmap, int *started,
                            uint64_t seq)
{
    uint64_t bit, dist;

    if (!*started) {
        *started = 1;
        *max = seq;
        *bitmap = 1;
        return 1;
    }
    if (seq > *max) {
        dist = seq - *max;
        *bitmap = dist >= 64 ? 0 : *bitmap << dist;
        *bitmap |= 1;
        *max = seq;
        return 1;
    }
    dist = *max - seq;
    if (dist >= 64) return 0;
    bit = 1ULL << dist;
    if (*bitmap & bit) return 0;
    *bitmap |= bit;
    return 1;
}

static int dc_replay_ok(struct vap *v, uint64_t seq)
{
    return dc_replay_window(&v->rx_max, &v->rx_bitmap, &v->rx_started, seq);
}

/* The manager sends one 0x500b per VAP.  a2=0 is a real value ("no datachan
   on this VAP"), so it must not be confused with "this VAP never carried a
   variant" (fall back to the last create). */
static int dc_variant_for(const struct vap *v, const struct dc_ctx *d)
{
    if (v && v->dc_variant_set) return v->dc_variant;
    return d->variant;
}

static void dc_store_variant(int rid, int wid, int a2)
{
    struct vap *v;
    if (rid < 0 || wid < 0 || wid > 15) return;
    v = &g_vap[rid % MAX_RADIOS][wid];
    v->dc_variant = a2;
    v->dc_variant_set = 1;
}

/* TX key selection.  The per-VAP key/slot always wins; the dc_ctx slots are
   only a fallback for a VAP whose 0x500b did not carry a key (e.g. the
   --dc-key test override).  Using the global active slot first encrypted
   VAP A's frames with VAP B's key whenever both creates used the same
   keyidx. */
static int dc_select_tx_key(const struct vap *v, const struct dc_ctx *d,
                            int rid, int wid, const uint8_t **key,
                            size_t *klen, uint8_t *keyidx)
{
    int idx;

    *key = NULL;
    *klen = 0;
    *keyidx = 0;
    if (v) {
        idx = v->keyidx & 1;
        if (v->slot_valid[idx] && v->slot_keylen[idx]) {
            *key = v->slot_key[idx];
            *klen = v->slot_keylen[idx];
            *keyidx = (uint8_t)idx;
            return 0;
        }
        if (v->klen) {
            *key = v->key;
            *klen = v->klen;
            *keyidx = v->keyidx;
            return 0;
        }
    }
    if (d->have_key && (int)d->rid == rid && (int)d->wid == wid) {
        *key = d->key;
        *klen = d->key_len;
        *keyidx = d->keyidx;
        return 0;
    }
    return -1;
}

/* RX keys in preference order: this VAP's indicated slot, its other slot
   (the 0x402b transition), its installed key, then the per-VAP create copy
   and finally the legacy global slots.  dc_service tries each candidate, so
   a frame that arrives with a stale keyidx still decrypts with the right
   per-VAP key. */
static int dc_rx_key_candidates(const struct vap *v, const struct dc_ctx *d,
                                const struct dc_keyent *ke, int keyidx,
                                const uint8_t *keys[], size_t lens[], int max)
{
    int n = 0, idx = keyidx & 1;

#define DC_ADD_KEY(k, l)                                                     \
    do {                                                                     \
        if ((l) && n < (max)) {                                              \
            keys[n] = (k);                                                   \
            lens[n] = (l);                                                   \
            n++;                                                             \
        }                                                                    \
    } while (0)

    if (v) {
        DC_ADD_KEY(v->slot_key[idx], v->slot_valid[idx] ? v->slot_keylen[idx] : 0);
        DC_ADD_KEY(v->slot_key[idx ^ 1],
                   v->slot_valid[idx ^ 1] ? v->slot_keylen[idx ^ 1] : 0);
        DC_ADD_KEY(v->key, v->klen);
    }
    if (ke && ke->used) DC_ADD_KEY(ke->key, ke->key_len);
    DC_ADD_KEY(d->slot_key[idx], d->slot_valid[idx] ? d->slot_keylen[idx] : 0);
    DC_ADD_KEY(d->slot_key[idx ^ 1],
               d->slot_valid[idx ^ 1] ? d->slot_keylen[idx ^ 1] : 0);
    DC_ADD_KEY(d->key, d->have_key ? d->key_len : 0);
#undef DC_ADD_KEY
    return n;
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
    const struct cfg *cfg = d->cfg;
    if (cfg && cfg->dc_peer_port) port = cfg->dc_peer_port;
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
                       uint16_t id, uint16_t port, uint8_t keyidx,
                       int rid, int wid)
{
    d->id = id;
    d->port = port;
    d->have_hdr = 0;
    /* rid/wid come from the VAP registry, never from the UDP port. */
    d->rid = (uint8_t)rid;
    d->wid = (uint8_t)wid;
    d->flags = 0;
    d->keyidx = keyidx;
    d->have_key = 0;
    if (key && (key_len == 16 || key_len == 32)) {
        memcpy(d->key, key, key_len);
        d->key_len = key_len;
        d->have_key = 1;
        memcpy(d->slot_key[keyidx & 1], key, key_len);
        d->slot_keylen[keyidx & 1] = key_len;
        d->slot_valid[keyidx & 1] = 1;
        if (d->active < 0) d->active = keyidx & 1;
        /* P1: the transmit path uses the per-VAP key, not dc_ctx's. */
        vap_set_key(rid, wid, key, key_len, keyidx);
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
    for (int r = 0; r < MAX_RADIOS; r++) {
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

/* 0x402b {a8=key,a9=slot}: install before ACK, switch TX to the new slot,
   keep the old slot for 1 s (c2.ko cm_datachan_key_add/-del semantics). */
static int dc_rekey(struct dc_ctx *d, int idx, const uint8_t *key, size_t len)
{
    if (idx < 0 || idx > 1 || (len != 16 && len != 32) || !key)
        return -1;
    int old = d->active;
    memcpy(d->slot_key[idx], key, len);
    d->slot_keylen[idx] = len;
    d->slot_valid[idx] = 1;
    if (old != idx) {
        d->active = idx;
        d->tx_seq = 0;
        d->rx_started = 0;
        d->rx_max = 0;
        d->rx_bitmap = 0;
    }
    if (old >= 0 && old != idx && d->slot_valid[old]) {
        d->pending_del = old;
        d->pending_ms = dc_now_ms() + 1000;
    }
    memcpy(d->key, key, len);
    d->key_len = len;
    d->have_key = 1;
    d->keyidx = (uint8_t)idx;
    /* A rekey belongs to the secure datachan.  Never arm a key on an a2=1
       (plain) or a2=0 (no datachan) VAP: the old code applied it to every
       VAP and reset plain VAPs' TX sequence.  Each secure VAP keeps its own
       slots and sequence; a changed slot restarts both directions because
       the manager restarts its TX sequence as well. */
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++) {
            struct vap *v = &g_vap[r][w];
            struct dc_keyent *e = &g_dckey[r][w];
            if (!v->used || !v->dc_variant_set || v->dc_variant != 2)
                continue;
            memcpy(v->slot_key[idx], key, len);
            v->slot_keylen[idx] = len;
            v->slot_valid[idx] = 1;
            if ((v->keyidx & 1) != idx) {
                v->keyidx = (uint8_t)idx;
                v->tx_seq = 0;
                v->rx_started = 0;
                v->rx_max = 0;
                v->rx_bitmap = 0;
            }
            memcpy(v->key, key, len);
            v->klen = len;
            if (e->used) {
                memcpy(e->key, key, len);
                e->key_len = len;
            }
        }
    /* Never log key material: a syslog reader must not learn even a few
     * bytes of the datachan key. */
    printf("datachan: key slot=%d active %d->%d tx_seq=%llu key_len=%zu\n",
           idx, old, d->active, (unsigned long long)d->tx_seq, len);
    return 0;
}

/* Same host for the datachan peer check.  A plain (a2=1) datachan has no
 * authentication at all, so the UDP source must at least be the manager we
 * joined over TLS; otherwise any host that can reach the CAP's datachan port
 * (a wireless client on a bridged VLAN, for example) could inject Ethernet
 * frames into any VAP. */
static int dc_same_host(const struct sockaddr_storage *a,
                        const struct sockaddr_storage *b)
{
    if (a->ss_family == AF_INET && b->ss_family == AF_INET)
        return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
               ((const struct sockaddr_in *)b)->sin_addr.s_addr;
    if (a->ss_family == AF_INET6 && b->ss_family == AF_INET6)
        return !memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
                       &((const struct sockaddr_in6 *)b)->sin6_addr,
                       sizeof(struct in6_addr));
    if (a->ss_family == AF_INET && b->ss_family == AF_INET6) {
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        if (IN6_IS_ADDR_V4MAPPED(&b6->sin6_addr))
            return !memcmp(b6->sin6_addr.s6_addr + 12,
                           &((const struct sockaddr_in *)a)->sin_addr, 4);
    }
    if (a->ss_family == AF_INET6 && b->ss_family == AF_INET) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr))
            return !memcmp(a6->sin6_addr.s6_addr + 12,
                           &((const struct sockaddr_in *)b)->sin_addr, 4);
    }
    return 0;
}

static void dc_service(struct dc_ctx *d)
{
    uint8_t buf[DC_PFX_LEN + DC_HDR_LEN + DC_MAX_PAYLOAD + DC_TAG_LEN];
    uint8_t pt[DC_MAX_PAYLOAD];

    if (d->fd < 0) return;
    if (d->pending_del >= 0 && dc_now_ms() >= d->pending_ms) {
        int o = d->pending_del;
        d->slot_valid[o] = 0;
        /* Drop the matching per-VAP slot as well.  Frames on the new slot may
           restart at sequence 1, so reset the VAP's replay window when its
           old slot disappears (c2.ko resets the watermark on slot delete). */
        for (int r = 0; r < MAX_RADIOS; r++)
            for (int w = 0; w < 16; w++) {
                struct vap *v = &g_vap[r][w];
                if (!v->used || !v->slot_valid[o]) continue;
                if ((v->keyidx & 1) == o) continue;
                v->slot_valid[o] = 0;
                v->rx_started = 0;
                v->rx_max = 0;
                v->rx_bitmap = 0;
            }
        printf("datachan: old slot=%d deleted after 1 s\n", o);
        d->pending_del = -1;
    }
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
            for (int r2 = 0; r2 < MAX_RADIOS && !matched; r2++)
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
                /* Match the cookie, but only let the manager host move the
                 * peer port.  A LAN sniffer that saw the cleartext cookie
                 * could otherwise redirect all datachan traffic to itself. */
                if (d->peer_len && !dc_same_host(&src, &d->peer) &&
                    !getenv("CAPAGENT_DC_ANY_SOURCE")) {
                    printf("datachan: keepalive from non-manager host ignored\n");
                    continue;
                }
                if (!d->peer_len || slen != d->peer_len ||
                    memcmp(&src, &d->peer, (size_t)slen) != 0) {
                    memcpy(&d->peer, &src, sizeof(src));
                    d->peer_len = slen;
                    printf("datachan: peer learned from keepalive\n");
                }
                printf("datachan keepalive len=%d\n", (int)r);
                continue;
            }
            /* A keepalive-shaped frame with an unknown cookie is not data.
             * Falling through used to feed its cookie bytes to the plain
             * parser, which could turn a forged keepalive into an injected
             * Ethernet frame. */
            printf("datachan: keepalive with unknown cookie dropped\n");
            continue;
        }
        if (buf[1] & DC_PFX_FRAG) {
            printf("datachan: fragmented frame, unsupported\n");
            continue;
        }
        if ((size_t)r < DC_PFX_LEN + DC_HDR_LEN) continue;
        dc_hdr_read(buf + DC_PFX_LEN, &rid, &wid, &flags, &keyidx, &seq);
        /* (rid,wid) identify the VAP that owns the key.  Do not rewrite it
           from the first frame: every VAP shares the datachan. */
        struct vap *v = vap_get(rid, wid);
        int variant = dc_variant_for(v, d);
        /* a2=1 is unauthenticated on the wire.  Only the manager peer may
         * inject it; a2=2 frames are CCM-authenticated and can be accepted
         * independently of the source address (useful after a manager
         * address change). */
        if (variant == 1 && d->peer_len &&
            !dc_same_host(&src, &d->peer) &&
            !getenv("CAPAGENT_DC_ANY_SOURCE")) {
            printf("datachan: plain frame from non-manager source dropped\n");
            continue;
        }
        plen = (size_t)r - DC_PFX_LEN - DC_HDR_LEN;
        ct = buf + DC_PFX_LEN + DC_HDR_LEN;
        if (v && v->dc_variant_set && v->dc_variant == 0) {
            printf("datachan: frame for a2=0 VAP rid=%u wid=%u dropped\n",
                   rid, wid);
            continue;
        }
        if (variant == 1) {             /* 0xa2=1: bare Ethernet, no tag */
            int ok = v ? dc_replay_ok(v, seq)
                       : dc_replay_window(&d->rx_max, &d->rx_bitmap,
                                          &d->rx_started, seq);
            if (!ok) {
                printf("datachan replay dropped seq=%llu\n",
                       (unsigned long long)seq);
                continue;
            }
            if (plen > DC_MAX_PAYLOAD) {
                printf("datachan: oversize plain frame %zu rid=%u wid=%u\n",
                       plen, rid, wid);
                continue;
            }
            printf("datachan plain rid=%u wid=%u seq=%llu ethtype=%02x%02x "
                   "payload=%zu\n", rid, wid, (unsigned long long)seq,
                   plen >= 14 ? ct[12] : 0, plen >= 14 ? ct[13] : 0, plen);
            dp_rx_frame(d, rid, wid, ct, plen);
            fflush(stdout);
            continue;
        }
        {
            struct dc_keyent *ke = &g_dckey[rid % MAX_RADIOS][wid & 0x0f];
            const uint8_t *keys[8];
            size_t lens[8];
            int nk, got = 0;

            if (plen < DC_TAG_LEN) {
                printf("datachan frame rid=%u wid=%u len=%zu (short)\n",
                       rid, wid, plen);
                continue;
            }
            ct_len = plen - DC_TAG_LEN;
            if (ct_len > sizeof(pt)) continue;
            tag = ct + ct_len;
            nk = dc_rx_key_candidates(v, d, ke, keyidx, keys, lens, 8);
            if (!nk) {
                printf("datachan frame rid=%u wid=%u len=%zu (no key)\n",
                       rid, wid, plen);
                continue;
            }
            for (int i = 0; i < nk; i++) {
                if (dc_decrypt_key(keys[i], lens[i], buf + DC_PFX_LEN, ct,
                                   ct_len, tag, pt) == 0) {
                    got = 1;
                    break;
                }
            }
            if (!got) {
                printf("datachan auth failed rid=%u wid=%u keyidx=%u "
                       "flags=%u seq=%llu len=%zu\n", rid, wid, keyidx,
                       flags, (unsigned long long)seq, plen);
                continue;
            }
        }
        {
            int ok = v ? dc_replay_ok(v, seq)
                       : dc_replay_window(&d->rx_max, &d->rx_bitmap,
                                          &d->rx_started, seq);
            if (!ok) {
                printf("datachan replay dropped seq=%llu\n",
                       (unsigned long long)seq);
                continue;
            }
        }
        printf("datachan secure rid=%u wid=%u seq=%llu payload=%zu\n",
               rid, wid, (unsigned long long)seq, ct_len);
        dp_rx_frame(d, rid, wid, pt, ct_len);
        fflush(stdout);
    }
}

/* Transmit one Ethernet frame on the datachan, c2.ko layout:
       secure: UDP payload = 10 | flags | cdh[8] | AES-CCM(ct||tag16)
       plain:  UDP payload = 10 | flags | cdh[8] | eth
   assoclen/AAD = cdh, nonce = cdh||0*5, seq per VAP from 1. */
static int dc_send_frame_vap(struct dc_ctx *d, int rid, int wid,
                             const uint8_t *frame, size_t flen)
{
    uint8_t cdh[DC_HDR_LEN];
    uint8_t pkt[DC_PFX_LEN + DC_HDR_LEN + DC_MAX_PAYLOAD + DC_TAG_LEN];
    mbedtls_ccm_context ccm;
    struct vap *v;
    const uint8_t *key = NULL;
    size_t klen = 0;
    uint8_t keyidx = 0;
    int ret;

    if (rid < 0 || wid < 0) return -EINVAL;
    v = &g_vap[rid % MAX_RADIOS][wid & 0x0f];
    if (d->fd < 0 || !d->peer_len) return -1;
    if (flen > DC_MAX_PAYLOAD) return -1;
    int variant = dc_variant_for(v, d);
    /* a2=0 is "this VAP has no datachan", not the legacy default.  Do not
       fall through to the secure path and borrow another VAP's global key. */
    if (v->dc_variant_set && variant == 0) return -EINVAL;

    dc_select_tx_key(v, d, rid, wid, &key, &klen, &keyidx);

    pkt[0] = DC_PFX_MAGIC;
    pkt[1] = 0x00;                  /* unfragmented, not keepalive */
    dc_hdr_write(cdh, (uint8_t)rid, (uint8_t)wid, 0, keyidx, ++v->tx_seq);
    memcpy(pkt + DC_PFX_LEN, cdh, sizeof(cdh));
    if (variant == 1) {             /* 0xa2=1: no tag, no crypto */
        memcpy(pkt + DC_PFX_LEN + DC_HDR_LEN, frame, flen);
        return sendto(d->fd, pkt, DC_PFX_LEN + DC_HDR_LEN + flen, 0,
                      (struct sockaddr *)&d->peer, d->peer_len) < 0 ? -1 : 0;
    }
    if (!klen) return -EINVAL;

    mbedtls_ccm_init(&ccm);
    if (mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key,
                           (unsigned)klen * 8) != 0) {
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

__attribute__((unused))
static int dc_send_frame(struct dc_ctx *d, const uint8_t *frame, size_t flen)
{
    return dc_send_frame_vap(d, d->rid, d->wid, frame, flen);
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
    int vrid = create_port >> 8, vwid = create_port & 0xff;
    int a2 = -1;

    if (find_el(body, len, 0x4a, &v, &l) && l == 4) id = (uint16_t)rd32(v);
    if (find_el(body, len, 0xa6, &v, &l) && l == 2) port = rd16(v);
    if (find_el(body, len, 0xa2, &v, &l) && l == 1) {
        a2 = v[0];
        d->variant = a2;
        d->secure = (a2 != 1);
        /* The a2 variant is per VAP: the manager sends one 0x500b for every
         * VAP, and the on-cap VAPs carry a2=0.  The VAP is resolved from
         * 0x7d/0x08 below, so store the variant after that resolution, not
         * on the request port (which can be the master VAP). */
        printf("0x500b datachan variant a2=%d (%s)\n", a2,
               a2 == 2 ? "AES-CCM" : a2 == 1 ? "plain" : "none");
    }
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

    if (c->dc_key_len) { key = c->dc_key; key_len = c->dc_key_len; }
    if (c->dc_cookie_len) {
        cookie = c->dc_cookie;
        cookie_len = c->dc_cookie_len;
    }

    /* Every VAP has its own key/cookie on the shared datachan. */
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
            if (wid < 0) {
                fprintf(stderr, "datachan: no free vapid for rid=%d, key "
                        "not installed\n", rid);
            } else {
                vrid = rid;
                vwid = wid;
                struct dc_keyent *e = &g_dckey[rid % MAX_RADIOS][wid & 0x0f];
                e->used = 1;
                memcpy(e->key, key, key_len);
                e->key_len = key_len;
                if (cookie && cookie_len) {
                    memcpy(e->cookie, cookie, cookie_len);
                    e->cookie_len = cookie_len;
                }
                /* P1: the data path uses the VAP registry copy. */
                vap_set_key(rid, wid, key, key_len, keyidx);
                printf("datachan: key rid=%d wid=%d vlan=%u keyidx=%u "
                       "cookie=%zuB\n", rid, wid, vlan, keyidx, cookie_len);
            }
        }
    }

    /* Apply a2 to the VAP the key/VLAN actually resolved to.  vrid/vwid may
       have changed from create_port when 0x7d/0x08 named a VLAN VAP. */
    if (a2 >= 0) dc_store_variant(vrid, vwid, a2);
    if (!key && !cookie && !c->dc_key_len && !c->dc_cookie_len) return;

    printf("0x500b datachan id=%u port=%u key=%zuB cookie=%zuB a2=%d\n",
           id, port, key_len, cookie_len, a2);
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
    dc_install(d, key, key_len, cookie, cookie_len, id, port, keyidx,
               vrid, vwid);
    dc_send_keepalive(d);
    printf("datachan: listening on UDP %u, id %u rid %u wid %u keyidx %u\n",
           port, id, d->rid, d->wid, d->keyidx);
    fflush(stdout);
}

/* W25: forget a VAP's datachan key/cookie when the manager destroys it.
   Otherwise a recreated VAP with the same id could inherit the old key. */
static void dc_forget_vap(int rid, int wid)
{
    if (rid < 0 || rid >= MAX_RADIOS || wid < 0 || wid > 15) return;
    memset(&g_dckey[rid][wid], 0, sizeof(g_dckey[rid][wid]));
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
