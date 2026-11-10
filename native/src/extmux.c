/*
 * extmux -- multi-VAP hostapd external-RSN relay core (W8 reference)
 * See extmux.h for the ABI and REPORT.md for the design.
 */
#define _GNU_SOURCE
#include "extmux.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define EXTMUX_FOURWAY_MS_DEFAULT 10000
#define EXTMUX_M1_RETRY_MS_DEFAULT 3000
#define EXTMUX_TXN_MS_DEFAULT      1000
#define EXTMUX_MAX_M1_RETRIES      2
#define EXTMUX_MAX_AUTHZ_RETRIES   2

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(m) (m)[0], (m)[1], (m)[2], (m)[3], (m)[4], (m)[5]

struct extmux {
    char ext_dir[108];
    char ctrl_dir[108];
    struct extmux_cb cb;
    struct extmux_vap vap[EXTMUX_MAX_VAPS];
    struct extmux_sess sess[EXTMUX_MAX_SESS];
    unsigned fourway_ms;
    unsigned m1_retry_ms;
    unsigned txn_ms;
    struct extmux_stats st;
};

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void mlog(struct extmux *m, const char *fmt, ...)
{
    char buf[512];
    va_list ap;

    if (!m || !m->cb.log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    m->cb.log(m->cb.ctx, buf);
}

static int mac_eq(const uint8_t a[6], const uint8_t b[6])
{
    return memcmp(a, b, 6) == 0;
}

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2],
                     &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)v[i];
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *s, uint8_t *out, size_t outmax)
{
    size_t n = 0;
    while (s[0] && s[1] && n < outmax) {
        int hi = hexval(s[0]), lo = hexval(s[1]);
        if (hi < 0 || lo < 0)
            break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return n;
}

static size_t fmt_hex(char *out, size_t outmax, const uint8_t *in, size_t n)
{
    static const char h[] = "0123456789abcdef";
    size_t i;
    if (outmax < 2 * n + 1)
        return 0;
    for (i = 0; i < n; i++) {
        out[2 * i] = h[in[i] >> 4];
        out[2 * i + 1] = h[in[i] & 0xf];
    }
    out[2 * n] = 0;
    return 2 * n;
}

const char *extmux_state_name(int state)
{
    switch (state) {
    case EXTMUX_ASSOC:      return "ASSOC";
    case EXTMUX_WAIT_M2:    return "WAIT_M2";
    case EXTMUX_WAIT_M4:    return "WAIT_M4";
    case EXTMUX_PTK:        return "PTK";
    case EXTMUX_AUTHORIZED: return "AUTHORIZED";
    case EXTMUX_FAILED:     return "FAILED";
    default:                return "FREE";
    }
}

/* EAPOL-Key classification.  Returns 1 = M1, 2 = M2, 3 = M3, 4 = M4,
 * 0 = not a 4-way frame, -1 = not EAPOL-Key. */
static int eapol_classify(const uint8_t *e, size_t n)
{
    unsigned info;

    if (n < 7 || e[1] != 3)
        return -1;
    info = ((unsigned)e[5] << 8) | e[6];
    if (info & 0x0080) {                    /* ACK */
        if (info & 0x0100) return 3;        /* ACK + MIC = M3 */
        return 1;                           /* ACK      = M1 */
    }
    if (info & 0x0100) {                    /* MIC */
        if (info & 0x0200) return 4;        /* MIC + SECURE = M4 */
        return 2;                           /* MIC          = M2 */
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* VAP table / sockets                                                 */
/* ------------------------------------------------------------------ */

static struct extmux_vap *vap_alloc(struct extmux *m)
{
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++)
        if (!m->vap[i].used)
            return &m->vap[i];
    return NULL;
}

struct extmux_vap *extmux_vap_by_port(struct extmux *m, uint16_t port)
{
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++)
        if (m->vap[i].used && m->vap[i].port == port)
            return &m->vap[i];
    return NULL;
}

struct extmux_vap *extmux_vap_at(struct extmux *m, int idx)
{
    if (!m || idx < 0 || idx >= EXTMUX_MAX_VAPS || !m->vap[idx].used)
        return NULL;
    return &m->vap[idx];
}

struct extmux_vap *extmux_vap_by_ifname(struct extmux *m, const char *ifname)
{
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++)
        if (m->vap[i].used && !strcmp(m->vap[i].ifname, ifname))
            return &m->vap[i];
    return NULL;
}

static int bind_ext_socket(struct extmux *m, struct extmux_vap *v)
{
    struct sockaddr_un sa;
    char path[256];
    int fd, n;

    n = snprintf(path, sizeof(path), "%s/ext-auth-%s", m->ext_dir, v->ifname);
    if (n < 0 || (size_t)n >= sizeof(sa.sun_path)) {
        mlog(m, "extmux: ext path too long for %s", v->ifname);
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, path, strlen(path) + 1);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&sa,
             (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                         strlen(path) + 1)) != 0) {
        mlog(m, "extmux: bind %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    chmod(path, 0660);

    /* One abstract source address per VAP so hostapd's reply is routable. */
    v->ctrl_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (v->ctrl_fd >= 0) {
        struct sockaddr_un src;
        char aname[64];
        int alen;

        memset(&src, 0, sizeof(src));
        src.sun_family = AF_UNIX;
        alen = snprintf(aname, sizeof(aname), "extmux.%ld.%u",
                        (long)getpid(), (unsigned)v->port);
        src.sun_path[0] = 0;               /* abstract namespace */
        memcpy(src.sun_path + 1, aname, (size_t)alen);
        if (bind(v->ctrl_fd, (struct sockaddr *)&src,
                 (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                             alen)) != 0) {
            mlog(m, "extmux: abstract bind %s failed: %s", aname,
                 strerror(errno));
            close(v->ctrl_fd);
            v->ctrl_fd = -1;
        }
    }
    v->ext_fd = fd;
    return 0;
}

int extmux_add_vap(struct extmux *m, uint16_t port, const char *ifname,
                   int ifindex, const uint8_t bssid[6])
{
    struct extmux_vap *v;

    if (!m || !ifname || !*ifname)
        return -1;
    v = extmux_vap_by_port(m, port);
    if (v) {
        mlog(m, "extmux: port 0x%04x already mapped to %s", port, v->ifname);
        return -1;
    }
    v = vap_alloc(m);
    if (!v) {
        mlog(m, "extmux: VAP table full (%d)", EXTMUX_MAX_VAPS);
        return -1;
    }
    memset(v, 0, sizeof(*v));
    v->used = 1;
    v->port = port;
    v->ifindex = ifindex;
    v->ext_fd = -1;
    v->ctrl_fd = -1;
    snprintf(v->ifname, sizeof(v->ifname), "%s", ifname);
    if (bssid)
        memcpy(v->bssid, bssid, 6);
    if (bind_ext_socket(m, v) != 0) {
        v->used = 0;
        return -1;
    }
    m->st.vaps++;
    mlog(m, "extmux: VAP port=0x%04x if=%s ifindex=%d ext=%s/ext-auth-%s",
         port, ifname, ifindex, m->ext_dir, ifname);
    return 0;
}

int extmux_del_vap(struct extmux *m, uint16_t port)
{    struct extmux_vap *v = extmux_vap_by_port(m, port);
    char path[256];

    if (!v)
        return -1;
    for (int i = 0; i < EXTMUX_MAX_SESS; i++)
        if (m->sess[i].used && m->sess[i].port == port) {
            m->sess[i].used = 0;
            m->st.sessions--;
        }
    if (v->ext_fd >= 0)
        close(v->ext_fd);
    if (v->ctrl_fd >= 0)
        close(v->ctrl_fd);
    snprintf(path, sizeof(path), "%s/ext-auth-%s", m->ext_dir, v->ifname);
    unlink(path);
    v->used = 0;
    if (m->st.vaps)
        m->st.vaps--;
    return 0;
}

int extmux_set_ifindex(struct extmux *m, uint16_t port, int ifindex)
{
    struct extmux_vap *v;

    if (!m || ifindex <= 0) return -1;
    v = extmux_vap_by_port(m, port);
    if (!v) return -1;
    if (v->ifindex == ifindex) return 0;
    mlog(m, "extmux: VAP %s ifindex %d -> %d", v->ifname, v->ifindex, ifindex);
    v->ifindex = ifindex;
    return 0;
}

/* ------------------------------------------------------------------ */
/* session table                                                       */
/* ------------------------------------------------------------------ */

static struct extmux_sess *sess_find(struct extmux *m, uint16_t port,
                                     const uint8_t mac[6])
{
    for (int i = 0; i < EXTMUX_MAX_SESS; i++)
        if (m->sess[i].used && m->sess[i].port == port &&
            mac_eq(m->sess[i].mac, mac))
            return &m->sess[i];
    return NULL;
}

static struct extmux_sess *sess_get(struct extmux *m, uint16_t port,
                                    const uint8_t mac[6], int create)
{
    struct extmux_sess *s = sess_find(m, port, mac);
    struct extmux_sess *victim = NULL;

    if (s || !create)
        return s;
    for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
        if (!m->sess[i].used) {
            victim = &m->sess[i];
            break;
        }
    }
    if (!victim) {
        /* Prefer a FAILED/FREE-like row, else the oldest authorized one. */
        uint64_t oldest = UINT64_MAX;
        for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
            if (m->sess[i].state == EXTMUX_FAILED) {
                victim = &m->sess[i];
                break;
            }
            if (m->sess[i].t_assoc < oldest) {
                oldest = m->sess[i].t_assoc;
                victim = &m->sess[i];
            }
        }
        mlog(m, "extmux: session table full, evicting " MAC_FMT,
             MAC_ARG(victim->mac));
    }
    memset(victim, 0, sizeof(*victim));
    victim->used = 1;
    victim->port = port;
    memcpy(victim->mac, mac, 6);
    victim->state = EXTMUX_ASSOC;
    victim->t_assoc = now_ms();
    m->st.sessions++;
    return victim;
}

/* ------------------------------------------------------------------ */
/* hostapd control interface transactions                              */
/* ------------------------------------------------------------------ */

static int ctrl_path(struct extmux *m, const struct extmux_vap *v,
                     struct sockaddr_un *sa, socklen_t *salen)
{
    char path[108];
    int n;

    n = snprintf(path, sizeof(path), "%s/%s", m->ctrl_dir, v->ifname);
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1;
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, path, strlen(path) + 1);
    *salen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                        strlen(path) + 1);
    return 0;
}

static int ctrl_send(struct extmux *m, struct extmux_vap *v, const char *cmd)
{
    struct sockaddr_un sa;
    socklen_t salen;
    ssize_t n;

    if (v->ctrl_fd < 0)
        return -1;
    if (ctrl_path(m, v, &sa, &salen) != 0)
        return -1;
    n = sendto(v->ctrl_fd, cmd, strlen(cmd), 0,
               (struct sockaddr *)&sa, salen);
    if (n < 0)
        return -errno;
    return 0;
}

static void txn_start(struct extmux *m, struct extmux_vap *v, int type,
                      const uint8_t mac[6], const char *cmd)
{
    if (ctrl_send(m, v, cmd) != 0) {
        mlog(m, "extmux: ctrl %s send failed for %s", type == 2 ? "AUTHORIZE"
             : "TX", v->ifname);
        if (type == 1 && m->cb.on_direct_tx) {
            /* caller fallback happens in extmux_tx; here just mark done */
            m->st.tx_failed++;
        }
        v->txn_active = 0;
        return;
    }
    v->txn_active = 1;
    v->txn_type = type;
    memcpy(v->txn_mac, mac, 6);
    v->txn_deadline = now_ms() + m->txn_ms;
    /* W53: txn_retries is owned by the caller.  Resetting it here made the
     * AUTHORIZE retry counter immortal (every retry restarted at 0), so a
     * hostapd that rejects the command was retried forever instead of
     * failing over / failing the session. */
    if (type == 1)
        m->st.tx_ok++;
}

static void sess_authorized(struct extmux *m, struct extmux_vap *v,
                            struct extmux_sess *s)
{
    s->state = EXTMUX_AUTHORIZED;
    s->authorized = 1;
    s->authz_want = 0;
    s->deadline = 0;
    s->retry_at = 0;
    m->st.authorized++;
    v->authz_ok++;
    mlog(m, "extmux: AUTHORIZED port=0x%04x " MAC_FMT " (ok)",
         v->port, MAC_ARG(s->mac));
    if (m->cb.on_authorized)
        m->cb.on_authorized(m->cb.ctx, v, s->mac);
}

static void authz_failed(struct extmux *m, struct extmux_vap *v,
                         struct extmux_sess *s)
{
    s->state = EXTMUX_FAILED;
    s->authorized = 0;
    s->authz_want = 0;
    v->authz_fail++;
    m->st.authz_failed++;
    mlog(m, "extmux: AUTHORIZE failed port=0x%04x " MAC_FMT,
         v->port, MAC_ARG(s->mac));
    if (m->cb.on_deauth)
        m->cb.on_deauth(m->cb.ctx, v, s->mac, 15);
}

/* One-shot report when hostapd rejects EXT_AUTH_TX for a BSS.  After this
 * the VAP uses nl80211 control-port TX for every frame; no per-frame log. */
static void tx_use_direct(struct extmux *m, struct extmux_vap *v,
                          const char *why)
{
    if (v->direct_tx)
        return;
    v->direct_tx = 1;
    mlog(m, "extmux: %s: hostapd rejected EXT_AUTH_TX (%s); this BSS now "
         "uses direct nl80211 control-port TX", v->ifname, why);
}

/* A reply arrived for the in-flight command of this VAP. */
static void txn_reply(struct extmux *m, struct extmux_vap *v, int ok,
                      const char *reply)
{
    struct extmux_sess *s;

    if (!v->txn_active) {
        mlog(m, "extmux: stray ctrl reply on %s: %s", v->ifname, reply);
        return;
    }
    s = sess_find(m, v->port, v->txn_mac);
    if (v->txn_type == 1) {
        /* EXT_AUTH_TX: an error reply means this hostapd build cannot (or
         * will not) send the frame.  Switch the BSS to direct control-port
         * TX from now on.  Do not blind-reinject this frame: an old build
         * can transmit it and still answer FAIL (its ctrl wrapper tested
         * the positive driver return), and a duplicate M1 confuses the
         * manager.  The next 0x201c / M1 retry uses the direct path. */
        if (ok) {
            v->txn_active = 0;
            return;
        }
        v->txn_active = 0;
        tx_use_direct(m, v, reply[0] ? reply : "error reply");
        return;
    }
    /* AUTHORIZE */
    if (ok) {
        if (s)
            sess_authorized(m, v, s);
        else
            mlog(m, "extmux: authorize OK for unknown session");
        v->txn_active = 0;
        return;
    }
    if (v->txn_retries < EXTMUX_MAX_AUTHZ_RETRIES) {
        char cmd[96];
        v->txn_retries++;
        snprintf(cmd, sizeof(cmd), "EXT_AUTH_AUTHORIZE " MAC_FMT,
                 MAC_ARG(v->txn_mac));
        m->st.authz_retries++;
        mlog(m, "extmux: authorize retry %u port=0x%04x " MAC_FMT,
             v->txn_retries, v->port, MAC_ARG(v->txn_mac));
        txn_start(m, v, 2, v->txn_mac, cmd);
        return;
    }
    v->txn_active = 0;
    if (s && !v->direct_authz && m->cb.on_direct_authz &&
        m->cb.on_direct_authz(m->cb.ctx, v, v->txn_mac) == 0) {
        v->direct_authz = 1;
        mlog(m, "extmux: %s: hostapd EXT_AUTH_AUTHORIZE unavailable (%s); "
             "authorized " MAC_FMT " through nl80211", v->ifname, reply,
             MAC_ARG(v->txn_mac));
        sess_authorized(m, v, s);
        return;
    }
    if (s)
        authz_failed(m, v, s);
}

/* ------------------------------------------------------------------ */
/* hostapd -> relay event socket                                       */
/* ------------------------------------------------------------------ */

static void handle_assoc(struct extmux *m, struct extmux_vap *v,
                         const char *rest)
{
    char macs[32];
    uint8_t mac[6];
    struct extmux_sess *s;

    if (sscanf(rest, "%31s", macs) != 1 || parse_mac(macs, mac) != 0)
        return;
    s = sess_get(m, v->port, mac, 1);
    if (s->state == EXTMUX_AUTHORIZED)
        mlog(m, "extmux: re-assoc of authorized " MAC_FMT " port=0x%04x",
             MAC_ARG(mac), v->port);
    s->state = EXTMUX_ASSOC;
    s->authorized = 0;
    s->adopted = 0;
    s->stale = 0;
    s->authz_want = 0;
    s->retries = 0;
    s->t_assoc = s->t_last_rx = now_ms();
    s->deadline = s->t_assoc + m->fourway_ms;
    s->retry_at = 0;
    s->last_frame_len = 0;
    v->rx_events++;
    mlog(m, "extmux: ASSOC port=0x%04x " MAC_FMT " (4-way deadline %ums)",
         v->port, MAC_ARG(mac), m->fourway_ms);
}

static void handle_eapol(struct extmux *m, struct extmux_vap *v,
                         const char *rest)
{
    char macs[32], encs[8], hex[EXTMUX_EXT_MAX * 2 + 8];
    uint8_t mac[6], eapol[EXTMUX_EXT_MAX];
    size_t len;
    int enc, cls;
    struct extmux_sess *s;

    if (sscanf(rest, "%31s %7s %8191s", macs, encs, hex) != 3)
        return;
    if (parse_mac(macs, mac) != 0)
        return;
    enc = atoi(encs);
    len = parse_hex(hex, eapol, sizeof(eapol));
    if (!len)
        return;
    s = sess_get(m, v->port, mac, 1);
    s->t_last_rx = now_ms();
    if (s->state != EXTMUX_AUTHORIZED)
        s->deadline = s->t_last_rx + m->fourway_ms;
    cls = eapol_classify(eapol, len);
    switch (cls) {
    case 2:
        s->m2++;
        s->retry_at = 0;
        if (s->state == EXTMUX_WAIT_M2 || s->state == EXTMUX_ASSOC)
            s->state = EXTMUX_WAIT_M4;   /* M2 done, M3 outstanding */
        break;
    case 4:
        s->m4++;
        s->retry_at = 0;
        s->state = EXTMUX_PTK;
        break;
    case 1:
        /* A STA-originated M1 is unexpected; the manager owns the 4-way. */
        mlog(m, "extmux: unexpected M1 from " MAC_FMT, MAC_ARG(mac));
        break;
    case 3:
        mlog(m, "extmux: unexpected M3 from " MAC_FMT, MAC_ARG(mac));
        break;
    default:
        break;
    }
    v->rx_events++;
    mlog(m, "extmux: EAPOL port=0x%04x " MAC_FMT " len=%zu enc=%d class=%d",
         v->port, MAC_ARG(mac), len, enc, cls);
    if (m->cb.on_eapol)
        m->cb.on_eapol(m->cb.ctx, v, mac, eapol, len, enc);
}

static void ext_read(struct extmux *m, struct extmux_vap *v)
{
    for (;;) {
        char buf[EXTMUX_EXT_MAX + 128];
        ssize_t n = recv(v->ext_fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        if (n <= 0)
            break;
        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;
        if (!strncmp(buf, "ASSOC ", 6)) {
            handle_assoc(m, v, buf + 6);
        } else if (!strncmp(buf, "AUTH ", 5) ||
                   !strncmp(buf, "ASSOCREQ ", 9)) {
            int is_auth = !strncmp(buf, "AUTH ", 5);
            char *rest = buf + (is_auth ? 5 : 9);
            char macs[32], hex[EXTMUX_EXT_MAX * 2 + 8];
            uint8_t fr[EXTMUX_EXT_MAX];
            size_t fl;

            if (sscanf(rest, "%31s %8191s", macs, hex) != 2)
                continue;
            fl = parse_hex(hex, fr, sizeof(fr));
            if (fl < 24)
                continue;
            mlog(m, "extmux: %s port=0x%04x len=%zu",
                 is_auth ? "AUTH" : "ASSOCREQ", v->port, fl);
            if (m->cb.on_mgmt)
                m->cb.on_mgmt(m->cb.ctx, v, fr, fl);
        } else if (!strncmp(buf, "EAPOL ", 6)) {
            handle_eapol(m, v, buf + 6);
        } else if (!strncmp(buf, "DISCONNECT ", 11)) {
            uint8_t mac[6];
            if (parse_mac(buf + 11, mac) != 0)
                continue;
            mlog(m, "extmux: DISCONNECT port=0x%04x " MAC_FMT,
                 v->port, MAC_ARG(mac));
            if (m->cb.on_delsta)
                m->cb.on_delsta(m->cb.ctx, v, mac);
            extmux_forget(m, v->port, mac, 0);
        } else if (!strncmp(buf, "BSS_UP ", 7)) {
            mlog(m, "extmux: BSS_UP %s", buf + 7);
        } else {
            mlog(m, "extmux: unknown event on %s: %s", v->ifname, buf);
        }
    }
}

static void ctrl_read(struct extmux *m, struct extmux_vap *v)
{
    for (;;) {
        char buf[256];
        ssize_t n = recv(v->ctrl_fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        int ok;

        if (n <= 0)
            break;
        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;
        ok = !strncmp(buf, "OK", 2);
        txn_reply(m, v, ok, buf);
    }
}

/* ------------------------------------------------------------------ */
/* timers                                                              */
/* ------------------------------------------------------------------ */

static void retry_m1(struct extmux *m, struct extmux_vap *v,
                     struct extmux_sess *s)
{
    if (!s->last_frame_len)
        return;
    if (v->txn_active)
        return;                         /* ctrl busy; try next tick */
    s->retries++;
    m->st.m1_retries++;
    mlog(m, "extmux: M1 retry %u port=0x%04x " MAC_FMT,
         s->retries, v->port, MAC_ARG(s->mac));
    extmux_tx(m, v->port, s->mac, s->last_frame, s->last_frame_len,
              s->last_frame_enc);
}

static void sess_timeout(struct extmux *m, struct extmux_vap *v,
                         struct extmux_sess *s)
{
    mlog(m, "extmux: 4-way timeout port=0x%04x " MAC_FMT
         " state=%s m1=%u m2=%u m3=%u m4=%u",
         v->port, MAC_ARG(s->mac), extmux_state_name(s->state),
         s->m1, s->m2, s->m3, s->m4);
    m->st.deauth_timeouts++;
    s->state = EXTMUX_FAILED;
    s->authz_want = 0;
    if (m->cb.on_deauth)
        m->cb.on_deauth(m->cb.ctx, v, s->mac, 15 /* 4-way timeout */);
    if (m->cb.on_delsta)
        m->cb.on_delsta(m->cb.ctx, v, s->mac);
    /* Keep the FAILED row briefly so a late M4/DISCONNECT is attributable;
     * it is replaced by the next ASSOC. */
    s->deadline = 0;
}

void extmux_tick(struct extmux *m, uint64_t now)
{
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++) {
        struct extmux_vap *v = &m->vap[i];
        if (!v->used)
            continue;
        /* in-flight hostapd command timeout */
        if (v->txn_active && now >= v->txn_deadline) {
            if (v->txn_type == 2 &&
                v->txn_retries < EXTMUX_MAX_AUTHZ_RETRIES) {
                char cmd[96];
                v->txn_retries++;
                m->st.authz_retries++;
                snprintf(cmd, sizeof(cmd),
                         "EXT_AUTH_AUTHORIZE " MAC_FMT,
                         MAC_ARG(v->txn_mac));
                mlog(m, "extmux: authorize timeout, retry %u port=0x%04x",
                     v->txn_retries, v->port);
                txn_start(m, v, 2, v->txn_mac, cmd);
            } else if (v->txn_type == 2) {
                struct extmux_sess *s = sess_find(m, v->port, v->txn_mac);
                v->txn_active = 0;
                if (s && !v->direct_authz && m->cb.on_direct_authz &&
                    m->cb.on_direct_authz(m->cb.ctx, v, v->txn_mac) == 0) {
                    v->direct_authz = 1;
                    mlog(m, "extmux: %s: no reply to EXT_AUTH_AUTHORIZE; "
                         "authorized " MAC_FMT " through nl80211",
                         v->ifname, MAC_ARG(v->txn_mac));
                    sess_authorized(m, v, s);
                } else if (s) {
                    authz_failed(m, v, s);
                }
            } else {
                v->txn_active = 0;      /* TX is best effort */
            }
        }
        /* pending authorizations for this VAP */
        if (!v->txn_active) {
            for (int k = 0; k < EXTMUX_MAX_SESS; k++) {
                struct extmux_sess *s = &m->sess[k];
                if (s->used && s->port == v->port && s->authz_want) {
                    char cmd[96];
                    snprintf(cmd, sizeof(cmd),
                             "EXT_AUTH_AUTHORIZE " MAC_FMT,
                             MAC_ARG(s->mac));
                    v->txn_retries = 0;
                    txn_start(m, v, 2, s->mac, cmd);
                    break;
                }
            }
        }
        for (int k = 0; k < EXTMUX_MAX_SESS; k++) {
            struct extmux_sess *s = &m->sess[k];
            if (!s->used || s->port != v->port)
                continue;
            if (s->state == EXTMUX_AUTHORIZED || s->state == EXTMUX_FAILED)
                continue;
            if (s->retry_at && now >= s->retry_at && s->m2 == 0 &&
                s->retries < EXTMUX_MAX_M1_RETRIES) {
                s->retry_at = now + m->m1_retry_ms;
                retry_m1(m, v, s);
            }
            if (s->deadline && now >= s->deadline)
                sess_timeout(m, v, s);
        }
    }
}

/* ------------------------------------------------------------------ */
/* public API                                                          */
/* ------------------------------------------------------------------ */

struct extmux *extmux_new(const char *ext_dir, const char *ctrl_dir,
                          const struct extmux_cb *cb)
{
    struct extmux *m;

    if (!ext_dir || !ctrl_dir)
        return NULL;
    m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    snprintf(m->ext_dir, sizeof(m->ext_dir), "%s", ext_dir);
    snprintf(m->ctrl_dir, sizeof(m->ctrl_dir), "%s", ctrl_dir);
    if (cb)
        m->cb = *cb;
    m->fourway_ms = EXTMUX_FOURWAY_MS_DEFAULT;
    m->m1_retry_ms = EXTMUX_M1_RETRY_MS_DEFAULT;
    m->txn_ms = EXTMUX_TXN_MS_DEFAULT;
    return m;
}

void extmux_set_timeouts(struct extmux *m, unsigned fourway_ms,
                         unsigned m1_retry_ms, unsigned txn_ms)
{
    if (!m)
        return;
    if (fourway_ms) m->fourway_ms = fourway_ms;
    if (m1_retry_ms) m->m1_retry_ms = m1_retry_ms;
    if (txn_ms) m->txn_ms = txn_ms;
}

void extmux_free(struct extmux *m)
{
    if (!m)
        return;
    for (int i = 0; i < EXTMUX_MAX_VAPS; i++) {
        struct extmux_vap *v = &m->vap[i];
        char path[256];
        if (!v->used)
            continue;
        if (v->ext_fd >= 0)
            close(v->ext_fd);
        if (v->ctrl_fd >= 0)
            close(v->ctrl_fd);
        snprintf(path, sizeof(path), "%s/ext-auth-%s", m->ext_dir, v->ifname);
        unlink(path);
    }
    free(m);
}

int extmux_tx(struct extmux *m, uint16_t port, const uint8_t mac[6],
              const uint8_t *eapol, size_t len, int encrypted)
{
    struct extmux_vap *v = extmux_vap_by_port(m, port);
    struct extmux_sess *s;
    char hex[EXTMUX_EXT_MAX * 2 + 1];
    char cmd[EXTMUX_EXT_MAX * 2 + 128];
    int cls;

    if (!v || !eapol || !len)
        return -1;
    s = sess_get(m, port, mac, 1);
    cls = eapol_classify(eapol, len);
    s->t_last_tx = now_ms();
    if (cls == 1) {
        s->m1++;
        s->state = EXTMUX_WAIT_M2;
        s->retries = 0;
        s->t_assoc = s->t_assoc ? s->t_assoc : s->t_last_tx;
        s->deadline = s->t_last_tx + m->fourway_ms;
        s->retry_at = s->t_last_tx + m->m1_retry_ms;
        if (len <= sizeof(s->last_frame)) {
            memcpy(s->last_frame, eapol, len);
            s->last_frame_len = len;
            s->last_frame_enc = encrypted;
        }
    } else if (cls == 3) {
        s->m3++;
        s->state = EXTMUX_WAIT_M4;
        s->retry_at = 0;
        s->deadline = s->t_last_tx + m->fourway_ms;
    }
    if (fmt_hex(hex, sizeof(hex), eapol, len) == 0)
        return -1;
    /* W53: hostapd ctrl_iface commands are newline-terminated only on the
     * wire format wpa_ctrl uses; the daemon passes the buffer verbatim to
     * the command parser.  EXT_AUTH_TX computes the hex length from the
     * rest of the line, so a trailing '\n' made it odd and hostapd
     * rejected every frame without sending it.  Send it bare. */
    if (encrypted)
        snprintf(cmd, sizeof(cmd), "EXT_AUTH_TX " MAC_FMT " %s encrypt=1",
                 MAC_ARG(mac), hex);
    else
        snprintf(cmd, sizeof(cmd), "EXT_AUTH_TX " MAC_FMT " %s",
                 MAC_ARG(mac), hex);

    if (v->direct_tx || v->txn_active) {
        m->st.tx_fallback++;
        if (m->cb.on_direct_tx) {
            int r = m->cb.on_direct_tx(m->cb.ctx, v, mac, eapol, len);
            if (r == 0)
                m->st.tx_ok++;
            else
                m->st.tx_failed++;
            return r;
        }
        return -1;
    }
    if (ctrl_send(m, v, cmd) != 0) {
        m->st.tx_fallback++;
        tx_use_direct(m, v, "ctrl socket send failed");
        if (m->cb.on_direct_tx) {
            int r = m->cb.on_direct_tx(m->cb.ctx, v, mac, eapol, len);
            if (r == 0)
                m->st.tx_ok++;
            else
                m->st.tx_failed++;
            return r;
        }
        m->st.tx_failed++;
        return -1;
    }
    v->txn_active = 1;
    v->txn_type = 1;
    memcpy(v->txn_mac, mac, 6);
    v->txn_deadline = now_ms() + m->txn_ms;
    v->txn_retries = 0;
    v->tx_cmds++;
    m->st.tx_ok++;
    mlog(m, "extmux: TX port=0x%04x " MAC_FMT " len=%zu class=%d enc=%d",
         port, MAC_ARG(mac), len, cls, encrypted);
    return 0;
}

int extmux_ptk_installed(struct extmux *m, uint16_t port,
                         const uint8_t mac[6])
{
    struct extmux_vap *v = extmux_vap_by_port(m, port);
    struct extmux_sess *s;

    if (!v)
        return -1;
    s = sess_get(m, port, mac, 1);
    s->ptk++;
    s->state = EXTMUX_PTK;
    s->authz_want = 1;
    s->deadline = now_ms() + m->fourway_ms;
    mlog(m, "extmux: PTK installed port=0x%04x " MAC_FMT ", authorizing",
         port, MAC_ARG(mac));
    return 0;
}

void extmux_forget(struct extmux *m, uint16_t port, const uint8_t mac[6],
                   int notify_manager)
{
    struct extmux_vap *v = extmux_vap_by_port(m, port);
    struct extmux_sess *s = sess_find(m, port, mac);

    if (!s)
        return;
    if (notify_manager && v && m->cb.on_delsta)
        m->cb.on_delsta(m->cb.ctx, v, mac);
    if (s->authorized && m->st.authorized)
        m->st.authorized--;
    s->used = 0;
    if (m->st.sessions)
        m->st.sessions--;
}

int extmux_deauth(struct extmux *m, uint16_t port, const uint8_t mac[6],
                  int reason)
{
    struct extmux_vap *v = extmux_vap_by_port(m, port);
    struct extmux_sess *s = sess_find(m, port, mac);

    if (!v)
        return -1;
    mlog(m, "extmux: deauth port=0x%04x " MAC_FMT " reason=%d",
         port, MAC_ARG(mac), reason);
    if (m->cb.on_deauth)
        m->cb.on_deauth(m->cb.ctx, v, mac, reason);
    if (m->cb.on_delsta)
        m->cb.on_delsta(m->cb.ctx, v, mac);
    if (s) {
        s->state = EXTMUX_FAILED;
        s->authorized = 0;
        s->authz_want = 0;
        s->deadline = 0;
    }
    return 0;
}

/* --- restart recovery --- */

void extmux_resync_begin(struct extmux *m)
{
    for (int i = 0; i < EXTMUX_MAX_SESS; i++)
        if (m->sess[i].used)
            m->sess[i].stale = 1;
    mlog(m, "extmux: resync begin (%u sessions to confirm)", m->st.sessions);
}

int extmux_adopt(struct extmux *m, uint16_t port, const uint8_t mac[6],
                 int ifindex, int authorized)
{
    struct extmux_vap *v = extmux_vap_by_port(m, port);
    struct extmux_sess *s;

    if (!v)
        return -1;
    if (ifindex > 0)
        v->ifindex = ifindex;
    s = sess_get(m, port, mac, 1);
    s->stale = 0;
    s->adopted = 1;
    s->authorized = authorized ? 1 : 0;
    s->state = authorized ? EXTMUX_AUTHORIZED : EXTMUX_ASSOC;
    s->t_assoc = now_ms();
    s->t_last_rx = s->t_assoc;
    /* An authorized STA is adopted as-is.  An associated STA that was
     * never authorized lost its 4-way state with the relay, so force a
     * fresh handshake immediately instead of leaving it half-open. */
    s->deadline = authorized ? 0 : now_ms();
    s->retry_at = 0;
    s->last_frame_len = 0;
    mlog(m, "extmux: adopt port=0x%04x " MAC_FMT " %s", port, MAC_ARG(mac),
         authorized ? "AUTHORIZED" : "assoc (will reauth)");
    return 0;
}

void extmux_resync_finish(struct extmux *m)
{
    for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
        struct extmux_sess *s = &m->sess[i];
        struct extmux_vap *v;
        if (!s->used || !s->stale)
            continue;
        v = extmux_vap_by_port(m, s->port);
        mlog(m, "extmux: resync: stale " MAC_FMT " port=0x%04x %s",
             MAC_ARG(s->mac), s->port,
             s->authorized ? "(authorized, manager cleanup)" : "(deauth)");
        if (v && m->cb.on_delsta)
            m->cb.on_delsta(m->cb.ctx, v, s->mac);
        if (v && !s->authorized && m->cb.on_deauth)
            m->cb.on_deauth(m->cb.ctx, v, s->mac, 15);
        if (s->authorized && m->st.authorized)
            m->st.authorized--;
        s->used = 0;
        if (m->st.sessions)
            m->st.sessions--;
    }
    mlog(m, "extmux: resync done");
}

/* --- journal (never contains key material) --- */

int extmux_save(struct extmux *m, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fprintf(f, "# extmux v1: port mac state authorized assoc_ms\n");
    for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
        struct extmux_sess *s = &m->sess[i];
        if (!s->used)
            continue;
        fprintf(f, "%04x " MAC_FMT " %d %d %llu\n", s->port, MAC_ARG(s->mac),
                s->state, s->authorized, (unsigned long long)s->t_assoc);
    }
    fclose(f);
    return 0;
}

int extmux_load(struct extmux *m, const char *path)
{
    FILE *f = fopen(path, "r");
    char line[256];
    int n = 0;

    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned port, state, authz;
        char macs[32];
        unsigned long long ts;
        uint8_t mac[6];
        struct extmux_sess *s;
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (sscanf(line, "%x %31s %u %u %llu", &port, macs, &state, &authz,
                   &ts) != 5)
            continue;
        if (parse_mac(macs, mac) != 0)
            continue;
        s = sess_get(m, (uint16_t)port, mac, 1);
        s->state = (int)state;
        s->authorized = authz ? 1 : 0;
        s->t_assoc = ts;
        s->stale = 1;                   /* must be confirmed by resync */
        n++;
    }
    fclose(f);
    mlog(m, "extmux: loaded %d journal rows from %s", n, path);
    return n;
}

void extmux_stats(struct extmux *m, struct extmux_stats *out)
{
    if (!m || !out)
        return;
    *out = m->st;
    out->sessions = 0;
    out->authorized = 0;
    out->stale = 0;
    for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
        if (!m->sess[i].used)
            continue;
        out->sessions++;
        if (m->sess[i].authorized)
            out->authorized++;
        if (m->sess[i].stale)
            out->stale++;
    }
}

int extmux_session_count(struct extmux *m, uint16_t port)
{
    int n = 0;
    for (int i = 0; i < EXTMUX_MAX_SESS; i++)
        if (m->sess[i].used && m->sess[i].port == port)
            n++;
    return n;
}

void extmux_dump(struct extmux *m, void (*out)(void *, const char *),
                 void *outctx)
{
    char line[256];
    if (!m || !out)
        return;
    for (int i = 0; i < EXTMUX_MAX_SESS; i++) {
        struct extmux_sess *s = &m->sess[i];
        if (!s->used)
            continue;
        snprintf(line, sizeof(line),
                 "port=0x%04x " MAC_FMT " %-10s auth=%d adopted=%d "
                 "m1=%u m2=%u m3=%u m4=%u ptk=%u retries=%u",
                 s->port, MAC_ARG(s->mac), extmux_state_name(s->state),
                 s->authorized, s->adopted, s->m1, s->m2, s->m3, s->m4,
                 s->ptk, s->retries);
        out(outctx, line);
    }
}

int extmux_service(struct extmux *m, int timeout_ms)
{
    struct pollfd pfd[EXTMUX_MAX_VAPS * 2];
    struct extmux_vap *pv[EXTMUX_MAX_VAPS * 2];
    int nfd = 0, i, rc;
    uint64_t now = now_ms(), next = 0, wait;

    if (!m)
        return -1;
    for (i = 0; i < EXTMUX_MAX_VAPS; i++) {
        struct extmux_vap *v = &m->vap[i];
        if (!v->used)
            continue;
        if (v->ext_fd >= 0) {
            pfd[nfd].fd = v->ext_fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            pv[nfd++] = v;
        }
        if (v->ctrl_fd >= 0 && v->txn_active) {
            pfd[nfd].fd = v->ctrl_fd;
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            pv[nfd++] = v;
        }
    }
    /* nearest timer */
    for (i = 0; i < EXTMUX_MAX_SESS; i++) {
        struct extmux_sess *s = &m->sess[i];
        if (!s->used)
            continue;
        if (s->deadline && (!next || s->deadline < next)) next = s->deadline;
        if (s->retry_at && (!next || s->retry_at < next)) next = s->retry_at;
    }
    for (i = 0; i < EXTMUX_MAX_VAPS; i++) {
        if (m->vap[i].used && m->vap[i].txn_active &&
            (!next || m->vap[i].txn_deadline < next))
            next = m->vap[i].txn_deadline;
    }
    wait = timeout_ms < 0 ? 1000 : (uint64_t)timeout_ms;
    if (next) {
        if (next <= now) wait = 0;
        else if (next - now < wait) wait = next - now;
    }
    if (wait > 1000) wait = 1000;

    rc = poll(pfd, (nfds_t)nfd, (int)wait);
    if (rc > 0) {
        for (i = 0; i < nfd; i++) {
            if (!pfd[i].revents)
                continue;
            if (pfd[i].fd == pv[i]->ext_fd)
                ext_read(m, pv[i]);
            if (pfd[i].fd == pv[i]->ctrl_fd)
                ctrl_read(m, pv[i]);
        }
    }
    extmux_tick(m, now_ms());
    return rc;
}
