/*
 * test_extmux -- regression gate for the hostapd EXT_AUTH_TX contract (W53).
 *
 * No radio, no hostapd: a fake hostapd control socket stands in for the
 * daemon and checks the exact wire format extmux sends, plus the one-shot
 * fallback when the daemon rejects the command.
 *
 * Build/run (host):
 *     cc -O2 -Wall -Wextra -I native/src -o test_extmux \
 *        native/tests/test_extmux.c native/src/extmux.c
 *     ./test_extmux
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "extmux.h"

static int failures;
#define CHECK(cond, ...) do {                                       \
    if (!(cond)) {                                                  \
        failures++;                                                 \
        printf("FAIL %s:%d: ", __FILE__, __LINE__);                 \
        printf(__VA_ARGS__);                                        \
        printf("\n");                                               \
    }                                                               \
} while (0)

struct fake {
    int fd;
    char dir[108];
    char reply[32];
    int commands;
    int saw_newline;
    char last[8192];
};

static int fake_open(struct fake *f, const char *dir, const char *ifname,
                     const char *reply)
{
    struct sockaddr_un sa;
    char path[256];

    memset(f, 0, sizeof(*f));
    f->fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (f->fd < 0)
        return -1;
    snprintf(f->dir, sizeof(f->dir), "%s", dir);
    snprintf(f->reply, sizeof(f->reply), "%s", reply);
    snprintf(path, sizeof(path), "%s/%s", dir, ifname);
    unlink(path);
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%.*s",
             (int)sizeof(sa.sun_path) - 1, path);
    if (bind(f->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
        return -1;
    return 0;
}

/* Consume one command from extmux and answer it. */
static int fake_serve(struct fake *f)
{
    char buf[8192];
    struct sockaddr_un src;
    socklen_t slen = sizeof(src);
    ssize_t n;

    n = recvfrom(f->fd, buf, sizeof(buf) - 1, 0,
                 (struct sockaddr *)&src, &slen);
    if (n <= 0)
        return -1;
    buf[n] = '\0';
    f->commands++;
    snprintf(f->last, sizeof(f->last), "%s", buf);
    if (strchr(buf, '\n'))
        f->saw_newline = 1;
    if (sendto(f->fd, f->reply, strlen(f->reply), 0,
               (struct sockaddr *)&src, slen) < 0)
        return -1;
    return 0;
}

struct counts {
    int logs;
    int rejected_line;
    int authz_line;
    int direct_tx;
    int direct_authz;
    int deauth;
    int eapol_to_manager;
};

static void cb_log(void *ctx, const char *msg)
{
    struct counts *c = ctx;
    c->logs++;
    if (strstr(msg, "rejected EXT_AUTH_TX"))
        c->rejected_line++;
    if (strstr(msg, "EXT_AUTH_AUTHORIZE"))
        c->authz_line++;
    printf("  log: %s\n", msg);
}

static int cb_eapol(void *ctx, const struct extmux_vap *v,
                    const uint8_t mac[6], const uint8_t *e, size_t n, int enc)
{
    (void)v; (void)mac; (void)e; (void)n; (void)enc;
    ((struct counts *)ctx)->eapol_to_manager++;
    return 0;
}

static int cb_delsta(void *ctx, const struct extmux_vap *v, const uint8_t *m)
{
    (void)ctx; (void)v; (void)m;
    return 0;
}

static int cb_deauth(void *ctx, const struct extmux_vap *v, const uint8_t *m,
                     int r)
{
    (void)v; (void)m; (void)r;
    ((struct counts *)ctx)->deauth++;
    return 0;
}

static int cb_direct_tx(void *ctx, const struct extmux_vap *v,
                        const uint8_t mac[6], const uint8_t *e, size_t n)
{
    (void)v; (void)mac; (void)e; (void)n;
    ((struct counts *)ctx)->direct_tx++;
    return 0;
}

static int cb_direct_authz(void *ctx, const struct extmux_vap *v,
                           const uint8_t mac[6])
{
    (void)v; (void)mac;
    ((struct counts *)ctx)->direct_authz++;
    return 0;
}

static void cb_authorized(void *ctx, const struct extmux_vap *v,
                          const uint8_t mac[6])
{
    (void)ctx; (void)v; (void)mac;
}

/* Minimal EAPOL-Key: version 2, type 3, body length 95. */
static size_t mk_eapol(uint8_t *b, unsigned info)
{
    memset(b, 0, 99);
    b[0] = 2;             /* EAPOL version */
    b[1] = 3;             /* EAPOL-Key   */
    b[2] = 0; b[3] = 95;  /* body length */
    b[5] = (uint8_t)(info >> 8);
    b[6] = (uint8_t)info;
    return 99;
}

static const uint8_t STA[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x53 };

/* Case 1: the frame must go out bare (no trailing newline) and a normal
 * hostapd OK reply must keep the ctrl path. */
static void test_bare_command(void)
{
    char dir[] = "/tmp/extmux-test-XXXXXX";
    struct fake f;
    struct counts c = {0};
    struct extmux_cb cb = {
        .log = cb_log, .ctx = &c,
        .on_eapol = cb_eapol, .on_delsta = cb_delsta,
        .on_deauth = cb_deauth, .on_direct_tx = cb_direct_tx,
        .on_direct_authz = cb_direct_authz, .on_authorized = cb_authorized,
    };
    struct extmux *m;
    uint8_t eapol[128];
    size_t n;
    int r;

    printf("case 1: bare EXT_AUTH_TX, hostapd OK\n");
    if (!mkdtemp(dir)) { failures++; return; }
    CHECK(fake_open(&f, dir, "wlanA", "OK\n") == 0, "fake hostapd bind");
    m = extmux_new(dir, dir, &cb);
    CHECK(m != NULL, "extmux_new");
    CHECK(extmux_add_vap(m, 0x0001, "wlanA", 7, NULL) == 0, "add vap");

    n = mk_eapol(eapol, 0x008a);          /* M1: ACK */
    r = extmux_tx(m, 0x0001, STA, eapol, n, 0);
    CHECK(r == 0, "extmux_tx ret=%d", r);
    CHECK(fake_serve(&f) == 0, "hostapd did not receive a command");
    CHECK(!f.saw_newline, "EXT_AUTH_TX carried a trailing newline: '%s'",
          f.last);
    CHECK(strncmp(f.last, "EXT_AUTH_TX 02:00:00:00:00:53 ", 30) == 0,
          "unexpected command: '%s'", f.last);
    extmux_service(m, 0);
    CHECK(c.direct_tx == 0, "direct fallback used after OK (%d)", c.direct_tx);
    CHECK(c.rejected_line == 0, "spurious rejection line");
    extmux_free(m);
    close(f.fd);
    remove(dir);
}

/* Case 2: a hostapd that rejects EXT_AUTH_TX must switch the BSS to the
 * direct path exactly once, and never log per frame. */
static void test_reject_fallback(void)
{
    char dir[] = "/tmp/extmux-test-XXXXXX";
    struct fake f;
    struct counts c = {0};
    struct extmux_cb cb = {
        .log = cb_log, .ctx = &c,
        .on_eapol = cb_eapol, .on_delsta = cb_delsta,
        .on_deauth = cb_deauth, .on_direct_tx = cb_direct_tx,
        .on_direct_authz = cb_direct_authz, .on_authorized = cb_authorized,
    };
    struct extmux *m;
    uint8_t eapol[128];
    size_t n;

    printf("case 2: hostapd rejects EXT_AUTH_TX\n");
    if (!mkdtemp(dir)) { failures++; return; }
    CHECK(fake_open(&f, dir, "wlanB", "FAIL\n") == 0, "fake hostapd bind");
    m = extmux_new(dir, dir, &cb);
    CHECK(m != NULL, "extmux_new");
    CHECK(extmux_add_vap(m, 0x0002, "wlanB", 8, NULL) == 0, "add vap");

    n = mk_eapol(eapol, 0x008a);
    CHECK(extmux_tx(m, 0x0002, STA, eapol, n, 0) == 0, "first tx");
    CHECK(fake_serve(&f) == 0, "hostapd did not receive the first command");
    extmux_service(m, 0);
    CHECK(c.rejected_line == 1, "expected one rejection line, got %d",
          c.rejected_line);
    CHECK(c.direct_tx == 0, "frame was blind-reinjected (%d)", c.direct_tx);

    for (int i = 0; i < 4; i++) {
        CHECK(extmux_tx(m, 0x0002, STA, eapol, n, 0) == 0, "tx %d", i);
        extmux_service(m, 0);
    }
    CHECK(c.direct_tx == 4, "expected 4 direct TX, got %d", c.direct_tx);
    CHECK(c.rejected_line == 1, "rejection line repeated %d times",
          c.rejected_line);
    CHECK(f.commands == 1, "kept talking to a rejecting hostapd (%d commands)",
          f.commands);
    extmux_free(m);
    close(f.fd);
    remove(dir);
}

/* Case 3: a hostapd that cannot authorize must not close the data path: the
 * PTK is installed, so nl80211 authorizes the station instead. */
static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void test_authz_fallback(void)
{
    char dir[] = "/tmp/extmux-test-XXXXXX";
    struct fake f;
    struct counts c = {0};
    struct extmux_cb cb = {
        .log = cb_log, .ctx = &c,
        .on_eapol = cb_eapol, .on_delsta = cb_delsta,
        .on_deauth = cb_deauth, .on_direct_tx = cb_direct_tx,
        .on_direct_authz = cb_direct_authz, .on_authorized = cb_authorized,
    };
    struct extmux *m;
    struct extmux_vap *v;

    printf("case 3: hostapd rejects EXT_AUTH_AUTHORIZE\n");
    if (!mkdtemp(dir)) { failures++; return; }
    CHECK(fake_open(&f, dir, "wlanC", "FAIL\n") == 0, "fake hostapd bind");
    m = extmux_new(dir, dir, &cb);
    CHECK(m != NULL, "extmux_new");
    CHECK(extmux_add_vap(m, 0x0003, "wlanC", 9, NULL) == 0, "add vap");
    extmux_set_timeouts(m, 10000, 3000, 50);

    CHECK(extmux_ptk_installed(m, 0x0003, STA) == 0, "ptk installed");
    extmux_tick(m, mono_ms());
    /* initial command + two retries; the third FAIL triggers the nl80211
     * authorize fallback */
    for (int i = 0; i < 4 && c.direct_authz == 0; i++) {
        CHECK(fake_serve(&f) == 0, "authorize command %d", i);
        extmux_service(m, 0);
    }
    v = extmux_vap_by_port(m, 0x0003);
    CHECK(c.direct_authz == 1, "direct authorize not called (%d)",
          c.direct_authz);
    CHECK(c.deauth == 0, "session was deauthenticated (%d)", c.deauth);
    CHECK(v && v->authz_ok == 1, "authz_ok=%lu", v ? v->authz_ok : 0UL);
    extmux_free(m);
    close(f.fd);
    remove(dir);
}

int main(void)
{
    test_bare_command();
    test_reject_fallback();
    test_authz_fallback();
    if (failures) {
        printf("extmux-test: %d failure(s)\n", failures);
        return 1;
    }
    printf("extmux-test: all tests passed\n");
    return 0;
}
