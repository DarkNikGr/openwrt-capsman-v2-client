/* W34 host unit test for src/ownership.inc.
 *
 * This compiles the real ownership state machine with tiny stubs for the
 * kernel/hostapd side, so the transition table in REPORT.md is executable:
 * pure manager-only, pure legacy, mixed, netifd reload and agent restart.
 *
 *   tests/run-w34-tests.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>

/* ---- stubs required by ownership.inc ---------------------------------- */

#define MAX_RADIOS 8
struct cfg {
    int vap_auto;
    const char *vap_state;
    int wireless_mode;
    int vap_teardown;
};
struct vap {
    int used, rid, wid;
    uint16_t vlan;
    uint8_t bssid[6];
    int ifindex;
    char ifname[32];
    int l2fd, extfd;
    uint32_t freq;
};
static struct vap g_vap[MAX_RADIOS][16];
static void *g_extmux;

#define FAKE_MAX 64
struct fake_net { int used; char name[32]; int ifindex; uint8_t mac[6]; };
static struct fake_net g_net[FAKE_MAX];
static int g_next_ifindex = 10;
static int g_created, g_deleted, g_starts, g_stops, g_ready;
static int g_create_fail;
static int g_pid_alive[4096];

static int fake_kill(pid_t pid, int sig)
{
    if (pid > 0 && pid < 4096 && g_pid_alive[pid]) {
        if (sig == 0)
            return 0;               /* liveness probe */
        g_pid_alive[pid] = 0;
        g_stops++;
        return 0;
    }
    errno = ESRCH;
    return -1;
}
#define kill fake_kill
#define usleep(x) ((void)(x))

static int read_sysfs_int(const char *ifname, const char *leaf)
{
    if (strcmp(leaf, "ifindex")) return 0;
    for (int i = 0; i < FAKE_MAX; i++)
        if (g_net[i].used && !strcmp(g_net[i].name, ifname))
            return g_net[i].ifindex;
    return 0;
}

static struct fake_net *fake_find(const char *name)
{
    for (int i = 0; i < FAKE_MAX; i++)
        if (g_net[i].used && !strcmp(g_net[i].name, name))
            return &g_net[i];
    return NULL;
}

static struct fake_net *fake_add(const char *name)
{
    struct fake_net *n = fake_find(name);
    if (n) return n;
    for (int i = 0; i < FAKE_MAX; i++)
        if (!g_net[i].used) {
            n = &g_net[i];
            n->used = 1;
            snprintf(n->name, sizeof(n->name), "%s", name);
            n->ifindex = g_next_ifindex++;
            return n;
        }
    return NULL;
}

/* W33 deterministic MAC lookup: AP/AP_VLAN only, deterministic name. */
static int ifindex_by_mac_ap(const uint8_t mac[6], int want_phy,
                             char *name, size_t n)
{
    (void)want_phy;
    for (int i = 0; i < FAKE_MAX; i++)
        if (g_net[i].used && !memcmp(g_net[i].mac, mac, 6)) {
            if (name && n) snprintf(name, n, "%s", g_net[i].name);
            return g_net[i].ifindex;
        }
    return 0;
}

/* W33 AP-only predicate: every fake netdev is an AP. */
static int iface_is_ap(int ifindex) { (void)ifindex; return 1; }

/* W36 seam: no in-CAP MLME in the host model. */
static int mlme_owns_port(int port) { (void)port; return 0; }

static int vap_netdev_create(int phy, const char *ifname, const uint8_t mac[6])
{
    (void)phy; (void)mac;
    if (g_create_fail)
        return -1;
    if (fake_find(ifname))
        return -2;
    if (!fake_add(ifname))
        return -1;
    memcpy(fake_find(ifname)->mac, mac, 6);
    g_created++;
    return fake_find(ifname)->ifindex;
}

static int vap_netdev_del(int ifindex)
{
    for (int i = 0; i < FAKE_MAX; i++)
        if (g_net[i].used && g_net[i].ifindex == ifindex) {
            memset(&g_net[i], 0, sizeof(g_net[i]));
            g_deleted++;
            return 0;
        }
    return -1;
}

static int vap_hostapd_start(int port, const char *ifname, int phy, int vapid,
                             const uint8_t *body, uint16_t len,
                             const struct vap *vp, const struct cfg *c)
{
    (void)port; (void)phy; (void)vapid; (void)body; (void)len;
    (void)vp; (void)c;
    int pid = 3000 + ++g_starts;
    char p[128];
    FILE *f;

    g_pid_alive[pid] = 1;
    snprintf(p, sizeof(p), OWN_RUN_DIR "/vap-%s.pid", ifname);
    f = fopen(p, "w");
    if (f) { fprintf(f, "%d\n", pid); fclose(f); }
    return pid;
}

static void cap_vap_ready(int phy, int vapid, int ifindex, const char *ifname,
                          const uint8_t mac[6], const struct cfg *c)
{
    (void)phy; (void)vapid; (void)ifindex; (void)ifname; (void)mac; (void)c;
    g_ready++;
}

static void extmux_del_vap(void *m, uint16_t port)
{
    (void)m; (void)port;
}
static void pmap_del(int port) { (void)port; }
static void dp_del_ifindex(int ifindex) { (void)ifindex; }
static size_t parse_hex(const char *s, uint8_t *out, size_t max)
{
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

#include "ownership.inc"

/* ---- test harness ----------------------------------------------------- */

static int failures;
static struct cfg T;

static void check(int cond, const char *what)
{
    if (!cond) { printf("FAIL: %s\n", what); failures++; }
    else printf("ok: %s\n", what);
}

static void reset_all(void)
{
    memset(g_own, 0, sizeof(g_own));
    memset(g_vap, 0, sizeof(g_vap));
    memset(g_net, 0, sizeof(g_net));
    memset(g_pid_alive, 0, sizeof(g_pid_alive));
    memset(&g_own_nd, 0, sizeof(g_own_nd));
    g_extmux = NULL;
    g_next_ifindex = 10;
    g_created = g_deleted = g_starts = g_stops = g_ready = 0;
    g_create_fail = 0;
    g_own_probe_at = 0;
    g_own_probe_state = OWN_PROBE_UNKNOWN;
    g_own_ubus_missing = -1;
    g_own_dirty = 0;
    g_own_path = OWN_RUN_DIR "/test.state";
    unlink(OWN_RUN_DIR "/test.state");
    /* clear fake state dirs' vap files */
    {
        DIR *d = opendir(OWN_RUN_DIR);
        struct dirent *de;
        if (d) {
            while ((de = readdir(d)) != NULL) {
                if (strncmp(de->d_name, "vap-", 4) == 0) {
                    char p[256];
                    snprintf(p, sizeof(p), OWN_RUN_DIR "/%s", de->d_name);
                    unlink(p);
                }
            }
            closedir(d);
        }
    }
    T.vap_auto = 1;
    T.vap_state = OWN_RUN_DIR "/test.state";
    T.wireless_mode = -1;
    T.vap_teardown = 1;
}

static void set_nd(const char *json)
{
    const char *path = getenv("CAPAGENT_NETIFD_STATUS");
    FILE *f = fopen(path, "w");
    if (!f) { perror("nd file"); exit(2); }
    fputs(json, f);
    fclose(f);
}

static int claim_start(struct cfg *c, int phy, int vapid, const char *name_exp)
{
    char ifname[32];
    uint8_t mac[6] = { 0x02, 0, 0, 0, (uint8_t)phy, (uint8_t)vapid };
    int idx = 0, managed = 0;
    int r = own_claim(c, phy, vapid, NULL, mac, ifname, sizeof(ifname),
                      &idx, &managed);
    static const uint8_t body[] = { 0x00, 0x03, 0x00, 0x04, 't', 'e', 's', 't' };
    struct vap vp;
    memset(&vp, 0, sizeof(vp));
    memcpy(vp.bssid, mac, 6);
    vp.vlan = 0;
    vp.freq = 2437;
    if (r > 0 && idx > 0)
        own_note_start(c, (phy << 8) | vapid, body, sizeof(body),
                       &vp, idx, managed);
    if (name_exp)
        check(!strcmp(ifname, name_exp), "claimed expected ifname");
    return r > 0 && managed ? idx : 0;
}

static int entry_owner(int port)
{
    struct own_entry *e = own_by_port((uint16_t)port);
    return e ? e->owner : -1;
}

static void test_pure_manager(void)
{
    int idx;
    printf("-- pure manager-only --\n");
    set_nd("{}");
    reset_all();
    idx = claim_start(&T, 0, 0, "phy0-ap0");
    check(idx > 0, "port 0 gets a netdev");
    check(entry_owner(0) == OWN_CAPAGENT, "port 0 is CAPAGENT");
    {
        char nm[32];
        check(own_managed_strict(0) &&
              own_ifname_for_port(0, nm, sizeof(nm)) &&
              !strcmp(nm, "phy0-ap0"), "port lookup uses the real name");
    }
    check(g_created == 1 && g_starts == 1, "one netdev, one hostapd");
    own_service(&T);
    check(g_starts == 1, "service does not duplicate hostapd");
    own_destroy(&T, 0);
    check(g_deleted == 1, "destroy deletes our netdev");
    check(entry_owner(0) != OWN_CAPAGENT, "port 0 released");
    check(g_stops == 1, "destroy stops hostapd");
}

static void test_pure_legacy(void)
{
    printf("-- pure legacy (netifd owns both names) --\n");
    set_nd("{\"radio0\":{\"up\":true,\"interfaces\":["
           "{\"section\":\"s0\",\"ifname\":\"phy0-ap0\"},"
           "{\"section\":\"s1\",\"ifname\":\"phy0-ap1\"}]}}");
    reset_all();
    fake_add("phy0-ap0");
    fake_add("phy0-ap1");
    g_created = 0;
    claim_start(&T, 0, 0, "cap0-0");
    claim_start(&T, 0, 1, "cap0-1");
    check(entry_owner(0) == OWN_CAPAGENT && entry_owner(1) == OWN_CAPAGENT,
          "both manager ports get alternate names");
    own_service(&T);
    check(fake_find("phy0-ap0") && fake_find("phy0-ap1"),
          "legacy netdevs untouched");
    own_destroy(&T, 0);
    check(!fake_find("cap0-0") && fake_find("phy0-ap0"),
          "destroy removes only our netdev");
}

static void test_mixed(void)
{
    printf("-- mixed (one legacy BSS + manager VAPs) --\n");
    set_nd("{\"radio0\":{\"up\":true,\"interfaces\":["
           "{\"section\":\"legacy\",\"ifname\":\"phy0-ap0\"}]}}");
    reset_all();
    fake_add("phy0-ap0");
    claim_start(&T, 0, 0, "cap0-0");
    claim_start(&T, 0, 1, "phy0-ap1");
    check(entry_owner(0) == OWN_CAPAGENT && entry_owner(1) == OWN_CAPAGENT,
          "collision moved to cap0-0, free name kept");
    own_service(&T);
    check(fake_find("phy0-ap0") && fake_find("cap0-0") &&
          fake_find("phy0-ap1"), "legacy + both manager netdevs coexist");
}

static void test_netifd_takeover(void)
{
    printf("-- netifd reload takes our name --\n");
    set_nd("{}");
    reset_all();
    claim_start(&T, 0, 1, "phy0-ap1");
    check(entry_owner(0x0001) == OWN_CAPAGENT, "phy0-ap1 is ours");
    set_nd("{\"radio0\":{\"up\":true,\"interfaces\":["
           "{\"section\":\"new\",\"ifname\":\"phy0-ap1\"}]}}");
    own_service(&T);
    check(entry_owner(0x0001) == OWN_NETIFD, "netifd wins the name");
    check(g_deleted == 0, "detach does not delete netifd's netdev");
    check(g_stops == 1, "our hostapd is stopped");
    /* netifd releases the name again */
    memset(&g_net[0], 0, sizeof(g_net[0]));
    for (int i = 1; i < FAKE_MAX; i++)
        if (g_net[i].used && !strcmp(g_net[i].name, "phy0-ap1"))
            memset(&g_net[i], 0, sizeof(g_net[i]));
    set_nd("{}");
    own_service(&T);
    check(entry_owner(0x0001) == -1, "released netifd row is dropped");
    claim_start(&T, 0, 1, "phy0-ap1");
    check(entry_owner(0x0001) == OWN_CAPAGENT, "manager re-claims the name");
}

static void test_agent_restart(void)
{
    int before;
    printf("-- capagent restart --\n");
    set_nd("{}");
    reset_all();
    claim_start(&T, 0, 0, "phy0-ap0");
    before = g_starts;
    check(before == 1, "one hostapd before restart");
    /* Simulate process restart: memory is lost, journal and netdev remain. */
    memset(g_own, 0, sizeof(g_own));
    own_init(&T);
    own_restore_vaps(&T);
    check(entry_owner(0) == OWN_CAPAGENT, "journal restored the owner");
    check(g_starts == before, "no second hostapd on the same BSS");
    check(g_created == 1, "no duplicate netdev");
    check(g_ready > 0, "relay re-registered the VAP");
}

static void test_probe_unknown_then_retry(void)
{
    char bad[160], good[160];
    printf("-- netifd probe unknown -> pending -> retry --\n");
    snprintf(bad, sizeof(bad), OWN_RUN_DIR "/nd-missing.json");
    snprintf(good, sizeof(good), OWN_RUN_DIR "/nd-good.json");
    unlink(bad);
    setenv("CAPAGENT_NETIFD_STATUS", bad, 1);
    reset_all();
    g_create_fail = 1;
    {
        char ifname[32];
        uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0 };
        int idx = 0, managed = 1;
        static const uint8_t body[] = { 1, 2, 3 };
        struct vap vp;
        memset(&vp, 0, sizeof(vp));
        int r = own_claim(&T, 0, 0, NULL, mac, ifname, sizeof(ifname),
                          &idx, &managed);
        check(r == 0 && idx == 0, "claim deferred while ubus is unusable");
        check(entry_owner(0) == OWN_PENDING, "port is PENDING");
        own_note_start(&T, 0, body, sizeof(body), &vp, 0, 0);
        check(g_starts == 0, "no hostapd while deferred");
    }
    g_create_fail = 0;
    {
        FILE *f = fopen(good, "w");
        if (f) { fputs("{}", f); fclose(f); }
    }
    setenv("CAPAGENT_NETIFD_STATUS", good, 1);
    own_service(&T);
    check(entry_owner(0) == OWN_CAPAGENT, "PENDING resolved after probe");
    check(g_created == 1 && g_starts == 1, "netdev+hostapd created on retry");
}

static void test_busy_and_stale(void)
{
    char stale[160];
    printf("-- netifd busy/pending + stale files --\n");
    set_nd("{\"radio0\":{\"pending\":true,\"up\":false,\"interfaces\":["
           "{\"section\":\"s\",\"ifname\":\"phy0-ap0\"}]}}");
    reset_all();
    fake_add("phy0-ap0");
    claim_start(&T, 0, 0, "cap0-0");
    check(entry_owner(0) == OWN_CAPAGENT, "busy probe still avoids netifd name");
    check(fake_find("phy0-ap0") && fake_find("cap0-0"),
          "netifd netdev untouched during reload");

    snprintf(stale, sizeof(stale), OWN_TMP_DIR "/vap-stale.conf");
    {
        FILE *f = fopen(stale, "w");
        if (f) { fputs("interface=stale\n", f); fclose(f); }
    }
    own_cleanup_stale();
    check(access(stale, F_OK) != 0, "stale /tmp/vap-*.conf removed");
}

static void test_netifd_readonly_and_forced(void)
{
    char ifname[32];
    uint8_t mac[6] = { 0x02, 0, 0, 0, 0, 0 };
    int idx = -1, managed = 1, r;

    printf("-- netifd name is reported read-only; forced legacy never creates --\n");
    set_nd("{\"radio0\":{\"up\":true,\"interfaces\":["
           "{\"section\":\"s0\",\"ifname\":\"phy0-ap0\"}]}}");
    reset_all();
    fake_add("phy0-ap0");
    T.wireless_mode = 1;                 /* read-only: no alternate create */
    r = own_claim(&T, 0, 0, NULL, mac, ifname, sizeof(ifname), &idx, &managed);
    check(r == 1 && managed == 0 && idx > 0,
          "0xd00b can report netifd's existing ifindex");
    check(!strcmp(ifname, "phy0-ap0"), "netifd name kept");
    check(g_created == 0 && g_starts == 0, "nothing created/started");

    set_nd("{}");
    reset_all();
    T.wireless_mode = 1;                 /* --wireless-owner legacy */
    r = own_claim(&T, 0, 0, NULL, mac, ifname, sizeof(ifname), &idx, &managed);
    check(r == 0 && managed == 0 && g_created == 0,
          "forced legacy refuses to create");
    check(entry_owner(0) == OWN_PENDING, "refused claim is PENDING");
    T.wireless_mode = -1;
}

static void test_reload_recreate(void)
{
    int before_c, before_s;
    printf("-- wifi reload removes netdev/hostapd --\n");
    set_nd("{}");
    reset_all();
    claim_start(&T, 0, 0, "phy0-ap0");
    before_c = g_created;
    before_s = g_starts;
    /* netifd teardown: netdev and hostapd gone, journal intact */
    for (int i = 0; i < FAKE_MAX; i++)
        if (g_net[i].used) memset(&g_net[i], 0, sizeof(g_net[i]));
    for (int p = 0; p < 4096; p++)
        g_pid_alive[p] = 0;
    own_service(&T);
    check(g_created == before_c + 1, "netdev recreated from the journal");
    check(g_starts == before_s + 1, "hostapd restarted from the saved body");
    check(entry_owner(0) == OWN_CAPAGENT, "port stays CAPAGENT");

    /* hostapd crash only: netdev intact, no duplicate netdev */
    before_c = g_created;
    before_s = g_starts;
    for (int p = 0; p < 4096; p++)
        g_pid_alive[p] = 0;
    own_service(&T);
    check(g_created == before_c, "no netdev recreated on hostapd crash");
    check(g_starts == before_s + 1, "hostapd restarted on crash");
}

int main(void)
{
    char dir[256];
    char nd[256];

    {
        const char *d = getenv("W34_TEST_DIR");
        if (!d || !*d) { fprintf(stderr, "W34_TEST_DIR not set\n"); return 2; }
        snprintf(dir, sizeof(dir), "%s", d);
    }
    mkdir(dir, 0700);
    snprintf(nd, sizeof(nd), "%s/nd.json", dir);
    setenv("CAPAGENT_NETIFD_STATUS", nd, 1);
    set_nd("{}");
    T.vap_auto = 1;

    test_pure_manager();
    test_pure_legacy();
    test_mixed();
    test_netifd_takeover();
    test_agent_restart();
    test_probe_unknown_then_retry();
    test_busy_and_stale();
    test_netifd_readonly_and_forced();
    test_reload_recreate();

    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("all ownership tests passed\n");
    return 0;
}
