/* policy.inc — W33/W34: wireless ownership policy + deterministic identity
 *
 * Part of capagent.c (single translation unit; included after nl80211.inc).
 *
 * The single source of truth is the ownership table in src/ownership.inc,
 * populated from `ubus call network.wireless status` (src/netifd_status.inc)
 * and from the netdev journal.  There is no /etc/config/wireless heuristic in
 * production any more.
 *
 * Per netdev:
 *   NETIFD    the name appears in network.wireless status.  capagent never
 *             creates, starts, deletes or reconfigures it.
 *   CAPAGENT  the journal says we created/adopted it.  Full lifecycle.
 *   FOREIGN   exists, neither netifd nor ours.  Never touched; the manager
 *             VAP is placed on an alternate name.
 *   PENDING   manager asked while the netifd probe was unusable.  Retried.
 *
 * `wl_legacy()` is the coarse session predicate: at least one netifd wireless
 * ifname exists (so UCI apply and other global config writes stay off).  All
 * per-netdev effects use wl_port_managed()/own_claim(), which is what makes a
 * mixed legacy+manager setup safe.  --wireless-owner legacy / the env override
 * forces the old fully read-only contract.  An explicitly supplied
 * --wireless-config FILE is still counted for diagnostics/selftests.
 */

#include "netifd_status.inc"

#define WL_CONF_DEFAULT "/etc/config/wireless"

static int g_wl_legacy;             /* 1 = legacy UCI owns the BSSes */
static int g_wl_ifaces;             /* number of wifi-iface sections  */
static char g_wl_path[160] = WL_CONF_DEFAULT;

/* Count "config wifi-iface" sections.  Hand-rolled because capagent is
   static and must not depend on libuci in the early-boot path.  A line is a
   section header only when its first non-blank token is "config" and the
   next token is exactly "wifi-iface" (so a comment or an option value can
   never be mistaken for one).  Returns the count, -1 when unreadable. */
static int wl_count_iface(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int n = 0;

    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') continue;
        if (strncmp(p, "config", 6) != 0) continue;
        p += 6;
        if (*p != ' ' && *p != '\t') continue;      /* "configx" */
        while (*p == ' ' || *p == '\t') p++;
        if (strncmp(p, "wifi-iface", 10) != 0) continue;
        p += 10;
        /* must be terminated: EOL, whitespace, comment or a section name */
        if (*p && *p != ' ' && *p != '\t' && *p != '\'' && *p != '"' &&
            *p != '\r' && *p != '\n' && *p != '#')
            continue;
        n++;
    }
    fclose(f);
    return n;
}

static const char *wl_mode_name(void)
{
    return g_wl_legacy ? "legacy" : "own";
}

/* Read-only in legacy mode.  Every netdev / hostapd / UCI side effect in
   this agent must be behind this predicate. */
static int wl_legacy(void) { return g_wl_legacy; }
static int wl_own(void)    { return !g_wl_legacy; }

/* Count ifnames in a network.wireless status payload (ubus).  Also exposes
 * the pending flag and the first name for diagnostics/selftests. */
static int wl_status_ifaces(const char *json, int *pending, char *first,
                            size_t first_len)
{
    struct nd_status st;
    if (nd_parse(json, &st) != 0)
        return -1;
    if (pending) *pending = st.pending;
    if (first && first_len)
        snprintf(first, first_len, "%s",
                 st.n ? st.iface[0].ifname : "");
    return st.n;
}

/* Print the live ubus/journal decision without reconciling or writing
 * anything (--check-wireless is strictly read-only). */
static void wl_report_ubus(const struct cfg *c)
{
    const char *env_mode = getenv("CAPAGENT_WIRELESS_MODE");
    int forced = -1;

    if (c->wireless_mode >= 0)
        forced = c->wireless_mode;
    else if (env_mode && *env_mode)
        forced = !strcmp(env_mode, "legacy");
    g_wl_ifaces = own_netifd_count();
    if (forced >= 0)
        g_wl_legacy = forced;
    else
        g_wl_legacy = g_wl_ifaces > 0;
    printf("wl: ownership=%s (%s; ubus: %d netifd ifname%s, %d capagent row%s)\n",
           wl_mode_name(), forced >= 0 ? "forced" : "auto",
           g_wl_ifaces, g_wl_ifaces == 1 ? "" : "s",
           own_managed_count(), own_managed_count() == 1 ? "" : "s");
    if (g_wl_legacy)
        printf("wl: netifd owns %d name(s); capagent only manages names outside "
               "that set\n", g_wl_ifaces);
    fflush(stdout);
}

/* Every session starts here.  In auto mode the decision is the live netifd
 * status plus our journal; the config file is only read when the operator
 * explicitly points at one (tests, --check-wireless diagnostics). */
static void wl_classify(const struct cfg *c)
{
    const char *path = c->wireless_conf ? c->wireless_conf : WL_CONF_DEFAULT;
    const char *env_conf = getenv("CAPAGENT_WIRELESS_CONF");
    const char *env_mode = getenv("CAPAGENT_WIRELESS_MODE");
    int explicit_file;

    if (env_conf && *env_conf) path = env_conf;
    snprintf(g_wl_path, sizeof(g_wl_path), "%s", path);
    explicit_file = (env_conf && *env_conf) ||
                    (c->wireless_conf &&
                     strcmp(c->wireless_conf, WL_CONF_DEFAULT) != 0);

    if (c->wireless_mode >= 0) {
        g_wl_legacy = c->wireless_mode ? 1 : 0;
        g_wl_ifaces = 0;
        printf("wl: ownership=%s (forced), config=%s\n", wl_mode_name(), path);
        fflush(stdout);
        return;
    }
    if (env_mode && *env_mode) {
        g_wl_legacy = !strcmp(env_mode, "legacy");
        g_wl_ifaces = 0;
        printf("wl: ownership=%s (env), config=%s\n", wl_mode_name(), path);
        fflush(stdout);
        return;
    }

    if (explicit_file) {
        int n = wl_count_iface(path);
        g_wl_ifaces = n < 0 ? 0 : n;
        g_wl_legacy = n > 0;
        printf("wl: ownership=%s (%s: %d wifi-iface, explicit file)\n",
               wl_mode_name(), path, g_wl_ifaces);
        fflush(stdout);
        return;
    }

    own_policy_refresh();
    wl_report_ubus(c);
}

/* Per-port authority.  With a table row the row decides; without one the
 * legacy session predicate does (lab/own mode boots). */
static int wl_port_managed(int port)
{
    if (own_has_entry(port))
        return own_managed_strict(port);
    return !g_wl_legacy;
}

/* ---- deterministic netdev identity -------------------------------- */

static int iface_mac(const char *name, uint8_t mac[6])
{
    return read_sysfs_mac(name, mac) == 0 ? 0 : -1;
}

static int iface_phy_index(const char *name)
{
    return read_sysfs_int(name, "phy80211/index");
}

/* The one predicate that keeps monitors (cm0/cm1, which carry the radio MAC)
   and AP_VLAN from being mistaken for the AP netdev of a VAP. */
static int iface_is_ap(int ifindex)
{
    int t = nl_get_iftype(ifindex);
    return t == NL80211_IFTYPE_AP || t == NL80211_IFTYPE_AP_VLAN;
}

/* Resolve a MAC to an AP netdev, deterministically.
 *
 * v0.33 bug: the old lookup returned the first /sys/class/net entry with a
 * matching MAC.  A MAC appears on more than one netdev in practice (the
 * radio MAC is also the address of the mgmt monitor VIF cm<N>, and VAP0 uses
 * the radio MAC), and readdir() order is arbitrary, so the same MAC could
 * resolve to cm1 on one session and phy1-ap0 on the next.  The 0xd00b reply
 * then advertised a monitor ifindex and vap_provision created a second
 * netdev for the same BSS.
 *
 * Rules, in order: must be a wireless netdev, must be an AP/AP_VLAN, must
 * belong to want_phy (when >= 0), prefer the conventional phy<N>-ap<M> name,
 * otherwise pick the lowest ifindex.  Never returns a monitor/STA netdev.
 */
static int ifindex_by_mac_ap(const uint8_t mac[6], int want_phy,
                             char *name, size_t n)
{
    DIR *d = opendir("/sys/class/net");
    struct dirent *de;
    int best = 0;
    char best_name[IF_NAMESIZE] = "";

    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        uint8_t m[6];
        int idx;

        if (de->d_name[0] == '.') continue;
        if (iface_mac(de->d_name, m) != 0 || memcmp(m, mac, 6) != 0) continue;
        if (iface_phy_index(de->d_name) < 0) continue;   /* not wireless */
        idx = read_sysfs_int(de->d_name, "ifindex");
        if (idx <= 0 || !iface_is_ap(idx)) continue;
        if (want_phy >= 0 && iface_phy_index(de->d_name) != real_phy(want_phy))
            continue;
        /* conventional names win; otherwise the lowest ifindex */
        if (want_phy >= 0 && strstr(de->d_name, "-ap")) {
            snprintf(best_name, sizeof(best_name), "%.*s",
                     (int)sizeof(best_name) - 1, de->d_name);
            best = idx;
            break;
        }
        if (!best || idx < best) {
            best = idx;
            snprintf(best_name, sizeof(best_name), "%.*s",
                     (int)sizeof(best_name) - 1, de->d_name);
        }
    }
    closedir(d);
    if (best > 0 && name && n) snprintf(name, n, "%s", best_name);
    return best;
}

/* ---- pure decisions (unit-tested by --selftest-policy) ------------ */

/* Start a hostapd instance for this BSS?
 * Legacy mode never does, even if the netdev exists and no pid file does.
 * (The pre-W33 code only checked the pid file, so a legacy interface with
 * no /var/run/vap-<if>.pid was treated as "free" and a second hostapd was
 * spawned on top of netifd's.) */
static int vap_should_start_bss(int legacy, int vap_auto, int ifindex,
                                int hostapd_running)
{
    if (ifindex <= 0) return 0;
    if (legacy) return 0;
    if (!vap_auto) return 0;
    if (hostapd_running) return 0;
    return 1;
}

/* The manager sends 0x500b with port vapid=0 for every VAP and identifies
 * the VAP by MAC.  Mapping that request port onto (phy<<8)|vapid would make
 * every VAP overwrite the same pmap slot, so only alias when they agree. */
static int vap_port_alias_ok(int req_vap, int vapid)
{
    return req_vap == vapid;
}

/* ---- self-test ---------------------------------------------------- */

static int wl_test_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(text, f);
    fclose(f);
    return 0;
}

static int wl_selftest(void)
{
    int fails = 0, checks = 0;
    char p[128];
    struct {
        const char *body;
        int expect;
        const char *what;
    } cases[] = {
        { "", 0, "empty file" },
        { "config wifi-device 'radio0'\n\toption channel '6'\n", 0,
          "device only" },
        { "config wifi-iface 'bss0'\n", 1, "one iface" },
        { "# config wifi-iface 'x'\nconfig wifi-device 'r'\n", 0,
          "commented iface" },
        { "config wifi-iface\n\toption ssid 'x'\n", 1, "unnamed iface" },
        { "  config   wifi-iface   'a'\r\n", 1, "indented + spaces + CRLF" },
        { "option foo 'config wifi-iface'\n", 0, "option value is not a section" },
        { "config wifi-ifacex 'a'\n", 0, "prefix must not match" },
    };
    char big[4096];
    size_t off = 0;

    snprintf(p, sizeof(p), "/tmp/capagent-wl-selftest-%ld.conf", (long)getpid());

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int got;
        checks++;
        if (wl_test_write(p, cases[i].body) != 0) {
            printf("policy-selftest: cannot write %s\n", p);
            fails++;
            continue;
        }
        got = wl_count_iface(p);
        if (got != cases[i].expect) {
            printf("policy-selftest: FAIL %s: got %d want %d\n", cases[i].what,
                   got, cases[i].expect);
            fails++;
        }
    }

    /* The section count for a full legacy config must be exact. */
    off = 0;
    for (int i = 0; i < 8; i++)
        off += (size_t)snprintf(big + off, sizeof(big) - off,
                                "config wifi-iface 'bss_%d'\n"
                                "\toption device 'radio%d'\n", i, i / 4);
    checks++;
    if (wl_test_write(p, big) != 0) {
        fails++;
    } else if (wl_count_iface(p) != 8) {
        printf("policy-selftest: FAIL 8-iface config: got %d\n",
               wl_count_iface(p));
        fails++;
    }
    unlink(p);

    /* Missing file means "we own it". */
    checks++;
    snprintf(p, sizeof(p), "/tmp/capagent-wl-selftest-missing-%ld.conf",
             (long)getpid());
    unlink(p);
    if (wl_count_iface(p) != -1) {
        printf("policy-selftest: FAIL missing file should be -1\n");
        fails++;
    }

    /* Decision table.                                              expect */
    struct { int legacy, auto_bss, ifindex, running, want; } d[] = {
        { 1, 1, 9, 1, 0 },   /* legacy + hostapd alive                    */
        { 1, 1, 9, 0, 0 },   /* legacy + no pid file: still never spawn    */
        { 1, 1, 0, 0, 0 },   /* legacy + no netdev                         */
        { 0, 1, 9, 1, 0 },   /* own + already running                      */
        { 0, 1, 9, 0, 1 },   /* own + netdev, no hostapd                   */
        { 0, 0, 9, 0, 0 },   /* own + --no-vap-auto                        */
        { 0, 1, 0, 0, 0 },   /* own + missing netdev                       */
    };
    for (size_t i = 0; i < sizeof(d) / sizeof(d[0]); i++) {
        int got;
        checks++;
        got = vap_should_start_bss(d[i].legacy, d[i].auto_bss, d[i].ifindex,
                                   d[i].running);
        if (got != d[i].want) {
            printf("policy-selftest: FAIL decision %zu: got %d want %d\n", i,
                   got, d[i].want);
            fails++;
        }
    }

    checks++;
    if (!vap_port_alias_ok(0, 0) || vap_port_alias_ok(0, 1) ||
        !vap_port_alias_ok(3, 3) || vap_port_alias_ok(3, 2)) {
        printf("policy-selftest: FAIL port alias rule\n");
        fails++;
    }

    /* The classifier used by run_once(), on the same fixtures. */
    struct cfg c;
    memset(&c, 0, sizeof(c));
    snprintf(p, sizeof(p), "/tmp/capagent-wl-selftest-cls-%ld.conf",
             (long)getpid());
    c.wireless_conf = p;
    c.wireless_mode = -1;
    checks++;
    if (wl_test_write(p, big) == 0) {
        wl_classify(&c);
        if (!wl_legacy() || g_wl_ifaces != 8) {
            printf("policy-selftest: FAIL classify(8 iface) legacy=%d n=%d\n",
                   wl_legacy(), g_wl_ifaces);
            fails++;
        }
    } else {
        fails++;
    }
    checks++;
    if (wl_test_write(p, "config wifi-device 'radio0'\n") == 0) {
        wl_classify(&c);
        if (wl_legacy() || !wl_own()) {
            printf("policy-selftest: FAIL classify(device only) legacy=%d\n",
                   wl_legacy());
            fails++;
        }
    } else {
        fails++;
    }
    unlink(p);

    /* A zero MAC can never resolve to a netdev. */
    checks++;
    {
        uint8_t z[6] = {0};
        if (ifindex_by_mac_ap(z, -1, NULL, 0) != 0) {
            printf("policy-selftest: FAIL zero MAC resolved\n");
            fails++;
        }
    }

    /* W34: the ubus payload is the production ownership source. */
    {
        static const char *empty = "{}";
        static const char *legacy =
            "{\"radio0\":{\"up\":true,\"pending\":false,\"interfaces\":["
            "{\"section\":\"s0\",\"ifname\":\"phy0-ap0\"},"
            "{\"section\":\"s1\",\"ifname\":\"phy0-ap1\"},"
            "{\"section\":\"v\",\"ifname\":\"phy0-ap1.10\"}]}}";
        static const char *busy =
            "{\"radio0\":{\"pending\":true,\"interfaces\":["
            "{\"section\":\"s0\",\"ifname\":\"phy0-ap0\"}]}}";
        int pending = 0, n;
        char first[ND_NAME_MAX];

        checks++;
        if (wl_status_ifaces(empty, &pending, first, sizeof(first)) != 0) {
            printf("policy-selftest: FAIL ubus empty count\n");
            fails++;
        }
        checks++;
        n = wl_status_ifaces(legacy, &pending, first, sizeof(first));
        if (n != 3 || pending) {
            printf("policy-selftest: FAIL ubus legacy count=%d pending=%d\n",
                   n, pending);
            fails++;
        }
        checks++;
        if (!strcmp(first, "phy0-ap0")) {
            /* expected */
        } else {
            printf("policy-selftest: FAIL ubus first ifname %s\n", first);
            fails++;
        }
        checks++;
        n = wl_status_ifaces(busy, &pending, first, sizeof(first));
        if (n != 1 || !pending) {
            printf("policy-selftest: FAIL ubus busy count=%d pending=%d\n",
                   n, pending);
            fails++;
        }
        checks++;
        if (wl_status_ifaces("Command failed: Not found", NULL, NULL, 0) != -1) {
            printf("policy-selftest: FAIL ubus error text accepted\n");
            fails++;
        }
        checks++;
        if (wl_status_ifaces(legacy, NULL, NULL, 0) != 3) {
            printf("policy-selftest: FAIL ubus AP_VLAN not counted\n");
            fails++;
        }
    }

    printf("policy-selftest: %d checks, %d failure(s)\n", checks, fails);
    return fails ? 1 : 0;
}
