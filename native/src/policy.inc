/* policy.inc — W33/W34/W51: wireless ownership policy + deterministic identity
 *
 * Part of capagent.c (single translation unit; included after nl80211.inc).
 *
 * The single source of truth is the ownership table in src/ownership.inc.
 * Its netifd rows are populated from `ubus call network.wireless status`
 * (src/netifd_status.inc) when that object exists.  W51 adds an explicit
 * source chain for images that do not export it (vendor WiFi stacks):
 *
 *   ubus network.wireless  ->  uci show wireless  ->  /etc/config/wireless
 *                          ->  unknown: refuse to adopt (read-only)
 *
 * Whenever ubus is unusable, the session is hard read-only (`g_wl_readonly`):
 * nothing is created, adopted, stolen, started or deleted (an already
 * journaled hostapd is only stopped when netifd claims its name).  An MLD
 * companion netdev (mld-*) and every netdev named by the netifd/vendor status
 * are never adoptable.  `--wireless-owner own` is the explicit opt-in out of
 * the fail-safe; `legacy` forces the fully read-only contract.
 *
 * Per netdev:
 *   NETIFD    the name appears in network.wireless status.  capagent never
 *             creates, starts, deletes or reconfigures it.
 *   CAPAGENT  the journal says we created/adopted it.  Full lifecycle.
 *   FOREIGN   exists, neither netifd nor ours.  Never touched; the manager
 *             VAP is placed on an alternate name.
 *   PENDING   manager asked while the netifd probe was unusable.  Retried.
 *
 * `wl_legacy()` is the coarse session predicate: netifd/vendor wireless owns
 * at least one BSS (so UCI apply and other global config writes stay off).
 * All per-netdev effects use wl_port_managed()/own_claim(), which is what
 * makes a mixed legacy+manager setup safe.  An explicitly supplied
 * --wireless-config FILE is still counted for diagnostics/selftests.
 */

#include "netifd_status.inc"

#define WL_CONF_DEFAULT "/etc/config/wireless"

/* W51: where the ownership decision came from.  ubus is authoritative when it
 * answers; on vendor images that do not export network.wireless the answer is
 * reconstructed from the UCI database, then from the config file.  If none of
 * them can be read the answer is "unknown" and the session is read-only. */
#define WL_SRC_NONE   0
#define WL_SRC_UBUS   1
#define WL_SRC_UCI    2
#define WL_SRC_FILE   3

static int g_wl_legacy;             /* 1 = legacy UCI owns the BSSes */
static int g_wl_ifaces;             /* number of wifi-iface sections  */
static int g_wl_src = WL_SRC_NONE;  /* W51 ownership source          */
static int g_wl_readonly = 1;       /* W51 fail-safe: no create/steal */
static int g_wl_vendor;            /* W51 source is a vendor stack   */
static int g_wl_explicit;           /* W51 offline --wireless-config  */
static int g_wl_ubus = OWN_PROBE_UNKNOWN;
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

static const char *wl_src_name(int src)
{
    switch (src) {
    case WL_SRC_UBUS: return "ubus";
    case WL_SRC_UCI:  return "uci";
    case WL_SRC_FILE: return "file";
    default:          return "none";
    }
}

static const char *wl_ubus_name(void)
{
    switch (g_wl_ubus) {
    case OWN_PROBE_OK:   return "ok";
    case OWN_PROBE_BUSY: return "busy";
    default:             return "unknown";
    }
}

/* Read-only in legacy mode.  Every netdev / hostapd / UCI side effect in
   this agent must be behind this predicate. */
static int wl_legacy(void) { return g_wl_legacy; }
static int wl_own(void)    { return !g_wl_legacy; }

/* W51: the hard read-only contract.  True when the ownership source could not
 * be proven (vendor image without network.wireless, unreadable config) or the
 * operator forced legacy.  Nothing may be created, adopted, stolen, started
 * or deleted while this is set; the only stop is an already-journaled
 * hostapd whose name netifd has just claimed (conflict resolution). */
static int wl_readonly(void) { return g_wl_readonly; }

/* Count "wifi-iface" sections through uci, which normalises includes, deltas
 * and anonymous sections.  Returns -1 when uci is absent or the wireless
 * config does not exist, so the caller can fall back to the file. */
static int wl_uci_count(void)
{
    const char *uci = NULL;
    char cmd[96], line[512];
    FILE *p;
    int n = 0, rc;

    if (access("/sbin/uci", X_OK) == 0) uci = "/sbin/uci";
    else if (access("/usr/bin/uci", X_OK) == 0) uci = "/usr/bin/uci";
    else if (access("/bin/uci", X_OK) == 0) uci = "/bin/uci";
    if (!uci) return -1;

    snprintf(cmd, sizeof(cmd), "%s -q show wireless 2>/dev/null", uci);
    p = popen(cmd, "r");
    if (!p) return -1;
    while (fgets(line, sizeof(line), p)) {
        char *eq = strchr(line, '='), *v;
        if (!eq) continue;
        v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        if (strncmp(v, "wifi-iface", 10) != 0) continue;
        if (v[10] && v[10] != ' ' && v[10] != '\t' &&
            v[10] != '\r' && v[10] != '\n')
            continue;
        n++;
    }
    rc = pclose(p);
    if (rc != 0 && n == 0) return -1;       /* "Entry not found" / no uci  */
    return n;
}

/* W51: the owned-name guards.  An MLD companion netdev (mld-<parent>, the
 * Deco BE65 exports mld-wifi0 with address 00:00:00:00:00:00) is multi-link
 * bookkeeping, never a BSS: no MAC, no management frame, no hostapd. */
static int wl_netdev_ignored(const char *name)
{
    if (!name) return 1;
    return !strncmp(name, "mld-", 4);
}

/* A MAC that cannot identify a BSS: all-zero, multicast or broadcast.  The
 * zero address is what made a zero MAC resolve to mld-wifi0. */
static int wl_mac_usable(const uint8_t mac[6])
{
    if (!(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]))
        return 0;
    if (mac[0] & 0x01)                 /* multicast (includes broadcast) */
        return 0;
    return 1;
}

/* W51: a name that some other wireless stack may own.  netifd's status is
 * exact; on a vendor image every pre-existing AP netdev is vendor-owned and
 * only an MLD/proven-ours exception applies. */
static int wl_name_protected(const char *name)
{
    if (wl_netdev_ignored(name)) return 1;
    return own_nd_has(name, NULL, 0);
}

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

/* -1 auto, 0 own, 1 legacy.  --wireless-owner wins over the env override. */
static int wl_forced_mode(const struct cfg *c)
{
    const char *env_mode = getenv("CAPAGENT_WIRELESS_MODE");

    if (c->wireless_mode >= 0)
        return c->wireless_mode ? 1 : 0;
    if (env_mode && *env_mode)
        return !strcmp(env_mode, "legacy");
    return -1;
}

/* W51: resolve the ownership source.  Chain:
 *   1. ubus network.wireless status      (netifd, authoritative)
 *   2. uci -q show wireless              (vendor/non-netifd stacks)
 *   3. /etc/config/wireless              (no uci / unreadable database)
 *   4. none                              -> refuse to adopt (read-only)
 * Whenever ubus is unusable the result is read-only: on an image where the
 * wireless stack is not netifd we cannot enumerate the protected netdevs,
 * so nothing may be adopted or created.  `--wireless-owner own` is the only
 * explicit opt-in out of that fail-safe. */
static void wl_detect_source(const char *path, int explicit_file)
{
    int n;

    g_wl_explicit = explicit_file;

    if (explicit_file) {
        /* Offline diagnostics/selftests: the named file is the authority and
         * no live probe runs, so the result never depends on the host. */
        g_wl_ubus = OWN_PROBE_UNKNOWN;
        n = wl_count_iface(path);
        g_wl_ifaces = n < 0 ? 0 : n;
        g_wl_legacy = n > 0;
        g_wl_src = n < 0 ? WL_SRC_NONE : WL_SRC_FILE;
        g_wl_readonly = (n != 0);          /* >0 legacy, <0 unreadable */
        g_wl_vendor = 0;
        return;
    }

    g_wl_ubus = own_probe(1);

    if (g_wl_ubus == OWN_PROBE_OK || g_wl_ubus == OWN_PROBE_BUSY) {
        g_wl_src = WL_SRC_UBUS;
        g_wl_ifaces = own_netifd_count();
        g_wl_legacy = g_wl_ifaces > 0;
        g_wl_readonly = 0;
        g_wl_vendor = 0;
        return;
    }

    n = wl_uci_count();
    if (n >= 0) {
        g_wl_src = WL_SRC_UCI;
    } else {
        n = wl_count_iface(path);
        g_wl_src = n >= 0 ? WL_SRC_FILE : WL_SRC_NONE;
    }
    if (n < 0) n = 0;
    g_wl_ifaces = n;
    g_wl_legacy = 1;
    g_wl_readonly = 1;
    g_wl_vendor = 1;
}

/* One startup line, always: the effective --wireless-owner result plus how it
 * was reached.  Every session prints it before connecting. */
static void wl_print_decision(const char *mode, int forced)
{
    printf("wl: ownership=%s mode=%s source=%s ifaces=%d ubus=%s action=%s\n",
           wl_mode_name(), mode, wl_src_name(g_wl_src), g_wl_ifaces,
           wl_ubus_name(), g_wl_readonly ? "read-only" : "may-adopt");
    if (g_wl_explicit) {
        printf("wl: explicit config %s, offline decision (no live probe)\n",
               g_wl_path);
    } else if (!forced && g_wl_readonly) {
        if (g_wl_src == WL_SRC_NONE)
            printf("wl: network.wireless, uci and %s are all unusable; "
                   "refusing to adopt any netdev (read-only)\n", g_wl_path);
        else
            printf("wl: network.wireless=%s; %s reports %d wifi-iface "
                   "section(s) -> %s stack, refusing to adopt any netdev "
                   "(read-only)\n", wl_ubus_name(), wl_src_name(g_wl_src),
                   g_wl_ifaces, g_wl_vendor ? "vendor" : "wireless");
    }
    if (!g_wl_explicit && g_wl_readonly) {
        printf("wl: MLD (mld-*) and any netifd/vendor netdev are never "
               "adopted, stolen, deleted or restarted\n");
    } else if (!g_wl_explicit && g_wl_ifaces > 0) {
        printf("wl: %s reports %d wifi-iface section(s); capagent only manages "
               "names outside that set\n",
               g_wl_src == WL_SRC_UBUS ? "netifd" : wl_src_name(g_wl_src),
               g_wl_ifaces);
    }
    fflush(stdout);
}

/* Print the live decision without reconciling or writing anything
 * (--check-wireless is strictly read-only). */
static void wl_report_ubus(const struct cfg *c)
{
    const char *path = c->wireless_conf ? c->wireless_conf : WL_CONF_DEFAULT;
    const char *env_conf = getenv("CAPAGENT_WIRELESS_CONF");
    int explicit_file, forced;

    if (env_conf && *env_conf) path = env_conf;
    snprintf(g_wl_path, sizeof(g_wl_path), "%s", path);
    explicit_file = (env_conf && *env_conf) ||
                    (c->wireless_conf &&
                     strcmp(c->wireless_conf, WL_CONF_DEFAULT) != 0);
    forced = wl_forced_mode(c);
    wl_detect_source(path, explicit_file);
    if (forced == 1) {
        g_wl_legacy = 1;
        g_wl_readonly = 1;
    } else if (forced == 0) {
        g_wl_legacy = 0;
        g_wl_readonly = 0;
    }
    printf("wl: journal: %d capagent row(s)\n", own_managed_count());
    wl_print_decision(forced >= 0 ? (c->wireless_mode >= 0 ? "forced" : "env")
                                  : "auto", forced);
}

/* Every session starts here.  The ownership source chain decides legacy vs
 * own and, more importantly, whether anything may be touched at all. */
static void wl_classify(const struct cfg *c)
{
    const char *path = c->wireless_conf ? c->wireless_conf : WL_CONF_DEFAULT;
    const char *env_conf = getenv("CAPAGENT_WIRELESS_CONF");
    int explicit_file, forced;

    if (env_conf && *env_conf) path = env_conf;
    snprintf(g_wl_path, sizeof(g_wl_path), "%s", path);
    explicit_file = (env_conf && *env_conf) ||
                    (c->wireless_conf &&
                     strcmp(c->wireless_conf, WL_CONF_DEFAULT) != 0);

    forced = wl_forced_mode(c);
    wl_detect_source(path, explicit_file);
    if (forced == 1) {
        g_wl_legacy = 1;
        g_wl_readonly = 1;
    } else if (forced == 0) {
        g_wl_legacy = 0;
        g_wl_readonly = 0;
    }
    wl_print_decision(forced >= 0 ? (c->wireless_mode >= 0 ? "forced" : "env")
                                  : "auto", forced);
    if (forced < 0 &&
        (g_wl_ubus == OWN_PROBE_OK || g_wl_ubus == OWN_PROBE_BUSY))
        own_policy_refresh();
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
 *
 * W51: an unusable MAC (all-zero, multicast, broadcast) never resolves, and
 * an MLD companion netdev (mld-*) is skipped.  The Deco BE65 exports
 * mld-wifi0 with address 00:00:00:00:00:00 and iftype AP, which used to be
 * returned for a zero MAC.
 */
static int ifindex_by_mac_ap(const uint8_t mac[6], int want_phy,
                             char *name, size_t n)
{
    DIR *d;
    struct dirent *de;
    int best = 0;
    char best_name[IF_NAMESIZE] = "";

    if (!mac || !wl_mac_usable(mac)) return 0;
    d = opendir("/sys/class/net");
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        uint8_t m[6];
        int idx;

        if (de->d_name[0] == '.') continue;
        /* W51: mld-* (and anything else non-BSS) is never a VAP netdev. */
        if (wl_netdev_ignored(de->d_name)) continue;
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

    /* W51 regression: an unusable MAC (zero/multicast/broadcast) must never
     * resolve, and an MLD companion netdev (mld-*) must never be returned as
     * a VAP netdev.  On the Deco BE65, mld-wifi0 has address 00:00:00:00:00:00
     * and iftype AP, so a zero MAC used to resolve to it.  This is still one
     * check so the historical 27-check total is unchanged. */
    checks++;
    {
        uint8_t z[6] = {0};
        uint8_t mc[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01};
        uint8_t bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint8_t uc[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
        int bad = 0, mld = 0;
        DIR *d;

        if (ifindex_by_mac_ap(z, -1, NULL, 0) != 0) {
            printf("policy-selftest: FAIL zero MAC resolved\n");
            bad = 1;
        }
        if (ifindex_by_mac_ap(mc, -1, NULL, 0) != 0) {
            printf("policy-selftest: FAIL multicast MAC resolved\n");
            bad = 1;
        }
        if (ifindex_by_mac_ap(bc, -1, NULL, 0) != 0) {
            printf("policy-selftest: FAIL broadcast MAC resolved\n");
            bad = 1;
        }
        if (!wl_mac_usable(uc) || wl_mac_usable(z) || wl_mac_usable(mc) ||
            wl_mac_usable(bc)) {
            printf("policy-selftest: FAIL MAC usability predicate\n");
            bad = 1;
        }
        if (!wl_netdev_ignored("mld-wifi0") || wl_netdev_ignored("wifi0") ||
            !wl_netdev_ignored("mld-phy0")) {
            printf("policy-selftest: FAIL MLD name predicate\n");
            bad = 1;
        }
        /* Live regression: if this system has an mld-* netdev, its own MAC
         * must not resolve back to it. */
        d = opendir("/sys/class/net");
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                uint8_t m[6];
                int self, got;
                char nm[64] = "";
                if (!wl_netdev_ignored(de->d_name)) continue;
                if (de->d_name[0] == '.') continue;
                mld++;
                if (read_sysfs_mac(de->d_name, m) != 0) continue;
                self = read_sysfs_int(de->d_name, "ifindex");
                got = ifindex_by_mac_ap(m, -1, nm, sizeof(nm));
                if (got > 0 && (got == self || !strcmp(nm, de->d_name))) {
                    printf("policy-selftest: FAIL MLD %s resolved by MAC\n",
                           de->d_name);
                    bad = 1;
                }
            }
            closedir(d);
        }
        if (mld)
            printf("policy-selftest: MLD netdevs present=%d, none resolved\n",
                   mld);
        if (bad)
            fails++;
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
