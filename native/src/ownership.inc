/* ownership.inc — W34: one ownership model for every wireless netdev.
 *
 * Part of capagent.c (single translation unit; included after vap.inc).
 *
 * Problem
 * -------
 * The old rule was "if /etc/config/wireless contains a wifi-iface, netifd owns
 * the wireless interfaces".  That is intent, not reality: netifd can own
 * auto-generated radios, a config can have one section and no matching BSS, and
 * stale /tmp/vap-*.conf files survived reboots.  Acting on it either skipped
 * the manager's VAPs or spawned a second hostapd on a netifd BSS.
 *
 * Model
 * -----
 * `ubus call network.wireless status` is the only authority for netifd.  For
 * every netdev we can be in exactly one state (see g_own[] and REPORT.md):
 *
 *   NONE     no netdev, not reserved            -> may be created
 *   NETIFD   named by network.wireless status   -> never create/start/delete
 *   CAPAGENT OURS: created, or adopted because  -> full lifecycle
 *            our pid file points at live hostapd
 *   FOREIGN  exists, neither netifd nor ours    -> never touch
 *   PENDING  manager asked while the netifd      -> retry on next reconcile
 *            probe was unusable
 *
 * The table is the single source of truth for port -> ifname/ifindex/pid/owner
 * at runtime.  It is mirrored to a small journal (default
 * /var/run/capagent-vaps.state) so a capagent restart, a netifd reload or a
 * wifi reload can be repaired without orphaning a netdev or starting a second
 * hostapd.  The journal holds no key material: the manager is the RSN
 * authenticator and the CAP never receives a PSK.
 *
 * Safety rules
 * ------------
 *  - probe UNKNOWN (ubus failed / netifd restarting) or BUSY (pending=true):
 *    never delete, never steal a name, and only adopt netdevs already proven
 *    ours by the journal or by a live hostapd pid file;
 *  - netifd always wins a name collision.  The manager's VAP is placed on an
 *    alternate name (cap<phy>-<vapid>) instead of fighting it;
 *  - a netdev is deleted only when the manager destroys a CAPAGENT entry and
 *    netifd does not list the name.
 */

#include "netifd_status.inc"

#ifndef OWN_RUN_DIR
#define OWN_RUN_DIR        "/var/run"
#endif
#ifndef OWN_TMP_DIR
#define OWN_TMP_DIR        "/tmp"
#endif
#ifndef OWN_PROBE_MS
#define OWN_PROBE_MS       1500
#endif

#define OWN_MAX            128
#define OWN_NAME_MAX       32
#define OWN_SECTION_MAX    32
#define OWN_START_MAX      512
#define OWN_DEFAULT_STATE  OWN_RUN_DIR "/capagent-vaps.state"
#define OWN_FALLBACK_STATE OWN_TMP_DIR "/capagent-vaps.state"

#define OWN_PROBE_UNKNOWN  0
#define OWN_PROBE_OK       1
#define OWN_PROBE_BUSY     2

#define OWN_NONE      0
#define OWN_NETIFD    1
#define OWN_CAPAGENT  2
#define OWN_FOREIGN   3
#define OWN_PENDING   4

struct own_entry {
    int used;
    int owner;
    uint16_t port;              /* manager port; 0xffff = netifd-only row */
    int ifindex;
    int pid;                    /* hostapd pid when owner == CAPAGENT */
    int created;                /* netdev was created by capagent */
    int active;                 /* manager sent 0x6016 for this port */
    int fail_count;             /* hostapd start backoff */
    int start_given_up;         /* bounded retries exhausted, reported */
    int starting;               /* a start is in flight (serialises callers) */
    uint64_t starting_at;
    uint64_t retry_at;
    uint8_t bssid[6];
    uint16_t vlan;
    uint32_t freq;
    char ifname[OWN_NAME_MAX];
    char section[OWN_SECTION_MAX];
    uint16_t start_len;         /* last 0x6016 body, for auto-heal */
    uint8_t start[OWN_START_MAX];
};

static struct own_entry g_own[OWN_MAX];
static const char *g_own_path;
static int g_own_dirty;
static int g_own_ubus_missing = -1;
static int g_own_probe_state = OWN_PROBE_UNKNOWN;
static uint64_t g_own_probe_at;
static struct nd_status g_own_nd;

/* ---- small helpers ---------------------------------------------------- */

static uint64_t own_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int own_name_ok(const char *s)
{
    size_t n;
    if (!s) return 0;
    n = strlen(s);
    if (n == 0 || n >= OWN_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static const char *own_owner_name(int owner)
{
    switch (owner) {
    case OWN_NETIFD:   return "netifd";
    case OWN_CAPAGENT: return "capagent";
    case OWN_FOREIGN:  return "foreign";
    case OWN_PENDING:  return "pending";
    default:           return "none";
    }
}

static int own_owner_parse(const char *s)
{
    if (!strcmp(s, "netifd")) return OWN_NETIFD;
    if (!strcmp(s, "capagent")) return OWN_CAPAGENT;
    if (!strcmp(s, "foreign")) return OWN_FOREIGN;
    if (!strcmp(s, "pending")) return OWN_PENDING;
    return OWN_NONE;
}

/* --wireless-owner legacy / CAPAGENT_WIRELESS_MODE=legacy: no netdev is ever
 * created.  In auto mode ownership is per name (see own_claim). */
static int own_forced_readonly(const struct cfg *c)
{
    const char *env = getenv("CAPAGENT_WIRELESS_MODE");
    if (c && c->wireless_mode == 1)
        return 1;
    return env && *env && !strcmp(env, "legacy");
}

static struct own_entry *own_by_port(uint16_t port)
{
    if (port == 0xffff)
        return NULL;
    for (int i = 0; i < OWN_MAX; i++)
        if (g_own[i].used && g_own[i].port == port)
            return &g_own[i];
    return NULL;
}

static struct own_entry *own_by_name(const char *ifname)
{
    if (!ifname || !*ifname)
        return NULL;
    for (int i = 0; i < OWN_MAX; i++)
        if (g_own[i].used && !strcmp(g_own[i].ifname, ifname))
            return &g_own[i];
    return NULL;
}

/* Find by name first (a netifd row may already exist), then by port, then a
 * free slot.  Never clears an existing row: claim/restore keeps its journal
 * data (start body, VLAN, BSSID) across a name change. */
static struct own_entry *own_alloc(uint16_t port, const char *ifname)
{
    struct own_entry *e = own_by_name(ifname);
    int slot = -1;

    if (!e && port != 0xffff)
        e = own_by_port(port);
    for (int i = 0; i < OWN_MAX && !e; i++) {
        if (!g_own[i].used) { slot = i; break; }
    }
    if (!e) {
        if (slot < 0)
            return NULL;
        e = &g_own[slot];
        memset(e, 0, sizeof(*e));
        e->used = 1;
        e->port = port;
        if (ifname && own_name_ok(ifname))
            snprintf(e->ifname, sizeof(e->ifname), "%s", ifname);
        g_own_dirty = 1;
    } else if (port != 0xffff && e->port != port) {
        e->port = port;                    /* netifd row adopted by a port */
        g_own_dirty = 1;
    }
    return e;
}

static void own_set_name(struct own_entry *e, const char *ifname)
{
    if (!e || !own_name_ok(ifname))
        return;
    if (strcmp(e->ifname, ifname)) {
        snprintf(e->ifname, sizeof(e->ifname), "%s", ifname);
        g_own_dirty = 1;
    }
}

static void own_free(struct own_entry *e)
{
    if (!e || !e->used) return;
    memset(e, 0, sizeof(*e));
    g_own_dirty = 1;
}

/* ---- netifd probe ----------------------------------------------------- */

static int own_nd_has(const char *ifname, char *section, size_t section_len)
{
    return nd_find(&g_own_nd, ifname, section, section_len);
}

static int own_probe(int force)
{
    uint64_t now = own_now_ms();
    const uint64_t interval = (uint64_t)OWN_PROBE_MS;
    const char *ub = NULL;
    char cmd[160];
    FILE *p;
    char *buf;
    size_t n = 0;
    int rc, state;

    if (!force && g_own_probe_at && now - g_own_probe_at < interval)
        return g_own_probe_state;
    g_own_probe_at = now;

    /* Test/diagnostic override: parse a saved ubus payload instead of running
     * ubus.  Used by tests/test_ownership.c; absent on production devices. */
    {
        const char *jf = getenv("CAPAGENT_NETIFD_STATUS");
        if (jf) {
            FILE *jfp = fopen(jf, "r");
            char *jbuf = malloc(ND_JSON_MAX);
            if (!jbuf) {
                if (jfp) fclose(jfp);
                g_own_probe_state = OWN_PROBE_UNKNOWN;
                return g_own_probe_state;
            }
            size_t jn = 0;
            if (jfp) {
                jn = fread(jbuf, 1, ND_JSON_MAX - 1, jfp);
                fclose(jfp);
            }
            jbuf[jn] = 0;
            if (!jfp || !strchr(jbuf, '{')) {
                state = OWN_PROBE_UNKNOWN;
            } else {
                struct nd_status st;
                if (nd_parse(jbuf, &st) == 0) {
                    g_own_nd = st;
                    state = st.pending ? OWN_PROBE_BUSY : OWN_PROBE_OK;
                } else {
                    state = OWN_PROBE_UNKNOWN;
                }
            }
            free(jbuf);
            g_own_probe_state = state;
            return state;
        }
    }

    if (g_own_ubus_missing < 0) {
        if (access("/bin/ubus", X_OK) == 0)
            ub = "/bin/ubus";
        else if (access("/usr/bin/ubus", X_OK) == 0)
            ub = "/usr/bin/ubus";
        g_own_ubus_missing = (ub == NULL);
        if (g_own_ubus_missing) {
            printf("own: ubus not found; netifd ownership unavailable\n");
            fflush(stdout);
        }
    }
    if (g_own_ubus_missing) {
        memset(&g_own_nd, 0, sizeof(g_own_nd));
        g_own_nd.ok = 1;
        g_own_probe_state = OWN_PROBE_OK;
        return g_own_probe_state;
    }

    snprintf(cmd, sizeof(cmd), "%s -t 1 call network.wireless status "
             "2>/dev/null",
             access("/bin/ubus", X_OK) == 0 ? "/bin/ubus" : "/usr/bin/ubus");
    p = popen(cmd, "r");
    if (!p) {
        g_own_probe_state = OWN_PROBE_UNKNOWN;
        return g_own_probe_state;
    }
    buf = malloc(ND_JSON_MAX);
    if (!buf) {
        pclose(p);
        g_own_probe_state = OWN_PROBE_UNKNOWN;
        return g_own_probe_state;
    }
    while (n + 4096 < ND_JSON_MAX) {
        size_t r = fread(buf + n, 1, 4096, p);
        if (!r) break;
        n += r;
    }
    buf[n] = 0;
    rc = pclose(p);

    if (rc != 0 || !strchr(buf, '{')) {
        /* Command failed or netifd is restarting.  Keep the last known set:
         * it is a safe over-approximation (we may refuse a name that was
         * just released, never steal one that is still netifd's). */
        state = OWN_PROBE_UNKNOWN;
    } else {
        struct nd_status st;
        if (nd_parse(buf, &st) == 0) {
            g_own_nd = st;
            state = st.pending ? OWN_PROBE_BUSY : OWN_PROBE_OK;
        } else {
            state = OWN_PROBE_UNKNOWN;
        }
    }
    free(buf);

    if (state != g_own_probe_state) {
        printf("own: netifd status -> %s (%d ifnames%s)\n",
               state == OWN_PROBE_OK ? "ok" :
               state == OWN_PROBE_BUSY ? "busy" : "unknown",
               g_own_nd.n, state == OWN_PROBE_BUSY ? ", pending" : "");
        fflush(stdout);
    }
    g_own_probe_state = state;
    return state;
}

/* ---- hostapd process identity ---------------------------------------- */

static int own_pid_alive(int pid)
{
    if (pid <= 0) return 0;
    if (kill((pid_t)pid, 0) == 0) return 1;
    return errno == EPERM;
}

#ifndef OWN_TEST_PID_OK
static int own_pid_is_hostapd(int pid)
{
    char path[64], b[96];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgets(b, sizeof(b), f))
            b[strcspn(b, "\r\n")] = 0;
        else
            b[0] = 0;
        fclose(f);
        if (!strncmp(b, "hostapd", 7) || !strncmp(b, "wpad", 4))
            return 1;
    }
    /* -B rewrites the proctitle; fall back to argv[0] when available. */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = fopen(path, "r");
    if (f) {
        size_t r = fread(b, 1, sizeof(b) - 1, f);
        fclose(f);
        b[r] = 0;
        if (!strncmp(b, "hostapd", 7) || strstr(b, "/hostapd"))
            return 1;
    }
    return 0;
}

/* Unit-test seam: the host test has no real hostapd process. */
#define own_pid_ok(pid) own_pid_is_hostapd(pid)
#else
#define own_pid_ok(pid) (1)
#endif

/* A pid file is ours only when it names the per-ifname path we pass to
 * hostapd -P and the process really is a hostapd.  This is a secondary
 * signal for journal loss, never the primary ownership rule. */
static int own_hostapd_pid(const char *ifname)
{
    char pidf[96];
    long pid = 0;
    FILE *f;

    if (!own_name_ok(ifname))
        return 0;
    snprintf(pidf, sizeof(pidf), OWN_RUN_DIR "/vap-%s.pid", ifname);
    f = fopen(pidf, "r");
    if (!f) return 0;
    if (fscanf(f, "%ld", &pid) != 1)
        pid = 0;
    fclose(f);
    if (pid <= 0)
        return 0;
    if (!own_pid_alive((int)pid)) {
        unlink(pidf);
        return 0;
    }
    if (!own_pid_ok((int)pid))
        return 0;
    return (int)pid;
}

static void own_stop_pid(int pid)
{
    if (!own_pid_alive(pid))
        return;
    kill((pid_t)pid, SIGTERM);
    for (int i = 0; i < 20; i++) {
        if (!own_pid_alive(pid))
            return;
        usleep(50000);
    }
    kill((pid_t)pid, SIGKILL);
}

static void own_files_remove(const char *ifname)
{
    char p[128];
    if (!own_name_ok(ifname))
        return;
    snprintf(p, sizeof(p), OWN_TMP_DIR "/vap-%s.conf", ifname);
    unlink(p);
    snprintf(p, sizeof(p), OWN_RUN_DIR "/vap-%s.pid", ifname);
    unlink(p);
}

/* ---- journal ---------------------------------------------------------- */

static void own_save(void)
{
    char tmp[192];
    FILE *f;

    if (!g_own_dirty || !g_own_path)
        return;
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_own_path);
    f = fopen(tmp, "w");
    if (!f) {
        g_own_dirty = 0;
        return;
    }
    fprintf(f, "# capagent ownership v1: port ifname ifindex pid owner "
               "created active bssid vlan freq section start\n");
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->ifname[0])
            continue;
        fprintf(f, "port=%04x ifname=%s ifindex=%d owner=%s pid=%d "
                   "created=%d active=%d bssid=%02x:%02x:%02x:%02x:%02x:%02x "
                   "vlan=%u freq=%u section=%s start=",
                e->port, e->ifname, e->ifindex, own_owner_name(e->owner),
                e->pid, e->created, e->active,
                e->bssid[0], e->bssid[1], e->bssid[2],
                e->bssid[3], e->bssid[4], e->bssid[5],
                e->vlan, e->freq, e->section[0] ? e->section : "-");
        if (e->start_len)
            for (uint16_t k = 0; k < e->start_len; k++)
                fprintf(f, "%02x", e->start[k]);
        else
            fputc('-', f);
        fputc('\n', f);
    }
    fclose(f);
    if (rename(tmp, g_own_path) != 0) {
        unlink(tmp);
        fprintf(stderr, "own: cannot update %s: %s\n",
                g_own_path, strerror(errno));
    }
    g_own_dirty = 0;
}

static void own_load(void)
{
    char line[2048];
    FILE *f;

    if (!g_own_path || !(f = fopen(g_own_path, "r")))
        return;
    while (fgets(line, sizeof(line), f)) {
        struct own_entry tmp;
        char *tok, *save = NULL;
        int have_name = 0;

        if (line[0] == '#' || line[0] == '\n')
            continue;
        memset(&tmp, 0, sizeof(tmp));
        tmp.port = 0xffff;
        tmp.owner = OWN_NONE;
        for (tok = strtok_r(line, " \t\r\n", &save); tok;
             tok = strtok_r(NULL, " \t\r\n", &save)) {
            char *eq = strchr(tok, '=');
            const char *key, *val;
            if (!eq) continue;
            *eq = 0;
            key = tok;
            val = eq + 1;
            if (!strcmp(key, "port")) {
                unsigned p = 0;
                if (sscanf(val, "%x", &p) == 1) tmp.port = (uint16_t)p;
            } else if (!strcmp(key, "ifname")) {
                if (own_name_ok(val)) {
                    snprintf(tmp.ifname, sizeof(tmp.ifname), "%s", val);
                    have_name = 1;
                }
            } else if (!strcmp(key, "ifindex")) {
                tmp.ifindex = atoi(val);
            } else if (!strcmp(key, "owner")) {
                tmp.owner = own_owner_parse(val);
            } else if (!strcmp(key, "pid")) {
                tmp.pid = atoi(val);
            } else if (!strcmp(key, "created")) {
                tmp.created = atoi(val) ? 1 : 0;
            } else if (!strcmp(key, "active")) {
                tmp.active = atoi(val) ? 1 : 0;
            } else if (!strcmp(key, "vlan")) {
                tmp.vlan = (uint16_t)atoi(val);
            } else if (!strcmp(key, "freq")) {
                tmp.freq = (uint32_t)strtoul(val, NULL, 10);
            } else if (!strcmp(key, "section")) {
                if (own_name_ok(val))
                    snprintf(tmp.section, sizeof(tmp.section), "%s", val);
            } else if (!strcmp(key, "bssid")) {
                unsigned m[6];
                if (sscanf(val, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2],
                           &m[3], &m[4], &m[5]) == 6)
                    for (int k = 0; k < 6; k++)
                        tmp.bssid[k] = (uint8_t)m[k];
            } else if (!strcmp(key, "start")) {
                if (strcmp(val, "-") != 0)
                    tmp.start_len = (uint16_t)parse_hex(
                        val, tmp.start, sizeof(tmp.start));
            }
        }
        if (!have_name)
            continue;
        struct own_entry *e = own_alloc(tmp.port, tmp.ifname);
        if (!e) continue;
        /* Keep a previously journaled start body if this row does not have
         * one (e.g. an older format), but otherwise trust the file. */
        uint8_t keep[OWN_START_MAX];
        uint16_t keep_len = e->start_len;
        memcpy(keep, e->start, sizeof(keep));
        e->owner = tmp.owner;
        e->ifindex = tmp.ifindex;
        e->pid = tmp.pid;
        e->created = tmp.created;
        e->active = tmp.active;
        e->vlan = tmp.vlan;
        e->freq = tmp.freq;
        memcpy(e->bssid, tmp.bssid, 6);
        if (tmp.section[0])
            snprintf(e->section, sizeof(e->section), "%s", tmp.section);
        if (tmp.start_len) {
            e->start_len = tmp.start_len;
            memcpy(e->start, tmp.start, tmp.start_len);
        } else {
            e->start_len = keep_len;
            memcpy(e->start, keep, keep_len);
        }
        if (!e->pid)
            e->pid = own_hostapd_pid(e->ifname);
        g_own_dirty = 1;
    }
    fclose(f);
    printf("own: journal %s loaded\n", g_own_path);
    fflush(stdout);
}

/* ---- discovery of processes/files that survived a journal loss -------- */

static void own_adopt_pidfiles(void)
{
    DIR *d = opendir(OWN_RUN_DIR);
    struct dirent *de;

    if (!d)
        return;
    while ((de = readdir(d)) != NULL) {
        const char *n = de->d_name;
        char ifname[OWN_NAME_MAX];
        size_t len;
        int pid;

        if (strncmp(n, "vap-", 4) != 0)
            continue;
        len = strlen(n);
        if (len <= 4 + 4 || strcmp(n + len - 4, ".pid") != 0)
            continue;
        if (len - 4 - 4 >= sizeof(ifname))
            continue;
        memcpy(ifname, n + 4, len - 4 - 4);
        ifname[len - 4 - 4] = 0;
        if (!own_name_ok(ifname))
            continue;
        pid = own_hostapd_pid(ifname);
        if (!pid)
            continue;
        if (own_nd_has(ifname, NULL, 0))
            continue;                      /* netifd's pid naming never "vap-" */
        int ifindex = read_sysfs_int(ifname, "ifindex");
        struct own_entry *e = own_by_name(ifname);
        if (e && e->owner == OWN_NETIFD)
            continue;
        if (!e)
            e = own_alloc(0xffff, ifname);
        if (!e)
            continue;
        if (ifindex <= 0) {
            /* hostapd without its netdev is an orphan: stop it */
            printf("own: orphan hostapd pid=%d %s (no netdev), stopping\n",
                   pid, ifname);
            own_stop_pid(pid);
            own_files_remove(ifname);
            if (e->owner != OWN_CAPAGENT)
                own_free(e);
            continue;
        }
        e->owner = OWN_CAPAGENT;
        e->ifindex = ifindex;
        e->pid = pid;
        e->created = 0;
        g_own_dirty = 1;
        printf("own: adopted hostapd pid=%d %s (journal missing)\n",
               pid, ifname);
        fflush(stdout);
    }
    closedir(d);
}

static void own_cleanup_stale(void)
{
    DIR *d = opendir(OWN_TMP_DIR);
    struct dirent *de;

    if (!d)
        return;
    while ((de = readdir(d)) != NULL) {
        const char *n = de->d_name;
        char ifname[OWN_NAME_MAX];
        size_t len;

        if (strncmp(n, "vap-", 4) != 0)
            continue;
        len = strlen(n);
        if (len <= 4 + 5 || strcmp(n + len - 5, ".conf") != 0)
            continue;
        if (len - 5 - 4 >= sizeof(ifname))
            continue;
        memcpy(ifname, n + 4, len - 5 - 4);
        ifname[len - 5 - 4] = 0;
        if (!own_name_ok(ifname))
            continue;
        struct own_entry *e = own_by_name(ifname);
        int alive = own_hostapd_pid(ifname);
        if (e && e->owner == OWN_CAPAGENT)
            continue;
        if (alive && (!e || e->owner != OWN_NETIFD)) {
            /* journal lost but the process is real; adopt instead of kill */
            int ifindex = read_sysfs_int(ifname, "ifindex");
            if (ifindex > 0 && !own_nd_has(ifname, NULL, 0)) {
                if (!e)
                    e = own_alloc(0xffff, ifname);
                if (e) {
                    e->owner = OWN_CAPAGENT;
                    e->ifindex = ifindex;
                    e->pid = alive;
                    e->created = 0;
                    g_own_dirty = 1;
                    continue;
                }
            }
        }
        /* Nothing in the table, no live process: this is exactly the stale
         * /tmp/vap-*.conf that used to poison ownership.  Drop it. */
        printf("own: removing stale %s (owner=%s)\n", n,
               e ? own_owner_name(e->owner) : "none");
        {
            char path[128];
            snprintf(path, sizeof(path), OWN_TMP_DIR "/%s", n);
            unlink(path);
        }
        own_files_remove(ifname);
    }
    closedir(d);
}

/* ---- state transitions ------------------------------------------------- */

static void own_unmirror(const struct own_entry *e)
{
    if (e->port == 0xffff) return;
    struct vap *v = &g_vap[(e->port >> 8) % MAX_RADIOS][e->port & 0x0f];
    if (v->used && (!strcmp(v->ifname, e->ifname) ||
                    (e->ifindex > 0 && v->ifindex == e->ifindex))) {
        printf("own: detaching port=0x%04x %s from the datapath\n",
               e->port, e->ifname);
        if (v->ifindex > 0)
            dp_del_ifindex(v->ifindex);
        v->used = 0;
        if (v->extfd >= 0) { close(v->extfd); v->extfd = -1; }
        v->l2fd = -1;
    }
    if (g_extmux && e->port != 0xffff)
        extmux_del_vap(g_extmux, e->port);
    pmap_del(e->port);
}

/* Stop our hostapd and forget the netdev, but never delete it: the name now
 * belongs to netifd (or to an unknown process), so the netdev is not ours. */
static void own_detach(struct own_entry *e, const char *why)
{
    int pid = e->pid ? e->pid : own_hostapd_pid(e->ifname);
    if (pid) {
        printf("own: %s: stopping hostapd pid=%d (%s)\n", e->ifname, pid, why);
        own_stop_pid(pid);
    }
    own_files_remove(e->ifname);
    own_unmirror(e);
    e->pid = 0;
    e->created = 0;
    e->active = 0;
    g_own_dirty = 1;
}

/* Full removal of a CAPAGENT netdev (manager 0x600c or an orphan). */
static void own_release(struct own_entry *e, const char *why)
{
    int pid = e->pid ? e->pid : own_hostapd_pid(e->ifname);
    int ifindex = e->ifindex > 0 ? e->ifindex
                                 : read_sysfs_int(e->ifname, "ifindex");

    if (pid) {
        printf("own: %s: stopping hostapd pid=%d (%s)\n", e->ifname, pid, why);
        own_stop_pid(pid);
    }
    if (ifindex > 0 && !own_nd_has(e->ifname, NULL, 0)) {
        int rc = vap_netdev_del(ifindex);
        printf("own: %s: delete netdev ifindex=%d rc=%d (%s)\n",
               e->ifname, ifindex, rc, why);
    } else if (ifindex > 0) {
        printf("own: %s: netifd owns the name, leaving netdev (%s)\n",
               e->ifname, why);
    }
    own_unmirror(e);
    own_files_remove(e->ifname);
    own_free(e);
}

static void own_mirror(struct own_entry *e)
{
    struct vap *v;

    if (e->port == 0xffff || !e->active || e->ifindex <= 0)
        return;
    v = &g_vap[(e->port >> 8) % MAX_RADIOS][e->port & 0x0f];
    if (!v->used) {
        v->used = 1;
        v->rid = e->port >> 8;
        v->wid = e->port & 0x0f;
        v->vlan = e->vlan;
        v->extfd = -1;
        v->l2fd = -1;
    }
    v->ifindex = e->ifindex;
    snprintf(v->ifname, sizeof(v->ifname), "%s", e->ifname);
    memcpy(v->bssid, e->bssid, 6);
    if (e->freq)
        v->freq = e->freq;
}

/* Bring up the netdev/hostapd recorded in the journal without waiting for the
 * manager to repeat 0x6016 (netifd reload, wifi reload, agent restart). */
#define OWN_START_TRIES 5

static void own_try_start(const struct cfg *c, struct own_entry *e)
{
    uint64_t now = own_now_ms();
    struct vap vp;
    int pid;

    if (!e->active || !e->start_len || e->ifindex <= 0)
        return;
    if (own_forced_readonly(c))
        return;                    /* forced legacy: never spawn hostapd */
    if (e->port != 0xffff && mlme_owns_port(e->port))
        return;                    /* W36: in-CAP MLME, never hostapd */
    if (e->fail_count >= OWN_START_TRIES) {
        if (!e->start_given_up) {
            printf("own: %s: hostapd start gave up after %d attempts; "
                   "waiting for a new 0x6016\n", e->ifname, OWN_START_TRIES);
            fflush(stdout);
            e->start_given_up = 1;
            g_own_dirty = 1;
        }
        return;
    }
    if (e->retry_at && now < e->retry_at)
        return;
    /* 0x6016 and own_service() can race on the same entry; a start takes up
       to 3 s, during which e->pid is still 0.  Without this lock both would
       spawn a daemon and the loser would take the interface down. */
    if (e->starting) {
        if (now - e->starting_at < 15000)
            return;
        e->starting = 0;
    }
    if (own_nd_has(e->ifname, NULL, 0)) {
        own_detach(e, "netifd claimed the name before start");
        e->owner = OWN_NETIFD;
        return;
    }
    pid = own_hostapd_pid(e->ifname);
    if (pid > 0) {
        e->pid = pid;
        return;
    }
    /* The pid file can be missing while the daemon is alive (hostapd -B
       detaches before writing it, or someone removed the file).  Use the
       config path in /proc so we never spawn a second daemon.  The unit test
       has no /proc scan shim, so skip it there. */
#ifndef OWN_TEST_PID_OK
    {
        pid_t hp = vap_find_hostapd(e->ifname);
        if (hp > 0) {
            e->pid = (int)hp;
            return;
        }
    }
#endif
    memset(&vp, 0, sizeof(vp));
    vp.used = 1;
    vp.rid = e->port >> 8;
    vp.wid = e->port & 0x0f;
    vp.vlan = e->vlan;
    vp.freq = e->freq;
    vp.ifindex = e->ifindex;
    snprintf(vp.ifname, sizeof(vp.ifname), "%s", e->ifname);
    memcpy(vp.bssid, e->bssid, 6);
    vp.extfd = -1;
    vp.l2fd = -1;

    e->starting = 1;
    e->starting_at = now;
    pid = vap_hostapd_start(e->port, e->ifname, e->port >> 8, e->port & 0x0f,
                            e->start, e->start_len, &vp, c);
    e->starting = 0;
    if (pid > 0) {
        e->pid = pid;
        e->fail_count = 0;
        e->retry_at = 0;
        e->start_given_up = 0;
        printf("own: %s: hostapd restored pid=%d\n", e->ifname, pid);
    } else {
        int shift = e->fail_count < 5 ? e->fail_count : 5;
        e->fail_count++;
        if (e->fail_count >= OWN_START_TRIES) {
            e->retry_at = 0;
            e->start_given_up = 1;
            printf("own: %s: hostapd start failed %d/%d, giving up "
                   "(reported; a new 0x6016 resets the budget)\n",
                   e->ifname, e->fail_count, OWN_START_TRIES);
        } else {
            e->retry_at = now + (uint64_t)(2000u << shift);
            printf("own: %s: hostapd start failed %d/%d, retry in %ums\n",
                   e->ifname, e->fail_count, OWN_START_TRIES, 2000u << shift);
        }
    }
    fflush(stdout);
    g_own_dirty = 1;
}

/* netifd is the authority: mark, adopt or detach rows it now reports. */
static void own_sync_netifd(void)
{
    char section[OWN_SECTION_MAX];

    if (g_own_probe_state != OWN_PROBE_OK)
        return;

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int in;
        if (!e->used || !e->ifname[0])
            continue;
        in = own_nd_has(e->ifname, section, sizeof(section));
        if (in) {
            if (e->owner == OWN_CAPAGENT || e->owner == OWN_PENDING)
                own_detach(e, "netifd now owns this name");
            e->owner = OWN_NETIFD;
            e->pid = 0;
            e->created = 0;
            e->ifindex = read_sysfs_int(e->ifname, "ifindex");
            if (section[0])
                snprintf(e->section, sizeof(e->section), "%s", section);
            g_own_dirty = 1;
        } else if (e->owner == OWN_NETIFD) {
            e->ifindex = read_sysfs_int(e->ifname, "ifindex");
            if (e->ifindex <= 0) {
                printf("own: netifd released %s\n", e->ifname);
                own_free(e);
            }
        }
    }
    for (int i = 0; i < g_own_nd.n; i++) {
        const struct nd_iface *ni = &g_own_nd.iface[i];
        struct own_entry *e = own_by_name(ni->ifname);
        if (!e)
            e = own_alloc(0xffff, ni->ifname);
        if (!e)
            continue;
        if (e->owner != OWN_CAPAGENT) {
            e->owner = OWN_NETIFD;
            e->created = 0;
            e->pid = 0;
            e->ifindex = read_sysfs_int(ni->ifname, "ifindex");
            snprintf(e->section, sizeof(e->section), "%s", ni->section);
            g_own_dirty = 1;
        }
    }
}

/* Try to repair CAPAGENT rows; only runs with a usable netifd probe. */
static void own_reconcile(const struct cfg *c)
{
    own_sync_netifd();

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int ifindex;
        if (!e->used || !e->ifname[0])
            continue;
        if (e->owner != OWN_CAPAGENT && e->owner != OWN_PENDING) {
            if (e->owner == OWN_FOREIGN &&
                read_sysfs_int(e->ifname, "ifindex") <= 0) {
                printf("own: foreign netdev %s disappeared\n", e->ifname);
                own_free(e);
            }
            continue;
        }
        if (own_nd_has(e->ifname, NULL, 0)) {
            if (e->owner == OWN_CAPAGENT)
                own_detach(e, "name reserved by netifd");
            e->owner = OWN_NETIFD;
            e->pid = 0;
            e->ifindex = read_sysfs_int(e->ifname, "ifindex");
            continue;
        }

        ifindex = read_sysfs_int(e->ifname, "ifindex");
        if (ifindex > 0) {
            if (e->owner == OWN_PENDING) {
                int pid = own_hostapd_pid(e->ifname);
                e->owner = pid > 0 ? OWN_CAPAGENT : OWN_FOREIGN;
                e->pid = pid;
                if (!pid) {
                    printf("own: %s appeared but is not ours; leaving it\n",
                           e->ifname);
                    continue;
                }
            }
            e->ifindex = ifindex;
            if (e->pid && !own_pid_alive(e->pid))
                e->pid = 0;
            if (!e->pid)
                e->pid = own_hostapd_pid(e->ifname);
            own_mirror(e);
            if (!e->pid)
                own_try_start(c, e);
            continue;
        }

        /* netdev vanished: recreate only when the manager asked for it and we
         * have its last start body.  Otherwise this is an orphan. */
        e->pid = 0;
        if (e->owner == OWN_CAPAGENT)
            own_unmirror(e);
        if (!e->active) {
            if (e->owner == OWN_CAPAGENT || e->owner == OWN_PENDING) {
                printf("own: dropping orphan row %s (active=%d)\n",
                       e->ifname, e->active);
                own_release(e, "orphan");
            }
            continue;
        }
        if (!e->start_len) {
            printf("own: %s vanished but no 0x6016 body to rebuild it; "
                   "waiting for the manager\n", e->ifname);
            continue;
        }
        if (own_forced_readonly(c))
            continue;
        ifindex = vap_netdev_create(e->port >> 8, e->ifname, e->bssid);
        if (ifindex > 0) {
            e->owner = OWN_CAPAGENT;
            e->created = 1;
            e->ifindex = ifindex;
            own_mirror(e);
            own_try_start(c, e);
        } else if (ifindex == -2) {
            printf("own: %s reappeared while recreating; re-checking\n",
                   e->ifname);
        }
    }
}

/* While netifd is restarting we must not create or delete anything, but a
 * crashed hostapd on a netdev that still exists is safe to restart. */
static void own_reconcile_soft(const struct cfg *c)
{
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int pid;
        if (!e->used || e->owner != OWN_CAPAGENT || !e->ifname[0])
            continue;
        if (read_sysfs_int(e->ifname, "ifindex") <= 0)
            continue;
        if (e->pid && own_pid_alive(e->pid))
            continue;
        pid = own_hostapd_pid(e->ifname);
        if (pid > 0) {
            e->pid = pid;
            continue;
        }
        own_try_start(c, e);
    }
}

/* ---- public entry points ---------------------------------------------- */

/* Resolve the netdev for (phy, vapid), creating it only when allowed.
 * Returns 1 with ifindex and managed filled (managed=0 means a netifd or
 * foreign netdev exists and is reported read-only), 0 when the decision must
 * be retried, -1 on a hard create error. */
static int own_claim(const struct cfg *c, int phy, int vapid,
                     const char *preferred, const uint8_t mac[6],
                     char *ifname, size_t ifname_len,
                     int *ifindex, int *managed)
{
    uint16_t port = (uint16_t)((phy << 8) | (vapid & 0xff));
    struct {
        char name[OWN_NAME_MAX];
        int safe_unknown;
    } cand[5];
    int nc = 0, state;
    struct own_entry *e;
    int fb_idx = 0, fb_owner = OWN_NONE, hard_err = 0;
    char fb_name[OWN_NAME_MAX] = "";
    char conv[OWN_NAME_MAX], alt[OWN_NAME_MAX], macname[OWN_NAME_MAX];

    (void)c;
    if (ifname && ifname_len) ifname[0] = 0;
    if (ifindex) *ifindex = 0;
    if (managed) *managed = 0;

    state = own_probe(0);
    e = own_by_port(port);

    snprintf(conv, sizeof(conv), "phy%d-ap%d", phy, vapid);
    snprintf(alt, sizeof(alt), "cap%d-%d", phy, vapid);

#define OWN_ADD_CAND(nm, safe)                                             \
    do {                                                                   \
        const char *nm_ = (nm);                                            \
        int dup = 0;                                                       \
        if (nm_ && own_name_ok(nm_)) {                                     \
            for (int ci_ = 0; ci_ < nc; ci_++)                             \
                if (!strcmp(cand[ci_].name, nm_)) { dup = 1; break; }      \
            if (!dup && nc < 5) {                                          \
                snprintf(cand[nc].name, OWN_NAME_MAX, "%s", nm_);          \
                cand[nc].safe_unknown = (safe);                            \
                nc++;                                                      \
            }                                                              \
        }                                                                  \
    } while (0)

    OWN_ADD_CAND(e && e->ifname[0] ? e->ifname : NULL, 1);
    OWN_ADD_CAND(preferred, 0);
    /* W33 R1: a MAC is not a name.  Only an AP/AP_VLAN netdev of this phy is
     * allowed to stand in for the VAP, picked deterministically. */
    if (mac && (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) &&
        ifindex_by_mac_ap(mac, phy, macname, sizeof(macname)) > 0)
        OWN_ADD_CAND(macname, 1);
    OWN_ADD_CAND(conv, 0);
    OWN_ADD_CAND(alt, 1);
#undef OWN_ADD_CAND

    for (int i = 0; i < nc; i++) {
        const char *nm = cand[i].name;
        int idx, pid, ours, created = 0;

        if (state != OWN_PROBE_OK && !cand[i].safe_unknown)
            continue;                      /* cannot verify netifd right now */
        if (own_nd_has(nm, NULL, 0)) {
            /* netifd always wins the name; remember its ifindex so a legacy
             * 0xd00b can report the existing BSS read-only. */
            int nidx = read_sysfs_int(nm, "ifindex");
            if (nidx > 0 && !fb_idx) {
                fb_idx = nidx;
                fb_owner = OWN_NETIFD;
                snprintf(fb_name, sizeof(fb_name), "%.*s",
                         (int)sizeof(fb_name) - 1, nm);
            }
            continue;
        }

        idx = read_sysfs_int(nm, "ifindex");
        if (idx > 0) {
            if (!iface_is_ap(idx)) {
                printf("own: %s is not an AP/AP_VLAN netdev, ignoring\n", nm);
                continue;
            }
            pid = own_hostapd_pid(nm);
            ours = pid > 0 ||
                   (e && !strcmp(e->ifname, nm) && e->owner == OWN_CAPAGENT);
            if (!ours) {
                if (!fb_idx) {
                    fb_idx = idx;
                    fb_owner = OWN_FOREIGN;
                    snprintf(fb_name, sizeof(fb_name), "%.*s",
                             (int)sizeof(fb_name) - 1, nm);
                }
                continue;
            }
            if (!e) e = own_alloc(port, nm);
            if (!e) continue;
            own_set_name(e, nm);
            e->owner = OWN_CAPAGENT;
            e->ifindex = idx;
            e->pid = pid;
            memcpy(e->bssid, mac, 6);
            if (ifname) snprintf(ifname, ifname_len, "%.*s",
                                 (int)ifname_len - 1, nm);
            if (ifindex) *ifindex = idx;
            if (managed) *managed = 1;
            g_own_dirty = 1;
            printf("own: port=0x%04x -> %s ifindex=%d (adopted)\n",
                   port, nm, idx);
            fflush(stdout);
            own_save();
            return 1;
        }

        if (own_forced_readonly(c))
            continue;                  /* forced legacy: read-only */
        idx = vap_netdev_create(phy, nm, mac);
        if (idx > 0) {
            created = 1;
        } else if (idx == -2) {
            /* Lost a race: something created the name between the check and
             * the NEW_INTERFACE.  Classify it on the next pass. */
            int nidx = read_sysfs_int(nm, "ifindex");
            if (nidx > 0) {
                pid = own_hostapd_pid(nm);
                if (pid > 0) {
                    if (!e) e = own_alloc(port, nm);
                    if (e) {
                        e->owner = OWN_CAPAGENT;
                        e->ifindex = nidx;
                        e->pid = pid;
                        memcpy(e->bssid, mac, 6);
                        own_set_name(e, nm);
                        if (ifname) snprintf(ifname, ifname_len, "%.*s",
                                 (int)ifname_len - 1, nm);
                        if (ifindex) *ifindex = nidx;
                        if (managed) *managed = 1;
                        g_own_dirty = 1;
                        own_save();
                        return 1;
                    }
                }
                if (!fb_idx) {
                    fb_idx = nidx;
                    fb_owner = own_nd_has(nm, NULL, 0) ? OWN_NETIFD
                                                      : OWN_FOREIGN;
                    snprintf(fb_name, sizeof(fb_name), "%.*s",
                             (int)sizeof(fb_name) - 1, nm);
                }
            }
            continue;
        } else {
            hard_err = 1;
            continue;
        }

        if (!e) e = own_alloc(port, nm);
        if (!e) continue;
        own_set_name(e, nm);
        e->owner = OWN_CAPAGENT;
        e->ifindex = idx;
        e->pid = 0;
        e->created = 1;
        memcpy(e->bssid, mac, 6);
        if (ifname) snprintf(ifname, ifname_len, "%.*s",
                                 (int)ifname_len - 1, nm);
        if (ifindex) *ifindex = idx;
        if (managed) *managed = 1;
        g_own_dirty = 1;
        printf("own: port=0x%04x -> %s ifindex=%d (created%s)\n",
               port, nm, idx, created ? "" : "");
        fflush(stdout);
        own_save();
        return 1;
    }

    if (!e) {
        const char *pend = own_nd_has(conv, NULL, 0) ? alt : conv;
        if (fb_idx && fb_name[0])
            pend = fb_name;
        e = own_alloc(port, pend);
    }
    if (!e)
        return -1;

    if (fb_idx) {
        e->owner = fb_owner;
        e->ifindex = fb_idx;
        e->pid = 0;
        e->created = 0;
        own_set_name(e, fb_name);
        if (ifname) snprintf(ifname, ifname_len, "%s", fb_name);
        if (ifindex) *ifindex = fb_idx;
        if (managed) *managed = 0;
        g_own_dirty = 1;
        printf("own: port=0x%04x -> %s (%s), read-only\n",
               port, fb_name, own_owner_name(fb_owner));
        fflush(stdout);
        own_save();
        return 1;
    }

    e->owner = OWN_PENDING;
    e->ifindex = 0;
    e->pid = 0;
    memcpy(e->bssid, mac, 6);
    if (!e->ifname[0])
        own_set_name(e, conv);
    if (ifname) snprintf(ifname, ifname_len, "%s", e->ifname);
    if (managed) *managed = 0;
    g_own_dirty = 1;
    printf("own: port=0x%04x deferred (netifd probe %s, hard_err=%d)\n",
           port, state == OWN_PROBE_BUSY ? "busy" :
                 state == OWN_PROBE_OK ? "ok" : "unknown", hard_err);
    fflush(stdout);
    own_save();
    return hard_err && state == OWN_PROBE_OK ? -1 : 0;
}

static void own_note_start(const struct cfg *c, int port, const uint8_t *body,
                           uint16_t len, const struct vap *vp, int ifindex,
                           int managed)
{
    struct own_entry *e = own_by_port((uint16_t)port);

    if (!e)
        e = own_alloc((uint16_t)port, NULL);
    if (!e)
        return;
    e->active = 1;
    if (ifindex > 0)
        e->ifindex = ifindex;
    if (vp) {
        memcpy(e->bssid, vp->bssid, 6);
        e->vlan = vp->vlan;
        e->freq = vp->freq;
    }
    int same_body = body && len && len == e->start_len &&
                    len <= OWN_START_MAX && !memcmp(e->start, body, len);
    if (body && len && len <= OWN_START_MAX) {
        memcpy(e->start, body, len);
        e->start_len = len;
    } else if (len > OWN_START_MAX) {
        e->start_len = 0;          /* never restart from a stale body */
    }
    g_own_dirty = 1;

    if (!managed || !c->vap_auto || e->owner != OWN_CAPAGENT)
        return;
    if (own_forced_readonly(c))
        return;
    if (own_nd_has(e->ifname, NULL, 0)) {
        printf("own: %s appeared in netifd status, not starting\n", e->ifname);
        e->pid = 0;
        own_save();
        return;
    }
    if (e->pid && own_pid_alive(e->pid)) {
        /* The official manager re-sends 0x6016 with a body that differs in
         * non-configuration bytes; restarting on every repeat killed the
         * daemon in a tight loop and left the BSS unusable.  A live daemon
         * wins: journal the newest body for a future cold start, but do not
         * touch the running process.  A real profile change arrives as
         * 0x600c + 0x500b + 0x6016. */
        printf("vap: %s already running pid=%d, repeated 0x6016 ignored "
               "(body %s)\n", e->ifname, e->pid,
               same_body ? "identical" : "updated");
        g_own_dirty = 1;
        own_save();
        return;
    }
    /* A new start request gets a fresh bounded retry budget. */
    e->fail_count = 0;
    e->retry_at = 0;
    e->start_given_up = 0;
    own_try_start(c, e);
    own_save();
}

static int own_ifname_for_port(int port, char *out, size_t n)
{
    struct own_entry *e = own_by_port((uint16_t)port);
    if (!e || !e->ifname[0])
        return 0;
    snprintf(out, n, "%s", e->ifname);
    return 1;
}

/* Re-adopt everything that survived a manager reconnect or agent restart. */
static void own_restore_vaps(const struct cfg *c)
{
    int state;

    own_adopt_pidfiles();
    own_cleanup_stale();
    state = own_probe(1);
    if (state == OWN_PROBE_OK)
        own_sync_netifd();

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int ifindex;
        if (!e->used || !e->ifname[0])
            continue;
        if (e->owner != OWN_CAPAGENT)
            continue;
        if (state == OWN_PROBE_OK && own_nd_has(e->ifname, NULL, 0)) {
            own_detach(e, "netifd owns the name at restore");
            e->owner = OWN_NETIFD;
            continue;
        }
        ifindex = read_sysfs_int(e->ifname, "ifindex");
        if (ifindex <= 0) {
            if (!e->active || !e->start_len || state != OWN_PROBE_OK)
                continue;              /* wait for a usable probe */
            if (own_forced_readonly(c))
                continue;
            ifindex = vap_netdev_create(e->port >> 8, e->ifname, e->bssid);
            if (ifindex <= 0)
                continue;
            e->created = 1;
            e->ifindex = ifindex;
            printf("own: recreated %s ifindex=%d after reload\n",
                   e->ifname, ifindex);
        }
        e->ifindex = ifindex;
        e->pid = own_hostapd_pid(e->ifname);
        own_mirror(e);
        if (e->port != 0xffff) {
            cap_vap_ready(e->port >> 8, e->port & 0x0f, ifindex, e->ifname,
                          e->bssid, c);
            if (e->active && !e->pid)
                own_try_start(c, e);
        }
        g_own_dirty = 1;
        printf("own: restored port=0x%04x %s ifindex=%d pid=%d\n",
               e->port, e->ifname, ifindex, e->pid);
        fflush(stdout);
    }
    own_save();
}

/* 0x600c: delete only what capagent owns. */
static void own_destroy(const struct cfg *c, int port)
{
    struct own_entry *e = own_by_port((uint16_t)port);
    char conv[OWN_NAME_MAX];

    (void)c;
    if (!e) {
        snprintf(conv, sizeof(conv), "phy%d-ap%d", port >> 8, port & 0xff);
        e = own_by_name(conv);
    }
    if (!e) {
        printf("own: destroy port=0x%04x: unknown, nothing to do\n", port);
        fflush(stdout);
        return;
    }
    if (e->owner != OWN_CAPAGENT) {
        printf("own: destroy port=0x%04x %s: owned by %s, refusing\n",
               port, e->ifname, own_owner_name(e->owner));
        fflush(stdout);
        return;
    }
    printf("own: destroy port=0x%04x %s (manager request)\n", port, e->ifname);
    if ((c && c->vap_teardown == 0) || own_forced_readonly(c)) {
        /* W33 --no-vap-teardown / forced legacy: keep the netdev/hostapd,
         * drop our claim. */
        printf("own: %s kept (no-vap-teardown), forgetting the row\n",
               e->ifname);
        own_unmirror(e);
        own_free(e);
    } else {
        own_release(e, "manager destroy");
    }
    fflush(stdout);
    own_save();
}

static int own_has_entry(int port)
{
    return own_by_port((uint16_t)port) != NULL;
}

/* Watchdog helpers: never reap a name that the journal still owns (the
   reconcile loop is the only path that may restart/recreate it) or that
   netifd reports as its own. */
static int own_name_claimed(const char *ifname)
{
    return own_by_name(ifname) != NULL;
}

static int own_name_is_netifd(const char *ifname)
{
    return own_nd_has(ifname, NULL, 0);
}

static int own_created_port(int port)
{
    struct own_entry *e = own_by_port((uint16_t)port);
    return e && e->owner == OWN_CAPAGENT && e->created;
}

static int own_managed_strict(int port)
{
    struct own_entry *e = own_by_port((uint16_t)port);
    return e && e->owner == OWN_CAPAGENT;
}

static int own_count_owner(int owner)
{
    int n = 0;
    for (int i = 0; i < OWN_MAX; i++)
        if (g_own[i].used && g_own[i].owner == owner)
            n++;
    return n;
}

static int own_netifd_count(void)
{
    return g_own_nd.n;
}

static int own_managed_count(void)
{
    return own_count_owner(OWN_CAPAGENT);
}

static int own_any_managed(void)
{
    return own_managed_count() > 0;
}

/* Read-only journal+probe load for --check-wireless: no cleanup, no sync, no
 * save, no hostapd/netdev action. */
static void own_inspect(struct cfg *c)
{
    if (c->vap_state && *c->vap_state)
        g_own_path = c->vap_state;
    else if (access(OWN_RUN_DIR, W_OK) == 0)
        g_own_path = OWN_DEFAULT_STATE;
    else
        g_own_path = OWN_FALLBACK_STATE;
    own_load();
    own_probe(1);
}

/* Session-start policy refresh: probe netifd, reconcile its rows into the
 * table, and persist.  Called from wl_classify() before every session. */
static void own_policy_refresh(void)
{
    own_probe(1);
    if (g_own_probe_state == OWN_PROBE_OK)
        own_sync_netifd();
    own_save();
}

static void own_service(const struct cfg *c)
{
    int state = own_probe(0);

    if (state == OWN_PROBE_OK)
        own_reconcile(c);
    else
        own_reconcile_soft(c);
    own_save();
}

static void own_init(struct cfg *c)
{
    if (c->vap_state && *c->vap_state) {
        g_own_path = c->vap_state;
    } else if (access(OWN_RUN_DIR, W_OK) == 0) {
        g_own_path = OWN_DEFAULT_STATE;
    } else {
        g_own_path = OWN_FALLBACK_STATE;
    }

    own_load();
    own_adopt_pidfiles();
    own_cleanup_stale();
    if (own_probe(1) == OWN_PROBE_OK)
        own_sync_netifd();
    own_save();

    int n = 0;
    for (int i = 0; i < OWN_MAX; i++)
        if (g_own[i].used)
            n++;
    printf("own: ready state=%s entries=%d netifd=%s(%d)\n",
           g_own_path, n,
           g_own_probe_state == OWN_PROBE_OK ? "ok" :
           g_own_probe_state == OWN_PROBE_BUSY ? "busy" : "unknown",
           g_own_nd.n);
    fflush(stdout);
}
