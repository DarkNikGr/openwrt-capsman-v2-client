/* phy.inc — one hostapd process per radio, all VAPs as bss= sections.
 *
 * Included AFTER ownership.inc (it reads the journal bodies) and before
 * main.inc.
 *
 * Why: one hostapd per VAP gave every BSS its own nl80211 client on the same
 * phy.  On the mt7603e/mt7612e the instances then contended, one ended in
 * uninterruptible state D, and the BSSes died within a second although each
 * had reached AP-ENABLED.  OpenWrt/netifd runs a single hostapd per phy with
 * `interface=` plus `bss=` sections, which is what this does.
 */

static void vap_phy_paths(int phy, char *conf, size_t cl, char *pidf, size_t pl,
                          char *logf, size_t ll)
{
    snprintf(conf, cl, VAP_CONF_DIR "/vap-phy%d.conf", phy);
    snprintf(pidf, pl, "/var/run/vap-phy%d.pid", phy);
    snprintf(logf, ll, "/tmp/vap-phy%d.log", phy);
}

/* Pid of the phy-wide hostapd.  hostapd -B may leave the -P file empty, so
 * fall back to a /proc scan for our exact config path: every journal row of
 * the phy resolves to the same process, which stops the 1 s reconcile from
 * restarting the whole phy. */
/* /proc/<pid>/cmdline is NUL-separated: strstr() stops at the first NUL and
 * therefore never sees the config path.  Match each argument exactly.  This
 * matters for a foreground (-dd) hostapd, which leaves no pid file at all. */
static int vap_proc_has_conf(pid_t pid, const char *conf)
{
    char p[64], buf[4096];
    snprintf(p, sizeof(p), "/proc/%ld/cmdline", (long)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    size_t cl = strlen(conf);
    for (ssize_t off = 0; off < n; ) {
        size_t l = strnlen(buf + off, (size_t)(n - off));
        if (l == cl && !memcmp(buf + off, conf, cl)) return 1;
        off += (ssize_t)l + 1;
    }
    return 0;
}

/* A zombie still answers kill(pid, 0), so a dead hostapd would look alive and
 * the reconcile would never restart it.  Read the state from /proc. */
static int pid_is_zombie(pid_t pid)
{
    char p[64], buf[256];
    snprintf(p, sizeof(p), "/proc/%ld/stat", (long)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *rp = strrchr(buf, ')');
    if (!rp || rp[1] != ' ') return 0;
    return rp[2] == 'Z';
}

static pid_t vap_phy_pid(int phy)
{
    char conf[128], pidf[128], logf[128];
    vap_phy_paths(phy, conf, sizeof(conf), pidf, sizeof(pidf),
                  logf, sizeof(logf));
    FILE *f = fopen(pidf, "r");
    long fpid = 0;
    int fgot = 0;
    if (f) {
        fgot = fscanf(f, "%ld", &fpid);
        fclose(f);
        if (fgot == 1 && fpid > 0 && pid_is_zombie((pid_t)fpid)) {
            int wst;
            waitpid((pid_t)fpid, &wst, WNOHANG);
            fpid = 0;
        } else if (fgot == 1 && fpid > 0 &&
                   (kill((pid_t)fpid, 0) == 0 || errno == EPERM) &&
                   vap_proc_has_conf((pid_t)fpid, conf))
            return (pid_t)fpid;
    }
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    pid_t found = 0;
    while ((de = readdir(d))) {
        char *end = NULL;
        long c = strtol(de->d_name, &end, 10);
        if (!end || *end || c <= 0) continue;
        if (vap_proc_has_conf((pid_t)c, conf)) { found = (pid_t)c; break; }
    }
    closedir(d);
    if (getenv("CAPAGENT_DBG_PID"))
        printf("dbg-pid: phy%d pidf=%s got=%d pid=%ld scan=%d\n", phy, pidf,
               fgot, fpid, (int)found);
    return found;
}

/* Is a live hostapd running for the phy of this ifname (phyN-apM / capN-M)? */
static pid_t vap_phy_pid_for_ifname(const char *ifname)
{
    int phy = -1, w = -1;
    char tail;
    if (sscanf(ifname, "phy%d-ap%d%c", &phy, &w, &tail) != 2 &&
        sscanf(ifname, "cap%d-%d%c", &phy, &w, &tail) != 2)
        return 0;
    if (phy < 0 || phy >= MAX_RADIOS) return 0;
    pid_t pid = vap_phy_pid(phy);
    if (pid <= 0) return 0;
    char p[64], b[64];
    snprintf(p, sizeof(p), "/proc/%ld/comm", (long)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return 0;
    b[n] = 0;
    return !strncmp(b, "hostapd", 7) ? pid : 0;
}

static void vap_phy_stop(int phy)
{
    pid_t pid = vap_phy_pid(phy);
    if (pid > 0) {
        printf("vap: stopping phy%d hostapd pid=%d\n", phy, (int)pid);
        fflush(stdout);
        kill(pid, SIGTERM);
        for (int i = 0; i < 30; i++) {
            if (kill(pid, 0) != 0 && errno != EPERM) { pid = 0; break; }
            usleep(100000);
        }
        if (pid > 0) kill(pid, SIGKILL);
        /* Reap it before starting the next instance: hostapd is our child now,
         * and until it is reaped its cfg80211 mgmt subscription can still be
         * alive, which makes the next nl80211_mgmt_subscribe_ap() fail and the
         * whole radio abort with "Could not configure driver mode". */
        for (int i = 0; i < 20; i++) {
            int st = 0;
            pid_t w = waitpid((pid_t)pid, &st, WNOHANG);
            if (w == (pid_t)pid || w < 0) break;
            usleep(50000);
        }
    }
}

/* Write the per-BSS options from a journal row. */
static void vap_phy_bss(FILE *f, const char *kw, const struct own_entry *e,
                        const struct cfg *c, int is_first)
{
    const uint8_t *ssid = NULL, *ie = NULL, *chv = NULL;
    uint16_t sl = 0, il = 0, cl = 0;
    find_el(e->start, e->start_len, 0x03, &ssid, &sl);
    find_el(e->start, e->start_len, 0x04, &ie, &il);
    find_el(e->start, e->start_len, 0x0a, &chv, &cl);

    struct rsn_info ri;
    rsn_parse(ie, il, &ri);
    char bridge[32] = "";
    vap_bridge_if_present(e->ifname, e->vlan, bridge, sizeof(bridge));

    fprintf(f, "%s=%s\n", kw, e->ifname);
    if (is_first) {
        fprintf(f, "driver=nl80211\nauth_algs=1\n");
        if (c->ext_ctrl_dir || c->ext_auth_dir)
            fprintf(f, "ctrl_interface=%s\n",
                    c->ext_ctrl_dir ? c->ext_ctrl_dir : c->ext_auth_dir);
        vap_write_channel(f, e->freq, vap_mgr_width(chv, cl));
    }
    if (ssid && sl) fprintf(f, "ssid=%.*s\n", (int)sl, (const char *)ssid);
    fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
            e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
            e->bssid[4], e->bssid[5]);
    if (bridge[0]) fprintf(f, "bridge=%s\n", bridge);

    int have_psk = ri.valid && (ri.akm_psk || ri.akm_psk256);
    int have_sae = ri.valid && (ri.akm_sae || ri.akm_owe) &&
                   hostapd_has_sae_override();

    if (have_psk || have_sae) {
        int first = 1;
        fprintf(f, "wpa=2\nwpa_key_mgmt=");
        if (ri.akm_psk) { fprintf(f, "WPA-PSK"); first = 0; }
        if (ri.akm_psk256) {
            fprintf(f, "%sWPA-PSK-SHA256", first ? "" : " "); first = 0;
        }
        if (have_sae && ri.akm_sae) {
            fprintf(f, "%sSAE", first ? "" : " "); first = 0;
        }
        if (have_sae && ri.akm_owe) {
            fprintf(f, "%sOWE", first ? "" : " "); first = 0;
        }
        fprintf(f, "\nrsn_pairwise=CCMP\nwpa_group_rekey=0\nwpa_ptk_rekey=0\n");
        fprintf(f, "ieee80211w=%d\n", ri.mfpr ? 2 : (ri.mfpc ? 1 : 0));
        if (have_sae && ri.mfpc)
            fprintf(f, "group_mgmt_cipher=AES-128-CMAC\n");
        if (have_sae && ri.akm_sae)
            fprintf(f, "sae_pwe=2\n");
        fprintf(f, "external_rsn_auth=1\n");
        if (hostapd_has_opt("external_rsn_sae"))
            fprintf(f, "external_rsn_sae=1\n");
        if (c->ext_auth_dir)
            fprintf(f, "ext_auth_socket=%s/ext-auth-%s\n", c->ext_auth_dir,
                    e->ifname);
    } else {
        fprintf(f, "wpa=0\n");
    }

    if (ri.valid && hostapd_has_rsn_override() && ie && il) {
        size_t p = 0;
        uint8_t blob[257];
        size_t bl = 0;
        int want_rsnxe = have_sae;
        while (p + 2 <= il) {
            uint8_t id = ie[p], l = ie[p + 1];
            if (p + 2 + l > il) break;
            if (id == 48 || (want_rsnxe && id == 244)) {
                if (bl + 2 + l <= sizeof(blob)) {
                    memcpy(blob + bl, ie + p, 2 + (size_t)l);
                    bl += 2 + (size_t)l;
                }
            }
            p += 2 + l;
        }
        if (bl) {
            fprintf(f, "external_rsn_ie=");
            for (size_t i = 0; i < bl; i++) fprintf(f, "%02x", blob[i]);
            fprintf(f, "\n");
        }
    }
    fprintf(f, "ignore_broadcast_ssid=0\nap_isolate=0\n");
}

/* A journal row is only written into the phy config when its netdev exists
 * right now: hostapd must never create an interface itself (that hits the
 * phy vif limit and fails with -23/ENFILE). */
static int vap_phy_row_ready(const struct own_entry *e, int phy)
{
    return e->used && e->active && e->start_len && e->ifname[0] &&
           (e->port >> 8) == phy && if_nametoindex(e->ifname) > 0;
}

/* (Re)start the single hostapd for this phy with every journaled VAP. */
static int vap_phy_apply(int phy, const struct cfg *c)
{
    if (phy < 0 || phy >= MAX_RADIOS) return -1;
    if (wl_legacy()) return -1;

    /* Rows with a start body.  The master (lowest vapid) is the netdev hostapd
     * attaches to with `interface=`; it must exist.  Every other BSS is handed
     * over: capagent deletes its netdev and hostapd creates it, the OpenWrt
     * model.  Static `bss=` setup always issues NL80211_CMD_NEW_INTERFACE for
     * a secondary, so leaving our netdev in place only makes hostapd delete
     * and re-create it behind our back (the -23 churn). */
    int n = 0, master = -1;
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->active || !e->start_len || !e->ifname[0] ||
            (e->port >> 8) != phy)
            continue;
        n++;
        if (master < 0 || (e->port & 0xff) < (g_own[master].port & 0xff))
            master = i;
    }
    if (!n || master < 0) return -1;

    /* Idempotent: a live hostapd that already carries exactly these rows must
     * not be restarted.  Every caller (reconcile, retry, auto-heal) used to
     * rebuild the radio, which invalidated the other rows and pulled the phy
     * into a permanent restart loop. */
    {
        pid_t live = vap_phy_pid(phy);
        if (live > 0) {
            int same = 1;
            for (int i = 0; i < OWN_MAX; i++) {
                struct own_entry *e = &g_own[i];
                if (!e->used || !e->active || !e->start_len ||
                    (e->port >> 8) != phy)
                    continue;
                if (e->applied_len != e->start_len ||
                    e->applied_hash != own_body_hash(e->start, e->start_len)) {
                    same = 0;
                    break;
                }
            }
            if (same) {
                for (int i = 0; i < OWN_MAX; i++) {
                    struct own_entry *e = &g_own[i];
                    if (!e->used || (e->port >> 8) != phy) continue;
                    e->pid = (int)live;
                    if (!e->ifindex) e->ifindex = if_nametoindex(e->ifname);
                }
                return (int)live;
            }
        }
    }

    /* Start only when the phy has settled: the driver's netdev count for this
     * phy must be unchanged for 2.5 s.  Rebuilding while interfaces are still
     * appearing restarted hostapd mid-flight and lost the BSSes. */
    {
        static int last_count[MAX_RADIOS];
        static uint64_t last_at[MAX_RADIOS];
        char p[96];
        int real = 0;
        snprintf(p, sizeof(p), "/sys/class/ieee80211/phy%d/device/net",
                 real_phy(phy));
        DIR *d = opendir(p);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)))
                if (de->d_name[0] != '.') real++;
            closedir(d);
        }
        if (real != last_count[phy]) {
            last_count[phy] = real;
            last_at[phy] = own_now_ms();
            return -1;
        }
        if (own_now_ms() - last_at[phy] < 2500) return -1;
    }

    char conf[128], pidf[128], logf[128];
    vap_phy_paths(phy, conf, sizeof(conf), pidf, sizeof(pidf),
                  logf, sizeof(logf));
    vap_phy_stop(phy);

    /* The master must exist; create it if the manager's 0x500b was lost. */
    struct own_entry *m = &g_own[master];
    if (if_nametoindex(m->ifname) <= 0) {
        int idx = vap_netdev_create(phy, m->ifname, m->bssid);
        if (idx <= 0) {
            printf("vap: phy%d: master %s could not be created\n",
                   phy, m->ifname);
            fflush(stdout);
            return -1;
        }
        m->ifindex = idx;
        g_own_dirty = 1;
    }

    /* Hand the secondary BSSes over to hostapd. */
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int idx;
        if (i == master || !e->used || !e->active || !e->start_len ||
            !e->ifname[0] || (e->port >> 8) != phy)
            continue;
        e->handed_over = 1;
        idx = if_nametoindex(e->ifname);
        if (idx <= 0) continue;
        vap_netdev_del(idx);
        for (int k = 0; k < 40; k++) {
            if (!if_nametoindex(e->ifname)) break;
            usleep(25000);
        }
        printf("vap: phy%d: handed %s over to hostapd (was ifindex %d)\n",
               phy, e->ifname, idx);
        fflush(stdout);
        e->ifindex = 0;
        g_own_dirty = 1;
    }

    FILE *f = fopen(conf, "w");
    if (!f) return -1;
    /* Logger options are global: hostapd only honours them before the first
     * interface=/bss= section.  Appended at the end they were parsed as
     * per-BSS keys, so -dd stayed at INFO and every failure was invisible. */
    if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
        /* stdout to a file is block-buffered, so a long-running hostapd
         * leaves its last lines unwritten and every diagnostic read from
         * /tmp/vap-phyN.log is truncated.  Syslog is flushed per message, so
         * the debug build logs there too and `logread` is the real trace. */
        fprintf(f, "logger_syslog=0\nlogger_syslog_level=1\n"
                   "logger_stdout=-1\nlogger_stdout_level=0\n");
    int first = 1;
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->active || !e->start_len || !e->ifname[0] ||
            (e->port >> 8) != phy)
            continue;
        char ctrl[128];
        snprintf(ctrl, sizeof(ctrl), "/var/run/hostapd/%s", e->ifname);
        unlink(ctrl);
        vap_phy_bss(f, first ? "interface" : "bss", e, c, first);
        first = 0;
    }
    fclose(f);

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(logf, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
            execl(hostapd_exe_path(), "hostapd", "-dd", "-P", pidf, conf,
                  (char *)NULL);
        else
            /* No -B: hostapd stays our direct child, so (a) its pid is the one
             * fork() returned instead of a pid file that -B writes late or
             * leaves empty, and (b) it cannot be reparented and die on its
             * own after AP-ENABLED (that was the restart loop). */
            execl(hostapd_exe_path(), "hostapd", "-P", pidf, conf,
                  (char *)NULL);
        _exit(127);
    }
    if (pid < 0) return -1;

    int st = 0, reaped = 0;
    for (int i = 0; i < 40; i++) {
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == pid) { reaped = 1; break; }
        if (r < 0) break;
        usleep(100000);
    }
    if (reaped && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
        printf("vap: phy%d hostapd failed to start (status=%d), see %s\n",
               phy, WIFEXITED(st) ? WEXITSTATUS(st) : -1, logf);
        fflush(stdout);
        return -1;
    }
    int ready = vap_wait_ap_enabled(logf, 15000);
    pid_t hp = vap_phy_pid(phy);
    if (hp <= 0) {
        int wst = 0;
        if (waitpid(pid, &wst, WNOHANG) == 0) hp = pid;   /* still our child */
    }
    if (ready <= 0) {
        printf("vap: phy%d hostapd not ready (%d), see %s\n", phy, ready, logf);
        fflush(stdout);
        if (hp > 0) kill(hp, SIGKILL);
        return -1;
    }

    /* The master is ours, the secondaries belong to hostapd now.  Record what
     * the live config carries and refresh every ifindex from the real netdev
     * so the datapath and the 0x2018 relay address what exists. */
    if (hp > 0) {
        FILE *pf = fopen(pidf, "w");
        if (pf) { fprintf(pf, "%d\n", (int)hp); fclose(pf); }
        for (int i = 0; i < OWN_MAX; i++) {
            struct own_entry *e = &g_own[i];
            if (!e->used || !e->active || (e->port >> 8) != phy) continue;
            e->pid = (int)hp;
            e->fail_count = 0;
            e->retry_at = 0;
            e->ifindex = if_nametoindex(e->ifname);
            e->applied_len = e->start_len;
            e->applied_hash = own_body_hash(e->start, e->start_len);
            if (e->ifindex > 0) own_mirror(e);
            /* The relay must follow the netdev hostapd created: a stale
             * ifindex makes 0x201c/0x2019 TX fail with -EINVAL and the BSS
             * silently stops relaying. */
            cap_vap_refresh(phy, e->port & 0xff, e->ifindex, e->ifname,
                            e->bssid, c);
        }
        g_own_dirty = 1;
        own_save();
    }
    printf("vap: phy%d hostapd up with %d BSS(es) pid=%d\n", phy, n, (int)hp);
    fflush(stdout);
    return hp > 0 ? (int)hp : -1;
}
