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

/* A second capagent instance (a distinct CAP identity for the same wiphy, see
 * the multi-identity experiment) must not share the per-phy config/pid/log
 * paths with the first one.  CAPAGENT_RUN_TAG adds a suffix to them. */
static const char *vap_run_tag(void)
{
    const char *t = getenv("CAPAGENT_RUN_TAG");
    return (t && *t) ? t : "";
}

static void vap_phy_paths(int phy, char *conf, size_t cl, char *pidf, size_t pl,
                          char *logf, size_t ll)
{
    const char *t = vap_run_tag();
    snprintf(conf, cl, VAP_CONF_DIR "/vap-phy%d%s%s.conf", phy,
             *t ? "-" : "", t);
    snprintf(pidf, pl, "/var/run/vap-phy%d%s%s.pid", phy, *t ? "-" : "", t);
    snprintf(logf, ll, "/tmp/vap-phy%d%s%s.log", phy, *t ? "-" : "", t);
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

/* pid_is_zombie() lives in ownership.inc (shared with own_pid_alive). */

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
        if (pid_is_zombie((pid_t)c)) continue;
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
    if (!ap_parse_name(ifname, &phy, &w) &&
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
        for (int i = 0; i < 20 && pid > 0; i++) {
            int st = 0;
            pid_t w = waitpid((pid_t)pid, &st, WNOHANG);
            if (w == (pid_t)pid || w < 0) break;
            usleep(50000);
        }
        own_reap_children();
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
    const uint8_t *dtv = NULL;
    uint16_t dtl = 0;
    find_el(e->start, e->start_len, 0x24, &dtv, &dtl);

    struct rsn_info ri;
    rsn_parse(ie, il, &ri);
    struct rsn_policy rp;
    rsn_policy_from_ie(&ri, hostapd_has_sae_override(), &rp);
    if (rp.ft) {
        uint8_t md[2];
        if (rsn_mde_mdid(ie, il, md))
            snprintf(rp.mdid, sizeof(rp.mdid), "%02x%02x", md[0], md[1]);
        else
            printf("vap: %s has an FT AKM but no Mobility Domain element; "
                   "falling back to the non-FT AKM\n", e->ifname);
        fflush(stdout);
    }
    char bridge[32] = "";
    vap_bridge_if_present(e->ifname, e->vlan, bridge, sizeof(bridge));

    fprintf(f, "%s=%s\n", kw, e->ifname);
    /* CAPsMAN assigns each VAP its BSSID and drops management frames whose
     * addr1/addr3 is not it (FINDINGS T13).  The driver derives its own
     * addresses for secondary BSSes, so hand hostapd the manager's address
     * explicitly; it applies it when it creates the interface. */
    {
        struct vap *vp = vap_get(e->port >> 8, e->port & 0xff);
        if (vp && (vp->mgr_bssid[0] | vp->mgr_bssid[1] | vp->mgr_bssid[2] |
                   vp->mgr_bssid[3] | vp->mgr_bssid[4] | vp->mgr_bssid[5]))
            fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    vp->mgr_bssid[0], vp->mgr_bssid[1], vp->mgr_bssid[2],
                    vp->mgr_bssid[3], vp->mgr_bssid[4], vp->mgr_bssid[5]);
    }
    /* ctrl_interface must be repeated in EVERY section: hostapd only creates
     * /var/run/hostapd/<ifname> for the BSSes that carry it, and without that
     * socket EXT_AUTH_AUTHORIZE cannot be delivered, so the station stays
     * unauthorized and no data passes (this is exactly what netifd's generated
     * config does). */
    if (c->ext_ctrl_dir || c->ext_auth_dir)
        fprintf(f, "ctrl_interface=%s\n",
                c->ext_ctrl_dir ? c->ext_ctrl_dir : c->ext_auth_dir);
    if (is_first) {
        fprintf(f, "driver=nl80211\nauth_algs=1\n");
        vap_write_channel(f, e->freq, vap_mgr_width(chv, cl));
    }
    /* dtim-period is per VAP (0x6016 TLV 0x24, a u32). */
    if (dtv && dtl >= 4) {
        uint32_t d = rd32(dtv);
        if (d) fprintf(f, "dtim_period=%u\n", d);
    }
    if (ssid && sl) fprintf(f, "ssid=%.*s\n", (int)sl, (const char *)ssid);
    fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
            e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
            e->bssid[4], e->bssid[5]);
    if (bridge[0]) fprintf(f, "bridge=%s\n", bridge);

    char rsn[256];
    rsn_conf_write(rsn, sizeof(rsn), &rp);
    fputs(rsn, f);
    if (rp.wpa) {
        if (hostapd_has_opt("external_rsn_sae"))
            fprintf(f, "external_rsn_sae=1\n");
        if (c->ext_auth_dir)
            fprintf(f, "ext_auth_socket=%s/ext-auth-%s\n", c->ext_auth_dir,
                    e->ifname);
    }

    if (ri.valid && hostapd_has_rsn_override() && ie && il) {
        uint8_t blob[257];
        size_t bl = rsn_ie_blob(blob, sizeof(blob), ie, il, rp.want_rsnxe);
        if (bl) {
            fprintf(f, "external_rsn_ie=");
            for (size_t i = 0; i < bl; i++) fprintf(f, "%02x", blob[i]);
            fprintf(f, "\n");
        }
    }
    fprintf(f, "ignore_broadcast_ssid=0\nap_isolate=0\n");
}

/* A row belongs in this phy's hostapd config when the manager has sent a
 * start body for it.  Existence of the netdev is NOT required: the master is
 * created by capagent and every secondary is handed to hostapd, which creates
 * it (the OpenWrt single-hostapd-per-radio model). */
static int vap_phy_row_cfg(const struct own_entry *e, int phy)
{
    return e->used && e->active && e->start_len && e->ifname[0] &&
           (e->port >> 8) == phy;
}

static int vap_dbg_phy(void)
{
    return getenv("CAPAGENT_DBG_PHY") || getenv("CAPAGENT_DBG_OWN");
}

static int vap_phy_keep_name(const char *name, int phy)
{
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->ifname[0] || (e->port >> 8) != phy)
            continue;
        if (!strcmp(e->ifname, name))
            return 1;
    }
    return 0;
}

/* Is this ifname one of ours for this phy?  Only names capagent hands out
 * (phyN-apM / capN-M) are considered, so a netifd/foreign netdev is safe. */
static int vap_phy_name_of(const char *name, int phy)
{
    int p = -1, w = 0;
    char tail;
    if (ap_parse_name(name, &p, &w) && p == phy)
        return 1;
    if (sscanf(name, "cap%d-%d%c", &p, &w, &tail) == 2 && p == phy)
        return 1;
    return 0;
}

/* F45: delete this phy's netdevs that are not part of the config being
 * written.  They are leftovers from an older manager slot (the manager
 * renumbers its interfaces on a CAP reconnect) or from a handover that never
 * completed; keeping them burns a vif slot and starves hostapd's
 * NEW_INTERFACE with -23/ENFILE.  Runs only after vap_phy_stop(), so no live
 * hostapd owns them.  netifd names are never touched. */
static void vap_phy_drop_leftovers(int phy)
{
    char dirp[96], names[32][OWN_NAME_MAX];
    int n = 0;
    snprintf(dirp, sizeof(dirp), "/sys/class/ieee80211/phy%d/device/net",
             real_phy(phy));
    DIR *d = opendir(dirp);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) && n < 32) {
        if (de->d_name[0] == '.') continue;
        if (!vap_phy_name_of(de->d_name, phy)) continue;
        if (vap_phy_keep_name(de->d_name, phy)) continue;
        if (strlen(de->d_name) >= OWN_NAME_MAX) continue;
        memcpy(names[n], de->d_name, strlen(de->d_name) + 1);
        n++;
    }
    closedir(d);
    for (int i = 0; i < n; i++) {
        int idx;
        if (own_nd_has(names[i], NULL, 0)) continue;
        idx = if_nametoindex(names[i]);
        if (idx <= 0) continue;
        printf("vap: phy%d: dropping leftover %s ifindex=%d\n", phy,
               names[i], idx);
        fflush(stdout);
        vap_netdev_del(idx);
    }
    for (int k = 0; k < 40 && n; k++) {
        int left = 0;
        for (int i = 0; i < n; i++)
            if (if_nametoindex(names[i]) > 0) { left = 1; break; }
        if (!left) break;
        usleep(25000);
    }
}

/* Row-by-row view of what vap_phy_apply() sees.  F45: rows with a start body
 * in the journal were silently left out of the config; this prints the exact
 * field that excluded them. */
static void vap_phy_dump_rows(int phy, int n, int master)
{
    printf("dbg-phy: phy%d apply rows=%d master=%d live=%d\n", phy, n, master,
           (int)vap_phy_pid(phy));
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || (e->port >> 8) != phy) continue;
        printf("dbg-phy:   [%d] port=0x%04x if=%s used=%d active=%d "
               "start=%u owner=%s handed=%d app_len=%u app_hash=%08x "
               "pid=%d ifindex=%d(idx=%d)\n", i, e->port,
               e->ifname[0] ? e->ifname : "-", e->used, e->active,
               e->start_len, own_owner_name(e->owner), e->handed_over,
               e->applied_len, e->applied_hash, e->pid, e->ifindex,
               e->ifname[0] ? read_sysfs_int(e->ifname, "ifindex") : 0);
    }
    fflush(stdout);
}

/* (Re)start the single hostapd for this phy with every journaled VAP. */
static int vap_phy_apply(int phy, const struct cfg *c)
{
    if (phy < 0 || phy >= MAX_RADIOS) return -1;
    if (wl_legacy()) return -1;

    /* F45: clear hostapd children killed earlier so a zombie never looks
     * alive to pid_is_zombie()/own_pid_alive() or counts in pidof. */
    own_reap_children();

    /* Rows with a start body.  The master (lowest vapid) is the netdev hostapd
     * attaches to with `interface=`; it must exist.  Every other BSS is handed
     * over: capagent deletes its netdev and hostapd creates it, the OpenWrt
     * model.  Static `bss=` setup always issues NL80211_CMD_NEW_INTERFACE for
     * a secondary, so leaving our netdev in place only makes hostapd delete
     * and re-create it behind our back (the -23 churn). */
    int n = 0, master = -1;
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!vap_phy_row_cfg(e, phy)) continue;
        n++;
        if (master < 0 || (e->port & 0xff) < (g_own[master].port & 0xff))
            master = i;
    }
    if (vap_dbg_phy()) {
        printf("dbg-phy: phy%d apply entered n=%d master=%d\n", phy, n, master);
        vap_phy_dump_rows(phy, n, master);
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
                if (!vap_phy_row_cfg(e, phy)) continue;
                if (e->applied_len != e->start_len ||
                    e->applied_hash != own_body_hash(e->start, e->start_len)) {
                    if (vap_dbg_phy())
                        printf("dbg-phy: phy%d row %s not in live config "
                               "(app_len=%u start=%u), rebuild\n", phy,
                               e->ifname, e->applied_len, e->start_len);
                    same = 0;
                    break;
                }
            }
            if (same) {
                if (vap_dbg_phy())
                    printf("dbg-phy: phy%d already carries every row, keep "
                           "pid=%d\n", phy, (int)live);
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
            if (vap_dbg_phy())
                printf("dbg-phy: phy%d netdev count %d changed, wait\n",
                       phy, real);
            return -1;
        }
        if (own_now_ms() - last_at[phy] < 2500) {
            if (vap_dbg_phy())
                printf("dbg-phy: phy%d netdev count stable %d for %ums, "
                       "wait\n", phy, real,
                       (unsigned)(own_now_ms() - last_at[phy]));
            return -1;
        }
    }

    char conf[128], pidf[128], logf[128];
    vap_phy_paths(phy, conf, sizeof(conf), pidf, sizeof(pidf),
                  logf, sizeof(logf));
    vap_phy_stop(phy);
    vap_phy_drop_leftovers(phy);

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

    /* The manager derives a primary BSS's address from the radio MAC it was
     * given.  A virtual radio identity (F63) presents a MAC the driver does
     * not expect, and the driver's derived address then differs from the
     * manager's; the manager drops the station's frames in that case.  Set
     * the master netdev to the manager's address before hostapd starts. */
    {
        struct vap *mvp = vap_get(phy, m->port & 0xff);
        if (mvp && (mvp->mgr_bssid[0] | mvp->mgr_bssid[1] |
                    mvp->mgr_bssid[2] | mvp->mgr_bssid[3] |
                    mvp->mgr_bssid[4] | mvp->mgr_bssid[5]) &&
            memcmp(mvp->mgr_bssid, m->bssid, 6) != 0 &&
            set_if_mac(m->ifname, mvp->mgr_bssid) == 0) {
            printf("vap: phy%d master %s BSSID -> manager's %02x:%02x:%02x:"
                   "%02x:%02x:%02x\n", phy, m->ifname, mvp->mgr_bssid[0],
                   mvp->mgr_bssid[1], mvp->mgr_bssid[2], mvp->mgr_bssid[3],
                   mvp->mgr_bssid[4], mvp->mgr_bssid[5]);
            fflush(stdout);
            memcpy(m->bssid, mvp->mgr_bssid, 6);
            g_own_dirty = 1;
        }
    }

    /* Hand the secondary BSSes over to hostapd. */
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        int idx;
        if (i == master || !vap_phy_row_cfg(e, phy))
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
        if (!vap_phy_row_cfg(e, phy)) continue;
        char ctrl[128];
        snprintf(ctrl, sizeof(ctrl), "/var/run/hostapd/%s", e->ifname);
        unlink(ctrl);
        if (vap_dbg_phy())
            printf("dbg-phy: phy%d write %s=%s\n", phy,
                   first ? "interface" : "bss", e->ifname);
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
        for (int i = 0; i < 40; i++) {
            int wst = 0;
            pid_t w = waitpid(hp > 0 ? hp : pid, &wst, WNOHANG);
            if (w == (hp > 0 ? hp : pid) || w < 0) break;
            usleep(25000);
        }
        own_reap_children();
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
            if (!vap_phy_row_cfg(e, phy)) continue;
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
    /* The manager's tx power is a radio setting (0x500b TLV 0x61).  It is
     * applied after the BSS exists because nl80211 needs a live wdev, and
     * values outside a plausible dBm range mean "no explicit setting". */
    if (phy >= 0 && phy < MAX_RADIOS) {
        int dbm = g_phy_txpower[phy];
        if (dbm > 40) dbm = 0;
        for (int i = 0; i < OWN_MAX; i++) {
            struct own_entry *e = &g_own[i];
            if (e->used && e->active && e->ifindex > 0 &&
                (e->port >> 8) == phy) {
                int tr = nl_set_txpower(e->ifindex, dbm);
                if (dbm > 0)
                    printf("vap: phy%d tx-power %d dBm (nl80211 ret=%d)\n",
                           phy, dbm, tr);
                break;
            }
        }
    }
    printf("vap: phy%d hostapd up with %d BSS(es) pid=%d\n", phy, n, (int)hp);
    fflush(stdout);
    return hp > 0 ? (int)hp : -1;
}
