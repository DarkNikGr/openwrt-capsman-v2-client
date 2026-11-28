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
 *
 * Exception: a 5/6 GHz phy cannot always bring up a secondary BSS from a
 * shared `bss=` config.  mt76x2e rejects the manager's secondary BSSID
 * (F73/F66); the 6 GHz stack fails in the driver with "Authentication
 * algorithm number required"/"Failed to add BSS" (ag42/ag44).  The solo and
 * 8-radio runs prove that one single-BSS hostapd per interface works on the
 * same phy.  vap_phy_apply_per_vap() therefore starts one such process per
 * journaled 5/6 GHz row, spaced and ack-gated exactly like solo.  2.4 GHz
 * keeps the shared multi-BSS config below.
 *
 * Knob: CAPAGENT_PER_VAP=auto|yes|no (CAPAGENT_5G_PER_VAP is an alias).
 *   auto (default)  per-VAP for a phy with any journaled row >= 4900 MHz
 *                   (5 or 6 GHz); shared multi-BSS for 2.4-only phys.
 *   yes             force per-VAP for every phy (2.4 included; test only).
 *   no              always use the shared multi-BSS config.
 */

/* A second capagent instance (a distinct CAP identity for the same wiphy, see
 * the multi-identity experiment) must not share the per-phy config/pid/log
 * paths with the first one.  CAPAGENT_RUN_TAG adds a suffix to them. */
static int vap_netdev_setmaster(int ifindex, int master_ifindex);
static int vap_phy_row_cfg(const struct own_entry *e, int phy);
static int vap_phy_name_of(const char *name, int phy);
static uint32_t vap_chan_freq(const struct own_entry *e);
static pid_t vap_pervap_title_pid(const char *ifname);
static void vap_pervap_stop_phy(int phy);

static const char *vap_run_tag(void)
{
    const char *t = getenv("CAPAGENT_RUN_TAG");
    return (t && *t) ? t : "";
}

static void vap_phy_paths(int phy, char *conf, size_t cl, char *pidf, size_t pl,
                          char *logf, size_t ll)
{
    const char *t = vap_run_tag();
    /* These files are per real *radio*, not per VAP.  They must NOT use the
     * vap-* names own_cleanup_stale()/own_adopt_pidfiles() scan: those derive
     * an ifname from the file name (phyN here), find no netdev and unlink
     * the live hostapd's config/pid.  The tagged form keeps its historical
     * vap-phyN-<tag>.pid name (multi-identity scripts look for it); the
     * untagged form uses the distinct cap-phyN base. */
    if (*t) {
        snprintf(conf, cl, VAP_CONF_DIR "/cap-phy%d-%s.conf", phy, t);
        snprintf(pidf, pl, "/var/run/vap-phy%d-%s.pid", phy, t);
        snprintf(logf, ll, "/tmp/vap-phy%d-%s.log", phy, t);
    } else {
        snprintf(conf, cl, VAP_CONF_DIR "/cap-phy%d.conf", phy);
        snprintf(pidf, pl, "/var/run/cap-phy%d.pid", phy);
        snprintf(logf, ll, "/tmp/vap-phy%d.log", phy);
    }
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

/* hostapd rewrites its argv after startup, so the config path is no longer
 * in /proc/<pid>/cmdline.  /proc/<pid>/comm survives and identifies the
 * daemon; the pid file name already ties the pid to this logical radio. */
static int vap_proc_is_hostapd(pid_t pid)
{
    char p[64], b[32];
    snprintf(p, sizeof(p), "/proc/%ld/comm", (long)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return 0;
    b[n] = 0;
    return !strncmp(b, "hostapd", 7) || !strncmp(b, "wpad", 4);
}

/* pid_is_zombie() lives in ownership.inc (shared with own_pid_alive). */

/* Knob parser: -1 auto, 0 shared multi-BSS, 1 one hostapd per BSS.
 * CAPAGENT_PER_VAP wins; CAPAGENT_5G_PER_VAP is the historical alias the
 * ag37 prototype used, so an existing /etc/cap/capagent.conf keeps working.
 * Unknown values fall back to auto and say so once (a typo must not silently
 * disable the 6 GHz workaround). */
static int vap_pervap_env(void)
{
    const char *v = getenv("CAPAGENT_PER_VAP");
    static int warned;
    if (!v || !*v) v = getenv("CAPAGENT_5G_PER_VAP");
    if (!v || !*v) return -1;
    if (!strcasecmp(v, "auto")) return -1;
    if (!strcasecmp(v, "yes") || !strcasecmp(v, "on") ||
        !strcasecmp(v, "true") || !strcmp(v, "1"))
        return 1;
    if (!strcasecmp(v, "no") || !strcasecmp(v, "off") ||
        !strcasecmp(v, "false") || !strcmp(v, "0"))
        return 0;
    if (!warned) {
        printf("vap: unknown CAPAGENT_PER_VAP='%s', using auto\n", v);
        fflush(stdout);
        warned = 1;
    }
    return -1;
}

/* One hostapd process per BSS on this phy.  Auto-detection is journal-based,
 * not driver-based: any row on the phy that the manager provisioned for
 * 5/6 GHz selects per-VAP, so mt76x02 5 GHz, 6 GHz (mt7915/mt7996/wifi6/7
 * and hwsim) all get the layout that works, while a 2.4-only phy keeps the
 * single multi-BSS hostapd.  The row's own 0x6016 0x0a descriptor is used
 * (a secondary's 0x500b may carry a placeholder 2412 MHz); e->freq is the
 * fallback for a body without 0x0a. */
static int vap_pervap_wanted(int phy)
{
    int force = vap_pervap_env();

    if (force >= 0) return force;
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!vap_phy_row_cfg(e, phy)) continue;
        if (vap_chan_freq(e) >= 4900) return 1;
    }
    return 0;
}

/* Pid of the single-BSS hostapd for one interface.  The per-VAP files use
 * the historical vap-<ifname> names: the ifname is a real netdev, so
 * own_adopt_pidfiles()/own_cleanup_stale() handle a crash correctly (unlike
 * the phy-wide vap-phyN.pid, whose name has no netdev). */
static pid_t vap_pervap_pid(const char *ifname)
{
    char conf[128], pidf[128];
    FILE *f;
    long fpid = 0;

    if (!ifname || !*ifname) return 0;
    vap_paths(ifname, conf, sizeof(conf), pidf, sizeof(pidf));
    f = fopen(pidf, "r");
    if (f) {
        int got = fscanf(f, "%ld", &fpid);
        fclose(f);
        if (got == 1 && fpid > 0) {
            if (pid_is_zombie((pid_t)fpid)) {
                int wst;
                waitpid((pid_t)fpid, &wst, WNOHANG);
            } else if (kill((pid_t)fpid, 0) == 0 || errno == EPERM) {
                /* Verify the pid really is *this* BSS: the config path
                 * (before hostapd rewrites argv) or the exact title
                 * "hostapd: <ifname>" (after).  A recycled pid that belongs
                 * to another hostapd must never be returned or killed. */
                if (vap_proc_has_conf((pid_t)fpid, conf) ||
                    vap_pervap_title_pid(ifname) == (pid_t)fpid)
                    return (pid_t)fpid;
            }
        }
    }
    /* hostapd may leave the -P file empty; fall back to the exact config
     * path in /proc (works for the pre-rewrite window and -dd runs). */
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
    return found;
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
                   (vap_proc_has_conf((pid_t)fpid, conf) ||
                    vap_proc_is_hostapd((pid_t)fpid)))
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
    /* Per-VAP mode: this ifname has its own single-BSS hostapd.  A per-VAP
     * pid file only exists for a real netdev name, so the check is safe in
     * shared mode too (there it simply finds nothing). */
    {
        pid_t pv = vap_pervap_pid(ifname);
        if (pv > 0) return pv;
    }
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

/* Exact /proc title lookup for a single-BSS hostapd after it rewrote argv
 * ("hostapd: <ifname>").  This is stricter than vap_find_hostapd()'s
 * substring scan on purpose: with a shared multi-BSS hostapd the title names
 * only the primary interface, and a substring match could kill the whole
 * radio from a per-row stop path. */
static pid_t vap_pervap_title_pid(const char *ifname)
{
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    pid_t found = 0;
    size_t nl = strlen(ifname);
    while ((de = readdir(d))) {
        char *end = NULL;
        long c = strtol(de->d_name, &end, 10);
        char p[64], buf[512];
        const char *t = NULL;
        ssize_t n;
        int fd;
        if (!end || *end || c <= 0 || pid_is_zombie((pid_t)c)) continue;
        if (!vap_proc_is_hostapd((pid_t)c)) continue;
        snprintf(p, sizeof(p), "/proc/%ld/cmdline", c);
        fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        if (!strncmp(buf, "hostapd: ", 9)) t = buf + 9;
        else if (!strncmp(buf, "wpad: ", 6)) t = buf + 6;
        if (t && strlen(t) >= nl && !strncmp(t, ifname, nl) &&
            (t[nl] == 0 || t[nl] == ' ')) {
            found = (pid_t)c;
            break;
        }
    }
    closedir(d);
    return found;
}

/* Stop one per-VAP hostapd and remove its pid file.  Resolve the pid exactly
 * as the start path does (pid file, then our config path in /proc, then the
 * exact process title), so a pidfile that was already unlinked or emptied
 * cannot hide a live process on the netdev.  Without this the next start
 * inherited a stale daemon on the same vif and failed with "Could not
 * configure driver mode". */
static void vap_pervap_stop_ifname(const char *ifname)
{
    char conf[128], pidf[128];
    pid_t pid, hp;

    if (!ifname || !*ifname || !own_name_ok(ifname)) return;
    vap_paths(ifname, conf, sizeof(conf), pidf, sizeof(pidf));
    pid = vap_pervap_pid(ifname);
    if (pid > 0) {
        printf("vap: stopping per-VAP hostapd %s pid=%d\n", ifname, (int)pid);
        fflush(stdout);
        own_stop_pid((int)pid);
    }
    /* The daemon may have rewritten its title and lost the -P file; the
     * exact title scan finds it too. */
    hp = vap_pervap_title_pid(ifname);
    if (hp > 0 && hp != pid) {
        printf("vap: stopping untracked per-VAP hostapd %s pid=%d\n",
               ifname, (int)hp);
        fflush(stdout);
        own_stop_pid((int)hp);
    }
    unlink(pidf);
}

/* Every per-VAP hostapd of one real phy: the journal rows, every netdev the
 * phy currently exposes under a capagent name, and any vap-*.pid left by an
 * older journal/slot.  Called before a phy rebuild, a width change and a
 * mode switch, so no stale process can own the radio or a vif. */
static void vap_pervap_stop_phy(int phy)
{
    char dirp[128];

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->ifname[0] || (e->port >> 8) != phy) continue;
        vap_pervap_stop_ifname(e->ifname);
    }
    snprintf(dirp, sizeof(dirp), "/sys/class/ieee80211/phy%d/device/net",
             real_phy(phy));
    DIR *d = opendir(dirp);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            if (!vap_phy_name_of(de->d_name, phy)) continue;
            vap_pervap_stop_ifname(de->d_name);
        }
        closedir(d);
    }
    d = opendir("/var/run");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            size_t l = strlen(de->d_name);
            char nm[OWN_NAME_MAX];
            if (l < 9 || strncmp(de->d_name, "vap-", 4) ||
                strcmp(de->d_name + l - 4, ".pid"))
                continue;
            if (l - 4 >= sizeof(nm)) continue;
            memcpy(nm, de->d_name + 4, l - 4 - 4);
            nm[l - 4 - 4] = 0;
            if (!vap_phy_name_of(nm, phy)) continue;
            vap_pervap_stop_ifname(nm);
        }
        closedir(d);
    }
    own_reap_children();
}

static void vap_phy_stop(int phy)
{
    /* Per-VAP mode: one hostapd per journaled BSS.  Stop every one (and any
     * stale one) before a teardown/rejoin; an incremental vap_phy_apply()
     * never reaches here.  In shared mode this also cleans a phy that is
     * switching back from per-VAP. */
    vap_pervap_stop_phy(phy);
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

/* Logger options are global: hostapd only honours them before the first
 * interface=/bss= section. */
static void vap_phy_logger(FILE *f)
{
    if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
        /* stdout to a file is block-buffered, so a long-running hostapd
         * leaves its last lines unwritten and every diagnostic read from
         * /tmp/vap-phyN.log is truncated.  Syslog is flushed per message, so
         * the debug build logs there too and `logread` is the real trace. */
        fprintf(f, "logger_syslog=0\nlogger_syslog_level=1\n"
                   "logger_stdout=-1\nlogger_stdout_level=0\n");
}

/* The channel context a BSS must use.  The manager repeats the chosen
 * channel descriptor in the 0x6016 body's 0x0a element (0x0b freq, 0x0c
 * width, 0x10 band).  A secondary VAP's 0x500b request often carries a
 * placeholder (2412 MHz on a 6 GHz profile), so the start body is
 * authoritative when it has a frequency; e->freq is only the fallback. */
static uint32_t vap_chan_freq(const struct own_entry *e)
{
    const uint8_t *chv = NULL;
    uint16_t cl = 0, p = 0;
    if (find_el(e->start, e->start_len, 0x0a, &chv, &cl)) {
        while (p + 4 <= cl) {
            uint16_t t = rd16(chv + p), l = rd16(chv + p + 2);
            p += 4;
            if (p + l > cl) break;
            if (t == 0x0b && l == 4) {
                uint32_t f = rd32(chv + p);
                if (f) return f;
            }
            p += l;
        }
    }
    return e->freq;
}

/* Write the per-BSS options from a journal row.  per_vap=1 writes a
 * single-interface config (one hostapd process per BSS): no bridge= because
 * several hostapd processes on one real phy cannot open a bridged AP vif
 * while a sibling AP is already up; those BSSes are bridged after start.
 * chan_src supplies the channel context (freq + 0x0a width/band): the
 * per-VAP writer passes the master row for every BSS, so all processes start
 * on the radio's real channel instead of a sibling's placeholder 0x500b. */
static void vap_phy_bss(FILE *f, const char *kw, const struct own_entry *e,
                        const struct cfg *c, int is_first, int per_vap,
                        const struct own_entry *chan_src)
{
    const uint8_t *ssid = NULL, *ie = NULL, *chv = NULL;
    uint16_t sl = 0, il = 0, cl = 0;
    const struct own_entry *ch = chan_src ? chan_src : e;
    uint32_t chan_freq = vap_chan_freq(ch);
    find_el(e->start, e->start_len, 0x03, &ssid, &sl);
    find_el(e->start, e->start_len, 0x04, &ie, &il);
    find_el(ch->start, ch->start_len, 0x0a, &chv, &cl);
    const uint8_t *dtv = NULL;
    uint16_t dtl = 0;
    find_el(e->start, e->start_len, 0x24, &dtv, &dtl);

    struct rsn_info ri;
    rsn_parse(ie, il, &ri);
    struct rsn_policy rp;
    rsn_policy_from_ie(&ri, hostapd_has_sae_override(), &rp);
    /* NEWPHY 0x84 bit 9 (caps84[1] 0x02) is set whenever the phy has a
     * >= 5925 MHz frequency, i.e. the CAP tells the manager it supports
     * beacon protection.  Actually enable it on the matching BSS, or the
     * claim is only a join gate.  hostapd requires PMF, and the option
     * name is beacon_prot in the 2.10+ sample config; probe the binary so
     * an older/patched hostapd cannot make the whole phy config invalid. */
    if (chan_freq >= 5925 && rp.wpa && rp.ieee80211w &&
        hostapd_has_opt("beacon_prot"))
        rp.beacon_prot = 1;
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
     * explicitly; it applies it when it creates the interface.  This is the
     * ONLY bssid= line: the old code wrote mgr_bssid here and e->bssid later,
     * and the later line silently overrode the manager's slave BSSID. */
    {
        struct vap *vp = vap_get(e->port >> 8, e->port & 0xff);
        const uint8_t *bss = e->bssid;
        if (vp && (vp->mgr_bssid[0] | vp->mgr_bssid[1] | vp->mgr_bssid[2] |
                   vp->mgr_bssid[3] | vp->mgr_bssid[4] | vp->mgr_bssid[5]))
            bss = vp->mgr_bssid;
        fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                bss[0], bss[1], bss[2], bss[3], bss[4], bss[5]);
        if (vp && bss == vp->mgr_bssid && memcmp(vp->mgr_bssid, e->bssid, 6))
            printf("vap: %s: hostapd BSSID = manager's "
                   "%02x:%02x:%02x:%02x:%02x:%02x (was %02x:%02x:%02x:%02x:%02x:%02x)\n",
                   e->ifname, bss[0], bss[1], bss[2], bss[3], bss[4], bss[5],
                   e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3],
                   e->bssid[4], e->bssid[5]);
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
        vap_write_channel(f, chan_freq, vap_mgr_width(chv, cl),
                          chan_freq >= 5925 && phy_has_eht(ch->port >> 8) &&
                          hostapd_has_eht());
    }
    /* dtim-period is per VAP (0x6016 TLV 0x24, a u32). */
    if (dtv && dtl >= 4) {
        uint32_t d = rd32(dtv);
        if (d) fprintf(f, "dtim_period=%u\n", d);
    }
    if (ssid && sl) fprintf(f, "ssid=%.*s\n", (int)sl, (const char *)ssid);
    /* CAPAGENT_RRM advertises the RM Enabled Capabilities element so a
     * station enables its own RRM (and answers beacon-report requests).  The
     * manager does not send RRM caps in 0x6016, so this is opt-in. */
    if (getenv("CAPAGENT_RRM"))
        fprintf(f, "rrm_neighbor_report=1\nrrm_beacon_report=1\n");
    /* With one hostapd per phy the kernel can bridge the interface while
     * hostapd brings it up.  When several capagent instances share the phy
     * (multi-identity, CAPAGENT_RUN_TAG) or several logical radios share one
     * real phy (solo), opening a bridged AP vif on a phy that already has a
     * running AP returns EBUSY on the 5 GHz driver, so those BSSes bridge
     * after hostapd is up. */
    if (bridge[0] && !per_vap && !*ap_tag() && !getenv("CAPAGENT_NO_BRIDGE") &&
        !real_phy_shared(e->port >> 8, c->nradios))
        fprintf(f, "bridge=%s\n", bridge);

    char rsn[256];
    rsn_conf_write(rsn, sizeof(rsn), &rp);
    fputs(rsn, f);
    if (rp.wpa) {
        if (hostapd_has_opt("external_rsn_sae") && !rp.local_owe)
            fprintf(f, "external_rsn_sae=1\n");
        if (c->ext_auth_dir && !rp.local_owe)
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

/* ---- one hostapd process per VAP ------------------------------------- */

/* The address the manager assigned to this VAP (0x08), not the driver-derived
 * one: the manager drops frames whose addr1/addr3 differs, and the PTK is
 * derived over this BSSID. */
static void vap_pervap_addr(const struct own_entry *e, uint8_t out[6])
{
    struct vap *vp = vap_get(e->port >> 8, e->port & 0xff);
    memcpy(out, e->bssid, 6);
    if (vp && (vp->mgr_bssid[0] | vp->mgr_bssid[1] | vp->mgr_bssid[2] |
               vp->mgr_bssid[3] | vp->mgr_bssid[4] | vp->mgr_bssid[5]))
        memcpy(out, vp->mgr_bssid, 6);
}

/* Create (or adopt) the netdev and give it the manager's BSSID, down, before
 * hostapd attaches.  hostapd uses an existing interface for its primary BSS
 * (use_existing is unconditional for the first BSS even without patch
 * 9999c), so the mt76x02 BSS index is the one the manager's MAC selected at
 * NEW_INTERFACE time instead of one hostapd derives later. */
static int vap_pervap_prepare(int phy, struct own_entry *e)
{
    uint8_t want[6], cur[6];
    int idx;

    vap_pervap_addr(e, want);
    idx = if_nametoindex(e->ifname);
    if (idx <= 0)
        idx = vap_netdev_create(phy, e->ifname, want);
    if (idx <= 0) return 0;
    if (read_sysfs_mac(e->ifname, cur) != 0 || memcmp(cur, want, 6) != 0) {
        set_if_flags(e->ifname, 0);
        if (set_if_mac(e->ifname, want) != 0)
            printf("vap: %s: cannot set BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
                   e->ifname, want[0], want[1], want[2], want[3], want[4],
                   want[5]);
    }
    set_if_flags(e->ifname, 0);
    memcpy(e->bssid, want, 6);
    e->ifindex = idx;
    e->handed_over = 0;
    g_own_dirty = 1;
    return idx;
}

static pid_t vap_pervap_fork(const char *conf, const char *pidf,
                             const char *logf)
{
    pid_t pid = fork();
    if (pid != 0) return pid;
    int fd = open(logf, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
    if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
        execl(hostapd_exe_path(), "hostapd", "-dd", "-P", pidf, conf,
              (char *)NULL);
    else
        execl(hostapd_exe_path(), "hostapd", "-P", pidf, conf, (char *)NULL);
    _exit(127);
}

static const char *vap_pervap_spacing_env(void)
{
    const char *s = getenv("CAPAGENT_PER_VAP_SPACING_MS");
    return (s && *s) ? s : "4000";
}

/* Fingerprint of the channel context (0x0a element + effective freq).  Every
 * per-VAP process on a phy must follow the master's channel; when the
 * manager changes width/band/channel there, all of them must restart even
 * though only the master's start body changed. */
static uint32_t vap_chan_ctx_hash(const struct own_entry *chan)
{
    const uint8_t *chv = NULL;
    uint16_t cl = 0;
    uint32_t h = 2166136261u, f = vap_chan_freq(chan);
    if (find_el(chan->start, chan->start_len, 0x0a, &chv, &cl))
        for (uint16_t i = 0; i < cl; i++) {
            h ^= chv[i];
            h *= 16777619u;
        }
    for (int i = 0; i < 4; i++) {
        h ^= (f >> (8 * i)) & 0xff;
        h *= 16777619u;
    }
    return h ? h : 1u;
}

/* applied_cfg_hash stores the row's own config hash folded with the master
 * channel context, so a width/band change on the master restarts siblings. */
static uint32_t vap_pervap_cfg_hash(const struct own_entry *e,
                                    const struct own_entry *chan)
{
    uint32_t h = own_cfg_hash(e->start, e->start_len);
    uint32_t c = vap_chan_ctx_hash(chan);
    h ^= c;
    h *= 16777619u;
    return h ? h : 1u;
}

static int vap_pervap_in_rows(const char *name, struct own_entry **rows, int n)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(rows[i]->ifname, name)) return 1;
    return 0;
}

/* Stop per-VAP daemons of this phy that are not part of the current row set:
 * a renumbered manager slot or a profile that moved to a new ifname leaves a
 * hostapd on the old vif, and it keeps the radio/vif slot busy ("Could not
 * configure driver mode" for the replacement). */
static void vap_pervap_prune_phy(int phy, struct own_entry **rows, int n)
{
    char dirp[128];

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!e->used || !e->ifname[0] || (e->port >> 8) != phy) continue;
        if (vap_pervap_in_rows(e->ifname, rows, n)) continue;
        vap_pervap_stop_ifname(e->ifname);
    }
    snprintf(dirp, sizeof(dirp), "/sys/class/ieee80211/phy%d/device/net",
             real_phy(phy));
    DIR *d = opendir(dirp);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            if (!vap_phy_name_of(de->d_name, phy)) continue;
            if (vap_pervap_in_rows(de->d_name, rows, n)) continue;
            vap_pervap_stop_ifname(de->d_name);
        }
        closedir(d);
    }
    d = opendir("/var/run");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            size_t l = strlen(de->d_name);
            char nm[OWN_NAME_MAX];
            if (l < 9 || strncmp(de->d_name, "vap-", 4) ||
                strcmp(de->d_name + l - 4, ".pid"))
                continue;
            if (l - 8 >= sizeof(nm)) continue;
            memcpy(nm, de->d_name + 4, l - 8);
            nm[l - 8] = 0;
            if (!vap_phy_name_of(nm, phy)) continue;
            if (vap_pervap_in_rows(nm, rows, n)) continue;
            vap_pervap_stop_ifname(nm);
        }
        closedir(d);
    }
}

static int vap_phy_apply_per_vap(int phy, const struct cfg *c)
{
    struct own_entry *rows[OWN_MAX];
    struct own_entry *chan;
    int n = 0, master = -1, ok = 0, failed = 0, anylive = 0;
    int rp = real_phy(phy);
    static uint64_t last_start_ms[16];

    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (!vap_phy_row_cfg(e, phy)) continue;
        rows[n++] = e;
        if (master < 0 || (e->port & 0xff) < (g_own[master].port & 0xff))
            master = i;
        if (vap_pervap_pid(e->ifname) > 0) anylive = 1;
    }
    if (!n || master < 0) return -1;
    /* The master row is the radio's channel context for every process:
     * its 0x6016 0x0a descriptor is the real freq/width; a sibling's 0x500b
     * frequency can be a placeholder (2412 for a 6 GHz profile). */
    chan = &g_own[master];

    own_reap_children();
    /* Remove daemons that are not part of the current row set.  Leftover
     * netdevs can only be dropped when nothing is alive; deleting a vif
     * under a live hostapd kills the whole radio. */
    vap_pervap_prune_phy(phy, rows, n);
    if (!anylive)
        vap_phy_stop(phy);          /* also clears a shared-mode daemon */
    vap_phy_drop_leftovers(phy);

    /* Keep healthy daemons, stop only a row whose configuration or whose
     * master channel context changed. */
    int keep[OWN_MAX] = {0};
    for (int k = 0; k < n; k++) {
        struct own_entry *e = rows[k];
        pid_t live = vap_pervap_pid(e->ifname);
        if (live <= 0) continue;
        if (e->applied_len == e->start_len &&
            e->applied_hash == own_body_hash(e->start, e->start_len) &&
            e->applied_cfg_hash == vap_pervap_cfg_hash(e, chan)) {
            keep[k] = 1;
            e->pid = (int)live;
            e->ifindex = if_nametoindex(e->ifname);
            if (e->ifindex > 0) {
                own_mirror(e);
                cap_vap_refresh(phy, e->port & 0xff, e->ifindex, e->ifname,
                                e->bssid, c);
            }
            continue;
        }
        printf("vap: phy%d: %s profile changed, restarting its hostapd\n",
               phy, e->ifname);
        fflush(stdout);
        vap_pervap_stop_ifname(e->ifname);
    }

    long spacing = strtol(vap_pervap_spacing_env(), NULL, 10);
    if (spacing < 0) spacing = 0;
    if (spacing > 60000) spacing = 60000;
    int r0 = (rp >= 0 && rp < 16) ? rp : 0;

    int picked[OWN_MAX] = {0};
    for (int done = 0; done < n; done++) {
        int pick = -1;
        for (int k = 0; k < n; k++) {
            if (picked[k]) continue;
            if (pick < 0 ||
                (rows[k]->port & 0xff) < (rows[pick]->port & 0xff))
                pick = k;
        }
        if (pick < 0) break;
        picked[pick] = 1;
        struct own_entry *e = rows[pick];
        if (keep[pick]) {
            ok++;
            continue;
        }
        if (last_start_ms[r0]) {
            uint64_t now = own_now_ms();
            if (now < last_start_ms[r0] + (uint64_t)spacing) {
                uint64_t wait = last_start_ms[r0] + (uint64_t)spacing - now;
                printf("vap: phy%d: per-VAP spacing %llums before %s\n", phy,
                       (unsigned long long)wait, e->ifname);
                fflush(stdout);
                usleep((useconds_t)wait * 1000);
            }
        }
        if (vap_pervap_prepare(phy, e) <= 0) {
            printf("vap: phy%d: %s could not be prepared\n", phy, e->ifname);
            fflush(stdout);
            failed++;
            continue;
        }
        char conf[128], pidf[128], logf[128];
        vap_paths(e->ifname, conf, sizeof(conf), pidf, sizeof(pidf));
        snprintf(logf, sizeof(logf), "/tmp/vap-%s.log", e->ifname);
        FILE *f = fopen(conf, "w");
        if (!f) { failed++; continue; }
        vap_phy_logger(f);
        vap_phy_bss(f, "interface", e, c, 1, 1, chan);
        fclose(f);
        unlink(pidf);
        last_start_ms[r0] = own_now_ms();
        pid_t pid = vap_pervap_fork(conf, pidf, logf);
        if (pid < 0) { failed++; continue; }
        int st = 0, reaped = 0;
        for (int i = 0; i < 40; i++) {
            pid_t r = waitpid(pid, &st, WNOHANG);
            if (r == pid) { reaped = 1; break; }
            if (r < 0) break;
            usleep(100000);
        }
        if (reaped && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
            printf("vap: phy%d: %s hostapd failed to start (status=%d), see "
                   "%s\n", phy, e->ifname,
                   WIFEXITED(st) ? WEXITSTATUS(st) : -1, logf);
            fflush(stdout);
            failed++;
            continue;
        }
        int ready = vap_wait_ap_enabled(logf, 15000);
        pid_t hp = vap_pervap_pid(e->ifname);
        if (hp <= 0) {
            int wst = 0;
            if (waitpid(pid, &wst, WNOHANG) == 0) hp = pid;
        }
        if (ready <= 0) {
            printf("vap: phy%d: %s hostapd not ready (%d), see %s\n", phy,
                   e->ifname, ready, logf);
            fflush(stdout);
            if (hp > 0) own_stop_pid((int)hp);
            else if (pid > 0) own_stop_pid((int)pid);
            e->applied_len = 0;
            failed++;
            continue;
        }
        FILE *pf = fopen(pidf, "w");
        if (pf) { fprintf(pf, "%d\n", (int)hp); fclose(pf); }
        e->pid = (int)hp;
        e->fail_count = 0;
        e->retry_at = 0;
        e->start_given_up = 0;
        e->ifindex = if_nametoindex(e->ifname);
        e->applied_len = e->start_len;
        e->applied_hash = own_body_hash(e->start, e->start_len);
        e->applied_cfg_hash = vap_pervap_cfg_hash(e, chan);
        if (e->ifindex > 0) own_mirror(e);
        cap_vap_refresh(phy, e->port & 0xff, e->ifindex, e->ifname, e->bssid,
                        c);
        ok++;
        printf("vap: phy%d: %s AP-ENABLED pid=%d\n", phy, e->ifname, (int)hp);
        fflush(stdout);
    }

    /* The manager's tx power is a radio setting; apply it once, through any
     * live BSS of the phy. */
    if (phy >= 0 && phy < MAX_RADIOS) {
        int dbm = g_phy_txpower[phy];
        if (dbm > 40) dbm = 0;
        for (int k = 0; k < n; k++) {
            if (rows[k]->pid > 0 && rows[k]->ifindex > 0) {
                int tr = nl_set_txpower(rows[k]->ifindex, dbm);
                if (dbm > 0)
                    printf("vap: phy%d tx-power %d dBm (nl80211 ret=%d)\n",
                           phy, dbm, tr);
                break;
            }
        }
    }
    /* bridge= was deliberately omitted from every single-BSS config: a
     * bridged AP vif is EBUSY when a sibling AP is already up on mt76x2e.
     * Join the VLAN bridge only after the BSS is AP-ENABLED, and only when
     * the kernel does not already report it as a port of that bridge (the
     * 1 Hz reconcile calls this path repeatedly; an unconditional SETLINK
     * printed an error every tick on an already-enslaved vif). */
    for (int k = 0; k < n; k++) {
        struct own_entry *e = rows[k];
        char bridge[32] = "", mp[96], lnk[128];
        if (!e->vlan || e->applied_len != e->start_len) continue;
        /* Same bridge name the shared writer would use (vap_bridge_if_present
         * honours a pre-existing br-vlanN/bond). */
        vap_bridge_if_present(e->ifname, e->vlan, bridge, sizeof(bridge));
        if (!bridge[0]) continue;
        int bidx = if_nametoindex(bridge);
        int idx = if_nametoindex(e->ifname);
        if (bidx <= 0 || idx <= 0) continue;
        snprintf(mp, sizeof(mp), "/sys/class/net/%s/master", e->ifname);
        ssize_t ln = readlink(mp, lnk, sizeof(lnk) - 1);
        if (ln > 0) {
            const char *bn;
            lnk[ln] = 0;
            bn = strrchr(lnk, '/');
            bn = bn ? bn + 1 : lnk;
            if (!strcmp(bn, bridge)) continue;
        }
        int mr = vap_netdev_setmaster(idx, bidx);
        printf("vap: phy%d %s -> %s (rc=%d)\n", phy, e->ifname, bridge, mr);
        fflush(stdout);
    }
    g_own_dirty = 1;
    own_save();
    printf("vap: phy%d per-VAP hostapd: %d/%d up (%d failed)\n", phy, ok, n,
           failed);
    fflush(stdout);
    if (failed) return -1;
    return g_own[master].pid > 0 ? g_own[master].pid
                                 : (ok ? (int)vap_pervap_pid(
                                             g_own[master].ifname)
                                       : -1);
}

/* (Re)start the single hostapd for this phy with every journaled VAP. */
static int vap_phy_apply(int phy, const struct cfg *c)
{
    static uint64_t real_apply_ms[16];
    int rp0;
    uint64_t now0;

    if (phy < 0 || phy >= MAX_RADIOS) return -1;
    if (wl_legacy()) return -1;

    /* Solo (one identity, several logical radios on one real phy) starts one
     * hostapd per logical radio in a burst.  The driver/hostapd needs the
     * previous AP to be stable before the next NEW_INTERFACE; otherwise the
     * third/fourth 5 GHz BSS is torn down as a transient orphan.  Keep a
     * minimum gap per real phy (the manual multi-identity launcher uses 15 s;
     * 4 s is enough here because the previous AP-ENABLED wait is already
     * included). */
    rp0 = real_phy(phy);
    now0 = own_now_ms();
    if (rp0 >= 0 && rp0 < 16 && real_apply_ms[rp0] &&
        now0 < real_apply_ms[rp0] + 4000) {
        uint64_t wait = real_apply_ms[rp0] + 4000 - now0;
        printf("vap: phy%d spacing %llums on real phy%d\n", phy,
               (unsigned long long)wait, rp0);
        fflush(stdout);
        usleep((useconds_t)wait * 1000);
        now0 = own_now_ms();
    }
    if (rp0 >= 0 && rp0 < 16)
        real_apply_ms[rp0] = now0;

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

    /* One hostapd per BSS on an mt76x02 5 GHz phy (or CAPAGENT_5G_PER_VAP=1):
     * the shared `bss=` config cannot bring up its secondaries, while a
     * one-BSS process per VAP is exactly the mode the 8-radio/solo runs
     * proved.  Each row has its own config/pid/log and is started, kept and
     * stopped independently. */
    if (vap_pervap_wanted(phy))
        return vap_phy_apply_per_vap(phy, c);

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
        /* CAPAGENT_KEEP_SEC keeps the pre-created secondary netdevs so they
         * can carry the BSSID the manager assigned (the driver derives its
         * own addresses for interfaces hostapd creates).  hostapd attaches
         * via the use_existing patch; the bridge is joined after start. */
        if (getenv("CAPAGENT_KEEP_SEC")) {
            struct vap *kvp = vap_get(e->port >> 8, e->port & 0xff);
            uint8_t want[6];
            memcpy(want, e->bssid, 6);
            if (kvp && (kvp->mgr_bssid[0] | kvp->mgr_bssid[1] |
                        kvp->mgr_bssid[2] | kvp->mgr_bssid[3] |
                        kvp->mgr_bssid[4] | kvp->mgr_bssid[5]))
                memcpy(want, kvp->mgr_bssid, 6);
            idx = if_nametoindex(e->ifname);
            if (idx <= 0)
                idx = vap_netdev_create(phy, e->ifname, want);
            if (idx > 0 && (memcmp(want, e->bssid, 6) != 0 ||
                            idx <= 0))
                set_if_mac(e->ifname, want);
            if (idx > 0) {
                set_if_flags(e->ifname, 0);
                printf("vap: phy%d keeping %s with BSSID "
                       "%02x:%02x:%02x:%02x:%02x:%02x for hostapd\n",
                       phy, e->ifname, want[0], want[1], want[2], want[3],
                       want[4], want[5]);
                fflush(stdout);
                memcpy(e->bssid, want, 6);
                e->ifindex = idx;
                e->handed_over = 0;
                g_own_dirty = 1;
            }
            continue;
        }
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
    vap_phy_logger(f);
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
        vap_phy_bss(f, first ? "interface" : "bss", e, c, first, 0, NULL);
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
            e->applied_cfg_hash = own_cfg_hash(e->start, e->start_len);
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
    /* Tagged (multi-identity) instances could not use hostapd's bridge= on
     * 5 GHz; the same is true when several logical radios share one real
     * phy.  Join each BSS to its VLAN bridge now that it is up. */
    if (*ap_tag() || getenv("CAPAGENT_NO_BRIDGE") ||
        real_phy_shared(phy, c->nradios)) {
        for (int i = 0; i < OWN_MAX; i++) {
            struct own_entry *e = &g_own[i];
            if (!vap_phy_row_cfg(e, phy) || !e->vlan) continue;
            char br[32];
            snprintf(br, sizeof(br), "br-vlan%u", e->vlan);
            int bidx = if_nametoindex(br);
            int idx = if_nametoindex(e->ifname);
            if (bidx <= 0 || idx <= 0) continue;
            int mr = vap_netdev_setmaster(idx, bidx);
            printf("vap: phy%d %s -> %s (rc=%d)\n", phy, e->ifname, br, mr);
            fflush(stdout);
        }
    }
    printf("vap: phy%d hostapd up with %d BSS(es) pid=%d\n", phy, n, (int)hp);
    fflush(stdout);
    return hp > 0 ? (int)hp : -1;
}

/* F80: does this port belong to a pure-OWE BSS completed by hostapd?  The
 * live VAP registry answers while a 0x6016 is in force.  After a capagent
 * restart (vap->used == 0 until the manager re-sends the start body) fall
 * back to the journaled 0x6016 body, so the key/Auth plane never mistakes a
 * local-OWE BSS for a manager-relay one.  Used by 0x201c/0x201f and by
 * cap_vap_ready() (forward-declared in mgmt.inc). */
static int own_port_local_owe(uint16_t port)
{
    struct vap *vp = vap_get((port >> 8) & 0xff, port & 0x0f);
    struct own_entry *e;
    const uint8_t *ie = NULL;
    uint16_t il = 0;
    struct rsn_info ri;

    if (vp && vp->local_owe) return 1;
    e = own_by_port(port);
    if (!e || !e->start_len) return 0;
    if (!find_el(e->start, e->start_len, 0x04, &ie, &il)) return 0;
    rsn_parse(ie, il, &ri);
    return rsn_local_owe(&ri);
}
