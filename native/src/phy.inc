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

static pid_t vap_phy_pid(int phy)
{
    char conf[128], pidf[128], logf[128];
    vap_phy_paths(phy, conf, sizeof(conf), pidf, sizeof(pidf),
                  logf, sizeof(logf));
    FILE *f = fopen(pidf, "r");
    if (!f) return 0;
    long pid = 0;
    int got = fscanf(f, "%ld", &pid);
    fclose(f);
    if (got != 1 || pid <= 0) return 0;
    if (kill((pid_t)pid, 0) != 0 && errno != EPERM) return 0;
    return (pid_t)pid;
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

/* (Re)start the single hostapd for this phy with every journaled VAP. */
static int vap_phy_apply(int phy, const struct cfg *c)
{
    if (phy < 0 || phy >= MAX_RADIOS) return -1;
    if (wl_legacy()) return -1;

    int n = 0;
    for (int i = 0; i < OWN_MAX; i++) {
        struct own_entry *e = &g_own[i];
        if (e->used && e->active && e->start_len && e->ifname[0] &&
            (e->port >> 8) == phy)
            n++;
    }
    if (!n) return -1;

    char conf[128], pidf[128], logf[128];
    vap_phy_paths(phy, conf, sizeof(conf), pidf, sizeof(pidf),
                  logf, sizeof(logf));
    vap_phy_stop(phy);

    FILE *f = fopen(conf, "w");
    if (!f) return -1;
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
    if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
        fprintf(f, "logger_syslog=-1\nlogger_stdout_level=3\n");
    fclose(f);

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(logf, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        if (getenv("CAPAGENT_HOSTAPD_DEBUG"))
            execl(hostapd_exe_path(), "hostapd", "-dd", "-P", pidf, conf,
                  (char *)NULL);
        else
            execl(hostapd_exe_path(), "hostapd", "-B", "-P", pidf, conf,
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
    if (ready <= 0) {
        printf("vap: phy%d hostapd not ready (%d), see %s\n", phy, ready, logf);
        fflush(stdout);
        if (hp > 0) kill(hp, SIGKILL);
        return -1;
    }
    /* Every journaled VAP of this phy is carried by this one process: record
     * the pid on all of them, otherwise each row's reconcile thinks its
     * hostapd is dead and restarts the phy on every tick. */
    if (hp > 0) {
        for (int i = 0; i < OWN_MAX; i++) {
            struct own_entry *e = &g_own[i];
            if (e->used && e->active && (e->port >> 8) == phy) {
                e->pid = (int)hp;
                e->fail_count = 0;
                e->retry_at = 0;
            }
        }
        g_own_dirty = 1;
        own_save();
    }
    printf("vap: phy%d hostapd up with %d BSS(es) pid=%d\n", phy, n, (int)hp);
    fflush(stdout);
    return hp > 0 ? (int)hp : -1;
}
