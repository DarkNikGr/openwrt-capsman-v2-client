/* vap.inc — create the AP netdev and the hostapd instance for a VAP that the
 * manager provisioned (0x500b create + 0x6016 start).
 *
 * Part of capagent.c (single translation unit; included after channels.inc).
 *
 * Design notes
 * ------------
 * The manager never sends a configuration file.  It sends:
 *   0x500b  port=(phy<<8)|vapid  MAC (0x08), VLAN (0x7d)
 *   0x6016  port=(phy<<8)|vapid  SSID (0x03), IE blob (0x04), channel (0x0a)
 * That is everything needed to bring up a BSS: the RSN IE in 0x04 carries the
 * AKM/cipher/PMF policy, and the passphrase is NOT part of it because the
 * manager is the RSN authenticator.
 *
 * So for every VAP whose netdev does not exist we:
 *   1. NL80211_CMD_NEW_INTERFACE type __ap on the wiphy, with the MAC from
 *      0x500b, and bring it up;
 *   2. write a hostapd config with external_rsn_auth=1 (no PSK at all) and an
 *      ext_auth_socket that capagent binds;
 *   3. start hostapd for it.
 *
 * Interfaces that already exist (netifd/hostapd owns them, e.g. a legacy
 * /etc/config/wireless) are left completely alone.
 */

#define VAP_CONF_DIR "/tmp"

/* Regulatory country for hostapd.  CAPsMAN v2 does not deliver it in 0x500b or
 * 0x6016, so it is a CAP setting (--country / COUNTRY= in the config).  Empty
 * means "do not program a country": 5 GHz will then only come up if something
 * else already set the regdomain. */
static const char *g_vap_country;

static int vap_hostapd_pid(const char *ifname);

/* Parse the RSN IE (element 48) out of the manager's IE blob. */
struct rsn_info {
    int valid;
    int group;          /* 4 = CCMP, 2 = TKIP */
    int pairwise;       /* 4 = CCMP */
    int akm_psk;
    int akm_psk256;
    int akm_sae;
    int mfpr;
    int mfpc;
};

static void rsn_parse(const uint8_t *ie, size_t len, struct rsn_info *ri)
{
    memset(ri, 0, sizeof(*ri));
    size_t p = 0;
    while (p + 2 <= len) {
        uint8_t id = ie[p], l = ie[p + 1];
        if (p + 2 + l > len) break;
        if (id == 48 && l >= 18) {          /* RSN IE */
            const uint8_t *r = ie + p + 2;
            size_t n = l;
            ri->valid = 1;
            if (n >= 8) ri->group = r[5];
            size_t k = 6;   /* version(2) + group(4) */
            if (k + 2 <= n) {
                int pc = r[k] | (r[k + 1] << 8);
                if (pc >= 1 && k + 6 <= n) ri->pairwise = r[k + 5];
                k += 2 + 4 * (size_t)pc;
            }
            if (k + 2 <= n) {
                int ac = r[k] | (r[k + 1] << 8);
                for (int i = 0; i < ac && k + 4 + 4 * (size_t)i + 3 < n; i++) {
                    const uint8_t *a = r + k + 2 + 4 * (size_t)i;
                    if (a[0] == 0x00 && a[1] == 0x0f && a[2] == 0xac) {
                        if (a[3] == 2)  ri->akm_psk = 1;
                        if (a[3] == 6)  ri->akm_psk256 = 1;
                        if (a[3] == 8)  ri->akm_sae = 1;
                    }
                }
                k += 2 + 4 * (size_t)ac;
            }
            if (k + 2 <= n) {
                uint16_t caps = (uint16_t)(r[k] | (r[k + 1] << 8));
                ri->mfpr = !!(caps & 0x0040);
                ri->mfpc = !!(caps & 0x0080);
            }
            return;
        }
        p += 2 + l;
    }
}

/* Does this hostapd build accept external_rsn_ie=<hex>?  The option only
   exists in the patched wpad, so probe the binary instead of guessing: an
   unknown option makes hostapd refuse the whole configuration. */
static int hostapd_has_rsn_override(void)
{
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = 0;
    FILE *f = fopen("/usr/sbin/wpad", "rb");
    if (!f) f = fopen("/usr/sbin/hostapd", "rb");
    if (!f) return 0;
    const char needle[] = "external_rsn_ie";
    size_t nl = sizeof(needle) - 1, hit = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if ((char)c == needle[hit]) {
            if (++hit == nl) { cached = 1; break; }
        } else {
            hit = ((char)c == needle[0]) ? 1 : 0;
        }
    }
    fclose(f);
    return cached;
}

/* True when a legacy UCI file owns BSSes (then we must not touch them).
 * W33: this is now a thin accessor over the per-session policy decision;
 * the file is parsed exactly once per session in policy.inc. */
__attribute__((unused))
static int wireless_has_bss(void)
{
    return wl_legacy();
}

/* 0x0c width code from the manager: 1=20, 2=40, 3=80, 4=160. */
static int vap_mgr_width(const uint8_t *chv, uint16_t cl)
{
    size_t p = 0;
    while (p + 4 <= cl) {
        uint16_t t = rd16(chv + p), l = rd16(chv + p + 2);
        p += 4;
        if (p + l > cl) break;
        if (t == 0x0c && l == 1) return chv[p];
        p += l;
    }
    return 0;
}

static int vap_is_5g(uint32_t f) { return f >= 4900 && f <= 5925; }

/* DFS channels in the ETSI/GR regulatory domain. */
static int vap_is_dfs_chan(int chan)
{
    return (chan >= 52 && chan <= 64) || (chan >= 100 && chan <= 144);
}

/* HT40 secondary-channel direction for a 5 GHz primary channel. */
static int vap_ht40_sign5(uint32_t freq)
{
    int chan = (int)(freq / 5 - 1000);
    if (chan >= 165) return 0;
    if (chan >= 149) return (chan % 8 == 5) ? 1 : -1;
    return (chan % 8 == 4) ? 1 : -1;
}

/* hostapd channel lines for one VAP.  wcode is the manager's 0x0c width code.
 * A VHT80 BSS needs both vht_oper_chwidth and the centre-frequency index,
 * otherwise hostapd's DFS start-channel computation fails even on ch36. */
static void vap_write_channel(FILE *f, uint32_t freq, int wcode)
{
    if (!vap_is_5g(freq)) {
        int chan = (int)((freq - 2407) / 5);
        if (chan < 1 || chan > 14) chan = 6;
        int width = (wcode == 2 || wcode == 3) ? 40 : 20;
        fprintf(f, "hw_mode=g\nchannel=%d\nieee80211n=1\n", chan);
        if (width == 40) {
            fprintf(f, "ht_capab=[HT40%c]\n", chan <= 7 ? '+' : '-');
            fprintf(f, "noscan=1\n");       /* W54: no 40 MHz coex scan */
        }
        return;
    }

    int chan = (int)(freq / 5 - 1000);
    int width;
    switch (wcode) {
    case 1:  width = 20; break;
    case 2:  width = 40; break;
    case 3:  width = 80; break;
    default: width = 80; break;
    }

    fprintf(f, "hw_mode=a\nchannel=%d\n", chan);
    /* W54: never let hostapd run the 40 MHz coexistence scan
     * (HAPD_IFACE_HT_SCAN, ieee80211n_check_40mhz()).  On mt76x02 one
     * wiphy = one channel, so the offchannel scan that hostapd issues
     * before enabling an HT40/VHT BSS returns -EBUSY (or never completes)
     * as soon as another interface exists on the phy.  After 15 retries
     * hostapd falls back to HT20, which then cannot carry the VHT80
     * centre frequency ("80/80+80 MHz: no second channel offset") and the
     * BSS ends AP-DISABLED -- the W38 "5 GHz per-BSS hostapd hangs in D"
     * symptom.  noscan=1 skips only the scan; HT40 and VHT80 stay.  The
     * stock OpenWrt hostapd already ships this option (300-noscan.patch)
     * and netifd sets ht_coex=0 for the same reason. */
    if (width >= 40) fprintf(f, "noscan=1\n");
    if (g_vap_country && g_vap_country[0])
        fprintf(f, "country_code=%s\nieee80211d=1\n%s\n", g_vap_country,
                vap_is_dfs_chan(chan) ? "ieee80211h=1" : "");
    fprintf(f, "ieee80211n=1\nieee80211ac=1\n");

    if (width >= 40) {
        int sign = vap_ht40_sign5(freq);
        if (!sign) width = 20;
        else fprintf(f, "ht_capab=[HT40%c]\n", sign > 0 ? '+' : '-');
    }
    if (width >= 80) {
        fprintf(f, "vht_oper_chwidth=1\n");
        fprintf(f, "vht_oper_centr_freq_seg0_idx=%u\n",
                ccfi80(freq) / 5 - 1000);
    } else {
        fprintf(f, "vht_oper_chwidth=0\n");
    }
}

/* Create an AP netdev on the wiphy.  Returns the ifindex or <= 0. */
static int vap_netdev_create(int phy, const char *ifname, const uint8_t mac[6])
{
    int rp = real_phy(phy);
    if (nl_cmd_open() != 0) return -1;

    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_NEW_INTERFACE, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_WIPHY, (uint32_t)rp);
    nlb_put(&m, NL80211_ATTR_IFNAME, ifname, strlen(ifname) + 1);
    nlb_u32(&m, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    int rc = nl_send_ack(g_nl_cmd_fd, &m);
    if (rc && rc != -EEXIST) {
        fprintf(stderr, "vap: NEW_INTERFACE phy=%d %s: %d (%s)\n",
                rp, ifname, rc, rc < 0 ? strerror(-rc) : "?");
        return -1;
    }
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        fprintf(stderr, "vap: %s did not appear\n", ifname);
        return -1;
    }
    if (set_iface_up(ifname) < 0)
        fprintf(stderr, "vap: %s up: %s\n", ifname, strerror(errno));
    printf("vap: created %s ifindex=%d phy=%d\n", ifname, ifindex, rp);
    fflush(stdout);
    return ifindex;
}

/* Join an existing bridge if the VLAN bridge is present (best effort). */
static void vap_bridge_if_present(const char *ifname, unsigned vlan,
                                  char *out, size_t outlen)
{
    out[0] = 0;
    if (!vlan) return;
    char br[32];
    snprintf(br, sizeof(br), "br-vlan%u", vlan);
    if (access("/sys/class/net", F_OK) != 0) return;
    char p[64];
    snprintf(p, sizeof(p), "/sys/class/net/%s", br);
    if (access(p, F_OK) != 0) return;
    snprintf(out, outlen, "%s", br);
    (void)ifname;
}

/* W54: serialise hostapd starts per agent and only report success when the
 * BSS really reached AP-ENABLED.  hostapd -B daemonizes after driver init
 * but before eloop setup, so a pid file exists while the interface can
 * still be in HT_SCAN/DFS; the next start on the same phy then gets EBUSY
 * or blocks in D state.  The lock plus the bounded wait (and the hard kill
 * on timeout) keep one bad BSS from poisoning the whole radio. */
static int vap_wait_ap_enabled(const char *logf, int ms)
{
    for (int i = 0; i < ms / 100; i++) {
        FILE *f = fopen(logf, "r");
        if (f) {
            char b[4096];
            size_t n = fread(b, 1, sizeof(b) - 1, f);
            fclose(f);
            b[n] = 0;
            if (strstr(b, "AP-ENABLED") ||
                strstr(b, "DFS-CAC-START") ||
                strstr(b, "DFS-CAC-COMPLETED")) return 1;
            if (strstr(b, "AP-DISABLED") ||
                strstr(b, "driver initialization failed") ||
                strstr(b, "Could not set interface")) return 0;
        }
        usleep(100000);
    }
    return -1;
}

/* Build and start a hostapd instance for one provisioned VAP. */
static int vap_hostapd_start_one(int port, const char *ifname, int phy, int vapid,
                                 const uint8_t *body, uint16_t len,
                                 const struct vap *vp, const struct cfg *c)
{
    const uint8_t *ssid = NULL, *ie = NULL, *chv = NULL;
    uint16_t sl = 0, il = 0, cl = 0;
    if (!find_el(body, len, 0x03, &ssid, &sl) || sl == 0) return -1;
    find_el(body, len, 0x04, &ie, &il);
    find_el(body, len, 0x0a, &chv, &cl);

    struct rsn_info ri;
    rsn_parse(ie, il, &ri);

    uint32_t freq = 0;
    vchan_get(port, &freq, NULL, NULL);
    if (!freq) freq = vp ? vp->freq : 0;
    if (!freq) return -1;

    char path[128], pidf[128], logf[128];
    snprintf(path, sizeof(path), VAP_CONF_DIR "/vap-%s.conf", ifname);
    snprintf(pidf, sizeof(pidf), "/var/run/vap-%s.pid", ifname);
    snprintf(logf, sizeof(logf), "/tmp/vap-%s.log", ifname);

    char bridge[32] = "";
    vap_bridge_if_present(ifname, vp ? vp->vlan : 0, bridge, sizeof(bridge));

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "vap: %s: %s\n", path, strerror(errno));
        return -1;
    }
    fprintf(f, "interface=%s\ndriver=nl80211\n", ifname);
    if (c->ext_ctrl_dir || c->ext_auth_dir)
        fprintf(f, "ctrl_interface=%s\n",
                c->ext_ctrl_dir ? c->ext_ctrl_dir : c->ext_auth_dir);
    fprintf(f, "ssid=%s\n", (const char *)ssid);
    if (vp) {
        fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                vp->bssid[0], vp->bssid[1], vp->bssid[2], vp->bssid[3],
                vp->bssid[4], vp->bssid[5]);
    }
    if (bridge[0]) fprintf(f, "bridge=%s\n", bridge);
    vap_write_channel(f, freq, vap_mgr_width(chv, cl));

    if (ri.valid && (ri.akm_psk || ri.akm_psk256)) {
        fprintf(f, "wpa=2\n");
        fprintf(f, "wpa_key_mgmt=%s%s\n", ri.akm_psk ? "WPA-PSK" : "",
                ri.akm_psk256 ? (ri.akm_psk ? " WPA-PSK-SHA256" : "WPA-PSK-SHA256") : "");
        fprintf(f, "rsn_pairwise=CCMP\nwpa_group_rekey=0\nwpa_ptk_rekey=0\n");
        fprintf(f, "ieee80211w=%d\n", ri.mfpr ? 2 : (ri.mfpc ? 1 : 0));
        fprintf(f, "external_rsn_auth=1\n");
        if (c->ext_auth_dir)
            fprintf(f, "ext_auth_socket=%s/ext-auth-%s\n", c->ext_auth_dir,
                    ifname);
    } else {
        /* open / SAE / OWE: the manager drives the handshake or none exists */
        fprintf(f, "wpa=0\n");
    }
    /* The station compares the RSN IE in M3 with the one in our beacon and
       drops the handshake on any difference.  When the build can take the
       manager's exact IE, hand it over verbatim. */
    if (ri.valid && hostapd_has_rsn_override() && ie && il) {
        const uint8_t *r = NULL;
        size_t p = 0, rl = 0;
        while (p + 2 <= il) {
            uint8_t id = ie[p], l = ie[p + 1];
            if (p + 2 + l > il) break;
            if (id == 48) { r = ie + p; rl = (size_t)l + 2; break; }
            p += 2 + l;
        }
        if (r && rl) {
            fprintf(f, "external_rsn_ie=");
            for (size_t i = 0; i < rl; i++) fprintf(f, "%02x", r[i]);
            fprintf(f, "\n");
        }
    }
    fprintf(f, "ignore_broadcast_ssid=0\nap_isolate=0\n");
    fclose(f);

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(logf, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        execl("/usr/sbin/hostapd", "hostapd", "-B", "-P", pidf, path,
              (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        fprintf(stderr, "vap: fork hostapd %s: %s\n", ifname, strerror(errno));
        return -1;
    }
    {
        /* hostapd -B daemonizes: the direct child exits once setup is done,
           so reap it (otherwise every failed BSS leaves a zombie) and use
           its status to tell "started" from "config/driver refused".  Never
           block the TLS loop on a slow setup (DFS/ACS): poll for 3 s. */
        int st = 0, reaped = 0;
        for (int i = 0; i < 30; i++) {
            pid_t r = waitpid(pid, &st, WNOHANG);
            if (r == pid) { reaped = 1; break; }
            if (r < 0) break;
            usleep(100000);
        }
        if (reaped && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
            printf("vap: hostapd %s failed to start (status=%d), see %s\n",
                   ifname, WIFEXITED(st) ? WEXITSTATUS(st) : -1, logf);
            fflush(stdout);
            return -1;
        }
    }
    /* Bounded, log-based readiness check: the pid alone proves nothing,
     * and hostapd -B may write it only while we are waiting. */
    int ready = vap_wait_ap_enabled(logf, 12000);
    int hpid = vap_hostapd_pid(ifname);
    if (ready == 0) {
        printf("vap: hostapd %s did not enable, see %s\n", ifname, logf);
        fflush(stdout);
        if (hpid > 0) kill((pid_t)hpid, SIGTERM);
        /* Never unlink the pid file here: it may belong to an instance that
         * is already up (a repeated 0x6016) and unlinking it makes the
         * watchdog spawn a duplicate.  A stale pid is harmless. */
        return -1;
    }
    if (ready < 0) {
        /* Still not enabled after 12 s: do not leave it holding the phy. */
        printf("vap: hostapd %s STUCK (no AP-ENABLED in 12 s), killing pid=%d,"
               " see %s\n", ifname, hpid, logf);
        fflush(stdout);
        if (hpid > 0) kill((pid_t)hpid, SIGKILL);
        return -1;
    }
    printf("vap: hostapd %s ssid=%s freq=%u akm=%s%s%s mfp=%d vlan=%u pid=%d\n",
           ifname, (const char *)ssid, freq,
           ri.akm_psk ? "psk" : "", ri.akm_psk256 ? ",psk256" : "",
           ri.akm_sae ? ",sae" : "", ri.mfpr ? 2 : (ri.mfpc ? 1 : 0),
           vp ? vp->vlan : 0, hpid);
    fflush(stdout);
    return hpid > 0 ? hpid : -1;
}

static int vap_hostapd_start(int port, const char *ifname, int phy, int vapid,
                             const uint8_t *body, uint16_t len,
                             const struct vap *vp, const struct cfg *c)
{
    int lockfd = open("/var/run/cap-vap-start.lock",
                      O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (lockfd >= 0) flock(lockfd, LOCK_EX);
    int r = vap_hostapd_start_one(port, ifname, phy, vapid, body, len, vp, c);
    if (lockfd >= 0) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    return r;
}

/* True when the pid file points at a live hostapd **that we started**.
 * W33: the pid is verified against our own config path.  A stale pid file
 * whose number was recycled by netifd's wpad must never be mistaken for
 * "our BSS is already up" (and must never be killed). */
static int vap_hostapd_pid(const char *ifname)
{
    char pidf[96], want[128], cmd[256];
    long pid = 0;
    FILE *pf;
    int found = 0;

    snprintf(pidf, sizeof(pidf), "/var/run/vap-%s.pid", ifname);
    pf = fopen(pidf, "r");
    if (!pf) return 0;
    if (fscanf(pf, "%ld", &pid) != 1) pid = 0;
    fclose(pf);
    if (pid <= 0 || kill((pid_t)pid, 0) != 0) return 0;

    snprintf(want, sizeof(want), "%s/vap-%s.conf", VAP_CONF_DIR, ifname);
    snprintf(cmd, sizeof(cmd), "/proc/%ld/cmdline", pid);
    pf = fopen(cmd, "r");
    if (!pf) return 0;
    size_t n = fread(cmd, 1, sizeof(cmd) - 1, pf);
    fclose(pf);
    cmd[n] = 0;
    /* argv is NUL-separated; just look for our config path anywhere in it */
    for (size_t i = 0; i + strlen(want) <= n; i++) {
        if (!memcmp(cmd + i, want, strlen(want))) { found = 1; break; }
    }
    if (!found) return 0;
    return (int)pid;
}

static int vap_hostapd_running(const char *ifname)
{
    return vap_hostapd_pid(ifname) > 0;
}

/* Delete a netdev by ifindex — only ever one the ownership table proved ours
 * and netifd does not list. */
static int vap_netdev_del(int ifindex)
{
    if (ifindex <= 0) return 0;
    if (nl_cmd_open() != 0) return -1;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_DEL_INTERFACE, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    int r = nl_send_ack(g_nl_cmd_fd, &m);
    printf("vap: DEL_INTERFACE ifindex=%d ret=%d (%s)\n", ifindex,
           r, r ? strerror(-r) : "ok");
    fflush(stdout);
    return r;
}

/* Resolve the netdev that belongs to (phy,vapid).  W34: the ownership table
 * is the only authority; it also incorporates W33's deterministic AP-only MAC
 * lookup (never a monitor VIF) and netifd name protection. */
static int vap_resolve(const struct cfg *c, int phy, int vapid,
                       const uint8_t mac[6], char *name, size_t n,
                       int *created)
{
    char pref[32];
    const char *preferred = NULL;
    int ifindex = 0, managed = 0;

    if (created) *created = 0;
    snprintf(pref, sizeof(pref), "phy%d-ap%d", phy, vapid);
    if (vapid == 0 && phy < MAX_RADIOS && c->ifnames[phy][0] &&
        strcmp(c->ifnames[phy], pref) != 0)
        preferred = c->ifnames[phy];

    own_claim(c, phy, vapid, preferred, mac, name, n, &ifindex, &managed);
    if (ifindex <= 0)
        return 0;
    if (created) *created = own_created_port((phy << 8) | vapid);
    return ifindex;
}

/* Re-resolve the netdev for a port right before it is used (W33).
 *
 * The manager's MAC-identified port is not enough on its own: after a
 * reconnect the cached ifindex can be stale (netdev recreated) or, worse,
 * recycled by an unrelated netdev.  Every 0x201f key install goes through
 * here so NEW_KEY/SET_KEY always target the live AP netdev.  Updates the
 * port map and the extmux BSS as a side effect. */
static int vap_refresh_ifindex(int port, uint8_t mac[6], int *changed)
{
    int phy = (port >> 8) & 0x0f;
    int wid = port & 0xff;
    struct vap *vp = vap_get(phy, wid);
    char name[32] = "";
    uint8_t m[6] = {0};
    int old = 0, idx = 0;

    if (changed) *changed = 0;
    if (own_has_entry(port) && !own_managed_strict(port))
        return 0;                    /* netifd/foreign: never install keys */
    pmap_get(port, &old, NULL);

    if (vp && vp->used && vp->ifname[0]) {
        idx = (int)if_nametoindex(vp->ifname);
        if (idx > 0) snprintf(name, sizeof(name), "%s", vp->ifname);
    }
    if (idx <= 0) {
        idx = vap_ifindex(port, m);          /* validated pmap/name/AP-only */
        if (idx > 0 && !if_indextoname((unsigned)idx, name)) idx = 0;
    }
    if (idx <= 0) return 0;

    if (mac) read_sysfs_mac(name, mac);
    if (vp) {
        vp->used = 1;
        vp->rid = phy;
        vp->wid = wid;
        vp->ifindex = idx;
        snprintf(vp->ifname, sizeof(vp->ifname), "%s", name);
    }
    pmap_set(port, idx, mac ? mac : m);
    if (g_extmux) extmux_set_ifindex(g_extmux, (uint16_t)port, idx);
    if (old > 0 && old != idx) {
        printf("0x201f: ifindex refreshed port=0x%04x %d -> %d (%s)\n", port,
               old, idx, name);
        fflush(stdout);
        if (changed) *changed = 1;
    }
    return idx;
}

/* Called from the 0x6016 handler.  Resolves the netdev, registers the port,
 * journals the request and (only when the ownership table says ours) starts
 * hostapd.  netifd-owned names are read-only. */
static void vap_provision(int port, const uint8_t *body, uint16_t len,
                          const struct cfg *c)
{
    int phy = (port >> 8) & 0x0f;
    int vapid = port & 0x0f;
    if (phy >= MAX_RADIOS) return;
    struct vap *vp = &g_vap[phy % MAX_RADIOS][vapid & 0x0f];

    char ifname[32];
    int created = 0;
    int ifindex = vap_resolve(c, phy, vapid, vp->bssid, ifname,
                              sizeof(ifname), &created);
    int managed = own_managed_strict(port);
    if (ifindex <= 0) {
        printf("vap: port 0x%04x has no AP netdev (ownership: %s)\n", port,
               managed ? "ours" : "netifd/foreign/forced-legacy");
        fflush(stdout);
        own_note_start(c, port, body, len, vp, 0, 0);
        return;
    }
    vp->used = 1;
    vp->rid = phy;
    vp->wid = vapid;
    vp->ifindex = ifindex;
    snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);
    if (managed && (created || own_created_port(port))) vp->we_created = 1;
    if (!vp->bssid[0] && !vp->bssid[1]) read_sysfs_mac(ifname, vp->bssid);

    /* Bind (or re-bind) the per-BSS ext-auth relay socket before hostapd
     * starts accepting clients.  cap_vap_ready() itself enforces ownership. */
    cap_vap_ready(phy, vapid, ifindex, ifname, vp->bssid, c);

    if (!managed) {
        printf("vap: %s is not capagent-owned (netifd/foreign/forced-legacy), "
               "no hostapd\n", ifname);
        fflush(stdout);
        own_note_start(c, port, body, len, vp, ifindex, 0);
        return;
    }

    /* W36: this VAP runs its MLME in-process; never spawn hostapd for it. */
    if (mlme_owns_port(port)) {
        int mr = mlme_vap_start(phy, vapid, ifindex, ifname, body, len, c);
        if (mr < 0)
            fprintf(stderr, "vap: %s in-CAP MLME failed (%d)\n", ifname, mr);
        own_note_start(c, port, body, len, vp, ifindex, 0);
        return;
    }

    /* One hostapd per VAP is enforced by the ownership row + pid check, not
     * by an extra in-memory flag. */
    int running = vap_hostapd_running(ifname);
    if (!vap_should_start_bss(0, c->vap_auto, ifindex, running)) {
        if (running)
            printf("vap: %s already running, not restarted\n", ifname);
        fflush(stdout);
        own_note_start(c, port, body, len, vp, ifindex, 0);
        return;
    }
    /* own_note_start journals the 0x6016 body and starts hostapd with the
     * W33 start function (pid journaled for reconcile). */
    own_note_start(c, port, body, len, vp, ifindex, 1);
    if (vap_hostapd_running(ifname)) vp->ap_started = 1;
}

/* 0x600c destroy.  Always ack, always release our bookkeeping (the vapid
 * map is only 16 slots per radio: leaking one per destroy wedged the second
 * create cycle).  Netdev/hostapd teardown only for objects we created and
 * only in own mode. */
static void vap_destroy(int port, const struct cfg *c)
{
    int phy = (port >> 8) & 0x0f;
    int vapid = port & 0x0f;
    uint8_t mac[6] = {0};
    struct vap *vp;

    if (phy >= MAX_RADIOS) return;
    vp = &g_vap[phy % MAX_RADIOS][vapid & 0x0f];
    if (vp->used) memcpy(mac, vp->bssid, 6);

    printf("0x600c: destroy port=0x%04x %s%s\n", port,
           vp->used && vp->ifname[0] ? vp->ifname : "(unbound)",
           wl_legacy() ? " -- legacy read-only, only our bookkeeping" : "");
    fflush(stdout);

    if (g_extmux) {
        extmux_del_vap(g_extmux, (uint16_t)port);
        extmux_del_vap(g_extmux, (uint16_t)((phy << 8) | vapid));
    }
    if (vp->used && vp->extfd >= 0) close(vp->extfd);
    pmap_del(port);
    pmap_del((phy << 8) | vapid);
    vchan_del((phy << 8) | vapid);

    /* W34: the ownership table decides stop/delete and journals the result;
     * --no-vap-teardown is honoured inside own_destroy(). */
    own_destroy(c, port);
    if (vp->ifindex > 0)
        dp_del_ifindex(vp->ifindex);

    if (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5])
        vapid_release(phy, mac);

    memset(vp, 0, sizeof(*vp));
    vp->extfd = -1;
    vp->l2fd = -1;
}
