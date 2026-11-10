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

/* True when a legacy UCI file owns BSSes (then we must not touch them). */
static int wireless_has_bss(void)
{
    FILE *f = fopen("/etc/config/wireless", "r");
    if (!f) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "config wifi-iface")) { found = 1; break; }
    }
    fclose(f);
    return found;
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
        if (width == 40)
            fprintf(f, "ht_capab=[HT40%c]\n", chan <= 7 ? '+' : '-');
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

/* ====================================================================
 * W25/W28: complete VAP lifecycle (integrated on top of W36/extmux)
 *
 * Every resource is owned explicitly:
 *   netdev phyN-apM   (NL80211_CMD_NEW_INTERFACE, own_netdev)
 *   hostapd           (pid file /var/run/vap-<ifname>.pid)
 *   ext-auth socket   (extmux record, or extpath for the legacy relay)
 *   config            (/tmp/vap-<ifname>.conf)
 *   vapid slot        (g_vmap, released on 0x600c)
 * A teardown stops hostapd, drops the relay socket, unlinks the files,
 * deletes the netdev and only then frees the slot.  The watchdog repeats
 * the same cleanup for anything left behind by a crash/restart.
 * ==================================================================== */

static void vap_paths(const char *ifname, char *conf, size_t cl,
                      char *pidf, size_t pl)
{
    snprintf(conf, cl, VAP_CONF_DIR "/vap-%s.conf", ifname);
    snprintf(pidf, pl, "/var/run/vap-%s.pid", ifname);
}

static int vap_pid_alive(pid_t pid)
{
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    return errno == EPERM;
}

static pid_t vap_read_pidfile(const char *ifname)
{
    char conf[128], pidf[128];
    vap_paths(ifname, conf, sizeof(conf), pidf, sizeof(pidf));
    FILE *f = fopen(pidf, "r");
    if (!f) return 0;
    long pid = 0;
    int got = fscanf(f, "%ld", &pid);
    fclose(f);
    return (got == 1 && pid > 0) ? (pid_t)pid : 0;
}

/* Find a hostapd whose argv carries our exact per-VAP config path.  This
   covers a missing/stale pid file (e.g. hostapd crashed after writing it). */
static pid_t vap_find_hostapd(const char *ifname)
{
    char want[128];
    snprintf(want, sizeof(want), VAP_CONF_DIR "/vap-%s.conf", ifname);
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    pid_t found = 0;
    while ((de = readdir(d)) != NULL) {
        char *end = NULL;
        long pid = strtol(de->d_name, &end, 10);
        if (!end || *end || pid <= 0) continue;
        char p[64], buf[4096];
        snprintf(p, sizeof(p), "/proc/%ld/cmdline", pid);
        int fd = open(p, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        for (ssize_t i = 0; i < n; ) {
            const char *arg = buf + i;
            size_t al = strlen(arg);
            if (al && !strcmp(arg, want)) { found = (pid_t)pid; break; }
            i += (ssize_t)al + 1;
        }
        if (found) break;
    }
    closedir(d);
    return found;
}

static void vap_stop_hostapd(struct vap *v)
{
    if (!v || !v->ifname[0]) return;
    char conf[128], pidf[128];
    vap_paths(v->ifname, conf, sizeof(conf), pidf, sizeof(pidf));
    pid_t pid = vap_read_pidfile(v->ifname);
    if (pid <= 0) pid = v->hostapd_pid;
    if (!vap_pid_alive(pid)) pid = vap_find_hostapd(v->ifname);
    if (vap_pid_alive(pid)) {
        printf("vap: stopping hostapd %s pid=%d\n", v->ifname, (int)pid);
        fflush(stdout);
        kill(pid, SIGTERM);
        for (int i = 0; i < 20 && vap_pid_alive(pid); i++)
            usleep(100000);
        if (vap_pid_alive(pid)) {
            printf("vap: hostapd %s did not exit, SIGKILL\n", v->ifname);
            kill(pid, SIGKILL);
            for (int i = 0; i < 10 && vap_pid_alive(pid); i++)
                usleep(100000);
        }
        /* If it was our direct child, reap it; a -B daemon is owned by
           init and this is a harmless ECHILD. */
        waitpid(pid, NULL, WNOHANG);
    }
    unlink(pidf);
    v->hostapd_pid = 0;
    v->hostapd_started = 0;
}

/* Wait briefly for the kernel to remove a netdev.  DEL_INTERFACE is
   synchronous for the device model, but the sysfs entry can lag a tick. */
static int vap_wait_netdev_gone(const char *ifname)
{
    for (int i = 0; i < 20; i++) {
        if (if_nametoindex(ifname) == 0) return 1;
        usleep(50000);
    }
    return if_nametoindex(ifname) == 0;
}

static int vap_netdev_delete_name(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) return 0;
    int r = nl_del_interface(ifindex);
    int gone = vap_wait_netdev_gone(ifname);
    printf("vap: deleted netdev %s ifindex=%d nl=%d gone=%d\n",
           ifname, ifindex, r, gone);
    fflush(stdout);
    return gone;
}

static void vap_remove_files(const char *ifname)
{
    char conf[128], pidf[128], logf[128];
    vap_paths(ifname, conf, sizeof(conf), pidf, sizeof(pidf));
    snprintf(logf, sizeof(logf), "/tmp/vap-%s.log", ifname);
    unlink(pidf);
    unlink(conf);
    (void)logf;                        /* keep the log for post-mortem */
}

/* Drop the ext-auth relay state for one VAP.  With extmux the per-BSS
   ext/ctrl sockets and the session table belong to the relay, so the whole
   record is removed; the legacy relay only has the dgram socket. */
static void vap_relay_close(int phy, int vapid, struct vap *v)
{
    if (g_extmux)
        extmux_del_vap(g_extmux, (uint16_t)((phy << 8) | vapid));
    ext_auth_close(v);
}

/* The one teardown used by 0x600c, cleanup-on-recreate and the watchdog. */
static void vap_teardown(struct vap *v, int remove_netdev)
{
    if (!v) return;
    char ifname[32];
    snprintf(ifname, sizeof(ifname), "%s", v->ifname);
    vap_stop_hostapd(v);
    if (ifname[0]) vap_remove_files(ifname);
    if (remove_netdev && v->own_netdev && ifname[0]) {
        vap_netdev_delete_name(ifname);
        v->own_netdev = 0;
        v->ifindex = 0;
    }
    v->hostapd_started = 0;
    v->hostapd_pid = 0;
}

/* Destroy one VAP: data path, monitor, datachan key, channel map, pmap,
   relay socket, hostapd/netdev/files, then the vapid slot itself. */
static void vap_destroy(int phy, int vapid, const char *why)
{
    if (phy < 0 || phy >= MAX_RADIOS || vapid < 0 || vapid > 15) return;
    int r = phy % MAX_RADIOS;
    struct vap *v = &g_vap[r][vapid];
    int ifindex = v->ifindex;
    uint16_t vlan = v->vlan;
    char ifname[32];
    snprintf(ifname, sizeof(ifname), "%s", v->ifname);
    int was_used = v->used;

    if (was_used) {
        dp_vap_close(v);
        vap_relay_close(phy, vapid, v);
        dc_forget_vap(phy, vapid);
        vchan_clear((phy << 8) | vapid);
        pmap_del((phy << 8) | vapid);
        vap_teardown(v, 1);            /* hostapd + netdev we created */
        memset(v, 0, sizeof(*v));
        v->l2fd = -1;
        v->extfd = -1;
    } else {
        /* cap_reset_session() drops the registry on a reconnect, so the
           netdev/hostapd can outlive the entry.  Only touch objects that
           carry our own per-VAP config file: that proves we made them. */
        char conf[128], pidf[128], name[32];
        snprintf(name, sizeof(name), "phy%d-ap%d", phy, vapid);
        vap_paths(name, conf, sizeof(conf), pidf, sizeof(pidf));
        if (access(conf, F_OK) == 0) {
            struct vap tmp;
            memset(&tmp, 0, sizeof(tmp));
            snprintf(tmp.ifname, sizeof(tmp.ifname), "%s", name);
            tmp.ifindex = if_nametoindex(name);
            tmp.own_netdev = 1;        /* the conf file proves it */
            tmp.l2fd = -1;
            tmp.extfd = -1;
            vap_stop_hostapd(&tmp);
            vap_remove_files(name);
            if (vap_ifname_is_ours(name) && !wireless_has_bss())
                vap_netdev_delete_name(name);
            printf("0x600c: reaped unregistered VAP %s\n", name);
            fflush(stdout);
        }
    }
    /* Only after the netdev is gone (vap_teardown waited for it) is the
       manager's 0x47 slot safe to reuse. */
    vapid_release_slot(phy, vapid);
    mgmt_vap_del(phy);                 /* only when this was the last VAP */
    printf("0x600c: released rid=%d wid=%d ifindex=%d ifname=%s vlan=%u "
           "(%s)%s\n", phy, vapid, ifindex, ifname, vlan, why,
           was_used ? "" : " [slot was already free]");
    fflush(stdout);
}

/* Parse a destroy message: the header port is authoritative, but a body
   0x47 is accepted when present.  Returns 0 on a valid id. */
static int vap_destroy_target(uint16_t port, const uint8_t *body, uint16_t len,
                              int *out_phy, int *out_vapid)
{
    int phy = (port >> 8) & 0xff;
    int vapid = port & 0xff;
    const uint8_t *v = NULL; uint16_t l = 0;
    if (find_el(body, len, 0x47, &v, &l) && l == 4) {
        uint32_t id = rd32(v);
        if (id <= 15) vapid = (int)id;
    }
    /* A destroy body is empty on 7.25.1, but if a manager variant includes
       0x08, prefer the BSSID that is actually live.  This also recovers
       from a header that always carries vap 0. */
    if (phy >= 0 && phy < MAX_RADIOS &&
        find_el(body, len, 0x08, &v, &l) && l == 6) {
        for (int w = 0; w < 16; w++)
            if (g_vap[phy][w].used &&
                !memcmp(g_vap[phy][w].bssid, v, 6)) {
                vapid = w;
                break;
            }
    }
    if (phy < 0 || phy >= MAX_RADIOS || vapid < 0 || vapid > 15)
        return -1;
    *out_phy = phy;
    *out_vapid = vapid;
    return 0;
}

/* Build and start a hostapd instance for one provisioned VAP. */
static int vap_hostapd_start(int port, const char *ifname, int phy, int vapid,
                             const uint8_t *body, uint16_t len,
                             struct vap *vp, const struct cfg *c)
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
    fprintf(f, "ssid=%.*s\n", (int)sl, (const char *)ssid);
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
    printf("vap: hostapd %s ssid=%s freq=%u akm=%s%s%s mfp=%d vlan=%u\n",
           ifname, (const char *)ssid, freq,
           ri.akm_psk ? "psk" : "", ri.akm_psk256 ? ",psk256" : "",
           ri.akm_sae ? ",sae" : "", ri.mfpr ? 2 : (ri.mfpc ? 1 : 0),
           vp ? vp->vlan : 0);
    fflush(stdout);
    if (vp) vp->hostapd_started_at = time(NULL);
    return 0;
}

/* True when the pid file points at a live hostapd. */
__attribute__((unused))
static int vap_hostapd_running(const char *ifname)
{
    char pidf[96];
    long pid = 0;
    FILE *pf;
    snprintf(pidf, sizeof(pidf), "/var/run/vap-%s.pid", ifname);
    pf = fopen(pidf, "r");
    if (!pf) return 0;
    if (fscanf(pf, "%ld", &pid) != 1) pid = 0;
    fclose(pf);
    return pid > 0 && kill((pid_t)pid, 0) == 0;
}

/* Called from the 0x6016 handler.  The VAP is already bound by 0x500b.  A
 * previous hostapd (profile change, duplicate start, stale daemon) is stopped
 * before a new one is started, so a recreate always gets a clean slate. */
static void vap_provision(int port, const uint8_t *body, uint16_t len,
                          const struct cfg *c)
{
    int phy = (port >> 8) & 0xff;
    int vapid = port & 0xff;
    if (phy < 0 || phy >= MAX_RADIOS || vapid < 0 || vapid > 15) return;
    struct vap *vp = &g_vap[phy % MAX_RADIOS][vapid];
    if (!vp->used) {
        fprintf(stderr, "vap: 0x6016 for unbound port 0x%04x, ignored\n",
                port);
        fflush(stderr);
        return;
    }

    char ifname[32];
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    int created = 0;
    /* createvap_response() may have created a differently named netdev (the
     * -i mapping) and stored it on the VAP; prefer that binding. */
    int ifindex = 0;
    {
        char chk[IF_NAMESIZE];
        if (vp->ifindex > 0 && vp->ifname[0] &&
            if_indextoname((unsigned)vp->ifindex, chk)) {
            ifindex = vp->ifindex;
            snprintf(ifname, sizeof(ifname), "%s", vp->ifname);
        }
    }
    if (ifindex <= 0) ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        ifindex = vap_netdev_create(phy, ifname, vp->bssid);
        if (ifindex <= 0) return;
        created = 1;
    }
    vp->ifindex = ifindex;
    snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);
    if (created)
        vp->own_netdev = 1;
    else if (!vp->own_netdev && vap_ifname_is_ours(ifname) &&
             !wireless_has_bss())
        vp->own_netdev = 1;     /* adopt a netdev left by an earlier run */

    /* Bind (or re-bind) the per-BSS ext-auth relay socket before hostapd
     * starts accepting clients.  Also seeds the port/channel map. */
    cap_vap_ready(phy, vapid, ifindex, ifname, vp->bssid, c);

    /* W36: this VAP runs its MLME in-process; never spawn hostapd for it. */
    if (mlme_owns_port(port)) {
        int mr = mlme_vap_start(phy, vapid, ifindex, ifname, body, len, c);
        if (mr < 0)
            fprintf(stderr, "vap: %s in-CAP MLME failed (%d)\n", ifname, mr);
        return;
    }

    if (!c->vap_auto) return;

    /* A legacy UCI file owns this interface: leave it alone. */
    if (!vp->own_netdev && wireless_has_bss() &&
        !vap_pid_alive(vap_read_pidfile(ifname)) && !vp->hostapd_started)
        return;

    /* Clean slate: never stack a second hostapd on the same BSS. */
    if (vp->hostapd_started || vap_read_pidfile(ifname) > 0 ||
        vap_find_hostapd(ifname) > 0) {
        pid_t old = vap_read_pidfile(ifname);
        printf("vap: %s restarting hostapd (old pid=%d)\n", ifname, (int)old);
        fflush(stdout);
        vap_stop_hostapd(vp);
        char conf[128], pidf[128];
        vap_paths(ifname, conf, sizeof(conf), pidf, sizeof(pidf));
        unlink(conf);
        unlink(pidf);
    }

    if (vap_hostapd_start(port, ifname, phy, vapid, body, len, vp, c) != 0)
        return;
    vp->hostapd_started = 1;
    /* hostapd -B writes the pid file after daemonizing; wait briefly so the
       watchdog and 0x600c see the real daemon pid. */
    pid_t pid = 0;
    for (int i = 0; i < 20; i++) {
        pid = vap_read_pidfile(ifname);
        if (pid > 0) break;
        usleep(25000);
    }
    vp->hostapd_pid = pid;
    printf("vap: %s hostapd ready pid=%d\n", ifname, (int)pid);
    fflush(stdout);
}

/* Reap anything that lost its registry entry: pid files, conf files,
   hostapd processes, ext-auth sockets and phyN-apM netdevs.  Runs from the
   main loop; all operations are idempotent. */
static int vap_name_live(const char *ifname)
{
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++)
            if (g_vap[r][w].used && !strcmp(g_vap[r][w].ifname, ifname))
                return 1;
    return 0;
}

static void vap_kill_orphan(pid_t pid, const char *why)
{
    if (!vap_pid_alive(pid)) return;
    printf("watchdog: killing %s pid=%d\n", why, (int)pid);
    fflush(stdout);
    kill(pid, SIGTERM);
    for (int i = 0; i < 20 && vap_pid_alive(pid); i++) usleep(100000);
    if (vap_pid_alive(pid)) kill(pid, SIGKILL);
    waitpid(pid, NULL, WNOHANG);
}

static void vap_watchdog(const struct cfg *c)
{
    /* Reap the short-lived fork() children from hostapd -B. */
    while (waitpid(-1, NULL, WNOHANG) > 0) { }
    if (!c->vap_auto) return;

    time_t now = time(NULL);

    /* 1. Live VAPs whose hostapd or netdev vanished: mark for re-provision
          instead of keeping a stale "started" flag forever. */
    for (int r = 0; r < MAX_RADIOS; r++)
        for (int w = 0; w < 16; w++) {
            struct vap *v = &g_vap[r][w];
            if (!v->used) continue;
            if (v->hostapd_started &&
                !vap_pid_alive(vap_read_pidfile(v->ifname)) &&
                !vap_pid_alive(v->hostapd_pid) &&
                now - v->hostapd_started_at > 5) {
                printf("watchdog: %s hostapd gone, marking down\n",
                       v->ifname);
                fflush(stdout);
                v->hostapd_started = 0;
                v->hostapd_pid = 0;
            }
            if (v->ifname[0] && v->ifindex > 0 &&
                (int)if_nametoindex(v->ifname) != v->ifindex) {
                printf("watchdog: %s netdev gone (ifindex %d)\n",
                       v->ifname, v->ifindex);
                fflush(stdout);
                v->ifindex = 0;
                v->own_netdev = 0;
                v->hostapd_started = 0;
                v->hostapd_pid = 0;
            }
        }

    /* 2. Orphan pid/conf files: if no live VAP claims the name, stop the
          daemon, unlink the files and delete the matching netdev. */
    DIR *d = opendir("/var/run");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            const char *n = de->d_name;
            if (strncmp(n, "vap-", 4) || strcmp(n + strlen(n) - 4, ".pid"))
                continue;
            char ifname[32];
            size_t nl = strlen(n) - 4;
            if (nl < 4 || nl - 4 >= sizeof(ifname)) continue;
            snprintf(ifname, sizeof(ifname), "%.*s", (int)(nl - 4), n + 4);
            if (vap_name_live(ifname)) continue;
            char p[128];
            snprintf(p, sizeof(p), "/var/run/%s", n);
            pid_t pid = vap_read_pidfile(ifname);
            if (pid <= 0) pid = vap_find_hostapd(ifname);
            if (pid > 0) vap_kill_orphan(pid, "orphan hostapd");
            unlink(p);
            vap_remove_files(ifname);
            if (vap_ifname_is_ours(ifname) && !wireless_has_bss())
                vap_netdev_delete_name(ifname);
            if (c->ext_auth_dir) {
                char s[300];
                snprintf(s, sizeof(s), "%s/ext-auth-%s", c->ext_auth_dir,
                         ifname);
                unlink(s);
            }
            printf("watchdog: reaped orphan VAP %s\n", ifname);
            fflush(stdout);
        }
        closedir(d);
    }

    /* 3. Orphan netdevs in our name space (e.g. after the agent restarted
          with an empty registry and no pid file was left). */
    d = opendir("/sys/class/net");
    if (d) {
        struct dirent *de;
        int legacy = wireless_has_bss();
        while ((de = readdir(d)) != NULL) {
            if (!vap_ifname_is_ours(de->d_name)) continue;
            if (vap_name_live(de->d_name)) continue;
            if (legacy) continue;      /* UCI may own the same name */
            if (vap_netdev_delete_name(de->d_name)) {
                printf("watchdog: reaped orphan netdev %s\n", de->d_name);
                fflush(stdout);
            }
        }
        closedir(d);
    }

    /* 4. Orphan ext-auth sockets for names with no live VAP.  With extmux
          the relay owns the paths, but a socket left by an older process
          still has to go. */
    if (c->ext_auth_dir) {
        d = opendir(c->ext_auth_dir);
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                const char *n = de->d_name;
                if (strncmp(n, "ext-auth-", 9)) continue;
                const char *ifname = n + 9;
                if (vap_name_live(ifname)) continue;
                if (g_extmux && extmux_vap_by_ifname(g_extmux, ifname))
                    continue;
                char s[300];
                snprintf(s, sizeof(s), "%s/%s", c->ext_auth_dir, n);
                unlink(s);
                printf("watchdog: reaped orphan ext-auth socket %s\n", n);
                fflush(stdout);
            }
            closedir(d);
        }
    }
}
