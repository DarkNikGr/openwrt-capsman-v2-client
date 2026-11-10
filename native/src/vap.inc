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

/* Build and start a hostapd instance for one provisioned VAP. */
static int vap_hostapd_start(int port, const char *ifname, int phy, int vapid,
                             const uint8_t *body, uint16_t len,
                             const struct vap *vp)
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
    fprintf(f, "ssid=%s\n", (const char *)ssid);
    if (vp) {
        fprintf(f, "bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                vp->bssid[0], vp->bssid[1], vp->bssid[2], vp->bssid[3],
                vp->bssid[4], vp->bssid[5]);
    }
    if (bridge[0]) fprintf(f, "bridge=%s\n", bridge);
    if (freq < 3000) fprintf(f, "hw_mode=g\n");
    else fprintf(f, "hw_mode=a\n");
    if (freq < 3000) {
        int chan = (int)((freq - 2407) / 5);
        if (chan < 1 || chan > 14) chan = 6;
        fprintf(f, "channel=%d\n", chan);
        fprintf(f, "ieee80211n=1\n");
    } else {
        fprintf(f, "channel=%u\n", freq / 5 - 1000);
        fprintf(f, "ieee80211n=1\nieee80211ac=1\n");
        fprintf(f, "vht_oper_chwidth=1\n");
    }

    if (ri.valid && (ri.akm_psk || ri.akm_psk256)) {
        fprintf(f, "wpa=2\n");
        fprintf(f, "wpa_key_mgmt=%s%s\n", ri.akm_psk ? "WPA-PSK" : "",
                ri.akm_psk256 ? (ri.akm_psk ? " WPA-PSK-SHA256" : "WPA-PSK-SHA256") : "");
        fprintf(f, "rsn_pairwise=CCMP\nwpa_group_rekey=0\nwpa_ptk_rekey=0\n");
        fprintf(f, "ieee80211w=%d\n", ri.mfpr ? 2 : (ri.mfpc ? 1 : 0));
        fprintf(f, "external_rsn_auth=1\n");
        fprintf(f, "ext_auth_socket=/var/run/hostapd/ext-auth-%s\n", ifname);
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
    return 0;
}

/* Called from the 0x6016 handler.  Only acts when the netdev is missing, i.e.
 * when the manager is the only owner of the wireless configuration. */
static void vap_provision(int port, const uint8_t *body, uint16_t len,
                          const struct cfg *c)
{
    int phy = (port >> 8) & 0x0f;
    int vapid = port & 0x0f;
    if (phy >= MAX_RADIOS) return;
    struct vap *vp = &g_vap[phy % MAX_RADIOS][vapid & 0x0f];

    char ifname[32];
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", phy, vapid);
    int created = 0;
    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        ifindex = vap_netdev_create(phy, ifname, vp->bssid);
        if (ifindex <= 0) return;
        created = 1;
    }
    vp->ifindex = ifindex;
    snprintf(vp->ifname, sizeof(vp->ifname), "%s", ifname);

    /* Bind the ext-auth dgram socket under the name hostapd will use. */
    if (c->ext_auth_dir) {
        if (vp->extfd >= 0) { close(vp->extfd); vp->extfd = -1; }
        ext_auth_bind(vp, c->ext_auth_dir);
    }

    if (!c->vap_auto) return;

    char pidf[96];
    snprintf(pidf, sizeof(pidf), "/var/run/vap-%s.pid", ifname);
    if (!created && wireless_has_bss()) {
        /* A legacy UCI file owns this interface: leave it alone. */
        if (access(pidf, F_OK) != 0) return;
        FILE *pf = fopen(pidf, "r");
        if (pf) {
            long pid = 0;
            if (fscanf(pf, "%ld", &pid) == 1 && pid > 0 &&
                kill((pid_t)pid, 0) == 0) {
                fclose(pf);
                return;                     /* already running */
            }
            fclose(pf);
        }
    }
    vap_hostapd_start(port, ifname, phy, vapid, body, len, vp);
}
