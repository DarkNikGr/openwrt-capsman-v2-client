/* apply.inc — 0x77/M2 config parse and UCI apply (argv, no shell)
 * Part of capagent.c (single translation unit; included in order). */

static const struct cfg_key *cfg_key_find(uint16_t id)
{
    for (size_t i = 0; i < sizeof(cfg_keys)/sizeof(cfg_keys[0]); i++)
        if (cfg_keys[i].id == id) return &cfg_keys[i];
    return NULL;
}

static int tlv_walkable(const uint8_t *b, size_t n)
{
    size_t i = 0;
    int cnt = 0;

    while (i + 4 <= n) {
        uint16_t l = rd16(b + i + 2);
        if (i + 4 + l > n) return 0;
        i += 4 + l;
        cnt++;
    }
    return i == n && cnt > 0;
}

static void cfg_note(uint16_t id, const uint8_t *v, uint16_t len)
{
    size_t n;

    switch (id) {
    case 0x1004:
        n = len < sizeof(g_cfg_seen.ssid) - 1
              ? len : sizeof(g_cfg_seen.ssid) - 1;
        memcpy(g_cfg_seen.ssid, v, n);
        g_cfg_seen.ssid[n] = 0;
        g_cfg_seen.have_ssid = 1;
        break;
    case 0xbb06:
        if (len == 4) { g_cfg_seen.vlan = rd32(v); g_cfg_seen.have_vlan = 1; }
        break;
    case 0xd000:
        if (len == 4) { g_cfg_seen.auth = rd32(v); g_cfg_seen.have_auth = 1; }
        break;
    case 0xd90f:
        n = len < sizeof(g_cfg_seen.passphrase) - 1
              ? len : sizeof(g_cfg_seen.passphrase) - 1;
        memcpy(g_cfg_seen.passphrase, v, n);
        g_cfg_seen.passphrase[n] = 0;
        g_cfg_seen.have_pass = 1;
        break;
    }
}

static void cfg_leaf(const struct cfg_key *k, const uint8_t *v, uint16_t len,
                     int depth)
{
    char s[80];

    if (k->kind == CFG_STR) {
        size_t n = len < sizeof(s) - 1 ? len : sizeof(s) - 1;
        memcpy(s, v, n);
        s[n] = 0;
        for (size_t i = 0; i < n; i++)
            if (s[i] < 0x20 || s[i] > 0x7e) s[i] = '.';
        printf("%*s0x%04x %-24s \"%s\"\n", depth * 2, "", k->id, k->name, s);
    } else if (k->kind == CFG_U32) {
        uint32_t u = len >= 4 ? rd32(v) : 0;
        printf("%*s0x%04x %-24s %u (0x%08x)\n", depth * 2, "",
               k->id, k->name, u, u);
    } else {
        printf("%*s0x%04x %-24s %u\n", depth * 2, "", k->id, k->name,
               len ? v[0] : 0);
    }
    cfg_note(k->id, v, len);
}

static void cfg_walk(const uint8_t *b, size_t n, int depth)
{
    size_t i = 0;

    while (i + 4 <= n && g_cfg_lines < 512) {
        uint16_t id = rd16(b + i), len = rd16(b + i + 2);
        const uint8_t *v = b + i + 4;
        const struct cfg_key *k;

        if (i + 4 + len > n) break;
        g_cfg_lines++;
        k = cfg_key_find(id);
        if (k) {
            cfg_leaf(k, v, len, depth);
        } else {
            printf("%*s0x%04x %-24s len=%u%s\n", depth * 2, "", id,
                   "(container)", len, depth >= 4 ? " (max depth)" : "");
            if (depth < 4 && len >= 4 && tlv_walkable(v, len))
                cfg_walk(v, len, depth + 1);
        }
        i += 4 + len;
    }
}

/* ---- nv::flat_message ("M2") parser for the 0x77 config tree ---------- */
struct vapcfg {
    int have_ssid, have_vlan, have_auth, have_pass;
    char ssid[33];
    char pass[64];
    uint32_t vlan;
    uint32_t auth;
};

static struct vapcfg g_vaps[8];
static int g_nvap;
static int g_apply;

static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int parse_m2(const uint8_t *b, size_t n)
{
    if (n < 8 || b[4] != 'M' || b[5] != '2')
        return -1;
    uint32_t mlen = rd32le(b);
    size_t end = 4u + mlen;
    if (end > n) end = n;
    size_t p = 6;
    g_nvap = 0;
    while (p + 4 <= end) {
        uint32_t h = rd32le(b + p);
        uint32_t id = h & 0x00ffffffu;
        p += 4;
        if ((h & 0xff000000u) == 0x21000000u) {      /* bytes element */
            if (p >= end) break;
            uint8_t l = b[p++];
            if (p + l > end) break;
            if (id == 0x1004) {
                if (g_nvap < (int)(sizeof(g_vaps)/sizeof(g_vaps[0]))) {
                    struct vapcfg *v = &g_vaps[g_nvap];
                    memset(v, 0, sizeof(*v));
                    size_t k = l < sizeof(v->ssid) - 1 ? l : sizeof(v->ssid) - 1;
                    memcpy(v->ssid, b + p, k);
                    v->ssid[k] = 0;
                    v->have_ssid = 1;
                    g_nvap++;
                }
            } else if (id == 0x2000 && g_nvap > 0) {  /* passphrase */
                struct vapcfg *v = &g_vaps[g_nvap - 1];
                size_t k = l < sizeof(v->pass) - 1 ? l : sizeof(v->pass) - 1;
                memcpy(v->pass, b + p, k);
                v->pass[k] = 0;
                v->have_pass = 1;
            }
            p += l;
        } else if ((h & 0xff000000u) == 0x88000000u) { /* u32 array */
            if (p + 2 > end) break;
            uint16_t cnt = rd16le(b + p);
            p += 2;
            if (p + (size_t)cnt * 4 > end) break;
            if (g_nvap > 0 && cnt) {
                struct vapcfg *v = &g_vaps[g_nvap - 1];
                if (id == 0xbb06) { v->vlan = rd32le(b + p); v->have_vlan = 1; }
                else if (id == 0xd000) { v->auth = rd32le(b + p); v->have_auth = 1; }
            }
            p += (size_t)cnt * 4;
        } else {
            break;
        }
    }
    return g_nvap;
}

static int run_argv(char *const av[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(av[0], av);
        _exit(127);
    }
    if (pid < 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Set a UCI option without a shell: the value is passed as a single argv
   element, so quotes/semicolons in an SSID or passphrase cannot inject. */
static void uci_set_opt(const char *sec, const char *opt, const char *val)
{
    char kv[512];
    snprintf(kv, sizeof(kv), "wireless.%s.%s=%s", sec, opt, val);
    char *av[] = { "uci", "-q", "set", kv, NULL };
    if (run_argv(av) != 0)
        printf("apply: uci set wireless.%s.%s failed\n", sec, opt);
}

static void apply_vaps(void)
{
    if (!g_apply || g_nvap <= 0)
        return;

    FILE *p = popen("uci -q show wireless", "r");
    if (!p) {
        printf("apply: cannot read wireless config\n");
        return;
    }
    char line[512];
    char devs[MAX_RADIOS][32];
    int ndev = 0;
    while (fgets(line, sizeof(line), p)) {
        /* wireless.<dev>=wifi-device -> collect for reconf */
        if (strncmp(line, "wireless.", 9) == 0) {
            char *eqd = strchr(line, '=');
            if (eqd && strstr(eqd + 1, "wifi-device")) {
                *eqd = 0;
                char *nm = line + 9;
                if (!strchr(nm, '.') && ndev < MAX_RADIOS) {
                    size_t nl = strlen(nm);
                    int okd = (nl > 0 && nl < 32);
                    for (size_t k = 0; k < nl; k++)
                        if (!isalnum((unsigned char)nm[k]) && nm[k] != '_')
                            okd = 0;
                    if (okd) {
                        memcpy(devs[ndev], nm, nl);
                        devs[ndev][nl] = 0;
                        ndev++;
                    }
                }
                continue;
            }
        }
        /* wireless.<sec>.network='wifi<vlan>' */
        char *d1 = strchr(line, '.');
        if (!d1) continue;
        char *d2 = strchr(d1 + 1, '.');
        if (!d2) continue;
        char *eq = strchr(d2, '=');
        if (!eq) continue;
        char *val = eq + 1;
        while (*val == '\'' || *val == '"') val++;
        if (strncmp(val, "wifi", 4) != 0) continue;
        unsigned vlan = (unsigned)atoi(val + 4);
        char sec[64];
        size_t sl = (size_t)(d2 - d1 - 1);
        if (sl == 0 || sl >= sizeof(sec)) continue;
        memcpy(sec, d1 + 1, sl);
        sec[sl] = 0;
        int ok = 1;
        for (size_t k = 0; k < sl; k++)
            if (!isalnum((unsigned char)sec[k]) && sec[k] != '_') ok = 0;
        if (!ok) continue;

        for (int i = 0; i < g_nvap; i++) {
            struct vapcfg *v = &g_vaps[i];
            if (!v->have_ssid || !v->have_pass) continue;
            unsigned vv = v->have_vlan && v->vlan ? v->vlan : 1;
            if (vv != vlan) continue;
            const char *sec_type =
                (v->have_auth && v->auth == 2) ? "sae" : "psk2";
            uci_set_opt(sec, "ssid", v->ssid);
            uci_set_opt(sec, "encryption", sec_type);
            uci_set_opt(sec, "key", v->pass);
            printf("apply: vlan=%u ssid=%s sec=%s (key not logged)\n",
                   vlan, v->ssid, sec_type);
        }
    }
    pclose(p);

    char *commit[] = { "uci", "-q", "commit", "wireless", NULL };
    run_argv(commit);
    for (int i = 0; i < ndev; i++) {
        /* devs[] entries are 32-byte UCI device names; the larger buffer
           keeps -Wformat-truncation quiet about the %s bound. */
        char json[288];
        snprintf(json, sizeof(json), "{\"device\":\"%s\"}", devs[i]);
        char *av[] = { "ubus", "call", "network.wireless", "reconf",
                       json, NULL };
        run_argv(av);
    }
    printf("apply: %d wifi-iface sections updated, %d radios reconfigured\n",
           g_nvap, ndev);
}

static void handle_c029(const uint8_t *body, uint16_t len)
{
    const uint8_t *v = NULL, *tree = NULL;
    uint16_t vl = 0, tlen = 0;
    unsigned version = 0;

    if (find_el(body, len, 0xa7, &v, &vl) && vl)
        version = v[0];
    printf("RX 0xc029 joinresp len=%u version=%u\n", len, version);

    if (!find_el(body, len, 0x77, &tree, &tlen) || !tlen) {
        printf("0xc029: no 0x77 config tree (SSID/VLAN/security not "
               "delivered yet)\n");
        fflush(stdout);
        return;
    }

    dump_raw("cfg77", TYPE_JOIN_RESP, 0, tree, tlen);
    int cfd = getenv("CAPAGENT_DEBUG")
              ? open("/tmp/capagent-cfg77.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600)
              : -1;
    FILE *f = cfd >= 0 ? fdopen(cfd, "wb") : NULL;
    if (f) { fwrite(tree, 1, tlen, f); fclose(f); }
    printf("0xc029: 0x77 payload len=%u -> /tmp/capagent-cfg77.bin\n",
           tlen);

    memset(&g_cfg_seen, 0, sizeof(g_cfg_seen));
    g_cfg_lines = 0;
    if (parse_m2(tree, tlen) > 0) {
        printf("0xc029: parsed %d VAP(s) from M2 tree\n", g_nvap);
        for (int i = 0; i < g_nvap; i++)
            printf("  vap%d ssid=%s vlan=%u auth=%u pass=%s\n",
                   i, g_vaps[i].ssid, g_vaps[i].vlan,
                   g_vaps[i].auth, g_vaps[i].pass);
        apply_vaps();
    } else if (!tlv_walkable(tree, tlen)) {
        printf("0xc029: 0x77 is not an M2/nv::message tree, raw dump only\n");
    } else {
        printf("0xc029: parsing 0x77 as a TLV tree\n");
        cfg_walk(tree, tlen, 0);
        printf("0xc029: seen ssid=%s vlan=%u auth=0x%08x passphrase_set=%d\n",
               g_cfg_seen.have_ssid ? g_cfg_seen.ssid : "-",
               g_cfg_seen.have_vlan ? g_cfg_seen.vlan : 0,
               g_cfg_seen.have_auth ? g_cfg_seen.auth : 0,
               g_cfg_seen.have_pass);
    }
    printf("0xc029: %s\n", g_apply ? "applied to UCI" : "log/dump only");
    fflush(stdout);
}

static int vapid_for(int phy, const uint8_t mac[6]);

/* VLAN -> vapid map, learned from the a2=0 virtual creates.  The a2=1
   datachan creates carry the master MAC for every VLAN, so the MAC alone
   cannot identify the VAP. */
struct vlan_wid { int used; uint16_t vlan; int wid; };
static struct vlan_wid g_vw[MAX_RADIOS][16];

