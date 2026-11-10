/* nl80211.inc — generic netlink: control-port EAPOL, NEW_KEY/SET_KEY, authorize
 * Part of capagent.c (single translation unit; included in order). */

/* ======================================================================
 * nl80211: 0x201C control-port injection, 0x201F key install, authorize.
 * T4's constants: NEW_KEY=11 SET_KEY=10 SET_STATION=18; ATTR_KEY=80,
 * KEY_DATA=1, KEY_IDX=2, KEY_CIPHER=3, KEY_SEQ=4, KEY_DEFAULT=5,
 * KEY_DEFAULT_MGMT=6, KEY_TYPE=7, KEY_DEFAULT_TYPES=8,
 * KEY_DEFAULT_TYPE_MULTICAST=2, STA_FLAGS2=67, AUTHORIZED=BIT(1).
 * ==================================================================== */

static int g_nl_family = -1;
static int g_nl_cmd_fd = -1;       /* synchronous commands            */
static int g_nl_evt_fd = -1;       /* mgmt + control-port events      */
static uint32_t g_nl_seq;

struct nl_buf { struct nlmsghdr *nlh; uint8_t buf[NL_MAX_MSG]; };

static void nlb_init(struct nl_buf *m, uint16_t cmd, uint16_t flags)
{
    memset(m, 0, sizeof(*m));
    m->nlh = (struct nlmsghdr *)m->buf;
    m->nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    m->nlh->nlmsg_type = (uint16_t)g_nl_family;
    m->nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    m->nlh->nlmsg_seq = ++g_nl_seq;
    struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(m->nlh);
    g->cmd = cmd;
    g->version = 1;
}

static struct nlattr *nlb_put(struct nl_buf *m, uint16_t type,
                              const void *data, size_t len)
{
    size_t off = NLMSG_ALIGN(m->nlh->nlmsg_len);
    size_t alen = NLA_HDRLEN + len;
    if (off + NLA_ALIGN(alen) > sizeof(m->buf)) {
        fprintf(stderr, "nl80211: message overflow\n");
        return NULL;
    }
    struct nlattr *a = (struct nlattr *)(m->buf + off);
    a->nla_type = type;
    a->nla_len = (uint16_t)alen;
    if (len && data) memcpy((uint8_t *)a + NLA_HDRLEN, data, len);
    memset((uint8_t *)a + alen, 0, NLA_ALIGN(alen) - alen);
    m->nlh->nlmsg_len = off + NLA_ALIGN(alen);
    return a;
}
static void nlb_u8 (struct nl_buf *m, uint16_t t, uint8_t v)  { nlb_put(m,t,&v,1); }
static void nlb_u16(struct nl_buf *m, uint16_t t, uint16_t v) { nlb_put(m,t,&v,2); }
static void nlb_u32(struct nl_buf *m, uint16_t t, uint32_t v) { nlb_put(m,t,&v,4); }
static void nlb_flag(struct nl_buf *m, uint16_t t)            { nlb_put(m,t,NULL,0); }
static struct nlattr *nlb_nest(struct nl_buf *m, uint16_t t)
{
    return nlb_put(m, (uint16_t)(t | NLA_F_NESTED), NULL, 0);
}
static void nlb_nest_end(struct nl_buf *m, struct nlattr *a)
{
    a->nla_len = (uint16_t)((uint8_t *)m->buf + m->nlh->nlmsg_len -
                            (uint8_t *)a);
}

static int nl_send_ack(int fd, struct nl_buf *m)
{
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, m->buf, m->nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -errno;

    uint8_t rbuf[NL_MAX_MSG];
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, 2000);
        if (pr == 0) return -ETIMEDOUT;
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        int n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != m->nlh->nlmsg_seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nlh);
                return e->error;              /* 0 = ack */
            }
            if (nlh->nlmsg_type == NLMSG_DONE) return 0;
        }
    }
}

static int nl_open_socket(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) return -1;
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int nl_resolve_family(int fd)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        uint8_t buf[64];
    } req;
    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 0x5443;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;
    struct nlattr *a = (struct nlattr *)((uint8_t *)&req +
                                         NLMSG_ALIGN(req.n.nlmsg_len));
    a->nla_type = CTRL_ATTR_FAMILY_NAME;
    a->nla_len = NLA_HDRLEN + 8;
    memcpy((uint8_t *)a + NLA_HDRLEN, "nl80211", 8);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + NLA_ALIGN(a->nla_len);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.n.nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;

    uint8_t rbuf[4096];
    int n = recv(fd, rbuf, sizeof(rbuf), 0);
    if (n <= 0) return -1;
    for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
         nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
        int alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
        struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                              GENL_HDRLEN);
        for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
             x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
             alen -= NLA_ALIGN(x->nla_len),
             x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
            if ((x->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID)
                return *(uint16_t *)((uint8_t *)x + NLA_HDRLEN);
        }
    }
    return -1;
}

static int nl_cmd_open(void)
{
    if (g_nl_cmd_fd >= 0) return 0;
    g_nl_family = -1;
    int fd = nl_open_socket();
    if (fd < 0) return -1;
    int fam = nl_resolve_family(fd);
    if (fam < 0) {
        close(fd);
        return -1;
    }
    g_nl_family = fam;
    g_nl_cmd_fd = fd;
    printf("nl80211: family=%d cmd-socket=%d\n", fam, fd);
    fflush(stdout);
    return 0;
}

/* Resolve a multicast group id ("mlme") for NETLINK_ADD_MEMBERSHIP. */
static int nl_resolve_group(int fd, const char *name)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        uint8_t buf[64];
    } req;
    struct sockaddr_nl sa;
    size_t nl = strlen(name) + 1;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = ++g_nl_seq;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;
    struct nlattr *a = (struct nlattr *)((uint8_t *)&req +
                                         NLMSG_ALIGN(req.n.nlmsg_len));
    a->nla_type = CTRL_ATTR_FAMILY_NAME;
    a->nla_len = (uint16_t)(NLA_HDRLEN + 8);
    memcpy((uint8_t *)a + NLA_HDRLEN, "nl80211", 8);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + NLA_ALIGN(a->nla_len);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.n.nlmsg_len, 0, (struct sockaddr *)&sa,
               sizeof(sa)) < 0)
        return -1;

    uint8_t rbuf[4096];
    for (;;) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, 1000) <= 0) return -1;
        int n = recv(fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) return -1;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != req.n.nlmsg_seq) continue;
            if (nlh->nlmsg_type != GENL_ID_CTRL) continue;
            int alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                                  GENL_HDRLEN);
            for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
                 x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
                 alen -= NLA_ALIGN(x->nla_len),
                 x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
                if ((x->nla_type & NLA_TYPE_MASK) != CTRL_ATTR_MCAST_GROUPS)
                    continue;
                int glen = x->nla_len - NLA_HDRLEN;
                struct nlattr *g = (struct nlattr *)((uint8_t *)x + NLA_HDRLEN);
                for (; glen >= (int)NLA_HDRLEN && g->nla_len >= NLA_HDRLEN &&
                     g->nla_len <= glen;
                     glen -= NLA_ALIGN(g->nla_len),
                     g = (struct nlattr *)((uint8_t *)g + NLA_ALIGN(g->nla_len))) {
                    int elen = g->nla_len - NLA_HDRLEN;
                    struct nlattr *e = (struct nlattr *)((uint8_t *)g +
                                                         NLA_HDRLEN);
                    const char *gname = NULL;
                    int gid = -1;
                    for (; elen >= (int)NLA_HDRLEN &&
                         e->nla_len >= NLA_HDRLEN && e->nla_len <= elen;
                         elen -= NLA_ALIGN(e->nla_len),
                         e = (struct nlattr *)((uint8_t *)e +
                                               NLA_ALIGN(e->nla_len))) {
                        int t = e->nla_type & NLA_TYPE_MASK;
                        if (t == CTRL_ATTR_MCAST_GRP_NAME)
                            gname = (const char *)e + NLA_HDRLEN;
                        else if (t == CTRL_ATTR_MCAST_GRP_ID &&
                                 e->nla_len >= NLA_HDRLEN + 4)
                            gid = (int)*(uint32_t *)((uint8_t *)e +
                                                      NLA_HDRLEN);
                    }
                    if (gname && gid >= 0 && !strncmp(gname, name, nl))
                        return gid;
                }
            }
        }
    }
}

/* Current nl80211 iftype of a netdev (AP_VLAN detection for the bridge). */
static int nl_get_iftype(int ifindex)
{
    if (ifindex <= 0 || nl_cmd_open() != 0) return -1;
    struct nl_buf m;
    struct sockaddr_nl sa;
    uint8_t rbuf[NL_MAX_MSG];

    nlb_init(&m, NL80211_CMD_GET_INTERFACE, 0);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(g_nl_cmd_fd, m.buf, m.nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -1;
    for (;;) {
        struct pollfd pfd = { .fd = g_nl_cmd_fd, .events = POLLIN,
                              .revents = 0 };
        if (poll(&pfd, 1, 1000) <= 0) return -1;
        int n = recv(g_nl_cmd_fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) return -1;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf; NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != m.nlh->nlmsg_seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) return -1;
            int alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                                  GENL_HDRLEN);
            for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
                 x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
                 alen -= NLA_ALIGN(x->nla_len),
                 x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
                if ((x->nla_type & NLA_TYPE_MASK) == NL80211_ATTR_IFTYPE &&
                    x->nla_len >= NLA_HDRLEN + 4)
                    return (int)*(uint32_t *)((uint8_t *)x + NLA_HDRLEN);
            }
        }
    }
}

/* Supported cipher suites of a wiphy, from NL80211_CMD_GET_WIPHY
   (NL80211_ATTR_CIPHER_SUITES, a u32 array).  Returns bytes written. */
static int nl_get_wiphy_ciphers(int phy, uint8_t *out, int outmax)
{
    if (nl_cmd_open() != 0) return 0;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_GET_WIPHY, 0);
    nlb_u32(&m, NL80211_ATTR_WIPHY, (uint32_t)phy);
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(g_nl_cmd_fd, m.buf, m.nlh->nlmsg_len, 0,
               (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return 0;
    uint8_t rbuf[NL_MAX_MSG];
    for (;;) {
        struct pollfd pfd = { .fd = g_nl_cmd_fd, .events = POLLIN,
                              .revents = 0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) return 0;
        int n = recv(g_nl_cmd_fd, rbuf, sizeof(rbuf), 0);
        if (n <= 0) return 0;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)rbuf;
             NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_seq != m.nlh->nlmsg_seq) continue;
            if (nlh->nlmsg_type == NLMSG_ERROR) return 0;
            int alen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
            struct nlattr *at = (struct nlattr *)((uint8_t *)NLMSG_DATA(nlh) +
                                                  GENL_HDRLEN);
            for (struct nlattr *x = at; alen >= (int)NLA_HDRLEN &&
                 x->nla_len >= NLA_HDRLEN && x->nla_len <= alen;
                 alen -= NLA_ALIGN(x->nla_len),
                 x = (struct nlattr *)((uint8_t *)x + NLA_ALIGN(x->nla_len))) {
                if ((x->nla_type & NLA_TYPE_MASK) !=
                    NL80211_ATTR_CIPHER_SUITES) continue;
                int bytes = x->nla_len - NLA_HDRLEN;
                uint32_t *v = (uint32_t *)((uint8_t *)x + NLA_HDRLEN);
                int cnt = 0;
                for (int i = 0; i < bytes / 4 && cnt < outmax; i++) {
                    out[cnt * 4 + 0] = (uint8_t)(v[i] >> 24);
                    out[cnt * 4 + 1] = (uint8_t)(v[i] >> 16);
                    out[cnt * 4 + 2] = (uint8_t)(v[i] >> 8);
                    out[cnt * 4 + 3] = (uint8_t)v[i];
                    cnt++;
                }
                return cnt * 4;
            }
            return 0;
        }
    }
}

/* port -> netdev.  The manager addresses a VAP as (phy<<8)|vapid; the
   interface created for it is phy<N>-ap<M> (see createvap_response). */
struct port_map {
    int used;
    int port;
    int ifindex;
    uint8_t mac[6];
};
static struct port_map g_pmap[128];

static void pmap_set(int port, int ifindex, const uint8_t mac[6])
{
    int slot = -1;
    for (int i = 0; i < 128; i++) {
        if (g_pmap[i].used && g_pmap[i].port == port) { slot = i; break; }
        if (!g_pmap[i].used && slot < 0) slot = i;
    }
    if (slot < 0) return;
    g_pmap[slot].used = 1;
    g_pmap[slot].port = port;
    g_pmap[slot].ifindex = ifindex;
    if (mac) memcpy(g_pmap[slot].mac, mac, 6);
}

static int pmap_get(int port, int *ifindex, uint8_t mac[6])
{
    for (int i = 0; i < 128; i++)
        if (g_pmap[i].used && g_pmap[i].port == port) {
            if (ifindex) *ifindex = g_pmap[i].ifindex;
            if (mac) memcpy(mac, g_pmap[i].mac, 6);
            return 1;
        }
    return 0;
}

/* Resolve (phy<<8)|vap to an ifindex, falling back to sysfs. */
static int vap_ifindex(int port, uint8_t mac[6])
{
    int ifindex = 0;
    if (pmap_get(port, &ifindex, mac) && ifindex > 0)
        return ifindex;
    char ifname[32];
    snprintf(ifname, sizeof(ifname), "phy%d-ap%d", port >> 8, port & 0xff);
    ifindex = read_sysfs_int(ifname, "ifindex");
    if (ifindex <= 0) {
        char alt[32];
        snprintf(alt, sizeof(alt), "wlan%d", (port >> 8) * 2 + (port & 1));
        ifindex = read_sysfs_int(alt, "ifindex");
        if (ifindex > 0) snprintf(ifname, sizeof(ifname), "%s", alt);
    }
    if (ifindex > 0) {
        if (mac) read_sysfs_mac(ifname, mac);
        pmap_set(port, ifindex, mac);
    }
    return ifindex;
}

/* One key.  group=0 -> PAIRWISE with ATTR_MAC; group=1 -> GTK/IGTK. */
static int nl_install_key(int ifindex, const uint8_t *mac, int idx,
                          uint32_t cipher, const uint8_t *key, size_t klen,
                          const uint8_t *seq, size_t slen, int group)
{
    if (ifindex <= 0 || !key || !klen) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_NEW_KEY, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    if (mac && !group) nlb_put(&m, NL80211_ATTR_MAC, mac, 6);

    struct nlattr *k = nlb_nest(&m, NL80211_ATTR_KEY);
    nlb_put(&m, NL80211_KEY_DATA, key, klen);
    nlb_u32(&m, NL80211_KEY_CIPHER, cipher);
    nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
    if (seq && slen) nlb_put(&m, NL80211_KEY_SEQ, seq, slen);
    nlb_u32(&m, NL80211_KEY_TYPE,
            group ? NL80211_KEYTYPE_GROUP : NL80211_KEYTYPE_PAIRWISE);
    nlb_nest_end(&m, k);
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* Make idx the default RX key.  GTK -> DEFAULT(+MULTICAST), IGTK ->
   DEFAULT_MGMT, BIGTK -> DEFAULT_BEACON (T4 §3.2). */
static int nl_set_default(int ifindex, int idx, int group, int is_igtk)
{
    if (ifindex <= 0) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_SET_KEY, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    struct nlattr *k = nlb_nest(&m, NL80211_ATTR_KEY);
    nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
    if (is_igtk && idx >= 4 && idx <= 5) {
        nlb_flag(&m, NL80211_KEY_DEFAULT_MGMT);
    } else if (is_igtk) {
        nlb_flag(&m, NL80211_KEY_DEFAULT_BEACON);
    } else {
        nlb_flag(&m, NL80211_KEY_DEFAULT);
        if (group) {
            struct nlattr *t = nlb_nest(&m, NL80211_KEY_DEFAULT_TYPES);
            nlb_flag(&m, NL80211_KEY_DEFAULT_TYPE_MULTICAST);
            nlb_nest_end(&m, t);
        }
    }
    nlb_nest_end(&m, k);
    int r = nl_send_ack(g_nl_cmd_fd, &m);
    if (r == -EINVAL && !is_igtk) {
        /* Older kernels take the plain flag only. */
        nlb_init(&m, NL80211_CMD_SET_KEY, NLM_F_ACK);
        nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
        k = nlb_nest(&m, NL80211_ATTR_KEY);
        nlb_u8(&m, NL80211_KEY_IDX, (uint8_t)idx);
        nlb_flag(&m, NL80211_KEY_DEFAULT);
        nlb_nest_end(&m, k);
        r = nl_send_ack(g_nl_cmd_fd, &m);
    }
    return r;
}

/* 4-way complete: exactly hostapd's SET_STATION STA_FLAGS2 AUTHORIZED. */
static int nl_sta_authorize(int ifindex, const uint8_t mac[6])
{
    if (ifindex <= 0) return -EINVAL;
    struct nl_buf m;
    struct nl80211_sta_flag_update upd;
    memset(&upd, 0, sizeof(upd));
    upd.mask = 1u << NL80211_STA_FLAG_AUTHORIZED;
    upd.set  = 1u << NL80211_STA_FLAG_AUTHORIZED;
    nlb_init(&m, NL80211_CMD_SET_STATION, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    nlb_put(&m, NL80211_ATTR_STA_FLAGS2, &upd, sizeof(upd));
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* Inject a bare EAPOL frame (EAPOL header first) to one station. */
static int nl_control_port_tx(int ifindex, const uint8_t mac[6],
                              const uint8_t *eapol, size_t len)
{
    if (ifindex <= 0 || !mac || !eapol || len < 4) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_CONTROL_PORT_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    nlb_u16(&m, NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_EAPOL);
    nlb_put(&m, NL80211_ATTR_MAC, mac, 6);
    nlb_put(&m, NL80211_ATTR_FRAME, eapol, len);
    nlb_flag(&m, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT);
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* Transmit one management frame on an AP netdev (manager-initiated Deauth /
 * Action from 0x2019).  No ACK wait: a Deauth is fire-and-forget and we must
 * not stall the TLS loop for a missing ack. */
static int nl_mgmt_tx(int ifindex, uint32_t freq, const uint8_t *fr, size_t len)
{
    if (ifindex <= 0 || !fr || len < 24 || len > 2048) return -EINVAL;
    struct nl_buf m;
    nlb_init(&m, NL80211_CMD_FRAME, NLM_F_ACK);
    nlb_u32(&m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    if (freq) {
        nlb_u32(&m, NL80211_ATTR_WIPHY_FREQ, freq);
        nlb_u32(&m, NL80211_ATTR_DURATION, 0);
    }
    nlb_put(&m, NL80211_ATTR_FRAME, fr, len);
    nlb_flag(&m, NL80211_ATTR_DONT_WAIT_FOR_ACK);
    return nl_send_ack(g_nl_cmd_fd, &m);
}

/* ---------------- TLV iterator (u16 tag | u16 len | value) ------------- */
struct tlv_it { const uint8_t *p; size_t len; };
static int tlv_next(struct tlv_it *it, uint16_t *tag,
                    const uint8_t **val, size_t *vlen)
{
    if (it->len < 4) return 0;
    uint16_t t = rd16(it->p), l = rd16(it->p + 2);
    if ((size_t)l > it->len - 4) return 0;
    *tag = t;
    *val = it->p + 4;
    *vlen = l;
    it->p += 4 + l;
    it->len -= 4 + l;
    return 1;
}

static void dump_raw(const char *tag, uint16_t type, uint16_t port,
                     const uint8_t *b, size_t n)
{
    if (!getenv("CAPAGENT_DEBUG")) return;
    int fd = open("/tmp/capagent-msgs.log",
                  O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;
    FILE *f = fdopen(fd, "a");
    if (!f) { close(fd); return; }
    fprintf(f, "%ld %s type=0x%04x port=0x%04x len=%zu ",
            (long)time(NULL), tag, type, port, n);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fprintf(f, "\n");
    fclose(f);
}

/* ---- 0xC029 config sync: optional 0x77 nested config tree ------------ */
/* Log/dump only: the tree is not applied yet.  Leaf keys are the ones
   recovered from the CAP config-apply path (arm ww2 0x41c18/0x422c0);
   the nesting above them is not decoded, so recurse into any element that
   looks like another TLV list. */

enum { CFG_STR, CFG_U32, CFG_U8 };

struct cfg_key {
    uint16_t id;
    const char *name;
    int kind;
};

static const struct cfg_key cfg_keys[] = {
    {0x1004, "ssid", CFG_STR},
    {0x200d, "iface-field", CFG_U32},
    {0xbb06, "vlan-id", CFG_U32},
    {0x6002, "datapath/security", CFG_U32},
    {0xd000, "authentication-types", CFG_U32},
    {0xd001, "cipher/pmf", CFG_U8},
    {0xd002, "security-field", CFG_U32},
    {0xd003, "cipher/pmf", CFG_U8},
    {0xd004, "cipher/pmf", CFG_U8},
    {0xd005, "security-field", CFG_U32},
    {0xd006, "security-field", CFG_U32},
    {0xd007, "security-field", CFG_U32},
    {0xd008, "security-field", CFG_U32},
    {0xd90f, "passphrase/dpp", CFG_STR},
    {0x2014, "pmf", CFG_U8},
    {0x2015, "key-holder", CFG_U32},
    {0x2017, "pmf", CFG_U8},
    {0x2018, "ptk", CFG_U32},
    {0x2019, "pmk-r0-key-holder-id", CFG_STR},
    {0x2021, "reassoc-timeout", CFG_U32},
    {0x2023, "pmf", CFG_U8},
};

struct cfg_seen {
    int have_ssid, have_vlan, have_auth, have_pass;
    char ssid[33];
    uint32_t vlan;
    uint32_t auth;
    char passphrase[64];
};

static struct cfg_seen g_cfg_seen;
static int g_cfg_lines;

