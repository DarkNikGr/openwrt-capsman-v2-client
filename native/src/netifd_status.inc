/* netifd_status.inc — parse `ubus call network.wireless status` (W34).
 *
 * Part of capagent.c (single translation unit) and of the host unit test
 * tests/test_netifd_status.c, so it must stay free of OS dependencies.
 *
 * netifd is the authority for the netdevs it created.  The JSON is small and
 * only two things matter to us:
 *   - every "ifname" string in the tree (wifi-iface netdevs, AP_VLANs and
 *     radio master devices): those netdevs belong to netifd;
 *   - the nearest preceding "section" (for logging which UCI section owns it)
 *     and a "pending": true flag (a reload/transition is in flight).
 *
 * We deliberately do not grep /etc/config/wireless: the config file describes
 * intent, while the status object describes the interfaces that actually
 * exist and are owned right now.
 */
#ifndef NETIFD_STATUS_INC
#define NETIFD_STATUS_INC

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define ND_NAME_MAX     32
#define ND_SECTION_MAX  32
#define ND_MAX_IFACE    128
#define ND_JSON_MAX     131072

struct nd_iface {
    char ifname[ND_NAME_MAX];
    char section[ND_SECTION_MAX];
};

struct nd_status {
    int ok;                 /* 1 = JSON was parsed */
    int pending;            /* a radio reports pending/reload in progress */
    int up;                 /* at least one radio reported up=true */
    int n;
    struct nd_iface iface[ND_MAX_IFACE];
};

static int nd_name_ok(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n >= ND_NAME_MAX)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static void nd_add(struct nd_status *st, const char *name, const char *section)
{
    if (!nd_name_ok(name) || st->n >= ND_MAX_IFACE)
        return;
    for (int i = 0; i < st->n; i++)
        if (!strcmp(st->iface[i].ifname, name))
            return;                         /* first occurrence wins */
    snprintf(st->iface[st->n].ifname, ND_NAME_MAX, "%.*s",
                 ND_NAME_MAX - 1, name);
    if (section && nd_name_ok(section))
        snprintf(st->iface[st->n].section, ND_SECTION_MAX, "%.*s",
                     ND_SECTION_MAX - 1, section);
    else
        st->iface[st->n].section[0] = 0;
    st->n++;
}

static const char *nd_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

/* p points at the opening quote.  On return p is just past the closing one. */
static int nd_string(const char **pp, char *out, size_t outlen)
{
    const char *p = *pp;
    size_t n = 0;

    if (*p != '"')
        return -1;
    p++;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1])              /* keep the escaped byte as-is */
            p++;
        if (n + 1 < outlen)
            out[n++] = *p;
        p++;
    }
    if (*p == '"')
        p++;
    out[n] = 0;
    *pp = p;
    return 0;
}

/* Cheap JSON walker: enough for ubus' flat status object.  Unknown shapes
 * are skipped byte by byte; a malformed document yields ok=0 only when there
 * is no '{' at all, because a partial walk is still a safe over-approximation
 * (we may mark a netdev as netifd-owned, never the other way round). */
static int nd_parse(const char *json, struct nd_status *st)
{
    const char *p;
    char section[ND_SECTION_MAX] = "";

    memset(st, 0, sizeof(*st));
    if (!json || !(p = strchr(json, '{')))
        return -1;

    while (*p) {
        char key[32], val[64];
        size_t k = 0;

        if (*p != '"') {
            p++;
            continue;
        }
        p++;
        while (*p && *p != '"' && k + 1 < sizeof(key))
            key[k++] = *p++;
        key[k] = 0;
        if (*p == '"')
            p++;
        p = nd_ws(p);
        if (*p != ':')
            continue;
        p = nd_ws(p + 1);

        if (*p == '"') {
            if (nd_string(&p, val, sizeof(val)) != 0)
                continue;
            if (!strcmp(key, "ifname")) {
                nd_add(st, val, section);
            } else if (!strcmp(key, "section")) {
                if (nd_name_ok(val))
                    snprintf(section, sizeof(section), "%.*s",
                             (int)sizeof(section) - 1, val);
                else
                    section[0] = 0;
            }
        } else if (*p == '{' || *p == '[') {
            /* Container value: descend into it on the next iteration so the
             * keys inside ("section", "ifname", ...) are still seen. */
            p++;
        } else {
            size_t i = 0;
            while (*p && (isalnum((unsigned char)*p) || *p == '-' ||
                          *p == '+' || *p == '.') && i + 1 < sizeof(val))
                val[i++] = *p++;
            val[i] = 0;
            if (!strcmp(key, "pending") && !strcmp(val, "true"))
                st->pending = 1;
            else if (!strcmp(key, "up") && !strcmp(val, "true"))
                st->up = 1;
        }
    }
    st->ok = 1;
    return 0;
}

static int nd_find(const struct nd_status *st, const char *ifname,
                   char *section, size_t section_len)
{
    for (int i = 0; i < st->n; i++) {
        if (strcmp(st->iface[i].ifname, ifname))
            continue;
        if (section && section_len)
            snprintf(section, section_len, "%s", st->iface[i].section);
        return 1;
    }
    return 0;
}

#endif /* NETIFD_STATUS_INC */
