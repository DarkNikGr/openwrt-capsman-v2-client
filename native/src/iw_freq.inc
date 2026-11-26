/* Parse one `iw phy ... info` frequency entry (old integer and newer .0
 * MHz formats).  A scanf conversion count is not enough: "%u MHz" also
 * accepts "* 1 (20 MHz)" after converting the unrelated number. */
static int parse_iw_frequency(const char *line, uint32_t *freq)
{
    const unsigned char *p = (const unsigned char *)line;
    char *end;
    unsigned long mhz;

    while (*p == ' ' || *p == '\t') p++;
    if (*p++ != '*' || (*p != ' ' && *p != '\t')) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (!isdigit(*p)) return 0;
    mhz = strtoul((const char *)p, &end, 10);
    p = (const unsigned char *)end;
    if (*p == '.') {
        p++;
        if (!isdigit(*p)) return 0;
        do {
            if (*p != '0') return 0;
            p++;
        } while (isdigit(*p));
    }
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp((const char *)p, "MHz", 3) != 0) return 0;
    p += 3;
    if (*p && !isspace(*p)) return 0;
    while (*p == ' ' || *p == '\t') p++;
    /* Older iw versions may omit the channel in brackets.  When present,
     * require a complete numeric channel before accepting its flags. */
    if (*p == '[') {
        p++;
        if (!isdigit(*p)) return 0;
        while (isdigit(*p)) p++;
        if (*p++ != ']') return 0;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (*p && *p != '\n' && *p != '\r' && *p != '(') return 0;
    if (strstr(line, "(disabled)")) return 0;
    /* Do not mislabel sub-GHz/60 GHz entries as 2.4/5/6 GHz bands. */
    if (mhz < 2300 || mhz > 7125) return 0;
    *freq = (uint32_t)mhz;
    return 1;
}
