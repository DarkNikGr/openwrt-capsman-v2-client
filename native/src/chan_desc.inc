/* chan_desc.inc — the 0x000A channel-descriptor builder.
 *
 * Kept in its own header so the host unit test (tests/test_chan_desc.c) can
 * include exactly the code that ships, without dragging in the whole agent.
 * Included by channels.inc after util.inc (put_el/put32/band6_code).
 */

/* Band byte a 6 GHz descriptor is advertised with.  It is deliberately a
 * separate knob from CAPAGENT_BAND6: the NEWPHY 0x4d radio view and the
 * 0xD00B 0x000A descriptor are two different manager inputs, and F79 swept
 * only the former.  Default stays 0x06 so shipped behaviour is unchanged. */
static uint8_t __attribute__((unused)) chan_band6(void)
{
    const char *e = getenv("CAPAGENT_CHAN_BAND6");
    if (e && *e) return (uint8_t)strtol(e, NULL, 16);
    return band6_code();
}

static size_t add_chan_desc(uint8_t *b, size_t n, uint32_t freq,
                            uint8_t width, uint8_t band, uint32_t ccfi)
{
    uint8_t sub[48], f[4], c[4];
    size_t sn = 0;
    put32(f, freq);
    sn += put_el(sub + sn, 0x0b, f, 4);
    sn += put_el(sub + sn, 0x0c, &width, 1);
    if (width > 1) {
        put32(c, ccfi);
        sn += put_el(sub + sn, 0x0d, c, 4);
    }
    sn += put_el(sub + sn, 0x10, &band, 1);
    return n + put_el(b + n, 0x0a, sub, (uint16_t)sn);
}
