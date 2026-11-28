/* chan_desc.inc — the 0x000A channel-descriptor builder.
 *
 * Kept in its own header so the host unit test (tests/test_chan_desc.c) can
 * include exactly the code that ships, without dragging in the whole agent.
 * Included by channels.inc after util.inc (put_el/put32/band6_code).
 */

/* Band byte a 6 GHz descriptor is advertised with.  It is deliberately a
 * separate knob from CAPAGENT_BAND6: the NEWPHY 0x4d radio view and the
 * 0xD00B 0x000A descriptor are two different manager inputs, and F79 swept
 * only the former.  Without the override it follows band6_code() (0x04 for
 * a HE-only radio, 0x06 for EHT). */
static uint8_t __attribute__((unused)) chan_band6(void)
{
    const char *e = getenv("CAPAGENT_CHAN_BAND6");
    if (e && *e) return (uint8_t)strtol(e, NULL, 16);
    return band6_code();
}

/* RouterOS 7.25.1 width codes as observed from the manager's channel list:
 * 1=20, 2=40, 3=80, 4=80+80, 5=160, 6=320.  0x0d is the segment-0 centre.
 * An 80+80 descriptor (width 4) needs a second segment; 0x0e is used for
 * it here, but that field is not attested by a captured manager reply, so
 * add_channel_tlvs() only emits 80+80 behind CAPAGENT_CHAN_8080.  160 and
 * 320 MHz are contiguous blocks and use only 0x0d. */
static size_t add_chan_desc2(uint8_t *b, size_t n, uint32_t freq,
                             uint8_t width, uint8_t band, uint32_t ccfi,
                             uint32_t ccfi2)
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
    if (width == 4 && ccfi2) {
        put32(c, ccfi2);
        sn += put_el(sub + sn, 0x0e, c, 4);
    }
    sn += put_el(sub + sn, 0x10, &band, 1);
    return n + put_el(b + n, 0x0a, sub, (uint16_t)sn);
}

static size_t add_chan_desc(uint8_t *b, size_t n, uint32_t freq,
                            uint8_t width, uint8_t band, uint32_t ccfi)
{
    return add_chan_desc2(b, n, freq, width, band, ccfi, 0);
}
