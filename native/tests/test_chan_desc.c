/* Host-only unit test for the 0xD00B 0x000A channel descriptor.
 *
 * It compiles the exact builder that ships (native/src/chan_desc.inc) with a
 * tiny TLV helper set, then checks the band byte and the wide-channel centre
 * fields.  No kernel module, radio or manager is touched.
 *
 * Build/run: tests/run-chan-desc-test.sh
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define BODY_MAX 16384

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}
static size_t put_el(uint8_t *p, uint16_t id, const void *data, uint16_t len)
{
    put16(p, id);
    put16(p + 2, len);
    if (len && data) memcpy(p + 4, data, len);
    return 4 + len;
}

/* Stand-in for util.inc's NEWPHY 6 GHz id (CAPAGENT_BAND6). */
static uint8_t band6_code(void) { return 0x06; }

#include "../src/chan_desc.inc"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int fails;

static void check(const char *what, uint32_t got, uint32_t want)
{
    if (got != want) {
        printf("FAIL %-28s got 0x%x want 0x%x\n", what, got, want);
        fails++;
    } else {
        printf("ok   %-28s 0x%x\n", what, got);
    }
}

/* Parse one descriptor and verify fields.  Returns 1 on structural error. */
static int parse_desc2(const uint8_t *b, size_t n, uint32_t freq, uint8_t width,
                       uint8_t band, uint32_t ccfi, uint32_t ccfi2)
{
    if (n < 4 || rd16(b) != 0x0a) { printf("FAIL outer TLV id\n"); fails++; return 1; }
    uint16_t ol = rd16(b + 2);
    const uint8_t *s = b + 4;
    uint32_t got_f = 0, got_c = 0, got_c2 = 0;
    uint8_t got_w = 0, got_b = 0;
    int have_c = 0, have_c2 = 0;
    for (uint16_t i = 0; i + 4 <= ol; ) {
        uint16_t id = rd16(s + i), l = rd16(s + i + 2);
        const uint8_t *v = s + i + 4;
        if (i + 4 + l > ol) { printf("FAIL inner overrun\n"); fails++; return 1; }
        if (id == 0x0b && l == 4) got_f = rd32(v);
        if (id == 0x0c && l == 1) got_w = v[0];
        if (id == 0x0d && l == 4) { got_c = rd32(v); have_c = 1; }
        if (id == 0x0e && l == 4) { got_c2 = rd32(v); have_c2 = 1; }
        if (id == 0x10 && l == 1) got_b = v[0];
        i += 4 + l;
    }
    check("frequency", got_f, freq);
    check("width", got_w, width);
    check("band", got_b, band);
    check("centre present", (uint32_t)have_c, width > 1 ? 1 : 0);
    if (width > 1) check("centre freq", got_c, ccfi);
    check("second centre present", (uint32_t)have_c2, ccfi2 ? 1 : 0);
    if (ccfi2) check("second centre freq", got_c2, ccfi2);
    return 0;
}

static int parse_desc(const uint8_t *b, size_t n, uint32_t freq, uint8_t width,
                      uint8_t band, uint32_t ccfi)
{
    return parse_desc2(b, n, freq, width, band, ccfi, 0);
}

int main(void)
{
    unsetenv("CAPAGENT_CHAN_BAND6");
    check("chan_band6 default", chan_band6(), 0x06);
    setenv("CAPAGENT_CHAN_BAND6", "04", 1);
    check("chan_band6 override", chan_band6(), 0x04);

    /* Exactly the calls add_channel_tlvs() makes for 5955 MHz.  On
     * RouterOS 7.25.1 width 5 is 160 MHz (centre 6025) and width 4 is the
     * two-centre 80+80 form; width 6 is 320 MHz, whose centre for 5955 in
     * a 64-channel block is channel 31 (6105 MHz). */
    static const struct { uint8_t w; uint32_t ccfi, ccfi2; } d[] = {
        { 1, 0, 0 }, { 2, 5965, 0 }, { 3, 5985, 0 }, { 5, 6025, 0 },
        { 6, 6105, 0 }, { 4, 5985, 5775 },
    };
    for (size_t i = 0; i < sizeof(d) / sizeof(d[0]); i++) {
        uint8_t b[64] = {0};
        size_t n = add_chan_desc2(b, 0, 5955, d[i].w, 0x06,
                                  d[i].ccfi, d[i].ccfi2);
        printf("-- 5955/width %u\n", d[i].w);
        parse_desc2(b, n, 5955, d[i].w, 0x06, d[i].ccfi, d[i].ccfi2);
    }

    /* Width 6 must not grow an inferred second-centre field. */
    {
        uint8_t b[64] = {0};
        size_t n = add_chan_desc(b, 0, 5955, 6, 0x06, 6105);
        parse_desc(b, n, 5955, 6, 0x06, 6105);
    }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nall checks passed\n", fails);
    return fails ? 1 : 0;
}
