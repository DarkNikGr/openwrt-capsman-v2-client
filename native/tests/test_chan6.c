/* Host-only unit test for the 6 GHz width/op_class/centre mapping used by
 * both the 0xD00B descriptor builder and the hostapd VAP writer.
 *
 * Compiles the exact shipped code (native/src/chan6.inc); no radio, kernel
 * module or manager is touched.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../src/chan6.inc"

static int fails;

static void eq(const char *what, long got, long want)
{
    if (got != want) {
        printf("FAIL %-34s got %ld want %ld\n", what, got, want);
        fails++;
    } else {
        printf("ok   %-34s %ld\n", what, got);
    }
}

static void plan(const char *tag, int wcode, int eht, uint32_t freq,
                 int width, int opclass, int he_ch, int eht_ch,
                 uint32_t center, int cidx)
{
    struct chan6_plan p;
    printf("-- %s (width code %d, eht=%d, %u MHz)\n", tag, wcode, eht, freq);
    chan6_plan_for(wcode, eht, freq, &p);
    eq("width", p.width, width);
    eq("op_class", p.opclass, opclass);
    eq("he_oper_chwidth", p.he_chwidth, he_ch);
    eq("eht flag", p.eht, eht_ch != 0);
    eq("eht_oper_chwidth", p.eht_chwidth, eht_ch);
    eq("centre freq", p.center, center);
    eq("centre index", p.center_idx, cidx);
}

static int file_has(FILE *f, const char *needle)
{
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

int main(void)
{
    /* 5955 MHz is 6 GHz channel 1.  Widths 4 and 5 both mean 160 here. */
    plan("20", 1, 0, 5955, 20, 131, 0, 0, 5955, 1);
    plan("40", 2, 0, 5955, 40, 132, 0, 0, 5965, 3);
    plan("80", 3, 0, 5955, 80, 133, 1, 0, 5985, 7);
    plan("160 (width 4)", 4, 0, 5955, 160, 134, 2, 0, 6025, 15);
    plan("160 (width 5)", 5, 0, 5955, 160, 134, 2, 0, 6025, 15);
    /* F89: width 6 on an EHT radio is a real 320 MHz BSS. */
    plan("320 EHT", 6, 1, 5955, 320, 137, 2, 9, 6105, 31);
    /* A HE-only radio must not claim 320; its max contiguous width is 160. */
    plan("320 on HE-only", 6, 0, 5955, 160, 134, 2, 0, 6025, 15);

    /* Second 320 MHz-1 block: 6435 MHz is channel 97, centre 95 (6425). */
    plan("320 EHT block 2", 6, 1, 6435, 320, 137, 2, 9, 6425, 95);

    /* The hostapd lines are what actually fixes F89; check the exact keys. */
    {
        struct chan6_plan p;
        chan6_plan_for(6, 1, 5955, &p);
        FILE *f = tmpfile();
        if (!f) { printf("FAIL tmpfile\n"); return 1; }
        chan6_write(f, &p);
        rewind(f);
        eq("hostapd op_class=137", file_has(f, "op_class=137\n"), 1);
        rewind(f);
        eq("hostapd ieee80211be=1", file_has(f, "ieee80211be=1\n"), 1);
        rewind(f);
        eq("hostapd eht_oper_chwidth=9",
           file_has(f, "eht_oper_chwidth=9\n"), 1);
        rewind(f);
        eq("hostapd eht centre 31",
           file_has(f, "eht_oper_centr_freq_seg0_idx=31\n"), 1);
        fclose(f);
    }
    {
        struct chan6_plan p;
        chan6_plan_for(6, 0, 5955, &p);
        FILE *f = tmpfile();
        if (!f) { printf("FAIL tmpfile\n"); return 1; }
        chan6_write(f, &p);
        rewind(f);
        eq("HE-only has no ieee80211be", file_has(f, "ieee80211be"), 0);
        rewind(f);
        eq("HE-only uses op_class=134", file_has(f, "op_class=134\n"), 1);
        rewind(f);
        eq("HE-only has no eht width", file_has(f, "eht_oper_chwidth"), 0);
        fclose(f);
    }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nall checks passed\n", fails);
    return fails ? 1 : 0;
}
