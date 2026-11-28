/* chan6.inc — 6 GHz channel width / operating-class mapping.
 *
 * Shared by the 0xD00B descriptor builder (channels.inc) and the hostapd
 * config writer (vap.inc).  It is a pure translation unit so the host unit
 * test (tests/test_chan6.c) can compile the exact mapping that ships.
 *
 * RouterOS width codes: 1=20, 2=40, 3=80, 4=80+80, 5=160, 6=320.
 * A 6 GHz profile cannot use 80+80, so width 4 is accepted as 160 (the
 * manager has used it for that in the past).  Width 6 is EHT-only: an HE
 * radio falls back to its maximum contiguous width (160 MHz) instead of
 * claiming 320.
 */
#ifndef CAPAGENT_CHAN6_INC
#define CAPAGENT_CHAN6_INC

/* 6 GHz blocks: 20 MHz channels are numbered 1,5,9,... (5 MHz steps in the
 * channel number per 20 MHz).  A 40/80/160 MHz block starts at 1, 1, 1 and
 * the centre channel is start+2/+6/+14. */
static uint32_t c40_6g(uint32_t f)
{
    int ch = (int)((f - 5950) / 5);
    int start = ((ch - 1) / 8) * 8 + 1;
    return 5950 + (uint32_t)(start + 2) * 5;
}

static uint32_t c80_6g(uint32_t f)
{
    int ch = (int)((f - 5950) / 5);
    int start = ((ch - 1) / 16) * 16 + 1;
    return 5950 + (uint32_t)(start + 6) * 5;
}

static uint32_t c160_6g(uint32_t f)
{
    int ch = (int)((f - 5950) / 5);
    int start = ((ch - 1) / 32) * 32 + 1;
    return 5950 + (uint32_t)(start + 14) * 5;
}

/* 320 MHz is a 64-channel block; its centre is start+30.  In 6 GHz the
 * 320 MHz-1 centres are 31/95/159/223.  (The offset 320 MHz-2 alignment
 * uses 63/127/191; a single primary frequency cannot select both, so only
 * the aligned-64 form is advertised.) */
static uint32_t c320_6g(uint32_t f)
{
    int ch = (int)((f - 5950) / 5);
    int start = ((ch - 1) / 64) * 64 + 1;
    return 5950 + (uint32_t)(start + 30) * 5;
}

/* One 6 GHz VAP channel plan.  The field names match hostapd's config:
 * op_class is IEEE 802.11 operating class, he_oper_chwidth/eht_oper_chwidth
 * are enum oper_chan_width values (1=80, 2=160, 9=320), and the centre
 * index is eht_oper_centr_freq_seg0_idx / he_oper_centr_freq_seg0_idx. */
struct chan6_plan {
    int chan;             /* primary channel number (1..233) */
    int width;            /* 20/40/80/160/320 MHz */
    int opclass;          /* 131/132/133/134/137 */
    int he_chwidth;       /* hostapd he_oper_chwidth */
    int eht;              /* EHT (802.11be) BSS */
    int eht_chwidth;      /* hostapd eht_oper_chwidth (9 = 320) */
    uint32_t center;      /* centre frequency in MHz */
    int center_idx;       /* centre frequency channel index */
};

/* Map a manager width code to the hostapd/6 GHz plan.  eht_ok is true only
 * when both the radio and the hostapd binary support EHT; otherwise width
 * 6 falls back to 160 MHz so the BSS is not silently started at 20 MHz. */
static void chan6_plan_for(int wcode, int eht_ok, uint32_t freq,
                           struct chan6_plan *p)
{
    int width;
    p->chan = (int)((freq - 5950) / 5);
    if (p->chan < 1 || p->chan > 233) p->chan = 1;

    switch (wcode) {
    case 2:  width = 40; break;
    case 3:  width = 80; break;
    case 4:
    case 5:  width = 160; break;
    case 6:  width = eht_ok ? 320 : 160; break;
    default: width = 20; break;
    }

    p->width = width;
    p->eht = width == 320;
    p->opclass = width == 320 ? 137 : width == 160 ? 134 :
                 width == 80 ? 133 : width == 40 ? 132 : 131;
    /* hostapd derives these from op_class in the 6 GHz band, but writing
     * the matching enum values keeps the config self-consistent and gives
     * an older hostapd the same answer. */
    p->he_chwidth = width >= 160 ? 2 : width == 80 ? 1 : 0;
    p->eht_chwidth = width == 320 ? 9 : 0;
    p->center = width == 320 ? c320_6g(freq) :
                width == 160 ? c160_6g(freq) :
                width == 80 ? c80_6g(freq) :
                width == 40 ? c40_6g(freq) : freq;
    p->center_idx = (int)((p->center - 5950) / 5);
}

/* hostapd channel lines for a 6 GHz BSS.  For 320 MHz the HE operation is
 * capped at 160 (HE has no 320) and the width lives in the EHT operation;
 * hostapd requires the EHT centre index or it emits ccfs0 = channel. */
static void chan6_write(FILE *f, const struct chan6_plan *p)
{
    fprintf(f, "hw_mode=a\nchannel=%d\nop_class=%d\n", p->chan, p->opclass);
    fprintf(f, "ieee80211ax=1\nhe_6ghz_reg_pwr_type=0\n");
    if (p->width > 20)
        fprintf(f, "he_oper_chwidth=%d\n"
                   "he_oper_centr_freq_seg0_idx=%d\n",
                p->he_chwidth, p->center_idx);
    if (p->eht)
        fprintf(f, "ieee80211be=1\n"
                   "eht_oper_chwidth=%d\n"
                   "eht_oper_centr_freq_seg0_idx=%d\n",
                p->eht_chwidth, p->center_idx);
}

#endif /* CAPAGENT_CHAN6_INC */
