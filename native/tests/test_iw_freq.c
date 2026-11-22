#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/iw_freq.inc"

static void accepted(const char *line, uint32_t expected)
{
    uint32_t freq = 0;
    assert(parse_iw_frequency(line, &freq));
    assert(freq == expected);
}

static void rejected(const char *line)
{
    uint32_t freq = 0xdeadbeef;
    assert(!parse_iw_frequency(line, &freq));
    assert(freq == 0xdeadbeef);
}

int main(int argc, char **argv)
{
    /* Real hwsim iw 6.7 and older integer-MHz output.  `no IR` is a
     * regulatory restriction, not a disabled frequency: parser only. */
    accepted("\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n", 2412);
    accepted("\t\t\t* 5180.0 MHz [36] (20.0 dBm) (no IR)\n", 5180);
    accepted("\t* 5180 MHz [36] (no IR)\n", 5180);
    accepted(" * 5200 MHz [40]\n", 5200);
    accepted(" * 2462 MHz\n", 2462);
    accepted(" * 2412.00 MHz [1]\r\n", 2412);
    rejected(" * 5955.0 MHz [1] (disabled)\n");
    rejected(" * 5180 MHz [36] (20 dBm) (disabled) (no IR)\n");
    rejected(" * 1 (20 MHz)\n");
    /* These rate bullets occur in the saved hwsim iw phy output. */
    rejected("\t\t* 1.0 Mbps\n");
    rejected("\t\t* 2.0 Mbps (short preamble supported)\n");
    rejected("\t\t* 54.0 Mbps\n");
    rejected(" * 1 (20 MHz) 2412 MHz\n");
    rejected(" * MCS: 1 2 3\n");
    rejected(" * 2412.5 MHz [1]\n");
    rejected(" * 2412. MHz [1]\n");
    rejected(" * 2412.0MHz [1]\n");
    rejected(" * 2412 MHzgarbage [1]\n");
    rejected(" * 2412 MHz [x]\n");
    rejected(" * 2412 MHz [1\n");
    rejected(" * 2412 MHz junk\n");
    rejected(" * 2412 MHz [1] junk\n");
    rejected(" * +2412 MHz [1]\n");
    rejected(" * -2412 MHz [1]\n");
    rejected(" * 0 MHz [1]\n");
    rejected(" * 58320 MHz [1]\n");
    rejected(" * 184467440737095516160 MHz [1]\n");
    rejected("Frequency: 2412 MHz\n");

    if (argc > 1) {
        FILE *fp = fopen(argv[1], "r");
        char line[512];
        unsigned count = 0, low = 0, high = 0;
        uint32_t freq;
        assert(fp);
        while (fgets(line, sizeof(line), fp))
            if (parse_iw_frequency(line, &freq)) {
                count++;
                if (freq < 3000) low++;
                else high++;
            }
        assert(!ferror(fp));
        fclose(fp);
        printf("iw frequency fixture: %u channels (%u 2.4 GHz, %u 5+ GHz)\n",
               count, low, high);
        assert(count == 38 && low == 14 && high == 24);
    }
    puts("iw frequency parser: PASS");
    return 0;
}
