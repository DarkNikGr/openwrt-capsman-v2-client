/* test_rsn.c — host-side unit test for the RSN decision the CAP feeds hostapd.
 *
 * The manager is the RSN authenticator, so the only thing capagent has to get
 * right is the translation of the manager's RSN IE (0x04 in 0x6016) into the
 * per-BSS hostapd options: AKM set, PMF, SAE/OWE external-auth, group-mgmt
 * cipher and the verbatim external_rsn_ie/RSNXE relay.  A wrong byte here
 * shows up only live, as "IE in 3/4 msg does not match" or a station that
 * refuses the BSS, so the mapping is pinned here.
 *
 * Built for the host (no cross toolchain, no radio): make -C native rsn-test.
 * The IEs are the real shapes from docs/FINDINGS.md, docs/MANAGER-ONLY.md
 * (§3.7) and the live 0x6016 logs.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/rsn_decide.h"

/* Manager's live IE, 28 bytes: PSK + MFPC + BIP-CMAC group management.
 * This is the exact blob documented in docs/MANAGER-ONLY.md §3.7. */
static const uint8_t ie_psk_mfpc[] = {
    0x30, 0x1a,
    0x01, 0x00,                                     /* version 1 */
    0x00, 0x0f, 0xac, 0x04,                         /* group CCMP */
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,             /* 1 pairwise: CCMP */
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,             /* 1 AKM: PSK */
    0x80, 0x00,                                     /* MFPC */
    0x00, 0x00,                                     /* 0 PMKIDs */
    0x00, 0x0f, 0xac, 0x06,                         /* BIP-CMAC-128 */
};

/* PSK only, no PMF: the classic WPA2-PSK profile. */
static const uint8_t ie_psk[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
    0x00, 0x00,
};

/* PSK + MFPR (required): caps 0x00c0 (MFPR implies MFPC). */
static const uint8_t ie_psk_mfpr[] = {
    0x30, 0x1a,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
    0xc0, 0x00,
    0x00, 0x00,
    0x00, 0x0f, 0xac, 0x06,
};

/* WPA3 transition: PSK + SAE with MFPC (and the RSNXE, see ie_sae_rsnxe). */
static const uint8_t ie_psk_sae[] = {
    0x30, 0x1e,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x02, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x08,
    0x80, 0x00,
    0x00, 0x00,
    0x00, 0x0f, 0xac, 0x06,
};

/* WPA3-Personal pure SAE + MFPC. */
static const uint8_t ie_sae[] = {
    0x30, 0x1a,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x08,
    0x80, 0x00,
    0x00, 0x00,
    0x00, 0x0f, 0xac, 0x06,
};

/* Enhanced Open (OWE) only + MFPC. */
static const uint8_t ie_owe[] = {
    0x30, 0x1a,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x12,             /* AKM 18 = OWE */
    0x80, 0x00,
    0x00, 0x00,
    0x00, 0x0f, 0xac, 0x06,
};

/* WPA2-PSK with SHA-256 AKM (802.11w deployments, no SAE). */
static const uint8_t ie_psk256[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x06,             /* AKM 6 = PSK-SHA256 */
    0x00, 0x00,
};

/* 802.1X (enterprise) is not an AKM the split-MAC CAP can mirror. */
static const uint8_t ie_8021x[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x01,             /* AKM 1 = 802.1X */
    0x00, 0x00,
};

static const uint8_t ie_8021x256[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x05,             /* AKM 5 = 802.1X-SHA256 */
    0x00, 0x00,
};

/* AKM 4 = FT-PSK (used by the FT cases below). */
/* AKM 11 = 802.1X Suite B 192: a suite this CAP does not implement, so the
 * policy must produce no RSN config rather than silently mislabelling it. */
static const uint8_t ie_unknown[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x0b,             /* AKM 11 */
    0x00, 0x00,
};

static const uint8_t ie_ft[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,             /* AKM 4 = FT-PSK */
    0x00, 0x00,
};

/* SAE + RSNXE, surrounded by the SSID and a vendor IE as in the real 191-byte
 * 0x6016 blob.  Element 244 must be relayed for SAE/OWE, and only there. */
static const uint8_t ie_local[] = {
    0x00, 0x04, 'l', 'a', 'b', '1',                 /* SSID */
    0xdd, 0x04, 0x00, 0x50, 0xf2, 0x04,             /* vendor (WMM) */
    0x30, 0x1a,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x08,             /* SAE */
    0x80, 0x00,
    0x00, 0x00,
    0x00, 0x0f, 0xac, 0x06,
    0xf4, 0x03, 0x8c, 0x00, 0x00,                   /* RSNXE */
    0xdd, 0x02, 0x00, 0x00,                         /* trailing vendor */
};

static void expect_head(const char *conf, const char *line)
{
    size_t l = strlen(line);
    assert(strncmp(conf, line, l) == 0 && conf[l] == '\n');
}

static void expect_line(const char *conf, const char *line)
{
    char pat[192];
    int n = snprintf(pat, sizeof(pat), "\n%s\n", line);
    assert(n > 0 && (size_t)n < sizeof(pat));
    assert(strstr(conf, pat) != NULL);
}

static void expect_absent(const char *conf, const char *needle)
{
    assert(strstr(conf, needle) == NULL);
}

static const char *conf_of(const uint8_t *ie, size_t il, int sae_override,
                           struct rsn_info *ri, struct rsn_policy *rp,
                           char *conf, size_t n)
{
    rsn_parse(ie, il, ri);
    rsn_policy_from_ie(ri, sae_override, rp);
    size_t w = rsn_conf_write(conf, n, rp);
    assert(w == strlen(conf));
    return conf;
}

/* PSK only: WPA-PSK, PMF disabled, no SAE/OWE, no external RSNXE. */
static void case_psk(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_psk, sizeof(ie_psk), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_psk);
    assert(!ri.akm_psk256 && !ri.akm_sae && !ri.akm_owe);
    assert(!ri.mfpc && !ri.mfpr);
    assert(rp.wpa == 2);
    assert(strcmp(rp.key_mgmt, "WPA-PSK") == 0);
    assert(rp.ieee80211w == 0);
    assert(!rp.group_mgmt_cmac && !rp.sae_pwe);
    assert(!rp.external_auth && !rp.want_rsnxe);
    expect_head(conf, "wpa=2");
    expect_line(conf, "wpa_key_mgmt=WPA-PSK");
    expect_line(conf, "rsn_pairwise=CCMP");
    expect_line(conf, "ieee80211w=0");
    expect_line(conf, "external_rsn_auth=1");
    expect_absent(conf, "group_mgmt_cipher");
    expect_absent(conf, "sae_pwe");
    expect_absent(conf, "external_rsn_sae");
    expect_absent(conf, "wpa_passphrase");
}

/* The live 28-byte manager IE: PSK + MFPC -> ieee80211w=1, no SAE lines. */
static void case_psk_mfpc_live(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256], hex[2 * sizeof(ie_psk_mfpc) + 1];
    uint8_t blob[257];

    conf_of(ie_psk_mfpc, sizeof(ie_psk_mfpc), 1, &ri, &rp, conf,
            sizeof(conf));
    assert(ri.valid && ri.akm_psk && ri.mfpc && !ri.mfpr);
    assert(rp.ieee80211w == 1);
    assert(strcmp(rp.key_mgmt, "WPA-PSK") == 0);
    expect_line(conf, "ieee80211w=1");
    /* MFPC without SAE must not add the group-mgmt cipher: hostapd has no
     * SAE BSS to run BIP on here, and the deployed config does not carry it. */
    expect_absent(conf, "group_mgmt_cipher");
    expect_absent(conf, "sae_pwe");

    /* external_rsn_ie must be the manager's element byte for byte. */
    size_t bl = rsn_ie_blob(blob, sizeof(blob), ie_psk_mfpc,
                            sizeof(ie_psk_mfpc), rp.want_rsnxe);
    assert(bl == sizeof(ie_psk_mfpc));
    assert(memcmp(blob, ie_psk_mfpc, bl) == 0);
    for (size_t i = 0; i < bl; i++) sprintf(hex + 2 * i, "%02x", blob[i]);
    assert(strcmp(hex, "301a0100000fac040100000fac040100000fac02"
                       "80000000000fac06") == 0);
}

/* PSK + MFPR -> ieee80211w=2 (required), not 1. */
static void case_psk_mfpr(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_psk_mfpr, sizeof(ie_psk_mfpr), 1, &ri, &rp, conf,
            sizeof(conf));
    assert(ri.valid && ri.mfpr && ri.mfpc && ri.akm_psk);
    assert(rp.ieee80211w == 2);
    assert(strcmp(rp.key_mgmt, "WPA-PSK") == 0);
    expect_line(conf, "ieee80211w=2");
    expect_absent(conf, "group_mgmt_cipher");
    expect_absent(conf, "sae_pwe");
}

/* PSK + SAE + MFPC: the WPA3 transition profile the live matrix starts with.
 * Both AKMs, sae_pwe=2, BIP-CMAC group management, RSNXE relayed. */
static void case_psk_sae(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_psk_sae, sizeof(ie_psk_sae), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_psk && ri.akm_sae && ri.mfpc);
    assert(rp.wpa == 2);
    assert(strcmp(rp.key_mgmt, "WPA-PSK SAE") == 0);
    assert(rp.ieee80211w == 1);
    assert(rp.group_mgmt_cmac && rp.sae_pwe == 2);
    assert(rp.external_auth && rp.want_rsnxe);
    expect_line(conf, "wpa_key_mgmt=WPA-PSK SAE");
    expect_line(conf, "ieee80211w=1");
    expect_line(conf, "group_mgmt_cipher=AES-128-CMAC");
    expect_line(conf, "sae_pwe=2");
    expect_line(conf, "external_rsn_auth=1");

    /* Without the patched wpad (no external_rsn_sae) hostapd cannot suppress
     * its own SAE.  The PSK half must survive as a plain WPA2-PSK BSS, while
     * SAE/OWE and the RSNXE relay are dropped; SAE-only would fall to wpa=0. */
    conf_of(ie_psk_sae, sizeof(ie_psk_sae), 0, &ri, &rp, conf, sizeof(conf));
    assert(rp.wpa == 2 && !rp.external_auth && !rp.want_rsnxe);
    assert(strcmp(rp.key_mgmt, "WPA-PSK") == 0);
    assert(rp.sae_pwe == 0 && !rp.group_mgmt_cmac);
    expect_line(conf, "wpa_key_mgmt=WPA-PSK");
    expect_absent(conf, "SAE");
    expect_absent(conf, "sae_pwe");
    expect_absent(conf, "group_mgmt_cipher");
}

/* SAE only: SAE without WPA-PSK prefix, still sae_pwe=2 + BIP-CMAC. */
static void case_sae_only(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_sae, sizeof(ie_sae), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.akm_sae && !ri.akm_psk && !ri.akm_owe);
    assert(strcmp(rp.key_mgmt, "SAE") == 0);
    assert(rp.sae_pwe == 2 && rp.group_mgmt_cmac && rp.want_rsnxe);
    expect_line(conf, "wpa_key_mgmt=SAE");
    expect_line(conf, "sae_pwe=2");
    expect_line(conf, "group_mgmt_cipher=AES-128-CMAC");
}

/* OWE only: OWE AKM, BIP-CMAC for MFPC, but no sae_pwe (there is no SAE). */
static void case_owe(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_owe, sizeof(ie_owe), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_owe && !ri.akm_psk && !ri.akm_sae);
    assert(rp.wpa == 2);
    assert(strcmp(rp.key_mgmt, "OWE") == 0);
    assert(rp.ieee80211w == 1 && rp.group_mgmt_cmac);
    /* Pure OWE is completed by this hostapd by default (RouterOS 7.25.1
     * has no manager-side OWE DH); the manager still provisions the VAP. */
    assert(rp.sae_pwe == 0 && !rp.external_auth && rp.local_owe &&
           rp.want_rsnxe);
    expect_line(conf, "wpa_key_mgmt=OWE");
    expect_line(conf, "ieee80211w=1");
    expect_line(conf, "group_mgmt_cipher=AES-128-CMAC");
    expect_absent(conf, "sae_pwe");
    expect_absent(conf, "external_rsn_auth");
}

/* CAPAGENT_LOCAL_OWE=0 restores the old manager-relay decision. */
static void case_owe_relay(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    setenv("CAPAGENT_LOCAL_OWE", "0", 1);
    conf_of(ie_owe, sizeof(ie_owe), 1, &ri, &rp, conf, sizeof(conf));
    unsetenv("CAPAGENT_LOCAL_OWE");
    assert(strcmp(rp.key_mgmt, "OWE") == 0);
    assert(rp.external_auth && !rp.local_owe);
    expect_line(conf, "external_rsn_auth=1");
}

/* WPA-PSK-SHA256 is its own AKM keyword and must not become plain WPA-PSK. */
static void case_psk256(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_psk256, sizeof(ie_psk256), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_psk256 && !ri.akm_psk);
    assert(strcmp(rp.key_mgmt, "WPA-PSK-SHA256") == 0);
    assert(rp.ieee80211w == 0);
    expect_line(conf, "wpa_key_mgmt=WPA-PSK-SHA256");
    expect_absent(conf, "sae_pwe");
}

/* An AKM the CAP cannot mirror and a missing IE both mean "open" (wpa=0),
 * never a half-configured PSK BSS. */
/* FT-PSK (AKM 4) with a Mobility Domain element (54, MDID a1b2). */
static const uint8_t ie_ft_psk_mde[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,             /* AKM 4 = FT-PSK */
    0x00, 0x00,
    0x36, 0x03, 0xa1, 0xb2, 0x01,                   /* MDE: MDID a1b2 */
};

/* FT-802.1X (AKM 3), same MDE. */
static const uint8_t ie_ft_eap_mde[] = {
    0x30, 0x14,
    0x01, 0x00,
    0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x03,             /* AKM 3 = FT-802.1X */
    0x00, 0x00,
    0x36, 0x03, 0xa1, 0xb2, 0x01,
};

/* 802.11r: with an MDE the config must carry FT-PSK + mobility_domain; without
 * one the BSS falls back to the plain AKM so hostapd still starts. */
static void case_ft(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[320];
    uint8_t md[2];

    conf_of(ie_ft_psk_mde, sizeof(ie_ft_psk_mde), 1, &ri, &rp, conf,
            sizeof(conf));
    assert(ri.valid && ri.akm_ft_psk && !ri.akm_psk);
    assert(rp.ft == 1);
    assert(rsn_mde_mdid(ie_ft_psk_mde, sizeof(ie_ft_psk_mde), md) == 1);
    snprintf(rp.mdid, sizeof(rp.mdid), "%02x%02x", md[0], md[1]);
    rsn_conf_write(conf, sizeof(conf), &rp);
    expect_line(conf, "wpa_key_mgmt=FT-PSK");
    expect_line(conf, "mobility_domain=a1b2");
    expect_line(conf, "ft_over_ds=1");
    expect_line(conf, "external_rsn_auth=1");

    conf_of(ie_ft_eap_mde, sizeof(ie_ft_eap_mde), 1, &ri, &rp, conf,
            sizeof(conf));
    assert(ri.valid && ri.akm_ft_eap);
    assert(rp.ft == 1 && rp.external_auth == 1);
    assert(strcmp(rp.key_mgmt, "FT-EAP") == 0);
    assert(strcmp(rp.key_mgmt_base, "") == 0);

    /* No MDE: rsn_conf_write must use the plain set (empty here, so it keeps
     * the FT name rather than emitting a broken empty list). */
    conf_of(ie_ft, sizeof(ie_ft), 1, &ri, &rp, conf, sizeof(conf));
    assert(rp.ft == 1 && rp.key_mgmt_base[0] == 0);
    assert(strcmp(rp.key_mgmt, "FT-PSK") == 0);
    assert(rsn_mde_mdid(ie_ft, sizeof(ie_ft), md) == 0);
}

/* 802.1X is split-MAC too: the manager terminates EAP against RADIUS, so the
 * CAP reproduces the AKM and enables the external authentication switch. */
static void case_eap(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_8021x, sizeof(ie_8021x), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_eap && !ri.akm_psk);
    assert(strcmp(rp.key_mgmt, "WPA-EAP") == 0);
    assert(rp.external_auth == 1);
    assert(rp.ieee80211w == 0);
    expect_line(conf, "wpa_key_mgmt=WPA-EAP");
    expect_line(conf, "external_rsn_auth=1");
    expect_absent(conf, "sae_pwe");

    conf_of(ie_8021x256, sizeof(ie_8021x256), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && ri.akm_eap256 && !ri.akm_eap);
    assert(strcmp(rp.key_mgmt, "WPA-EAP-SHA256") == 0);
    assert(rp.external_auth == 1);
    expect_line(conf, "wpa_key_mgmt=WPA-EAP-SHA256");
}

static void case_unsupported(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[256];

    conf_of(ie_unknown, sizeof(ie_unknown), 1, &ri, &rp, conf, sizeof(conf));
    assert(ri.valid && !ri.akm_psk && !ri.akm_sae && !ri.akm_owe &&
           !ri.akm_eap && !ri.akm_eap256 && !ri.akm_ft_psk);
    assert(rp.wpa == 0 && rp.key_mgmt[0] == 0);
    assert(strcmp(conf, "wpa=0\n") == 0);

    rsn_parse(NULL, 0, &ri);
    assert(!ri.valid);
    rsn_policy_from_ie(&ri, 1, &rp);
    assert(rp.wpa == 0);
    assert(rsn_conf_write(conf, sizeof(conf), &rp) == 6);
    assert(strcmp(conf, "wpa=0\n") == 0);

    /* Truncated RSN IE (shorter than the 18-byte minimum): ignored, not
     * misparsed as a valid one. */
    rsn_parse(ie_psk, 12, &ri);
    assert(!ri.valid);
    /* An element whose length runs past the blob must not be read. */
    {
        static const uint8_t bad[] = { 0x30, 0x40, 0x01, 0x00 };
        rsn_parse(bad, sizeof(bad), &ri);
        assert(!ri.valid);
    }
}

/* external_rsn_ie relay: only element 48 is copied for PSK, 48 + 244 (RSNXE)
 * for SAE/OWE, with every other element dropped. */
static void case_blob(void)
{
    uint8_t blob[257];
    struct rsn_info ri;
    struct rsn_policy rp;

    /* PSK over the SAE-shaped local blob: RSNXE is not part of that IE. */
    rsn_parse(ie_local, sizeof(ie_local), &ri);
    assert(ri.valid && ri.akm_sae);
    rsn_policy_from_ie(&ri, 1, &rp);
    size_t bl = rsn_ie_blob(blob, sizeof(blob), ie_local, sizeof(ie_local),
                            rp.want_rsnxe);
    assert(bl == 28 + 5);
    assert(blob[0] == 0x30 && blob[1] == 0x1a);
    assert(blob[28] == 0xf4 && blob[29] == 0x03);
    assert(blob[30] == 0x8c && blob[31] == 0x00 && blob[32] == 0x00);

    /* Same blob, PSK policy: only the RSN IE. */
    bl = rsn_ie_blob(blob, sizeof(blob), ie_local, sizeof(ie_local), 0);
    assert(bl == 28);
    assert(blob[0] == 0x30 && blob[27] == 0x06);

    /* A blob with no RSN IE yields nothing to relay. */
    bl = rsn_ie_blob(blob, sizeof(blob), ie_psk, 2, 1);
    assert(bl == 0);
    bl = rsn_ie_blob(blob, sizeof(blob), NULL, 0, 1);
    assert(bl == 0);
}

/* The writer must never overflow the caller's buffer. */
static void case_truncation(void)
{
    struct rsn_info ri;
    struct rsn_policy rp;
    char conf[8];

    rsn_parse(ie_psk_sae, sizeof(ie_psk_sae), &ri);
    rsn_policy_from_ie(&ri, 1, &rp);

    memset(conf, 'X', sizeof(conf));
    size_t n = rsn_conf_write(conf, sizeof(conf), &rp);
    assert(n == sizeof(conf) - 1);
    assert(strlen(conf) == n);
    assert(conf[sizeof(conf) - 1] == 0);
    assert(memcmp(conf, "wpa=2\nw", 7) == 0);

    assert(rsn_conf_write(conf, 0, &rp) == 0);
}

int main(void)
{
    case_psk();
    case_psk_mfpc_live();
    case_psk_mfpr();
    case_psk_sae();
    case_sae_only();
    case_owe();
    case_owe_relay();
    case_psk256();
    case_eap();
    case_ft();
    case_unsupported();
    case_blob();
    case_truncation();
    puts("RSN decision (PSK/MFPC/MFPR/SAE/OWE/PSK256/EAP/FT): PASS");
    return 0;
}
