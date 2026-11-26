/* rsn_decide.h — RSN IE parsing and the hostapd RSN option decision.
 *
 * Pure code: no nl80211, no hostapd probing, no I/O.  vap.inc (the per-VAP
 * path, kept for the 0x6016 journal) and phy.inc (the per-phy hostapd that
 * is actually deployed) both call rsn_policy_from_ie()/rsn_conf_write(), and
 * tests/test_rsn.c asserts the mapping so the generated hostapd config does
 * not drift from the manager's RSN IE.
 *
 * The decision is what the split-MAC model needs: the manager is the RSN
 * authenticator, so the CAP only reproduces the AKM set, the PMF setting and
 * the "manager owns 802.11 Auth" (SAE/OWE) switch in hostapd's config.
 */
#ifndef RSN_DECIDE_H
#define RSN_DECIDE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Parsed element 48 (RSN IE).  `valid` means an RSN IE was found; the
 * individual fields stay 0 when the IE is too short to carry them. */
struct rsn_info {
    int valid;
    int group;          /* 4 = CCMP, 2 = TKIP */
    int pairwise;       /* 4 = CCMP */
    int akm_eap;              /* 802.1X (CAPsMAN owns the EAP exchange) */
    int akm_eap256;
    int akm_ft_eap;           /* 3 = FT-802.1X (802.11r) */
    int akm_ft_psk;           /* 4 = FT-PSK (802.11r) */
    int akm_psk;
    int akm_psk256;
    int akm_sae;
    int akm_owe;
    int mfpr;
    int mfpc;
};

/* Parse the RSN IE (element 48) out of an IE blob (the manager's 0x04
 * attribute in 0x6016).  Walks the element list so vendor IEs before or
 * after element 48 are ignored.  Never reads past `len`. */
static void rsn_parse(const uint8_t *ie, size_t len, struct rsn_info *ri)
{
    memset(ri, 0, sizeof(*ri));
    size_t p = 0;
    while (p + 2 <= len) {
        uint8_t id = ie[p], l = ie[p + 1];
        if (p + 2 + l > len) break;
        if (id == 48 && l >= 18) {          /* RSN IE */
            const uint8_t *r = ie + p + 2;
            size_t n = l;
            ri->valid = 1;
            if (n >= 8) ri->group = r[5];
            size_t k = 6;   /* version(2) + group(4) */
            if (k + 2 <= n) {
                int pc = r[k] | (r[k + 1] << 8);
                if (pc >= 1 && k + 6 <= n) ri->pairwise = r[k + 5];
                k += 2 + 4 * (size_t)pc;
            }
            if (k + 2 <= n) {
                int ac = r[k] | (r[k + 1] << 8);
                for (int i = 0; i < ac && k + 4 + 4 * (size_t)i + 3 < n; i++) {
                    const uint8_t *a = r + k + 2 + 4 * (size_t)i;
                    if (a[0] == 0x00 && a[1] == 0x0f && a[2] == 0xac) {
                        if (a[3] == 1)  ri->akm_eap = 1;
                        if (a[3] == 3)  ri->akm_ft_eap = 1;
                        if (a[3] == 4)  ri->akm_ft_psk = 1;
                        if (a[3] == 5)  ri->akm_eap256 = 1;
                        if (a[3] == 2)  ri->akm_psk = 1;
                        if (a[3] == 6)  ri->akm_psk256 = 1;
                        if (a[3] == 8)  ri->akm_sae = 1;
                        if (a[3] == 18) ri->akm_owe = 1;
                    }
                }
                k += 2 + 4 * (size_t)ac;
            }
            if (k + 2 <= n) {
                uint16_t caps = (uint16_t)(r[k] | (r[k + 1] << 8));
                ri->mfpr = !!(caps & 0x0040);
                ri->mfpc = !!(caps & 0x0080);
            }
            return;
        }
        p += 2 + l;
    }
}

/* What the generated hostapd config has to say about RSN. */
struct rsn_policy {
    int wpa;             /* 0 = open/unsupported, 2 = WPA2/WPA3 */
    char key_mgmt[64];   /* hostapd wpa_key_mgmt list, space separated */
    char key_mgmt_base[64]; /* same without the FT-* AKMs (fallback when the
                               manager sends no Mobility Domain element) */
    int ft;              /* the manager advertised an 802.11r AKM */
    char mdid[5];        /* mobility domain from element 54 (4 hex chars) */
    int ieee80211w;      /* 0 = disabled, 1 = capable, 2 = required */
    int group_mgmt_cmac; /* emit group_mgmt_cipher=AES-128-CMAC */
    int sae_pwe;         /* 0 = no line, 2 = sae_pwe=2 */
    int external_auth;   /* SAE/OWE present and the CAP owns 802.11 Auth */
    int want_rsnxe;      /* relay element 244 (RSNXE) too */
};

static void rsn_key_mgmt_add(char *buf, size_t n, size_t *len, const char *s)
{
    size_t l = strlen(s);
    if (*len && *len + 1 < n) buf[(*len)++] = ' ';
    if (l > n - 1 - *len) l = n - 1 - *len;
    memcpy(buf + *len, s, l);
    *len += l;
    buf[*len] = 0;
}

/* Turn a parsed IE into the hostapd decision.  sae_override is false when
 * the installed wpad lacks external_rsn_sae: then hostapd cannot suppress
 * its own SAE and the BSS must fall back to wpa=0 (the manager then still
 * sees the external RSN IE, exactly as before). */
static void rsn_policy_from_ie(const struct rsn_info *ri, int sae_override,
                               struct rsn_policy *p)
{
    memset(p, 0, sizeof(*p));

    int have_psk = ri->valid && (ri->akm_psk || ri->akm_psk256);
    int have_sae = ri->valid && (ri->akm_sae || ri->akm_owe) && sae_override;
    int have_eap = ri->valid && (ri->akm_eap || ri->akm_eap256);
    int have_ft = ri->valid && (ri->akm_ft_eap || ri->akm_ft_psk);

    /* 802.1X is also a split-MAC exchange here: the manager terminates EAP
     * with its RADIUS server, so hostapd must relay EAPOL and run no local
     * 802.1X state machine, exactly like SAE/OWE. */
    /* FT-EAP carries 802.1X inside the FT exchange, so the manager owns the
     * Auth there too.  FT-PSK keeps hostapd's open-system Auth (which we
     * mirror to the manager as 0x2018) exactly like plain PSK. */
    p->external_auth = have_sae || have_eap || (have_ft && ri->akm_ft_eap);
    p->want_rsnxe = have_sae;
    p->ft = have_ft;
    if (!have_psk && !have_sae && !have_eap && !have_ft) return;

    p->wpa = 2;
    size_t len = 0;
    if (ri->akm_eap)    rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt),
                                         &len, "WPA-EAP");
    if (ri->akm_eap256) rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt),
                                         &len, "WPA-EAP-SHA256");
    if (ri->akm_psk)    rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt),
                                         &len, "WPA-PSK");
    if (ri->akm_psk256) rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt),
                                         &len, "WPA-PSK-SHA256");
    if (have_sae && ri->akm_sae)
        rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt), &len, "SAE");
    if (have_sae && ri->akm_owe)
        rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt), &len, "OWE");
    /* Plain (non-FT) view of the same set: used when the manager advertises
     * FT but no Mobility Domain element, because hostapd refuses FT without
     * mobility_domain and the BSS would not start at all. */
    memcpy(p->key_mgmt_base, p->key_mgmt, sizeof(p->key_mgmt_base));
    if (have_ft) {
        if (ri->akm_ft_eap)
            rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt), &len,
                             "FT-EAP");
        if (ri->akm_ft_psk)
            rsn_key_mgmt_add(p->key_mgmt, sizeof(p->key_mgmt), &len,
                             "FT-PSK");
    }

    p->ieee80211w = ri->mfpr ? 2 : (ri->mfpc ? 1 : 0);
    p->group_mgmt_cmac = have_sae && ri->mfpc;
    p->sae_pwe = (have_sae && ri->akm_sae) ? 2 : 0;
}

/* Write the RSN block of a hostapd config into out.  Byte-for-byte what the
 * deployed per-phy path emits today (same lines, same order).  The caller
 * appends external_rsn_sae=1 (only when the binary has it) and
 * ext_auth_socket=... after this block.  Returns the number of bytes
 * written (excluding the NUL), or 0 if out is too small. */
static size_t rsn_conf_write(char *out, size_t n, const struct rsn_policy *p)
{
    int r;
    if (!n) return 0;
    if (!p->wpa) {
        r = snprintf(out, n, "wpa=0\n");
    } else {
        r = snprintf(out, n,
                     "wpa=2\n"
                     "wpa_key_mgmt=%s\n"
                     "rsn_pairwise=CCMP\n"
                     "wpa_group_rekey=0\n"
                     "wpa_ptk_rekey=0\n"
                     "ieee80211w=%d\n"
                     "%s"
                     "%s"
                     "external_rsn_auth=1\n",
                     (p->ft && p->mdid[0]) ? p->key_mgmt :
                         (p->key_mgmt_base[0] ? p->key_mgmt_base
                                             : p->key_mgmt),
                     p->ieee80211w,
                     p->group_mgmt_cmac ?
                         "group_mgmt_cipher=AES-128-CMAC\n" : "",
                     p->sae_pwe ? "sae_pwe=2\n" : "");
    }
    if (r < 0) return 0;
    if (p->wpa && p->ft && p->mdid[0]) {
        int r2 = snprintf(out + r, n - (size_t)r,
                          "mobility_domain=%s\nft_over_ds=1\n", p->mdid);
        if (r2 > 0) r += r2;
    }
    if ((size_t)r >= n) { out[n - 1] = 0; return n - 1; }
    return (size_t)r;
}

/* Mobility Domain element (54), 3 bytes: MDID (2, top bit reserved) + FT
 * capability.  Returns 1 and fills out[0..1] when present. */
static int rsn_mde_mdid(const uint8_t *ie, size_t len, uint8_t out[2])
{
    size_t p = 0;
    if (!ie) return 0;
    while (p + 2 <= len) {
        uint8_t id = ie[p], l = ie[p + 1];
        if (p + 2 + l > len) break;
        if (id == 54 && l >= 3) {
            out[0] = ie[p + 2];
            out[1] = ie[p + 3];
            return 1;
        }
        p += 2 + l;
    }
    return 0;
}

/* Copy element 48 — and element 244 (RSNXE) when want_rsnxe — out of an IE
 * blob, preserving the wire bytes.  The station compares both elements
 * against the ones in M3, so they must be relayed verbatim.  Returns the
 * blob length (0 when there is nothing to relay). */
static size_t rsn_ie_blob(uint8_t *out, size_t n, const uint8_t *ie,
                          size_t il, int want_rsnxe)
{
    size_t p = 0, bl = 0;
    if (!ie) return 0;
    while (p + 2 <= il) {
        uint8_t id = ie[p], l = ie[p + 1];
        if (p + 2 + l > il) break;
        if (id == 48 || (want_rsnxe && id == 244)) {
            if (bl + 2 + (size_t)l <= n) {
                memcpy(out + bl, ie + p, 2 + (size_t)l);
                bl += 2 + (size_t)l;
            }
        }
        p += 2 + l;
    }
    return bl;
}

#endif /* RSN_DECIDE_H */
