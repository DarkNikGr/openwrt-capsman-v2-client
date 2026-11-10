# hostapd patches for the split-MAC CAP

These patches turn OpenWrt's `wpad-mbedtls` into a CAP-mode hostapd that never
holds the WPA passphrase: the official CAPsMAN v2 manager is the RSN
authenticator and the CAP only relays EAPOL and installs the derived keys.

Apply order is lexicographic, after the stock OpenWrt patches:

| file | what it does | required |
|---|---|---|
| `999-external-rsn-auth.patch` | `external_rsn_auth=1` / `ext_auth_socket=`; hostapd stops running the 4-way, relays EAPOL to the CAP daemon over a UNIX dgram socket, and authorizes on request | yes |
| `9997-external-rsn-ie.patch` | `external_rsn_ie=<hex>`; replaces the generated RSN IE with the manager's exact bytes (the station rejects M3 on any difference) | yes for PSK-free |
| `9998-external-rsn-eapol-rx.patch` | relay STA EAPOL from `ieee802_1x_receive()` (the path mac80211 uses), not only from the driver event | yes |
| `9999-external-rsn-no-psk.patch` | in external mode, discard every PSK field from the config and allow a passphrase-free BSS; reject SAE/OWE/802.1X there | yes |
| `9999a-external-rsn-sae.patch` | `external_rsn_sae=1`; allow SAE/OWE in external mode, suppress the local SAE exchange and relay raw `AUTH`/`ASSOCREQ` frames to the capagent socket, skip local `wpa_validate_wpa_ie()` (the manager already validated it and owns the PMK), set the MFP station flag, accept an `external_rsn_ie` blob with RSNXE, add `EXT_AUTH_MGMT_TX` so the manager's 0x2019 Auth/Assoc frames go out through the owning BSS, and trim the trailing newline on `EXT_AUTH_TX` | yes for SAE/OWE |

`9999a` sorts immediately after `9999` in the C locale (`-` < `a`), so it is
applied after the PSK-only guard it relaxes.

## Build

```
SDK=/path/to/openwrt-sdk-24.10.0-ramips-mt7621
cp patches/*.patch $SDK/package/network/services/hostapd/patches/
# make sure CONFIG_EXTERNAL_RSN_AUTH=y in
# package/network/services/hostapd/files/hostapd-full.config
cd $SDK && make package/network/services/hostapd/compile
```

The full recipe (SDK layout, package overlay, wifi-scripts passthrough,
expected sizes/hashes) is in [`docs/BUILD.md`](../docs/BUILD.md).

Verify the series before building:

```
./scripts/patches-check.sh --tarball dl/hostapd-2024.09.15~5ace39b0.tar.zst \
    --openwrt-patches $SDK/package/network/services/hostapd/patches \
    --wifi-scripts $SDK
```

It replays the 61 stock OpenWrt patches **merged with** this series, sorted by
basename in C order — the same single pass OpenWrt performs — and exits
non-zero on any rejected hunk or fuzz.  Current result: 4 patches, 41 hunks,
0 fuzz (`999` 0, `9997` 0, `9998` +4, `9999` +1..+17).

`999-` (not `0999-`) is deliberate: the name must sort after the last stock
patch, `804-…`.  A `0999-` name sorts before `110-…` and the package build
then fails on context that those later stock patches introduce.

`patches/wifi-scripts/` holds the companion patch for
`package/network/config/wifi-scripts/files/lib/netifd/hostapd.sh`; it is not
part of the hostapd tree.

`capagent` probes the resulting binary for `external_rsn_ie` and only emits the
option when it is present, so an unpatched wpad keeps working.  The same probe
pattern gates `external_rsn_sae` and `EXT_AUTH_MGMT_TX`; a binary without them
keeps the WPA2-PSK-only behaviour (SAE VAPs are left open/unsupported instead
of receiving an unknown config keyword).

## What the CAP sends to hostapd

WPA2-PSK (unchanged):

```
ssid=<from 0x6016 tag 0x03>
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ieee80211w=<0|1|2 as the manager's RSN capabilities say>
external_rsn_auth=1
external_rsn_ie=<the RSN IE from 0x6016 tag 0x04, verbatim>
ext_auth_socket=/var/run/hostapd/ext-auth-<ifname>
wpa_group_rekey=0
wpa_ptk_rekey=0
```

SAE/OWE (only with `9999a` in the binary):

```
ssid=<from 0x6016 tag 0x03>
wpa=2
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
group_mgmt_cipher=AES-128-CMAC
ieee80211w=2
sae_pwe=2
external_rsn_auth=1
external_rsn_sae=1
external_rsn_ie=<RSN IE + RSNXE from 0x6016, verbatim>
ext_auth_socket=/var/run/hostapd/ext-auth-<ifname>
wpa_group_rekey=0
wpa_ptk_rekey=0
```

No `wpa_passphrase`, no `wpa_psk_file`, no `sae_password`: the passphrase stays
on the manager.  `external_rsn_sae=1` makes hostapd drop the local SAE frame and
skip local RSN-IE validation; the manager's `0x2019` Auth response is sent with
`EXT_AUTH_MGMT_TX`, and capagent sets `NL80211_STA_FLAG_MFP` before
`AUTHORIZED`.
