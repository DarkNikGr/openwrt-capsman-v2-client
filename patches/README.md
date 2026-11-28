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
| `9999-external-rsn-no-psk.patch` | in external mode, discard every PSK field from the config and allow a passphrase-free BSS; reject SAE/OWE/802.1X there (relaxed by `9999a` when `external_rsn_sae=1`) | yes |
| `9999a-external-rsn-sae.patch` | W46: `external_rsn_sae=1` + `EXT_AUTH_MGMT_TX` (raw Auth/AssocReq relay), and **`EXT_AUTH_TX` trims a trailing CR/LF** — without the trim every M1/M3 is rejected before TX (the daemon does not strip the control wire newline) | yes |
| `9999b-external-rsn-tx-retval.patch` | W53: only a negative `hostapd_wpa_auth_send_eapol()` return is an error; the nl80211 `PF_PACKET` path returns the byte count, so a transmitted frame used to answer `FAIL` | yes |
| `9999c-hostapd-use-existing-bss.patch` | W63: pass `use_existing` for every AP BSS, so a BSS netdev created by the CAP is attached instead of deleted and re-created (that moved the ifindex under the CAP and caused the restart loop) | yes |
| `9999d-hostapd-set-mode-ealready.patch` | W64: `SET_INTERFACE` returning `-EALREADY` ("Match already configured") is success — a CAP that brings the BSS up as AP before hostapd starts made the whole radio fail to initialise | yes |
| `9999e-external-rsn-null-wpa-sm.patch` | W65: `wpa_auth_sm_event(sta->wpa_sm, WPA_AUTH)` crashes when the RSN authenticator is external (no local `wpa_sm`); it SIGSEGV'd hostapd right after `authentication OK`, so no AssocResp was ever sent | yes |
| `9999f-external-rsn-action.patch` | relay a station's Radio Measurement (category 5) action frame through `ext_auth_notify_assocreq` as `0x2018`, so a Beacon Report reaches the manager | for 11k |
| `9999g-hostapd-rrm-ie-without-capab.patch` | accept the station's explicit RM Enabled Capabilities IE even when wpa_supplicant does not set the Radio Measurement capability bit | for 11k |
| `9999h-external-rsn-queue-early-eapol.patch` | queue the newest EAPOL frame per station and flush it from `ext_auth_notify_assoc()`, because on 6 GHz the manager can send M1 before hostapd has associated the station | for 6 GHz/SAE |
| `9999i-hostapd-short-rrm-ie.patch` | keep a short RRM Enabled Capabilities IE and preserve it through the external-RSN early return in `__check_assoc_ies`, so `req_beacon` sees the station's beacon-report bits | for 11k |
| `9999j-external-rsn-wnm-action.patch` | relay the station's WNM (category 10) action frame, e.g. the BTM Response, as `0x2018` | for 802.11v |

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
non-zero on any rejected hunk or fuzz.  The series is now 11 patches (the
original four-patch capture was 6 patches, 59 hunks, 0 fuzz); run the script
for the current hunk/fuzz count.

`999-` (not `0999-`) is deliberate: the name must sort after the last stock
patch, `804-…`.  A `0999-` name sorts before `110-…` and the package build
then fails on context that those later stock patches introduce.

`patches/wifi-scripts/` holds the companion patch for
`package/network/config/wifi-scripts/files/lib/netifd/hostapd.sh`; it is not
part of the hostapd tree.

`capagent` probes the resulting binary for `external_rsn_ie` and only emits the
option when it is present, so an unpatched wpad keeps working.

## What the CAP sends to hostapd

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

No `wpa_passphrase`, no `wpa_psk_file`: the passphrase stays on the manager.
