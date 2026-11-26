# v0.5.3 / v0.5.4 — WPA2-EAP in the shipped image

Patch release on v0.5.2. The only functional change is the one that made
wpa2-eap possible; until now it existed only as a hand-installed `wpad`.

## Highlights

* **The image now contains a `wpad` that accepts 802.1X AKMs.** Patch `9999a`
  used to reject `WPA-EAP`:

  ```
  external_rsn_auth supports only WPA-PSK, WPA-PSK-SHA256, SAE and OWE
  1 errors found in configuration file '/tmp/vap-phy0.conf'
  → phy0 hostapd failed to start (status=1)
  ```

  so a `wpa2-eap` BSS could not even come up and no EAPOL ever flowed.
  `WPA_KEY_MGMT_IEEE8021X` and `WPA_KEY_MGMT_IEEE8021X_SHA256` are now in the
  allowed mask; the manager terminates EAP with its RADIUS server and the CAP
  only relays EAPOL, exactly like SAE/OWE.
* **The agent understands 802.1X.** `src/rsn_decide.h` maps AKM 1/5 to
  `wpa_key_mgmt=WPA-EAP` / `WPA-EAP-SHA256` with `external_rsn_auth=1`, and
  `src/*.h` is now a build dependency (the header change had been silently not
  rebuilt).
* **`scripts/station-test.sh` speaks EAP**: `KEY_MGMT=WPA-EAP EAP=PEAP
  IDENTITY=… PASSWORD=… EAP_PHASE2=…`.

## Proven live (hand-installed `wpad`, same code as this image)

```
manager: sec-eap (wpa2-eap, eap-methods=peap, ccmp) + cfg-eap ssid=cap-eap
CAP:     wpa=2 · wpa_key_mgmt=WPA-EAP · ieee80211w=1 · external_rsn_auth=1
station: CONNECTED, authorized: yes, authenticated: yes
         ping 3 packets transmitted, 3 received, 0% packet loss
RADIUS:  FreeRADIUS 3.2.8 on 10.0.0.3, User-Name = "captest" (PEAP/MSCHAPv2)
```

Image sha256 `e8d24c78ff55d575bfb2fea2728660230c54fb0e304c4fc1bee22761758e7a35`
(7,472,226 B), flashed with `sysupgrade -n`: 8/8 SSIDs, `br-vlan*` zone and
bridges without manual steps, `MGMT_SOURCE=off`, patched `wpad`
(`external_rsn_sae=2`, no debug probes).

## Artifacts

`capagent-mipsel`, `capagent-aarch64`, the two bundles, the image and
`SHA256SUMS`.

## Still open

* **`on-capsman` / secure datachan** (`a2=1` lab only, `a2=2` never live).
* **`MANAGER=auto`** — OpenWrt's `udhcpc` does not export RouterOS DHCP
  option 138.
* ACL/multi-passphrase, 802.11k/v/r, tx-power/beacon tuning, local-forwarding,
  6 GHz/MLO — see `docs/CAPSMAN-COVERAGE.md`.


## v0.5.4 — packaging fix

The v0.5.3 image was built **without rebuilding the capagent ipk**, so it shipped
the previous binary: the generated BSS had `wpa=0` (no RSN IE in the beacon) and
a station ignored the SSID even though `external_rsn_ie` was present. Rebuilding
`package/capagent` from the current `native/capagent-mipsel` before the image
fixes it:

```
config: wpa=2 · wpa_key_mgmt=WPA-EAP
station: CTRL-EVENT-CONNECTED → authorized: yes → ping 3/3, 0% packet loss
CAP:     NEW_KEY PAIRWISE ret=0 · SET_STATION MFP ret=0 · EXTMUX: authorized
```

Image sha256 `0a6dcafbe62a0eb3ed2038a5c3921bae73cf9ac815da2035fc4a4a7d65e6d434`.
Release the image whenever `native/` changes: the ipk embeds a prebuilt binary,
so it is easy to ship a stale one.
