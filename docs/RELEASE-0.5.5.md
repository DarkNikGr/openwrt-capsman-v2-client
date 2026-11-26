# v0.5.5 — zero-touch discovery (DHCP 138), manager tx-power/DTIM, relay self-heal

Feature release on v0.5.4. All three changes are verified on the reference
Xiaomi Mi Router 4A and the flashed image.

## Highlights

* **`MANAGER=auto` now works.** RouterOS advertises its CAPsMAN address in
  DHCP option 138, but OpenWrt's `udhcpc` only exports it when asked. The
  package installs `/etc/uci-defaults/98-cap-dhcp138` (adds `138` to
  `network.wan.reqopts`) and `/etc/udhcpc.user.d/99-cap-dhcp138` (decodes the
  hex value into `/tmp/cap-manager`), and the agent prefers that file over the
  broadcast. Verified on a clean flash with **no baked address**:

  ```
  MANAGER=auto · reqopts=138 · cache=10.0.0.1
  capagent: discovery: manager 10.0.0.1 from DHCP option 138
  capagent: manager=10.0.0.1:5246 radios=2 discovery=wan
  ssids=8
  ```

  RouterOS does not answer the old broadcast probe at all (`no manager
  discovered on wan`), so option 138 is the only working auto path. The image
  now ships `MANAGER=auto`.

* **The manager's TX power and DTIM period are applied.** `0x500b` TLV `0x61`
  is the radio TX power (`0x500b: phy0 tx-power=17 dBm`); hostapd 2.11 has no
  `txpower` item, so the agent fixes it through `NL80211_CMD_SET_WIPHY`
  (`vap: phy0 tx-power 17 dBm (nl80211 ret=0)`). Values above 40 dBm mean "no
  explicit setting" (the 5 GHz radio sends 100) and clear a fixed value.
  `0x6016` TLV `0x24` is the per-VAP DTIM period, written as `dtim_period=`.

* **The ext-auth relay heals itself.** When hostapd recreates a BSS (or the
  socket directory is wiped), the per-VAP socket file can be gone while the
  agent still thinks the VAP is registered; the manager then never receives the
  AssocReq and the station times out with no M1. `extmux_vap_ensure()` detects
  the missing file and rebinds. New unit test `test_ensure_rebind`.

* **Harness and tests.** `scripts/station-test.sh` now deauthenticates and waits
  before tearing the netns down, so the AP does not keep retrying a station
  that vanished. `tests/test_rsn.c` covers the 802.1X AKMs (AKM 1/5 →
  `WPA-EAP`/`WPA-EAP-SHA256`) and uses FT-PSK for the "unsupported" case.

## Verified on

Xiaomi Mi Router 4A Gigabit (ramips/mt7621, OpenWrt 24.10.0), RB1100AHx4 /
RouterOS 7.25.1. `make check`: ownership, netifd_status, extmux (incl. the new
rebind case), iw frequency, RSN decisions, crypto KATs and the 27-check policy
selftest pass. A clean `sysupgrade -n` gives 8/8 SSIDs, the `br-vlan*` firewall
zone, four bridges and the manager discovered through DHCP, with no manual step.

Image sha256 `61758b2cafb5ed45bd2b21ebf54cffae607784065104b4410c67f2bc3e87ea70`
(7,472,226 B).

## Known limits (unchanged, documented)

* A station on a **secondary (virtual) VAP** still does not reach the 4-way on
  this manager: the Auth/AssocReq are relayed but nothing comes back. The same
  SSID works when provisioned as the radio `master-configuration`. See F58/F59
  in `docs/OPEN-PROBLEMS.md` (the 5 GHz manager-assigned BSSIDs also differ
  from the driver's derived ones).
* Secure datachan `a2=2` is never requested by the manager (`a2=0`, no
  `0x402b`) — blocked on a capture from a genuine MikroTik CAP.
* `local-forwarding` is impossible by design: CAPsMAN v2 never sends the PSK.
