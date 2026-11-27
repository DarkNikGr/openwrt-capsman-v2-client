# v0.5.7 — multi-identity CAP (4 SSIDs on 2.4 GHz), fixed SET_INTERFACE patch

Feature release on v0.5.6.

## Highlights

* **One SSID per CAP identity (multi-identity).** A second, third and fourth
  capagent can run on the same wiphy, each with its own identity, certificate,
  journal and ext-auth directory (`CAPAGENT_RUN_TAG`), so every SSID is
  provisioned as the **master** of its own CAP radio and the manager's
  virtual-VAP routing is no longer needed. Live on the 2.4 GHz phy: four
  identities (`phy0-aap0` … `phy0-dap0`, all at 2437) carrying cap-test,
  cap-guest, cap-iot and a hidden cap-hidden; a station on **each** got
  `authorized: yes` and `ping 3/3, 0%` on its VLAN.
* **Two multi-instance bugs fixed.** Tagged hostapd configs are
  `/tmp/cap-phyN-<tag>.conf` (the old `vap-*` name made one instance kill the
  others' hostapd as "orphans"), and a bridged AP interface cannot be opened
  while another AP runs (`EBUSY`), so tagged instances bridge the BSS after it
  is up instead of using hostapd's `bridge=`.
* **The `SET_INTERFACE -EALREADY` patch was applied to the wrong function.**
  `9999d` matched the nl80211 connect path instead of `nl80211_set_mode`, so it
  neither fixed `Could not configure driver mode` nor left the connect retry
  untouched. The hunk is now minimal, anchored on
  `NL80211_CMD_SET_INTERFACE`, and verified with `patch --fuzz=0`; the image
  ships the rebuilt `wpad`.
* `scripts/multi-cap.sh` + `docs/MULTI-IDENTITY.md` (manager rules, config,
  launcher, proven table, limits).

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1. Clean
`sysupgrade -n`: `MANAGER=auto`, DHCP option 138 discovery, 8/8 SSIDs,
`br-vlan*` zone, 2.4 GHz on channel 6. `make check` green.

Image sha256 `d7acca85d8abe0e8a37e08d47315da898c026c5da8fa6ab61280e83870ae7317`
(7,472,226 B).

## Still open

* **5 GHz multi-identity** is not complete: the driver refuses a second AP
  interface per-phy in the independent-instance model. A shared hostapd was
  tried; the primary starts once typed `managed` (the EALREADY fix), hostapd
  creates the secondaries, but a secondary with the manager's fake-radio MAC is
  refused at bring-up and the merged setup did not reach four BSSes (F65).
* Virtual (slave) VAPs on the real radio still do not reach the 4-way
  (F58–F60); secure datachan `a2=2` is never requested by the manager;
  6 GHz/MLO and local-forwarding are out of reach.
