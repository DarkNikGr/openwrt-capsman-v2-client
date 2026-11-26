# v0.5.0 — PSK-free CAP completes the 4-way; zero-touch image flashed

Userspace CAP for the **official RouterOS 7.25.1 CAPsMAN v2** manager.

This is the release where the goal is met on hardware: a station associates,
the **manager** runs the 4-way handshake, the station becomes authorized, and
traffic flows — while the CAP never holds the passphrase. It also ships a
reproducible zero-touch image and the patches that were missing.

## Highlights

* **A station completes the 4-way with no key on the CAP — live.**
  `0x201c` (M1) → `0x201b` (M2) → `0x201f` PTK install → `authorized: yes`,
  `authenticated: yes`, `ping` 3/3 over the manager's VLAN.
  The last blocker was a hostapd SIGSEGV inside `__check_assoc_ies()`: with an
  external authenticator there is no local `wpa_sm`, and the SAE skip path fell
  through to `wpa_auth_get_pairwise(NULL)` (patch `9999a` now returns
  `WLAN_STATUS_SUCCESS` there). It killed the radio right after
  `authentication OK`, which is why no AssocResp ever reached a station.
* **8/8 SSIDs, reproducibly.** One hostapd **per radio** with `bss=` sections
  runs as capagent's own foreground child. Three separate causes were found and
  fixed: `hostapd -B` daemonised and its daemon died after `AP-ENABLED`
  (`9999d` also tolerates `SET_INTERFACE -EALREADY`), the old instance was not
  reaped before a restart, and `Failed to create interface … -23` is hostapd's
  reading of `NEW_INTERFACE` returning `-ENFILE` for a name that already exists
  — a name collision, not a vif limit (`9999c`).
* **Zero-touch sysupgrade image, built from this repo and flashed.**
  `openwrt/capagent/` (procd service + `/etc/cap/capagent.conf` with no SSID,
  key or VLAN) and `scripts/build-image.sh`, which builds the patched `wpad`
  at `PKG_RELEASE=99` (the repo ships `r3`, so an `r2` build silently loses and
  the image keeps the stock wpad), ships a matching `hostapd-common`, and then
  verifies the image with `unsquashfs`. Written with `sysupgrade -n`, it boots,
  **enrols a certificate by itself** and provisions 8/8 with no manual step.
* **Reproducible patched wpad.** `scripts/build-wpad-9999a.sh`: the official
  24.10.0 SDK contains no hostapd sources, so the script overlays the
  `v24.10.0` package tree into it, builds mbedtls/libubox/ubus/uci first, drops
  the Lua bindings and the openssl variants, and applies
  `999/9997/9998/9999/9999a/9999b/9999c/9999d/9999e`.
* **`0x2019` deauth now delivered.** hostapd's `MGMT_TX` answers `-EINVAL` for
  a station it already dropped; the relay now retries on the other transport and
  always runs hostapd's `DEAUTHENTICATE`. Live: `ret=0`, `reply=OK`.
* **Honest tooling.** `scripts/station-test.sh` moves the real station wiphy
  into a netns (it used to move a phy that does not exist here, so an earlier
  "no association" reading was a harness artefact), runs `wpa_supplicant` in the
  foreground and keeps the link up for the ping. `scripts/live-manager-only.sh`
  refuses to start unless the CAP really has zero `wifi-iface`.
* **Docs.** README status/results/open questions rewritten; the measured facts
  are numbered F1–F47 in `docs/OPEN-PROBLEMS.md` so the dead ends (monitor VIF,
  vif limits, pid files, buffered hostapd logs) are not re-derived.

## Verified on

Xiaomi Mi Router 4A Gigabit (ramips/mt7621, OpenWrt 24.10.0, MT7603E +
MT7612E) against RB1100AHx4 / RouterOS 7.25.1. The Deco BE65 used as a second
CAP stayed read-only throughout.

Reference image: 7,472,226 B,
sha256 `3827098b8ce028a52b28d55a5f00ab84b20cb1aa69914893a63547895a251508`.

## Still open

* `/etc/init.d/capagent restart` can come back with fewer BSSes; boot and
  factory reset are always 8/8 (F45/F47).
* Secure c2 datachan (`a2=2`): codec and KATs done, never live — the manager's
  key install does not run on a radio-less controller.
* `MANAGER=auto` does not discover this manager (RouterOS DHCP option 138 is
  not exported by OpenWrt's `udhcpc`), so the address is baked at build time.
* Soak/concurrency (SAE/OWE/PMF across VAPs, GTK rekey under load) and 6 GHz /
  MLO.
