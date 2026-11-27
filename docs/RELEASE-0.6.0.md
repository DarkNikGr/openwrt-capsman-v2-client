# v0.6.0 — all 8 SSIDs authenticate: multi-identity reaches both radios

Feature release on v0.5.9. v0.5.9 proved the secure datachan; this release
closes the last provisioning gap: **every manager-provisioned SSID completes
the 4-way on both radios**, including four SSIDs on 5 GHz.

## Highlights

* **8/8 SSIDs authenticate (multi-identity).** Eight capagent identities —
  four on the 2.4 GHz phy (mt7603e) and four on the 5 GHz phy (mt76x2e) — each
  advertise their own fake radio and are provisioned as the **master** of one
  SSID. The manager's registration table showed all eight stations at once:

  ```
  0 interface=cap-wifi15 ssid=cap-test   band=2ghz-g vlan-id=30
  1 interface=cap-wifi17 ssid=cap-guest  band=2ghz-g vlan-id=10
  2 interface=cap-wifi2  ssid=cap-iot    band=2ghz-g vlan-id=20
  3 interface=cap-wifi14 ssid=cap-hidden band=2ghz-g vlan-id=20
  4 interface=cap-wifi20 ssid=cap-test   band=5ghz-ac vlan-id=30
  5 interface=cap-wifi19 ssid=cap-guest  band=5ghz-ac vlan-id=10
  6 interface=cap-wifi18 ssid=cap-iot    band=5ghz-ac vlan-id=20
  7 interface=cap-wifi21 ssid=cap-hidden band=5ghz-ac vlan-id=20
  ```

  Every station test: `authorized: yes`, `ping 3/3, 0%` (2.4 at 2437 MHz,
  5 GHz at 5180 MHz; hidden SSIDs included).
* **F74: the 5 GHz BSS index comes from the first MAC byte.** Four AP vifs
  with `2A/2E/22/26:D1:27:1B:2D:90` all come up; four sharing `02:` collide
  (`EBUSY`). The 2.4 GHz phy has no such constraint. This supersedes the old
  "one 5 GHz SSID" limit (F64/F66/F73) for the multi-identity path — see
  [`MULTI-IDENTITY.md`](MULTI-IDENTITY.md).
* **Multi-identity is now a first-class service mode.** `/etc/init.d/capagent`
  reads `/etc/cap/identities.conf` and opens **one procd instance per SSID**
  (own tag, certificate, ext-auth dir, VAP journal, hostapd files). Without the
  file the normal single-identity topology is used, so a fresh zero-touch CAP
  still works on a manager that has no per-SSID rules.
* **Shipped helpers.** `/usr/sbin/multi-cap.sh` (manual start/stop/status) and
  `/etc/cap/identities.conf.example` (proven eight-identity map) are installed
  by the `capagent` package and included in the image.
* **`scripts/build-wpad-9999a.sh` now applies `9999f`/`9999g`** as part of the
  series (the image verifier already rejected a stock wpad).

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1. Clean
`sysupgrade -n` of the image below, DHCP option 138 discovery, self-enrolment,
8/8 SSIDs in the default topology; then `cp /etc/cap/identities.conf.example
/etc/cap/identities.conf && /etc/init.d/capagent restart` → 8 identities up,
all eight station tests green (manager table above).

Image sha256 `7e2847860e07a926a0ae64454ff6c36495fead8d1e69ef3f0b8e920c930556c6`
(7,472,226 B).

## Still open

* 11k live (F71, station firmware drops the RM IE) and 802.11v (the manager
  sends no deterministic trigger).
* 6 GHz/MLO — the reference board has no 6 GHz radio (the Deco BE65 is
  read-only).
* `local-forwarding` is impossible by design: CAPsMAN v2 never sends the PSK.
* A station on a **virtual (slave) VAP** still does not reach the 4-way
  (F58–F60); use multi-identity when every SSID must authenticate.
