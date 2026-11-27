# v0.5.6 — the radio follows the configured channel; 802.11r/FT ready; ACL proven

Patch release on v0.5.5.

## Highlights

* **The radio now runs on the VAP's configured channel.** CAPsMAN sends the
  radio's *current* channel in `0x500b` and the VAP's configured one in
  `0x6016` (`0x0a/0x0b`); capagent kept the former, so the 2.4 GHz radio ran on
  2412 while the manager's VAPs were configured for 2437, and the relayed
  `0x2018` reported 2412. `vap_provision` now syncs the start body's channel
  into the VAP and the relay table. Live: `channel 6 (2437 MHz)`, matching the
  manager.
* **802.11r/FT support (CAP side).** `rsn_decide.h` parses AKM 3/4 and emits
  `FT-EAP`/`FT-PSK`; with a Mobility Domain element it adds
  `mobility_domain=<mdid>` + `ft_over_ds=1`, and without one it falls back to
  the plain AKM so hostapd still starts. `tests/test_rsn.c` covers FT-PSK+MDID,
  FT-EAP+MDID and FT-without-MDE. RouterOS 7.25.1 does not send FT to this CAP
  (`security.ft=yes` leaves the `0x6016` RSN IE at AKM 2 and no `36 03`), so the
  path is ready but not exercisable here (F61).
* **ACL verified live (manager-side).** `access-list action=reject` (all) makes
  the station unable to associate; removing it gives `authorized: yes` and
  `ping 3/3, 0% loss`. The manager filters before the CAP, so no CAP change is
  needed.
* **Harness:** `SCAN_FREQ=` (one-band runs) and `MDID=` (FT stations).

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1. Clean
`sysupgrade -n`: `MANAGER=auto` discovered through DHCP option 138, 8/8 SSIDs,
`br-vlan*` zone, 2.4 GHz on channel 6. `make check` green (ownership,
netifd_status, extmux incl. the rebind case, iw frequency, RSN incl. FT,
crypto KATs, 27-check policy).

Image sha256 `01997ab70de1e6d6dd44d4c9941717085270d225db3b51d5ba88356f43b5ac59`
(7,472,226 B).

## Still open (documented, see OPEN-PROBLEMS F58–F61)

* A station on a **secondary VAP** still gets no 4-way from this manager
  (Auth/AssocReq relayed, manager silent). Six framing variants were tried and
  ruled out; the CAP-side is correct for a master BSS.
* Secure datachan `a2=2` is never requested by the manager (`a2=0`, no
  `0x402b`).
* `local-forwarding` is impossible by design (the PSK is never sent).
