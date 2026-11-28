# Release notes index

Current release: **v0.6.9**. The version is stored in
[`../VERSION`](../VERSION) and printed by `capagent --version`.

| Release | Headline |
|---|---|
| [`0.6.9`](RELEASE-0.6.9.md) | real 5 GHz radio + 3 slaves, no fake radios (F90); 6 GHz 1 radio + 3 virtuals (F91) |
| [`0.6.8`](RELEASE-0.6.8.md) | 6 GHz 320 MHz EHT encoding (F89 fixed) |
| [`0.6.7`](RELEASE-0.6.7.md) | 6 GHz 160 MHz (`6ghz-ax` + EHT `6ghz-be`), 0x4d dedupe, `beacon_prot` |
| [`0.6.6`](RELEASE-0.6.6.md) | `6ghz-ax` live, datachan/OWE hardening, honest `--version` |
| [`0.6.5`](RELEASE-0.6.5.md) | OWE live (CAP-local), `a2=1` datachan live, live `0x6017` keeps 8/8 |
| [`0.6.4`](RELEASE-0.6.4.md) | one CAP identity with eight radios (solo); reliable after cold reboot |
| [`0.6.3`](RELEASE-0.6.3.md) | 802.11v BTM live on the virtual bench; `6ghz-ax` closed as manager-side |
| [`0.6.2`](RELEASE-0.6.2.md) | 6 GHz end to end on a virtual radio, 11k live, live `0x6017` security changes |
| [`0.6.1`](RELEASE-0.6.1.md) | staggered multi-identity hostapd starts (cold-boot convergence) |
| [`0.6.0`](RELEASE-0.6.0.md) | multi-identity: all 8 SSIDs authenticate (4 per phy) |
| [`0.5.9`](RELEASE-0.5.9.md) | secure CAPsMAN datachan (`a2=2`) comes up and carries traffic |
| [`0.5.8`](RELEASE-0.5.8.md) | 802.11k action-frame relay in the CAP; `a2=2` re-checked |
| [`0.5.7`](RELEASE-0.5.7.md) | multi-identity CAP (4 SSIDs on 2.4 GHz), fixed `SET_INTERFACE` patch |
| [`0.5.6`](RELEASE-0.5.6.md) | radio follows the configured channel; 802.11r/FT ready; ACL proven |
| [`0.5.5`](RELEASE-0.5.5.md) | zero-touch DHCP option 138 discovery, tx-power/DTIM, relay self-heal |
| [`0.5.3`](RELEASE-0.5.3.md) | WPA2-EAP in the shipped image (v0.5.3/v0.5.4) |
| [`0.5.2`](RELEASE-0.5.2.md) | on-cap datapath out of the box, PMF required, PMF/SAE verified |
| [`0.5.1`](RELEASE-0.5.1.md) | restart converges to 8/8, WPA3/SAE live, warning-free build |
| [`0.5.0`](RELEASE-0.5.0.md) | PSK-free CAP completes the 4-way; zero-touch image flashed |
| [`0.4.0`](RELEASE-0.4.0.md) | initial manager-only image and certificate enrolment |

The v0.6.8 image sha256 is
`79411d06d6e7cfa5eba97a65ee7458bcdea6c32b942ff25f6dbf80ba85fe0f92`
(7,406,690 B). The one-CAP/eight-radio topology uses one
`cap=OpenWrt-CAPSOLO` with 8 radios, 8 SSIDs and all eight station tests
`authorized: yes`, 3/3, 0% — including after a cold reboot.

Per-release files are historical: a limitation written in an old note may
have been fixed later. Use [`../README.md`](../README.md),
[`CAPSMAN-COVERAGE.md`](CAPSMAN-COVERAGE.md) and
[`OPEN-PROBLEMS.md`](OPEN-PROBLEMS.md) for current status.
