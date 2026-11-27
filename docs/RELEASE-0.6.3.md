# v0.6.3 — 802.11v BTM live; 6 GHz `6ghz-ax` closed as manager-side

Patch release on v0.6.2. The CAP now proves the 802.11v BTM path end to end on
the virtual bench, and the 6 GHz band-id question is closed.

## 802.11v / BTM

* The manager's steering group alone does nothing while the simulated station
  sits at -27 dBm. `CAPAGENT_FAKE_RSSI=-80` overrides the RSSI in the `0x200e`
  station update (lab hook), and a steering group
  (`/interface wifi steering add name=sg1 neighbor-group=cap-wifi22,cap-wifi2`)
  then triggers a real BTM exchange:
  ```
  capagent: 0x2019 action -> 9a:1d:15:49:02:59 ... len=49 ret=0
  station:  Received Action frame ... Category=10
  station:  WNM: BSS Transition Management Request: dialog_token=1 ...
  station:  WNM: Send BSS Transition Management Response ... status=1
  ```
* **Patch `9999j`** relays the station's WNM action frame (category 10) to the
  manager, like `9999f` does for Radio Measurement:
  ```
  capagent: EXTMUX: 0x2018 action port=0x0000 len=29 freq=5955
  capagent: 0x2018 ext 9a:1d:15:49:02:59 -> manager (len=29)
  ```
* The BTM Request carried no candidate list because the group's neighbour was a
  different SSID (`cap-test`); the manager/CAP request and station/CAP response
  paths are proven. A same-SSID second BSS can carry candidates.

## 6 GHz `6ghz-ax` — manager-side limitation

A fresh-MAC sweep of the 6 GHz band id (`CAPAGENT_BAND6` = 0x05, 0x06,
0x07..0x10) with a `6ghz-ax` profile (beacon-protection bit and the full
20/40/80/160 descriptors) still gives `no available channels` in every case.
The manager's radio view always labels the CAP's 6 GHz channels `be` (band ids
outside 0x06 also add `(unknown)`), and only `6ghz-be` is selectable. 6 GHz
works at 20 and 80 MHz with `6ghz-be`; `6ghz-ax` cannot be exercised on this
RouterOS/hwsim combination.

## Xiaomi image

Clean `sysupgrade -n` of the image below, then `identities.conf` + restart:
8 identities/8 SSIDs. After a **cold reboot**: 8 SSIDs, 8 capagent,
10 hostapd. All eight station tests `authorized: yes`, 3/3, 0% (2.4 GHz 2437,
5 GHz 5180, hidden included).

Image sha256 `ab32d3b659b15c9a5ebe5af0809b16a682bf3968a7d61c1886cbd2778541d14e`
(7,472,226 B).

## Still open

* `6ghz-ax` and MLO/EHT multi-link, 6 GHz 160/320 MHz on real hardware.
* Real 6 GHz/AFC; the Intel 3168 11k limitation.
