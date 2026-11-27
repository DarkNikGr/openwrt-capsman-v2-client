# v0.5.8 — 802.11k action-frame relay in the CAP; a2=2 re-checked

Patch release on v0.5.7.

## Highlights

* **802.11k Radio Measurement relay (CAP side).** Patch `9999f` hooks
  `WLAN_FC_STYPE_ACTION` in `ieee802_11_mgmt`; a category-5 (Radio
  Measurement) action frame from a station is handed to the external-RSN relay
  and reported to the manager as `0x2018`, and capagent labels subtype 13 as
  `action`. The patch applies with `patch --fuzz=0` against the 2024.09.15
  source and the image ships the rebuilt `wpad`. The end-to-end test is
  documented as blocked on the bench (F69): the host's iwlwifi accepts a raw
  `NL80211_CMD_FRAME` injection but the frame never reaches hostapd, and this
  `wpad` has no 11k/`hostapd_cli` to request a real beacon report.
* **`a2=2` re-checked with a fresh capture (F68).** With
  `traffic-processing=on-capsman-secure` the manager still sends `a2=0`
  (`0x500b datachan variant a2=0 (none)`) and no `0x402b`; the only datachan
  traffic is the CAP's keepalives. Unchanged.

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1. Clean
`sysupgrade -n`: `MANAGER=auto`, DHCP option 138 discovery, 8/8 SSIDs,
`br-vlan*` zone, 2.4 GHz on channel 6. `make check` green.

Image sha256 `80851b3a1fb7dc09afcd1309655daa1a9c994eb1d8f5b5a8550a87aa72be7f9f`
(7,472,226 B).

## Still open

* 5 GHz beyond one master SSID (F66), secure datachan (F68), 11k live test
  (F69), 802.11v, 6 GHz/MLO, local-forwarding.
