# v0.5.9 — the secure CAPsMAN datachan comes up (a2=2) and carries traffic

Feature release on v0.5.8. The headline is the manager's secure datachan,
which had never come up in earlier runs.

## Highlights

* **`traffic-processing=on-capsman-secure` (`a2=2`) is live.** With a freshly
  created `dt-sec` datapath and the agent running `--datachan`, the manager
  sends the secure datachan create:

  ```
  RX 0x500b phy=0 vap=0 a2=2 len=196
  0x500b datachan variant a2=2 (AES-CCM)
  datachan: key rid=0 wid=0 vlan=40 keyidx=1 cookie=16B
  0x500b datachan id=428 port=5248 key=32B cookie=16B a2=2
  datachan: listening on UDP 5248, id 428 rid 0 wid 0 keyidx 1
  ```

  A station on that VAP gets `authorized: yes` and `ping 3/3, 0%`, and the
  traffic is carried as encrypted datachan frames (21 ×
  `datachan secure … payload=…` during the test). The manager's decision
  persists across CAP restarts; the CAP needed no change beyond the existing
  `--datachan` support.
* **802.11k machinery in the CAP.** `CAPAGENT_RRM=1` advertises the RM Enabled
  Capabilities element (so a station enables RRM), patch `9999f` relays
  category-5 action frames as `0x2018`, and patch `9999g` accepts a station's
  RM IE even without the capability bit (wpa_supplicant 2.11 omits it). The
  live beacon-report test is blocked by the bench station (the Intel 3168
  firmware drops the RM element), documented as F71.
* **Capability sweep hooks** `CAPAGENT_A7`, `CAPAGENT_NEWPHY_84/86` and
  `CAPAGENT_JOIN_A8` (a7: 37 values swept) for probing the manager's
  datachan/secure decisions.
* **Fixed `SET_INTERFACE -EALREADY`** (from v0.5.7) and the multi-identity
  work from v0.5.7 remain in the image.

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1. Clean
`sysupgrade -n`: `MANAGER=auto`, DHCP option 138 discovery, 8/8 SSIDs,
`br-vlan*` zone, 2.4 GHz on channel 6. `make check` green.

Image sha256 `c807f7eb98db5d411f90e052137877876ee9367584125569c2fe80d54114f973`
(7,472,226 B).

## Still open

* 5 GHz beyond one SSID (F66), 11k live (F71, station-side), 802.11v,
  6 GHz/MLO, local-forwarding.
