# v0.6.2 — 6 GHz end to end on a virtual radio, 11k live, live security changes

Feature release on v0.6.1. The Xiaomi image still runs 8/8 SSIDs on both
bands; the headline work is three previously-open items, proven on the
`mac80211_hwsim` bench (no 6 GHz hardware, Deco untouched).

## 6 GHz, end to end (virtual radio)

* The manager provisions a **6 GHz** VAP on a hwsim radio:
  `6ghz-be`, 5955 MHz, `wpa3-psk` + PMF, hostapd `AP-ENABLED`.
* **New capability:** NEWPHY `0x84` byte 1 bit 1 (bit 9, beacon protection)
  is set automatically when the phy has frequencies >= 5925; without it the
  manager refuses the VAP with `beacon protection must be enabled for wifi7
  cap`. 6 GHz also rejects WPA2 (`Invalid AKM suite for 6 GHz`) — use SAE/OWE.
* **New hostapd config:** `hw_mode=a channel=<6g> op_class=131/132/133/134`,
  `ieee80211ax=1`, `he_6ghz_reg_pwr_type=0`, and for wider channels
  `he_oper_chwidth` + `he_oper_centr_freq_seg0_idx`. The 0xD00B reply now
  advertises 6 GHz 20/40/80/160 MHz descriptors (`BODY_MAX` 16 KiB).
* **Datapath:** a SAE station completes the 4-way and pings **3/3, 0%** in
  both directions; 20 MHz and **80 MHz** (center 5985) were verified.
* **Patch `9999h`:** the manager sends M1 before hostapd has associated the
  station; queue the newest EAPOL per station and flush it from
  `ext_auth_notify_assoc()`. Without it the 4-way died on 6 GHz.

Recipe and limits: [`6GHZ-HWSIM.md`](6GHZ-HWSIM.md).

## 802.11k live

* **Patch `9999i`:** keep a short RRM Enabled Capabilities IE (and copy it
  through the external-RSN early return in `__check_assoc_ies`), so
  `req_beacon` sees the station's beacon-report bits.
* A hwsim station advertises `46 05 70 ...`, receives the Beacon Request and
  answers with a real Beacon Report; the CAP relays it to the manager as
  `0x2018 action len=235`. This closes the CAP side of F69/F71; the bench Intel
  3168 still drops the RM IE.
* `CAPAGENT_NO_MFP` is a lab hook for wpa_supplicant's unprotected robust
  action frames.

Recipe: [`11K-HWSIM.md`](11K-HWSIM.md).

## Live manager security changes

* The manager signals a live profile change with **`0x6017`** (len 0) and
  marks the VAP INACTIVE. The agent now treats it as a change notification and
  re-joins, so the manager re-pushes `0x500b`/`0x6016`.
* A repeated `0x6016` whose SSID/RSN/channel/VLAN/DTIM actually changed also
  rebuilds the phy hostapd (`own_cfg_hash`); non-configuration repeats are
  still ignored (no restart loop).
* Verified live on 6 GHz: `sec-6g2` → `sec-6g3` passphrase change, VAP back to
  `MDB`, station with the new passphrase pings 0%, no identity restart.

## Xiaomi image

Clean `sysupgrade -n` of the image below: default 8 SSIDs (4+4), then
`identities.conf` + restart → 8 identities, and after a **cold reboot**:
8 SSIDs, 8 capagent, 10 hostapd, all eight station tests `authorized: yes`,
3/3, 0% (2.4 GHz 2437, 5 GHz 5180, hidden included).

Image sha256 `9a6dd9e8b35c24eb57c850222da1f9e7ea950b2c2c0b776f38aa146d3b30ee10`
(7,472,226 B).

## Still open

* 802.11v/BTM: the manager exposes steering groups but no deterministic BTM
  trigger (F67); the relay covers category 5 only.
* MLO/EHT multi-link, 6 GHz 160/320 MHz.
* Real 6 GHz hardware/AFC; the Intel 3168 11k limitation.
