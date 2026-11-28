# v0.6.7 — 6 GHz 160 MHz and EHT `6ghz-be` live

Focused 6 GHz release on v0.6.6. The one-CAP/eight-radio topology is unchanged.

## The RouterOS 7.25.1 width code for 160 MHz is 5, not 4

The v0.6.6 6 GHz descriptor list emitted width `4` for 160 MHz. On this
manager width `4` is the 80+80 shape and a 160 profile was refused with
`no available channels` (`5955/ax/eeee/?(4/6025/0)`). The manager matches the
profile width **exactly**;

* `1` = 20 MHz
* `2` = 40 MHz
* `3` = 80 MHz
* `4` = 80+80
* `5` = 160 MHz
* `6` = 320 MHz

The CAP now emits width `5` for 160 and accepts width `5` from a `0x6016`
start. Verified on hwsim + RB1100AHx4 / RouterOS 7.25.1:

| Profile | Manager | hostapd / radio | SAE station |
|---|---|---|---|
| `6ghz-ax` 20 | `5955/ax` | op_class 131, 20 MHz | authorized, 3/3, 0% |
| `6ghz-ax` 40 | `5955/ax/Ce` | op_class 132, 40 MHz | authorized, 3/3, 0% |
| `6ghz-ax` 80 | `5955/ax/Ceee` | op_class 133, 80 MHz | authorized, 3/3, 0% |
| **`6ghz-ax` 160** | `5955/ax/Ceeeeeee` | **op_class 134, 160 MHz, cf 6025** | authorized, 3/3, 0% |
| **`6ghz-be` 160 (EHT)** | accepted | **op_class 134, 160 MHz** | authorized, 3/3, 0% |

```
/tmp/cap-phy0.conf:
  channel=1 op_class=134
  he_oper_chwidth=3
  he_oper_centr_freq_seg0_idx=15
  beacon_prot=1
iw dev: channel 1 (5955 MHz), width: 160 MHz, center1: 6025 MHz
```

## 320 MHz: CAP descriptor works, hostapd encoding does not

A width-6 descriptor is generated and the manager accepts
`channel.width=20/40/80/160/320mhz`, exposing
`5955/ax/Ceeeeeeeeeeeeeee`. The CAP's hostapd has no 6 GHz width-6 encoding
yet, so it starts at 20 MHz (`op_class=131`). The HE-only hwsim radio also has
no 320 capability. **320 MHz is not claimed**; see F89. 80+80 is generated
behind `CAPAGENT_CHAN_8080` but not claimed against the manager.

## Also in this release

* One `0x4d` NEWPHY entry per band id (no duplicate `0x06` on tri-band EHT).
* `beacon_prot=1` is emitted for a 6 GHz PMF BSS when hostapd supports it.
* `6ghz-be` uses descriptor band `0x06`; `6ghz-ax` uses `0x04` (v0.6.6).
* `6ghz-ax` remains the default for HE-only; `CAPAGENT_BAND6` overrides.

## Not in this release (evaluated, not merged)

* **Solo convergence patch:** the 855-line deferral/debounce patch applied and
  passed `make check`, but the live A/B on the Xiaomi stuck at 5/8 (phy5/6/7
  without SSID) for >5 minutes. It was reverted; v0.6.6 cold-boot behaviour is
  unchanged (5/8 at ~2 min, 8/8 by ~3 min).
* **TLS/security hardening and `0x6017` keep-VAPs:** patches are prepared and
  host-tested; not enabled in this release.

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1, one
`cap=OpenWrt-CAPSOLO` with 8 radios:

```
ssids=8  capagent=1  hostapd=10
capagent 0.6.7
```

6 GHz evidence is from `mac80211_hwsim` + the real manager; the reference
Xiaomi has no 6 GHz hardware.

Image sha256 `4907a68b90e7e479d6f732013c9cbbd09adbd04deff82763603cadbe208e587b` (7,472,226 B).
