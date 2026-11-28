# v0.6.8 — 320 MHz EHT encoding (F89 fixed)

Focused 6 GHz release on v0.6.7. The one-CAP/eight-radio topology is unchanged.

## 320 MHz on an EHT 6 GHz BSS

v0.6.7 generated the width-6 `0xD00B` descriptor and the manager accepted
`channel.width=20/40/80/160/320mhz`, but the CAP's hostapd had no width-6
mapping and started at 20 MHz. The new shared `chan6.inc` emits the real EHT
320 configuration:

```
op_class=137
ieee80211be=1
eht_oper_chwidth=9              # CONF_OPER_CHWIDTH_320MHZ
eht_oper_centr_freq_seg0_idx=31
eht_bw320_offset=1
he_oper_chwidth=2
he_oper_centr_freq_seg0_idx=31
```

Verified on an EHT `mac80211_hwsim` radio with a BE-enabled hostapd:

```
ap320: AP-ENABLED
iw dev ap320: channel 1 (5955 MHz), width: 320 MHz, center1: 6105 MHz
hostapd status: ieee80211ax=1 ieee80211be=1 eht_oper_chwidth=9
               eht_oper_centr_freq_seg0_idx=31
```

If the radio or hostapd has no EHT/320 support, a width-6 profile falls back
to **160 MHz** (`op_class=134`), never 20 MHz, and no `ieee80211be` line is
written. The CAP still only advertises width 6 for an EHT radio (or the
`CAPAGENT_CHAN_320` lab override), so an HE-only radio does not claim 320.

The descriptor/hostapd centre and op-class rules now live in one file,
`native/src/chan6.inc`, with a host test (`test_chan6`) and `make check` gate.
20/40/80/160 `6ghz-ax`, 160/320 `6ghz-be`, and the v0.6.7 width-5 160 mapping
are unchanged.

## Not in this release

* **Solo convergence:** the ag17 patch was reverted after a live 5/8; a
  corrected ack/start design (`/tmp/ag23-solo/ag23-fix.diff`) is ready but
  needs a live A/B. v0.6.8 keeps the v0.6.6 cold-boot behaviour.
* **TLS/security and `0x6017` keep-VAPs:** the combined v0.6.8 candidate builds
  and passes `make check`; TLS is recommended for a canary, `0x6017` remains
  opt-in and live-unvalidated.

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1, one
`cap=OpenWrt-CAPSOLO` with 8 radios:

```
ssids=8  capagent=1  hostapd=10
capagent 0.6.8
```

6 GHz 320 evidence is from the EHT hwsim bench + BE hostapd; the reference
Xiaomi has no 6 GHz hardware.

Image sha256 `79411d06d6e7cfa5eba97a65ee7458bcdea6c32b942ff25f6dbf80ba85fe0f92` (7,406,690 B).
