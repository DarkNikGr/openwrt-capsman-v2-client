# v0.7.0 — dynamic 5 GHz provisioning, no static and no fake radios (F92)

The 5 GHz radio now works like the 2.4 GHz one: **one real radio + three
manager-provisioned virtual APs**, all four SSIDs authenticate, and the
manager uses a normal **provisioning rule** (`master-configuration` +
`slave-configurations`). No static `/interface wifi`, no fake radio, no fake
base MAC.

## What was blocking it

RouterOS derives dynamic virtual BSSIDs as `master[0] | 0x02` with the last
octet incremented:

```
28:D1:27:1B:2D:83  master
2A:D1:27:1B:2D:85  virtual1
2A:D1:27:1B:2D:86  virtual2
2A:D1:27:1B:2D:87  virtual3
```

On mt76x02 this hits two independent hardware gates:

1. **BSS slot collision.** The stock driver selects the AP slot from BSSID
   byte 0 only; all three `2A:...` vifs map to slot 1 and the second one fails
   with `-EBUSY`.
2. **RX address comparator.** The MAC compares the received RA against the
   single radio base (`MT_MAC_ADDR`/`MT_MAC_BSSID`). `MT_RX_FILTR_CFG` bit 2
   (`PROMISC` in mt76, `DROP_NOT_TO_ME` in the rt2800 documentation of the same
   MAC block) drops frames whose RA does not match. Auth for `...:85/86/87`
   never reaches mac80211 or hostapd.

Even after both are fixed, hostapd's AP Auth/Assoc response from a non-primary
BSS may never be reported as ACKed. The station does receive it and
associates, but hostapd logs `did not acknowledge authentication response`
and drops the station before the 4-way.

## The fix (two patches, no fake)

1. **`patches/mt76/0001-mt76x02-sequential-slots-and-any-bssid-rx.patch`**
   - assigns the first free hardware slot (`__ffs64(~vif_mask)`) instead of
     deriving it from byte 0;
   - clears `MT_RX_FILTR_CFG` bit 2 when an AP vif outside the radio base
     prefix is added, so the MAC delivers the frame and mac80211 routes by the
     real BSSID.
   - module parameter `accept_any_bssid` (default on); `dev_info` lines show
     the slot and the RX-drop clear.
2. **`patches/9999k-hostapd-external-rsn-noack-tolerance.patch`**
   - in external-RSN mode, accepts an AP Auth/Assoc response whose TX status is
     not ACKed. The 4-way, key install and authorization are unchanged; a
     wrong PSK still fails.

The CAP needs no new knob: it automatically starts one hostapd per 5/6 GHz
VAP and keeps the single multi-BSS hostapd on 2.4 GHz.

## Live evidence (Xiaomi Mi Router 4A + RB1100AHx4 / RouterOS 7.25.1)

Manager: exactly two dynamic rules, no static 5G interfaces:

```
0 radio-mac=28:D1:27:1B:2D:82 master=cfg-hidden-sec slaves=cfg,cfg-guest,cfg-iot
1 radio-mac=28:D1:27:1B:2D:83 master=cfg5 slaves=cfg5-guest,cfg5-iot,cfg5-hidden-sec
```

CAP: 8 SSIDs, automatic one-hostapd-per-VAP, patched `mt76x02-lib.ko`,
patched wpad (`9999k`):

| BSSID | port | 4-way | `0x201f` | authorized |
|---|---|---|---|---|
| `28:...:83` 5G master | 0x0100 | yes | ok | **yes** |
| `2A:...:85` 5G guest | 0x0101 | yes | `ret=0` | **yes** |
| `2A:...:86` 5G iot | 0x0102 | yes | `ret=0` | **yes** |
| `2A:...:87` 5G hidden | 0x0103 | yes | `ret=0` | **yes** |
| `28:...:82` 2.4 master | 0x0000 | yes | ok | **yes** |
| `2A:...:82/83/84` 2.4 slaves | 0x0001–3 | yes | `ret=0` | **yes** |

`dmesg` on the 5 GHz radio:

```
vif 2a:...:85 type 3 -> hw BSS slot 1 (base 28:...:83)
vif 2a:...:85 is outside base prefix 28:...:83: clearing RX drop-not-to-me
...
```

All three dynamic 5G slaves complete the 4-way and are authorized; the state
survives a cold reboot.

## 6 GHz

Unchanged from v0.6.9: a normal provisioning rule with one 6 GHz radio and
three `slave-configurations` gives four `AP-ENABLED` BSSes at 5955 MHz,
`6ghz-ax`, 160 MHz, one hostapd per VAP; SAE/PMF stations are authorized on
the master and each slave (20/40/80/160). Real 6 GHz RF still needs a 6E/7
board; the reference Xiaomi has no 6 GHz radio.

## Install / upgrade

The release image contains:

* `capagent` 0.7.0,
* `wpad-mbedtls` with `9999k`,
* `/lib/modules/6.6.73/mt76x02-lib.ko` (patched; stock `mt76.ko`/
  `mt76x2*.ko` retained),
* `/etc/cap/capagent.conf` with `KEEP_SEC=yes`.

For an existing device, install the patched module and wpad, replace any
static 5G interfaces with a normal dynamic provisioning rule, and reboot.

## Verified on / image

Xiaomi Mi Router 4A Gigabit (ramips/mt7621, OpenWrt 24.10), RB1100AHx4 /
RouterOS 7.25.1, `capagent 0.7.0`, patched `mt76x02-lib.ko`, patched wpad
(`9999k`):

```
ssids=8  capagent=1  hostapd=7
capagent 0.7.0
```

The release image contains `KEEP_SEC=yes`, automatic one-hostapd-per-VAP,
the patched module at `/lib/modules/6.6.73/mt76x02-lib.ko` and the patched
wpad.

* image: `ecaa2dfdd8d99ca2e3d0755549691ccc863651bd263873953e3ff8c94d4a2af8`
  (7,537,762 B)
* `capagent-mipsel`: `904fb41e9254aa4b0c41e8fea1f002a1510c78796df79e2cc63a1a6c5d03dbfb`
* `capagent-aarch64`: `7fb6be2816c38ac14cef800141c3cf91af60df569031778e31b431b40d8f8bb3`
* `mt76x02-lib.ko`: `8f3aa3a8b9c3b94593cb9842da378f783ccc87eba4f5ff610b340b6f4c814e70`

## Not in this release

* A driver-only fix for the non-primary-BSS TX-status gate: it still needs the
  narrow hostapd no-ACK tolerance.
* Real 6 GHz hardware, AFC/standard-power and MLO.
