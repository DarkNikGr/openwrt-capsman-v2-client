# mt76x02 patches for RouterOS dynamic 5 GHz provisioning

`0001-mt76x02-sequential-slots-and-any-bssid-rx.patch` is the driver half of
the no-static 5 GHz fix. It applies to `openwrt/mt76` at
`8e4f72b682e9070108536507c5e2720b18c3816d` (the module in the OpenWrt 24.10
Xiaomi image, `mt76-2025.01.14~8e4f72b6`).

## Why

RouterOS derives dynamic virtual AP BSSIDs as `master[0] | 0x02` with the
last octet incremented:

```
28:D1:27:1B:2D:83  master
2A:D1:27:1B:2D:85  virtual1
2A:D1:27:1B:2D:86  virtual2
2A:D1:27:1B:2D:87  virtual3
```

On mt76x02 that breaks in two independent places:

1. **BSS slot.** Stock derives the slot from BSSID byte 0 only, so all three
   `2A:...` vifs map to slot 1 and the second one fails with `-EBUSY`.
2. **RX address comparator.** The MAC compares the received RA against the
   single radio base (`MT_MAC_ADDR`/`MT_MAC_BSSID`). `MT_RX_FILTR_CFG` bit 2
   (`PROMISC` in mt76, `DROP_NOT_TO_ME` in the rt2800 documentation of the
   same MAC block) drops frames whose RA does not match. Frames for
   `...:85/86/87` never reach mac80211, so hostapd never sees Auth.

The patch assigns the first free slot (`__ffs64(~vif_mask)`) and clears
`DROP_NOT_TO_ME` when an AP vif outside the base prefix is added. mac80211 then
demultiplexes by the real BSSID. The stock 2.4 GHz mt7603e path is untouched.

## Companion hostapd patch

Even with the driver patch, hostapd sends the AP Auth/Assoc response from a
non-primary BSS and its TX status may never be reported as ACKed. The station
does receive the response and associates, but hostapd logs `did not
acknowledge authentication response` and drops the station. The companion
patch `patches/9999k-hostapd-external-rsn-noack-tolerance.patch` accepts the
response in external-RSN mode. Both patches are required for dynamic 5 GHz
provisioning.

## Build

Use the exact OpenWrt 24.10 kernel/toolchain/mac80211 backports of the image
(`6.6.73`, GCC 13.3.0, backports 6.12.6). In a buildroot or SDK that contains
`package/kernel/mt76`:

```
mkdir -p package/kernel/mt76/patches
cp patches/mt76/0001-mt76x02-*.patch package/kernel/mt76/patches/
make package/kernel/mt76/clean
make package/kernel/mt76/compile
```

Collect `mt76x02-lib.ko` from
`build_dir/target-mipsel_24kc_musl/mt76-*/mt76x02-lib.ko`; verify:

```
modinfo mt76x02-lib.ko | grep -E 'vermagic|accept_any_bssid'
# vermagic: 6.6.73 SMP mod_unload MIPS32_R2 32BIT
# parm: accept_any_bssid:bool
```

The prebuilt artifact used for v0.7.0 is
`artifacts/mt76x02-lib.ko` (sha256 `8f3aa3a8…`) in the release bundle.

## Image / install

The module is installed on its own; **do not replace `mt76.ko`** (that module
must keep its `mac80211,cfg80211` dependencies). The working set is:

```
stock  mt76.ko mt76x2-common.ko mt76x2e.ko
patch  mt76x02-lib.ko
```

`scripts/build-image.sh` accepts `MT76X02_KO=/path/to/mt76x02-lib.ko` and
overlays it at `/lib/modules/<kernel>/mt76x02-lib.ko`.

On a running device:

```
cp mt76x02-lib.ko /lib/modules/$(uname -r)/mt76x02-lib.ko
depmod -a
reboot
```

Then use a normal provisioning rule with `master-configuration` +
`slave-configurations`; the CAP config must have `SLAVES_STATIC=no`,
`PER_VAP=auto` and `KEEP_SEC=yes`. The manager derives `2A:...:85/86/87` and
all four 5 GHz BSSes authenticate. Static virtuals (`SLAVES_STATIC=yes`,
`2E/22/26:...:83`) remain a fallback for a stock driver.
