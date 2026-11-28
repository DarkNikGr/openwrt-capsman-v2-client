# v0.6.9 — real 5 GHz radio + 3 slaves, no fake radios (F90)

The headline: the reference Xiaomi now runs **two real radios and eight SSIDs**
with **no fake radio and no fake base MAC**. The 2.4 GHz radio keeps its
master + 3 manager slaves; the 5 GHz radio carries a static master + 3 static
virtuals, and **all four 5 GHz BSSes authenticate**.

## Root cause

`mt76x02` selects the AP BSS slot from **BSSID byte 0** only:

```c
idx = 1 + (((dev->mphy.macaddr[0] ^ vif->addr[0]) >> 2) & 7);
```

but the hardware RX/auth match is tied to the radio base MAC **bytes 1..5**.
RouterOS 7.25.1 derives dynamic 5 GHz slaves as `2A:D1:27:1B:2D:85/86/87`:
they all share byte 0 (`0x2A` → one slot) and their suffix differs from the
real base `28:D1:27:1B:2D:83`. They either collide (`-EBUSY`) or, with a
slot patch, never deliver auth to hostapd. Earlier fake-base tests worked only
because the first 5G vif `2A:...:90` rewrote the radio base and the slaves
shared its suffix.

## The fix (no driver patch)

* Manager: a **static** 5 GHz master on the real radio
  `28:D1:27:1B:2D:83`, plus static virtuals whose byte 0 is a legal slot and
  whose bytes 1..5 equal the base:

  ```
  cap5g        28:D1:27:1B:2D:83  cfg5
  cap5g-guest  2E:D1:27:1B:2D:83  cfg5-guest
  cap5g-iot    22:D1:27:1B:2D:83  cfg5-iot
  cap5g-hidden 26:D1:27:1B:2D:83  cfg5-hidden-sec
  ```

* CAP: `SLAVES_STATIC=yes` and the generic per-VAP mode
  `CAPAGENT_PER_VAP=auto` (init option `PER_VAP`). For every phy with a
  journaled row at **≥ 4900 MHz**, capagent starts **one hostapd per VAP**,
  each with a single `interface=`, no `bss=` siblings. The 2.4 GHz phy keeps
  the existing single multi-BSS hostapd.
* Stock `mt76x02`, stock module set, no base-MAC rewrite: the radio base stays
  `28:D1:27:1B:2D:83` and the first vif equals it.

## Live evidence (Xiaomi Mi Router 4A + RB1100AHx4 / RouterOS 7.25.1)

```
ssids=8  capagent=1
phy0=28:d1:27:1b:2d:82   phy1=28:d1:27:1b:2d:83

phy0-ap0 28:...:82  cap-hidden     phy1-ap0 28:...:83  cap-test
phy0-ap1 2a:...:82  cap-test       phy1-ap1 2e:...:83  cap-guest
phy0-ap2 2a:...:83  cap-guest      phy1-ap2 22:...:83  cap-iot
phy0-ap3 2a:...:84  cap-iot        phy1-ap3 26:...:83  cap-hidden
```

* Manager: exactly **two** radio MACs (`28:...:82`, `28:...:83`); `cap5g`
  and its three virtuals are `B` (bound), rule 0 for 2.4 untouched, the old
  dynamic 5G rule disabled.
* CAP: all four 5 GHz BSSes `AP-ENABLED` with four per-VAP hostapds; fresh
  `logread` has no `EBUSY`, `Failed to add BSS` or `AP-DISABLED`.
* Station (`wlp39s0`, BSSID-pinned WPA2-PSK): 5G master `28:...:83` and
  slaves `2E/22/26:...:83` all `authorized: yes`, `0x2018` on ports
  `0x0100..0x0103` → `0x201c` → `0x201f`. The 2.4 slave `2A:...:82` still
  authenticates.
* **Cold reboot**: 8 SSIDs, same BSSIDs, 5G slave `authorized: yes` again.

## 6 GHz

The same per-VAP transport is what makes 6 GHz work. On `mac80211_hwsim`, a
**normal provisioning rule** (dynamic master + 3 `slave-configurations`, no
static interfaces) on one 6 GHz radio at 5955 MHz / 160 MHz (`6ghz-ax`,
SAE + PMF) gives four `AP-ENABLED` BSSes and a station `authorized: yes` on
the master and each virtual; 20/40/80/160 all pass with ping 0% (F91, AG54).
Stock hostapd multi-BSS fails on this stack; one hostapd per VAP is required.

The reference Xiaomi has **no 6 GHz radio**, so this remains a virtual-radio
proof. Real 6 GHz RF/AFC needs a 6E/7 board; see
[`HARDWARE-6GHZ-MLO-PLAN.md`](HARDWARE-6GHZ-MLO-PLAN.md). 320 MHz EHT encoding
from v0.6.8 is unchanged.

## Upgrade notes

* The 2.4 GHz rule needs no change.
* Replace a **dynamic** 5 GHz rule (`master=cfg5 slaves=…`) with the static
  master + three static virtuals above. Dynamic 5 GHz slaves still cannot
  authenticate on mt76x02: their byte 0 collides and their suffix differs
  from the base.
* If the 5 GHz base is not the real radio MAC after earlier fake-radio tests,
  reload the stock `mt76x2e`/`mt76x02-lib` modules (or reboot the CAP) and
  check `/sys/class/ieee80211/phy1/macaddress` before provisioning.
* `CAPAGENT_5G_PER_VAP=yes` is kept as an alias; prefer `PER_VAP=auto`.

## Verified on

Xiaomi Mi Router 4A Gigabit (ramips/mt7621, OpenWrt 24.10), RB1100AHx4 /
RouterOS 7.25.1, `capagent 0.6.9`, stock `mt76x02` modules:

```
ssids=8  capagent=1  hostapd=7
capagent 0.6.9
```

The zero-touch sysupgrade image ships `KEEP_SEC=yes`, `SLAVES_STATIC=yes` and
`PER_VAP=auto` by default.

* image: `6fdeadc76e2bf74998dffea8b5c8e004de25bb9a717a69d4f87ef208d99e036e`
  (7,537,762 B)
* `capagent-mipsel`: `142f872ae7abe2e2cff52d67bb673cb279218626a5e2b57b58a93b8b075a4aa9`
* `capagent-aarch64`: `f0f0cd158551140eaf6b91716c57c3c00a73073927c31570951dca2460eca71f`

## Not in this release

* Dynamic manager 5G slaves (`2A:...:85/86/87`) on mt76x02 — driver/hardware
  limitation, not a CAP-config bug.
* Real 6 GHz hardware, AFC/standard-power and MLO.
* A driver patch is **not** required for the 5 GHz fix and is not shipped.
