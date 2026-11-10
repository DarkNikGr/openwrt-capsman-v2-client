# W56 — 5 GHz per-BSS rebase onto current `main`

Status: rebased, built and tested.  Base `7bfec3a` (`origin/main` at push
time), W54 change `a15c9c3`, branch `w56-5ghz-rebased`.

## Rebase result

`origin/main` advanced while W56 was running: it merged W54 as `7bfec3a`
(`merge: 5 GHz bring-up fix (W54)`), whose tree is identical to `a15c9c3`.
The W56 branch was therefore rebased from `f6cd5c8` onto `7bfec3a` and the
duplicate W54 cherry-pick was dropped:

```
7bfec3a (origin/main)
  |  merge: W54 (tree == a15c9c3)
  + bdc2b91  W56: narrow noscan, reserve BSS index 0 for VAPs
  + f7c76ab  docs: W56 record and patch series
```

No commit rewrites main's ownership work (`src/ownership.inc`,
`src/policy.inc`, `src/netifd_status.inc`, ubus detection).  `own_claim()`
still receives the address the netdev really carries (the W54 real BSSID),
and `0xd00b` reports that same address.


## What W56 changes on top of W54

### 1. `noscan=1` is now exactly the VHT80, non-DFS case

W54 wrote `noscan=1` for every 2.4 GHz 40 MHz and every 5 GHz >= 40 MHz BSS.
W56 narrows it:

```c
if (width >= 80 && !vap_is_dfs_chan(chan)) fprintf(f, "noscan=1\n");
```

* 2.4 GHz (20/40) has no reason to skip the coexistence scan and no longer
  does.
* 5 GHz 40 MHz is left with the normal hostapd scan.
* 5 GHz 80 MHz on a non-DFS primary (the case proven in W54) keeps `noscan=1`.
* A DFS primary (52–64, 100–144) **never** gets `noscan=1`; CAC/radar
  detection stays intact and `ieee80211h=1` is still emitted.
* The HT40 direction is now computed before the `noscan` line, so a channel
  that falls back to HT20 (no secondary channel, e.g. ch165) cannot leave a
  stale `noscan=1`.

### 2. Monitor never takes BSS index 0

`vap_bssid_pick_free()` starts at legal address index 1 and skips both
BSS index 0 and the radio MAC.  Index 0 stays available for VAP0 when the
manager sends a legal, free MAC that maps there.  On a 4-interface MT7603E
the monitor is still not created at all.

The device publishes the plan in index order:

```
$ cat /sys/class/ieee80211/phy1/addresses
28:d1:27:1b:2d:83   <- index 0, radio MAC
2a:d1:27:1b:2d:83   <- index 1, first address offered to the monitor
...
```

### 3. Allocator guarantees

* A manager BSSID is used unchanged only when it is **exactly** one of the
  addresses the phy publishes and its index is free.  Sharing bytes 1..5
  with the radio MAC is not sufficient (W54's check): a byte 0 outside the
  plan could still select index 0 and make the driver reprogram the radio
  base MAC.
* Otherwise the first free address from the phy plan is used and the real
  address is returned in `0xd00b` (body element `0x08`); the manager MAC
  remains known in `g_vmap` for later `0x6016`/`0x600c`/`0x201f`.
* The start gate keeps `flock(/var/run/cap-vap-start.lock)` and the bounded
  wait for `AP-ENABLED` / `DFS-CAC-START`; timeout kills the instance.

## W52 lifecycle compatibility

W52 (`d7363cb`, `w52-vap-lifecycle`) is not yet in `main`.  The W56 series
was also applied on top of W52 and resolved so that every function W52 uses
keeps its name and contract:

* `vap_hostapd_start()` remains the externally called function; W54's
  serialised implementation is the internal `vap_hostapd_start_one()`.
* `vapid_for()` still returns `-1` at 16/16 and still claims a registry row.
* `vapid_release()` / `vapid_release_slot()` now also free the mt76x02 BSS
  index, so destroy/recreate cycles do not leak indices.
* `vapid_claim()` initialises both identities (`mac` and `bssid`), so a
  reconnect/lost-reply row can never allocate a zero BSSID.
* W52's stale `g_vmap`/`g_vap` check compares against both identities before
  tearing a row down.
* `vap_destroy()` keeps its ordering: netdev gone first, then slot release.

Both variants build with `-Wall -Wextra` and pass the same checks.  Patch
files for the two bases live next to this document:

```
docs/W56/patches/main/  0001-w56...   (main already contains W54)
docs/W56/patches/w52/   0001-w54..., 0002-w56...
```

## Test evidence

* `make ... -j4`: mipsel static `capagent-mipsel`, no errors.
* `make ... check`: crypto selftest all pass, 27 policy checks 0 failures,
  ownership and netifd parser tests pass (both on `main` and on `w52`).
* `vapchan_test` (host harness built for mipsel, calls the production
  `vap_write_channel()`):
  * ch36 VHT80 -> `noscan=1`;
  * ch52/ch100 VHT80 -> **no** `noscan=1`, VHT80 centre frequency kept;
  * ch36 HT40 -> no `noscan=1`; ch6 HT40 -> no `noscan=1`;
  * output identical for the `main` and `w52` trees.
* `bssidx_test`: the eight addresses the live phy1 publishes map to unique
  indices 0..7; index 0 is the radio MAC and is reserved for VAP0.
* `alloc_test`, run on the live device (read-only, no netdev/hostapd):
  * with an empty-phy model: legal base `28:…:83` and legal index-1
    `2a:…:83` are kept; off-plan `28:…:92` -> `2e:…:83` (index 2);
    off-plan `3a:…:a1` -> `22:…:83` (index 3); monitor -> `26:…:83`
    (index 4, never index 0);
  * with the live phy state (another agent held indices 0/1): both legal
    requests are remapped because they are not free, which is the required
    "legal **and free**" rule.
* Device check: phy1 is `mt76x2e`, `addresses` index 0 is the radio MAC
  `28:d1:27:1b:2d:83`.  No wireless/netdev writes were made: the host lock
  was free, but another track's `capagent`/guard was active on the device,
  so only read-only sysfs inspection and the in-memory allocator harness
  were run.
