# W56 — 5 GHz per-BSS rebase onto current `main`

Status: rebased, built and tested.  Base `f6cd5c8` (`origin/main`, unchanged
when checked), W54 change `a15c9c3`, branch `w56-5ghz-rebased`.

## Rebase result

W54 was already a direct child of `f6cd5c8`, so the rebase itself is a
descendant-preserving cherry-pick with no tree change:

```
f6cd5c8 (origin/main)
  + e9d5018  W54: mt76x02 BSS index plan + noscan (cherry-pick of a15c9c3)
  + <next>   W56: narrow noscan, reserve BSS index 0 for VAPs
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

### 3. Unchanged W54 guarantees

* A manager BSSID that is legal and whose index is free is used unchanged.
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
docs/W56/patches/main/  0001-w54..., 0002-w56...
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
* Read-only device check: phy1 is `mt76x2e`, `addresses` index 0 is the radio
  MAC `28:d1:27:1b:2d:83`.  No live writes were made: the host lock was
  free, but another track's `capagent`/guard was active on the device.
