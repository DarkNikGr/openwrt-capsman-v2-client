# W51 — ownership source fallback + MLD guard

Two defects found by W49 on the Deco BE65 vendor image are fixed here.

## 1. `network.wireless` missing ⇒ wrong `ownership=own`

On the vendor image (IPQ5332, hostapd + vendor scripts, not netifd) ubus has
no `network.wireless` object:

```
# ubus -t 2 call network.wireless status
Command failed: Not found
# uci -q show wireless | grep -c '=wifi-iface'
26
```

The old auto probe mapped "ubus unusable" to "0 netifd ifnames" and therefore
to `ownership=own`, so a `--vap-auto` run would have adopted/created netdevs
next to the vendor's 17 BSSes.

### The chain

| # | Source | Result |
|---|---|---|
| 1 | `ubus call network.wireless status` | `ok`/`busy`: authoritative. `legacy` iff it names ≥1 netdev; otherwise `own` (mixed mode stays possible). |
| 2 | `uci -q show wireless` | count `=wifi-iface` sections |
| 3 | `/etc/config/wireless` | count `config wifi-iface` sections |
| 4 | none readable | `source=none` |

Steps 2–4 always produce a **hard read-only session**: `g_wl_readonly = 1`,
so `own_claim()`, `own_try_start()`, `own_reconcile()`, `own_restore_vaps()`,
`own_destroy()` and the W45 session deauth all refuse to create, adopt,
steal, start or delete anything.  `--vap-auto` does not override it.  (The
only stop is an already-journaled hostapd whose name netifd has just claimed,
needed to resolve the conflict.)

The effective result is printed once per session, before connecting:

```
wl: ownership=legacy mode=auto source=uci ifaces=26 ubus=unknown action=read-only
wl: MLD (mld-*) and any netifd/vendor netdev are never adopted, stolen, deleted or restarted
```

`--wireless-owner legacy` forces the same read-only result (also turning off
global UCI apply).  `--wireless-owner own` is the only explicit opt-in out of
the fail-safe (for test rigs and vendor images the operator really owns).
`--check-wireless` uses the same chain and prints the same line.

An explicitly supplied `--wireless-config FILE` stays an offline input: no
live probe runs, and a file with `wifi-iface` sections is read-only.

## 2. Zero/multicast MAC resolved to the MLD netdev

The Deco exports `mld-wifi0` (address `00:00:00:00:00:00`, iftype AP,
ifindex 22).  `ifindex_by_mac_ap({0})` matched it because the AP check passed
and the address compared equal, so `--selftest-policy` failed its zero-MAC
check and a zero MAC could have been advertised as a VAP netdev.

New guards:

* `wl_mac_usable()`: all-zero, multicast and broadcast MACs never resolve;
* `wl_netdev_ignored()`: `mld-*` is never a BSS — it is skipped by the MAC
  resolver, by the `own_claim()` candidate list, by journal restore (a stale
  row naming an MLD is dropped), by `vap_hostapd_start()`, and by the stale
  file cleaners;
* the policy selftest now covers zero/multicast/broadcast usability, the MLD
  name predicate and, on any system that has an `mld-*` netdev, proves its
  own MAC cannot resolve back to it ("MLD netdevs present=1, none resolved").

`--selftest-policy` remains **27 checks, 0 failures** (the new assertions are
folded into the existing zero-MAC check).  `tests/test_ownership.c` gained a
read-only-source + MLD regression group.

## Verification

* mipsel build (OpenWrt SDK, mt7621) and aarch64 build: no warnings;
* `--crypto-selftest` 4/4; `--selftest-policy` 27/27;
* host state machine 61/61, netifd parser 21/21 under `qemu-mipsel`;
* Deco BE65, strictly read-only, **auto ownership + `--vap-auto`**:
  `/etc/config/wireless` md5 `12136bed2bac904935572f2af5a1f8dd` before = after
  = final; 26 `wifi-iface`; 17 BSS entries; 13 hostapd conf md5s; `ip -br
  link` 43; no journal row, no `vap-*.pid`/`vap-*.conf`, no `cm*` monitor;
  manager reports `BE65 state=Ok`.

See `/tmp/opencode/work-W51/REPORT.md` for the full evidence index.
