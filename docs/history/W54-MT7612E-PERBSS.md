# W54 — 5 GHz per-BSS VAPs on the MT7612E (mt76x02)

Status: implemented, local tests pass.  Reviewed against OpenWrt 24.10,
kernel 6.6.73, hostapd 2.12-devel (OpenWrt `300-noscan.patch`).

## Symptom

Manager-only CAPsMAN v2 provisioning of 4 BSSes per radio brings up all four
2.4 GHz BSSes, but on the MT7612E only the first one reaches `AP-ENABLED`.
The later hostapd instances print

```
Could not set interface phy1-apN flags (UP): Resource busy
nl80211 driver initialization failed.
phy1-apN: AP-DISABLED
```

and the one that does start can sit in `HT_SCAN` while holding the wiphy, so
every other start blocks in `D` state (`SIOCSIFFLAGS`, cfg80211 netlink).
This is not an interface-count limit: the same phy runs 4 x VHT80 BSSes
under netifd, and `iw phy phy1 info` reports `total <= 8`.

## Three independent causes

### 1. `mt76x02` derives the hardware BSS index from byte 0 of the vif MAC

`mt76x02_add_interface()` (mt76x02_util.c):

```c
	if (vif->addr[0] & BIT(1))
		idx = 1 + (((dev->mphy.macaddr[0] ^ vif->addr[0]) >> 2) & 7);
	...
	if (dev->mt76.vif_mask & BIT_ULL(idx) ||
	    (vif->type != NL80211_IFTYPE_STATION && idx > 7))
		return -EBUSY;
```

Only byte 0 (bits 2..4) selects the index.  A BSSID plan that keeps byte 0
constant and varies only the last byte maps every VAP to the same index; the
first succeeds and the rest fail in `dev_open()` with `-EBUSY`.

`mt7603e` (2.4 GHz) allocates the first free index
(`__ffs64(~dev->mt76.vif_mask)`), independent of the MAC, which is why only
the 5 GHz radio failed.

The driver publishes the legal set in
`/sys/class/ieee80211/phyN/addresses` (8 addresses, bytes 1..5 on the radio
base, byte 0 encoding the index).  A manager MAC that is already one of them
is used unchanged; on a collision the first free legal address is used and
the real address is returned in `0xd00b`.  Only byte 0 bits 2..4 change, so
the driver never has to reprogram the radio base MAC.

### 2. The 40 MHz coexistence scan on a single-channel phy

With `ieee80211n=1`, `ht_capab=[HT40+]` (required for VHT80 centre
frequency) and `secondary_channel != 0`, hostapd runs
`ieee80211n_check_40mhz()` before enabling the BSS.  The offchannel scan is
refused with `-EBUSY` when another interface exists on the phy, or never
completes.  After 15 retries hostapd falls back to HT20, which cannot carry
the VHT80 centre frequency:

```
80/80+80 MHz: no second channel offset
Could not set channel for kernel driver
AP-DISABLED
```

`noscan=1` (OpenWrt `300-noscan.patch`, `conf->noscan`) makes
`ieee80211n_check_40mhz()` return immediately; HT40/VHT80 stay advertised.
netifd sets the same knob as `ht_coex=0` in `/var/run/hostapd-phyN.conf`.

### 3. A monitor VIF is a real driver interface

On the MT7603E a monitor consumes one of the four driver slots
(`MT7603_MAX_INTERFACES`), so with four VAPs it must not be created.  On
mt76x02 it does not take a BSS index but it must not carry the radio MAC,
which is index 0 / VAP0's address, so it gets its own legal address.

## Implementation

| file | change |
|---|---|
| `src/vap.inc` | `noscan=1` for HT40/VHT BSSes; start gate (flock) around hostapd; log-based `AP-ENABLED`/`DFS-CAC-START` wait bounded to 12 s with hard kill; pid read after the wait; never unlink a pid file that may belong to a live instance |
| `src/channels.inc` | mt76x02 address allocator (`vap_bssid_alloc`, `vap_bssid_free`, `vap_bssid_pick_free`), seeded from the interfaces already on the phy, with `phy_is_mt76x02`/`phy_max_vifs`; `g_vmap` keeps manager MAC and real BSSID; `vapid_for` matches both; `vapid_release`/`vapid_gc` free the index |
| `src/mgmt.inc` | monitor gets a free legal address on mt76x02 and is never created on a 4-interface radio |
| `capagent.c` | `<sys/file.h>` |

The start gate matters on top of the address fix: hostapd `-B` daemonizes
after `hostapd_driver_init` but before `hostapd_setup_interface()` returns,
so a pid file proves nothing.  Waiting for the log line and killing on
timeout is what makes "started" mean "beaconing" and keeps one bad BSS from
poisoning the next start on the same wiphy.

## Tests

* `make check`: crypto selftest, 27 policy checks, 30 netifd checks — pass.
* Live one-variable matrix on phy1 (real hostapd, 80 MHz, ch36):
  * driver address plan, no scan (`noscan=1`): 4/4
  * driver address plan, scan allowed: 4/4 when the phy is otherwise idle,
    `HT_SCAN` stalls as soon as the phy is busy — hence `noscan=1`
  * identical byte-0 plan: 1/4, `Resource busy` for the rest
  * driver plan + monitor: 4/4
* Manager-only CAPsMAN v2 peer: all 8 `0xd00b` accepted, the 5 GHz VAPs get
  indices 0/2/3/4 and the 2.4 GHz four VAPs start; see `REPORT.md` in the
  work directory for the full transcript and the interference caveat.

## Residual risks

1. A manager that requires the exact BSSID it sent will see a different one
   on mt76x02.  The CAP reports the real address in `0xd00b`.
2. `noscan=1` disables OBSS 40 MHz coexistence handling; with one channel
   per phy that handling was not functional.
3. DFS channels still need CAC; `DFS-CAC-START` counts as started and is not
   subject to the 12 s bound.
