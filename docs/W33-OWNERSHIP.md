> **Status:** historical track record — the behaviour it describes is
> merged into `main`. Canonical docs: [MANAGER-ONLY](MANAGER-ONLY.md),
> [ARCHITECTURE](ARCHITECTURE.md), [OPEN-PROBLEMS](OPEN-PROBLEMS.md).

# W33 — ownership invariant, deterministic VAPs, key-install refresh

Audit of `be2e23d` (extmux + SDK build), `38581fc` (per-BSS relay / 0x2018 /
reconnect) and `8bd0258` (deploy preflight), and the fixes that restore the
two-mode contract.

> **W34 update (current behaviour):** the `config wifi-iface` count is no
> longer the production ownership source.  capagent reads
> `ubus call network.wireless status`, keeps one port→ifname/ifindex/pid/owner
> table, and journals it to `/var/run/capagent-vaps.state`.  Netifd always
> wins a name; the manager VAP moves to `cap<phy>-<vapid>` on collision.
> `wl_legacy()` is now the coarse "netifd owns at least one wireless ifname"
> predicate for global UCI decisions; per-netdev guards use
> `wl_port_managed()`.  `--wireless-owner legacy` still forces the fully
> read-only contract below.  See `REPORT.md` (W34) and
> `native/src/ownership.inc`.

## 1. The invariant (W33 history)

`/etc/config/wireless` decided who owned the radios in W33.  W34 replaced this
with live ubus status; the historical contract is kept here for context.

| `config wifi-iface` | mode | allowed side effects |
|---|---|---|
| **>= 1** | `legacy` | none on the wireless stack. Report `0x2018`, answer `0xd00b`/`0xe016`, ack `0x201f`/`0x2019`/`0x600c` **without** touching anything. |
| **0** | `own` | create/delete AP netdevs, start/stop our hostapd BSSes, install keys, arm the datachan. |

Everything is behind one predicate (`wl_legacy()`, `src/policy.inc`):

| side effect | site | guard |
|---|---|---|
| `NL80211_CMD_NEW_INTERFACE` (`__ap`) | `vap_netdev_create()` ← `vap_resolve()`, `createvap_response()` | `wl_own()` / `!wl_legacy()` |
| `NL80211_CMD_DEL_INTERFACE` | `vap_netdev_del()` ← `vap_destroy()` | `wl_own() && vp->we_created` |
| monitor VIF `NEW_INTERFACE` | `mon_create()` ← `mgmt_monitor_add()` | `!wl_legacy()` (legacy reuses an existing VIF or stays off) |
| `SIOCSIFFLAGS` (up) | `set_iface_up()` ← netdev create, monitor create | as above |
| `SIOCSIFMTU` | `set_if_mtu()` ← `dp_vap_open()` | `!wl_legacy()` |
| `exec hostapd -B` | `vap_hostapd_start()` ← `vap_provision()` | `vap_should_start_bss()` → 0 in legacy |
| `SIGTERM hostapd` | `vap_hostapd_stop()` ← `vap_destroy()` | `wl_own()` + pid identity check |
| `uci set/commit`, `ubus network.wireless reconf` | `apply_vaps()` | refuses in legacy |
| `NEW_KEY`/`SET_KEY`/`SET_STATION AUTHORIZED` | `handle_201f()` | skipped in legacy (wpad owns the 4-way) |
| `NL80211_CMD_FRAME` (deauth/action) | `handle_2019()` | skipped in legacy |
| `EXT_AUTH_TX` (EAPOL to STA) | `handle_201c()` | skipped in legacy |
| ext-auth sockets / extmux BSS adoption | `cap_extmux_start()`, `cap_extmux_restore()`, `cap_vap_ready()` | disabled in legacy |
| datachan arm on `0x500b` | `dc_handle_create()` | only in own mode |
| mgmt `REGISTER_FRAME` | `mgmt_register_sta()` | only in own mode |

`capagent --check-wireless [--wireless-config FILE]` prints the decision;
`--wireless-owner own|legacy` (env `CAPAGENT_WIRELESS_MODE`) overrides it for
tests only.

## 2. Regressions found in the three commits

The live evidence below was captured read-only from `root@192.168.1.1`
(OpenWrt 6.6.73, mt7621, MT7603 2.4 GHz + MT7612E 5 GHz, CAPsMAN 7.25.1).

### R1 — `cap_reset_session()` wiped the netdev identity (non-determinism)

`38581fc` replaced the persistent VAP map with `memset(g_vap)`/`memset(g_pmap)`
at every connection. The netdevs survive the reconnect, so the next `0x500b`
re-resolved VAP0 purely by MAC — and `ifindex_by_mac()` returned the **first
`/sys/class/net` entry** with that MAC, arbitrary readdir order included. The
mgmt monitor VIF carries the *radio* MAC (`cm0`=28:d1:27:1b:2d:82,
`cm1`=28:d1:27:1b:2d:83), which is also VAP0's BSSID.

Live log (19:26:09, a reconnect):

```
RX 0x500b phy=1 vap=0 a2=0 len=129
vap: rid=1 wid=0 vlan=99 freq=5180 bssid=28:d1:27:1b:2d:83 ifindex=63 ifname=cm1
0xd00b phy=1 vapid=0 ifindex=63 ifname=cm1      <- the monitor
0x6016 start port=0x0100 ...
vap: created phy1-ap0 ifindex=71 phy=1        <- a second netdev for the same BSS
```

So `0xd00b` advertised the monitor ifindex, extmux bound `ext-auth-cm1`, and
`0x6016` then created `phy1-ap0`. The same MAC produced different VAP→netdev
mappings per session.

Fixes: `ifindex_by_mac_ap()` only accepts AP/AP_VLAN netdevs of the requested
phy and picks the conventional `phyN-apM` name, otherwise the lowest ifindex
(deterministic). `cap_reset_session()` keeps the per-VAP identity while the
netdev exists, closes only session handles, and `vapid_gc()` drops only
allocations whose netdev is gone. `vap_resolve()` is now the single resolution
path for `0x500b` and `0x6016`.

### R2 — `vap_provision()` recomputed `phy%d-ap%d` instead of using the bound netdev

Besides disagreeing with the `0xd00b` reply, a name mismatch made
`vap_provision()` call `vap_netdev_create()` (in legacy mode too), and because
`created == 1` bypassed the old `wireless_has_bss()` guard, a *second* hostapd
was spawned on top of netifd's BSS. That is the "start a hostapd at all" path
the invariant forbids.

Fixed by `vap_resolve()` (bound name → conventional name → AP-only MAC →
create only when `wl_own()`) and by `vap_should_start_bss()`, which returns 0
whenever the config is legacy — even when `/var/run/vap-<if>.pid` is absent
(the old code's only legacy-check was the pid file, so a legacy BSS with no
pid file looked "free").

### R3 — `0x600c` leaked the vapid (VAP lifecycle wedged)

`OPEN-PROBLEMS.md` §3 already listed it: the handler only sent `0xe00c`.
`vapid_release()` was dead code, and `vapid_for()` returns 0 when all 16 slots
are used, so the second create cycle mapped every new MAC onto vapid 0 (wrong
name, wrong `0xd00b`, duplicate VAP). `vap_destroy()` now:

* releases the MAC→vapid allocation and the `g_vap` slot,
* removes both port aliases from pmap/vchan and deletes the extmux BSS,
* stops **our** hostapd and deletes **our** netdev only in own mode
  (`vp->ap_started`, `vp->we_created`, `--no-vap-teardown` to opt out),
* is a pure bookkeeping no-op for netifd-owned interfaces.

Also fixed: `0x500b` always carries `vapid=0` on the wire (the MAC is the
identity), so the old code wrote `pmap_set(phy<<8|0, ...)` for **every** VAP —
port `0x0100` ended up pointing at the last VAP created. The request-port alias
is now written only when `req_vap == vapid` (`vap_port_alias_ok()`).

### R4 — `0x201f` used a possibly stale ifindex

`handle_201f()` trusted `pmap`/sysfs. After hostapd or a reconnect recreated
the netdev the index changes, and the live run shows the failure modes:

```
0x201f: NEW_KEY IGTK/BIGTK idx=4 cipher=0fac06 len=16 ifindex=73 ret=-127 (Network is down)
0x201f: NEW_KEY IGTK/BIGTK idx=4 cipher=0fac06 len=16 ifindex=74 ret=-127 (Network is down)
```

(ifindex 73/74 are `phy1-ap2/ap3`, `state DOWN` because their hostapd never
started; `-127` is `ENETDOWN`, reported as "Network is down".) Other passes
reported `-ENODEV` on a recycled index.

`vap_refresh_ifindex()` re-resolves the netdev right before the key descriptor
loop: the VAP's bound ifname wins, then the validated pmap, then the AP-only
MAC lookup; pmap and the extmux BSS ifindex are updated together. `vap_ifindex()`
also validates its cached slot (ifindex still resolves, MAC still matches)
before returning it.

### R5 — mgmt monitor VIFs were created in legacy mode

`mgmt_vap_add()` (auto → monitor when hostapd owns `REGISTER_FRAME`) always
called `mon_create()`. On the 5 GHz phy this is doubly wrong: the wiphy allows
`#{managed, AP, ...} <= 4, total <= 4` (`iw list`), so with four legacy BSSes
the monitor create fails with `-ENFILE` — and it is still an interface
creation. Live log: `mon: NEW_INTERFACE phy=1 cm1: -23 (Too many open files in
system)`. Legacy mode now reuses an existing monitor VIF (`cm<N>`, verified by
iftype) and never creates one.

### R6 — `apply_vaps()` could rewrite the legacy config and reconf netifd

`APPLY=yes` is the packaged default. When the manager pushes an optional
`0x77` tree, `apply_vaps()` wrote `ssid/encryption/key` into every
`network=wifi<VLAN>` section, committed, and called
`ubus call network.wireless reconf {"device":"radioN"}` — a full netifd
reconfiguration of interfaces capagent does not own. It is now refused in
legacy mode (the tree is still parsed and logged).

### R7 — extmux adopted netifd's BSSes

`cap_extmux_restore()` walked every `phyN-apM` at session start and registered
it, binding `ext-auth-<if>` in `/var/run/hostapd` and resyncing stations via
`iw`/hostapd ctrl. In legacy mode that is someone else's BSS. It is now gated
on `!wl_legacy()` and on `iftype == AP`.

### R8 — hostapd zombies and unchecked starts

`vap_hostapd_start()` forked `hostapd -B` and never reaped the daemonizing
intermediate child; the live device had 8 `<defunct>` hostapd processes. The
handler now reaps it (3 s `WNOHANG` poll, so a slow DFS/ACS setup does not
stall the TLS loop) and reports a non-zero setup status with the per-BSS log
path instead of claiming success. `vap_hostapd_running()` also verifies the
pid's `/proc/<pid>/cmdline` contains **our** `/tmp/vap-<if>.conf`, so a
recycled pid or a zombie is never mistaken for "our BSS is up" (and never
killed).

## 3. Not regressions (kept, documented)

* **5 GHz hostapd cannot start on this radio in manager-only mode**:
  `phy1-ap0` logs `nl80211: kernel reports: Match already configured`, the
  rest `Resource busy` / `Interface initialization failed`. The wiphy also caps
  the 5 GHz phy at 4 interfaces total, while the manager provisions 4 BSSes
  *plus* our monitor. This is the pre-existing `OPEN-PROBLEMS.md` §2 (one
  hostapd process per BSS fights over the single per-phy channel configuration)
  — not caused by the three commits. W33 makes it visible (failed starts are
  now logged) and stops the agent from making it worse by adding VIFs.
  2.4 GHz keeps working (4/4 SSIDs).
* **`0x2018`/`0x2019`/`0x201f` parsing** from `38581fc` was re-checked: per
  descriptor class tags, `0x3f` as RSSI, subtype filtering, template discard —
  no change needed.
* **Discovery/preflight** (`8bd0258`): no netdev/hostapd/UCI effect, no change
  needed. The preflight's hostapd wait is satisfied by wpad in legacy mode.

## 4. Verification

Build (mt7621 SDK + mbedTLS 3.6.2, static, stripped):

```
mipsel-openwrt-linux-musl-gcc -O2 -Wall -Wextra ... -static -o capagent-mipsel
capagent-mipsel: ELF 32-bit LSB executable, MIPS, MIPS32 rel2, statically linked, stripped
```

Self-tests under `qemu-mipsel` (`make check`):

```
crypto-selftest: all tests passed
wl: ownership=legacy (/tmp/...: 8 wifi-iface) -- read-only, netifd/wpad owns the BSSes
wl: ownership=own (/tmp/...: 0 wifi-iface)
policy-selftest: 21 checks, 0 failure(s)
```

Syscall-level check of a full startup in legacy mode (`qemu-mipsel -strace`,
manager unreachable so the agent only classifies and retries):

```
wl: ownership=legacy (tests/wireless-legacy-8iface: 8 wifi-iface) -- read-only ...
SIOCSIFFLAGS 0   SIOCSIFMTU 0   exec hostapd 0   exec uci 0   kill 0
```

Fixtures: `native/tests/wireless-legacy-8iface`, `native/tests/wireless-own-0iface`.

## 5. Operator notes

* Switching manager-only → legacy: stop capagent first, remove
  `/var/run/vap-*.pid` and any `hostapd -B -P /var/run/vap-*.pid` process,
  then install the legacy config and `wifi reload`. A running per-BSS hostapd
  from the previous deployment otherwise holds the channel/BSSID and netifd's
  wpad cannot start (`Resource busy`). W33 never kills a hostapd on its own
  when a legacy config exists.
* Switching legacy → manager-only: remove every `wifi-iface` (keep or drop
  `wifi-device`), `wifi reload`, then start capagent; it will create `phyN-apM`
  itself.
* 5 GHz manager-only remains limited to what the 4-interface phy allows; the
  2.4 GHz radio is the working reference.
