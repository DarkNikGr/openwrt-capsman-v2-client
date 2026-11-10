# W52 — one VAP lifecycle on top of the W34 ownership table

Status: `w38-vap-lifecycle` merged onto `origin/main` (`f6cd5c8`).  There is
now exactly one lifecycle implementation: the W33/W34 ownership journal and
policy decide *who* owns a netdev; the W25/W28/W38 teardown decides *what* is
released and in which order.

## Guarantees

| guarantee | mechanism |
|---|---|
| one netdev per `(phy,vapid)` | `own_claim()` is the only creation path; `g_vmap`/`g_vap` keep the MAC→id stable; a duplicate `0x500b` returns the same id/ifindex/name |
| one hostapd per `(phy,vapid)` | pid file + journaled pid + `/proc/<pid>/cmdline` scan matched against `/tmp/vap-<ifname>.conf`; `own_try_start()` never starts when either proves a live daemon |
| duplicate `0x6016` | identical body → ignored; changed body → stop the old daemon, unlink pid/conf, start exactly one new one |
| `0x600c` full teardown | `dp_vap_close` → extmux/ext-auth close+unlink → `dc_forget_vap` → `vchan_clear`/`pmap_del` → `own_destroy` (hostapd, files, netdev) → wait for the name to vanish → `vapid_release_slot` → `mgmt_vap_del` |
| id release | `vapid_release_slot(phy,id)` after the netdev is gone, plus MAC release; the next `0x47` can reuse 0..15 without colliding |
| failure is bounded | `OWN_START_TRIES=5`, 2 s exponential backoff, each failure logged `n/5`, one final “giving up” line; a new `0x6016` resets the budget |
| no zombie/defunct hostapd | `vap_hostapd_start()` reaps the `-B` intermediate child; `vap_stop_hostapd()` TERM→KILL→`waitpid(WNOHANG)`; the watchdog also reaps orphans |
| no orphan objects | 5 s `vap_watchdog()` reaps pid/conf files, hostapd processes, `phyN-apM`/`capN-M` netdevs and `ext-auth-*` sockets with no live VAP or journal row — never a netifd BSS |

## Ownership, not a second truth

* `own_claim()` (W34) is called from both `0x500b` and `0x6016`; it reads
  `ubus call network.wireless status`, the journal and the live pid file.
  `netifd` always wins a name; the manager VAP moves to `cap<phy>-<vapid>`.
* `own_destroy()` stops/deletes only a `CAPAGENT` row and honours
  `--no-vap-teardown` / forced legacy.
* A destroy after a reconnect reaps the leftovers only when `/tmp/vap-<if>.conf`
  proves the CAP created them, and never when netifd owns the name.

## `0xd00b` contract (W1)

`0x49` is the **raw** ifname (not a nested `0x9e` blob), `0x47` the proposed
id, `0x48` the real ifindex, `0x61` the real MHz, and the W41 channel table is
unchanged.  Allocation is MAC-stable and returns `-1` at 16/16 (no reply), so
the manager retries instead of accepting a duplicate id.

## Tests

* local hwsim, real hostapd, fake CAPsMAN peer:
  `work-W52/evidence/cycle5-hwsim-dup.log` — 5/5 create/start/destroy cycles,
  duplicate `0x500b` idempotent, duplicate `0x6016` ignored, changed `0x6016`
  restarted in place, cap, slot reuse, watchdog orphan reap;
  `work-W52/evidence/cycle8-hwsim.log` — 3 × 8 VAPs, all counts 8→0.
* W34 ownership/netifd tests and policy selftest: 104 + 27 checks, 0 failures.
* live Xiaomi: see `work-W52/REPORT.md` §3.
