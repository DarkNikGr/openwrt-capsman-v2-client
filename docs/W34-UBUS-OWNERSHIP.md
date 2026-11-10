# W34 — ubus ownership on top of the W33 policy surface

W34 keeps the W33 API (`src/policy.inc`) and replaces the config-file
heuristic with live netifd detection and one ownership table.  There is
exactly one mechanism and one journal now.

## Sources of truth

| Source | Question it answers |
|---|---|
| `ubus call network.wireless status` (`src/netifd_status.inc`) | which netdev names does netifd own right now? |
| `g_own[]` / `/var/run/capagent-vaps.state` (`src/ownership.inc`) | which port did capagent create/adopt, with which ifname/ifindex/pid? |
| `/proc/<pid>` + `/var/run/vap-<if>.pid` | is the journaled hostapd still alive? |

The config file is **not** consulted in production.  `--wireless-config FILE`
is an offline diagnostic/selftest input only.

## States

| State | Detection | create | hostapd | keys/relay | delete |
|---|---|---|---|---|---|
| `netifd` | name in `network.wireless status` | never | never | never | never |
| `capagent` | journal row + live pid/netdev | owned | yes | yes | on `0x600c` |
| `foreign` | netdev exists, neither of the above | no (use alternate name) | no | no | no |
| `pending` | manager asked while ubus probe unusable | retry when probe recovers | after create | after create | no |

Probe states: `ok` (full reconcile), `busy` (`"pending": true`), `unknown`
(ubus failed/timeout).  `busy`/`unknown` disable creation, deletion and name
stealing; only hostapd restart on an already-proven netdev is allowed.

## W33 API mapping

| W33 API | W34 behaviour |
|---|---|
| `wl_legacy()` | coarse session predicate: netifd owns ≥1 wireless ifname; still gates global UCI apply |
| `--wireless-owner legacy` / env | forces full read-only; `own_claim()` refuses to create |
| `vap_should_start_bss()` | unchanged and still selftested; called with `legacy = !managed` |
| `vap_port_alias_ok()` | unchanged |
| `ifindex_by_mac_ap()` | used as a deterministic AP-only candidate inside `own_claim()` |
| `vap_resolve()` | delegates to `own_claim()` (journal → preferred → MAC/AP → phyN-apM → capN-M) |
| `vap_refresh_ifindex()` | refuses netifd/foreign ports; refreshes the owned name |
| `vap_destroy()` | bookkeeping + `own_destroy()` (stop/delete only if ours and not netifd) |
| `cap_extmux_restore()` | delegates to `own_restore_vaps()` (journal-driven) |
| `--check-wireless` | read-only: load journal + probe ubus, no reconcile/cleanup |

## Repair

`own_service()` runs every second and between manager reconnect attempts:

* netifd took one of our names → detach: stop our hostapd, never delete the
  netdev, mark the row `netifd`;
* our netdev vanished (`wifi reload`) → recreate from the journal's last
  `0x6016` body and restart hostapd with exponential backoff;
* hostapd crashed but the netdev is alive → restart only, no duplicate;
* stale `/tmp/vap-*.conf`/pid files with no journal row or live process →
  remove;
* manager `0x600c` → stop/delete only when the row is `capagent` and netifd
  does not list the name; `--no-vap-teardown` and forced legacy keep objects
  and only drop the claim.

## Tests

```sh
make SDK=... check
```

Runs under `qemu-mipsel`:

* `--crypto-selftest` — 4 checks;
* `--selftest-policy` — 27 checks (21 W33 + 6 ubus payload checks);
* `tests/test_ownership.c` — 52 state-machine checks (pure manager, pure
  legacy/read-only, mixed, netifd takeover, agent restart, busy/unknown,
  stale cleanup, wifi reload, forced legacy);
* `tests/test_netifd_status.c` — 21 parser checks.

Combined: **104 checks, 0 failures.**
