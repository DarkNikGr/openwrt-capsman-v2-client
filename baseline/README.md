# Baselines (W42)

Both files are raw `w42.cap-regression/1` reports from
`scripts/w42_harness.py` against the live RB1100AHx4 CAPsMAN v2 manager and
the Xiaomi Mi Router 4A CAP. The device was shared with other live tracks
(W39/W40/W41) during the session; the JSON is the authoritative snapshot of
the instant, not a permanent claim.

| file | mode | result |
|---|---|---|
| `legacy.json` | `--legacy` | FAIL: 9/12 required checks PASS; only `dhcp_vlan` and `ping` fail (the RB's VLAN-tagged DHCP path gave no OFFER); `fourway` PASSes with `owner=cap-local` |
| `manager-only.json` | `--manager-only` | FAIL: zero `wifi-iface`, join/state, 8 VAP objects, STA association, manager registration all PASS; `vaps_up` 6/8, `cap_psk_free` FAIL, `fourway` FAIL (manager row present but no PTK/authorize), DHCP/ping FAIL |

Common state in both captures:

* `vap_start_0x6016` 8/8, `stale_ifindex_fix` PASS.
* The manager-only capture logs 60 `0x201c` attempts, 30 successful
  injections and **zero** `ret=-19` — the direct proof that the stale-ifindex
  fix is active on the live CAP.
* `dhcp_vlan`/`ping` fail in both modes because the CAP's `br-vlanXX` path
  reaches its own dnsmasq but no OFFER returns over the RB VLAN. That is an
  environment/VLAN issue, independent of this change.

Re-run to refresh:

```sh
scripts/w42_harness.py --legacy       --json-out baseline/legacy.json
scripts/w42_harness.py --manager-only --json-out baseline/manager-only.json
```
