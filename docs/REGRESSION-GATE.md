# Regression gate (W42)

`scripts/w42_harness.py` is the project's one-command acceptance gate. It
queries the live RouterOS 7.25.1 CAPsMAN v2 manager and the Xiaomi Mi Router 4A
CAP, and prints a stable JSON report. The exit code is `0` only when every
**required** check for the selected mode passes.

Two modes are defined, and they are deliberately different:

| mode | what it proves | local `/etc/config/wireless` |
|---|---|---|
| `--legacy` (default) | the classic deployment still works: local `wifi-iface`, CAP-local RSN, 8 BSS, STA, DHCP, ping | ≥ 8 `wifi-iface` sections |
| `--manager-only` | the project goal: the manager owns everything; zero `wifi-iface`, 8 manager-created BSS, manager-owned 4-way | zero `wifi-iface` sections |

Both modes sample the CAP for a stability window, so a CAP that reaches 8/8 and
then loses a BSS fails.

## Usage

```sh
# classic deployment, read-only, JSON to stdout + file
scripts/w42_harness.py --legacy --json-out legacy.json --dump-dir ev-legacy

# zero-config acceptance
scripts/w42_harness.py --manager-only --settle 40 --json-out manager.json

# pin the station under test (otherwise the harness auto-selects cap-test)
scripts/w42_harness.py --manager-only --sta-mac 2a:96:f6:87:cc:1d

# convenience wrapper: first argument is the mode
scripts/run-regression.sh --legacy --json-out legacy.json
```

Exit codes: `0` live PASS, `1` live FAIL, `2` harness error. Credentials are the
lab ones baked into the script (`test-cap/testadmin1234` on port 2244; CAP root
SSH on `10.0.0.126`). Nothing is written to the manager or the CAP in either
mode; `--full` additionally runs a temporary local hwsim self-test and is not
part of the live verdict.

## Pass rules

The JSON contains a `pass_rules` object (`check id -> rule`) and a
`required_checks` list for the selected mode. The verdict is computed only from
checks whose `required` field is `true`; other checks are diagnostics.

### `--manager-only` (strict)

| id | PASS when |
|---|---|
| `zero_wifi_iface` | 0 `config wifi-iface` sections in `/etc/config/wireless` |
| `join` | `remote-cap` has `OpenWrt-CAP3` with address and connected-time |
| `manager_state_ok` | that entry's `state` is exactly `Ok` |
| `vaps_defined` | exactly 8 `/interface wifi` objects are bound to the CAP |
| `vaps_up` | all 8 `phyX-apN` exist, type `AP`, `operstate=up`, ifindex > 0, enslaved to the expected `br-vlanXX`, and still 8/8 at the end of the window |
| `vap_start_0x6016` | the CAP log has `RX 0x6016 start port=` for `0x0000-3` and `0x0100-3` |
| `sta_associate` | `associated=yes` and `authenticated=yes` |
| `manager_registration` | `/interface wifi registration-table` has a row for the STA |
| `cap_psk_free` | every hostapd BSS has `external_rsn_auth=1` and no real `wpa_passphrase` |
| `fourway` | `authorized=yes` **and** manager registration row **and** `0x201f NEW_KEY PAIRWISE > 0` **and** zero hostapd-local `EAPOL-4WAY-HS-COMPLETED` events |
| `dhcp_vlan` | a bound manager lease for the STA MAC is inside the SSID's VLAN subnet |
| `ping` | manager `ping <lease>` receives ≥ 1 reply |
| `stale_ifindex_fix` | no `0x201c: ... ret=-19` in the log window |

### `--legacy` (classic)

Required: `legacy_wifi_iface`, `classic_local_rsn`, `join`,
`manager_state_ok`, `vaps_defined`, `vaps_up`, `vap_start_0x6016`,
`sta_associate`, `fourway` (kernel `authorized=yes` is enough), `dhcp_vlan`,
`ping`, `stale_ifindex_fix`.

`manager_registration` and `cap_psk_free` are reported but **not required**:
in the classic design the CAP holds the PSK and completes the 4-way locally,
and the manager may show no registration row.

## The stale-ifindex fix

After a VAP netdev is recreated the kernel assigns a new ifindex. The old code
trusted the cached `port -> ifindex` map and injected the manager's M1
(`0x201c`) into the dead ifindex:

```
0x201c: inject -> ... ifindex=31 len=121 ret=-19 (No such device)
```

`vap_ifindex()` now re-validates the cached value on every use: it resolves the
provisioned ifname (or the VAP BSSID after a rename), updates the map, and logs

```
pmap: port 0x0001 refreshed ifindex 31 -> 74 (phy1-ap3)
```

The direct-injection fallback used by the extmux relay (`xm_on_direct`) also
calls the resolver instead of using the ifindex cached at bind time.

Deterministic self-test of that code path (no manager required):

```sh
qemu-mipsel native/capagent-mipsel --selftest-pmap <ifname>
# seeds port 0x0001 with a dead ifindex and requires re-resolution
# -> SELFTEST pmap iface=... result=PASS
```

On the CAP run it against a real VAP (`--selftest-pmap phy0-ap1`).

## Live-run safety

The Xiaomi is shared with other tracks. Before a live run take the device
lock and restore the classic state afterwards:

```sh
ssh root@192.168.1.1 'flock -w 900 /tmp/cap-live.lock -c "<test>"'
# after the run:
ssh root@192.168.1.1 \
  'cp /root/v22-stock/wireless.keep /etc/config/wireless; wifi reload; \
   /etc/init.d/capagent start; sleep 20; iw dev | grep -c ssid'
```

The expected post-run count is 8.

## Baseline

`baseline/legacy.json` and `baseline/manager-only.json` are recorded runs
against the live RB1100 + Xiaomi; `baseline/REPORT.md` explains the result.
