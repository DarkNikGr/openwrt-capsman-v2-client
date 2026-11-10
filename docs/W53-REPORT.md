# W53 — `EXT_AUTH_TX` contract, fix, tests, and live status

Work dir: `/tmp/opencode/work-W53/`
Repo worktree: `/tmp/opencode/work-W53/tree`
Branch: **`w53-ext-auth-tx`** (base `origin/main` @ `f6cd5c8`)
Commits: `8747141` (fix), `929c23d` (F13), `5455c3f` (reuse W46 `9999a`, add `9999b`)

## 1. Verdict (15 lines)

1. Root cause of `EXTMUX EXT_AUTH_TX FAIL` is proven from the source that built
   the deployed `wpad` (`d5a38360`): extmux appended `\n`, hostapd does not
   strip it, the hex length became odd and the handler returned `-1` **before**
   calling `hostapd_wpa_auth_send_eapol()`. M1 was never transmitted.
2. A second defect: the ctrl wrapper treated the nl80211 driver's positive
   "bytes sent" return as failure, so a transmitted frame still answered FAIL.
3. capagent now sends control commands bare (like `hostapd_cli`) and switches
   that BSS to the proven `nl_control_port_tx()` path after the first reject,
   with exactly one log line.
4. `EXT_AUTH_AUTHORIZE` failure now falls back to `NL80211 SET_STATION
   AUTHORIZED`; the authorize retry counter (reset on every retry) is finite.
5. The hostapd-side trim is **not duplicated**: W46's
   `patches/9999a-external-rsn-sae.patch` already has it and is reused
   verbatim; W53 adds only `patches/9999b-external-rsn-tx-retval.patch`.
6. The capagent half needs no `wpad` rebuild, so it works on the binary
   already deployed.
7. `native/tests/test_extmux.c` proves the wire format (no newline), the
   one-shot fallback and the authorize fallback; `make check` stays green.
8. `scripts/patches-check.sh`: 6 patches, 59 hunks, 0 fuzz.
9. Lab: a real hostapd built from this series accepts `EXT_AUTH_TX` with and
   without the trailing newline and sends the frame over the control port.
10. Live run: zero-config, join, `phy0-ap1` = `cap-test`, association all PASS.
11. **The live manager-driven 4-way was not reached**: the manager never sent
    `0x2018` for the test station, hence no `0x201c`/M1, hence no `0x201b`,
    `0x201f`, DHCP or ping. That blocker is *before* `EXT_AUTH_TX`.
12. `EXT_AUTH_TX FAIL` did not recur (0 occurrences) because no TX was ever
    requested — this is consistent with, but not proof of, the fix.
13. The live device was extremely contended (W39/W40/W52/W54 loops, two
    reboots); the last clean window was lost to a competing run.
14. Device always restored from `/root/v22-stock/wireless.keep`; at release it
    was verified **8 SSIDs / 8 wifi-iface**, md5 `3428463a…`, capagent up.
15. Bottom line: the reported bug is fixed and regression-tested; the full
    live 4-way still needs one undisturbed window (blocker documented in §5).

## 2. The exact hostapd contract

From `patches/999-external-rsn-auth.patch` and the source of the deployed
binary:

| direction | socket | message |
|---|---|---|
| hostapd → CAP | `ext_auth_socket` (`/var/run/hostapd/ext-auth-<if>`, dgram, CAP binds) | `ASSOC <mac> <rsn-ie-hex\|->`, `EAPOL <mac> <0\|1> <hex>`, `DISCONNECT <mac>` |
| CAP → hostapd | `ctrl_interface` (`/var/run/hostapd/<if>`, dgram, hostapd binds) | `EXT_AUTH_TX <mac> <hex> [encrypt=1]`, `EXT_AUTH_AUTHORIZE <mac>`; reply `OK\n` / `FAIL\n` |

`hostapd_ctrl_iface_receive_process()` pre-fills the reply with `OK\n` and only
overrides it on error. `EXT_AUTH_TX` measures the hex as "the rest of the
line", and `hostapd_ctrl_iface_receive()` does **not** strip the wire newline.
Therefore:

```
EXT_AUTH_TX <mac> 0203…f1\n   → strlen = 2*121+1 (odd) → len & 1 → -1
                              → FAIL, hostapd_wpa_auth_send_eapol() never called
```

That is the observed failure. `EXT_AUTH_AUTHORIZE` uses `hwaddr_aton()`, which
stops after 17 characters and tolerated the newline.

## 3. Fix

### 3.1 capagent (`native/src/extmux.c`, `native/src/mgmt.inc`)

* `EXT_AUTH_TX` / `EXT_AUTH_AUTHORIZE` are sent **without** a trailing newline.
* First non-`OK` TX reply on a BSS: set `direct_tx`, log **one** line, use
  `on_direct_tx` (`nl_control_port_tx`) for every later frame on that BSS.
  The rejected frame is not blind-reinjected (an old hostapd can transmit it
  and still answer FAIL; a duplicate M1 confuses the manager).
* `EXT_AUTH_AUTHORIZE` failure after retries → `on_direct_authz`
  (`NL80211_CMD_SET_STATION` + `NL80211_ATTR_STA_FLAGS2` AUTHORIZED).
* `txn_start()` no longer resets `txn_retries` (the authorize retry loop was
  immortal).

### 3.2 hostapd (`9999a` reused + `9999b` added)

* `patches/9999a-external-rsn-sae.patch` (W46, `w46-mgmt-auth` @ `d057013`)
  contains the trailing-CR/LF trim, plus `external_rsn_sae` and
  `EXT_AUTH_MGMT_TX`. Reused verbatim; applies cleanly after `999`/`9997`/
  `9998`/`9999`.
* `patches/9999b-external-rsn-tx-retval.patch` (W53): only a **negative**
  return from `hostapd_wpa_auth_send_eapol()` is an error; the nl80211
  `PF_PACKET` path returns the byte count. Dispatch tests `< 0`.
* Series: `999` → `9997` → `9998` → `9999` → `9999a` → `9999b`.

## 4. Tests and lab evidence

```
$ make -C native extmux-test
case 1: bare EXT_AUTH_TX, hostapd OK      → no newline, no fallback, no log
case 2: hostapd rejects EXT_AUTH_TX       → one line, 4 direct TX, daemon contacted once
case 3: hostapd rejects EXT_AUTH_AUTHORIZE→ 2 retries, nl80211 authorize, AUTHORIZED
extmux-test: all tests passed

$ make -C native check
crypto-selftest: all tests passed
policy-selftest: 27 checks, 0 failure(s)
W34 ownership + netifd tests: pass

$ ./scripts/patches-check.sh …   → 6 patches, 59 hunks, 0 fuzz
```

Lab contract test (`lab/`, hostapd with `9999a`, mac80211_hwsim, channel 1,
`/tmp/opencode/work-W53/lab/hostapd.log`):

```
EXT_AUTH_TX 02:00:00:00:00:99 <hex>\n  -> OK
EXT_AUTH_TX 02:00:00:00:00:99 <hex>    -> OK
hostapd: EXT-AUTH: TX 02:00:00:00:00:99 len=99 encrypt=0
hostapd: nl80211: Send over control port … no_encrypt=1
```

## 5. Live status and the remaining blocker

Run `live-20261111-004419` (bounded lock, restored):

```
S1   PASS 0 wifi-iface, 0 netifd phyX-apY SSIDs
S2   PASS capagent pid=17143 joined, manager sent 1x 0x6016
S3   PASS 2.4 GHz VAP phy0-ap1 advertises cap-test
S4-S8     station associated, then no 0x201c, no 0x201b, no 0x201f,
          authorized: no, no DHCP
S7b  INFO EXT_AUTH_TX failures=0 one-shot-fallback-lines=0
```

The station (`02:00:00:53:53:01`-class MAC) associated with BSSID
`2a:d1:27:1b:2d:82`, but the manager never received its `0x2018` relay: the
only `0x2018` lines are for another client (`50:8b:b9:7e:4f:e9`). Without the
assoc/auth relay the manager never issues M1, so `0x201c` never arrives and the
`EXT_AUTH_TX` path is not exercised. That is an assoc-relay issue (the same
area W46 addresses with raw `AUTH`/`ASSOCREQ` relay in `9999a` + its extmux
`on_mgmt`), not the TX contract.

Why it could not be re-run cleanly: the CAP was shared with W39/W40/W52/W54
loops (multiple lock holders, two reboots at 22:09 and 22:12, zero-config
windows from other tracks). The one clean window ended when a competing run
took the device; afterwards the device was explicitly released on request.

To finish the acceptance, with an undisturbed CAP (one bounded run):

1. Deploy the W53 `capagent-mipsel` (`58ebab73…`) and keep the deployed
   `wpad` (the capagent fix needs no rebuild).
2. Zero-config, start the agent, wait for **4x 2.4 GHz `0x6016`** (not 1).
3. Confirm the manager's registration table shows the CAP and that the
   station's `0x2018` reaches the manager; then `0x201c`/`0x201b`/`0x201f`,
   `authorized: yes`, DHCP, ping.
4. Expected log on the deployed wpad: exactly one
   `hostapd rejected EXT_AUTH_TX (FAIL); … direct nl80211 control-port TX`
   line per BSS, then `0x201b` and `0x201f` follow.

## 6. Device state at hand-off

* `/etc/config/wireless` was restored from `wireless.keep` and verified at
  **8 SSIDs / 8 wifi-iface**, md5 `3428463aa401ef2e94dbd008d1433058`
  (run trap, `evidence/live-20261111-004419/restore.txt`).
* The original `/usr/sbin/capagent` was restored and restarted.
* The W53 lock holder/guard, the temporary `crond`/crontab and all
  `/tmp/w53-*` files were removed; no w53 process remains.
* After release, the CAP was taken by another track (`/tmp/xx39/…`); the
  current zero-config state is that run's, not a leftover of W53.

## 7. Files

| file | change |
|---|---|
| `native/src/extmux.c` | bare ctrl commands, one-shot direct-TX fallback, authorize fallback, finite retries |
| `native/src/extmux.h` | `direct_tx` / `direct_authz`, `on_direct_authz` |
| `native/src/mgmt.inc` | `xm_on_direct_authz()` → nl80211 |
| `patches/9999a-external-rsn-sae.patch` | W46's patch, reused verbatim |
| `patches/9999b-external-rsn-tx-retval.patch` | TX return-value success test |
| `native/tests/test_extmux.c` | host regression gate (3 cases) |
| `native/Makefile` | `extmux-test` target |
| `docs/W53-EXT-AUTH-TX.md` | contract, root cause, fix |
| `patches/README.md`, `docs/BUILD.md`, `docs/OPEN-PROBLEMS.md` | series table, counts, F13 |
