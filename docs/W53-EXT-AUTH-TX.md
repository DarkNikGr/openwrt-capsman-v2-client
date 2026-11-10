# W53 — the `EXT_AUTH_TX` contract and why M1 never reached the station

Work dir: `/tmp/opencode/work-W53/`
Branch: `w53-ext-auth-tx`
Base: `origin/main` @ `f6cd5c8`

## 1. Symptom

Manager-only run on the live Xiaomi 4A: the manager sends `0x201c` (M1), the
CAP queues it, and the log repeats

```
RX 0x201c eapol-tx port=0x0001 len=135
EXTMUX: extmux: TX port=0x0001 32:60:f4:d2:af:d6 len=121 class=1 enc=0
EXTMUX: extmux: EXT_AUTH_TX FAIL port=0x0001 32:60:f4:d2:af:d6
```

with no `0x201b` from the station, no `0x201f` pairwise key, no DHCP and no
ping.  The pre-extmux path (`nl_control_port_tx` on `0x201c`) delivered the
same M1 to the same station.

## 2. The hostapd-side contract

`patches/999-external-rsn-auth.patch` adds, in `hostapd/ctrl_iface.c`:

```
EXT_AUTH_TX <sta-mac> <eapol-hex> [encrypt=1]
EXT_AUTH_AUTHORIZE <sta-mac>
```

Both are read from the **hostapd control interface** — the same UNIX
`SOCK_DGRAM` sockets under `ctrl_interface=` that `hostapd_cli` uses
(`/var/run/hostapd/<ifname>`), *not* from the ext-auth event socket.  The
ext-auth socket is one-way: hostapd → CAP (`ASSOC`, `EAPOL`, `DISCONNECT`).
The reply is `OK\n` on success and `FAIL\n` otherwise, because
`hostapd_ctrl_iface_receive_process()` pre-fills `reply` with `OK\n` and only
overrides it when a handler returns an error.

The handler computes the frame length as "the rest of the line":

```c
pos2 = os_strchr(pos, ' ');
len = pos2 ? (size_t)(pos2 - pos) : os_strlen(pos);
if (len & 1) return -1;          /* odd hex -> FAIL, nothing sent */
len /= 2;
...
ret = hostapd_wpa_auth_send_eapol(hapd, dst, buf, len, encrypt);
return ret;                      /* call site: if (ret) reply_len = -1; */
```

Two independent defects:

1. **Trailing newline.** `hostapd_ctrl_iface_receive()` does *not* strip the
   wire newline before dispatch (`PING\n` would not match either; commands are
   newline-free in `hostapd_cli`).  extmux built its command with `"\n"`, so
   the hex string was `2*len + 1` characters → odd → `return -1` **before**
   `hostapd_wpa_auth_send_eapol()` was ever called.  That is exactly the
   observed "M1 never reaches the STA".
2. **Success test.** `wpa_driver_nl80211_hapd_send_eapol()` returns the num-
   ber of bytes sent when it uses the `PF_PACKET` EAPOL socket (AP mode
   without control-port TX status), i.e. a **positive** value on success.  The
   call site treated any non-zero return as failure, so even a delivered frame
   answered `FAIL`.

`EXT_AUTH_AUTHORIZE` uses `hwaddr_aton()`, which stops after 17 characters and
therefore tolerated the newline; it was never the blocker, but it is retried
forever today because `txn_start()` reset `txn_retries` on every retry.

## 3. Fix

### capagent (works with the hostapd binaries already deployed)

`native/src/extmux.c`:

* control commands are sent **without** the trailing newline, exactly like
  `hostapd_cli` builds them;
* the first `EXT_AUTH_TX` reply that is not `OK` marks the BSS
  `direct_tx` and logs **one** line:
  `extmux: <if>: hostapd rejected EXT_AUTH_TX (FAIL); this BSS now uses
  direct nl80211 control-port TX`.  Every later frame on that BSS goes
  through the old `nl_control_port_tx()` path — no per-frame log, no
  per-frame retry;
* the rejected frame is **not** blind-reinjected: an old hostapd can transmit
  it and still answer `FAIL` (defect 2), and a duplicate M1 confuses the
  manager.  The manager's next `0x201c` (or the 3 s M1 retry) already uses
  the direct path;
* if `EXT_AUTH_AUTHORIZE` still fails after its retries (or never answers),
  the station is authorized with `NL80211_CMD_SET_STATION` +
  `NL80211_STA_FLAG_AUTHORIZED` (`on_direct_authz`), once per BSS, so the
  data path opens even on a hostapd build without the command;
* `txn_start()` no longer resets `txn_retries`; the authorize retry counter
  now actually terminates.

`native/src/mgmt.inc`: wire `xm_on_direct_authz()` into the extmux callbacks.

### hostapd (`patches/9990-external-rsn-tx-parse.patch`)

For a *new* build the parser is fixed properly: CR/LF/space/tab at the end of
the hex field are trimmed, and only a negative driver return is an error.  The
patch is part of the normal series (`999` → `9990` → `9997` → `9998` →
`9999`), so a rebuilt `wpad` needs neither the capagent fallback nor a retry.

### Capability-driven, not build-fatal

The CAP does not need to know which hostapd it talks to.  A good binary
answers `OK` and stays on the control path; a bad one answers `FAIL` once and
the BSS switches to the direct path.  An unpatched wpad (no
`external_rsn_auth` at all) never starts a VAP with that option, so nothing
changes for it.

## 4. Tests

`native/tests/test_extmux.c` (host, `make -C native extmux-test`) uses a fake
hostapd control socket:

1. the command on the wire is `EXT_AUTH_TX <mac> <hex>` with no trailing
   newline; `OK` keeps the control path and produces no extra log;
2. a daemon that answers `FAIL` switches the BSS to direct TX after exactly
   one frame, logs exactly one line, and sends every later frame direct
   without talking to the daemon again;
3. a daemon that cannot `EXT_AUTH_AUTHORIZE` is retried twice and then the
   station is authorized through `on_direct_authz`; no deauth, session
   `AUTHORIZED`.

`make -C native check` still passes: crypto KAT, policy 27/27, W34 ownership.

## 5. Live proof

See `REPORT.md` in the work dir for the full transcript (`0x201c` → STA,
`0x201b` → manager, `0x201f` PAIRWISE, `authorized: yes`, DHCP, ping) and the
restore evidence.
