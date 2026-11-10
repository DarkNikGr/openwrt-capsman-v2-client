# W27 — integration of W8 (multi-VAP relay), W6 (0x2018/0x2019), W14 (boot/reconnect)

Base: `3fbcaa6` (which already carries the earlier W14 re-resolve commit
`58e8f8f` and the exact-RSN-IE change `3fbcaa6`).  This series supersedes the
`58e8f8f` "re-resolve every third retry" loop: discovery now runs on every
attempt inside `run_once()`.
This tree is manager-only: no local `wifi-iface` is required or created from
UCI; `0x500b` creates the AP netdev and `0x6016` starts its hostapd BSS.

## What changed

### W8 — multi-VAP external-RSN relay

* `native/src/extmux.{c,h}` imported from `work-W8`. It is a separate
  translation unit with no mbedTLS/nl80211 dependency, so the same core is
  unit-testable on a host (61 checks pass).
* One `AF_UNIX SOCK_DGRAM` per BSS: `<ext-auth-dir>/ext-auth-<ifname>`.
  The socket identity is the VAP; the port map is `(phy << 8) | vapid`.
* Sessions are keyed by `(port, STA MAC)`, not MAC alone. The same station on
  two VAPs has two independent 4-ways.
* `0x201c` is delivered through hostapd `EXT_AUTH_TX` with a checked reply;
  direct nl80211 control-port injection is only the fallback.
* `0x201f` PTK completion goes through `extmux_ptk_installed()`, which sends
  `EXT_AUTH_AUTHORIZE`, checks `OK`/`FAIL`, retries twice, and deauths the STA
  when hostapd refuses.
* CAP-side 4-way deadline (default 10 s), M1 retry (default 3 s, twice),
  1 s ctrl transaction timeout. Timeout = deauth reason 15 + `0x201a` DELSTA.
* Restart/reconnect: a key-free journal (`--state-file`) plus `iw station
  dump` resync. Authorized stations are adopted; the rest are forced to
  reauthenticate.
* `0x201f` class (`0x5a`/`0x5b`) is now resolved per key descriptor. The
  message layout places the class tag *after* the descriptor, so the parser
  accepts both orders; a combined GTK+IGTK message no longer classifies one
  key by the other's class.

### W6 — `0x2018` and `0x2019`

* `0x2018` body is exactly `0x3e` (raw frame, no FCS) + `0x0a` (nested `0x0b`
  = the VAP's provisioned frequency) + optional `0x3f`.
* `0x3f` is now **RSSI in dBm** (`i32`), not frequency. It is omitted when the
  driver did not report a signal. Sources: `NL80211_ATTR_RX_SIGNAL_DBM` on the
  mlme path, radiotap dBm-antenna-signal on the monitor path.
* No `0x08`/`0x47` tags are emitted in `0x2018`.
* Frames whose `addr1 != addr3` are dropped before sending, and no VAP no
  longer falls back to a fake 2437 MHz channel.
* Radiotap FCS-present flag is honoured (4 trailing bytes stripped).
* `0x2019` is subtype-filtered: subtype 11 (Auth response) is discarded and
  acked because hostapd answered on air; subtype 12 (Deauth) and 13 (Action)
  are transmitted with `NL80211_CMD_FRAME` and acked. If the direct TX fails
  for a Deauth, `DEAUTHENTICATE` is sent through hostapd instead.
* `0x6019` remains discarded: it is a template (capab 0, AID 0, no RSN IE).

### W14 — boot race and reconnect

* Discovery moved from `main()` into `run_once()`, so it runs on **every**
  attempt. `--manager` is kept separately as `manager_spec`; `auto` is
  re-resolved each time. The first attempt can fail before the WAN lease and
  the next attempt still finds the manager.
* `cap_reset_session()` runs at the start of every connection: it drops the
  old extmux instance, VAP registry, port map, channel map and vapid
  allocation. Manager-derived state never leaks across a reconnect; kernel
  objects (netdevs, hostapd, installed keys) are left alone and re-adopted by
  `cap_extmux_restore()` + resync.
* Bounded TCP connect (5 s) and a 15 s TLS handshake deadline; socket
  read/write timeouts are set so a black-holed manager cannot stall the loop.
* `vap_provision()` no longer spawns a second hostapd when the pid file shows
  a live instance (agent restart / manager reconnect).
* `deploy/capagent-preflight` waits for phy → ubus/netifd → carrier + IPv4
  lease → hostapd global socket, then execs capagent. It never blocks rcS and
  still starts the agent on timeout. `capagent.init` keeps `START=95`, uses
  the preflight when present, adds `term_timeout 10` and an interface trigger.

## Build

```sh
cd native
make SDK=/tmp/opencode/work-V21/sdk            # static mipsel binary
make SDK=/tmp/opencode/work-V21/sdk check      # --crypto-selftest under qemu
```

Toolchain used: `staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin`,
mbedTLS 3.6.7 from `staging_dir/target-mipsel_24kc_musl/usr`.

## Verification in this work dir

* clean build, no new warnings;
* `--crypto-selftest` passes under `qemu-mipsel`;
* the imported extmux core passes its 61-check host unit test;
* `-DCAPAGENT_LAB` still compiles.

Not verified here (left to the live track): hostapd external-RSN behaviour,
real station 4-way, PMF/IGTK, RouterOS interop. No device writes were made.
