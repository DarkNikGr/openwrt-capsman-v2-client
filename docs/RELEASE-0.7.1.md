# v0.7.1 — fallback cleanup

Small cleanup release on v0.7.0. The live 5 GHz dynamic provisioning fix is
unchanged; the obsolete fallback switches around it are gone.

## Removed

* `SLAVES_STATIC` / `--slaves-static` — it was accepted for WinBox parity but
  never used. Static manager interfaces need no CAP option; they are simply a
  manager-side layout.
* `CAPAGENT_5G_PER_VAP` — the ag37 prototype alias.
* `CAPAGENT_PER_VAP=yes|no` — forcing or disabling per-VAP is no longer
  exposed. The CAP always uses one hostapd per BSS on any phy with a 5/6 GHz
  row, and the single multi-BSS hostapd on 2.4 GHz.
* Static `2E/22/26:...:83` 5 GHz fallback documentation. The supported path is
  RouterOS dynamic provisioning (`2A:...:85/86/87`) with the patched
  `mt76x02-lib.ko` and the `9999k` hostapd tolerance.
* `PER_VAP` / `SLAVES_STATIC` lines from the shipped `capagent.conf` and the
  init script.

## Unchanged

* The mt76x02 patch (sequential BSS slots + RX drop fix) and the hostapd
  `9999k` no-ACK tolerance.
* `KEEP_SEC=yes`, 2.4 GHz single multi-BSS hostapd, one hostapd per 5/6 GHz
  VAP.
* 6 GHz: one radio + three dynamic provisioning virtuals, 160 MHz, SAE/PMF.

## Verified

`make check` passes (policy 27/27, crypto selftest, version 0.7.1). The
reference Xiaomi remains at 8 SSIDs with all four 5 GHz dynamic slaves
`authorized: yes` after a cold reboot. See
[`RELEASE-0.7.0.md`](RELEASE-0.7.0.md) for the driver/hostapd evidence.

* image: `5feb77b57c4dd97954855f5c1bd7e70853a39f2297c532cbce168486ff035baf`
  (7,537,762 B)
* `capagent-mipsel`:
  `88477ceec77379b551ca8bf8cb2080950fd0887291a74fe1834622179b63df16`
* `capagent-aarch64`:
  `6e6213949bf96121e78effa2e05dbfa103212e513aa140299615fead122a3aa1`
* `mt76x02-lib.ko`:
  `8f3aa3a8b9c3b94593cb9842da378f783ccc87eba4f5ff610b340b6f4c814e70`
* `wpad` md5 `046c9a0470373a481649753f4ae87a51` (contains `9999k`)
