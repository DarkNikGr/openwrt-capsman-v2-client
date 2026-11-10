# W45 — session recovery, liveness and certificate safety

This change ports the W19 recovery reference (`fixes/w19-recovery.patch`,
base `8ac4046`) onto the current manager-only tree, preserving the W33/W34
netdev ownership contract.

## What a new manager session means

The manager discards every `Peer` when the TLS session dies. The kernel and
hostapd keep the old association and PTK, so a station that is not reset stays
invisible to the new manager session: no registration row, no accounting,
until it roams. `capagent` now treats one TLS session as one Peer lifetime:

* `cap_reset_session()` clears session state only: station map, channel map,
  datachan keys/cookies, VLAN map, dedup cache and per-VAP key/replay fields.
  Netdev identity (`used`/`ifname`/`ifindex`/`bssid`/`we_created`) and the
  MAC→vapid allocation survive, so the manager's fresh `0x500b` still lands on
  the same BSS.
* Once per session, after `0xc029` (with the first `0x6016` as a fallback),
  `session_deauth()` deletes every station on every **capagent-owned** BSS with
  `NL80211_CMD_DEL_STATION` (reason 3) and asks hostapd to deauthenticate it.
  The station retries Auth/Assoc, the CAP relays `0x2018`, and the manager
  builds a new Peer.

### Ownership invariant

`session_deauth()` calls `own_managed_strict(port)` and only touches rows the
W34 ownership table says are `CAPAGENT`. A `NETIFD`, `FOREIGN` or `PENDING`
row is counted in the recovery log and left alone. The `0x600c`/`0x6016`
paths keep their existing ownership checks.

## Liveness

| mechanism | value | effect |
|---|---|---|
| frame read deadline | 5 s per complete header/body | a 13-of-14-byte frame can no longer wedge `read_exact()` |
| manager silence | 20 s (configurable) | no protocol traffic at all → close and reconnect |
| watchdog | 60 s without loop progress (`SIGALRM`) | `_exit(70)` so procd `respawn 3600 5 0` restarts a hung agent |
| heartbeat | optional `--heartbeat FILE` | progress timestamp for an external supervisor |
| reconnect | 1→60 s exponential + 0–1 s jitter | no 5 s retry storm; reset after a successful join |
| discovery | re-run on every attempt | `MANAGER=auto` never caches an empty answer |

## Certificate safety

`connect_tls()` now fails closed:

* `--dont-verify-certificate` is the only way to use `VERIFY_NONE`;
* a configured CA that is missing, unreadable or invalid is a fatal error
  (it used to silently become `VERIFY_NONE` while printing `verify=ca`);
* no CA and no explicit opt-out is also fatal;
* an expired or not-yet-valid client certificate is refused instead of being
  presented silently.

The deploy script passes `--ca-cert` whenever `CA_CERT` is configured, even if
the file is temporarily missing, and the procd service passes
`--watchdog-secs` and a `wireless` reload trigger.

## Options

```
--silence-timeout SEC   manager silence before reconnect (default 20, 0 off)
--watchdog-secs SEC     stall budget before exit(70) (default 60, 0 off)
--heartbeat FILE        progress timestamp
--no-extmux             ext-auth socket + direct nl80211 EAPOL TX; compatibility
                        path for hostapd builds that reject EXT_AUTH_TX
```

## Lab evidence

CHR 7.25.1 + `mac80211_hwsim` + patched hostapd + real `wpa_supplicant`,
`--no-extmux` (the v18hostapd build in the W19 lab rejects `EXT_AUTH_TX`; the
default extmux relay is unchanged). Recovery scenarios:

| scenario | result |
|---|---|
| manager reboot | PASS (rejoin, VAP/config, STA re-assoc, reg row) |
| CAP crash / respawn | PASS (STA re-assoc, reg row) |
| WAN 25 s blackhole | PASS (detected, rejoin, reg row) |
| WAN 5 s | PASS (no spurious reconnect) |
| boot with no manager | PASS (re-discovery, join) |
| partial frame | PASS (deadline, reconnect) |
| missing CA | PASS (fail closed) |
| expired client cert | refused (no renewal path yet) |
| `0x402b` rekey | PASS (unchanged) |

Still open (unchanged from W19): applying `0x6016` SSID/channel/RSN,
`0x600c` teardown, `0x6017` rejoin, CA rotation/enrolment.
