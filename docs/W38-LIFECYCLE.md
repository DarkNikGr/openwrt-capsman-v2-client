# W38 — VAP lifecycle on the extmux tree

Status: integrated on top of `5364e76` (W36 MLME + the per-VAP channel
configuration).  The manager-only creation path in `native/src/vap.inc` and the
extmux relay are unchanged; the lifecycle now releases everything the CAP
allocated for a manager-provisioned VAP.

## What a `0x600c` now does

`RX 0x600c port=(phy<<8)|id` (body `0x47`, then a live `0x08` BSSID, then the
header port):

```
dp_vap_close()          AF_PACKET readers / AP_VLANs, STA registry
vap_relay_close()       extmux_del_vap(port) or legacy ext-auth socket + unlink
dc_forget_vap()         datachan key/cookie
vchan_clear(port)       channel state
pmap_del(port)          per-BSS netdev aliases
vap_teardown()
    vap_stop_hostapd()  pid file -> SIGTERM -> 2 s -> SIGKILL -> /proc argv scan
    vap_remove_files()  /var/run/vap-<if>.pid, /tmp/vap-<if>.conf
    vap_netdev_delete_name()   only if own_netdev; wait for sysfs to disappear
vapid_release_slot()    only after the netdev is gone
mgmt_vap_del(phy)       monitor VIF only when the last VAP on the radio is gone
TX 0xe00c
```

`own_netdev` is set when capagent created `phyN-apM`, or when it adopted a
`phyN-apM` in its own name space with no legacy `wifi-iface`.  A netdev that
netifd owns is never deleted.

## Create and start

* `0x500b` allocates a MAC-stable vapid, refuses with `-1` when all 16 slots on
  a radio are taken (the old code returned slot 0), enforces a total cap
  (`CAPAGENT_MAX_VAPS`, default 64), is idempotent for a live MAC and tears
  down a stale mapping first.
* `0x6016` restarts a stale hostapd instead of stacking a second one, waits for
  the pid file, keeps the W36 in-process MLME path and the extmux registration.

## Watchdog (every 5 s, `--vap-auto`)

Reaps orphan `hostapd` children, pid/conf files, `ext-auth-*` sockets and
`phyN-apM` netdevs that no live VAP and no legacy UCI BSS claims.

## `0xd00b` contract (W1)

* `0x49` is the raw ifname (not a nested `0x9e` blob).
* `0x47` is the proposed id; `0x48` the real ifindex.
* `0x61` is the real MHz, omitted outside 2000..7125.
* `0x0a` advertises every supported (frequency, width, band) combination;
  `0xb7` carries the union of the MHz and channel-number sets.

## Reconnect

`cap_reset_session()` now closes **and unlinks** the legacy ext-auth sockets.
A `0x600c` for a VAP that lost its registry entry (reconnect between create and
destroy) still reaps the hostapd/pid/conf/netdev when `/tmp/vap-<if>.conf`
proves the CAP created it.

## Verification

* host hwsim harness (real hostapd, fake CAPsMAN peer): 5/5 create/start/destroy
  cycles, duplicate create, VAP cap, post-cycle slot reuse and the watchdog
  pass (`harness/evidence/cycle-test.log`).
* live Xiaomi: 3 full manager-only cycles of 8 VAPs, see `REPORT.md`.
