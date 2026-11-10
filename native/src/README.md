# capagent source layout

`native/capagent.c` is a small entry unit: constants, shared structs, then one
`#include` per module. The `.inc` modules are compiled as a **single
translation unit**, so the order below is the dependency order.
`src/extmux.c` is the one separate compilation unit: it is deliberately free of
mbedTLS and nl80211 so it can also be unit-tested on a host.

| Module | Contents |
|---|---|
| `util.inc` | TLV/hex helpers, sysfs readers, join (`0x4029`) and NEWPHY (`0x001d`) builders |
| `nl80211.inc` | generic netlink: control-port EAPOL, mgmt-frame TX, `NEW_KEY`/`SET_KEY`, station authorize, validated port→ifindex map |
| `policy.inc` | W33 API: session mode, per-port authority, deterministic AP-only MAC→netdev lookup, `--selftest-policy` |
| `netifd_status.inc` | **W34**: dependency-free parser for `ubus call network.wireless status` |
| `ownership.inc` | **W34**: single port→ifname/ifindex/pid/owner table, journal, netifd reconcile, `0x600c` delete |
| `apply.inc` | `0x77`/M2 config parse and UCI apply (argv, no shell); refused in legacy mode |
| `datapath.inc` | split-MAC VAP registry, station map, AF_PACKET bridge, VLAN policy |
| `datachan.inc` | c2 datachan: AES-CCM/plain (`a2`), keepalive, per-VAP keys, `0x402b` rekey |
| `channels.inc` | `0x000a` channel descriptors, `0x00b7` set, vapid allocation/gc, `0xd00b` reply |
| `mgmt.inc` | EAPOL/key descriptors, `0x2018`/`0x2019` relay, monitor fallback, extmux glue |
| `mlme.inc` | W36: in-CAP MLME for one VAP — local Auth, `START_AP` from the manager's SSID/IEs, `0x6019` AssocResp, control-port EAPOL, no hostapd |
| `discovery.inc` | manager discovery, bounded TLS connect |
| `stats.inc` | `0x200e` signal + `0x2015` counters/rates |
| `vap.inc` | deterministic VAP resolution, hostapd start/stop, `0x600c` destroy (`0x500b`/`0x6016`) |
| `lab.inc` | `CAPAGENT_LAB`: hwsim AP, mgmt relay, test injection |
| `main.inc` | run loop, per-attempt discovery/session reset, options, `main` |
| `extmux.c` / `extmux.h` | per-BSS external-RSN relay: sessions keyed by (port, MAC), 4-way deadline/retry, ctrl reply checking, journal/resync |

## Ownership invariant (W33 API, W34 model)

`policy.inc` keeps the W33 API (`wl_legacy()`, `wl_own()`,
`vap_should_start_bss()`, `vap_port_alias_ok()`, `--check-wireless`,
`--selftest-policy`) but the production decision now comes from
`ubus call network.wireless status` parsed by `netifd_status.inc`, reconciled
into the one table in `ownership.inc` (journal:
`/var/run/capagent-vaps.state`, `--vap-state FILE`).

| Netdev state | Owner | capagent may |
|---|---|---|
| in `network.wireless status` | `netifd` | observe only; never create/delete/start/stop/install keys |
| in the journal / our `vap-*.pid` | `capagent` | create, start hostapd, install keys, tear down on `0x600c` |
| exists, neither | `foreign` | never touch; manager VAP gets an alternate name |
| manager asked, probe unusable | `pending` | retry when the probe recovers |

`wl_legacy()` remains the coarse "netifd owns at least one wireless ifname"
predicate for global UCI/apply decisions.  Per-netdev effects use
`wl_port_managed()` / `own_claim()`.  `--wireless-owner legacy` forces the old
fully read-only contract.  `--check-wireless` is read-only (journal + ubus
probe, no reconcile/cleanup).

## Build

With an OpenWrt SDK tree (mt7621, mbedTLS in staging_dir):

```sh
make SDK=/path/to/openwrt-sdk
make SDK=/path/to/openwrt-sdk check     # crypto + policy + W34 parser/state-machine tests under qemu-mipsel
```

With a standalone toolchain + mbedTLS source prefix:

```sh
make TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
     MBEDTLS=/path/to/mbedtls-3.6.2
```

The lab build adds `-DCAPAGENT_LAB` (hwsim AP, mgmt relay, synthetic
`--inject-assoc`); the production build leaves those out.

Split-MAC options: `--datapath-bridge`, `--vap-mtu`, `--bcast`,
`--mgmt-relay`, `--mgmt-source auto|nl80211|monitor|off`, `--ext-auth-dir`,
`--ext-ctrl-dir`, `--state-file`, `--fourway-timeout`, `--m1-retry`.

In-CAP MLME (W36): `--mlme --mlme-port 0x0000` replaces hostapd for that one
VAP.  The CAP builds the beacon from `0x6016` (SSID + manager IE blob),
answers open Auth itself, relays Auth/AssocReq as `0x2018`, transmits the
manager's `0x6019`/`0x2019`, and relays EAPOL over the control port.  The
manager remains the RSN authenticator and supplies `0x201f` keys.
`--mgmt-source monitor` is the hostapd-coexistence path (U3): a passive
monitor VIF relays the real Auth/AssocReq as `0x2018`, because cfg80211
delivers each mgmt frame to only one `REGISTER_FRAME` owner.

## Debug

Set `CAPAGENT_DEBUG=1` to enable the verbose per-second station log and the
`/tmp/capagent-*.bin` / `/tmp/capagent-msgs.log` dumps (mode 0600).
Production runs without it: no traffic/key dumps and no per-station log spam.
