# capagent source layout

`native/capagent.c` is a small entry unit: constants, shared structs, then one
`#include` per module. The `.inc` modules are compiled as a **single
translation unit**, so the order below is the dependency order.
`src/extmux.c` is the one separate compilation unit: it is deliberately free of
mbedTLS and nl80211 so it can also be unit-tested on a host.

| Module | Contents |
|---|---|
| `util.inc` | TLV/hex helpers, sysfs readers, join (`0x4029`) and NEWPHY (`0x001d`) builders |
| `nl80211.inc` | generic netlink: control-port EAPOL, mgmt-frame TX, `NEW_KEY`/`SET_KEY`, station authorize |
| `apply.inc` | `0x77`/M2 config parse and UCI apply (argv, no shell) |
| `datapath.inc` | split-MAC VAP registry, station map, AF_PACKET bridge, VLAN policy |
| `datachan.inc` | c2 datachan: AES-CCM/plain (`a2`), keepalive, per-VAP keys, `0x402b` rekey |
| `channels.inc` | `0x000a` channel descriptors, `0x00b7` set, vapid allocation |
| `mgmt.inc` | EAPOL/key descriptors, `0x2018`/`0x2019` relay, monitor fallback, extmux glue |
| `discovery.inc` | manager discovery, bounded TLS connect |
| `stats.inc` | `0x200e` signal + `0x2015` counters/rates |
| `vap.inc` | manager-driven BSS creation and hostapd start (`0x500b`/`0x6016`) |
| `lab.inc` | `CAPAGENT_LAB`: hwsim AP, mgmt relay, test injection |
| `main.inc` | run loop, per-attempt discovery/session reset, options, `main` |
| `extmux.c` / `extmux.h` | per-BSS external-RSN relay: sessions keyed by (port, MAC), 4-way deadline/retry, ctrl reply checking, journal/resync |

## Build

With an OpenWrt SDK tree (mt7621, mbedTLS in staging_dir):

```sh
make SDK=/path/to/openwrt-sdk
make SDK=/path/to/openwrt-sdk check     # runs --crypto-selftest under qemu-mipsel
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
`--mgmt-source monitor` is the hostapd-coexistence path (U3): a passive
monitor VIF relays the real Auth/AssocReq as `0x2018`, because cfg80211
delivers each mgmt frame to only one `REGISTER_FRAME` owner.

## Debug

Set `CAPAGENT_DEBUG=1` to enable the verbose per-second station log and the
`/tmp/capagent-*.bin` / `/tmp/capagent-msgs.log` dumps (mode 0600).
Production runs without it: no traffic/key dumps and no per-station log spam.
