# capagent source layout

`native/capagent.c` is a small entry unit: constants, shared structs, then one
`#include` per module. Everything is still compiled as a **single translation
unit**, so the order below is the dependency order and no extra build flags are
needed — `make` compiles `capagent.c` exactly as before.

| Module | Contents |
|---|---|
| `util.inc` | TLV/hex helpers, sysfs readers, join (`0x4029`) and NEWPHY (`0x001d`) builders |
| `nl80211.inc` | generic netlink: control-port EAPOL, `NEW_KEY`/`SET_KEY`, station authorize |
| `apply.inc` | `0x77`/M2 config parse and UCI apply (argv, no shell) |
| `datapath.inc` | split-MAC VAP registry, station map, AF_PACKET bridge, VLAN policy |
| `datachan.inc` | c2 datachan: AES-CCM/plain (`a2`), keepalive, per-VAP keys, `0x402b` rekey |
| `channels.inc` | `0x000a` channel descriptors, `0x00b7` set, vapid allocation |
| `mgmt.inc` | EAPOL/key descriptors, `0x2018` relay, monitor fallback, ext-auth |
| `discovery.inc` | manager discovery, MAC/interface resolution |
| `stats.inc` | `0x200e` signal + `0x2015` counters/rates |
| `lab.inc` | `CAPAGENT_LAB`: hwsim AP, mgmt relay, test injection |
| `main.inc` | run loop, options, `main` |

## Build

```sh
TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
MBEDTLS=/path/to/mbedtls-3.6.2 \
../scripts/build-mipsel.sh
```

The lab build adds `-DCAPAGENT_LAB` (hwsim AP, mgmt relay, synthetic
`--inject-assoc`); the production build leaves those out.

Split-MAC options: `--datapath-bridge`, `--vap-mtu`, `--bcast`,
`--mgmt-relay`, `--mgmt-source auto|nl80211|monitor|off`, `--ext-auth-dir`.
`--mgmt-source monitor` is the hostapd-coexistence path (U3): a passive
monitor VIF relays the real Auth/AssocReq as `0x2018`, because cfg80211
delivers each mgmt frame to only one `REGISTER_FRAME` owner.

## Debug

Set `CAPAGENT_DEBUG=1` to enable the verbose per-second station log and the
`/tmp/capagent-*.bin` / `/tmp/capagent-msgs.log` dumps (mode 0600).
Production runs without it: no traffic/key dumps and no per-station log spam.
