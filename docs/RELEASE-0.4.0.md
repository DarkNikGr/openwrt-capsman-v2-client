# v0.4.0 — manager-driven VAPs, no local wireless config

Userspace CAP for the **official RouterOS 7.25.1 CAPsMAN v2** manager.

This release is about the CAP side of zero-config provisioning: the manager
asks for VAPs, and the CAP now builds them without a local `wifi-iface`, and
without ever receiving the passphrase. It is **not** the finished goal — see
"Still open" below.

## Highlights

* **8/8 VAPs from the manager alone.** With `/etc/config/wireless` reduced to
  two `wifi-device` sections and **no `wifi-iface`**, the manager sends
  `0x500b` for both radios and `0x6016` for ports `0x0000`, `0x0100`,
  `0x0001`–`0x0003`, `0x0101`–`0x0103`, plus 6 `0x201f` key installs. capagent
  accepts the create, creates the AP netdev and answers `0xd00b` with a real
  `ifindex`.
* **One hostapd per VAP, no PSK.** From `0x6016` (SSID + RSN IE + channel)
  capagent writes `/tmp/vap-<ifname>.conf` and starts hostapd with
  `external_rsn_auth=1` and `ext_auth_socket=/var/run/hostapd/ext-auth-<ifname>`.
  The generated config contains no `wpa_passphrase`; the manager is the RSN
  authenticator.
* **Exact RSN IE.** New `docs/patches/9997-external-rsn-ie.patch` adds
  `external_rsn_ie=<hex>` to hostapd, so the beacon/assoc/EAPOL element is the
  manager's **byte-for-byte** (28 B, `caps=0x0080` + BIP-CMAC) instead of a
  regenerated 22 B element (`caps=0x008c`). capagent probes the installed
  `wpad` and uses the option automatically.
* **Multi-VAP EAPOL relay.** Per-BSS `AF_UNIX` sockets, sessions keyed by
  `(port, STA MAC)`, `0x201c` via hostapd `EXT_AUTH_TX`, `0x201f` PTK
  completion with `EXT_AUTH_AUTHORIZE`, restart journal. Proven on the real
  RB1100: STA M2 → `0x201b` → manager → `0x201c` M3.
* **`0x2018` / `0x2019` corrections.** `0x2018` body is `0x3e` (raw frame) +
  `0x0a` (VAP frequency) + optional `0x3f` RSSI in dBm; `0x2019` is
  subtype-filtered (Auth responses discarded, Deauth/Action transmitted);
  `0x6019` templates are discarded rather than replayed.
* **Boot/reconnect hardening.** Discovery runs on every attempt, so a CAP that
  starts before the WAN lease still joins; `capagent-preflight` waits for
  phy → netifd → carrier + IPv4 → hostapd socket and never blocks `rcS`.
* **Build hygiene.** Zero compiler warnings on mipsel and aarch64; the aarch64
  script now includes `extmux.h` and compiles `extmux.c` (without them it could
  not build at all); `--version` reports `0.4.0`; dead code removed.

## Validation

* mipsel clean build with the OpenWrt 24.10 SDK and mbedTLS 3.6.7, 0 warnings.
* aarch64 clean build (musl cross + mbedTLS), 0 warnings.
* `--crypto-selftest` passes under qemu-mipsel and qemu-aarch64.
* `capagent --version` → `0.4.0` on both binaries.
* Live zero-config run on the Xiaomi Mi Router 4A (OpenWrt 24.10) against
  RB1100AHx4 / RouterOS 7.25.1: 8/8 netdevs created, 8 hostapd instances, four
  2.4 GHz BSSes beaconing the manager's SSIDs, EAPOL relay over TLS.
* Hostapd `external_rsn_ie`: `RSN: Own IEs` equals the manager's M3 element
  byte-for-byte; option parse verified on the mipsel target binary under qemu.
* Zero-touch image: 55/55 static content checks (client + certificate + CA +
  patched `wpad` in ROM, no SSH/firewall/DHCP server, reset handler present).

## Still open (do not overclaim)

* **No hardware/factory-reset proof.** The zero-touch image has never been
  flashed. Boot, physical factory reset, rejoin and 8/8 re-provision are
  unverified on the device.
* **5 GHz hostapd start** fails on the MT7612E in this tree (VHT80 centre
  frequency / HT40 / regulatory domain). 2.4 GHz works.
* **VAP lifecycle:** `0x600c` does not stop hostapd / delete the netdev /
  release the vapid, so repeated creates for one port can duplicate or wedge.
* **Station-side M3 acceptance** with the patched `wpad` has not been observed
  on real hardware yet.
* The goal (a CAP that behaves like genuine MikroTik hardware after a factory
  reset, with no local configuration and no SSH) is **not met**.

See `docs/MANAGER-ONLY.md` for the full state and the reproduction steps, and
`docs/OPEN-PROBLEMS.md` for the tracked blockers.

## Install

```sh
curl -LO https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases/download/v0.4.0/capagent-mipsel-bundle.tar.gz
scp capagent-mipsel-bundle.tar.gz root@10.0.0.2:/root/
ssh root@10.0.0.2
mkdir -p /root/cap-bundle && tar -C /root/cap-bundle -xzf /root/capagent-mipsel-bundle.tar.gz
cd /root/cap-bundle && MANAGER=10.0.0.1 ./install.sh
```

`install.sh` selects the binary by `uname -m`. Certificates are expected at
`/etc/cap/client.pem` and `/etc/cap/client.key`. No configuration format
changed: an existing `/etc/cap/capagent.conf` keeps working.

For manager-driven BSS creation the CAP needs a `wpad` built with
`external_rsn_auth` and (for exact RSN IEs) `external_rsn_ie`; without the
latter capagent falls back to hostapd's generated IE.

## Assets

| Asset | SHA256 |
|---|---|
| `capagent-mipsel` | `6905d44ea86b880a6664e7f6842a1a7ee58c21e0fc90dbf60fa86b7ca30394fa` |
| `capagent-aarch64` | `dc294d0e9414b548a6ebc95a3da974be65ca17c9d8b511b4ff2df2a0996985f7` |
| `capagent-mipsel-bundle.tar.gz` | `96b2191b6567a6a7678ff06d4906f5215e1c36f0ee4989113de15259576372e4` |
| `capagent-aarch64-bundle.tar.gz` | `b9e0c8411f4f650fe2b5df6abfa23f54e241d63d853746feb27bd255e90cb193` |

`SHA256SUMS` is attached as well.
