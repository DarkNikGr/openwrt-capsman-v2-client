# MikroTik CAPsMAN v2 client for OpenWrt

Turn a non-MikroTik OpenWrt AP into a **CAP of the official RouterOS
CAPsMAN v2 manager** — no extra service on the manager, no SSH/REST from the
CAP, no static SSID/key/VLAN file as the source of truth.

Reference hardware: **Xiaomi Mi Router 4A Gigabit Edition** (ramips/mt7621,
OpenWrt 24.10, MediaTek MT7603E + MT7612E), managed by an
**RB1100AHx4 / RouterOS 7.25.1**.

> **Status:** the CAP protocol path works end-to-end. The official manager
> sees the CAP as `state="Ok"`, selects channels, and creates/binds the master
> and virtual interfaces (all active). It then pushes the configuration over
> TLS (`0x6016` SSID/RSN/channel, `0x500b` VLAN, `0x201f` security). Applying
> the pushed SSID/key/VLAN to OpenWrt UCI and the `0x6027` traffic/status
> report are the last two items on the roadmap — see [Status](#status).

---

## Why

RouterOS CAPsMAN v2 only accepts CAPs that speak its private control protocol
(TLS 5246) and drive the radio through RouterOS' own HAL. This project
re-implements the CAP side in C on OpenWrt so an inexpensive mt76 AP can be
provisioned by the same manager as MikroTik hardware.

* single static binary (~930 KB), **no Python, no runtime dependencies**
* the manager sees the real device (identity, board-name, radio MACs, serial)
* dynamic channel selection by the manager (2.4 GHz 20 MHz, 5 GHz 80 MHz)
* VLAN per SSID delivered in the create message (`0x7d`)
* config push (`0x6016`) with SSID, RSN IE and channel

## Status

| Capability | State |
|---|---|
| TLS join (`0x4029` → `0xc029`), certificate enrollment | ✅ |
| NEWPHY capabilities (`0x001d`) | ✅ |
| VAP create (`0x500b` → `0xd00b`), destroy (`0x600c`) | ✅ |
| Unique vapid per virtual interface | ✅ |
| Manager channel selection (`0x000a` + `0x00b7` + `0x0061`) | ✅ |
| Master + virtual interfaces bound & active on the manager | ✅ |
| SSID / RSN / channel push (`0x6016`, ack `0xe016`) | ✅ received |
| VLAN push (`0x500b` TLV `0x7d`) | ✅ received |
| Security material push (`0x201f`) | 🟡 GTK/IGTK observed |
| PSK / passphrase delivery | 🟡 **not observed yet** |
| Apply pushed SSID/VLAN to UCI | 🟡 in progress |
| Status/traffic poll (`0x6027` → `0xe027`) | 🟡 counters not observed yet |

### Open questions

In our captures CAPsMAN v2 behaves as a split-MAC manager: it validates the
passphrase and returns derived keys (`0x201f`), while `0x6016` carries the
SSID and the public RSN IE. We have **not yet observed** the PSK itself, nor
the `0x500b a2=1` datachan create that is the most likely carrier for it. The
c2 datachan is also the most likely source of the per-station traffic/status
counters.

Paths currently being investigated:

* trigger the manager to issue the datachan create (`a2=1`);
* bridge EAPOL to the manager over the datachan, so the manager acts as the
  RSN authenticator and the CAP never needs the PSK;
* a one-shot configuration fetch at boot (no daemon);
* complete split-MAC support in the client.

Until one of these lands, the AP serves the SSID/VLAN/key configuration
already present in `/etc/config/wireless`; the manager owns channels and
interface state.



## How it works

```
        RB1100 (official CAPsMAN v2)                Xiaomi / OpenWrt
        ───────────────────────────                 ────────────────
  TLS 5246   0x4029 join              <──────────   capagent
             0xc029 join ok / cert    ──────────>
             0x001d NEWPHY            <──────────   radios, bands, ciphers
             0x500b create-vap        ──────────>   MAC + VLAN (0x7d)
             0xd00b channels          <──────────   0x000a records,
                                                   0x0061 current freq,
                                                   0x00b7 channel set
             0x6016 start/config      ──────────>   SSID, RSN IE, channel
             0xe016 ack               <──────────
             0x201f security          ──────────>   per-VAP key material
             0x6027 status poll       ──────────>   counters / stations
             0xe027 status            <──────────
```

The manager's channel selection is driven by the CAP: `0xd00b` must contain
one `0x000a` channel descriptor per frequency (with the manager's band id) and
`0x00b7` must carry the channel-number set. A wrong band value or a missing
`0x00b7` leaves the interface at `no available channels`.

The manager identifies each interface **only by the MAC in `0x08`**; the CAP
must return a unique `vapid` (`0x47`) per interface or the virtual users stall
in `CreatingVap`.

See [`docs/FINDINGS.md`](docs/FINDINGS.md) for the message/TLV reference.

## Install on the CAP

The CAP certificate must be trusted by the manager (see
[`scripts/enroll.md`](scripts/enroll.md)). Download the latest release bundle:

<https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases/latest>

```sh
# on the workstation
curl -LO https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases/latest/download/capagent-mipsel-v0.1.0-bundle.tar.gz
scp capagent-mipsel-v0.1.0-bundle.tar.gz root@10.0.0.2:/root/

# on the router
ssh root@10.0.0.2
mkdir -p /root/cap-bundle
tar -C /root/cap-bundle -xzf /root/capagent-mipsel-v0.1.0-bundle.tar.gz
cd /root/cap-bundle
MANAGER=10.0.0.1 ./install.sh
```

A standalone `capagent-mipsel` binary is attached to the same release if you
prefer to copy it directly.

`install.sh` installs `/usr/sbin/capagent`, writes
`/etc/cap/capagent.conf` (if missing), enables `capagent` and restarts it.
Certificates are expected at `/etc/cap/client.pem` and `/etc/cap/client.key`.

### Manager side (once)

1. Enable CAPsMAN: `/interface wifi capsman set enabled=yes`
2. Trust the CAP certificate (import `client.pem` or enroll via
   `scripts/enroll.py`).
3. Create the `security`, `datapath`, `configuration` and `provisioning`
   entries as usual. Use `datapath.traffic-processing=on-cap` and a
   `datapath.vlan-id` per SSID.

## Build

Requirements: OpenWrt 24.10 SDK/toolchain (`mipsel_24kc_gcc-13.3.0_musl`) and
static mbedTLS 3.6.2 built with the same toolchain.

```sh
export TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
export MBEDTLS=/path/to/mbedtls-3.6.2
./scripts/build-mipsel.sh
```

Output: `dist/capagent-mipsel` (ELF32 MIPS32r2, statically linked, stripped).
`dist/` is a local, gitignored build directory; published binaries live under
[Releases](https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases).

## Configure

`/etc/cap/capagent.conf`:

```sh
CERT=/etc/cap/client.pem
KEY=/etc/cap/client.key
MANAGER=10.0.0.1          # or "auto" for UDP discovery
PORT=5246
DONT_VERIFY_CERTIFICATE=yes   # or CA_CERT=/etc/cap/ca.pem
APPLY=yes                 # apply pushed config to UCI
DATACHAN=yes              # enable UDP 5248 datachan
IDENTITY=OpenWrt-CAP3
```

The packaged init script also honours `CAP_ADDR`, `DISCOVERY_INTERFACES`,
`CA_CERT`, `CAPS_MAN_CERT_CN`, `LOCK_TO_CAPS_MAN`, `SLAVES_DATAPATH`,
`SLAVES_STATIC`, `MACS`, `SERIAL`, `A1`, `E70`, `A7`.

## Verify

On the manager:

```
/interface wifi capsman remote-cap print detail
/interface wifi radio print detail
/interface wifi print
```

Expected: `state="Ok"`, radios with `current-channels=...`, and
`cap-wifi1` / `cap-wifi2` plus their virtuals **without** the `I` (inactive)
flag and without `no available channels`.

On the CAP:

```sh
logread -f | grep capagent
iw dev
```

## Repository layout

```
cap-client/
├── docs/FINDINGS.md          # control protocol / TLV reference
├── native/
│   ├── capagent.c            # the CAP client
│   ├── Makefile
│   ├── enroll.py             # certificate enrollment helper
│   └── deploy/               # OpenWrt init script, example conf, tools
├── scripts/
│   ├── build-mipsel.sh
│   ├── install-on-cap.sh
│   └── enroll.md
└── README.md
```

Prebuilt binaries and the deploy bundle are published under
[Releases](https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases),
not committed to the repository. `scripts/build-mipsel.sh` writes its output to
`dist/` locally (gitignored).

## Security

Never commit `client.key`, `client.pem`, `ca.pem` or any private key material.
The `.gitignore` excludes them. Certificates belong in `/etc/cap` on the
device, not in the repository.

## License

MIT — see [`LICENSE`](LICENSE).
