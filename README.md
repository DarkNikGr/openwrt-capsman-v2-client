# MikroTik CAPsMAN v2 client for OpenWrt

Turn a non-MikroTik OpenWrt AP into a **CAP of the official RouterOS
CAPsMAN v2 manager**. The CAP side is native C: no extra service on the
manager, no agent inside RouterOS, and no static SSID/key/VLAN file as the
source of truth.

Reference hardware: **Xiaomi Mi Router 4A Gigabit Edition** (ramips/mt7621,
OpenWrt 24.10, MediaTek MT7603E + MT7612E), managed by an
**RB1100AHx4 / RouterOS 7.25.1**.

> **Status:** the control plane is working end-to-end. The official manager
> sees the CAP as `state="Ok"`, selects channels, creates and binds the master
> and virtual interfaces, and pushes the SSID/RSN/channel (`0x6016`), VLAN
> (`0x500b` `0x7d`) and group-key material (`0x201f`). The split-MAC data plane
> is implemented in the client and proven at the codec/control level in the lab,
> with one **manager-side gate** still under investigation on a radio-less
> manager. The WPA passphrase is not part of CAPsMAN v2; where local forwarding
> needs it, a boot-time configuration pull is the fallback.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full chain and
[`docs/FINDINGS.md`](docs/FINDINGS.md) for the message/TLV reference.

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
* split-MAC option: manager-side 802.1X/RSN, EAPOL relay and key install

## Architecture at a glance

```
                    RB1100 · RouterOS 7.25.1 CAPsMAN v2
   ┌────────────────────────────────────────────────────────────────────┐
   │ TLS 5246   join 0x4029 / NEWPHY 0x001d / 0x500b / 0x6016          │
   │            0x201f keys / 0x201c EAPOL-TX / 0x2018 assoc report     │
   │ UDP 5248   c2 datachan   10 | cdh[8] | payload                     │
   │            a2=1 plain, a2=2 AES-CCM                                │
   │ RSN authenticator + key derivation — the PSK stays here            │
   └───────────────┬───────────────────────────────────┬────────────────┘
                   │ TLS control                       │ c2 (split-MAC only)
   ┌───────────────┴───────────────────────────────────┴────────────────┐
   │ capagent (OpenWrt, mt76)                                           │
   │   control: join, NEWPHY, VAP create, channel, 0x200e / 0x2015      │
   │   split-MAC: 0x2018 assoc, 0x201b / 0x201c EAPOL, 0x201f keys      │
   │ hostapd/wpad: beacon, auth/assoc, RSN IE, AP-VLAN                  │
   └───────────────┬────────────────────────────────────────────────────┘
                   │ 802.11 (CCMP)
                clients
```

The control plane is always the same. Only the data path changes.

## Datapath modes

| Mode | Manager datapath | Client data | PSK on CAP | State |
|---|---|---|---|---|
| **Local forwarding** | `traffic-processing=on-cap` (default) | kernel bridge/VLAN on the AP | yes — static, or pulled at boot | **Working** (PSK local or boot-pull) |
| **Split-MAC, plain** | `traffic-processing=on-capsman` | every client frame in the c2 datachan (`0x500b` `a2=1`), plaintext | no — manager authenticates | Protocol proven; client variant branch open |
| **Split-MAC, secure** | `traffic-processing=on-capsman-secure` | same datachan (`a2=2`) with AES-256-CCM | no — manager authenticates | Codec/keepalive proven; rekey protocol proven; manager key gate open |

Notes:

There are two families: **local forwarding** (`on-cap`) and **split-MAC**
(`on-capsman` plain or `on-capsman-secure` AES-CCM). They share the same
control plane; only the data path differs.

* `on-cap` is the production-recommended mode. The kernel does the
  802.11→802.3 conversion and bridging; userspace only handles control, EAPOL
  and (optionally) statistics. The trade-off is that the PSK must exist on the
  CAP.
* `on-capsman` is the split-MAC mode. It is copy-bound: every client Ethernet
  frame crosses the c2 datachan. `on-capsman-secure` adds AES-CCM and is the
  variant this client implements; the plain `a2=1` variant is understood but
  needs a mode branch before it can be used.
* Enabling `on-capsman` changes forwarding completely: EAPOL and client data
  leave the AP over UDP 5248 and are forwarded by the manager.

## Split-MAC chain

1. **Join** — `0x4029` with identity/board/serial/MACs and NEWPHY
   capabilities. The manager replies `0xc029` (and may issue a certificate).
2. **Data-channel capability** — NEWPHY `0x84` byte 0 bit 6 must be set.
   For the secure variant, the join version vector `0xa7` must also advertise
   the capability the manager whitelists (`01 00 07` works).
3. **VAP create** — `0x500b` carries the MAC, VLAN (`0x7d`) and, when a
   datachan is configured, `a2`, the 32-byte key (`0xa8`), key index (`0xa9`),
   UDP port (`0xa6`) and keepalive cookie (`0xaa`). The CAP answers `0xd00b`
   with a unique `vapid`.
4. **BSS start** — `0x6016` carries SSID, RSN IE and channel; the CAP acks
   with `0xe016`. The manager then sends group-key material in `0x201f`.
5. **Association** — hostapd handles beacon/auth/assoc on air. The CAP reports
   the real Auth and AssocReq frames to the manager as `0x2018`. The manager
   creates the `Peer` and the registration-table row; AssocReq alone is not
   enough, Auth must come first.
6. **EAPOL** — the CAP sends the station's EAPOL to the manager as `0x201b`.
   The manager runs the 4-way and returns EAPOL-TX as `0x201c`; the CAP injects
   it on the cfg80211 control port.
7. **Keys** — `0x201f` carries PTK/GTK/IGTK; the CAP installs them with
   nl80211 (`NEW_KEY`/`SET_KEY`) and authorizes the station
   (`SET_STATION AUTHORIZED`). The CAP never needs the PSK.
8. **Data** — `on-cap`: local bridge. `on-capsman`/secure`: client Ethernet
   frames are encapsulated in the c2 datachan and forwarded by the manager.
9. **Status** — `0x200e` (station/signal) and `0x2015` (counters/rates) are
   sent on the `0x6027` poll.

## Status

| Capability | State |
|---|---|
| TLS join (`0x4029` → `0xc029`), certificate enrollment | ✅ |
| NEWPHY capabilities (`0x001d`), channel selection (`0x000a`/`0x00b7`/`0x0061`) | ✅ |
| VAP create (`0x500b` → `0xd00b`), destroy (`0x600c`) | ✅ |
| Unique vapid per virtual interface | ✅ |
| Master + virtual interfaces bound & active on the manager | ✅ |
| SSID / RSN / channel push (`0x6016`, ack `0xe016`) | ✅ received and acked |
| VLAN push (`0x500b` TLV `0x7d`) | ✅ received |
| Group-key push (`0x201f`) → nl80211 | ✅ |
| Datachan create (`0x500b` `a2=1`/`a2=2`) | ✅ reachable |
| Datachan keepalive (UDP 5248) | ✅ |
| Datachan rekey (`0x402b`) | 🟡 protocol proven; client logs/acks today, key-slot install not merged |
| Datachan plaintext (`a2=1`) send/receive | 🟡 protocol known; client needs the variant branch |
| Datachan secure (`a2=2`, AES-256-CCM) | 🟡 codec/keepalive proven; manager key gate open |
| Association + registration row (`0x2018` Auth + AssocReq) | 🟡 proven in the lab harness; production hostapd wiring open |
| EAPOL relay (`0x201b` / `0x201c`) + `0x201f` PTK install | 🟡 implemented; hwsim end-to-end pass; hostapd patch pending |
| Hostapd `external_rsn_auth` patch | 🟡 buildable, hwsim-proven; not in this tree yet |
| Status/traffic (`0x200e` / `0x2015`) | ✅ corrected sender; manager applies fields |
| PSK / passphrase delivery by CAPsMAN v2 | — not a protocol feature; use local config or boot-pull |
| Boot-time config pull (PSK fallback) | 🟡 validated prototype; productionization open |

### Datachan variants

The manager chooses the variant from the **VAP datapath**, not from NEWPHY:

* `on-cap` → no datachan (`a2` absent);
* `on-capsman` → `a2=1`, plaintext Ethernet after the c2 header;
* `on-capsman-secure` → `a2=2`, AES-256-CCM with a 16-byte tag.

The secure variant additionally requires the join `0xa7` capability. If the CAP
is not eligible, the manager creates no datachan at all instead of silently
downgrading. The c2 key is random, generated by the manager, and carried in
cleartext in `0x500b`; it is not derived from TLS or the CAP certificate.

### The remaining hard gate

The open item is **manager-side, not CAP-side**. In the radio-less CHR lab the
official manager never runs/succeeds its own datachan key install
(`Cap::sendEcho` → `CNl::addChanKey`): it sends no `0x402b` key challenge and
its c2 datachan cannot decrypt or encrypt. Consequently no `0x201c`, no 4-way,
no `0x201f` PTK and no authorization follow. The association half is already
demonstrated: `0x2018` Auth + AssocReq creates the manager `Peer` and a
registration-table row on the stock manager.

What is still under investigation is the manager's local association/key path on
a radio-less controller: whether the same limit applies to a radio-bearing
manager, whether a controller-only RB needs a manager-side precondition, and
whether a supported manager configuration (or a manager-side fix) makes the key
leg run. This is tracked as the single gate before the secure datachan can be
called end-to-end on real hardware. It is not a CAP formatting problem; the CAP
half is implemented and exercised against the stock manager.

### PSK and the boot-pull fallback

CAPsMAN v2 never serializes the WPA2 passphrase, PMK or PSK. `0x201f` contains
derived GTK/PTK/IGTK, `0x6016` contains the SSID and RSN IE, and `0x500b`
contains radio/VLAN/datachan fields. The official 7.25.1 manager sends no
`0x77` configuration tree.

For **local forwarding** the CAP therefore needs the PSK locally. The fallback
is a **boot-time pull** from the manager's management plane:

* a one-shot procd unit at boot fetches
  `GET /rest/interface/wifi/configuration` and `/provisioning`;
* the REST user needs `read,api,rest-api,sensitive`; without `sensitive` the
  passphrase is omitted;
* the surgical variant patches only `option key` (idempotent, no persistent
  loop); the full variant can regenerate the BSS/VLAN configuration;
* if the manager is down or returns 401, the old local configuration is kept
  and the unit exits non-zero.

This is an out-of-band compatibility path, not CAP-native provisioning. It
puts the passphrase on the CAP and on the REST transport, so the REST endpoint
must be restricted to the CAP address, the credentials must be mode 600, and
HTTPS (with a valid clock/certificate) is preferable to the plain HTTP 8088
used in the lab. The `on-capsman`/secure mode avoids this fallback: the
manager authenticates and the CAP only handles EAPOL and derived keys.

## Open questions

* Manager-side datachan key install on a radio-less manager (the hard gate
  above).
* Automatic `a2=1` plain vs `a2=2` secure selection in the client (the codec
  is secure-only today; the wire rule is documented).
* Production wiring for `0x2018`: hostapd's management-frame path vs a small
  nl80211 AP/MLME helper. The lab harness already proves the wire sequence.
* Carrying the hostapd `external_rsn_auth` patch in the OpenWrt package
  (the prototype builds and passes hwsim, but is not merged here).
* Multi-VAP datachan TX key selection, PMF/IGTK live validation, and a
  full hardware matrix on the Xiaomi + RB1100.
* Rekey/deauth/restart soak tests on real hardware.

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
             0x201f security          ──────────>   GTK/IGTK/PTK
             0x6027 status poll       ──────────>   counters / stations
             0xe027 status            <──────────
             0x2018 assoc report      ──────────>   Auth + AssocReq
             0x201b EAPOL from STA    ──────────>   relay to manager
             0x201c EAPOL to STA      <──────────   inject on control port
```

The manager's channel selection is driven by the CAP: `0xd00b` must contain
one `0x000a` channel descriptor per frequency (with the manager's band id) and
`0x00b7` must carry the channel-number set. A wrong band value or a missing
`0x00b7` leaves the interface at `no available channels`.

The manager identifies each interface **only by the MAC in `0x08`**; the CAP
must return a unique `vapid` (`0x47`) per interface or the virtual users stall
in `CreatingVap`.

See [`docs/FINDINGS.md`](docs/FINDINGS.md) for the message/TLV reference.

## Results so far

The table maps the main results to the work item that produced them (`T*` /
`S*` are the internal investigation labels). "Lab" means a private CHR 7.25.1 /
mac80211-hwsim setup; no production RB or Xiaomi configuration was changed.

| Area | Result | Evidence | State |
|---|---|---|---|
| Control plane | join, NEWPHY, VAP create, channel selection, ACKs | S1, S6, T9 | ✅ |
| Channel provisioning | per-frequency `0x000a`, band id, `0x00b7` set | T9, live RB | ✅ |
| VLAN / VAP identity | `0x7d` per VAP; unique vapid required | T6, S6 | ✅ |
| Config push | `0x6016` SSID/RSN/channel received and acked | S8, T9 | ✅ |
| Group keys | `0x201f` GTK/IGTK → nl80211 | T3, T9, T14 | ✅ |
| Datachan framing | `10`, control byte, cdh, payload; keepalive and sequence | T1, T8, S8 | ✅ |
| Datachan plain/secure | `a2=1` plain, `a2=2` AES-CCM; `a7` gate | T11, S2, S8 | ✅ protocol |
| Rekey | `0x402b` 41 B, slot 0/1, empty `0xc02b`, 1 s purge | T8 | 🟡 protocol proven |
| Association | `0x2018` Auth + AssocReq creates Peer + row | T6, T13 | ✅ live |
| EAPOL relay | `0x201b`/`0x201c`, control-port inject | T3, T4, T14 | ✅ hwsim |
| Key install / authorize | PTK/GTK, `SET_STATION AUTHORIZED` | T3, T14 | ✅ hwsim |
| Hostapd patch | `external_rsn_auth`, 389 added lines | T10, T12 | 🟡 prototype |
| Statistics | corrected `0x2015`, `0x200e`, `0x2013` | T7, T15 | ✅ sender |
| PSK carriers | not serialized by CAPsMAN v2 | S5, S9 | — by design |
| Boot-pull | REST pull of config/passphrase at boot | S9 | 🟡 prototype |
| Secure datachan e2e | manager key install does not run on the radio-less CHR | T9, T10 | 🟡 open |

## Install on the CAP

The CAP certificate must be trusted by the manager (see
[`scripts/enroll.md`](scripts/enroll.md)). Download the latest release bundle:

<https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases/latest>

```sh
# on the workstation
curl -LO https://github.com/DarkNikGr/openwrt-capsman-v2-client/releases/latest/download/capagent-mipsel-bundle.tar.gz
scp capagent-mipsel-bundle.tar.gz root@10.0.0.2:/root/

# on the router
ssh root@10.0.0.2
mkdir -p /root/cap-bundle
tar -C /root/cap-bundle -xzf /root/capagent-mipsel-bundle.tar.gz
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
   entries as usual.
4. Choose the datapath mode:
   * `datapath.traffic-processing=on-cap` and a `datapath.vlan-id` per SSID
     for local forwarding (recommended, needs a local PSK);
   * `datapath.traffic-processing=on-capsman` or `on-capsman-secure` for
     split-MAC (no PSK on the CAP; hostapd patch required).

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
APPLY=yes                 # apply an optional 0x77 config tree to UCI
DATACHAN=yes              # enable UDP 5248 datachan
IDENTITY=OpenWrt-CAP3
```

The packaged init script also honours `CAP_ADDR`, `DISCOVERY_INTERFACES`,
`CA_CERT`, `CAPS_MAN_CERT_CN`, `LOCK_TO_CAPS_MAN`, `SLAVES_DATAPATH`,
`SLAVES_STATIC`, `MACS`, `SERIAL`, `A1`, `E70`, `A7`.

`APPLY=yes` only acts when the manager sends an optional `0x77` configuration
tree; stock RouterOS 7.25.1 does not. The SSID/RSN in `0x6016` is received and
acked but does not contain the passphrase. Use the boot-pull fallback (or a
local key) for local forwarding.

Developer-only flags in the client (not wired into the init script):
`--eapol-leg tls|datachan|both`, `--crypto-selftest`, `--dc-*` test overrides,
and the `-DCAPAGENT_LAB` harness (`--lab-ap`, `--lab-ssid`, `--lab-chan`).

## Verify

On the manager:

```
/interface wifi capsman remote-cap print detail
/interface wifi radio print detail
/interface wifi print
/interface wifi registration-table print detail
```

Expected: `state="Ok"`, radios with `current-channels=...`, and
`cap-wifi1` / `cap-wifi2` plus their virtuals **without** the `I` (inactive)
flag and without `no available channels`. In split-MAC mode a real client
should also produce a registration-table row after Auth+Assoc; `authorized`
stays false until the 4-way completes.

On the CAP:

```sh
logread -f | grep capagent
iw dev
iw station dump
```

Useful log lines: `RX 0x500b ... a2=`, `datachan: listening`, `0x201c:
inject`, `0x201f key-install`, and the `0x2015`/`0x200e` counters.

## Repository layout

```
cap-client/
├── docs/
│   ├── FINDINGS.md           # control protocol / TLV reference
│   └── ARCHITECTURE.md       # datapath modes and split-MAC chain
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

See [`SECURITY.md`](SECURITY.md) for the threat model, the v0.2.1 fixes
(shell injection, `/tmp` dumps, key logging) and deployment hardening.

Never commit `client.key`, `client.pem`, `ca.pem` or any private key material.
The `.gitignore` excludes them. Certificates belong in `/etc/cap` on the
device, not in the repository.

The boot-pull fallback additionally stores manager REST credentials on the CAP
(mode 600) and may expose the passphrase over the management network. Restrict
the REST service to the CAP address, use a dedicated user with only
`read,api,rest-api,sensitive`, and prefer HTTPS. The split-MAC secure mode
avoids putting the PSK on the CAP at all.

## License

MIT — see [`LICENSE`](LICENSE).
