# MikroTik CAPsMAN v2 client for OpenWrt

Turn a non-MikroTik OpenWrt AP into a **CAP of the official RouterOS
CAPsMAN v2 manager**. The CAP side is native C: no extra service on the
manager, no agent inside RouterOS, and no static SSID/key/VLAN file as the
source of truth.

Reference hardware: **Xiaomi Mi Router 4A Gigabit Edition** (ramips/mt7621,
OpenWrt 24.10, MediaTek MT7603E + MT7612E), managed by an
**RB1100AHx4 / RouterOS 7.25.1**.

> ## ⚠️ STATUS: NOT SOLVED — closer, but no hardware/factory-reset proof
>
> **The goal is a CAP that behaves 100% like a genuine MikroTik CAP: the CAP
> gets everything (SSID, security, VLAN, channel) from the official CAPsMAN v2
> manager, with no local wireless configuration, no SSH, no second service and
> no manual step — including after a factory reset.**
>
> **That has NOT been achieved yet.**
>
> What works today (proven on the reference Xiaomi + RB1100):
>
> * the CAP joins the official manager and stays `state="Ok"`;
> * the manager sees the radios, their MACs and capabilities (`NEWPHY`);
> * with **zero `wifi-iface`** in `/etc/config/wireless` the manager provisions
>   **8/8 VAPs** (`0x500b` create + `0x6016` start for both radios, 6 `0x201f`
>   key installs) and accepts our `0xd00b` reply;
> * the CAP **creates the AP netdev** from `0x500b` and **starts one hostapd
>   per VAP** from `0x6016` — SSID, channel and RSN IE from the manager,
>   `external_rsn_auth=1`, **no PSK on the CAP**;
> * the manager is the RSN authenticator: the EAPOL relay is proven on the real
>   RB1100 (STA M2 → `0x201b` → manager → `0x201c` M3);
> * hostapd can advertise the manager's **exact RSN IE** (patch
>   [`docs/patches/9997-external-rsn-ie.patch`](docs/patches/9997-external-rsn-ie.patch)),
>   which removes the station's `IE in 3/4 msg does not match` cause; verified
>   byte-for-byte on the host and in the mipsel `wpad` parse.
>
> What does **not** work yet:
>
> * **No hardware/factory-reset proof.** A zero-touch sysupgrade image (client
>   + certificate + patched `wpad` in ROM, no SSH/firewall/DHCP) passes 55/55
>   static content checks but has **never been flashed**; boot, factory reset,
>   rejoin and 8/8 re-provision are unverified on the device.
> * **5 GHz hostapd start** still fails on the MT7612E (VHT80 centre-frequency /
>   HT40 / regulatory config); the four 2.4 GHz BSSes come up, 5 GHz does not.
> * **VAP lifecycle**: `0x600c` does not stop hostapd / delete the netdev /
>   release the vapid, so a repeated create for the same port can duplicate or
>   wedge.
> * **Station-side M3 acceptance** with the patched `wpad` has not been observed
>   on a real client yet.
> * There is still **no configuration tree** in CAPsMAN v2. The manager sends
>   SSID + RSN/WPA IE + channel and the CAP builds the BSS from that; it never
>   sends the passphrase, because it is the authenticator.
>
> Until the image is flashed and a factory reset is proven, **do not treat the
> current setup as the goal**. See
> [`docs/MANAGER-ONLY.md`](docs/MANAGER-ONLY.md) for what is proven and how to
> reproduce it, and [`docs/OPEN-PROBLEMS.md`](docs/OPEN-PROBLEMS.md) for the
> tracked blockers.
>
> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full chain and
> [`docs/FINDINGS.md`](docs/FINDINGS.md) for the message/TLV reference.

---

## Why

RouterOS CAPsMAN v2 only accepts CAPs that speak its private control protocol
(TLS 5246) and drive the radio through RouterOS' own HAL. This project
re-implements the CAP side in C on OpenWrt so an inexpensive mt76 AP can be
provisioned by the same manager as MikroTik hardware.

* single static binary (~800 KB mipsel), **no Python, no runtime dependencies**
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
| VAP create (`0x500b` → `0xd00b`) | ✅ creates the netdev, manager accepts the reply |
| VAP destroy (`0x600c`) | ❌ not implemented (no hostapd stop / netdev delete) |
| Unique vapid per virtual interface | ✅ |
| Master + virtual interfaces bound & active on the manager | ✅ |
| SSID / RSN / channel push (`0x6016`, ack `0xe016`) | ✅ received and turned into a BSS |
| Manager-only VAP creation (zero `wifi-iface`) | ✅ 8/8 on the reference CAP |
| Per-VAP hostapd (`external_rsn_auth=1`, no PSK) | ✅ 8 instances; 2.4 GHz BSSes up |
| RSN IE override (`external_rsn_ie`) | ✅ byte-for-byte on host; hardware station proof pending |
| 5 GHz hostapd start | ❌ VHT80/regulatory config, open |
| VLAN push (`0x500b` TLV `0x7d`) | ✅ received |
| Group-key push (`0x201f`) → nl80211 | ✅ |
| Datachan create (`0x500b` `a2=1`/`a2=2`) | ✅ reachable |
| Datachan keepalive (UDP 5248) | ✅ |
| Datachan rekey (`0x402b`) | 🟡 protocol proven; client logs/acks today, key-slot install not merged |
| Datachan plaintext (`a2=1`) send/receive | 🟡 protocol known; client needs the variant branch |
| Datachan secure (`a2=2`, AES-256-CCM) | 🟡 codec/keepalive proven; manager key gate open |
| Association + registration row (`0x2018` Auth + AssocReq) | ✅ live (real RB1100) |
| EAPOL relay (`0x201b` / `0x201c`) + `0x201f` PTK install | ✅ live; per-BSS extmux relay |
| Hostapd `external_rsn_auth` / `external_rsn_ie` patches | ✅ patch in `docs/patches/`; image content-verified |
| Status/traffic (`0x200e` / `0x2015`) | ✅ corrected sender; manager applies fields |
| PSK / passphrase delivery by CAPsMAN v2 | — not a protocol feature; never sent |
| Boot-time config pull (PSK fallback) | 🟡 validated prototype; productionization open |
| Zero-touch image + factory reset | 🟡 image built/verified, never flashed |

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

Two different gates must be kept apart:

* **BSS provisioning** is no longer a gate: the manager pushes `0x500b` and
  `0x6016`, and the CAP builds the netdev + hostapd from them (see
  [`docs/MANAGER-ONLY.md`](docs/MANAGER-ONLY.md)).
* **The secure c2 datachan** is still gated on the manager side. In the
  radio-less CHR lab the official manager never runs/succeeds its own datachan
  key install (`Cap::sendEcho` → `CNl::addChanKey`): it sends no `0x402b` key
  challenge and its c2 datachan cannot encrypt or decrypt. Consequently no
  `0x201c`, no 4-way over the datachan and no `0x201f` PTK follow **on that
  path**. The TLS EAPOL leg (`0x201b`/`0x201c`) does work on the real RB1100,
  which is why the manager-driven 4-way is proven without the datachan.

What is still under investigation is the manager's local association/key path on
a radio-less controller: whether the same limit applies to a radio-bearing
manager, whether a controller-only RB needs a manager-side precondition, and
whether a supported manager configuration (or a manager-side fix) makes the
datachan key leg run. This is tracked as the single gate before the secure
datachan can be called end-to-end on real hardware. It is not a CAP formatting
problem; the CAP half is implemented and exercised against the stock manager.

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

* Hardware/factory-reset acceptance of the zero-touch image (built, never
  flashed).
* 5 GHz hostapd start on the MT7612E (VHT80 centre frequency, HT40, regulatory
  domain).
* VAP lifecycle: implement `0x600c` teardown and vapid release.
* Station-side M3 acceptance with the patched `wpad` on a real client.
* Manager-side datachan key install on a radio-less manager (the secure c2
  gate above).
* Automatic `a2=1` plain vs `a2=2` secure selection in the client (the codec
  is secure-only today; the wire rule is documented).
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
| Config push | `0x6016` SSID/RSN/channel received and used to start a BSS | S8, T9, 1bd9d78 | ✅ |
| Manager-only VAP creation | 8/8 netdev + hostapd from `0x500b`/`0x6016`, no local `wifi-iface`, no PSK | zero-config live run | ✅ |
| VAP lifecycle | `0x600c` teardown not implemented | W25/W28 | ❌ open |
| 5 GHz BSS | hostapd start fails on MT7612E (VHT80/regulatory) | W22 | ❌ open |
| Group keys | `0x201f` GTK/IGTK → nl80211 | T3, T9, T14 | ✅ |
| Datachan framing | `10`, control byte, cdh, payload; keepalive and sequence | T1, T8, S8 | ✅ |
| Datachan plain/secure | `a2=1` plain, `a2=2` AES-CCM; `a7` gate | T11, S2, S8 | ✅ protocol |
| Rekey | `0x402b` 41 B, slot 0/1, empty `0xc02b`, 1 s purge | T8 | 🟡 protocol proven |
| Association | `0x2018` Auth + AssocReq creates Peer + row | T6, T13 | ✅ live |
| EAPOL relay | `0x201b`/`0x201c`, per-BSS extmux relay | T3, T4, T14, W8 | ✅ live RB1100 |
| Key install / authorize | PTK/GTK, `SET_STATION AUTHORIZED` | T3, T14 | ✅ hwsim |
| Hostapd patch | `external_rsn_auth` + `external_rsn_ie` | T10, T12, W21 | ✅ patch in `docs/patches/` |
| RSN IE equality | manager's 28-byte IE replayed byte-for-byte | W21 host log, qemu-mipsel | ✅ host; hardware STA pending |
| Zero-touch image | client + cert + patched `wpad` in ROM, 55/55 content checks | W35 | 🟡 built, not flashed |
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

Requirements: OpenWrt 24.10 SDK/toolchain (`mipsel_24kc_gcc-13.3.0_musl` for
the reference CAP) and static mbedTLS 3.6.x built with the same toolchain.

```sh
# mipsel, OpenWrt SDK tree with mbedTLS staged
make -C native SDK=/path/to/openwrt-sdk          # -> native/capagent-mipsel

# or a standalone toolchain + mbedTLS prefix
export TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
export MBEDTLS=/path/to/mbedtls-3.6.2
./scripts/build-mipsel.sh                        # -> dist/capagent-mipsel

# aarch64 (WiFi 6/7 APs)
TOOLCHAIN=/path/to/aarch64-linux-musl-cross/bin \
MBEDTLS=/path/to/mbedtls-aarch64 ./scripts/build-aarch64.sh
```

The SDK path expects `staging_dir/target-*/usr/{include,lib}` to contain
mbedTLS (`make package/libs/mbedtls/compile` in the SDK); if it does not, pass
`MBEDTLS_INC=`/`MBEDTLS_LIB=` explicitly. `make -C native check` runs the
AES-CCM known-answer tests under `qemu-mipsel`.

The version is printed by `capagent --version` (`0.4.0`) and stored in
`VERSION`. Output: `dist/capagent-mipsel` / `dist/capagent-aarch64` (static,
stripped). `dist/` is a local, gitignored build directory; published binaries
live under
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

### Ownership: netifd vs capagent (W33 policy, W34 ubus model)

At the start of every session capagent reads the **live** netifd state with
`ubus call network.wireless status` and reconciles it with its own per-netdev
journal (`/var/run/capagent-vaps.state`, `--vap-state FILE`).  There is one
ownership table and one decision path:

* a netdev whose name appears in `network.wireless status` is **netifd's**.
  capagent never creates, deletes, up/downs, tunes or reconfigures it, never
  starts/stops its hostapd, never installs keys on it and never writes UCI;
* a netdev created (or adopted from the journal) by capagent is **ours**.  It
  gets a hostapd BSS on `0x6016` and is torn down on `0x600c`;
* a netdev that is neither is **foreign** and is never touched;
* when netifd already owns the conventional `phy<N>-ap<M>` name, the manager
  VAP is created as `cap<N>-<M>` instead.  This is what makes a mixed
  legacy + manager setup safe: netifd always wins its names.

The session is still *legacy-coarse* when netifd owns at least one wireless
ifname (`wl_legacy()`), which keeps `APPLY=yes` and other global UCI writes
off.  Per-netdev effects use the ownership table, so manager VAPs work in a
mixed setup.  `--wireless-owner legacy` (or
`CAPAGENT_WIRELESS_MODE=legacy`) forces the fully read-only W33 contract.

The journal makes `wifi reload`, a netifd restart and a capagent restart
repair themselves: missing netdevs are recreated from the last `0x6016` body,
hostapd is restarted with backoff, and stale `/tmp/vap-*.conf` files are
removed only when no live process/journal row backs them.  A `busy`/`unknown`
ubus probe disables create/delete/steal until it recovers.

Check the live decision without touching anything:

```sh
capagent --check-wireless                          # ubus + journal (read-only)
capagent --check-wireless --wireless-config FILE   # offline fixture count
```

To hand the radios back to netifd after a manager-only run, stop capagent
first and remove its leftovers (`/var/run/vap-*.pid`,
`/var/run/capagent-vaps.state`, `pkill -f /tmp/vap-`), then write the legacy
`/etc/config/wireless` and run `wifi reload`.

Developer-only flags in the client (not wired into the init script):
`--eapol-leg tls|datachan|both`, `--crypto-selftest`, `--selftest-policy`,
`--wireless-owner own|legacy` (test override), `--vap-state FILE`,
`--no-vap-teardown`,
`--dc-*` test overrides, and the `-DCAPAGENT_LAB` harness (`--lab-ap`,
`--lab-ssid`, `--lab-chan`).

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

## Regression gate

One command, stable JSON, explicit pass rules:

```sh
scripts/w42_harness.py --legacy        # classic local-wifi-iface deployment
scripts/w42_harness.py --manager-only  # zero wifi-iface, manager owns the 4-way
scripts/w42_harness.py --manager-only --json-out manager.json --dump-dir ev/
```

Exit code `0` means every required check passed for that mode. Both modes
sample a stability window and require 8/8 VAPs, manager start (`0x6016`), STA
association, the correct VLAN lease, ping, and no `0x201c ... ret=-19`
injection. `--manager-only` additionally requires zero `wifi-iface`, a
manager-owned 4-way (`0x201f` + registration row, no CAP-local
`EAPOL-4WAY-HS-COMPLETED`) and a PSK-free CAP. See
[docs/REGRESSION-GATE.md](docs/REGRESSION-GATE.md) for the full rule table and
the stale-ifindex self-test (`--selftest-pmap`, `scripts/test-pmap-refresh.sh`).

## Repository layout

```
cap-client/
├── docs/
│   ├── MANAGER-ONLY.md       # what is proven, what is open, reproduce zero-config
│   ├── OPEN-PROBLEMS.md      # tracked blockers + verified facts
│   ├── ARCHITECTURE.md       # datapath modes and split-MAC chain
│   ├── FINDINGS.md           # control protocol / TLV reference
│   ├── REGRESSION-GATE.md    # acceptance modes, pass rules, baselines
│   ├── W27-INTEGRATION.md    # W8/W6/W14 integration notes
│   └── patches/              # hostapd 9997-external-rsn-ie.patch
├── native/
│   ├── capagent.c            # entry unit (constants + module includes)
│   ├── src/                  # protocol modules (util, nl80211, vap, datachan, ...)
│   ├── Makefile
│   ├── enroll.py             # certificate enrollment helper
│   └── deploy/               # OpenWrt init script, preflight, example conf, tools
├── scripts/
│   ├── build-mipsel.sh
│   ├── build-aarch64.sh
│   ├── install-on-cap.sh
│   ├── w42_harness.py        # regression gate (legacy / manager-only)
│   ├── run-regression.sh     # thin wrapper for the gate
│   ├── test-pmap-refresh.sh  # stale-ifindex self-test
│   └── enroll.md
├── baseline/                 # live legacy + manager-only JSON captures
├── VERSION
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
