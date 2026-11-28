# MikroTik CAPsMAN v2 client for OpenWrt

**v0.7.1** — see [`docs/RELEASE-0.7.1.md`](docs/RELEASE-0.7.1.md) and the
[release index](docs/RELEASES.md). Canonical documentation index:
[`docs/README.md`](docs/README.md).

Turn a non-MikroTik OpenWrt AP into a **CAP of the official RouterOS
CAPsMAN v2 manager**. The CAP side is native C: no extra service on the
manager, no agent inside RouterOS, and no static SSID/key/VLAN file as the
source of truth.

Reference hardware: **Xiaomi Mi Router 4A Gigabit Edition** (ramips/mt7621,
OpenWrt 24.10, MediaTek MT7603E + MT7612E), managed by an
**RB1100AHx4 / RouterOS 7.25.1**.

> ## ✅ STATUS: WORKING CAP — PSK-free, manager-provisioned, factory-reset proof
>
> The goal was a CAP that behaves 100% like a genuine MikroTik CAP: every
> SSID, VLAN, security and channel setting comes from the official CAPsMAN v2
> manager, with no local wireless file, no SSH-driven bootstrap and no second
> service on the manager. **That is now demonstrated on real hardware.**
>
> Verified on the reference Xiaomi Mi Router 4A + RB1100AHx4 / RouterOS 7.25.1:
>
> | Proof | Evidence |
> |---|---|
> | Manager provisions every VAP | `0x500b` + `0x6016` for 8 VAPs, `0xd00b` accepted |
> | **8/8 SSIDs** | `ssids=8` on **2 real radios, no fake, no static**: 2.4 GHz dynamic master+3 slaves, 5 GHz dynamic master+3 virtuals (`2A:...:85/86/87`) |
> | **All 8 SSIDs authenticate** | 2.4 GHz 4/4 + 5 GHz 4/4 (`authorized: yes` on the master and all slaves), also after a cold reboot; automatic one-hostapd-per-VAP, patched mt76x02 + `9999k` hostapd no-ACK tolerance (F92) |
> | **No PSK on the CAP** | `external_rsn_auth=1`, no `wpa_passphrase`/`wpa_psk_file` |
> | **Manager is the authenticator** | EAPOL `0x201c` (M1) → `0x201b` (M2) → `0x201f` PTK |
> | **Station authorized** | `authorized: yes`, `authenticated: yes`, -38 dBm |
> | **Traffic works** | `ping` 3/3, 0% loss over the manager's VLAN |
> | **Factory reset** | `sysupgrade -n` → boot → self-enrolment → 8/8, no manual step |
>
> How it works, in one line: 2.4 GHz uses one hostapd per radio with `bss=`
> sections; 5/6 GHz automatically uses one hostapd **per VAP** because mt76x02
> and the 6 GHz hostapd stack do not deliver auth to a multi-BSS secondary. hostapd relays the raw Auth/AssocReq and the EAPOL
> exchange, and never holds a key. The v0.7.0 image also ships the patched
> `mt76x02-lib.ko` (sequential BSS slots + RX drop fix) and the `9999k`
> hostapd no-ACK tolerance, so the manager's **dynamic** 5 GHz slaves work.
>
> The patched `wpad` (patches `999`/`9997`/`9998`/`9999`/`9999a`–`9999k`) is
> built by [`scripts/build-wpad-9999a.sh`](scripts/build-wpad-9999a.sh); the
> zero-touch image by [`scripts/build-image.sh`](scripts/build-image.sh);
> the mt76 patch and build notes are in
> [`patches/mt76/`](patches/mt76/README.md).
>
> ### What is still open (not blocking the above)
>
> * **The no-fake 2-radio dynamic layout is now the proven default.** 2.4 GHz
>   is a master + 3 manager slaves; 5 GHz is a dynamic master + 3 manager
>   virtuals (`2A:...:85/86/87`). The manager sees exactly two radios and
>   eight VAPs; all eight authenticate after a cold reboot (v0.7.0, F92).
>   The fixed mt76x02 module and the `9999k` hostapd tolerance ship in the
>   image. The older one-CAP/eight-radio **solo** mode and the eight-identity
>   layout (`/etc/cap/identities.conf`) still work, but are no longer required.
> * **`MANAGER=auto` works through DHCP option 138.** The image's
>   `/etc/udhcpc.user.d/99-cap-dhcp138` hook decodes the option into
>   `/tmp/cap-manager`; with `10.0.0.1` in that file the agent uses it. Baking
>   the address into `/etc/cap/capagent.conf` is no longer required.
> * **Live security changes work without any restart.** The manager signals
>   them with `0x6017`; capagent tears down the local VAPs/hostapds, re-joins
>   and rebuilds cleanly, so all eight SSIDs survive a passphrase change
>   (F82). PMF-required is live.
> * **802.11k and 802.11v are live on the virtual bench.** 11k: `rrm-capa=0x70`,
>   Beacon report token 1, relayed as `0x2018 action len=235` (F69/F71).
>   802.11v/BTM: request `0x2019 action len=49`, response `0x2018 action
>   len=29` (F67). The bench Intel 3168 still drops the RM IE.
> * **6 GHz works on hwsim as one radio + 3 dynamic provisioning virtuals**
>   at 5955 MHz / 160 MHz (`6ghz-ax`, SAE+PMF), no static interfaces, one
>   hostapd per VAP; all four BSSes `AP-ENABLED`, a station `authorized: yes`
>   on the master and each virtual, and 20/40/80/160 all pass (F91, AG54). The manager matches the descriptor band byte, not the
>   NEWPHY label: `0x04` gives `5955/ax`, `0x06` gives `6ghz-be` for EHT
>   (F85); 160 MHz is descriptor width 5, not 4. 320 MHz EHT is encoded
>   (`op_class=137`, `eht_oper_chwidth=9`, F89) and manager-accepted. The
>   reference Xiaomi has no 6 GHz radio, so real RF/AFC needs a 6E/7 board
>   (Flint 3/ath12k; see `docs/HARDWARE-6GHZ-MLO-PLAN.md`).
> * **OWE is live.** RouterOS 7.25.1 never sends a DH-bearing `0x6019`, so a
>   pure-OWE VAP is completed by the CAP's own hostapd while the manager still
>   provisions SSID/security/channel/VLAN. A station does the OWE DH, the
>   4-way and pings 0% (F80); `CAPAGENT_LOCAL_OWE=0` restores the relay.
> * **`on-capsman` (`a2=1`) is live on both radios.** The `a2` variant is
>   per VAP; stations on the Xiaomi 5 GHz and 2.4 GHz VAPs are
>   `authorized: yes` and ping 0% through the manager (F81/F88). The 2.4 VAP
>   needs `datapath.traffic-processing=on-capsman` explicitly on the
>   configuration, not only `datapath=dt-cm`.
> * There is **no configuration tree** in CAPsMAN v2: the manager keeps the
>   passphrase and is the authenticator, so it never sends the PSK to the CAP.
>
> Reproduction steps and the message reference:
> [`docs/MANAGER-ONLY.md`](docs/MANAGER-ONLY.md),
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
> [`docs/FINDINGS.md`](docs/FINDINGS.md). Which manager settings are proven and
> which are not: [`docs/CAPSMAN-COVERAGE.md`](docs/CAPSMAN-COVERAGE.md).

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
| **Split-MAC, plain** | `traffic-processing=on-capsman` | every client frame in the c2 datachan (`0x500b` `a2=1`), plaintext | no — manager authenticates | ✅ live on the Xiaomi 2.4 and 5 GHz with `DATACHAN`+`DATAPATH_BRIDGE`: station `authorized: yes`, ping 0%, `datachan plain` both ways (F81/F88); the 2.4 VAP needs the explicit `datapath.traffic-processing=on-capsman` |
| **Split-MAC, secure** | `traffic-processing=on-capsman-secure` | same datachan (`a2=2`) with AES-256-CCM | no — manager authenticates | Codec/keepalive proven; `a2=2` live on the RB1100 (F72); radio-less CHR key gate open |

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
   For the secure variant the join also advertises `0xa7 = 01 00 07`; a
   37-value sweep showed `0xa7` alone does not make the manager select
   `a2=2` (F70), and the reference RB1100 later selected it on its own (F72).
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

Last updated 2026-11-28 against `main` (v0.7.1). "Live" means the reference Xiaomi
Mi Router 4A + RB1100AHx4 / RouterOS 7.25.1; "lab" means CHR 7.25.1 + hwsim.

| Capability | State |
|---|---|
| TLS join (`0x4029` → `0xc029`) | ✅ live |
| Certificate enrolment (`0x76` → `0x77`/`0x78`), random CN, re-enrol on expiry/rotation/duplicate | ✅ lab 10/10, live enrolment |
| NEWPHY capabilities (`0x001d`) | ✅ live |
| Channel selection (`0x000a`/`0x00b7`/`0x0061`) with one descriptor per (freq, band, width) | ✅ live (`2ghz-n`, `5ghz-ac` start) |
| VAP create (`0x500b` → `0xd00b`) with a real ifindex | ✅ live 8/8 |
| VAP destroy (`0x600c`): hostapd stop, netdev delete, vapid release, orphan reaping | ✅ live 3 cycles × 8 VAPs, 0 failures |
| Manager-only VAP creation (zero `wifi-iface`) | ✅ live 8/8 |
| Two real radios, 8 SSIDs, no fake, no static (2.4 dynamic master+3 slaves, 5G dynamic master+3 virtuals) | ✅ live: 8/8 `authorized: yes`, also after a cold reboot (F92; patched mt76x02 + `9999k`) |
| One CAP with eight radios (solo) | ✅ live after a cold reboot: one `cap=OpenWrt-CAPSOLO`, 8 radios, 8 SSIDs, all eight `authorized: yes`, 3/3, 0% |
| One hostapd per radio with `bss=` on 2.4, one hostapd per VAP on 5/6 GHz (`external_rsn_auth=1`, **no PSK**) | ✅ live: 2.4 multi-BSS + 4 per-VAP 5 GHz hostapds; 8/8 `AP-ENABLED` (F90) |
| RSN IE override (`external_rsn_ie`) — beacon == manager M3 | ✅ lab byte-for-byte; live station connects with no IE mismatch |
| Per-BSS start on both radios (`SET_INTERFACE -EALREADY`, `noscan`, regulatory) | ✅ live 8/8 `AP-ENABLED`; `9999d` tolerates `-EALREADY` |
| VLAN push (`0x500b` `0x7d`) | ✅ live |
| Group/PTK keys (`0x201f` → nl80211), GTK/IGTK/BIGTK class pairing | ✅ live + lab |
| Datachan create (`0x500b` `a2=1`) | ✅ live |
| Datachan keepalive (UDP 5248) | ✅ live |
| Datachan plaintext (`a2=1`) frames | ✅ live on the Xiaomi 5 GHz (F81: `a2=1`, UDP 5248, station `authorized: yes` + ping 0%) |
| Datachan secure (`a2=2`, AES-256-CCM) | ✅ live on the RB1100 (F72: `a2=2`, UDP 5248, station `authorized: yes` + ping 0%); the radio-less CHR lab still never runs the manager's own key install |
| Datachan rekey (`0x402b`) | 🟡 protocol proven; slot install not merged |
| Association + manager registration row (`0x2018`) | ✅ live |
| EAPOL relay (`0x201b`/`0x201c`) + `0x201f` PTK install | ✅ live (M1→M2→M3); per-BSS extmux relay |
| Raw Auth/AssocReq relay for 4-interface radios (no monitor VIF) | ✅ live with the patched `wpad` (`0x2018` Auth + AssocReq → M1) |
| PSK-free WPA2-PSK | ✅ **live**: `authorized: yes`, PTK via `0x201f`, ping 3/3 |
| PSK-free WPA2-EAP / open | ✅ WPA2-EAP **live** (F53: FreeRADIUS PEAP/MSCHAPv2, `authorized: yes`, ping 3/3 0%); open/lab matrix also 9/9 |
| PSK-free SAE / OWE | ✅ SAE **live**; ✅ OWE **live** via CAP-local OWE (F80: OWE DH + 4-way + ping 0%; the manager still provisions the VAP) |
| 802.11k beacon report relay | ✅ live on a virtual station (F69/F71: `rrm-capa=0x70`, token 1, `0x2018 action len=235`); Intel 3168 firmware still drops the RM IE |
| 802.11v BTM request/response | ✅ live on the virtual bench (F67: `0x2019 action len=49`, `0x2018 action len=29`) |
| Ownership: netifd wins, ubus→uci→file→refuse, MLD never adopted | ✅ live + 27-check selftest |
| Recovery: new-session deauth, frame deadline, silence reconnect, fail-closed TLS | ✅ lab |
| Status/traffic (`0x200e`/`0x2015`) | ✅ |
| Regression harness + committed baselines | ✅ `scripts/w42_harness.py` |
| CI (host + ASan/UBSan + mipsel qemu) | ✅ `.github/workflows/ci.yml` |
| PSK / passphrase delivery by CAPsMAN v2 | — not a protocol feature; never sent |
| Boot-time config pull (PSK fallback) | 🟡 prototype only |
| Zero-touch image + factory reset | ✅ **flashed** (`sysupgrade -n`): self-enrolment, 8/8 re-provision, no manual step |
| Manager `0x2019` deauth relay | ✅ live `ret=0` (other-transport retry + hostapd `DEAUTHENTICATE` fallback) |

### Datachan variants

The manager chooses the variant from the **VAP datapath**, not from NEWPHY:

* `on-cap` → no datachan (`a2` absent);
* `on-capsman` → `a2=1`, plaintext Ethernet after the c2 header;
* `on-capsman-secure` → `a2=2`, AES-256-CCM with a 16-byte tag.

The secure variant also advertises the join `0xa7` capability. A capability
sweep showed that `0xa7` alone is not the manager's selector (F70); the
reference RB1100 later selected `a2=2` on its own (F72). If the CAP is not
eligible, the manager creates no datachan at all instead of silently
downgrading. The c2 key is random, generated by the manager, and carried in
cleartext in `0x500b`; it is not derived from TLS or the CAP certificate.

### The one manager-side gate that remains

The acceptance gates are closed: the manager provisions the BSSes, a station
completes the 4-way with no key on the CAP, traffic flows, and a factory-reset
image re-provisions itself. The one protocol variant that is still not
reproducible in every environment is:

* **The secure c2 datachan.** The CAP half is implemented, and the reference
  RB1100 has been observed selecting `a2=2` and carrying client traffic as
  encrypted datachan frames (F72). In the radio-less CHR lab, however, the
  official manager never runs/succeeds its own datachan key install
  (`Cap::sendEcho` → `CNl::addChanKey`): it sends no `0x402b` key challenge and
  its c2 datachan cannot encrypt or decrypt. Consequently no `0x201c`, no
  4-way over the datachan and no `0x201f` PTK follow **on that path**. The TLS
  EAPOL leg (`0x201b`/`0x201c`) works on both and is what production uses.

What is still under investigation is the manager's local association/key path on
a radio-less controller: whether a controller-only RB needs a manager-side
precondition, and whether a supported manager configuration (or a manager-side
fix) makes the datachan key leg run there. This is tracked as the single lab
gate before the secure datachan can be called end-to-end without a radio. It
is not a CAP formatting problem; the CAP half is implemented and exercised
against the stock manager.

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

Closed by the current state (kept here so old reports are not misread):

* ~~One clean end-to-end live run~~ — done: `authorized: yes` and `ping 3/3`
  with no PSK on the CAP, EAPOL `0x201c` → `0x201b` → `0x201f`.
* ~~Legacy mode not fully passive~~ — `own_service()` returns immediately when
  the policy is legacy, so a stale journal cannot start hostapd on a netifd BSS.
* ~~Factory reset unproven~~ — the zero-touch image is flashed and re-provisions
  8/8 by itself.
* ~~`service restart` came back 6/8 (F45)~~ — the journal rebuild/reconcile
  fixes it; a restart now converges to 8/8, and boot/factory reset are always
  8/8.

Still open, in priority order:

1. **Slave VAPs in the single-identity topology (F58–F60).** Only the master
   BSS per radio authenticates; use solo or multi-identity when every SSID must
   authenticate.
2. **Secure datachan (`a2=2`).** Codec and KATs are done, and the reference
   RB1100 has now been observed sending `a2=2` with a working encrypted
   datachan (F72). The manager-side key install still never succeeds on a
   radio-less CHR, so the CHR lab remains unable to exercise it.
3. **Soak / concurrency.** SAE, OWE and PMF across several VAPs at once, GTK
   rekey under load, and a hardware matrix beyond the two reference devices.
   OWE itself is live now (CAP-local OWE, F80); the remaining item is scale.
4. **6 GHz / MLO.** The 6 GHz SAE datapath and `6ghz-ax` are proven at
   20/40/80/160 (F85); 320 is manager-accepted but hostapd runs 20 MHz (F89).
   Real 6 GHz RF/AFC and ath12k per-link MLO plumbing are not implemented.
   The Deco BE65 is read-only; the hardware plan is
   `docs/HARDWARE-6GHZ-MLO-PLAN.md`.
5. **Boot-time PSK pull** for local forwarding — validated prototype only; the
   supported path is `traffic-processing=on-cap` with the manager as
   authenticator.

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
| VAP lifecycle | `0x600c` stop hostapd, delete netdev, release vapid, reap orphans | W52 | ✅ live 3 cycles × 8 VAPs |
| 5 GHz BSS | MT76x02 BSS index, `noscan`, regulatory, `-EALREADY` tolerated | W54, `9999d` | ✅ live `AP-ENABLED` |
| Group keys | `0x201f` GTK/IGTK → nl80211 | T3, T9, T14 | ✅ |
| Datachan framing | `10`, control byte, cdh, payload; keepalive and sequence | T1, T8, S8 | ✅ |
| Datachan plain/secure | `a2=1` plain, `a2=2` AES-CCM; `a7` advertised, not the selector | T11, S2, S8, F70/F72 | ✅ protocol |
| Rekey | `0x402b` 41 B, slot 0/1, empty `0xc02b`, 1 s purge | T8 | 🟡 protocol proven |
| Association | `0x2018` Auth + AssocReq creates Peer + row | T6, T13 | ✅ live |
| EAPOL relay | `0x201b`/`0x201c`, per-BSS extmux relay | T3, T4, T14, W8 | ✅ live RB1100 |
| Key install / authorize | PTK via `0x201f`, `SET_STATION AUTHORIZED` | T3, T14 | ✅ **live** (`authorized: yes`, ping) |
| Hostapd patch | `external_rsn_auth` + `external_rsn_ie` | T10, T12, W21 | ✅ patch series in `patches/` |
| RSN IE equality | manager's 28-byte IE replayed byte-for-byte | W21, live station | ✅ live, no IE mismatch |
| Zero-touch image | capagent + patched `wpad` + self-enrolment, verified by unsquashfs | F42/F43/F46 | ✅ **flashed**, 8/8 after factory reset |
| Statistics | corrected `0x2015`, `0x200e`, `0x2013` | T7, T15 | ✅ sender |
| PSK carriers | not serialized by CAPsMAN v2 | S5, S9 | — by design |
| Boot-pull | REST pull of config/passphrase at boot | S9 | 🟡 prototype |
| Secure datachan e2e | `a2=2` live on the RB1100 (F72); manager key install still absent on the radio-less CHR | T9, T10, F72 | ✅ live; CHR lab 🟡 |

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
Certificates are expected at `/etc/cap/client.pem` and `/etc/cap/client.key`;
if they are missing the agent enrols itself (below).

### Certificate lifecycle (zero-touch enrolment)

On first boot (factory reset) `/etc/cap` is empty. The agent then:

1. generates an EC P-256 key **on the CAP** (`client.key`, mode 0600);
2. sends a PKCS#10 CSR in the join (`0x4029` TLV `0x76`) with the CN
   `<identity>-<8 random hex>` — a fresh CN every time, because RouterOS
   refuses to issue a second certificate for an existing CN;
3. receives the signed leaf and the CAPsMAN CA in the join reply
   (`0xc029` TLVs `0x77`/`0x78`), verifies the leaf against the CA and against
   its own key, and atomically writes `client.pem`, `ca.pem` and `client.key`;
4. keeps using that certificate on every later join (mTLS), pinning the
   manager against the saved `ca.pem`.

A stored certificate that is expired is replaced. A manager CA rotation is
detected as a TLS verification failure and triggers a new enrolment. A
duplicate-CN rejection from the manager triggers a retry with a fresh CN.
Retries are spaced (5 s doubling to 60 s), never a busy loop, and every step
logs a `cert:` line.

Requirements and limits:

* the manager must have `require-peer-certificate=no` (default) at least
  until the CAP has enrolled; with `yes` a certificate-less CAP is rejected
  during the handshake and needs a pre-provisioned certificate;
* the first enrolment is trust-on-first-use: set `MANAGER` and/or
  `LOCK_TO_CAPS_MAN=yes` if the network is hostile;
* `--enroll` forces a new certificate, `--no-enroll` disables enrolment, and
  `--cert-cn CN` pins the CN (a duplicate adds a random suffix);
* `/etc/cap` must be writable (it is on the overlay).

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

For the exact SDK/toolchain paths used for the original 0.4.0 build, the hostapd and
wifi-scripts package recipe, the patch-series check and the recorded hashes,
see [`docs/BUILD.md`](docs/BUILD.md). The build is reproducible: two clean
clones of the same commit produce the same binary.

The version is printed by `capagent --version` (`0.7.1`) and stored in
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
`MACS`, `SERIAL`, `A1`, `E70`, `A7`.

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
│   ├── README.md             # index of canonical docs
│   ├── RELEASES.md           # release-note index
│   ├── CAPSMAN-COVERAGE.md   # which manager settings are proven and which are not
│   ├── MANAGER-ONLY.md       # zero-local-config reproduction
│   ├── MULTI-IDENTITY.md     # one identity per SSID, and the one-CAP solo mode
│   ├── 6GHZ-HWSIM.md         # 6 GHz on a virtual radio (6ghz-ax / 6ghz-be)
│   ├── 11K-HWSIM.md          # 11k/11v on a virtual station
│   ├── OPEN-PROBLEMS.md      # tracked blockers + verified facts
│   ├── ARCHITECTURE.md       # datapath modes and split-MAC chain
│   ├── FINDINGS.md           # control protocol / TLV reference
│   ├── REGRESSION-GATE.md    # acceptance modes, pass rules, baselines
│   ├── RELEASE-*.md          # per-release notes (history)
│   ├── history/              # superseded work reports (not current)
│   └── patches/              # hostapd 9997-external-rsn-ie.patch
├── native/
│   ├── capagent.c            # entry unit (constants + module includes)
│   ├── src/                  # protocol modules (util, nl80211, vap, datachan, ...)
│   ├── Makefile
│   ├── enroll.py             # certificate enrollment helper
│   └── deploy/               # OpenWrt init script, preflight, example conf, tools
├── patches/                  # full hostapd patch series (999 ... 9999j)
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
