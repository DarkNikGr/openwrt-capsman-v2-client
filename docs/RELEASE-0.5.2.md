# v0.5.2 — on-cap datapath out of the box, PMF required, PMF/SAE verified

Patch release on v0.5.1. Three things became true on hardware and one of them
changes the shipped defaults.

## Highlights

* **The on-cap datapath is proven end to end.** After the last round of fixes a
  station associates, is authorized, and `ping` runs **3/3 with 0% loss** in
  both directions. Two bugs were behind the earlier failures:
  * `ctrl_interface=` was emitted only in the first `bss=` section, so hostapd
    created a control socket for the master BSS alone and `EXT_AUTH_AUTHORIZE`
    for a secondary could never be delivered — the station stayed
    unauthenticated in the driver while the manager had already installed the
    PTK. It is now repeated in every section (one socket per BSS).
  * extmux's abstract source address can already be taken, leaving no control
    socket at all; the authorize then waited for the 4-way deadline and
    deauthenticated. With no control socket the agent authorizes through
    nl80211 immediately.
* **The image now ships the firewall zone for those bridges.** `br-vlan<N>` is
  created on demand, and `/etc/uci-defaults/99-cap-firewall` adds
  `zone capvlan { device 'br-vlan*', input ACCEPT, forward REJECT }` on first
  boot, so traffic addressed to the CAP is not rejected by the default input
  policy. Verified on a clean flash: `uci get firewall.capvlan.device` →
  `br-vlan*`, `nft` shows `iifname "br-vlan*" jump input_capvlan`, four bridges
  appear by themselves.
* **`management-protection=required` works live.** The manager's RSN caps carry
  MFPR, the CAP writes `ieee80211w=2` with the same 28-byte element
  (`…02c0…`), and a station with `ieee80211w=2` associates: `authorized: yes`,
  `SET_STATION MFP ret=0`, `ping` 3/3.
* **`MGMT_SOURCE=off` is now the shipped default.** The no-monitor ext-auth path
  is the one that is proven with a station on a 4-vif radio; monitor mode costs
  a vif slot on 2.4 GHz and the station never completed the 4-way there. The
  gateway image bakes `MANAGER=<address>` and `MGMT_SOURCE=off`.

## Verified on

Xiaomi Mi Router 4A Gigabit + RB1100AHx4 / RouterOS 7.25.1, image written with
`sysupgrade -n`: 8/8 SSIDs, patched `wpad` (no debug probes), certificate
enrolment, `br-vlan*` zone and bridges without any manual step, station
`authorized: yes`, `ping 0% loss`.

Image sha256 `9f72ba5d18509d1803fb9ca973ef20b506ec9b89c9fad9823a7a5e43b8edd707`.

## Artifacts

| Asset | What it is |
|---|---|
| `capagent-mipsel` | bare static client, mips/mipsel OpenWrt (reference Xiaomi) |
| `capagent-aarch64` | bare static-pie client, aarch64 OpenWrt (WiFi 6/7 APs) |
| `capagent-*-bundle.tar.gz` | the binary + `install.sh` + `capagent.conf.example` |
| `mi-4a-zero-touch-sysupgrade.bin` | full zero-touch image (capagent + patched wpad + firewall zone) |
| `SHA256SUMS` | hashes for everything above |

## Still open

* `wpa2-eap` / RADIUS — a FreeRADIUS server is prepared (10.0.0.3, PEAP and
  TTLS/PAP, `eapol_test` SUCCESS) but the manager profile and the station are
  not wired yet.
* Secure c2 datachan (`a2=2`): never live.
* `MANAGER=auto`: OpenWrt's `udhcpc` does not export RouterOS DHCP option 138.
* ACL/multi-passphrase, 802.11k/v/r, tx-power/beacon tuning, local-forwarding,
  6 GHz/MLO — see `docs/CAPSMAN-COVERAGE.md`.
