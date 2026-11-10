# Manager-only provisioning

How far this CAP gets towards the actual goal: **an OpenWrt AP with no local
wireless configuration that is provisioned entirely by an unmodified RouterOS
7.25.1 CAPsMAN v2 manager.** This page records what is proven, what is still
open, and how to reproduce the zero-local-config experiment on the bench.

The goal is **not met yet**. Everything below is measured on:

* CAP: Xiaomi Mi Router 4A Gigabit Edition (ramips/mt7621, OpenWrt 24.10,
  MT7603E `phy0` 2.4 GHz + MT7612E `phy1` 5 GHz)
* Manager: RB1100AHx4, RouterOS 7.25.1, CAPsMAN v2 enabled

---

## 1. What works (proven)

| # | Result | Evidence |
|---|---|---|
| 1 | With **zero `wifi-iface`** in `/etc/config/wireless` the manager still provisions **8/8 VAPs** — `0x500b` for both radios, `0x6016` for ports `0x0000`, `0x0100`, `0x0001`–`0x0003`, `0x0101`–`0x0103`, plus 6 `0x201f` key installs. The `0xd00b` reply we already send is accepted. | live zero-config run; `docs/OPEN-PROBLEMS.md` F7 |
| 2 | capagent **creates the AP netdev itself** from `0x500b` (MAC from TLV `0x08`, `NL80211_CMD_NEW_INTERFACE` type `__ap`), so the `0xd00b` reply carries a real `ifindex`. | `native/src/vap.inc`, commit `1bd9d78` |
| 3 | capagent **starts one hostapd per VAP** from `0x6016` (SSID `0x03`, IE blob `0x04`, channel `0x0a`): `external_rsn_auth=1`, `ext_auth_socket=/var/run/hostapd/ext-auth-<ifname>`, **no PSK anywhere in the generated config**. Live: 8/8 netdevs and 8 hostapd instances; the four 2.4 GHz BSSes beacon the manager's SSIDs. | `native/src/vap.inc`; `docs/OPEN-PROBLEMS.md` F8 |
| 4 | **EAPOL relay works on the real manager**: station M2 → `0x201b` → manager runs the 4-way → `0x201c` M3 back to the station. | live RB1100 log `EXT-AUTH: EAPOL ... -> 0x201b` |
| 5 | **RSN-IE equality**: the manager's 28-byte M3 RSN IE (`… 80 00 00 00 00 0f ac 06`, MFPC + BIP-CMAC) differs from what hostapd generates (`… 8c 00`, 22 B). Patch `docs/patches/9997-external-rsn-ie.patch` adds `external_rsn_ie=<hex>` and hostapd then emits the manager's element **byte-for-byte** in Beacon / Probe Response / (Re)Assoc Response / EAPOL. capagent writes the option automatically when the installed `wpad` contains the string. | `docs/patches/9997-…`; host log `RSN: Own IEs` identical; qemu-mipsel parse check |

The manager is the RSN authenticator in all of this: it holds the passphrase,
derives PTK/GTK/IGTK and sends only derived key material (`0x201f`). No PSK,
PMK or passphrase is sent to the CAP on any channel.

### Message → local action

| Manager message | CAP action |
|---|---|
| `0x4029` join → `0xc029` | TLS 1.2 session, identity/board/serial/MACs |
| `0x001d` NEWPHY | radios, bands, ciphers, `0x84` datachan capability |
| `0x500b` create-vap | `phyX-apY` netdev with the `0x08` MAC, VLAN `0x7d`; reply `0xd00b` with `ifindex` + channel set |
| `0x6016` start | `/tmp/vap-<ifname>.conf` from SSID + RSN IE + channel, `hostapd -B`, ack `0xe016` |
| `0x2018` | raw Auth/AssocReq relay (**CAP → manager**; the manager's own copy is ignored) |
| `0x201b` / `0x201c` | EAPOL from STA / EAPOL to STA |
| `0x2019` | Auth responses discarded, Deauth/Action transmitted, ack `0xe019` |
| `0x201f` | PTK/GTK/IGTK install via nl80211, `SET_STATION AUTHORIZED`, ack `0xe01f` |
| `0x600c` | **not implemented** — see open item 1 |

---

## 2. What is still open

### 2.1 VAP lifecycle duplication

`0x600c` (destroy) never stops the per-VAP hostapd, deletes the netdev or
releases the vapid. A second create cycle for the same port can therefore run
two hostapd instances against one interface, or wedge on a stale pid file.
`vapid_release()` exists in `native/src/channels.inc` but no handler calls it
yet. The manager's port-reuse/recreate churn is the trigger seen in the lab.

### 2.2 5 GHz hostapd start

In this tree, hostapd refuses to start the 5 GHz BSSes on the MT7612E. On the
2.4 GHz radio the four BSSes come up; on 5 GHz the interface stays
`DISABLED`. The generated config asks for VHT80 without the two values hostapd
needs to resolve an 80 MHz channel (`vht_oper_centr_freq_seg0_idx`, HT40
secondary) and does not set a regulatory domain, so a zero-local-config boot
has no usable 5 GHz AP channel. A candidate fix was investigated separately
(country code + `ieee80211h`, `ht_capab`, `vht_oper_centr_freq_seg0_idx`); it
is **not part of 0.4.0**.

### 2.3 The image has not been flashed

A sysupgrade image (client + certificate + CA + patched `wpad`, no SSH, no
firewall, no DHCP server, factory-reset handler) was built and verified at the
**content level** (55/55 static checks: ROM binaries, certificate/key match,
`external_rsn_ie` present in `wpad`, no `wifi-iface` in any ROM config, WAN
DHCP, reset button handler). It was **never written to the device**, so:

* boot + auto-provision after a real flash is unproven;
* **factory reset → rejoin → 8/8 VAPs is unproven on hardware**;
* the station-side M3 comparison with the patched `wpad` (no
  `IE in 3/4 msg does not match`) has not been observed on a real client.

Those three are the remaining acceptance items. Until they pass, the project
must not claim the goal is achieved.

---

## 3. Reproducing the zero-config experiment

### 3.1 Prerequisites

* OpenWrt 24.10 on the CAP, with the stock `wpad` replaced by a build carrying
  `CONFIG_EXTERNAL_RSN_AUTH=y`, `999-external-rsn-auth.patch`,
  `9997-external-rsn-ie.patch`, `9998-external-rsn-eapol-rx.patch`,
  `9999-external-rsn-no-psk.patch`.
* A CAP certificate trusted by the manager (`/etc/cap/client.pem`,
  `/etc/cap/client.key`, optional `/etc/cap/ca.pem`).
* Manager reachable over TLS 5246, CAPsMAN enabled, provisioning rules for the
  two radio MACs.

### 3.2 Build and install capagent

```sh
# SDK with mbedTLS staged (make package/libs/mbedtls/compile in the SDK)
make -C native SDK=/path/to/openwrt-sdk
# or: MBEDTLS_INC=... MBEDTLS_LIB=... make -C native SDK=...
# aarch64:
TOOLCHAIN=.../aarch64-linux-musl-cross/bin MBEDTLS=.../mbedtls-aarch64 \
    ./scripts/build-aarch64.sh
```

`make` writes `native/capagent-mipsel`; the scripts write `dist/`. Then on the
CAP:

```sh
install -m 0755 capagent-mipsel /usr/sbin/capagent
mkdir -p /etc/cap
install -m 0600 native/deploy/capagent.conf /etc/cap/capagent.conf
capagent --version        # capagent 0.4.0
```

### 3.3 Remove every local BSS

The experiment only means something if the CAP has no local SSID. Reduce
`/etc/config/wireless` to the radio definitions and **no `wifi-iface`**:

```
config wifi-device radio0
	option band 2g
	option channel 6
	option htmode HT20
	option disabled 0

config wifi-device radio1
	option band 5g
	option channel 36
	option htmode VHT80
	option disabled 0
```

```sh
wifi up
iw dev | grep -c ssid      # must print 0
```

### 3.4 Start the agent with the manager-driven paths

Stop the init script first so there is exactly one instance (the packaged init
passes the same options):

```sh
/etc/init.d/capagent stop
CAPAGENT_DEBUG=1 /usr/sbin/capagent \
    --manager auto --discovery-interfaces wan \
    --cert /etc/cap/client.pem --key /etc/cap/client.key \
    --dont-verify-certificate \
    --vap-auto \
    --mgmt-relay --mgmt-source monitor \
    --ext-auth-dir /var/run/hostapd \
    --eapol-leg both \
    --datachan
```

`--vap-auto` is the default in 0.4.0; it is stated here to make the experiment
explicit. `--datachan` is for split-MAC; it is not needed to prove VAP
creation and can be omitted.

### 3.5 What the CAP log must show

```
NEWPHY phy=0 mac=28:d1:27:1b:2d:82
NEWPHY phy=1 mac=28:d1:27:1b:2d:83
RX 0x500b phy=0 vap=0 a2=0 len=129
vap: created phy0-ap0 ifindex=10 phy=0
EXT-AUTH: bound /var/run/hostapd/ext-auth-phy0-ap0 ...
0xd00b phy=0 vapid=0 ifindex=10 ifname=phy0-ap0
RX 0x6016 start port=0x0000 -> ack 0xE016
vap: hostapd phy0-ap0 ssid=cap-test freq=2437 akm=psk mfp=1 vlan=1
...
RX 0x6016 start port=0x0103 -> ack 0xE016
RX 0x201f key-install port=0x... (6 messages)
```

The eight ports are `0x0000`, `0x0100`, `0x0001`–`0x0003`, `0x0101`–`0x0103`
(`(phy << 8) | vapid`). A replay of the pre-`1bd9d78` client instead shows
`ifindex=0` and no `vap: created` line — that is the bug the VAP work fixed.

### 3.6 Verify locally

```sh
iw dev                       # phy0-ap0..3 up with the manager SSIDs
ls -l /tmp/vap-*.conf        # one generated config per VAP
grep -c external_rsn_auth /tmp/vap-*.conf
pidof hostapd | wc -w        # one hostapd per VAP (8 with both radios)
logread | grep -E 'vap: created|vap: hostapd|EXT-AUTH'
```

Check that no generated config contains a passphrase:

```sh
grep -n 'wpa_passphrase' /tmp/vap-*.conf || echo "no PSK on the CAP"
```

### 3.7 Verify RSN-IE equality

```sh
# one line per BSS; the hex must equal element 0x04 of the manager's 0x6016
logread | grep 'EXT-AUTH: advertising external RSN IE'
# EXT-AUTH: advertising external RSN IE (28 bytes):
#   301a0100000fac040100000fac040100000fac0280000000000fac06
```

On the station, `wpa_supplicant -dd` must **not** print
`WPA: IE in 3/4 msg does not match with IE in Beacon/ProbeResp`, and must reach
`WPA: Key negotiation completed` / `CTRL-EVENT-CONNECTED`. If the option is
missing from the generated config, the installed `wpad` does not contain
`external_rsn_ie` (capagent probes the binary before writing it) and the old
22-byte generated IE is used.

### 3.8 Verify on the manager

```routeros
/interface wifi capsman remote-cap print detail where identity="OpenWrt-CAP3"
/interface wifi radio print detail
/interface wifi print count-only where name~"cap-"
/interface wifi print detail where name~"cap-"
```

Expected: `state="Ok"`, two radio rows with distinct MACs, eight `cap-` VAPs
(four SSIDs × two radios), all bound. `0xd00b` acceptance is visible as the
rows existing at all; the `I` (inactive) flag can persist while the data
channel is not in use and is not part of provisioning success.

### 3.9 Manager-side setup used in the run

```routeros
/interface wifi security
add name=sec-main  authentication-types=wpa2-psk passphrase=<manager-only>
add name=sec-guest authentication-types=wpa2-psk passphrase=<manager-only>
add name=sec-iot   authentication-types=wpa2-psk passphrase=<manager-only>

/interface wifi datapath
add name=dt-main vlan-id=1
add name=dt-guest vlan-id=10
add name=dt-iot  vlan-id=20
add name=dt-hidden vlan-id=99

/interface wifi configuration
add name=cfg-hidden ssid=cap-hidden datapath=dt-hidden hide-ssid=yes \
    channel.frequency=2437 channel.band=2ghz-g channel.width=20mhz
add name=cfg-main   ssid=cap-test  security=sec-main  datapath=dt-main  \
    channel.frequency=2437 channel.band=2ghz-g channel.width=20mhz
add name=cfg-guest  ssid=cap-guest security=sec-guest datapath=dt-guest \
    channel.frequency=2437 channel.band=2ghz-g channel.width=20mhz
add name=cfg-iot    ssid=cap-iot   security=sec-iot   datapath=dt-iot   \
    channel.frequency=2437 channel.band=2ghz-g channel.width=20mhz

/interface wifi provisioning
set [find radio-mac="28:D1:27:1B:2D:82"] master-configuration=cfg-hidden \
    slave-configurations=cfg-main,cfg-guest,cfg-iot
```

Repeat with 5 GHz `cfg5-*` objects for the second radio. The hidden open
master on a dead VLAN avoids the manager's "no supported unicast ciphers"
warning on encrypted masters.

### 3.10 Rollback

```sh
/etc/init.d/capagent stop
# restore the stock wpad/wifi-scripts and the previous /etc/config/wireless
wifi reload
/etc/init.d/capagent start
```

Keep the previous `/etc/config/wireless` and the stock `wpad` ipk on the device
before starting. Do not leave a half-provisioned `phyX-apY` netdev behind:
`ip link del phy0-apN` or reboot the CAP.

---

## 4. Non-negotiable constraints for this work

* No second service on the manager, no RouterOS container, no agent inside
  RouterOS.
* No SSH-driven bootstrap on the CAP; no local `wireless` file as the source
  of truth.
* The CAP must never receive the PSK when the manager is the authenticator.
* Any claim about factory reset or hardware behaviour needs a log from the
  device, not a static image check.
