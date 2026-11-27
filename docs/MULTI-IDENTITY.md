# Multi-identity CAP: one SSID per CAP identity

A RouterOS CAPsMAN v2 manager provisions **one radio master** per CAP radio.
Everything else becomes a *virtual* (slave) interface, and on this manager a
station on a virtual VAP never reaches the 4-way: the CAP relays the Auth and
AssocReq (`0x2018`) and the manager answers nothing (`registration-table`
empty, `4-way timeout … m1=0`, see F58–F60). Only a master BSS is answered.

The workaround is to present **one CAP identity per SSID**: each identity
advertises its own "radio" (a MAC the manager keys provisioning on) and that
SSID is provisioned as the master of that radio. The manager still owns the
SSID, security and VLAN; the CAP merely stops relying on virtual-VAP routing.

```
manager                              host
┌──────────────────────────┐         ┌───────────────────────────────┐
│ rule radio=…A0 master=cfg│◀──TLS──▶│ capagent tag=a  (OpenWrt-CAPA)│ phy0
│ rule radio=…A1 master=…  │◀──TLS──▶│ capagent tag=b  (OpenWrt-CAPB)│ phy0
│ rule radio=…A2 master=…  │◀──TLS──▶│ capagent tag=c  (OpenWrt-CAPC)│ phy0
│ rule radio=…A3 master=…  │◀──TLS──▶│ capagent tag=d  (OpenWrt-CAPD)│ phy0
│ rule radio=…90 master=…  │◀──TLS──▶│ capagent tag=e  (OpenWrt-CAPE)│ phy1
│ rule radio=…90 master=…  │◀──TLS──▶│ capagent tag=f  (OpenWrt-CAPF)│ phy1
│ rule radio=…90 master=…  │◀──TLS──▶│ capagent tag=g  (OpenWrt-CAPG)│ phy1
│ rule radio=…90 master=…  │◀──TLS──▶│ capagent tag=h  (OpenWrt-CAPH)│ phy1
└──────────────────────────┘         └───────────────────────────────┘
```

Each instance has its own certificate (`/etc/cap/id-<tag>.pem`), state journal
(`/var/run/caps<tag>.state`), ext-auth directory (`/var/run/hostapd<tag>`) and
hostapd config/pid/log suffix (`CAPAGENT_RUN_TAG=<tag>`). The tag also changes
the netdev names (`phy0-<tag>ap0`), so the phy-wide cleanup of one instance
never touches another instance's interfaces.

## Manager configuration

One provisioning rule per identity, no slaves:

```
/interface wifi provisioning
# 2.4 GHz identities (all have their own fake radio)
add radio-mac=02:D1:27:1B:2D:A0 action=create-dynamic-enabled \
    master-configuration=cfg slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A1 action=create-dynamic-enabled \
    master-configuration=cfg-guest slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A2 action=create-dynamic-enabled \
    master-configuration=cfg-iot slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A3 action=create-dynamic-enabled \
    master-configuration=cfg-hidden-sec slave-configurations=""
# 5 GHz identities (fake radios; the first byte must be unique per phy)
add radio-mac=2A:D1:27:1B:2D:90 action=create-dynamic-enabled \
    master-configuration=cfg5 slave-configurations=""
add radio-mac=2E:D1:27:1B:2D:90 action=create-dynamic-enabled \
    master-configuration=cfg5-guest slave-configurations=""
add radio-mac=22:D1:27:1B:2D:90 action=create-dynamic-enabled \
    master-configuration=cfg5-iot slave-configurations=""
add radio-mac=26:D1:27:1B:2D:90 action=create-dynamic-enabled \
    master-configuration=cfg5-hidden-sec slave-configurations=""
```

The radio MACs are arbitrary: they only have to be unique, match the rule and
follow the per-phy first-byte rule below. The CAP's instances advertise them
via NEWPHY (one identity per radio).

## Host configuration

`/etc/cap/identities.conf` — **eight instances**, four per phy (a shipped
example is `/etc/cap/identities.conf.example`):

```
# tag identity      radio-mac[,radio-mac...]
a     OpenWrt-CAPA  02:D1:27:1B:2D:A0                       # 2.4  cap-test
b     OpenWrt-CAPB  02:D1:27:1B:2D:A1                       # 2.4  cap-guest
c     OpenWrt-CAPC  02:D1:27:1B:2D:A2                       # 2.4  cap-iot
d     OpenWrt-CAPD  02:D1:27:1B:2D:A3                       # 2.4  cap-hidden
e     OpenWrt-CAPE  02:D1:27:1B:2D:B0,2A:D1:27:1B:2D:90      # 5 GHz cap-test
f     OpenWrt-CAPF  02:D1:27:1B:2D:B1,2E:D1:27:1B:2D:90      # 5 GHz cap-guest
g     OpenWrt-CAPG  02:D1:27:1B:2D:B2,22:D1:27:1B:2D:90      # 5 GHz cap-iot
h     OpenWrt-CAPH  02:D1:27:1B:2D:B3,26:D1:27:1B:2D:90      # 5 GHz cap-hidden
```

Instances `e`–`h` advertise two radios so that the *second* (5 GHz) wiphy is
used: radio 0 (`B0`…`B3`) has no provisioning rule and stays idle, radio 1
(`2A`/`2E`/`22`/`26`) is the 5 GHz master. Do **not** give one instance two
radios that both need provisioning when several instances share the manager:
the manager provisioned only one of the two (the other stayed disabled) in
testing.

The init script uses this file automatically (one procd instance per line).
`scripts/multi-cap.sh start` / `stop` / `status` is the manual launcher for
debugging; it uses the same file. Each identity enrols its certificate on
first start.

Starts are **staggered**: with one phy shared by four hostapd instances,
opening them at the same instant loses the driver race and leaves orphan AP
vifs that advertise the SSID but answer no authentication (F75). The init
script delays identity *n* by `n × CAPAGENT_STAGGER` (default 15 s, set
`CAPAGENT_STAGGER=20` in `capagent.conf` to match the manual launcher); the
manual launcher uses `DELAY=20`.

Changing a security profile on the manager is picked up live: the manager
sends `0x6017`, capagent re-joins and the manager re-pushes `0x500b`/`0x6016`;
a changed SSID/RSN/channel/VLAN in a repeated `0x6016` also rebuilds the phy
hostapd (`own_cfg_hash`). Verified with a passphrase change: the VAP returned
to ACTIVE and a station with the new passphrase pinged 0%, without restarting
the identity (F76). A brand-new RouterOS security object still needs its
passphrase at creation (`must specify passphrase for PSK` otherwise).

A phy carries **four AP vifs**, so a fifth identity cannot be added while the
other four run (`ip link set … up` → `Resource busy`); to test a new identity,
replace one line temporarily (the stagger restarts the service). When a tag is
removed from the file its hostapd/vif can survive the restart and steal the
free slot (F77): kill the hostapd named in `/tmp/cap-phyN-<tag>.conf`, delete
the `phyN-<tag>apM` netdev and restart before adding a different identity.

### First-byte rule on 5 GHz (F74)

The mt76x2 driver derives the **BSS index from the first byte** of the
interface address. Two AP vifs whose first byte is equal collide: the second
`ip link set … up` fails with `EBUSY` (or the BSS never starts). Every 5 GHz
identity therefore needs a **different, locally-administered unicast** first
byte: `02 06 0A 0E 12 16 1A 1E 22 26 2A 2E 32 36 3A 3E`.

* `2A/2E/22/26` → all four 5 GHz BSSes come up (driver-level test and live).
* `02` for all four → only the first comes up; the rest fail `EBUSY`.
* The 2.4 GHz phy (mt7603e) does not have this constraint; `02:…:A0..A3`
  coexist fine.

## What was proven live

Xiaomi Mi Router 4A Gigabit (ramfs/mt7621), RB1100AHx4 / RouterOS 7.25.1,
**eight identities, four per phy**, all SSIDs from the manager, one SSID each.
Station tests used `scripts/station-test.sh` with explicit `BSSID=` pinning.

2.4 GHz (phy0, 2437 MHz, mt7603e):

| SSID | identity | netdev | BSSID | VLAN | station |
|---|---|---|---|---|---|
| cap-test | A | `phy0-aap0` | `02:…:a0` | 30 | `authorized: yes`, ping 3/3, 0% |
| cap-guest | B | `phy0-bap0` | `02:…:a1` | 10 | `authorized: yes`, ping 3/3, 0% |
| cap-iot | C | `phy0-cap0` | `02:…:a2` | 20 | `authorized: yes`, ping 3/3, 0% |
| cap-hidden | D (hidden) | `phy0-dap0` | `02:…:a3` | 20 | `authorized: yes`, ping 3/3, 0% |

5 GHz (phy1, 5180 MHz, mt76x2e):

| SSID | identity | netdev | BSSID | VLAN | station |
|---|---|---|---|---|---|
| cap-test | E | `phy1-eap0` | `2a:…:90` | 30 | `authorized: yes`, ping 3/3, 0% |
| cap-guest | F | `phy1-fap0` | `2e:…:90` | 10 | `authorized: yes`, ping 3/3, 0% |
| cap-iot | G | `phy1-gap0` | `22:…:90` | 20 | `authorized: yes`, ping 3/3, 0% |
| cap-hidden | H (hidden) | `phy1-hap0` | `26:…:90` | 20 | `authorized: yes`, ping 3/3, 0% |

The manager's registration table showed the same four 2.4 GHz stations with
`band=2ghz-g vlan-id=30/10/20/20`. The station profile used one 5 GHz station
(Intel 3168), so the 5 GHz runs were sequential.

Each BSS is bridged to its VLAN bridge after hostapd brings it up, because a
bridged AP interface cannot be opened while another AP is running on the same
phy (`bridge=` is skipped for tagged instances).

## Limits

* **The single-identity topology still broadcasts 8 SSIDs (4+4) but only the
  masters authenticate** on this manager (virtual VAPs never get the 4-way,
  F58–F60). Use multi-identity when every SSID must authenticate.
* Multi-identity needs one provisioning rule per fake radio; on a manager
  without those rules the identities get no configuration. A fresh
  zero-touch CAP should therefore keep the single-identity default (no
  `/etc/cap/identities.conf`).
* Four AP vifs per phy is the mt76 limit; do not run the regular
  single-identity capagent at the same time (the vif budget is shared).
