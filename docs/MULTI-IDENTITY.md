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
add radio-mac=02:D1:27:1B:2D:A0 action=create-dynamic-enabled \
    master-configuration=cfg slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A1 action=create-dynamic-enabled \
    master-configuration=cfg-guest slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A2 action=create-dynamic-enabled \
    master-configuration=cfg-iot slave-configurations=""
add radio-mac=02:D1:27:1B:2D:A3 action=create-dynamic-enabled \
    master-configuration=cfg-hidden slave-configurations=""
```

The radio MACs are arbitrary: they only have to be unique and match the rule.
The CAP's instance advertises them via NEWPHY.

## Host configuration

`/etc/cap/identities.conf`:

```
# tag identity      radio-mac[,radio-mac...]
a     OpenWrt-CAPA  02:D1:27:1B:2D:A0,02:D1:27:1B:2D:A4
b     OpenWrt-CAPB  02:D1:27:1B:2D:A1,02:D1:27:1B:2D:A5
c     OpenWrt-CAPC  02:D1:27:1B:2D:A2,02:D1:27:1B:2D:A6
d     OpenWrt-CAPD  02:D1:27:1B:2D:A3,02:D1:27:1B:2D:A7
```

then `scripts/multi-cap.sh start` (and `stop` / `status`). Each identity
enrols its certificate on first start.

## What was proven live

Xiaomi Mi Router 4A Gigabit (ramfs/mt7621), RB1100AHx4 / RouterOS 7.25.1,
four identities on the **2.4 GHz** phy, all at 2437 MHz, one SSID each:

| SSID | identity | netdev | station |
|---|---|---|---|
| cap-test | A | `phy0-aap0` | `authorized: yes`, ping 3/3, 0% |
| cap-guest | B | `phy0-bap0` | `authorized: yes`, ping 3/3, 0% |
| cap-iot | C | `phy0-cap0` | `authorized: yes`, ping 3/3, 0% |
| cap-hidden | D (hidden) | `phy0-dap0` | `authorized: yes`, ping 3/3, 0% |

Each BSS is bridged to its VLAN bridge after hostapd brings it up, because a
bridged AP interface cannot be opened while another AP is running on the same
phy (`bridge=` is skipped for tagged instances).

## Limits

* **5 GHz: one hostapd set, and its secondaries must use driver MACs.**
  A merged config with four `bss=` sections and the working single-instance
  globals brings up four BSSes when the secondaries keep the driver's derived
  addresses; with the manager's BSSIDs the second secondary fails at bring-up
  (`Resource busy`), and a second hostapd process on the same phy always fails.
  Because the manager checks the BSSID and the PTK is derived over it, a
  secondary cannot authenticate with the manager's VAP BSSID. **Maximum
  working set: four 2.4 GHz identities + one 5 GHz master** (F66).
* The 2.4 GHz phy carries four AP vifs (the mt76 limit).
* Do not run the regular single-identity capagent on the same phy: the vif
  budget is shared.
