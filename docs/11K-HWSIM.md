# 802.11k live test on a virtual station (mac80211_hwsim)

The bench Intel 3168 loses the RM Enabled Capabilities element from its
Association Request (F71), so a real 11k run was never possible. A **hwsim
station** does not have that firmware: wpa_supplicant sets the Radio
Measurement capability bit, hostapd stores the RM IE, `hostapd_cli req_beacon`
sends a Beacon Request, and the station answers with a Beacon Report action
frame that patch `9999f` relays to the manager as `0x2018`.

Environment: the same `mac80211_hwsim` module and native capagent/hostapd as
[`6GHZ-HWSIM.md`](6GHZ-HWSIM.md), on 2.4 GHz.

## Setup

Manager: the normal 2.4 GHz profile (`cfg`, `cap-test`, WPA2-PSK). A CAP
identity is provisioned on the hwsim radio:

```sh
# capagent on the host, RRM advertisement + lab MFP handling
CAPAGENT_RRM=1 CAPAGENT_NO_MFP=1 CAPAGENT_HOSTAPD=<patched>/hostapd \
  capagent-host --manager 10.0.0.1 --discovery-interfaces lo --port 5246 \
    --cert /tmp/capsim/sim.pem --key /tmp/capsim/sim.key \
    --macs 02:00:00:00:00:82 --phys 16 --dont-verify-certificate \
    --identity SIM11K --eapol-leg both --mgmt-relay --mgmt-source off \
    --country GR --ext-auth-dir /tmp/capsim/ext
```

`CAPAGENT_RRM=1` writes `rrm_neighbor_report=1 rrm_beacon_report=1`; the
station's beacon then carries `46 05 72 00 00 00 00` (passive/active/table
beacon reporting).

Station (second hwsim radio, in a separate netns so the datapath is real):

```sh
# inside the netns
wpa_supplicant -dd -i wlan1 -c cap-test.conf -f /tmp/capsim/sta.log -B
```

with

```
network={
	ssid="cap-test"
	psk="cap-test-12345"
	key_mgmt=WPA-PSK
	pairwise=CCMP
	group=CCMP
	scan_freq=2437
}
```

The station log then shows:

```
RRM: Determining whether RRM can be used - device support: 0x10
RRM: Adding RRM IE to Association Request
```

## Beacon request

`req_beacon` takes the raw Measurement Request (operating class, channel,
randomization, duration, mode, BSSID). With duration 0 wpa_supplicant rejects
the request (`Beacon request: Duration is 0`); use duration 1:

```sh
hostapd_cli -p /tmp/capsim/ext -i phy0-ap0 req_beacon 02:00:00:00:01:00 \
    51060000000101020000000082
```

(0x51 = operating class 81, channel 6, randomization 0, duration 1, active
mode 1, BSSID `02:00:00:00:00:82`.)

## Evidence

Hostapd (with patch `9999i`, which keeps the station's RM capabilities even
through the external-RSN early return):

```
Beacon request: rrm-capa[0]=0x70 mode=1
mgmt::action cb ok=1
mgmt::action
Beacon report token 1 len 206 from 02:00:00:00:01:00
```

CAP agent:

```
EXTMUX: 0x2018 action port=0x0000 len=235 freq=2437
0x2018 ext 02:00:00:00:01:00 -> manager (port=0x0000 freq=2437 rssi=0 len=235)
```

So the whole 11k CAP path is live: RM advertisement → RM IE in the
(Re)Association Request → Beacon Request → **real Beacon Report action frame
from the station** → `0x2018` to the manager.

## Caveat

wpa_supplicant 2.11 on mac80211 sends the Beacon Report as an **unprotected**
robust action frame. When PMF is negotiated the AP's kernel drops it, which is
why the lab starts the CAP with `CAPAGENT_NO_MFP=1` (the manager's MFPC bit is
ignored). A station/driver that protects robust management frames (or a VAP
configured without PMF) needs no such hook. The relay itself is independent of
MFP.
