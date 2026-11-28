# v0.6.5 — OWE live, `a2=1` datachan live, and a live security change keeps 8/8

Feature release on v0.6.4. The one-CAP/eight-radio solo topology is unchanged;
this release closes the three remaining CAP-side gaps.

## OWE is live (CAP-local OWE)

RouterOS 7.25.1 never sends a DH-bearing `0x6019` for an OWE association: the
CAP relays the station's AssocReq and the manager answers with `0x2019 deauth`.
The CAP now leaves a **pure-OWE** VAP to its own hostapd: it writes
`wpa_key_mgmt=OWE`, `ieee80211w=2`, keeps the manager's SSID/RSN IE/channel and
VLAN, but omits `external_rsn_auth`, `external_rsn_sae` and the ext-auth
socket. The manager still provisions the VAP; the CAP derives the OWE PMK from
the station's DH element and runs the 4-way locally.

```
wlp39s0: OWE: Diffie-Hellman Parameter element - hexdump(len=37): ff 23 20 13 00 ...
wlp39s0: RSN: RX message 3 of 4-Way Handshake ... (AKM-defined - OWE)
wlp39s0: CTRL-EVENT-CONNECTED - Connection to 02:d1:27:1b:2d:a4 completed
authorized: yes
3 packets transmitted, 3 received, 0% packet loss
```

`CAPAGENT_LOCAL_OWE=0` restores the old relay for a manager that implements
manager-side OWE. The manager's registration table does not list a local-OWE
client.

## `traffic-processing=on-capsman` (`a2=1`) is live

The `a2` variant is **per VAP**, not per datachan: the manager sends one
`0x500b` per VAP and the on-cap VAPs carry `a2=0`. Keeping only the last value
made a 5 GHz `a2=1` VAP parse its frames as AES-CCM after a later `a2=0`
create (`datachan auth failed`). The variant is now stored in the VAP and used
for RX and TX.

On the Xiaomi 5 GHz radio the manager sends `a2=1` (key + cookie + `0x7d`);
with `DATACHAN=yes` and `DATAPATH_BRIDGE=yes` a station on that VAP is
`authorized: yes` and pings 3/3 0% with `datachan plain` frames both ways. The
2.4 GHz radio gets `a2=0`: the manager refuses on-capsman for that radio class.
`a2=2` remains live on the RB1100 (v0.5.9).

## A live security change keeps 8/8

`0x6017` now tears down every local VAP and stops every per-radio hostapd
before re-joining, so the manager's `0x500b/0x6016` burst rebuilds from a clean
journal like a cold boot. Previously the race could leave 5 GHz BSSes down
until `/etc/init.d/capagent restart`.

Verified with a `sec-iot` passphrase change:

```
RX 0x6017 configuration changed (len=0) -> re-joining the manager
0x6017: tearing down local VAPs before re-join
ssids=8 capagent=1 hostapd=10
cap-iot 2.4 GHz: authorized: yes, 3/3, 0%
cap-iot 5 GHz : authorized: yes, 3/3, 0%
```

## Also in this release

* The BSSID allocator keeps a manager BSSID when its **exact** address is free
  on the real phy, not when its driver index bit is free. This fixes a slave
  VAP whose manager BSSID shares its parent's byte 0 (e.g. `2A:…:90` →
  `2A:…:91`) and removes an unnecessary remap that broke the manager 4-way.
* The init combines `CAPAGENT_RUN_TAG` and the OWE switch in one
  `procd_set_param env` call; a second call replaced the first and silently
  dropped `RUN_TAG=solo`.
* `capagent-solo.conf` documents `DATACHAN`/`DATAPATH_BRIDGE` and
  `LOCAL_OWE`.

## Soak and regression

* **10/10 cold reboots** reached `ssids=8 capagent=1 hostapd=10` (5/8 at
  two minutes, all eight by three minutes; no stuck BSS, no manual step).
* **GTK rekey**: with `security.group-key-update=30s` a station held for 70 s
  logged `RSN: Group rekeying completed with … [GTK=CCMP]` and pinged 3/3 0%;
  the CAP installed `0x201f NEW_KEY GROUP idx=1/2` and relayed `0x201c`.
* **Live `0x6017` passphrase change** kept 8/8 (the teardown path above).
* Final regression after the soak/rekey: all eight SSIDs
  `authorized: yes`, 3/3, 0% (2.4 and 5 GHz test/guest/iot/hidden).

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1, one
`cap=OpenWrt-CAPSOLO` entry with eight radios. Cold boot and the live security
change both give `ssids=8`, `capagent=1`, `hostapd=10`; all eight station
tests are `authorized: yes`, 3/3, 0%.

Image sha256 `58ab0c2ecd2cf17257c670a91bebd5f158f0cf276a1b3c47e9fb28cc8cdd5dd9` (7,472,226 B).

## Still open

* `on-capsman` on the 2.4 GHz radio (manager returns `a2=0`; 5 GHz is live).
* Slave-VAP authentication in the plain single-identity topology.
* `6ghz-ax` as a configuration value (vendor-blocked; `6ghz-be` works).
* Real 6 GHz/MLO hardware, soak/concurrency beyond the reference devices.
