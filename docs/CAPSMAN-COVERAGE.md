# What of CAPsMAN v2 is actually covered

An honest matrix of the official manager's settings against what this CAP has
been **measured** to do. "Live" = Xiaomi Mi Router 4A + RB1100AHx4 /
RouterOS 7.25.1 with a real station; "lab" = CHR 7.25.1 + mac80211-hwsim.

> Read this before assuming "CAPsMAN works": the provisioning path and
> WPA2-PSK are proven end to end, most other per-VAP settings are not.

---

## Manager → CAP message coverage

| Message | Direction | Status | Notes |
|---|---|---|---|
| `0x4029` / `0xc029` join (TLS 5246) | both | ✅ live | plus certificate enrolment `0x76` → `0x77`/`0x78` |
| `0x001d` NEWPHY | CAP → manager | ✅ live | radios, bands, ciphers, interface count |
| `0x000a` / `0x00b7` / `0x0061` channels | both | ✅ live | one `0x0a` record per (freq, band, width) |
| `0x500b` create VAP | manager → CAP | ✅ live | MAC, VLAN (`0x7d`), datachan variant (`a2`) |
| `0xd00b` create reply | CAP → manager | ✅ live | real ifindex |
| `0x6016` start BSS | manager → CAP | ✅ live | SSID, RSN/WPA IE, channel; **never a passphrase** |
| `0x600c` destroy VAP | manager → CAP | ✅ live | stop hostapd, delete netdev, release vapid |
| `0x2018` assoc/Auth report | CAP → manager | ✅ live | `0x3e` raw frame + `0x0a` channel + `0x3f` rssi |
| `0x201b` EAPOL from STA | CAP → manager | ✅ live | per-BSS ext-auth socket |
| `0x201c` EAPOL to STA | manager → CAP | ✅ live | relayed, `ret=0` |
| `0x2019` Auth/Assoc/Deauth to STA | manager → CAP | ✅ live | deauth `ret=0` since the transport-retry fix |
| `0x201f` keys | manager → CAP | ✅ live | GTK/IGTK/BIGTK, PTK + `SET_STATION` authorize |
| `0x200e` / `0x2015` / `0x6027` stats | both | ✅ live | signal, counters, poll |
| `0x402b` datachan rekey | manager → CAP | 🟡 protocol only | never observed on the reference manager |
| datachan c2 (`a2=1`, `a2=2`) | both | 🟡 `a2=1` lab, `a2=2` never | manager-side key gate on a radio-less controller |

## `configuration` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `ssid` | ✅ live | beacon carries the manager's SSID |
| `hide-ssid=yes` | ✅ live | `cap-hidden` is not in scan results |
| `security` (see below) | ✅ live | RSN IE from the manager, byte-identical |
| `datapath` (see below) | ✅ live | VLAN per VAP |
| `channel.frequency`, `band`, `width` (20/40/80) | ✅ live | `hw_mode`/`channel`/`ht_capab` derived |
| `country` | ⚠️ not sent | CAPsMAN v2 sends no regulatory country; the CAP uses `--country` |
| `installation`, `tx-power`, `tx-chains`, `antenna-gain` | ❌ untested | not implemented (hostapd defaults) |
| `multicast-enhance`, `qos-classifier`, `beacon-interval`, `dtim-period` | ❌ untested | not implemented |
| `distance`, `frame-lifetime`, `guard-interval`, `hw-protection-mode`, `hw-retries` | ❌ untested | not implemented |
| `max-clients` | ❌ untested | not implemented |

## `security` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `authentication-types=wpa2-psk` | ✅ **live** | 4-way via the manager, `authorized: yes`, ping |
| `passphrase` | ✅ by design | stays on the manager: the CAP never receives it and generates no PSK |
| `management-protection=disabled` | ✅ live | the current profiles |
| `management-protection=required` (PMF) | ✅ **live** | manager sets MFPR; the CAP writes `ieee80211w=2` and reproduces the RSN IE (`caps=0x02c0`); station with MFP=2 → `authorized: yes`, `SET_STATION MFP ret=0`, ping 3/3 0% loss. Also verified in the multi-identity topology (2.4 identity, `ieee80211w=2`) |
| `management-protection` change on a live VAP | ❌ needs an identity restart | the manager marks the dynamic VAP INACTIVE and capagent keeps the old hostapd config until the identity restarts; a new security object also needs its passphrase (F76) |
| `group-key-update` | ⚠️ forced off | `wpa_group_rekey=0` on the CAP (the manager owns rekeying) |
| `wpa3` / SAE (`authentication-types=wpa3-psk`) | ✅ **live, single-identity and multi-identity** | fresh fake-radio identity provisioned with SAE: manager `auth-type=wpa3-psk mfp=yes`, CAP `wpa_key_mgmt=SAE ieee80211w=2 sae_pwe=2`, `0x201c` len=209 → `0x201b` → `0x201f`, station `authorized: yes`, ping 0% (F76). Mutating the security of an already-connected identity needs a restart (VAP stays INACTIVE) |
| `owe` | 🟡 lab 14/14 | not yet live |
| `wpa2-eap` / 802.1X / RADIUS | ✅ **live** | `sec-eap` (wpa2-eap, peap, ccmp) + FreeRADIUS 3.2.8 on 10.0.0.3 (`captest`); the CAP writes `wpa_key_mgmt=WPA-EAP`, `ieee80211w=1`, `external_rsn_auth=1` (patch 9999a now allows AKM 1/5) and the station reaches `authorized: yes` with ping 3/3 0% loss. Earlier detail: the RSN policy now emits `wpa_key_mgmt=WPA-EAP` (+`WPA-EAP-SHA256`) and `external_rsn_auth=1`; a FreeRADIUS 3.2.8 server answers `eapol_test` (PEAP/MSCHAPv2, TTLS/PAP). Live the manager's RADIUS request is rejected with `invalid Message-Authenticator` (see F52), so the 4-way never starts |
| `wpa-psk-sha256` | ❌ untested | AKM parsed, not exercised |
| `wps` | ❌ unsupported | not implemented |

## `datapath` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `tx-power` (configuration) | 🟡 applied, driver pins it | the manager sends it in `0x500b` TLV `0x61` (`0x500b: phy0 tx-power=17 dBm`); the agent fixes the radio power through `NL80211_CMD_SET_WIPHY` (`ret=0`). The reference mt76 driver keeps reporting 20 dBm for every value (`iw dev … set txpower fixed 1200` behaves identically), so the setting is a no-op on this hardware but the path is implemented and verified |
| `dtim-period` (configuration) | ✅ live | `0x6016` TLV `0x24` (u32) is written as `dtim_period=` in that BSS only (`dtim_period=4` for the master, 1 for the others); hostapd starts with 8/8 SSIDs |
| multi-passphrase / PPSK | ❌ not available | RouterOS 7.25.1 exposes only a `multi-passphrase-group` boolean (no passphrase-group object, `/interface wifi security multi-passphrase` does not exist), so there is nothing to provision. Even with it, the manager is the RSN authenticator, so per-station passphrases are inherently manager-side and need no CAP change |
| `traffic-processing=on-cap` | ✅ **live, ping 0% loss** (master BSS, or a per-SSID CAP identity — F63/F74) | the supported mode: the manager is the authenticator, the CAP forwards. The agent creates `br-vlan<N>` on demand; the image ships the `br-vlan*` zone. A station on a **slave** VAP does not reach the 4-way on this manager (F58–F60); with multi-identity every SSID is a master (8/8 authenticated) |
| `vlan-id` | ✅ live | per-VAP `bridge=` to `br-vlan<N>` |
| `traffic-processing=on-capsman` (`a2=1`) | 🟡 lab | plaintext datachan framing works; no live traffic test |
| `traffic-processing=on-capsman-secure` (`a2=2`) | ✅ **live** | the manager sends the datachan create (`a2=2`, 32-byte key, cookie); the CAP installs it, listens on UDP 5248 and a station on that VAP gets `authorized: yes` + ping 0% with the traffic carried as encrypted datachan frames (F72) |
| `bridge`, `interface`, `interface-list` | ❌ untested | the CAP derives the bridge from `vlan-id` |
| `local-forwarding` | ❌ untested | requires the PSK on the CAP, which CAPsMAN v2 never sends |
| `client-to-client-forwarding` | ❌ untested | not implemented |
| `.1x-forwarding` | ❌ untested | not implemented |

## `provisioning` / manager side

| Setting | Status | Evidence / why |
|---|---|---|
| `action=create-dynamic-enabled` | ✅ live | 8 VAPs from two rules, or 8 masters from eight fake-radio rules (multi-identity) |
| `master-configuration` + `slave-configurations` | ✅ live | 1 master + 3 virtuals per radio; virtuals broadcast but do not authenticate (F58–F60). Multi-identity: 8 masters, all authenticate |
| `radio-mac` | ✅ live | matched against NEWPHY; on 5 GHz each fake radio must use a distinct first byte (F74) |
| `require-peer-certificate=no` | ✅ live | zero-touch enrolment (`0x76` → `0x77`/`0x78`) |
| `enabled=yes`, `generated-ca-certificate` | ✅ live | the CAP pins the CA when `--ca-cert` is present |
| Manager discovery via DHCP option 138 | ❌ not consumed | OpenWrt's `udhcpc` does not export it; the address is baked |
| `upgrade-policy` | ❌ untested | no CAP firmware upgrade path |
| ACL / `access-list` | ✅ **live (manager-side)** | `access-list action=reject` (all) → station cannot associate (`NOT CONNECTED`); removing it → `authorized: yes`, ping 3/3 0%. The manager filters before the CAP, so no CAP change is needed |
| `multi-passphrase` / PPSK / VLAN pooling | ❌ not available | RouterOS 7.25.1 exposes only a `multi-passphrase-group` boolean (no passphrase-group object); per-station keys are manager-side anyway |
| 802.11k/v/r steering hints | 🟡 FT implemented, not exercisable | rsn_decide maps AKM 3/4 to `FT-EAP`/`FT-PSK` and adds `mobility_domain` from the MDE; RouterOS 7.25.1 sends neither (F61), so the BSS still comes up as plain PSK. 11k/11v (RRM/BSSTM) are not implemented |
| 6 GHz / MLO | ✅ **live in the virtual radio** (provisioning + station datapath) · 🟡 MLO not implemented | `mac80211_hwsim` + native capagent: the manager provisions `6ghz-be`/5955, hostapd is `AP-ENABLED` (beacon-protection capability `0x84` bit 9), a SAE station completes the 4-way (patch `9999h` queues the early M1), is `authorized: yes` and pings 0% both ways at `band=6ghz-ax`. MLO not attempted; the Deco BE65 stays read-only. See [`6GHZ-HWSIM.md`](6GHZ-HWSIM.md) and F78 |
| Sniffer (`/tool sniffer` over CAPsMAN) | ❌ untested | not implemented |

## How to extend the matrix

The flow that now works (manager-only, `traffic-processing=on-cap`,
`wpa2-psk`) is the template for every new row above:

```sh
# 1. manager: point one radio at the profile under test
/interface wifi provisioning set [find radio-mac="28:D1:27:1B:2D:82"] \
    master-configuration=<cfg> slave-configurations=""
# 2. CAP: zero-config manager-only run
scripts/live-manager-only.sh           # asserts 0 wifi-iface first
# 3. station
scripts/station-test.sh <ssid> <psk> 192.168.30.50/24 25
```

`0x2018` (Auth + AssocReq) → `0x201c` (M1) → `0x201b` (M2) → `0x201f` (keys) →
`authorized: yes` → ping is the acceptance line for a PSK-family profile;
SAE/OWE additionally require `external_rsn_sae=1` in the generated hostapd
config (the agent writes it when the installed `wpad` advertises the option).
