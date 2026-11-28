# What of CAPsMAN v2 is actually covered

An honest matrix of the official manager's settings against what this CAP has
been **measured** to do. "Live" = Xiaomi Mi Router 4A + RB1100AHx4 /
RouterOS 7.25.1 with a real station; "lab" = CHR 7.25.1 + mac80211-hwsim, or a
virtual station on the hwsim bench.

Legend:

| Mark | Meaning |
|---|---|
| ✅ | implemented and measured (live, or live on the virtual bench where stated) |
| 🟡 | partially implemented, lab-only, or implemented but not exercised end to end |
| ➖ | not applicable / not exposed by RouterOS 7.25.1 (or the hardware); the CAP cannot implement it because nothing is provisioned |
| ❌ | a real CAP setting the manager actually sends, but this CAP does not implement |

> Read this before assuming "CAPsMAN works": the provisioning path, WPA2-PSK,
> SAE, PMF and WPA2-EAP are proven end to end. Many optional per-VAP knobs are
> never sent to the CAP by RouterOS 7.25.1 and are marked ➖ rather than green.

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
| `0x6017` live security change | manager → CAP | ✅ live | re-join + `own_cfg_hash` rebuild after a full local VAP/hostapd teardown, so the burst cannot leave 5 GHz BSSes down; verified 8/8 without a service restart (F82) |
| `0x600c` destroy VAP | manager → CAP | ✅ live | stop hostapd, delete netdev, release vapid |
| `0x2018` assoc/Auth report | CAP → manager | ✅ live | `0x3e` raw frame + `0x0a` channel + `0x3f` rssi; action frames on the virtual bench |
| `0x201b` EAPOL from STA | CAP → manager | ✅ live | per-BSS ext-auth socket |
| `0x201c` EAPOL to STA | manager → CAP | ✅ live | relayed, `ret=0` |
| `0x2019` Auth/Assoc/Deauth/Action to STA | manager → CAP | ✅ live | deauth `ret=0`; BTM action `len=49` on the virtual bench |
| `0x201f` keys | manager → CAP | ✅ live | GTK/IGTK/BIGTK, PTK + `SET_STATION` authorize |
| `0x200e` / `0x2015` / `0x6027` stats | both | ✅ live | signal, counters, poll |
| `0x402b` datachan rekey | manager → CAP | 🟡 protocol only | never observed on the reference manager |
| datachan c2 (`a2=1`, `a2=2`) | both | ✅ **live** | `a2=2` on the RB1100 (F72); `a2=1` on the Xiaomi 5 GHz with a station `authorized: yes` and ping 0% after the per-VAP variant fix (F81). The 2.4 GHz radio is refused by the manager (`a2=0`) because of its radio class |

## `configuration` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `ssid` | ✅ live | beacon carries the manager's SSID |
| `hide-ssid=yes` | ✅ live | `cap-hidden` is not in scan results |
| `security` (see below) | ✅ live | RSN IE from the manager, byte-identical |
| `datapath` (see below) | ✅ live | VLAN per VAP |
| `channel.frequency`, `band`, `width` (20/40/80) | ✅ live | `hw_mode`/`channel`/`ht_capab` derived. 6 GHz only with `6ghz-be` on the virtual radio; `6ghz-ax` is vendor-blocked (F79) |
| `country` | ➖ not provisioned | CAPsMAN v2 sends no regulatory country; the CAP uses `--country` |
| `dtim-period` | ✅ live | `0x6016` TLV `0x24` (u32) written as `dtim_period=` in that BSS only |
| `tx-power` (configuration) | 🟡 applied, driver pins it | manager sends `0x500b` TLV `0x61`; the agent calls `NL80211_CMD_SET_WIPHY` (`ret=0`). The reference mt76 driver keeps reporting 20 dBm for every value, so it is a no-op on this hardware |
| `installation` | ➖ not provisioned | no TLV observed on the wire; not implemented (hostapd defaults) |
| `tx-chains` | ➖ not provisioned | no TLV observed; radio chain count is the driver default |
| `antenna-gain` | ➖ not provisioned | no TLV observed; not implemented |
| `multicast-enhance` | ➖ not provisioned | no TLV observed; not implemented |
| `qos-classifier` | ➖ not provisioned | no TLV observed; not implemented |
| `beacon-interval` | ➖ not provisioned | no TLV observed; hostapd default beacon interval is used |
| `distance` | ➖ not provisioned | no TLV observed; not implemented |
| `frame-lifetime` | ➖ not provisioned | no TLV observed; not implemented |
| `guard-interval` | ➖ not provisioned | no TLV observed; hostapd/HT defaults are used |
| `hw-protection-mode` | ➖ not provisioned | no TLV observed; not implemented |
| `hw-retries` | ➖ not provisioned | no TLV observed; not implemented |
| `max-clients` | ➖ not provisioned | no TLV observed; not implemented |

## `security` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `authentication-types=wpa2-psk` | ✅ **live** | 4-way via the manager, `authorized: yes`, ping |
| `passphrase` | ✅ by design | stays on the manager: the CAP never receives it and generates no PSK |
| `management-protection=disabled` | ✅ live | the current default profiles |
| `management-protection=required` (PMF) | ✅ **live** | manager sets MFPR; the CAP writes `ieee80211w=2` and reproduces the RSN IE (`caps=0x02c0`); station with MFP=2 → `authorized: yes`, `SET_STATION MFP ret=0`, ping 3/3 0% loss. Also verified in the multi-identity topology |
| `management-protection` change on a live VAP | ✅ **live** | `0x6017` re-join + `own_cfg_hash`, no identity restart (F76). A new security object still needs its passphrase at creation |
| `group-key-update` | ➖ manager-owned | the CAP writes `wpa_group_rekey=0`; the manager owns rekeying, so there is no CAP-side knob |
| `wpa3` / SAE (`authentication-types=wpa3-psk`) | ✅ **live, single-identity and multi-identity** | manager `auth-type=wpa3-psk mfp=yes`, CAP `wpa_key_mgmt=SAE ieee80211w=2 sae_pwe=2`, `0x201c` len=209 → `0x201b` → `0x201f`, station `authorized: yes`, ping 0% (F48/F76) |
| `owe` | ✅ **live (CAP-local OWE)** | the manager still provisions the SSID/security/channel/VLAN, but RouterOS 7.25.1 never sends a DH-bearing `0x6019` and deauthenticates a relayed OWE assoc. A pure-OWE VAP is therefore completed by the CAP's hostapd (`wpa_key_mgmt=OWE`, `ieee80211w=2`, no `external_rsn_auth`); a station performs the OWE DH, the 4-way and pings 3/3 0% (F80). The manager's registration table does not show that client |
| `wpa2-eap` / 802.1X / RADIUS | ✅ **live** | `sec-eap` (wpa2-eap, peap, ccmp) + FreeRADIUS 3.2.8 on 10.0.0.3 (`captest`); CAP writes `wpa_key_mgmt=WPA-EAP`, `ieee80211w=1`, `external_rsn_auth=1` (patch `9999a` allows AKM 1/5); station `authorized: yes`, RADIUS logs the user, ping 3/3 0% loss (F53). The earlier `invalid Message-Authenticator` failure was a duplicate/stale RADIUS entry, since fixed |
| `wpa-psk-sha256` | ➖ not exercised | RouterOS 7.25.1 has no SHA256-only security value to select; the CAP parses AKM 6 but the path is not exercised |
| `wps` | ➖ not exposed | CAPsMAN v2 does not provision WPS to the CAP |
| `ft` / 802.11r | 🟡 CAP-side ready | `rsn_decide.h` handles AKM 3/4 and MDID, but 7.25.1 sends no MDE (F61) |

## `datapath` settings

| Setting | Status | Evidence / why |
|---|---|---|
| `traffic-processing=on-cap` | ✅ **live, ping 0% loss** (master BSS, or a per-SSID CAP identity — F63/F74) | the supported mode: the manager is the authenticator, the CAP forwards. The agent creates `br-vlan<N>` on demand; the image ships the `br-vlan*` zone |
| `vlan-id` | ✅ live | per-VAP `bridge=` to `br-vlan<N>` |
| `traffic-processing=on-capsman` (`a2=1`) | ✅ **live on the Xiaomi 5 GHz** (F81) | manager sends `a2=1`; the CAP arms the plain datachan on UDP 5248 and a station gets `authorized: yes` + ping 3/3 0% through the manager (`datachan plain` frames both ways). The 2.4 GHz radio gets `a2=0` (the manager refuses on-capsman for that radio class); `--datachan --datapath-bridge` is required |
| `traffic-processing=on-capsman-secure` (`a2=2`) | ✅ **live on the RB1100** (F72) | manager sends `a2=2` + 32-byte key + cookie; CAP installs it, listens on UDP 5248, station `authorized: yes` + ping 0% with encrypted datachan frames. The radio-less CHR still never runs the manager key install |
| multi-passphrase / PPSK | ➖ not available | RouterOS 7.25.1 exposes only a `multi-passphrase-group` boolean (no passphrase-group object), so there is nothing to provision; per-station keys are manager-side anyway |
| `bridge`, `interface`, `interface-list` | ➖ not provisioned | the CAP derives the bridge from `vlan-id`; no such TLV is sent |
| `local-forwarding` | ➖ not applicable | not a separate CAPsMAN v2 setting here; the supported equivalent is `traffic-processing=on-cap`, and CAPsMAN v2 never sends the PSK |
| `client-to-client-forwarding` | ➖ not provisioned | no TLV observed; not implemented |
| `.1x-forwarding` | ➖ not provisioned | no TLV observed; not implemented |

## `provisioning` / manager side

| Setting | Status | Evidence / why |
|---|---|---|
| `action=create-dynamic-enabled` | ✅ live | 8 VAPs from two rules, or 8 masters from eight fake-radio rules (multi-identity/solo) |
| `master-configuration` + `slave-configurations` | ✅ live | 1 master + 3 virtuals per radio; virtuals broadcast but do not authenticate (F58–F60). Solo/multi-identity: 8 masters, all authenticate |
| `radio-mac` | ✅ live | matched against NEWPHY; on 5 GHz each fake radio must use a distinct first byte (F74) |
| `require-peer-certificate=no` | ✅ live | zero-touch enrolment (`0x76` → `0x77`/`0x78`) |
| `enabled=yes`, `generated-ca-certificate` | ✅ live | the CAP pins the CA when `--ca-cert` is present |
| Manager discovery via DHCP option 138 | ✅ live | `/etc/udhcpc.user.d/99-cap-dhcp138` decodes it into `/tmp/cap-manager`; `10.0.0.1` there and `MANAGER=auto` works |
| `upgrade-policy` | ➖ not exposed | CAPsMAN v2 provisions no CAP firmware upgrade to this client |
| ACL / `access-list` | ✅ **live (manager-side)** | `access-list action=reject` (all) → station cannot associate (`NOT CONNECTED`); removing it → `authorized: yes`, ping 3/3 0%. The manager filters before the CAP, so no CAP change is needed |
| 802.11k steering hints | ✅ **live on a virtual station** | `CAPAGENT_RRM=1` advertises the RM element, patch `9999f` relays the station's Beacon Report as `0x2018`, `9999i` keeps the short RM IE: `rrm-capa=0x70`, `Beacon report token 1`, `0x2018 action len=235` (F69/F71). The Intel 3168 still drops the RM IE |
| 802.11v / BTM | ✅ **live on the virtual bench** | a steering group + `CAPAGENT_FAKE_RSSI=-80` makes the manager send a BTM Request (`0x2019 action len=49`); patch `9999j` relays the BTM Response (`0x2018 action len=29`) (F67). RouterOS 7.25.1 sends no FT MD |
| 6 GHz | 🟡 virtual radio only | `mac80211_hwsim` + `6ghz-be`/5955: 20 and 80 MHz SAE datapath, `authorized: yes`, ping 0%. The literal `channel.band=6ghz-ax` is vendor-blocked (band-id sweep 0x05–0x1f and a no-EHT/no-UHR build still give `5955/be` + `no available channels`, F79). The reference Xiaomi has no 6 GHz hardware |
| MLO / EHT multi-link | ➖ not implemented | no MLD is established; the Deco BE65 stays read-only |
| Sniffer (`/tool sniffer` over CAPsMAN) | ➖ not exposed | no sniffer provisioning reaches the CAP |

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
SAE additionally requires `external_rsn_sae=1` in the generated hostapd
config (the agent writes it when the installed `wpad` advertises the option).
A **pure-OWE** VAP is the exception: it is completed by the CAP's hostapd
(F80), so the agent omits `external_rsn_auth`/`external_rsn_sae` and the
`ext_auth_socket` for it (`CAPAGENT_LOCAL_OWE=0` restores the relay).
