# Testing 6 GHz without 6 GHz hardware (mac80211_hwsim)

The reference Xiaomi Mi 4A has no 6 GHz radio and the Deco BE65 is read-only,
so there is no physical 6 GHz AP to test. The alternative is a **virtual radio
on the build host**: `mac80211_hwsim` creates a wiphy that advertises the 6 GHz
band, the native `capagent` drives it exactly like a real CAP, and the
RouterOS manager provisions it over the normal TLS session. Nothing is
installed on the manager and the Deco is not touched.

This document records the working recipe and what it has proven.

## Host side

Fedora 44 / kernel 7.2.14 does **not** ship `mac80211_hwsim` in
`kernel-modules-extra` (only 104 files, no `wireless/virtual/`). It can be
built out-of-tree from the matching vanilla source:

```sh
curl -LO https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.14.tar.xz
tar -xJf linux-7.2.14.tar.xz \
    linux-7.2.14/drivers/net/wireless/virtual
mkdir -p hwsim && cp linux-7.2.14/drivers/net/wireless/virtual/* hwsim/
cat > hwsim/Makefile <<'EOF'
obj-m := mac80211_hwsim.o
mac80211_hwsim-objs := mac80211_hwsim_main.o mac80211_hwsim_nan.o
EOF
make -C /lib/modules/$(uname -r)/build M=$PWD modules
sudo insmod hwsim/mac80211_hwsim.ko radios=2
sudo iw reg set GR          # GR allows 5945-6425 (5955 with IR)
```

`iw phy <phy> info` then has `Band 4` with `HE/EHT Iftypes: AP` and
`5955.0 MHz [1] (23.0 dBm)`.

CAP agent for the host (the same sources as the target):

```sh
gcc -O2 -Wall -Wextra -Wno-unused-parameter -Inative/src \
    -o /tmp/capsim/capagent-host native/capagent.c native/src/extmux.c \
    -lmbedtls -lmbedx509 -lmbedcrypto
```

hostapd must be **the patched build** (external RSN + SAE + 11ax). Prepare the
tree with `scripts/patches-check.sh` from the OpenWrt 24.10 stock patch set,
without the ubus/ucode patches (they pull libubus, which a plain host does not
have), then build:

```sh
./scripts/patches-check.sh \
    --tarball /path/to/hostapd-2024.09.15~5ace39b0.tar.zst \
    --openwrt-patches /tmp/patches-noubus --keep
# in <tree>/hostapd/.config: CONFIG_LIBNL32=y, CONFIG_IEEE80211AX=y,
# CONFIG_SAE=y, CONFIG_IEEE80211W=y, CONFIG_OWE=y, CONFIG_TLS=openssl
make -C <tree>/hostapd -j
```

Run the agent with the hostapd override and the hwsim phy:

```sh
CAPAGENT_HOSTAPD=<tree>/hostapd/hostapd \
  capagent-host --manager 10.0.0.1 --discovery-interfaces lo --port 5246 \
    --cert /tmp/capsim/sim6.pem --key /tmp/capsim/sim6.key \
    --macs 02:00:00:00:00:72 --phys 14 --dont-verify-certificate \
    --identity SIM6 --eapol-leg both --mgmt-relay --mgmt-source off \
    --country GR --ext-auth-dir /tmp/capsim/ext \
    --vap-state /tmp/capsim/vaps.state
```

`--phys` maps logical radio 0 to the hwsim wiphy index; the agent otherwise
picks the host Wi-Fi card (phy11 here).

## Manager side

```sh
/interface wifi security add name=sec-6g authentication-types=wpa3-psk \
    passphrase="SixGHz-12345" management-protection=required
/interface wifi configuration add name=cfg6 ssid=cap-6g security=sec-6g \
    datapath=dt-iot channel.band=6ghz-be channel.frequency=5955 channel.width=20mhz
/interface wifi provisioning add radio-mac=02:00:00:00:00:72 \
    action=create-dynamic-enabled master-configuration=cfg6 slave-configurations=""
```

Two manager details matter:

* **6 GHz requires WPA3.** With `wpa2-psk` the CAP's hostapd refuses to start
  (`Invalid AKM suite for 6 GHz`). Use `wpa3-psk`/SAE (or OWE).
* **Band name.** The manager labels a 6 GHz-capable CAP's channels `be`
  (`cap print`/`radio print` show `5955/be`), and `6ghz-ax` gets
  `no available channels`; `6ghz-be` is the working configuration value even
  though the station registration is later reported as `band=6ghz-ax`.

## F78: the beacon-protection capability bit

With `6ghz-be`, the manager first refuses the VAP with
`beacon protection must be enabled for wifi7 cap`, even when the security has
`management-protection=required`. The missing piece is a CAP capability bit:
in NEWPHY element `0x84` (little-endian bitset), **byte 1 bit 1 (bit 9)**.
The agent now sets it automatically when the phy has frequencies >= 5925:

```c
uint8_t caps84[8] = { 0x40, have6 ? 0x02 : 0x00, 0x00, 0x00 };
```

With that bit the VAP is active (`MDB`) and hostapd starts on 5955 MHz.
`CAPAGENT_NEWPHY_84=40020000` reproduces the same result manually.

## What was proven

* Manager builds the 6 GHz channel list from the CAP (`6g-channels=5955…6415`)
  and provisions `cfg6` with `channel.frequency=5955 channel.band=6ghz-be`.
* CAP hostapd config: `hw_mode=a channel=1 op_class=131 ieee80211ax=1
  he_6ghz_reg_pwr_type=0`; `AP-ENABLED` on `phy0-ap0`, channel 1 (5955 MHz),
  20 MHz. (Before the `vap.inc` fix the same config was written as
  `hw_mode=g channel=6`, because every frequency >= 4900 was treated as 5 GHz.)
* A second hwsim radio running wpa_supplicant (SAE, PMF) completes the SAE
  exchange with the manager through the CAP
  (`0x2018 auth len=128 freq=5955`, `0x2019 auth-resp`) and the manager's
  registration table shows:

  ```
  interface=cap-wifi22 ssid=cap-6g ... auth-type=wpa3-psk mfp=yes band=6ghz-ax vlan-id=20
  ```

## What is still open

The station is deauthenticated right after association
(`reason=6`, hostapd `deauthenticated due to local deauth request`) and never
receives an EAPOL-Key, while the manager retries M1 (`0x201c len=135`). This is
the same assoc-before-auth / 4-way race seen on the bench, now on 6 GHz; the
CAP/hostapd side still needs to hold the EAPOL until the station is
authenticated, or to avoid the local deauth. The manager side and the 6 GHz
radio provisioning path are proven; the full station data path is not.

## Limits of the simulation

* hwsim has no RF, no channel occupancy and no AFC; it cannot prove regulatory
  or 6 GHz power-mode behaviour.
* The `0x84` bit 9 and the `6ghz-be` band name are reverse-engineered from this
  manager version (7.25.1); a different RouterOS may use other values.
* Only 20 MHz was used. The CAP writes a 20 MHz 6 GHz BSS; wider channels need
  the HE centre-index fields (not implemented yet).
