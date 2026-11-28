# W62 — no-monitor `0x2018` path (lab status)

## Summary (15 lines)

1. Lab: stock CHR 7.25.1 (its built-in `/interface wifi capsman` v2), mac80211_hwsim, a patched hostapd 2.12-devel built from this repo's `999/9997/9998/9999/9999a/9999b` series, and capagent built for x86.
2. CAP ran with `--mgmt-source off`; one 2.4 GHz BSS (`cap-test`, channel 2412) was provisioned; the manager sent `0x6016` and the `0x201f` group keys.
3. `external_rsn_auth=1 external_rsn_sae=1` hostapd emitted `ASSOCREQ <mac> <hex>` on its ext-auth socket; capagent received it (`EXTMUX: ASSOCREQ ...`) and sent `0x2018` to the manager.
4. **Key finding:** for WPA2-PSK hostapd relays only AssocReq, not open-system Auth (9999a relays Auth only for SAE). The manager drops an AssocReq for an unknown MAC (`no sta`); it replied only `0x2019 deauth`.
5. A synthetic open-system Auth frame sent as `0x2018` immediately before the real AssocReq made the manager create the Peer: `RX 0x201c eapol-tx port=0x0000 len=135` (M1) followed every time.
6. So the no-monitor relay is proven through **0x2018 → Peer → 0x201c/M1**. The 4-way did **not** complete in the lab: no `0x201b` (M2), and the manager deauthenticated the station.
7. Lab-only cause: hostapd logged `ctrl_iface not configured!`, so EXT_AUTH_TX had no control socket; capagent's one-shot fallback injected M1 with `nl_control_port_tx` (`ret=0`) and still got no M2.
8. This is the W53 `EXT_AUTH_TX` contract, not the 0x2018 relay: the relay itself (Auth/AssocReq → 0x2018) worked on every assoc retry.
9. Live was **not** run. No lock was taken, `/etc/config/wireless` was not written, nothing was rebooted, and `/usr/sbin/wpad` was not touched by W62.
10. Evidence: `w62-evidence/lab-capagent.log`, `lab-station.log`, `lab-messages.log`.
11. Uncommitted W62 code: `mgmt.inc` (PSK synthetic open Auth before AssocReq), `util.inc` (`CAPAGENT_IW` override), `vap.inc` (honour `CAPAGENT_HOSTAPD` in `hostapd_has_opt`, scan the log tail for AP-ENABLED).
12. `phy.inc` changes in the worktree are W61's; W62 did not edit that file.
13. Remaining lab gap is the hostapd control-socket bind; live should exercise the already-deployed `wpad` `EXT_AUTH_TX` path instead.
14. Live acceptance still needs: `--mgmt-source off`, 2×2.4 GHz BSS, `scripts/station-test.sh cap-test cap-test-12345`, and `0x2018/0x201c/0x201b/0x201f` + `authorized:yes`.
15. Verdict: relay path **partially proven** (0x2018 and M1); end-to-end authorized/DHCP/ping remains unproven.

## What was measured

### Lab construction (no live device)

```sh
# hwsim module built against the running kernel source, then
insmod mac80211_hwsim.ko radios=4
# hostapd from hostap 5ace39b0 + repo patches, built with
# CONFIG_EXTERNAL_RSN_AUTH=y, CONFIG_SAE=y, CONFIG_IEEE80211W=y
# capagent x86 with mbedTLS 3.6.2
```

CHR was booted with qemu/KVM and configured as:

```text
/interface wifi capsman set enabled=yes require-peer-certificate=no
/interface wifi security add name=sec-wpa2 authentication-types=wpa2-psk passphrase=cap-test-12345 management-protection=allowed
/interface wifi channel add name=ch-2g band=2ghz-g frequency=2412 width=20mhz
/interface wifi configuration add name=cfg-test ssid=cap-test security=sec-wpa2 channel=ch-2g
/interface wifi provisioning add action=create-dynamic-enabled master-configuration=cfg-test
```

CAP command (host build):

```sh
CAPAGENT_IW=/tmp/opencode/w62/iw-2g \
CAPAGENT_HOSTAPD=/tmp/opencode/w62/hostapd-lab \
capagent --manager 127.0.0.1 --port 25246 --phys 2 \
  --macs e2:d6:88:5e:6b:21 --identity W62-LAB --mgmt-source off \
  --ext-auth-dir /tmp/opencode/w62/lab/ext \
  --ext-ctrl-dir /tmp/opencode/w62/lab/ext
```

### Evidence: hostapd relay → capagent → 0x2018

`w62-evidence/lab-capagent.log`:

```text
EXTMUX: extmux: ASSOCREQ port=0x0000 len=154
EXTMUX: 0x2018 assocreq port=0x0000 len=154 freq=2412
0x2018 auth-synth 4a:cc:65:f1:e3:6c -> manager (port=0x0000 freq=2412 rssi=0 len=30)
0x2018 ext 4a:cc:65:f1:e3:6c -> manager (port=0x0000 freq=2412 rssi=0 len=154)
RX 0x201c eapol-tx port=0x0000 len=135
EXTMUX: extmux: phy0-ap0: hostapd rejected EXT_AUTH_TX (ctrl socket send failed); this BSS now uses direct nl80211 control-port TX
0x201c: relay -> 4a:cc:65:f1:e3:6c port=0x0000 len=121 ret=0
```

The `ASSOCREQ` is hostapd's event on the ext-auth socket (the patched hostapd prints
`EXT-AUTH: relaying ASSOCREQ from ...`); capagent forwarded the raw frame in
`0x2018`. The manager answered with M1 (`0x201c`), proving Peer creation.

### Evidence: manager reaction without auth

Before the synthetic Auth:

```text
0x2019 deauth -> 4a:cc:65:f1:e3:6c port=0x0000 ifindex=37 freq=2412 len=26 ret=-22 (Invalid argument)
```

No `0x201c`, no registration row. After the synthetic Auth + AssocReq, `0x201c`
arrived on every retry. This matches `docs/FINDINGS.md`: `ActAp::handleAuth`
allocates the Peer; an AssocReq for an unknown MAC is dropped.

### Station / 4-way

`w62-evidence/lab-station.log`:

```text
wlan1: SME: Authentication response: peer=e2:d6:88:5e:6b:21 auth_type=0 auth_transaction=2 status_code=0
wlan1: Trying to associate with e2:d6:88:5e:6b:21 (SSID='cap-test' freq=2412 MHz)
...
wlan1: State: ASSOCIATING -> DISCONNECTED
```

No `CTRL-EVENT-CONNECTED`, no `0x201b`, no `0x201f` PTK, no `authorized: yes`.
The lab hostapd control interface failed (`ctrl_iface not configured!`), so the
fallback TX path was used; that is the remaining lab defect, not a failure of
the raw 0x2018 relay.

## Caveats / next step

* The deployed Xiaomi `wpad` was not modified and was not exercised by W62.
* Live still needs one locked run with `--mgmt-source off`, a 2-BSS 2.4 GHz
  profile, and `scripts/station-test.sh`; success criteria are
  `0x2018`, `0x201c`, `0x201b`, `0x201f`, `authorized: yes`, DHCP and ping.
* If WPA2-PSK live behaves like the lab, the synthetic open Auth before the
  real AssocReq is required; without it the manager only sends deauth.
