# Open problems — why this is not yet a "real" CAP

Target behaviour: plug in a factory-reset OpenWrt AP, it joins the official
CAPsMAN v2 manager, the manager provisions every SSID/VLAN/security setting,
clients connect with the manager's credentials, and **nothing on the CAP needs
SSH, a local wireless file or a second service**.

Current reality: the control plane joins, the manager provisions 8/8 VAPs with
no local `wifi-iface`, and the CAP creates the netdevs and starts one hostapd
per VAP with no PSK. What is still missing is the 5 GHz start, VAP teardown and
the **hardware/factory-reset proof** — see `docs/MANAGER-ONLY.md`.

---

## Verified facts (do not re-derive)

| # | Fact | Evidence |
|---|---|---|
| F1 | CAPsMAN v2 never sends a config tree / SSID-key payload. `0x6016` = SSID + RSN/WPA/WPS/MBSSID IEs + channel. `0xc029 0x77` = X.509 cert. | V2, V15, V16, V17 |
| F2 | The manager is the RSN authenticator. `0x201f` = derived PTK/GTK/IGTK/BIGTK only. No PSK/PMK anywhere on any channel. | V1, V3, V4, V5, V6, V9, V13, V14, V18 |
| F3 | `0x500b` `a8` is a random datachan key; `0x402b` `a8` is RNG. Not PSK-derived. | V5, V9 |
| F4 | A genuine CAP gets only TK + GTK/IGTK and uses `EXTERNAL_AUTH`; it never holds the passphrase. | V13 |
| F5 | `0x2018` Auth/Assoc relay + `0x201b`/`0x201c` EAPOL + `0x201f` keys works end-to-end in the lab (hwsim), including SAE. | V10, V12, U3, U17 |
| F6 | T12 hostapd `external_rsn_auth` patch: hostapd does beacon/auth/assoc, relays EAPOL, installs no keys. | V12 |
| F7 | **With zero `wifi-iface` on the CAP the manager still provisions all 8 VAPs** (`0x6016` for ports 0x0000/0x0100/0x0001-3/0x0101-3) and installs 6 key sets. The `0xd00b` reply we already send is accepted. | live zero-config run, `work-V22/ZERO-CONFIG-FINDING.md` |
| F8 | The CAP can create the netdevs itself from `0x500b` and spawn hostapd from `0x6016` (SSID + RSN IE + channel, `external_rsn_auth=1`, no PSK). Live: 8/8 created, 8 hostapd, the 4 x 2.4 GHz BSSes carry the manager's SSIDs. | `src/vap.inc`, commit 1bd9d78 |
| F9 | The EAPOL relay works on the real RB1100: STA M2 -> `0x201b` -> manager -> `0x201c` M3 back. | live log `EXT-AUTH: EAPOL ... -> 0x201b` |
| F10 | RSN-IE mismatch fixed at the CAP side: patch `9997-external-rsn-ie.patch` makes hostapd advertise the manager's 28-byte M3 element byte-for-byte; `vap.inc` writes `external_rsn_ie` when the installed `wpad` supports it. Verified on the host (`RSN: Own IEs` identical) and on the mipsel binary under qemu; station-side acceptance on hardware still pending. | `docs/patches/9997-…`, `native/src/vap.inc` |
| F11 | The zero-touch sysupgrade image (capagent + certificate + CA + patched `wpad`, no SSH/firewall/DHCP) is built and passes 55/55 static content checks, but it has **never been flashed**, so boot, factory reset and rejoin are unverified on hardware. | image content check, `docs/MANAGER-ONLY.md` §2.3 |
| F12 | The 5 GHz start failure is a config-shape problem (VHT80 without `vht_oper_centr_freq_seg0_idx`, no HT40 secondary, no `country_code`), not DFS or a driver limit. A candidate fix was investigated but is **not merged** in 0.4.0. | `docs/MANAGER-ONLY.md` §2.2 |

## Open blockers (ranked)

1. **Hardware proof** — the zero-touch image is built and content-verified but
   was never flashed; boot, factory reset, rejoin and 8/8 re-provision are
   unproven. This is the last acceptance gate, not a code change.
2. **5 GHz hostapd start** on the MT7612E: the generated config needs a
   regulatory domain, HT40 secondary and `vht_oper_centr_freq_seg0_idx` before
   VHT80 can resolve a channel. Candidate fix not merged (F12).
3. **VAP lifecycle** — `0x600c` never stops hostapd/deletes the netdev/releases
   the id, so a second create cycle for the same port can duplicate or wedge
   (W25/W28).
4. **Station-side M3 acceptance** with the patched `wpad` on real hardware
   (one `wpa_supplicant -dd` connect); the IE bytes are already equal.
5. **No manual fallback allowed** — no SSH-driven bootstrap, no local
   `wireless` file, no second daemon on the manager.

## Research tracks (20)

1. `0xd00b` reply fidelity: capture a genuine CAP's reply per VAP and diff
   field-by-field with ours (band `0x0a`, freq `0x61`, ifname `0x49`, `0x47`).
2. Manager's VAP-start state machine: what exactly must arrive after `0x500b`
   before `ActAp` sends `0x6016` (static analysis of `ww2`).
3. `0x500b` `a2=0` vs `a2=1` create paths on the CAP side: which one a genuine
   CAP answers, and with what TLV set.
4. VAP-id lifecycle: allocation, `0x600c` destroy, reuse, and why our mapping
   diverges per radio.
5. nl80211 dynamic VAP creation on mt76: `__ap` interfaces, MAC assignment,
   `AP_VLAN`, and reporting `ifindex` back to the manager.
6. `0x2018` semantics: raw frame vs parsed; when the manager needs
   `0x2019`/`0x6019` back and what it does with them.
7. EAPOL source selection on mt76: control-port registration vs monitor VIF
   capture vs `l2_packet`; pick the one a genuine CAP uses.
8. Multi-VAP external-RSN relay: one socket per BSS, per-BSS `0x201b` port and
   authorisation, without cross-talk.
9. hostapd vs custom MLME: measure the cost of a minimal in-client AP
   (beacon/auth/assoc/RSN IE) against keeping hostapd.
10. Channel/band matrix: exact `0x0a` encoding the manager requires for
    `2ghz-g`, `2ghz-n`, `2ghz-ax`, `5ghz-ac`, `5ghz-ax`, `6ghz` profiles.
11. PMF/802.11w: does the manager require `management-protection` for any
    profile, and can the relay path support IGTK/BIP end-to-end.
12. WPA3-SAE PSK-free: finish the "suppress local SAE auth" hostapd patch and
    relay `Auth` alg 3 seq 1 and 2 (V10 showed the manager can drive it).
13. OWE: manager-side OWE DH relay — reproduce V10's partial result and fix the
    AssocResp template handling.
14. Boot sequence of a genuine CAP: discovery, certificate, DHCP, ordering vs
    netifd/hostapd start; derive the correct `START=` ordering.
15. Custom OpenWrt image: built and content-verified (client + cert + patched
    `wpad` in ROM); the first-boot join and factory-reset acceptance run are
    still pending on hardware.
16. Certificate lifecycle: enrolment (`0x76`/`0x77`/`0x78`), renewal, and what
    happens when the manager rotates its CA.
17. Regression harness: one command that joins, waits for 8/8 VAPs, associates
    a STA, completes the 4-way, DHCPs and pings — pass/fail JSON.
18. Interop matrix: wpa2-psk / wpa2-eap / SAE / OWE × on-cap / on-capsman /
    on-capsman-secure, with the CAP holding **no** key.
19. Failure/recovery: manager reboot, CAP reboot, channel change while a STA is
    associated, loss of WAN — must self-heal with no manual step.
20. Conformance diff: run a genuine MikroTik CAP and our client against the
    same manager, capture both TLS streams, and diff every message the CAP
    sends (this is the most direct route to "behaves like a real CAP").

## Acceptance criteria

* factory reset → power on → joins the manager with no shell access;
* every BSS exists because the manager asked for it;
* no `/etc/config/wireless` entry is required to make WiFi work;
* no PSK on the CAP (or, if unavoidable, proof that it is not needed);
* 8/8 VAPs visible in `/interface wifi`, clients get DHCP on the right VLAN;
* recovery after manager/CAP reboot without touching the device.
