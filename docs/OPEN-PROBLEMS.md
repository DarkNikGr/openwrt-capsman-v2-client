# Open problems — why this is not yet a "real" CAP

Target behaviour: plug in a factory-reset OpenWrt AP, it joins the official
CAPsMAN v2 manager, the manager provisions every SSID/VLAN/security setting,
clients connect with the manager's credentials, and **nothing on the CAP needs
SSH, a local wireless file or a second service**.

Current reality: control plane joins, but the BSSes come from a local
`/etc/config/wireless`. That is manual configuration and is **not** the goal.

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

## Open blockers (ranked)

1. **Manager does not start the pilot VAP on the live CAP** — no `0x6016` for
   `port=0x0000`, no `0x201c`, so the PSK-free 4-way never begins. Suspected
   `0xd00b` reply fidelity (band/freq/ifname) and VAP-id mapping.
2. **Virtual VAPs are invisible to the manager** — `ifindex=0`, slave
   interfaces never created, `vapid` derived from MAC instead of the `0x500b`
   port; `0x600c` never releases.
3. **STA→manager EAPOL leg** — after the 9998 fix the CAP relays from
   `ieee802_1x_receive`, but on the live box the manager still retransmits M1
   (no `0x201b` observed when the VAP was not started).
4. **Zero-touch boot** — client + certificate + hostapd must live in ROM
   (custom image), otherwise a factory reset removes them.
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
15. Custom OpenWrt image: client + cert + config in ROM, first-boot join with
    no overlay; factory-reset acceptance test.
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
