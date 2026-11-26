# Open problems — why this is not yet a "real" CAP

Target behaviour: plug in a factory-reset OpenWrt AP, it joins the official
CAPsMAN v2 manager, the manager provisions every SSID/VLAN/security setting,
clients connect with the manager's credentials, and **nothing on the CAP needs
SSH, a local wireless file or a second service**.

Current reality: the control plane joins, the manager provisions 8/8 VAPs with
no local `wifi-iface`, and the CAP creates the netdevs and runs **one hostapd
per radio with `bss=` sections** with no PSK. What is still missing is a stable
4-BSS start on the 2.4 GHz MT7603E, the `0x2018` relay on that radio, and the
**hardware/factory-reset proof** — see `docs/MANAGER-ONLY.md`.

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
| F13 | The VAP lifecycle is single-implementation: W34 ownership/journal + W38/W25/W28 teardown. Live: 3 × create/start/destroy cycles of 4 BSSes on phy0 with zero netdev/hostapd/pid/conf/socket left and `0x47` slots 0..3 reused every cycle; local hwsim: 5 cycles + duplicate 0x6016 ignore/restart + 3 × 8 VAPs. | W52 `REPORT.md`, `docs/W52-LIFECYCLE.md` |
| F14 | One hostapd process per VAP deadlocks the phy (one instance in state `D`, BSSes die within ~1 s even after `AP-ENABLED`). One hostapd **per phy** with `interface=` + `bss=` sections carries 4 BSSes and 4 SSIDs in one process. | `native/src/phy.inc`, live `vap: phy0 hostapd up with 4 BSS(es)` |
| F15 | `hostapd -B` leaves the `-P` pid file empty, so "pid file unreadable" must never mean "instance dead": resolve the pid from `/proc` by our exact `vap-phyN.conf` path and write the pid file ourselves. Without this the 1 s reconcile restarted the radio 37 times in ~2 min. | `vap_phy_pid()`, live `dbg: … pid=9041 alive=1` on every row |
| F16 | hostapd must only ever **attach** to netdevs that already exist. Handing it a BSS without a netdev makes it call `NEW_INTERFACE`, hit the driver's vif limit and fail `-23 (ENFILE)`, which kills the whole instance. | `vap_phy_row_ready()`, `-23` 12 -> 0 in one run |
| F17 | Naming: in own mode (zero `wifi-iface`) the manager's `phyN-apM` names are used, and a netifd claim on a name that does not exist is stale and must be ignored. With a legacy config still in place the policy is `legacy` and every claim fell back to `capN-M` — that was the real reason for the earlier `cap0-*` runs, not the candidate order. | `wl: ownership=own (ubus: 0 netifd ifnames)`, `iw dev` shows `phy0-ap0..3`, `phy1-ap0..6` |
| F18 | The patched `wpad` (999/9997/9998/9999/9999a/9999b, `CONFIG_EXTERNAL_RSN_AUTH=y`) is built and **installed** on the reference Xiaomi and survives reboot: `external_rsn_sae=2`, `EXT_AUTH_MGMT_TX=1`, `external_rsn_ie=7`. The official 24.10.0 SDK ships no hostapd sources, so the build overlays the v24.10.0 package tree into the SDK and builds mbedtls/libubox/ubus/uci first. | `scripts/build-wpad-9999a.sh`, grep on `/usr/sbin/wpad` |
| F19 | The 2.4 GHz MT7603E brings up **2 BSSes** reliably (`phy0-ap0` + `phy0-ap1` with SSIDs) and fails from 3 BSSes with `Failed to create interface phy0-ap2: -23`. Real phy0 vif usage at that moment was 2/4, so it is not a simple vif-count limit. | live A/B: 2 BSS ok, 3 and 4 BSS fail |
| F20 | `mon_create(phy0)` refuses on purpose ("4-interface radio; not taking a VAP slot"), so the 2.4 GHz radio has **no** `cm0` and `0x2018` is not relayed from it. The no-monitor path is the `9999a` raw AUTH/ASSOCREQ relay. | live log, `src/mgmt.inc` |
| F22 | **`-23` is not a driver or vif limit.** hostapd's `nl80211_create_iface()` reads `-ENFILE` from `NL80211_CMD_NEW_INTERFACE` as "this name already exists". With `use_existing=0` it then prints `Failed to create interface phy0-apN: -23`, **deletes the netdev the CAP created** and makes its own, owned by its own netlink socket. The ifindex moves under capagent, which removes the row as an orphan and the BSS churns. Patch `9999c` passes `use_existing=1` for AP BSSes: live `Try to remove and re-create` 3+ -> **0**, both radios `hostapd up with 4 BSS(es)`. A 5th AP vif can be created by hand (`iw phy phy0 interface add probeap99 type __ap`) on the same radio, so the platform allows more than four. | `patches/9999c-…`, live A/B |
| F30 | `handle_assoc()` **is** entered: the relay proves it. For one station attempt capagent sent `0x2018 auth-synth` **and** `0x2018 ext … len=156 / len=148` (the AssocReq sizes) for ports `0x0101` and `0x0001`, and the relay hook lives inside `handle_assoc`. So the frame reaches hostapd; what never happens is an **AssocResp reaching the station** — wpa_supplicant reports `Association request send successfully` then `MLME event 38; timeout`, never `Association response`. The manager's `0x2019` deauth TX fails with `-22` in the same window, so the AP-side mgmt TX path is the suspect, not the relay. | live `d7.log` + `/tmp/capsta-wpa.log` |
| F32 | With `logger_stdout_level=0` (MSGDUMP) hostapd's log for one station contains **only** `MLME-DELETEKEYS` and `authenticated` — no association line at all — while capagent still receives an ext-auth frame of `len=156/148` (the AssocReq) and forwards it as `0x2018`. So `handle_assoc()` runs, the relay fires, and the function then returns without the station ever seeing an AssocResp (`MLME event 38; timeout`). | live `d8.log` |
| F33 | The `0x2019` deauth goes through `ext_auth_mgmt_tx()` (the hostapd control socket), not `nl_mgmt_tx()`, which is why the new "retry without freq" never fired: `ret=-22` is returned by hostapd's `MGMT_TX` handler. | live `d8.log`, `src/mgmt.inc` |
| F31 | Per-STA hostapd messages (`mgmt::auth`, `IEEE 802.11: associated`) are `MSG_MSGDUMP`/DEBUG and only appear at `logger_stdout_level=1` **and** the per-STA logger; absence of those lines is not evidence of failure, the `EXT-AUTH:` relay is. | live comparison |
| F28 | hostapd logger options are **global**: appended after the last `bss=` section they are parsed as per-BSS keys and ignored, so `-dd` stays at INFO and every failure is invisible. Written before the first `interface=` the log is complete (128 lines instead of 4 for a radio). | `CAPAGENT_HOSTAPD_DEBUG=1`, live |
| F29 | With `cap-test` as the radio master the full flow runs: Auth OK → `0x2018` → manager `0x201c` M1 (`len=121`) relayed with `ret=0` on both ports, then the manager sends `0x2019` deauth because no M2 ever comes back. hostapd never logs an association and never relays `ASSOCREQ` for the station, so its `handle_assoc()` is not entered at all — the `external_rsn` hook relays the AssocReq only once that code path runs. | live `d5.log` + `/tmp/vap-phy0.log` |
| F26 | `NL80211_CMD_SET_INTERFACE` returning `-EALREADY` ("Match already configured") made hostapd abort with `Could not configure driver mode`, so a radio whose BSS the CAP had already brought up as AP never initialised (phy1 failed 5/5 with `status=1`). Patch `9999d` treats `-EALREADY` as success. | live: 4+4 run `ssids=8`, `hostapd up with 4 BSS(es)` on both radios |
| F27 | **The manager answers `0x2018` only for the master VAP.** With `cap-test` provisioned as the radio master (ports `0x0000`/`0x0100`) the manager sent M1 — `RX 0x201c eapol-tx port=0x0000 len=135`, relayed as `[EAPOL TX] … info=008a` `ret=0`, and hostapd logged `STA …: authenticated`. The same SSID as a virtual (`cap-wifi1-virtual1`, ports `0x0001`/`0x0101`) produced the relayed Auth+AssocReq and **no** `0x201c`. Manager-initiated `0x2019 deauth` then fails on our side with `-22 (Invalid argument)`. | live d3.log vs earlier runs |
| F24 | **`hostapd -B` was the restart loop.** The daemon exits about a second after `AP-ENABLED`, before it writes the `-P` pid file, so the pid was never resolvable and the reconcile restarted the phy forever (35 starts/min, 0-4 SSIDs). Running hostapd in the foreground as the `fork()`ed child fixed it: the pid is the one `fork` returned, nothing reparents it, and a dead instance is a zombie that `pid_is_zombie()` reaps instead of looking alive to `kill(pid,0)`. | live: `ssids=8`, `hostapd up with 4 BSS(es)` twice, two hostapd processes |
| F25 | BSS ownership: the master (lowest vapid) netdev stays ours (`interface=`), every secondary is handed over — deleted, then hostapd creates it. Rows remember `handed_over` + `applied_len/hash`, so the reconcile refreshes the ifindex after `AP-ENABLED` instead of recreating what it just gave away. | `afcafa0`, live 8/8 SSIDs stable |
| F23 | With `9999c` hostapd **attaches** to our secondaries (good), but then only the master reaches `AP-ENABLED` and the secondaries stay `type AP` with no SSID: hostapd's static `bss=` path expects to own those netdevs. The OpenWrt model (delete the secondaries, let hostapd create them) does bring all four SSIDs up (W61 measured 28 s stable, zero `-23`), but the journal then loops: a handover row has `ifindex=0`, so the reconcile recreates the netdev it just gave away. Next step is to refresh each row's ifindex **after** `AP-ENABLED` and never treat `ifindex=0` on a handed-over row as "needs a netdev". | live runs `final4`/`final6` |
| F21 | The inline station harness used `iw phy phy0 set netns`, but the test host's station wiphy is **phy1** (`wlp39s0`), so `wpa_supplicant` never started and every earlier "station not connected / no 0x2018" result was a harness artefact. | `scripts/station-test.sh` (verified: phy1 moved, scan listed SSIDs, host restored) |

## Open blockers (ranked)

1. **Hardware proof** — the zero-touch image is built and content-verified but
   was never flashed; boot, factory reset, rejoin and 8/8 re-provision are
   unproven. This is the last acceptance gate, not a code change.
2. ~~**BSS ownership between capagent and hostapd**~~ — solved: `-23` is the
   name-exists convention (F22), attach leaves secondaries unconfigured (F23),
   and the handover + `handed_over`/`applied_*` state machine (F25) plus a
   foreground hostapd (F24) give **8/8 SSIDs** with one start per radio.
   Remaining: the relay chain is complete (Auth + AssocReq → `0x2018`), and
   with the SSID as the radio **master** the manager answers M1 (F27/F30).
   What is missing is the **AssocResp reaching the station**. `handle_assoc()`
   runs (the `0x2018` relay of the 148/156-byte AssocReq proves it) and then
   returns without a response the station ever sees. Next: read the `999`
   external-RSN hooks in `handle_assoc`/`send_assoc_resp` (the assoc may be
   deferred until the manager authorises, and the M1 path never marks the STA
   as associated) and log `send_assoc_resp()`'s return value. The `0x2019`
   `-22` comes from hostapd's `MGMT_TX` control handler (`ext_auth_mgmt_tx`),
   not from `nl_mgmt_tx`.
3. **`0x2018` on a radio without a monitor VIF** — `mon_create(phy0)` refuses
   by design, so the 2.4 GHz radio depends on the `9999a` raw
   AUTH/ASSOCREQ relay. W62 is proving that path with the installed `wpad`.
4. **Live station gate** — no station has completed 4-way → authorized →
   DHCP → ping on hardware. All earlier negative results are void (F21); use
   `scripts/station-test.sh`.
5. ~~**VAP lifecycle**~~ — solved in W52: `0x600c` parses the target
   (header port, body `0x47`/`0x08`), stops hostapd, drops the ext-auth
   socket/datachan key, deletes the netdev only when the ownership table
   proves it ours, waits for it to disappear, then releases the id.  A
   duplicate `0x6016` is ignored (same body) or restarts in place (changed
   body), never stacks; a failed start is retried 5 times and reported.  A
   5 s watchdog reaps orphan hostapd/pid/conf/socket/netdev objects.  See
   `docs/W52-LIFECYCLE.md`, `docs/W38-LIFECYCLE.md` and the live W52 run.
6. **Zero-touch boot** — the client and hostapd must live in ROM (custom
   image). The certificate no longer does: since W43 the agent generates its
   key + CSR and enrols on first boot when `/etc/cap` is empty, then re-joins
   with the stored certificate (manager `require-peer-certificate=no`, the
   default). Still open: client + hostapd in ROM, and the manager-only BSS
   path above.
7. **No manual fallback allowed** — no SSH-driven bootstrap, no local
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
    happens when the manager rotates its CA — **done in W43**
    (`native/src/cert.inc`, `scripts/lab-cert-lifecycle.sh`). Remaining:
    `require-peer-certificate=yes` has no protocol-level recovery after a
    factory reset, by design.
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

---

## Update 2026-11-11 — what is resolved and what is left

Resolved and merged into `main`:

* **Manager-only VAP creation** — `0x500b` creates the netdev (real ifindex in
  `0xd00b`), `0x6016` starts a per-VAP hostapd with `external_rsn_auth=1`, no
  passphrase, and the manager's exact RSN IE (`external_rsn_ie`). 8/8 VAPs are
  provisioned with zero `wifi-iface`.
* **PSK-free 4-way** — the manager authenticates; the CAP relays (`0x2018`,
  `0x201b`, `0x201c`) and installs `0x201f` keys. Lab: WPA2-PSK 10/10,
  SAE and OWE 14/14, key-free CAP.
* **Channel table** — one `0x0a` descriptor per (frequency, band, width),
  `BODY_MAX` 8192, so `2ghz-n` and `5ghz-ac` profiles start (live-proven).
* **Ownership** — ubus → uci → `/etc/config/wireless` → refuse; netifd always
  wins a name, MLD netdevs are never adopted, unknown means read-only.
* **Lifecycle** — full `0x600c` teardown, idempotent create, vapid release,
  orphan reaping; live 3 cycles × 8 VAPs, 0 failures.
* **5 GHz per-BSS start** — mt76x02 BSS index from MAC byte 0, legal-address
  allocator, `noscan` for non-DFS VHT80, monitor never index 0; 8/8 hostapd
  `AP-ENABLED` in isolation.
* **Recovery** — new-session deauth, frame deadline, silence reconnect,
  fail-closed TLS.
* **Zero-touch enrolment** — CSR `0x76` → `0x77`/`0x78`, random CN, re-enrol on
  duplicate/expired cert or CA rotation; no certificate needed in ROM.
* **EXT_AUTH_TX interop** — the daemon did not strip the control-wire newline,
  so every M1/M3 was rejected before TX. Fixed, with a one-shot fallback to
  `nl80211` control-port TX.

Still open:

0. **One hostapd process per VAP contends on the phy.** After the pid-file
   fallback (`3492186`) the live manager-only run reaches 4/4 VAPs, every
   hostapd logs `AP-ENABLED`, and then the instances die within ~1 s; one is
   caught in state `D` inside nl80211. The same happens with a single VAP, so
   it is not sibling contention on the management side: OpenWrt and netifd run
   **one hostapd per phy with `bss=` sections**, while this CAP starts one
   process per VAP. The structural fix is to generate one config per phy
   (interface= + bss=) and start it once, then ADD/ENABLE new BSSes through the
   hostapd control socket instead of spawning a new daemon.
   Earlier symptom (kept for the record): **duplicate VAP rows gave two
   hostapd instances per BSS**. In the live
   manager-only run the same port ends up with two names
   (`/tmp/vap-phy0-ap1.conf` and `/tmp/vap-cap0-1.conf`), the second hostapd
   fails with `nl80211 driver initialization failed`, and the reconcile loop
   retries every tick (7-12 starts). `own_hostapd_pid()` now falls back to the
   process table (`b9ea94c`), but the root cause is the claim path producing a
   second name/row for the same port. Fix: one row per port, rename only on a
   real netifd conflict, and never start a second instance while one is alive.
1. **0x2018 relay on a 4-interface radio**: the MT7603E allows four interfaces
   and all four are BSSes, so the monitor VIF is refused; hostapd owns
   `REGISTER_FRAME`. Fixed in `58a3149` by forwarding hostapd's raw
   `AUTH`/`ASSOCREQ` (relayed by patch `9999a`, enabled with
   `external_rsn_sae=1`) as `0x2018`. Needs a live run with a wpad that carries
   `9999a` to confirm M1 -> M2 -> M3.
2. **Full live manager-only run is not green end to end**: with the newest
   build the manager provisions 8 VAPs and the configs are correct, but a 5 GHz
   hostapd still lands in state `D`, a netifd-named `phy0-ap0` is created next
   to the ownership names, and no station completes the 4-way. Needs one quiet
   window to bisect (start serialisation vs VAP renaming vs BSS index).
3. **Repeated `0x6016`** can still spawn extra hostapd attempts in that run.
4. **Legacy mode is not fully passive**: a stale journal (`capagent-vaps.state`)
   makes the reconcile loop start hostapd on netifd-owned BSSes even when
   ownership says `legacy`. `vap_provision()` is gated (`3582444`); the
   reconcile path still needs the same gate.
5. **Factory-reset on hardware** — the zero-touch image passes 55/55 static
   checks and has never been flashed.
6. **Multi-VAP concurrency** for SAE/OWE/PMF and **GTK rekey soak** are not
   proven on hardware.
