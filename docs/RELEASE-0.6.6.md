# v0.6.6 — `6ghz-ax` is live; datachan/OWE hardening

Feature release on v0.6.5. The one-CAP/eight-radio topology is unchanged.

## `channel.band=6ghz-ax` is live (F79 was confounded)

The earlier "vendor-blocked" verdict changed only the **NEWPHY `0x4d`** band
label (0x05–0x1f) while the `0xD00B` `0x000A` channel descriptor kept `0x06`
in every run. The manager matches the profile's band **against the descriptor
byte**, not against the NEWPHY label.

The 6 GHz descriptor now uses the generation band:

* HE-only 6 GHz → `0x04` (`6ghz-ax`), the new default
* EHT 6 GHz → `0x06` (`6ghz-be`)
* `CAPAGENT_BAND6=<hex>` overrides both for a lab sweep

Verified on a no-EHT/no-UHR `mac80211_hwsim` 6 GHz radio + RB1100AHx4 /
RouterOS 7.25.1:

```
radio: 6ghz-ax:20mhz,...   5955/ax
VAP:   MDB ... channel.band=6ghz-ax
hostapd: phy0-ap0: AP-ENABLED @ 5955 MHz, 80 MHz
station: SAE (WPA3), authorized: yes, ping 3/3, 0%
```

`6ghz-be` remains available for EHT radios (or `CAPAGENT_BAND6=6`). The
reference Xiaomi still has no 6 GHz hardware; this is a virtual-radio result
with the real manager and the real CAP agent.

## Security and robustness

Found by a 10-agent review; all are in this build:

* **Plain datachan RX stack overflow fixed.** A 2064-byte `a2=1` frame for an
  unknown VAP could write 12 bytes past `dp_rx_frame()`'s local buffer; it is
  now rejected by an explicit bound.
* **Plain datachan source check.** An `a2=1` frame is accepted only from the
  TLS manager host; a forged keepalive with an unknown cookie is dropped
  instead of falling through to the plain parser. `CAPAGENT_DC_ANY_SOURCE`
  preserves the old lab behaviour.
* **Per-VAP datachan keys and rekey.** The `a2` variant and the two key slots
  are per VAP, not one global slot: mixed `a2=0/1/2` VAPs no longer decrypt
  with another VAP's key, `a2=0` VAPs drop their frames, and `0x402b` touches
  only secure VAPs and resets the replay window on a real slot change. A
  host test (`test_datachan`) pins it.
* **Local-OWE key ownership.** For a pure-OWE VAP the manager's `0x201f`
  GTK/IGTK/PTK and `0x201c` EAPOL no longer overwrite hostapd's locally
  derived keys, and no ext-auth socket/relay is registered. Verified:
  `wl: phy2-soloap0 is local-OWE (hostapd owns the 4-way)` and
  `0x201f: port 0x0200 is local-OWE, 2 key(s) left to hostapd`; the OWE
  station is `authorized: yes`, ping 0%.
* **Stock-hostapd OWE no longer downgrades to open.** Local OWE does not
  require the `external_rsn_sae` patch; an unpatched hostapd still gets a
  real `wpa=2`/`wpa_key_mgmt=OWE` BSS.
* **MLME frame-length guards and fd-0 fix.** Truncated Auth/AssocReq frames
  are rejected; the first session no longer closes stdin.
* **`0x6017` ownership guard.** `--no-vap-teardown`/netifd read-only/legacy
  modes no longer stop a hostapd they do not own.
* **`capagent --version` is honest.** It printed `0.4.0` from a hardcoded
  literal in every release; the build now injects `VERSION` and `make check`
  fails on a mismatch. The image build also refuses to reuse a stale
  `native/capagent-mipsel` and verifies `multi-cap.sh` and the solo example
  in the payload.

## Verified on

Xiaomi Mi Router 4A Gigabit, RB1100AHx4 / RouterOS 7.25.1:

```
cap=OpenWrt-CAPSOLO@10.0.0.126 (8 radios)
ssids=8  capagent=1  hostapd=10
2.4/5G cap-test, cap-guest, cap-iot, cap-hidden: authorized: yes, 3/3, 0%
OWE (CAP-local): authorized: yes, 3/3, 0%
a2=1 on 5 GHz: authorized: yes, 3/3, 0%, datachan plain both ways
live 0x6017 passphrase change: 8/8, no restart
```

Image sha256 `c5f8813e4d2e0065f336c03556ea9d887dece7d7dc4c08451cb5acd5c3b5fc3d` (7,472,226 B).

## Still open

* `on-capsman` on the 2.4 GHz radio: RouterOS refuses the 2.4-only band class
  (`a2=0`); the 5 GHz radio is live (F84).
* Real 6 GHz / MLO hardware: the 6 GHz AX datapath is proven on hwsim; see
  `docs/HARDWARE-6GHZ-MLO-PLAN.md` for the hardware matrix.
* Slave-VAP authentication in the plain single-identity topology (F58–F60).
