# v0.6.4 — one CAP identity with eight radios (single entry in Remote CAP)

Feature release on v0.6.3. The Xiaomi can now appear as **one** CAP in the
MikroTik's *Remote CAP* list while every SSID still authenticates, instead of
one CAP identity per SSID.

## One CAP, eight radios

Run one capagent with all eight fake radios and one certificate/identity:

```
MACS=02:D1:27:1B:2D:A0,…,26:D1:27:1B:2D:90
PHYS=0,0,0,0,1,1,1,1
IDENTITY=OpenWrt-CAPSOLO
RUN_TAG=solo
```

(`/etc/cap/capagent-solo.conf.example`; the init supports `PHYS`/`RUN_TAG`.)
Verified on the Xiaomi after a **cold reboot**:

```
cap=OpenWrt-CAPSOLO@10.0.0.126   (8 radios, one CAP)
ssids=8 capagent=1 hostapd=10
all eight station tests: authorized: yes, 3/3, 0%
```

The fixes that made it reliable:

* **Keep the manager's BSSID.** The allocator now accepts a locally
  administered unicast MAC with a free driver BSS index instead of remapping
  the 5 GHz fake-radio MACs (`2A/2E/22/26:…:90`) to the phy's `:83` plan; the
  manager drops the 4-way when its BSSID is changed.
* **Per-radio hostapd files** are `cap-phyN.conf`/`cap-phyN.pid` for untagged
  runs, so the ownership scan cannot unlink a live hostapd as a stale VAP;
  liveness also accepts a pid whose argv hostapd rewrote (`/proc/comm`).
* **Monitor/BSS planning** uses a logical representative of the real phy
  while keeping the real wiphy index; CAC is no longer treated as
  AP-ENABLED; BSSes on a shared real phy bridge after start; the frequency
  fallback uses the real radio band (not logical parity).

The default image still uses the normal single-identity topology
(`MACS=auto`), which needs no per-SSID rules; the solo mode is opt-in for a
manager that already has the eight provisioning rules.

## Proven earlier and unchanged

6 GHz SAE 20/80 MHz datapath with ping 0%, 11k beacon-report relay, 802.11v
BTM request/response, live `0x6017` security changes, and the eight-identity
fallback. `6ghz-ax` as a *configuration band value* remains a RouterOS
limitation (the CAP's 6 GHz channels are selected with `6ghz-be`; the manager
still reports the station as `band=6ghz-ax`).

Image sha256 `05a3c52e2955282308846ad23abb7c38ae6b33f5715fc385fedc96c5f9232d76` (7,472,226 B).
