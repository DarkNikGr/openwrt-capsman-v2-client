# v0.6.1 — multi-identity converges on every boot (staggered hostapd starts)

Patch release on v0.6.0. v0.6.0 made all eight SSIDs authenticate; this
release fixes the one thing a cold boot could still break: when the eight
procd instances opened at the same instant, four of the eight hostapd
processes lost the shared-phy race and died, leaving their AP netdevs up and
beaconing but unable to answer authentication (`AUTH_TIMED_OUT`, empty manager
registration table).

## Fix

* **F75 — stagger the identities.** `/etc/init.d/capagent` multi mode now
  delays identity *n* by `n × CAPAGENT_STAGGER` (default 15 s; override in
  `/etc/cap/capagent.conf`). This is the same serialisation the manual
  launcher (`DELAY=20`) has always used. A respawned instance keeps its slot,
  so recovery is also deterministic.
* Nothing else changes: the binaries, hostapd patches and manager rules are
  the same as v0.6.0.

## Verified on

Clean `sysupgrade -n` of the image below, then
`cp /etc/cap/identities.conf.example /etc/cap/identities.conf` and a **cold
reboot**:

```
hostapd=10 capagent=8          # 8 identity hostapd + the system wpad pair
ssids=8
phy0-aap0 … phy0-dap0          # 2.4 GHz: cap-test / cap-guest / cap-iot / cap-hidden
phy1-eap0 … phy1-hap0          # 5 GHz:  cap-test / cap-guest / cap-iot / cap-hidden
```

All eight station tests after the reboot: `authorized: yes`, `ping 3/3, 0%`
(2.4 GHz at 2437 MHz, 5 GHz at 5180 MHz, hidden SSIDs included). The manager
showed all eight registrations at once, four `band=2ghz-g` and four
`band=5ghz-ac`, VLANs 30/10/20/20.

Image sha256 `065e2330716be02d66c2fb1ccdf2cd71ff599c571134aff10022528e7161771d`
(7,472,226 B).

## Still open

* 11k live (F71, station firmware drops the RM IE), 802.11v (no deterministic
  manager trigger), 6 GHz/MLO (no 6 GHz radio), `local-forwarding` (CAPsMAN v2
  never sends the PSK).
* A station on a **virtual (slave) VAP** still does not reach the 4-way
  (F58–F60); multi-identity is the supported way to authenticate every SSID.
