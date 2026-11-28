# Documentation index

Canonical documentation for the MikroTik CAPsMAN v2 client. Start with the
top-level [`README.md`](../README.md); the documents below go deeper.

| Document | What it covers |
|---|---|
| [`../README.md`](../README.md) | project overview, current status, install, build, configuration |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | roles, control plane, datapath families and the split-MAC chain |
| [`BUILD.md`](BUILD.md) | reproducible SDK/toolchain build and the hostapd patch recipe |
| [`MANAGER-ONLY.md`](MANAGER-ONLY.md) | zero-local-config (manager-only) proof and reproduction steps |
| [`MULTI-IDENTITY.md`](MULTI-IDENTITY.md) | one identity per SSID, plus the one-CAP/eight-radio solo mode |
| [`6GHZ-HWSIM.md`](6GHZ-HWSIM.md) | 6 GHz on a virtual radio: `6ghz-ax` and `6ghz-be` live |
| [`HARDWARE-6GHZ-MLO-PLAN.md`](HARDWARE-6GHZ-MLO-PLAN.md) | real 6 GHz / WiFi 6E–7 / MLO hardware bring-up plan |
| [`11K-HWSIM.md`](11K-HWSIM.md) | 802.11k beacon reports and 802.11v BTM on a virtual station |
| [`CAPSMAN-COVERAGE.md`](CAPSMAN-COVERAGE.md) | honest matrix of manager settings: ✅ / 🟡 / ➖ / ❌ |
| [`OPEN-PROBLEMS.md`](OPEN-PROBLEMS.md) | chronological fact log and the current ranked blockers |
| [`FINDINGS.md`](FINDINGS.md) | control-protocol / TLV reference |
| [`REGRESSION-GATE.md`](REGRESSION-GATE.md) | acceptance modes, pass rules, baselines |
| [`../SECURITY.md`](../SECURITY.md) | threat model and deployment hardening |
| [`../patches/README.md`](../patches/README.md) | hostapd patch series (999 … 9999j) |
| [`RELEASES.md`](RELEASES.md) | index of per-release notes (v0.4.0 → v0.6.6) |
| [`history/`](history/README.md) | superseded work reports, kept as evidence only |

Current version: **v0.6.6** ([release](RELEASE-0.6.6.md),
[all releases](RELEASES.md)).
