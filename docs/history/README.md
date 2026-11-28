# Historical work reports

These files are **historical track records**, kept as evidence. They are not
current documentation and several statements in them were true only at the
time they were written. For current behaviour use:

* [`../README.md`](../README.md) — status overview
* [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — control plane and datapaths
* [`../OPEN-PROBLEMS.md`](../OPEN-PROBLEMS.md) — fact log and current blockers
* [`../CAPSMAN-COVERAGE.md`](../CAPSMAN-COVERAGE.md) — manager-setting matrix

| Moved file | Original track | Why it is historical |
|---|---|---|
| [`W27-INTEGRATION.md`](W27-INTEGRATION.md) | W27 / W8 / W6 / W14 | integration record for the multi-VAP relay; behaviour is merged and documented in ARCHITECTURE/FINDINGS |
| [`W33-OWNERSHIP.md`](W33-OWNERSHIP.md) | W33 | early ownership policy; superseded by the W34 ubus model in ARCHITECTURE/README |
| [`W34-UBUS-OWNERSHIP.md`](W34-UBUS-OWNERSHIP.md) | W34 | ubus/netifd ownership model; current contract is in README/ARCHITECTURE |
| [`W38-LIFECYCLE.md`](W38-LIFECYCLE.md) | W38 | VAP lifecycle design; final implementation is described by F13/F45 and the current sources |
| [`W50-INTEGRATION.md`](W50-INTEGRATION.md) | W50 | merge-only integration record |
| [`W52-LIFECYCLE.md`](W52-LIFECYCLE.md) | W52 | lifecycle guarantees, now part of the shipped code and F13/F45 |
| [`W53-EXT-AUTH-TX.md`](W53-EXT-AUTH-TX.md) | W53 | diagnosis of the EAPOL-TX newline bug; fixed and shipped |
| [`W53-REPORT.md`](W53-REPORT.md) | W53 | same W53 investigation report |
| [`W54-MT7612E-PERBSS.md`](W54-MT7612E-PERBSS.md) | W54 | 5 GHz per-BSS bring-up; superseded by the per-radio hostapd and F74 |
| [`W62-REPORT.md`](W62-REPORT.md) | W62 | lab-only `0x2018` no-monitor relay report; the production path is live |
| [`w62-evidence/`](w62-evidence/) | W62 | raw lab logs referenced by W62-REPORT |

Nothing here was deleted: the reports and evidence are preserved under this
directory. `docs/RELEASE-*.md` are **not** historical-only in the same sense —
they are the official per-release notes and stay in `docs/`.
