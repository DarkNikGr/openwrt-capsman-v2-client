# W50 — integration record

This branch consolidates the open W-tracks onto `origin/main` (`3764ba6`,
W41 channel table + W42 regression gate). It is a merge-only branch: no new
runtime behaviour is invented here. Every non-trivial resolution keeps main's
newer manager-only VAP/hostapd + W33/W34 ownership code and takes the
branch's feature code and prose.

## Merged (in this order)

| order | branch | tip | result |
|---|---|---|---|
| 1 | `w47-build-docs` | `ad6e9bb` | clean; docs + `0999-` → `999-` patch rename |
| 2 | `w43-certs` | `67b8b4c` | 3 content conflicts, resolved (below) |
| 3 | `w36-mlme` | `2bfbd22` | 1 content conflict, resolved (below) |

Merge commits: `e6005af` (W47), `5398e07` (W43), `155ac76` (W36).

## Not merged

| branch | tip | why |
|---|---|---|
| `w39-deterministic-vap-start` | `5364e76` | already an ancestor of `origin/main`; nothing to merge |
| `w46-mgmt-auth` | `0e8960e` | branch tip is an ancestor of `origin/main`; the actual W46 edits are **uncommitted** in `/tmp/opencode/work-W46/repo` (6 modified source files + `patches/9999a-external-rsn-sae.patch`). Not copied: another track owns that working tree and a merge must be reproducible from a pushed commit. Follow-up: commit/push W46, then merge it. |
| `w38-vap-lifecycle` | `9a961c3` | discovered on `origin` but not in the W50 branch list. One 919-line commit touching six VAP/datapath files; dry-run against main conflicts in **all six** (`channels.inc`, `datapath.inc`, `main.inc`, `mgmt.inc`, `nl80211.inc`, `vap.inc`). Out of scope for a mechanical consolidation: it needs its own review/merge track. It is the natural prerequisite for enabling W36's MLME teardown path. |

## Resolutions

### W43 — `native/src/main.inc`
Conflicts were additive, not competing:
* `run_once()`: keep W34's `last_own` and add W43's `enroll_deadline`.
* option enum: keep W42's `--selftest-pmap`/policy/ownership entries and add
  `--enroll`, `--no-enroll`, `--cert-cn`.
* reconnect loop: keep `own_service(&c)` and use W43's
  `cert_retry_delay()`/`g_cert_fail_streak` backoff instead of a fixed 5 s.
  Note: ownership repair now shares the certificate backoff (max 60 s).

### W43 — `README.md`, `docs/OPEN-PROBLEMS.md`
Main's W41/W42 "what does not work" list is newer than the branch's base.
Kept it, then added W43's certificate-lifecycle prose (auto re-enrolment,
`require-peer-certificate=no` caveat, `--enroll`/`--no-enroll`/`--cert-cn`)
and the branch's "certificate lifecycle done in W43" note.

### W36 — `native/deploy/capagent.conf`
Kept main's W33/W34 ownership block and appended the W36 `MLME`/`MLME_PORT`
documentation. No code conflict; `mlme.inc`, `mgmt.inc`, `util.inc` and the
init script merged cleanly.

## Build and tests

* SDK: OpenWrt 24.10.0 ramips/mt7621 GCC 13.3.0, static mbedTLS 3.6.2.
* `capagent-mipsel`: built, stripped, 1,124,848 B,
  sha256 `e9ff237f848d0f15667d6d48f1963f645b9c16cba01f2157165ff11be2741dbe`.
* `--crypto-selftest`: 4/4 ok.
* `--selftest-policy`: 27 checks, 0 failures.
* `--selftest-pmap`: PASS (dead ifindex re-resolved, netdev recreated).
* W34 ownership + netifd-status tests: PASS (`make check`).
* W42 harness, `--legacy`, self-contained hwsim/hostapd lab: full-lab
  association + 4-way PASS; DHCP/ping SKIP by surrogate design. The live
  manager/CAP targets were deliberately pointed at a dead endpoint so the
  shared Xiaomi was never contacted.

## Known follow-ups

1. W46 has to be committed and pushed before it can be merged.
2. `w38-vap-lifecycle` is still open and unmerged; it should be merged (or
   explicitly dropped) before W36 is enabled in production. Its dry run
   conflicts in all six files it touches.
3. W36 introduces two `-Wformat-truncation` warnings in
   `util.inc:phy_name_by_index`; the build is not warning-free.
4. W36's MLME teardown/`0x600c` path is not covered by the W38 lifecycle work
   (W38 is not on `origin/main`); test create/destroy cycles before enabling
   `MLME=yes`.
5. Re-run the live W42 gate (read-only) when the CAP is free; the committed
   `baseline/legacy.json` is still a pre-integration snapshot.
6. `docs/BUILD.md` pins `0e8960e` as its measurement base; update it to the
   integration tip after merge.

## Landing on main

```sh
git fetch origin
git checkout main
git merge --ff-only origin/w50-integration
# only after review / CI:
git push origin main
```

If `main` has advanced, either rebase this branch onto the new `origin/main`
and re-run the build/tests, or use a normal merge commit. Do not force-push.
A PR is equivalent: base `main`, head `w50-integration`.
