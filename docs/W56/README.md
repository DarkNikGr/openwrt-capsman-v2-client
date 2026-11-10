# W56 patch series

One copy per base.  Each copy applies with `git am` (checked on a fresh
worktree) and produces a tree identical to the corresponding
`w56-5ghz-rebased*` branch.

| base | command |
|---|---|
| `origin/main` `7bfec3a` (W54 merged) | `git am patches/main/000*.patch` |
| `w52-vap-lifecycle` `d7363cb` | `git am patches/w52/000*.patch` |

`main` already contains W54 (`7bfec3a`), so its series is the single W56
commit.  W52 is based on the pre-W54 `f6cd5c8`, so its two-patch series
carries the W54 change first.

The W52 copy additionally contains the merge resolution: the W52 lifecycle
functions keep their names, `vapid_release*()` frees the mt76x02 index, and
the allocator stores both the manager MAC and the real BSSID.
