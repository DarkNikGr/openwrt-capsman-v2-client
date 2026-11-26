# v0.5.1 — restart converges to 8/8, WPA3/SAE live, warning-free build

Patch release on top of v0.5.0. No behaviour change on the proven paths; it closes
the last reproducibility gap in the agent and hardens the code.

## Highlights

* **A capagent service restart converges to 8/8.** The manager renumbers its VAP
  slots, and a repeated `0x6016` used to be swallowed ("already running") because
  `own_hostapd_pid()` answers with the phy-wide pid for every ifname, so the row
  never entered the config. Now a live daemon that does not carry a row forces a
  phy rebuild, rows superseded by the same SSID on another port are released,
  leftover `phyN-apM`/`capN-M` netdevs without a journal row are removed, and
  hostapd children are `waitpid()`-reaped (a `Z` state is never "alive").
  Live: two consecutive restarts → `ssids=8`, `conf0=4 conf1=4`, 2 live hostapd,
  0 zombies.
* **WPA3/SAE works live.** `authentication-types=wpa3-psk` produces
  `sae_pwe=2` + `group_mgmt_cipher=AES-128-CMAC` + `external_rsn_sae=1`; the
  manager's M1 (209 B) is relayed, the station answers, and `0x201f` installs
  the PTK with `SET_STATION MFP` → `authorized: yes`, −37 dBm.
* **Warning-free, analyzer-clean build.** `-Wall -Wextra -Werror` (mipsel) is
  clean; `gcc -fanalyzer` reports nothing. The RSN/PMF/SAE decision moved into
  `native/src/rsn_decide.h` with `tests/test_rsn.c` (PSK, MFPC, MFPR, SAE, OWE,
  PSK-SHA256, truncation) wired into `make check` and CI, proving the generated
  hostapd config is byte-identical to the deployed one.
* **The image script works from scratch.** A clean run of
  `scripts/build-image.sh` now succeeds without caches. Five real bugs were
  fixed: the missing-Perl check only set a variable; `grep BUILD_LUA=OFF` matched
  libubox's *host* options and skipped the target edit; `-x` on non-executable
  `rules.mk`/`Makefile` re-downloaded the SDK and ImageBuilder every run; a
  clean clone has no `native/capagent-mipsel` (the script now builds it); and
  the unsquashfs check tripped over `/dev/console`.
* **Station harness fixes.** The wiphy number changes across driver reloads
  (`phy1` → `phy6`), so it is resolved from the interface; `KEY_MGMT=SAE` and
  `MFP=2` are supported; `ieee80211w` must live inside the `network` block (as a
  global wpa_supplicant rejects the whole config).

## Verified on

Xiaomi Mi Router 4A Gigabit (ramips/mt7621, OpenWrt 24.10.0) against
RB1100AHx4 / RouterOS 7.25.1. `make check`: ownership, netifd_status, extmux,
iw frequency, RSN decisions, crypto KATs and the 27-check policy selftest all
pass.

## Artifacts

| Asset | What it is |
|---|---|
| `capagent-mipsel` | bare static client for mips/mipsel OpenWrt (mt7621, reference Xiaomi) |
| `capagent-aarch64` | bare static-pie client for aarch64 OpenWrt (WiFi 6/7 APs) |
| `capagent-*-bundle.tar.gz` | the binary + `install.sh` + `capagent.conf.example` |
| `mi-4a-zero-touch-sysupgrade.bin` | full zero-touch image for the reference Xiaomi |
| `SHA256SUMS` | hashes for everything above |

The bare binaries are the same code as the image (HEAD at the tag). They need a
patched `wpad` on the target for the external-RSN options; the image already
contains it.

## Still open

* The zero-touch image ships no `br-vlan<N>` bridges, so an `on-cap` datapath
  has nowhere to forward until they exist (see F49 in `docs/OPEN-PROBLEMS.md`).
* Secure c2 datachan (`a2=2`), `MANAGER=auto` (DHCP option 138), PMF-required
  live, `wpa2-eap`, and the rest of the matrix in `docs/CAPSMAN-COVERAGE.md`.
