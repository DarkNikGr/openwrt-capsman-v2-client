# Build and reproduce

Everything here was run on the reference build host (Fedora, x86_64) on
2026-11-10 against `main` @ `0e8960e`.  Absolute paths are the ones that were
actually used; substitute your own if they differ.

The tree builds **three artefacts**:

| artefact | used by | reproducible |
|---|---|---|
| `capagent-mipsel` (static, stripped) | the reference Xiaomi 4A / mt7621 CAP | yes, bit-identical |
| `capagent-aarch64` (static-pie, stripped) | WiFi 6/7 APs (Deco BE65 class) | yes, bit-identical |
| `wpad-mbedtls` + `wifi-scripts` ipks | hostapd side of the split MAC | yes, bit-identical (§5) |

`capagent` contains **no absolute build paths** (`strings capagent-mipsel |
grep /home` returns nothing), so the output does not depend on the build
directory.  Building the same commit twice from two separate clones produced
identical SHA-256 sums.

---

## 1. Pinned inputs

| input | path on this host | SHA-256 |
|---|---|---|
| source | `git` `0e8960e` (`main`) | — |
| OpenWrt 24.10.0 ramips/mt7621 SDK | `/home/darknik/cap-sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64` | `sdk.tar.zst` = `ccf31fd66b0196a7eb06d34cc509459916597162668dc07976122e1d13316874` |
| mipsel toolchain | `$SDK/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin` (GCC 13.3.0, OpenWrt r28427-6df0e3d02a) | part of the SDK |
| mbedTLS 3.6.2 (mipsel, static) | `/home/darknik/cap-sdk/mbedtls-3.6.2` | `mbedtls.tar.gz` = `a3c959773bc5d5b22353bc605e96d92fae2eac486dcaf46990412b84a1a0fb5f` |
| aarch64 toolchain | `/home/darknik/cap-sdk/aarch64-linux-musl-cross/bin` (GCC 11.2.1) | `aarch64.tgz` = `c909817856d6ceda86aa510894fa3527eac7989f0ef6e87b5721c58737a06c38` |
| mbedTLS 3.6.2 (aarch64) | `/home/darknik/cap-sdk/mbedtls-aarch64` | built from the same tarball |
| hostapd tarball | `/tmp/opencode/work-V21/sdk/dl/hostapd-2024.09.15~5ace39b0.tar.zst` | `43187d1ddd923970ef3821a0fe267880c2483f6f1a5acd0dd2d7906661ab1372` (= OpenWrt `PKG_MIRROR_HASH`) |
| OpenWrt 24.10.0 source | `/tmp/opencode/work-V21/src/openwrt-24.10.tar.gz` | `bd05ed9def9df4aaa6bc943eeb8affeca1b33b7f4d4c8e3c24866bf2e6935028` |

mbedTLS **must be built with `MBEDTLS_CCM_C=y`**: the secure datachan needs
AES-256-CCM and OpenWrt 24.10 ships `libmbedtls` without it.  That is why
`capagent` is linked statically (`-static`) against this prefix instead of
`+libmbedtls` from the feed.

## 2. `make -C native`

The Makefile has two modes.  With `SDK=` it expects mbedTLS staged in the
SDK; without it, it expects a standalone toolchain and an mbedTLS source
prefix.

| variable | meaning | value used here |
|---|---|---|
| `SDK` | unpacked SDK root; implies `TOOLCHAIN`, `MBEDTLS_INC`, `MBEDTLS_LIB`, `STAGING_DIR` | `/home/darknik/cap-sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64` |
| `TOOLCHAIN` | `bin/` dir of a cross toolchain (`mipsel-openwrt-linux-musl-gcc`) | `$SDK/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin` |
| `MBEDTLS` | mbedTLS prefix (only used to derive the two below) | `/home/darknik/cap-sdk/mbedtls-3.6.2` |
| `MBEDTLS_INC` | include dir with `mbedtls/` | `$MBEDTLS/include` |
| `MBEDTLS_LIB` | dir with the three `.a` files | `$MBEDTLS/library` |
| `CROSS` | toolchain program prefix | `$(TOOLCHAIN)/mipsel-openwrt-linux-musl-` |
| `QEMU` | emulator for `make check` | `qemu-mipsel` |
| `CFLAGS` | extra flags | `-O2 -Wall -Wextra -Wno-unused-parameter` (+ includes) |
| `STAGING_DIR` | exported automatically from `SDK` | — |

**One command** (build + AES-CCM KAT + policy selftest + W34 tests):

```sh
make -C native \
  TOOLCHAIN=/home/darknik/cap-sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
  MBEDTLS=/home/darknik/cap-sdk/mbedtls-3.6.2 \
  check
```

Expected result:

```
capagent-mipsel: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV),
                 statically linked, stripped
-rwxr-xr-x 1 ... 1,1M ... capagent-mipsel
crypto-selftest: RFC 3610 #1 (AES-128/8-byte tag): ok
crypto-selftest: AES-256-CCM encrypt (c2.ko cdh, seq 1): ok
crypto-selftest: AES-256-CCM decrypt: ok
crypto-selftest: corrupted tag rejected: ok
crypto-selftest: all tests passed
policy-selftest: 27 checks, 0 failure(s)
all ownership tests passed
all netifd_status tests passed
```

| output | size | SHA-256 |
|---|---|---|
| `native/capagent-mipsel` | 1,098,240 B (1.1 MiB) | `e6b066978dd11bc511fe3220abef655f58fb48d75283c7b9769dcc8ec90d876a` |

The standalone form (`TOOLCHAIN` + `MBEDTLS`) is what `scripts/build-mipsel.sh`
uses and produces the same binary:

```sh
TOOLCHAIN=/home/darknik/cap-sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
MBEDTLS=/home/darknik/cap-sdk/mbedtls-3.6.2 \
OUT=dist/capagent-mipsel ./scripts/build-mipsel.sh
```

## 3. aarch64

```sh
TOOLCHAIN=/home/darknik/cap-sdk/aarch64-linux-musl-cross/bin \
MBEDTLS=/home/darknik/cap-sdk/mbedtls-aarch64 \
OUT=dist/capagent-aarch64 ./scripts/build-aarch64.sh
```

| output | size | SHA-256 |
|---|---|---|
| `dist/capagent-aarch64` | 983,824 B (961 KiB) | `ccd1853b85101649c23af7ead64ea202a202eeae5435c4041ad239f71f600183` |

`file` reports `ELF 64-bit LSB pie executable, ARM aarch64, static-pie linked,
stripped`.  `qemu-aarch64 dist/capagent-aarch64 --crypto-selftest` and
`--selftest-policy` both exit 0 with the same output as above.

## 4. Selftests under qemu

```sh
qemu-mipsel   native/capagent-mipsel --crypto-selftest
qemu-mipsel   native/capagent-mipsel --selftest-policy
qemu-aarch64  dist/capagent-aarch64 --crypto-selftest
qemu-aarch64  dist/capagent-aarch64 --selftest-policy
```

Expected: `crypto-selftest: all tests passed` and
`policy-selftest: 27 checks, 0 failure(s)` in every combination; exit 0.
`--selftest-policy` writes its two comparison files to
`/tmp/capagent-wl-selftest-cls-*.conf` and removes nothing else; it never
touches the live system.

## 5. hostapd package recipe (`wpad-mbedtls`)

The CAP needs three things the stock `wpad` does not do: accept
`external_rsn_auth=1`, advertise the manager's RSN IE verbatim, and relay STA
EAPOL from the mac80211 path.  All of it is in `patches/`.

### Patch series

Applied **after** the 61 stock OpenWrt 24.10.0 hostapd patches, in
lexicographic order:

| patch | hunks | what it does | offset | fuzz |
|---|---|---|---|---|
| `999-external-rsn-auth.patch` | 28 | `external_rsn_auth=1`, `ext_auth_socket=`, `src/ap/ext_auth.c`, EAPOL relay to a UNIX dgram socket | 0 | 0 |
| `9997-external-rsn-ie.patch` | 7 | `external_rsn_ie=<hex>` replaces the generated RSN IE with the manager's bytes | 0 | 0 |
| `9998-external-rsn-eapol-rx.patch` | 2 | relay STA EAPOL from `ieee802_1x_receive()` (the mac80211 path) | +4 | 0 |
| `9999-external-rsn-no-psk.patch` | 4 | external mode drops every PSK field, allows a passphrase-free BSS, rejects SAE/OWE/802.1X | +1..+17 | 0 |

Total: 41 hunks, **0 fuzz**.  `scripts/patches-check.sh` reproduces this table
from the tarball (see §6).

The first patch is `999-…`, **not** `0999-…`: OpenWrt applies the whole
`package/network/services/hostapd/patches/` directory in one `$(sort)` pass
(C byte order), so a `0999-` name sorts before `110-` and is applied before
the stock patches it depends on.  With `0999` the package build fails on
context in `hostapd_cli.c` and `src/ap/hostapd.c`; with `999` it lands after
`804-…`, which is where the hunks were authored.  The pilot SDK already uses
`999-external-rsn-auth.patch`, so copying the repo series over it is a
same-name overwrite, not a duplicate.

### Steps

```sh
REPO=/home/darknik/deco-luci/cap-client
SDK=/home/darknik/cap-sdk/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64
SRC=/tmp/opencode/work-V21/src/openwrt-24.10.tar.gz   # OpenWrt 24.10.0 source

# 0. host prerequisites: a complete Perl on PATH, and pre-seed the prereq
#    stamp because this host has no g++/ncurses (not needed by hostapd).
export PATH=/tmp/opencode/work-W15/toolchain:$PATH
mkdir -p "$SDK/host" && touch "$SDK/host/.prereq-build"

# 1. a fresh SDK ships no package/ network trees: overlay them from the source
mkdir -p /tmp/owrt
tar xf "$SRC" -C /tmp/owrt --strip-components=1 \
    openwrt-openwrt-24.10/package/network/services/hostapd \
    openwrt-openwrt-24.10/package/network/config/wifi-scripts \
    openwrt-openwrt-24.10/package/libs/{mbedtls,libnl-tiny,libubox,libjson-c,libmd,udebug} \
    openwrt-openwrt-24.10/package/system/{ubus,uci} \
    openwrt-openwrt-24.10/package/utils/ucode
for p in network/services/hostapd network/config/wifi-scripts \
         libs/mbedtls libs/libnl-tiny libs/libubox libs/libjson-c \
         libs/libmd libs/udebug system/ubus system/uci utils/ucode; do
    rm -rf "$SDK/package/$p"; cp -a "/tmp/owrt/package/$p" "$SDK/package/$p"
done

# 2. the series (999-, 9997-, 9998-, 9999-)
cp "$REPO"/patches/*.patch "$SDK/package/network/services/hostapd/patches/"

# 3. enable the compile-time switch (hostapd-full.config is the config used by
#    wpad-mbedtls)
echo 'CONFIG_EXTERNAL_RSN_AUTH=y' >> \
    "$SDK/package/network/services/hostapd/files/hostapd-full.config"

# 4. wifi-scripts passthrough (see below); skipped if already applied
( cd "$SDK" && patch -p1 --forward \
    < "$REPO/patches/wifi-scripts/0001-wifi-scripts-uci-external-rsn.patch" )

# 5. no Lua headers in the SDK: disable the target Lua bindings
for mk in libs/libubox system/ubus system/uci; do
    sed -i 's|-DLUAPATH=/usr/lib/lua|-DLUAPATH=/usr/lib/lua -DBUILD_LUA=OFF|' \
        "$SDK/package/$mk/Makefile"
done

# 6. build only what is needed
cat > "$SDK/.config" <<'EOF'
CONFIG_TARGET_ramips=y
CONFIG_TARGET_ramips_mt7621=y
CONFIG_TARGET_ramips_mt7621_DEVICE_xiaomi_mi-router-4a-gigabit=y
CONFIG_PACKAGE_wpad-mbedtls=y
CONFIG_PACKAGE_hostapd-common=y
CONFIG_PACKAGE_wifi-scripts=y
CONFIG_MBEDTLS_CCM_C=y
EOF
cd "$SDK" && make defconfig
make -j8 package/network/services/hostapd/compile \
         package/network/config/wifi-scripts/compile V=s
```

The resulting ipks are in `$SDK/bin/packages/mipsel_24kc/base/`.

`hostapd-full.config` is the right file: `Package/wpad-mbedtls` is built from
`Package/hostapd-full` (`Makefile`, `Package/wpad-mbedtls/install =
$(Package/wpad/install)`), so the switch must be in the *full* config, not in
`hostapd-mini.config`.

Verify the resulting binaries before installing:

```sh
strings $SDK/build_dir/target-mipsel_24kc_musl/hostapd-*/hostapd/wpad | \
    grep -E 'external_rsn_ie|ext_auth_socket'
```

Both strings must be present.  (A pre-9997 ipk has only `ext_auth_socket`.)

Build output on 2026-11-10 from the SDK at the top of this page:

| package | size | SHA-256 (ipk) |
|---|---|---|
| `wpad-mbedtls_2024.09.15~5ace39b0-r3_mipsel_24kc.ipk` | 764,717 B | `087703c9bf0675d3fbee8e5be254def5bbf8e68adbc88763ebfb54ccd089e5e7` |
| `wifi-scripts_1.0-r1_all.ipk` | 30,362 B | `e400723188db6c904916ca656e69a70a04cca7445bdbcc833161dd9e72c4a1fc` |
| `hostapd-common_2024.09.15~5ace39b0-r3_mipsel_24kc.ipk` | 2,710 B | `1f1556399fe441af1ca6362e7b25a6f030ad1f15361dfe7fb002da2f83596b31` |

The installed `/usr/sbin/wpad` inside the wpad ipk is
1,394,175 B, SHA-256
`d5a3836068c0f2b31b43a110f11da9e5c55c985e4fbeee4150f248a4b6fc818e`.
Two independent clean builds (hostapd `build_dir` deleted, package sources
re-overlaid from the OpenWrt tarball) produced the same ELF **and** the same
ipk hashes; `ipkg-build` normalises the inner tar mtimes.
`strings /usr/sbin/wpad` must contain `external_rsn_auth`,
`external_rsn_ie`, `ext_auth_socket` and `EXT-AUTH:`.

### wifi-scripts passthrough patch

`patches/wifi-scripts/0001-wifi-scripts-uci-external-rsn.patch` teaches
`/lib/netifd/hostapd.sh` to pass `external_rsn_auth` and `ext_auth_socket`
from UCI into the generated per-BSS hostapd config, and defaults
`external_rsn_auth` to `0`, so stock behaviour is unchanged unless a section
opts in.  Without it, `capagent`'s `hostapd.<ifname>.conf` still works (the
agent writes those files itself), but a `wifi-iface` with
`option external_rsn_auth 1` is silently ignored.

The patch is against the **pristine** OpenWrt 24.10.0
`package/network/config/wifi-scripts/files/lib/netifd/hostapd.sh`; applying it
to an already patched tree is detected and skipped by
`scripts/patches-check.sh --wifi-scripts`.

## 6. Patch-series check

```sh
./scripts/patches-check.sh \
  --tarball /tmp/opencode/work-V21/sdk/dl/hostapd-2024.09.15~5ace39b0.tar.zst \
  --openwrt-patches $SDK/package/network/services/hostapd/patches \
  --wifi-scripts $SDK
```

Output (2026-11-10):

```
tarball : .../hostapd-2024.09.15~5ace39b0.tar.zst
pristine: /tmp/opencode/patches-check.XXXXXX/hostapd-2024.09.15~5ace39b0
stock   : .../package/network/services/hostapd/patches
stock   : 61 patches merged (pristine OpenWrt 24.10.0 tree)

series  : .../cap-client/patches
ok    999-external-rsn-auth.patch (28 hunks, offset 0, fuzz 0)
ok    9997-external-rsn-ie.patch (7 hunks, offset 0, fuzz 0)
ok    9998-external-rsn-eapol-rx.patch (2 hunks, offset 4, fuzz 0)
ok    9999-external-rsn-no-psk.patch (4 hunks, offset 1..17, fuzz 0)

wifi-scripts: .../sdk
ok    wifi-scripts/0001-wifi-scripts-uci-external-rsn.patch (dry-run)

RESULT: OK — 4 patch(es) from this repo, 41 hunks, 0 fuzz
```

Exit status is 0 only in that case.  Any rejected hunk, any fuzz above
`--allow-fuzz` (default 0), and any unappliable wifi-scripts patch make it
exit 1.

The script merges the stock and repo patch files into one directory and sorts
the *basenames* with `LC_ALL=C`, which is the order OpenWrt's own `$(sort)`
produces — not the ambient locale's.  That detail matters: under a UTF-8
locale (this host runs `el_GR.UTF-8`), `sort` ignores `-` and puts `9997-…`
before `999-…`, which silently changes the result.  Always compare with
`LC_ALL=C`.

Why the stock series matters: the `patches/` series is authored against the
*prepared* hostapd tree that OpenWrt hands to the compiler, not against the
bare upstream tarball.  Against the bare tarball `999` still applies with
offsets but `9997`/`9999` fail on context in `hostapd_cli.c`,
`src/ap/hostapd.c` and `src/ap/ieee802_1x.c` that earlier OpenWrt patches
move.  Running without `--openwrt-patches` therefore fails by design and is
only useful for seeing which hunks are context-sensitive:

```
RESULT: FAIL (1 patch(es) failed)
```

## 7. Reproducibility notes

* `capagent` builds are deterministic: two clean clones of `0e8960e` at
  different paths produced the same SHA-256 for both architectures.  GCC's
  `-ffile-prefix-map` is **not** needed; the stripped binaries carry no build
  path and no build timestamp.
* The hostapd/wifi-scripts **ipk** files reproduced byte-for-byte across two
  clean builds in this SDK (`ipkg-build` normalises mtimes), and the inner
  `/usr/sbin/wpad` ELF matched; see the table in §5.
* `strip` is invoked in-place by `native/Makefile` and by both build scripts,
  so the hash above is of the installed artefact.
* Pebble in the 24.10 SDK on this host: the distro Perl lacks `FindBin`,
  `IPC::Cmd`, `Thread::Queue`, and `g++`/`ncurses` are absent, so
  `make defconfig` refuses to run.  Use a complete Perl first on `PATH` (the
  pilot used `/tmp/opencode/work-W15/toolchain/perl`) and pre-seed
  `$SDK/host/.prereq-build` (or `make FORCE=1`) since the hostapd build is
  pure C and does not need those host tools.
* libubox/ubus/uci target builds enable their Lua bindings even when
  `CONFIG_PACKAGE_*lua` is off; 24.10 does not ship Lua headers in the SDK.
  Add `-DBUILD_LUA=OFF` to the target `CMAKE_OPTIONS` of
  `package/libs/libubox`, `package/system/ubus` and `package/system/uci`
  before compiling (the Makefiles set it only for the *host* variant).
  `ucode` also needs `package/libs/{libmd,udebug}` overlaid next to it, or its
  configure step stops at `Package 'libmd' not found`.
