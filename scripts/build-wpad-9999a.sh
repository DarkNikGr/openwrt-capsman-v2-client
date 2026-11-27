#!/bin/sh
# Build a wpad-mbedtls ipk that carries the full external-RSN patch set
# (999/9997/9998/9999/9999a/9999b) for OpenWrt 24.10 / ramips-mt7621.
#
# Why this exists: the official openwrt-sdk-24.10.0 tarball does NOT ship the
# hostapd package sources ("hostapd pkg ABSENT"), so the SDK cannot build a
# patched wpad on its own.  This script clones the matching *source* tree at
# the v24.10.0 tag, overlays only the packages we need into the SDK, builds
# the missing target-side dependencies (mbedtls, libubox, ubus, uci) and then
# builds wpad-mbedtls.
#
# Result, verified on the reference Xiaomi:
#   external_rsn_sae=2  EXT_AUTH_MGMT_TX=1  external_rsn_ie=7
# which is what lets a 4-interface radio feed 0x2018 without a monitor VIF.
#
# Usage: scripts/build-wpad-9999a.sh [WORKDIR]     (default: /tmp/wpad-build)
set -eu

WORK=${1:-/tmp/wpad-build}
REPO=$(cd "$(dirname "$0")/.." && pwd)
OWRT_TAG=v24.10.0
SDK_URL=https://downloads.openwrt.org/releases/24.10.0/targets/ramips/mt7621/openwrt-sdk-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64.tar.zst

say() { echo "[wpad-build] $*" >&2; }

# Host prerequisites: OpenWrt's prepare-tmpinfo needs a *complete* perl.
if ! perl -e 'use FindBin; use threads; use Time::Piece' 2>/dev/null; then
	say "host prerequisite missing: a complete Perl (FindBin, threads, Time::Piece)"
	say "  Fedora: dnf install perl-core perl-Time-Piece"
	exit 1
fi
for tool in curl tar zstd git python3 make; do
	command -v "$tool" >/dev/null 2>&1 ||
		{ say "host prerequisite missing: $tool"; exit 1; }
done

mkdir -p "$WORK"
SRC=$WORK/owrt
SDK=$WORK/sdk

if [ ! -d "$SRC/package/network/services/hostapd" ]; then
	say "cloning OpenWrt $OWRT_TAG"
	git clone -q --depth 1 -b "$OWRT_TAG" \
		https://github.com/openwrt/openwrt.git "$SRC"
fi

if [ ! -f "$SDK/rules.mk" ]; then
	say "downloading the 24.10.0 mt7621 SDK"
	curl -fsSL --retry 2 -o "$WORK/sdk.tar.zst" "$SDK_URL"
	mkdir -p "$SDK"
	tar --zstd -xf "$WORK/sdk.tar.zst" -C "$SDK" --strip-components=1
	rm -f "$WORK/sdk.tar.zst"
fi

# 1. hostapd + the deps the SDK does not stage as sources
for p in network/services/hostapd libs/mbedtls libs/libubox libs/libnl-tiny \
	 libs/libjson-c libs/libmd libs/udebug system/ubus system/uci \
	 utils/ucode network/config/wifi-scripts; do
	[ -d "$SRC/package/$p" ] || continue
	mkdir -p "$SDK/package/$(dirname "$p")"
	rm -rf "$SDK/package/$p"
	cp -a "$SRC/package/$p" "$SDK/package/$p"
done

# 2. patches + the external-RSN build flag
for f in 999-external-rsn-auth 9997-external-rsn-ie 9998-external-rsn-eapol-rx \
         9999-external-rsn-no-psk 9999a-external-rsn-sae \
         9999b-external-rsn-tx-retval 9999c-hostapd-use-existing-bss 9999d-hostapd-set-mode-ealready \
         9999e-external-rsn-null-wpa-sm 9999f-external-rsn-action \
         9999g-hostapd-rrm-ie-without-capab \
         9999h-external-rsn-queue-early-eapol; do
	cp "$REPO/patches/$f.patch" \
	   "$SDK/package/network/services/hostapd/patches/$f.patch"
done
grep -q CONFIG_EXTERNAL_RSN_AUTH \
	"$SDK/package/network/services/hostapd/files/hostapd-full.config" ||
	printf '\nCONFIG_EXTERNAL_RSN_AUTH=y\n' >> \
	"$SDK/package/network/services/hostapd/files/hostapd-full.config"

# 3. hostapd variants: build only wpad-mbedtls + hostapd-common
python3 - "$SDK/package/network/services/hostapd/Makefile" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
keep = ('hostapd-common', 'wpad-mbedtls')
out = []
for line in s.splitlines():
    if line.startswith('$(eval $(call BuildPackage,') and \
       not any('BuildPackage,' + k + ')' in line for k in keep):
        out.append('#' + line)
    else:
        out.append(line)
open(p, 'w').write('\n'.join(out) + '\n')
PY

# 4. libubox/ubus/uci: drop the Lua bindings (the SDK has no liblua).
#    Only the *target* CMAKE_OPTIONS matter: libubox already sets BUILD_LUA=OFF
#    for its host variant, so a bare grep for that string skipped the edit and
#    the target build then failed on the missing liblua.
for mk in libs/libubox system/ubus system/uci; do
	f="$SDK/package/$mk/Makefile"
	if ! python3 - "$f" <<'PY'
import sys
s = open(sys.argv[1]).read()
target = s.split('CMAKE_HOST_OPTIONS', 1)[0]
sys.exit(0 if '-DBUILD_LUA=OFF' in target else 1)
PY
	then
		sed -i 's|^CMAKE_OPTIONS += \\|CMAKE_OPTIONS += \\\n\t-DBUILD_LUA=OFF \\|' "$f"
	fi
	sed -i 's|^PKG_BUILD_DEPENDS:=lua|PKG_BUILD_DEPENDS:=|' "$f"
	sed -i '/define Package\/libubox-lua/,/endef/d' "$f"
	sed -i '/define Package\/libubus-lua/,/endef/d' "$f"
	sed -i '/define Package\/libuci-lua/,/endef/d' "$f"
	sed -i '/BuildPackage,libubox-lua/d;/BuildPackage,libubus-lua/d;/BuildPackage,libuci-lua/d' "$f"
	sed -i 's|+libubox-lua||;s|+libubus-lua||;s|+libuci-lua||' "$f"
done

# 5. configure + build
cat > "$SDK/.config" <<'EOF'
CONFIG_TARGET_ramips=y
CONFIG_TARGET_ramips_mt7621=y
CONFIG_PACKAGE_wpad-mbedtls=y
CONFIG_PACKAGE_hostapd-common=y
CONFIG_MBEDTLS_CCM_C=y
# CONFIG_PACKAGE_wpad-basic-mbedtls is not set
EOF
mkdir -p "$SDK/staging_dir/host" && touch "$SDK/staging_dir/host/.prereq-build"

cd "$SDK"
make defconfig
make -j"$(nproc)" package/libs/mbedtls/compile
make -j"$(nproc)" package/libs/libubox/compile package/system/ubus/compile \
	package/system/uci/compile
make -j"$(nproc)" package/network/services/hostapd/compile

IPK=$(find "$SDK/bin/packages" -name 'wpad-mbedtls_*.ipk' | head -1)
[ -n "$IPK" ] || { echo "no ipk produced" >&2; exit 1; }
echo "$IPK"
