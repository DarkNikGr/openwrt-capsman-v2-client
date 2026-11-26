#!/bin/sh
# build-image.sh — reproducible zero-touch sysupgrade image.
#
# Result (verified): an OpenWrt 24.10.0 sysupgrade for the reference Xiaomi
# Mi Router 4A Gigabit that already contains
#
#   /usr/sbin/capagent           the CAP agent
#   /usr/sbin/wpad               the patched wpad (999/9997/9998/9999/9999a-e)
#   /etc/init.d/capagent         procd service, starts on boot
#   /etc/cap/capagent.conf       zero-touch defaults (no SSID/key/VLAN)
#
# Nothing local names an SSID or a key: after a factory reset the agent enrols
# a certificate, joins the CAPsMAN v2 manager and provisions every BSS the
# manager asks for.
#
# Why the version games below:
# * The official repo ships hostapd as ...-r3, so a locally built r2 loses the
#   version comparison and the image silently keeps the stock wpad.  The script
#   bumps PKG_RELEASE to 99 and ships hostapd-common with the same release,
#   because wpad depends on an exact hostapd-common version.
# * capagent must not depend on wpad-mbedtls: the image lists it explicitly and
#   the dependency makes opkg refuse to install during the image build.
#
# Usage: scripts/build-image.sh [WORKDIR]     (default: /tmp/zt-image)
# Env:   VERSION=24.10.0  PROFILE=xiaomi_mi-router-4a-gigabit
set -eu

WORK=${1:-/tmp/zt-image}
REPO=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${VERSION:-24.10.0}
PROFILE=${PROFILE:-xiaomi_mi-router-4a-gigabit}
TARGET=ramips/mt7621
IB_URL=https://downloads.openwrt.org/releases/$VERSION/targets/$TARGET/openwrt-imagebuilder-$VERSION-$(echo $TARGET | tr / -).Linux-x86_64.tar.zst

say() { echo "[image] $*" >&2; }

mkdir -p "$WORK"
SDK=$WORK/sdk
IB=$WORK/ib

# 1. SDK with our package trees (same overlay the wpad build needs).
if [ ! -x "$SDK/rules.mk" ]; then
	say "building the SDK with the hostapd tree (scripts/build-wpad-9999a.sh)"
	"$REPO/scripts/build-wpad-9999a.sh" "$WORK/wpad" >&2
	ln -sfn "$WORK/wpad/sdk" "$SDK"
fi

# 2. Bump hostapd's release so the local wpad wins over the repo's, and build.
HK=$SDK/package/network/services/hostapd
sed -i 's/^PKG_RELEASE:=.*/PKG_RELEASE:=99/' "$HK/Makefile"
rm -rf "$SDK/build_dir/target-mipsel_24kc_musl/hostapd-wpad-full-mbedtls"
( cd "$SDK" && make package/network/services/hostapd/compile ) >&2

# 3. capagent package (static binary from native/).
rm -rf "$SDK/package/capagent"
cp -a "$REPO/openwrt/capagent" "$SDK/package/capagent"
( cd "$SDK" && make package/capagent/compile \
	CAPAGENT_BIN="$REPO/native/capagent-mipsel" ) >&2

# 4. ImageBuilder.
if [ ! -x "$IB/Makefile" ]; then
	say "downloading the $VERSION ImageBuilder"
	curl -fsSL -o "$WORK/ib.tar.zst" "$IB_URL"
	mkdir -p "$IB"
	tar --zstd -xf "$WORK/ib.tar.zst" -C "$IB" --strip-components=1
	rm -f "$WORK/ib.tar.zst"
fi

mkdir -p "$IB/packages"
cp "$SDK"/bin/packages/mipsel_24kc/base/wpad-mbedtls_*.ipk "$IB/packages/"
cp "$SDK"/bin/packages/mipsel_24kc/base/hostapd-common_*.ipk "$IB/packages/"
cp "$SDK"/bin/packages/mipsel_24kc/base/capagent_*.ipk "$IB/packages/"

# 5. Build.  wpad-basic-mbedtls is removed so the patched wpad is the only one.
( cd "$IB" && make image PROFILE="$PROFILE" \
	PACKAGES="-wpad-basic-mbedtls wpad-mbedtls hostapd-common capagent" ) >&2

IMG=$(ls "$IB"/bin/targets/$TARGET/*sysupgrade.bin | head -1)
[ -n "$IMG" ] || { say "no sysupgrade image produced"; exit 1; }

# 6. Verify the contents instead of trusting the build.
TMP=$WORK/verify
rm -rf "$TMP" "$WORK/payload.sqsh"
mkdir -p "$TMP"
OFF=$(grep -abo hsqs "$IMG" | head -1 | cut -d: -f1)
dd if="$IMG" of="$WORK/payload.sqsh" bs=1 skip="$OFF" status=none
unsquashfs -q -d "$TMP" "$WORK/payload.sqsh" >/dev/null

need() { [ -e "$TMP/$1" ] || { say "MISSING $1"; exit 1; }; }
need usr/sbin/capagent
need usr/sbin/wpad
need etc/init.d/capagent
need etc/cap/capagent.conf
for s in external_rsn_sae EXT_AUTH_MGMT_TX external_rsn_ie; do
	grep -q "$s" "$TMP/usr/sbin/wpad" ||
		{ say "the wpad in the image is the stock one (missing $s)"; exit 1; }
done

echo "image: $IMG"
echo "size:  $(stat -c%s "$IMG") bytes"
echo "sha256: $(sha256sum "$IMG" | cut -d' ' -f1)"
echo "capagent: $(stat -c%s "$TMP/usr/sbin/capagent") bytes, wpad: $(stat -c%s "$TMP/usr/sbin/wpad") bytes (patched)"
