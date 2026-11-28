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

for tool in curl tar zstd unsquashfs sha256sum dd; do
	command -v "$tool" >/dev/null 2>&1 ||
		{ say "host prerequisite missing: $tool"; exit 1; }
done

mkdir -p "$WORK"
SDK=$WORK/sdk
IB=$WORK/ib

# 1. SDK with our package trees (same overlay the wpad build needs).
if [ ! -f "$SDK/rules.mk" ]; then
	say "building the SDK with the hostapd tree (scripts/build-wpad-9999a.sh)"
	"$REPO/scripts/build-wpad-9999a.sh" "$WORK/wpad" >&2
	ln -sfn "$WORK/wpad/sdk" "$SDK"
fi

# 2. Bump hostapd's release so the local wpad wins over the repo's, and build.
HK=$SDK/package/network/services/hostapd
sed -i 's/^PKG_RELEASE:=.*/PKG_RELEASE:=99/' "$HK/Makefile"
rm -rf "$SDK/build_dir/target-mipsel_24kc_musl/hostapd-wpad-full-mbedtls"
( cd "$SDK" && make package/network/services/hostapd/compile ) >&2

# 3. capagent package (static binary from native/).  A clean clone does not
#    contain native/capagent-mipsel (it is a build artefact), so build it from
#    the SDK's toolchain + the mbedTLS that step 1 just staged.  An existing
#    in-tree binary is reused only when it is newer than the sources and
#    VERSION; otherwise the image would silently ship a stale agent.
CAPAGENT_BIN=$REPO/native/capagent-mipsel
need_build=0
if [ -f "$CAPAGENT_BIN" ]; then
	[ "$CAPAGENT_BIN" -nt "$REPO/VERSION" ] || need_build=1
	if find "$REPO/native" -name '*.c' -newer "$CAPAGENT_BIN" | grep -q .; then
		need_build=1
	fi
	if find "$REPO/native/src" -name '*.inc' -newer "$CAPAGENT_BIN" | grep -q .; then
		need_build=1
	fi
	[ "$need_build" = 1 ] &&
		say "native/capagent-mipsel is older than the tree; rebuilding it"
else
	need_build=1
fi
if [ "$need_build" = 1 ]; then
	say "building capagent-mipsel (scripts/build-mipsel.sh)"
	CAPAGENT_BIN=$WORK/capagent-mipsel
	SDK=$SDK OUT=$CAPAGENT_BIN "$REPO/scripts/build-mipsel.sh" >&2
fi
rm -rf "$SDK/package/capagent"
cp -a "$REPO/openwrt/capagent" "$SDK/package/capagent"
# `make package/capagent/compile` is a no-op while the SDK tree still has the
# package's build stamps and ipk, so a changed CAPAGENT_BIN (or a new VERSION)
# would silently ship the previous binary.  Force a clean rebuild.
( cd "$SDK" && make package/capagent/clean >&2 || true )
rm -f "$SDK"/bin/packages/mipsel_24kc/base/capagent_*.ipk
( cd "$SDK" && make package/capagent/compile \
	CAPAGENT_BIN="$CAPAGENT_BIN" PKG_VERSION="$(cat "$REPO/VERSION")" \
	MULTI_CAP="$REPO/scripts/multi-cap.sh" ) >&2

# 4. ImageBuilder.
if [ ! -f "$IB/Makefile" ]; then
	say "downloading the $VERSION ImageBuilder"
	curl -fsSL -o "$WORK/ib.tar.zst" "$IB_URL"
	mkdir -p "$IB"
	tar --zstd -xf "$WORK/ib.tar.zst" -C "$IB" --strip-components=1
	rm -f "$WORK/ib.tar.zst"
fi

# 4b. Bake a manager address if one is given.  MANAGER=auto (the shipped
# default) relies on DHCP option 138, which OpenWrt's udhcpc does not export to
# the agent, so a site either bakes its manager here or edits
# /etc/cap/capagent.conf once.
FILES_OPT=""
if [ -n "${MANAGER:-}" ]; then
	F=$WORK/files
	rm -rf "$F"; mkdir -p "$F/etc/cap"
	sed "s|^MANAGER=.*|MANAGER=$MANAGER|" \
		"$REPO/openwrt/capagent/files/capagent.conf" > "$F/etc/cap/capagent.conf"
	FILES_OPT="FILES=$F"
	say "baking MANAGER=$MANAGER into /etc/cap/capagent.conf"
fi

mkdir -p "$IB/packages"
cp "$SDK"/bin/packages/mipsel_24kc/base/wpad-mbedtls_*.ipk "$IB/packages/"
cp "$SDK"/bin/packages/mipsel_24kc/base/hostapd-common_*.ipk "$IB/packages/"
cp "$SDK"/bin/packages/mipsel_24kc/base/capagent_*.ipk "$IB/packages/"

# 5. Build.  wpad-basic-mbedtls is removed so the patched wpad is the only one.
( cd "$IB" && make image PROFILE="$PROFILE" \
	PACKAGES="-wpad-basic-mbedtls wpad-mbedtls hostapd-common capagent" \
	$FILES_OPT ) >&2

IMG=$(ls "$IB"/bin/targets/$TARGET/*sysupgrade.bin | head -1)
[ -n "$IMG" ] || { say "no sysupgrade image produced"; exit 1; }

# 6. Verify the contents instead of trusting the build.
TMP=$WORK/verify
rm -rf "$TMP" "$WORK/payload.sqsh"
mkdir -p "$TMP"
OFF=$(grep -abo hsqs "$IMG" | head -1 | cut -d: -f1)
[ -n "$OFF" ] || { say "no squashfs payload found in $IMG"; exit 1; }
dd if="$IMG" of="$WORK/payload.sqsh" bs=1 skip="$OFF" status=none
unsquashfs -q -no-exit-code -d "$TMP" "$WORK/payload.sqsh" >/dev/null

need() { [ -e "$TMP/$1" ] || { say "MISSING $1"; exit 1; }; }
need usr/sbin/capagent
need usr/sbin/wpad
need usr/sbin/multi-cap.sh
need etc/init.d/capagent
need etc/cap/capagent.conf
need etc/cap/capagent-solo.conf.example
for s in external_rsn_sae EXT_AUTH_MGMT_TX external_rsn_ie; do
	grep -q "$s" "$TMP/usr/sbin/wpad" ||
		{ say "the wpad in the image is the stock one (missing $s)"; exit 1; }
done
if grep -q "EXT-DBG" "$TMP/usr/sbin/wpad"; then
	say "the wpad in the image carries EXT-DBG debug probes"; exit 1
fi

echo "image: $IMG"
echo "size:  $(stat -c%s "$IMG") bytes"
echo "sha256: $(sha256sum "$IMG" | cut -d' ' -f1)"
echo "capagent: $(stat -c%s "$TMP/usr/sbin/capagent") bytes, wpad: $(stat -c%s "$TMP/usr/sbin/wpad") bytes (patched)"
