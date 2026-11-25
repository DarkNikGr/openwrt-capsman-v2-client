#!/bin/sh
# Fetch the pinned OpenWrt 24.10.0 ramips/mt7621 toolchain and build the
# pinned mbedTLS for it, so `make -C native check` can run on a clean
# x86_64 Linux host (this is what .github/workflows/ci.yml does).
#
#   scripts/ci-setup-mipsel.sh DEST >> "$GITHUB_ENV"                   # in CI
#   make -C native $(scripts/ci-setup-mipsel.sh ~/cap-ci) check        # locally
#
# Every download is checked against the SHA-256 pinned below before it is
# unpacked.  stdout carries only the TOOLCHAIN=, MBEDTLS= and STAGING_DIR=
# assignments for native/Makefile; progress goes to stderr.  A re-run with
# the same DEST reuses what is already unpacked there without re-verifying;
# delete DEST to start clean.  DEST must not contain spaces.
set -eu

OPENWRT_URL=https://downloads.openwrt.org/releases/24.10.0/targets/ramips/mt7621
TC_NAME=openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64
# from $OPENWRT_URL/sha256sums (the SDK hash in that file matches docs/BUILD.md)
TC_SHA256=4db9eab44279ef9c7111ebf5050041846488395f458b9ca9ab18ad1989ab08dd
TC_SUBDIR=toolchain-mipsel_24kc_gcc-13.3.0_musl

MBEDTLS_VER=3.6.2
MBEDTLS_URL=https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VER}/mbedtls-${MBEDTLS_VER}.tar.bz2
# from the mbedtls-3.6.2 release notes / mbedtls-3.6.2-sha256sum.txt
MBEDTLS_SHA256=8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca

die() { echo "ci-setup-mipsel: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: $0 DEST"
[ "$(uname -sm)" = "Linux x86_64" ] || die "the OpenWrt toolchain needs Linux x86_64"
for tool in curl sha256sum tar zstd bzip2 make; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

mkdir -p "$1"
DEST=$(cd "$1" && pwd)

# fetch URL SHA256 FILE: download, verify, and only then move into place
fetch() {
    curl -fsSL --retry 3 --proto '=https' --proto-redir '=https' \
        -o "$3.part" "$1"
    echo "$2  $3.part" | sha256sum -c - >&2 || {
        rm -f "$3.part"; die "checksum mismatch: $1"; }
    mv "$3.part" "$3"
}

TC_ARCHIVE=$DEST/$TC_NAME.tar.zst
TC_ROOT=$DEST/$TC_NAME/$TC_SUBDIR
if [ ! -x "$TC_ROOT/bin/mipsel-openwrt-linux-musl-gcc" ]; then
    echo "== toolchain: $TC_NAME" >&2
    fetch "$OPENWRT_URL/$TC_NAME.tar.zst" "$TC_SHA256" "$TC_ARCHIVE"
    tar --zstd -xf "$TC_ARCHIVE" -C "$DEST"
    rm -f "$TC_ARCHIVE"
fi
[ -x "$TC_ROOT/bin/mipsel-openwrt-linux-musl-gcc" ] ||
    die "toolchain unpacked without $TC_SUBDIR/bin/mipsel-openwrt-linux-musl-gcc"

# The OpenWrt gcc wrapper warns on every call when STAGING_DIR is unset.
STAGING_DIR=$TC_ROOT
export STAGING_DIR
CROSS=$TC_ROOT/bin/mipsel-openwrt-linux-musl-

MBEDTLS=$DEST/mbedtls-$MBEDTLS_VER
if [ ! -f "$MBEDTLS/library/libmbedcrypto.a" ]; then
    echo "== mbedTLS $MBEDTLS_VER (static, mipsel)" >&2
    fetch "$MBEDTLS_URL" "$MBEDTLS_SHA256" "$MBEDTLS.tar.bz2"
    rm -rf "$MBEDTLS"
    tar -xjf "$MBEDTLS.tar.bz2" -C "$DEST"
    rm -f "$MBEDTLS.tar.bz2"
    # docs/BUILD.md: the secure datachan needs AES-CCM.
    grep -q '^#define MBEDTLS_CCM_C' "$MBEDTLS/include/mbedtls/mbedtls_config.h" ||
        die "MBEDTLS_CCM_C is not enabled in the mbedTLS default config"
    make -C "$MBEDTLS" -j"$(nproc)" lib \
        CC="${CROSS}gcc" AR="${CROSS}ar" >&2
fi
for lib in libmbedtls.a libmbedx509.a libmbedcrypto.a; do
    [ -f "$MBEDTLS/library/$lib" ] || die "mbedTLS build did not produce $lib"
done

"${CROSS}gcc" --version | head -n 1 >&2
echo "TOOLCHAIN=$TC_ROOT/bin"
echo "MBEDTLS=$MBEDTLS"
echo "STAGING_DIR=$STAGING_DIR"
