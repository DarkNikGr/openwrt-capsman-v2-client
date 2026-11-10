#!/bin/sh
# Build the mipsel CAP client with the OpenWrt SDK toolchain.
#
#   TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
#   MBEDTLS=/path/to/mbedtls-3.6.2 \
#   ./scripts/build-mipsel.sh
#
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOLCHAIN=${TOOLCHAIN:-${HOME}/openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin}
MBEDTLS=${MBEDTLS:-${HOME}/mbedtls-3.6.2}
CROSS=${CROSS:-${TOOLCHAIN}/mipsel-openwrt-linux-musl-}

CC=${CROSS}gcc
STRIP=${CROSS}strip
OUT=${OUT:-${ROOT}/dist/capagent-mipsel}

[ -x "${CC}" ] || { echo "compiler not found: ${CC}" >&2; exit 1; }
[ -f "${MBEDTLS}/library/libmbedtls.a" ] || {
    echo "mbedTLS static libs not found in ${MBEDTLS}" >&2; exit 1; }

mkdir -p "$(dirname "${OUT}")"

"${CC}" -O2 -Wall -Wextra -Wno-unused-parameter \
    -I"${MBEDTLS}/include" \
    -o "${OUT}" "${ROOT}/native/capagent.c" \
    "${MBEDTLS}/library/libmbedtls.a" \
    "${MBEDTLS}/library/libmbedx509.a" \
    "${MBEDTLS}/library/libmbedcrypto.a" \
    -static

"${STRIP}" "${OUT}"
ls -lh "${OUT}"
file "${OUT}"
