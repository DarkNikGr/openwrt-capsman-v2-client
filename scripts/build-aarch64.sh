#!/bin/sh
# Build the CAP client for aarch64 OpenWrt (WiFi 6/7 APs, e.g. Deco BE65).
#
#   TOOLCHAIN=/path/to/aarch64-linux-musl-cross/bin \
#   MBEDTLS=/path/to/mbedtls-aarch64 \
#   ./scripts/build-aarch64.sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOOLCHAIN=${TOOLCHAIN:-${HOME}/cap-sdk/aarch64-linux-musl-cross/bin}
MBEDTLS=${MBEDTLS:-${HOME}/cap-sdk/mbedtls-aarch64}
CROSS=${CROSS:-${TOOLCHAIN}/aarch64-linux-musl-}
OUT=${OUT:-${ROOT}/dist/capagent-aarch64}
CC=${CROSS}gcc
STRIP=${CROSS}strip
[ -x "${CC}" ] || { echo "compiler not found: ${CC}" >&2; exit 1; }
[ -f "${MBEDTLS}/library/libmbedtls.a" ] || {
    echo "mbedTLS static libs not found in ${MBEDTLS}" >&2; exit 1; }
mkdir -p "$(dirname "${OUT}")"
"${CC}" -O2 -Wall -Wextra -Wno-unused-parameter -I"${MBEDTLS}/include" \
    -o "${OUT}" "${ROOT}/native/capagent.c" \
    "${MBEDTLS}/library/libmbedtls.a" \
    "${MBEDTLS}/library/libmbedx509.a" \
    "${MBEDTLS}/library/libmbedcrypto.a" -static
"${STRIP}" "${OUT}"
ls -lh "${OUT}"; file "${OUT}"
