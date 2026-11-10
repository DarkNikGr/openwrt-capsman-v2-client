#!/bin/sh
# Build the mipsel CAP client with an OpenWrt SDK tree or a standalone
# toolchain + mbedTLS prefix.
#
#   SDK=/path/to/openwrt-sdk ./scripts/build-mipsel.sh
#
#   TOOLCHAIN=/path/to/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin \
#   MBEDTLS=/path/to/mbedtls-3.6.2 \
#   ./scripts/build-mipsel.sh
#
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "${SDK:-}" ]; then
    TOOLCHAIN=${TOOLCHAIN:-${SDK}/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin}
    MBEDTLS_INC=${MBEDTLS_INC:-${SDK}/staging_dir/target-mipsel_24kc_musl/usr/include}
    MBEDTLS_LIB=${MBEDTLS_LIB:-${SDK}/staging_dir/target-mipsel_24kc_musl/usr/lib}
    STAGING_DIR=${STAGING_DIR:-${SDK}/staging_dir}
    export STAGING_DIR
else
    TOOLCHAIN=${TOOLCHAIN:-${HOME}/openwrt-toolchain-24.10.0-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin}
    MBEDTLS=${MBEDTLS:-${HOME}/mbedtls-3.6.2}
    MBEDTLS_INC=${MBEDTLS_INC:-${MBEDTLS}/include}
    MBEDTLS_LIB=${MBEDTLS_LIB:-${MBEDTLS}/library}
fi
CROSS=${CROSS:-${TOOLCHAIN}/mipsel-openwrt-linux-musl-}

CC=${CROSS}gcc
STRIP=${CROSS}strip
OUT=${OUT:-${ROOT}/dist/capagent-mipsel}

[ -x "${CC}" ] || { echo "compiler not found: ${CC}" >&2; exit 1; }
[ -f "${MBEDTLS_LIB}/libmbedtls.a" ] || {
    echo "mbedTLS static libs not found in ${MBEDTLS_LIB}" >&2; exit 1; }

mkdir -p "$(dirname "${OUT}")"

"${CC}" -O2 -Wall -Wextra -Wno-unused-parameter \
    -I"${MBEDTLS_INC}" -I"${ROOT}/native/src" \
    -o "${OUT}" "${ROOT}/native/capagent.c" "${ROOT}/native/src/extmux.c" \
    "${MBEDTLS_LIB}/libmbedtls.a" \
    "${MBEDTLS_LIB}/libmbedx509.a" \
    "${MBEDTLS_LIB}/libmbedcrypto.a" \
    -static

"${STRIP}" "${OUT}"
ls -lh "${OUT}"
file "${OUT}"
