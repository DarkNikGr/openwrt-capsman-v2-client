#!/bin/sh
# patches-check.sh — verify the hostapd split-MAC patch series applies cleanly.
#
# The series in patches/ is written against the *prepared* OpenWrt 24.10.0
# hostapd tree: the upstream tarball (hostapd-2024.09.15~5ace39b0) plus
# OpenWrt's stock package patches.  OpenWrt applies the whole
# package/network/services/hostapd/patches/ directory in one lexicographic
# pass, so this script merges the stock and repo series, sorts by basename and
# replays that exact order in a throw-away tree.  That is what catches a patch
# whose name sorts *before* a stock patch it depends on.
#
# Exit status: 0 = every patch applied, zero fuzz; 1 = failure.
#
# Usage:
#   ./scripts/patches-check.sh --tarball FILE [--openwrt-patches DIR]
#                              [--wifi-scripts DIR] [--repo DIR] [--keep]
#
#   --tarball FILE         hostapd-2024.09.15~5ace39b0.tar.zst
#                          (default: $HOSTAPD_TARBALL)
#   --openwrt-patches DIR  package/network/services/hostapd/patches of an
#                          OpenWrt 24.10 source tree or SDK
#                          (default: $OPENWRT_HOSTAPD_PATCHES, else
#                          $SDK/package/network/services/hostapd/patches)
#   --wifi-scripts DIR     optional: OpenWrt source/SDK root, to dry-run
#                          patches/wifi-scripts/*.patch against
#                          package/network/config/wifi-scripts
#   --repo DIR             tree whose patches/ to test (default: this repo)
#   --keep                 keep the extracted tree (prints its path)
#   --allow-fuzz N         tolerate up to N lines of fuzz (default 0)
#
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TARBALL=${HOSTAPD_TARBALL:-}
OWRT_PATCHES=${OPENWRT_HOSTAPD_PATCHES:-}
WIFI_SCRIPTS_ROOT=
REPO=$ROOT
KEEP=0
ALLOW_FUZZ=0

while [ $# -gt 0 ]; do
    case $1 in
        --tarball)          TARBALL=$2; shift 2 ;;
        --openwrt-patches)  OWRT_PATCHES=$2; shift 2 ;;
        --wifi-scripts)     WIFI_SCRIPTS_ROOT=$2; shift 2 ;;
        --repo)             REPO=$2; shift 2 ;;
        --keep)             KEEP=1; shift ;;
        --allow-fuzz)       ALLOW_FUZZ=$2; shift 2 ;;
        -h|--help)          sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$TARBALL" ] || {
    echo "error: no hostapd tarball (use --tarball or \$HOSTAPD_TARBALL)" >&2
    exit 2
}
[ -f "$TARBALL" ] || { echo "error: tarball not found: $TARBALL" >&2; exit 2; }
[ -d "$REPO/patches" ] || { echo "error: no patches/ in $REPO" >&2; exit 2; }

if [ -z "$OWRT_PATCHES" ] && [ -n "${SDK:-}" ]; then
    OWRT_PATCHES=$SDK/package/network/services/hostapd/patches
fi
if [ -n "$OWRT_PATCHES" ] && [ ! -d "$OWRT_PATCHES" ]; then
    echo "error: OpenWrt hostapd patches dir not found: $OWRT_PATCHES" >&2
    exit 2
fi

TMPBASE=${TMPDIR:-/tmp/opencode}
mkdir -p "$TMPBASE"
WORK=$(mktemp -d "$TMPBASE/patches-check.XXXXXX")
trap '[ "$KEEP" = 1 ] || rm -rf "$WORK"' EXIT INT TERM

say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- extract
say "tarball : $TARBALL"
case $TARBALL in
    *.zst) tar --zstd -xf "$TARBALL" -C "$WORK" ;;
    *.gz)  tar -xzf  "$TARBALL" -C "$WORK" ;;
    *.bz2) tar -xjf  "$TARBALL" -C "$WORK" ;;
    *.xz)  tar -xJf  "$TARBALL" -C "$WORK" ;;
    *)     tar -xf   "$TARBALL" -C "$WORK" ;;
esac
SRC=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d ! -name patchset | head -n 1)
[ -n "$SRC" ] || { echo "error: tarball has no top-level directory" >&2; exit 1; }
say "pristine: $SRC"
[ -f "$SRC/hostapd/Makefile" ] || {
    echo "error: $SRC does not look like a hostapd tree" >&2; exit 1; }

# --------------------------------------------------- build the merged series
# OpenWrt uses one lexicographic pass over package/.../hostapd/patches, so the
# stock and repo patches are merged here exactly the same way.
PATCHSET=$WORK/patchset
mkdir -p "$PATCHSET"

OURS=
for p in "$REPO"/patches/*.patch; do
    [ -f "$p" ] || continue
    OURS="$OURS $(basename "$p")"
done

STOCK_N=0
if [ -n "$OWRT_PATCHES" ]; then
    say "stock   : $OWRT_PATCHES"
    for p in "$OWRT_PATCHES"/*.patch; do
        [ -f "$p" ] || continue
        b=$(basename "$p")
        skip=0
        for o in $OURS; do [ "$o" = "$b" ] && skip=1; done
        if [ "$skip" = 1 ]; then continue; fi
        cp -f "$p" "$PATCHSET/$b"
        STOCK_N=$((STOCK_N + 1))
    done
    say "stock   : $STOCK_N patches merged (pristine OpenWrt 24.10.0 tree)"
else
    say "stock   : (none — testing the series against the bare upstream tarball)"
fi
# repo copies win over a same-named SDK copy (e.g. an older 999-… from W15)
for p in "$REPO"/patches/*.patch; do
    [ -f "$p" ] || continue
    cp -f "$p" "$PATCHSET/$(basename "$p")"
done

# -------------------------------------------------------------- apply
say ""
say "series  : $REPO/patches"
TOTAL_HUNKS=0
OURS_N=0
FAILS=0
for p in $(find "$PATCHSET" -maxdepth 1 -name '*.patch' | LC_ALL=C sort); do
    b=$(basename "$p")
    is_ours=0
    for o in $OURS; do [ "$o" = "$b" ] && is_ours=1; done
    hunks=$(grep -c '^@@' "$p" || true)
    if ! out=$(patch -p1 -d "$SRC" --batch --forward --fuzz=0 < "$p" 2>&1); then
        say "FAIL  $b"
        printf '%s\n' "$out"
        FAILS=$((FAILS + 1))
        continue
    fi
    [ "$is_ours" = 1 ] || continue          # stock patches: only failures matter
    OURS_N=$((OURS_N + 1))
    fuzz=$(printf '%s\n' "$out" | grep -o 'with fuzz [0-9]*' | awk '{print $3}' | sort -nr | head -n 1)
    offsets=$(printf '%s\n' "$out" | grep -o 'offset [-0-9]* line' | awk '{print $2}' | sort -n | awk '
        NR == 1 { min = $1; max = $1 }
        { if ($1 < min) min = $1; if ($1 > max) max = $1 }
        END { if (NR == 0) print "0"; else if (min == max) print min; else print min ".." max }')
    [ -n "$fuzz" ] || fuzz=0
    TOTAL_HUNKS=$((TOTAL_HUNKS + hunks))
    if [ "$fuzz" -gt "$ALLOW_FUZZ" ]; then
        say "FAIL  $b ($hunks hunks, offset $offsets, fuzz $fuzz > $ALLOW_FUZZ)"
        FAILS=$((FAILS + 1))
    else
        say "ok    $b ($hunks hunks, offset $offsets, fuzz $fuzz)"
    fi
done

# ----------------------------------------------------- wifi-scripts (optional)
WIFI_RC=0
if [ -n "$WIFI_SCRIPTS_ROOT" ]; then
    rel=package/network/config/wifi-scripts/files/lib/netifd/hostapd.sh
    target=$WIFI_SCRIPTS_ROOT/$rel
    say ""
    say "wifi-scripts: $WIFI_SCRIPTS_ROOT"
    if [ ! -f "$target" ]; then
        say "FAIL  wifi-scripts: $rel not found"
        WIFI_RC=1
    elif grep -q 'external_rsn_auth' "$target"; then
        say "skip  wifi-scripts: already carries external_rsn_auth"
    else
        for p in $(find "$REPO/patches/wifi-scripts" -maxdepth 1 -name '*.patch' 2>/dev/null | LC_ALL=C sort); do
            if ! out=$(patch -p1 -d "$WIFI_SCRIPTS_ROOT" --batch --dry-run --forward --fuzz=0 < "$p" 2>&1); then
                say "FAIL  wifi-scripts/$(basename "$p")"
                printf '%s\n' "$out"
                WIFI_RC=1
            else
                say "ok    wifi-scripts/$(basename "$p") (dry-run)"
            fi
        done
    fi
fi

say ""
if [ "$FAILS" -ne 0 ] || [ "$WIFI_RC" -ne 0 ]; then
    say "RESULT: FAIL ($FAILS patch(es) failed)"
    [ "$KEEP" = 1 ] && say "tree kept at $SRC"
    exit 1
fi
say "RESULT: OK — $OURS_N patch(es) from this repo, $TOTAL_HUNKS hunks, 0 fuzz"
[ "$KEEP" = 1 ] && say "tree kept at $SRC"
exit 0
