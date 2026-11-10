#!/bin/sh
# W34 host tests: netifd status parser + ownership state machine.
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=${TMPDIR:-/tmp}/w34-tests.$$
mkdir -p "$tmp/run" "$tmp/tmp"
trap 'rm -rf "$tmp"' EXIT

CC=${CC:-cc}
CFLAGS="-Wall -Wextra -Wno-format-truncation -Wno-unused-function -I$root/native/src"

echo "== netifd status parser =="
$CC $CFLAGS -o "$tmp/test_netifd_status" "$root/tests/test_netifd_status.c"
"$tmp/test_netifd_status"

echo
echo "== ownership state machine =="
$CC $CFLAGS \
    -DOWN_RUN_DIR="\"$tmp/run\"" -DOWN_TMP_DIR="\"$tmp/tmp\"" \
    -DOWN_PROBE_MS=0 -DOWN_TEST_PID_OK \
    -o "$tmp/test_ownership" "$root/tests/test_ownership.c"
W34_TEST_DIR="$tmp/run" "$tmp/test_ownership"
