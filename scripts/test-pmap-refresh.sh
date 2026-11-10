#!/bin/sh
# Host self-test for the 0x201c stale-ifindex fix (no manager, no CAP).
# Requires qemu-mipsel and the cross-built native/capagent-mipsel, plus root
# for a temporary dummy interface.  The test seeds port 0x0001 with a dead
# ifindex and requires vap_ifindex() to re-resolve the live one by name.
set -eu
D=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN=${BIN:-$D/native/capagent-mipsel}
IF=${IF:-w42pmap0}

[ -x "$BIN" ] || { echo "missing $BIN (build first)" >&2; exit 1; }
command -v qemu-mipsel >/dev/null || { echo "qemu-mipsel not found" >&2; exit 1; }

cleanup() { ip link del "$IF" 2>/dev/null || true; }
trap cleanup EXIT

cleanup
ip link add "$IF" type dummy
old=$(cat /sys/class/net/$IF/ifindex)
echo "first: $IF ifindex=$old"
out=$(qemu-mipsel "$BIN" --selftest-pmap "$IF")
echo "$out"
echo "$out" | grep -q 'result=PASS' || { echo "FAIL first" >&2; exit 1; }

# Recreate the netdev: the kernel assigns a new ifindex while the cached
# port map still has the old one (the exact 0x201c bug).
cleanup
ip link add "$IF" type dummy
new=$(cat /sys/class/net/$IF/ifindex)
[ "$new" != "$old" ] || echo "warning: ifindex reused ($new); test still valid"
echo "recreated: $IF ifindex=$new (cached=$old)"
out=$(qemu-mipsel "$BIN" --selftest-pmap "$IF,$old")
echo "$out"
echo "$out" | grep -q 'result=PASS' || { echo "FAIL recreate" >&2; exit 1; }
echo "pmap refresh self-test: PASS (cached $old -> live $new)"
