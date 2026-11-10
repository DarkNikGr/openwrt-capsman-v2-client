#!/bin/sh
# sniff.sh <interface> [seconds] [packet-count] [out.pcap]
# Capture traffic to a pcap file stored ON the CAP (local-file variant of
# RouterOS "dev.udp-dump").  seconds=0 -> no time limit; count=0 -> no count
# limit (then stop with Ctrl-C).
# Examples:
#   sniff.sh br-vlan20 10                -> 10s capture, /tmp/cap.pcap
#   sniff.sh phy0-ap1 0 500 /tmp/x.pcap  -> 500 packets
set -u
IF="${1:-br-lan}"
SEC="${2:-10}"
CNT="${3:-0}"
OUT="${4:-/tmp/cap.pcap}"

[ -e "/sys/class/net/$IF" ] || { echo "no such interface: $IF" >&2; exit 1; }

set -- tcpdump -i "$IF" -U -s 0 -w "$OUT"
[ "$CNT" -gt 0 ] 2>/dev/null && set -- "$@" -c "$CNT"

if [ "$SEC" -gt 0 ] 2>/dev/null; then
	if command -v timeout >/dev/null 2>&1; then
		timeout "$SEC" "$@" 2>/dev/null
	else
		"$@" -G "$SEC" -W 1 2>/dev/null
	fi
else
	"$@" 2>/dev/null
fi

ls -l "$OUT" 2>/dev/null
