#!/bin/sh
# dump.sh <interface> [packet-count]
# Stream a pcap of <interface> to stdout (0 count = unlimited, Ctrl-C to stop).
# The equivalent of RouterOS "dev.udp-dump" for this OpenWrt CAP.
IF="${1:-br-lan}"
COUNT="${2:-0}"
[ -e "/sys/class/net/$IF" ] || { echo "no such interface: $IF" >&2; exit 1; }
if [ "$COUNT" -gt 0 ] 2>/dev/null; then
	exec tcpdump -i "$IF" -U -s 0 -c "$COUNT" -w -
else
	exec tcpdump -i "$IF" -U -s 0 -w -
fi
