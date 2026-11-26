#!/bin/sh
# station-test.sh — run a real station against the CAP from a netns.
#
# Why this exists: every earlier "station did not associate" result came from a
# broken harness.  `iw phy phy0 set netns` always failed with -ENODEV because
# this host has no phy0; the station wiphy is phy1 (wlp39s0).  A wpa_supplicant
# that never started cannot prove anything about the CAP, so the harness is a
# script now and it verifies itself before reporting.
#
# Usage: scripts/station-test.sh <ssid> <psk> [ip/cidr] [run-seconds]
#        scripts/station-test.sh cap-test cap-test-12345 192.168.30.50/24 40
#
# Output: the association state, the 4-way result and the captured log path.
# Exit:   0 = connected (4-way done), 1 = not connected.
set -eu

SSID=${1:?ssid}
PSK=${2:?psk}
ADDR=${3:-}
SECS=${4:-40}

PHY=${STATION_PHY:-phy1}
NETNS=${STATION_NETNS:-capsta}
PIDF=/tmp/$NETNS.pid
CONF=/tmp/$NETNS-wpa.conf
LOG=/tmp/$NETNS-wpa.log

say() { echo "[station] $*" >&2; }
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo -n"

cleanup() {
	if [ -s "$PIDF" ]; then
		NS=$(cat "$PIDF")
		$SUDO ip netns exec "$NETNS" iw phy "$PHY" set netns 1 \
			>/dev/null 2>&1 || true
	fi
	$SUDO ip netns del "$NETNS" >/dev/null 2>&1 || true
	$SUDO rm -f "$PIDF"
}
trap cleanup EXIT INT TERM

cleanup
$SUDO ip netns add "$NETNS"

# The netns must stay alive while the wiphy sits in it: keep one long sleep as
# the namespace holder and remember its pid.
$SUDO ip netns exec "$NETNS" sh -c "echo \$\$ > $PIDF; exec sleep 3600" \
	>/dev/null 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$PIDF" ] && break; sleep 0.5; done
[ -s "$PIDF" ] || { say "no namespace holder pid"; exit 1; }
NS_HOLDER=$(cat "$PIDF")

# Move the whole wiphy, not just the netdev: cfg80211 refuses a bare netdev move
# for a managed interface that has never been up.
if ! $SUDO iw phy "$PHY" set netns "$NS_HOLDER" 2>/tmp/$NETNS.err; then
	say "cannot move $PHY into $NETNS: $(cat /tmp/$NETNS.err)"
	exit 1
fi
IFNAME=$($SUDO ip netns exec "$NETNS" sh -c \
	'for i in /sys/class/net/*; do [ -e $i/phy80211 ] && basename $i; done' | head -1)
[ -n "$IFNAME" ] || { say "no wireless interface inside $NETNS"; exit 1; }
say "$PHY moved into $NETNS as $IFNAME"

$SUDO ip netns exec "$NETNS" ip link set lo up
$SUDO ip netns exec "$NETNS" ip link set "$IFNAME" up

cat > "$CONF" <<EOF
ctrl_interface=/tmp/$NETNS-ctrl
country=GR
network={
	ssid="$SSID"
	psk="$PSK"
	key_mgmt=WPA-PSK
	pairwise=CCMP
	group=CCMP
}
EOF
$SUDO rm -f "$LOG"
$SUDO rm -rf "/tmp/$NETNS-ctrl"
# Foreground with -dd, not -B: wpa_supplicant -B detaches and its -f log could
# stay empty, so an earlier run "measured" nothing and the assoc frames seen in
# the CAP log were from a neighbour's client, not ours.
$SUDO ip netns exec "$NETNS" sh -c \
	"exec wpa_supplicant -dd -i '$IFNAME' -c '$CONF' >'$LOG' 2>&1" &
WPID=$!
sleep 4
kill -0 "$WPID" 2>/dev/null ||
	{ say "wpa_supplicant exited immediately:"; tail -6 "$LOG"; exit 1; }
say "wpa_supplicant pid $WPID, interface $IFNAME"

say "waiting ${SECS}s for association to $SSID"
i=0
CONNECTED=0
while [ "$i" -lt "$SECS" ]; do
	sleep 1
	i=$((i + 1))
	if grep -q "CTRL-EVENT-CONNECTED" "$LOG" 2>/dev/null; then
		CONNECTED=1
		break
	fi
done

say "--- evidence ---"
grep -aE "Trying to associate|Associated with|4-Way Handshake|CTRL-EVENT-CONNECTED|does not match|deauth|SAE|OWE" "$LOG" | tail -8 || true
$SUDO ip netns exec "$NETNS" iw dev "$IFNAME" link 2>&1 | head -6 || true
$SUDO ip netns exec "$NETNS" iw dev "$IFNAME" station dump 2>/dev/null |
	grep -E "authorized|authenticated|signal" | head -4 || true

if [ -n "$ADDR" ]; then
	$SUDO ip netns exec "$NETNS" ip addr add "$ADDR" dev "$IFNAME" 2>/dev/null || true
	$SUDO ip netns exec "$NETNS" ip link set "$IFNAME" up
	GW=$(echo "$ADDR" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".1"}')
	say "DHCP-less check: ping $GW"
	$SUDO ip netns exec "$NETNS" ping -c 3 -W 2 "$GW" 2>&1 | tail -3 || true
fi

kill "$WPID" 2>/dev/null
[ "$CONNECTED" -eq 1 ] || { say "NOT CONNECTED (log: $LOG)"; exit 1; }
say "CONNECTED (log: $LOG)"
