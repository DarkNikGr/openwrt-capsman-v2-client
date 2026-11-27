#!/bin/sh
# Start one capagent per SSID ("multi-identity" CAP), so that every SSID is the
# master of its own CAP identity and the manager's virtual-VAP routing is not
# needed (see docs/OPEN-PROBLEMS.md F63/F64).
#
# Usage:
#   multi-cap.sh start   # launch every identity in /etc/cap/identities.conf
#   multi-cap.sh stop    # stop them
#   multi-cap.sh status  # what is running
#
# /etc/cap/identities.conf, one identity per line:
#   tag identity radio-mac[,radio-mac...]
# Maximum working topology (proven): one radio per instance, four 2.4 GHz
# identities plus one 5 GHz master:
#   a OpenWrt-CAPA 02:D1:27:1B:2D:A0
#   b OpenWrt-CAPB 02:D1:27:1B:2D:A1
#   c OpenWrt-CAPC 02:D1:27:1B:2D:A2
#   d OpenWrt-CAPD 02:D1:27:1B:2D:A3
#   e OpenWrt-CAPE 02:D1:27:1B:2D:B0,02:D1:27:1B:2D:A4   # 5 GHz (radio 1)
# A second radio in an instance is only used if its MAC has a provisioning
# rule; leave an unused MAC (like B0) in radio 0 to reach the 5 GHz wiphy.
#
# Each identity gets its own certificate (/etc/cap/id-<tag>.pem), journal
# (/var/run/caps<tag>.state), ext-auth directory (/var/run/hostapd<tag>) and
# hostapd config/pid/log suffix (CAPAGENT_RUN_TAG).
#
# The manager needs one provisioning rule per radio MAC, each with
# action=create-dynamic-enabled, master-configuration=<that SSID> and no
# slaves.  A single radio cannot carry several independent hostapd instances on
# 5 GHz (the mt76x2 driver refuses a second AP vif), so a 5 GHz identity can
# only be added when its phy is free (F64).
set -u

CONF=${CONF:-/etc/cap/identities.conf}
BIN=${BIN:-/usr/sbin/capagent}
COMMON=${COMMON:---manager auto --discovery-interfaces wan --port 5246
	--dont-verify-certificate --eapol-leg both --mgmt-relay
	--mgmt-source off --country GR}
LOG=/tmp/multi-cap.log

say() { echo "multi-cap: $*"; }

running_pids() {
	for f in /proc/[0-9]*/cmdline; do
		c=$(tr '\0' ' ' <"$f" 2>/dev/null) || continue
		case "$c" in
		*"$BIN"*) p=${f#/proc/}; echo "${p%/cmdline}" ;;
		esac
	done
}

stop_all() {
	for p in $(running_pids); do
		kill "$p" 2>/dev/null && say "stopped pid $p"
	done
	sleep 1
	# hostapd children are reaped by capagent; kill stragglers of our configs
	for f in /proc/[0-9]*/cmdline; do
		c=$(tr '\0' ' ' <"$f" 2>/dev/null) || continue
		case "$c" in
		*" -P /var/run/vap-phy"*)
			p=${f#/proc/}; kill "${p%/cmdline}" 2>/dev/null ;;
		esac
	done
}

case "${1:-start}" in
stop) stop_all; exit 0 ;;
status)
	say "identities: $(grep -cv '^[[:space:]]*\(#\|$\)' "$CONF" 2>/dev/null || echo 0)"
	for p in $(running_pids); do
		tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | cut -c1-80
		echo
	done
	exit 0 ;;
esac

[ -f "$CONF" ] || { say "no $CONF"; exit 1; }
[ -x "$BIN" ] || { say "no $BIN"; exit 1; }

# serialise starts: several hostapd processes on one phy must not race
DELAY=${DELAY:-15}
n=0
while read -r tag identity macs rest; do
	case "$tag" in ''|\#*) continue ;; esac
	[ -n "${identity:-}" ] && [ -n "${macs:-}" ] || continue
	dir=/var/run/hostapd$tag
	mkdir -p "$dir"
	CAPAGENT_RUN_TAG=$tag setsid "$BIN" $COMMON \
		--identity "$identity" --macs "$macs" \
		--cert "/etc/cap/id-$tag.pem" --key "/etc/cap/id-$tag.key" \
		--ext-auth-dir "$dir" --vap-state "/var/run/caps$tag.state" \
		>>"$LOG" 2>&1 </dev/null 9>&- &
	say "started tag=$tag identity=$identity macs=$macs"
	n=$((n + 1))
	sleep "$DELAY"
done <"$CONF"
say "$n identities started (log: $LOG)"
