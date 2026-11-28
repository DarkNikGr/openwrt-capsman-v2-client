#!/bin/sh
# Host gate for the per-VAP mode (not part of `make check`: it needs root,
# hostapd and the mac80211_hwsim module).
#
# Proves the property vap_phy_apply_per_vap() relies on: several single-BSS
# hostapd processes, each with interface= <one netdev> and NO bss= siblings,
# can all reach AP-ENABLED on one real wiphy when their starts are spaced.
#
#   sudo HWSIM_KO=/path/mac80211_hwsim.ko ./host-pervap-hwsim.sh [radios]
#
# Every process is killed and every vif removed on exit.  The module is only
# unloaded when this script loaded it.
set -eu

RADIOS=${1:-1}
HWSIM_KO=${HWSIM_KO:-}
WORK=${WORK:-/tmp/capagent-pervap-hwsim}
HOSTAPD=${HOSTAPD:-/usr/bin/hostapd}
LOADED=0

[ "$(id -u)" = 0 ] || { echo "run as root (netlink/vif creation)" >&2; exit 1; }
[ -x "$HOSTAPD" ] || { echo "no $HOSTAPD" >&2; exit 1; }
mkdir -p "$WORK"

cleanup() {
    for p in $(pgrep -x hostapd || true); do
        grep -q "$WORK" "/proc/$p/cmdline" 2>/dev/null && kill "$p" 2>/dev/null || true
    done
    for i in 0 1 2 3; do
        iw dev "pervap$i" del 2>/dev/null || true
    done
    [ "$LOADED" = 1 ] && rmmod mac80211_hwsim 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if ! grep -q mac80211_hwsim /proc/modules; then
    [ -n "$HWSIM_KO" ] && [ -f "$HWSIM_KO" ] || {
        echo "mac80211_hwsim not loaded and HWSIM_KO not set" >&2; exit 1; }
    insmod "$HWSIM_KO" radios="$RADIOS"
    LOADED=1
    sleep 1
fi

# Select the mac80211_hwsim wiphy explicitly: "the first wlan interface" may
# be a real radio on a developer host, and this test must never touch one.
PHY=""
for d in /sys/class/ieee80211/phy*; do
    drv=$(readlink "$d/device/driver" 2>/dev/null || true)
    case "$drv" in *mac80211_hwsim*) PHY=${d##*phy}; break ;; esac
done
[ -n "$PHY" ] || { echo "no mac80211_hwsim wiphy" >&2; exit 1; }
echo "hwsim: phy$PHY"

for i in 0 1 2 3; do
    iw phy "phy$PHY" interface add "pervap$i" type __ap
done
sleep 1
for i in 0 1 2 3; do
    ip link set "pervap$i" down
    ip link set "pervap$i" address "02:00:00:00:00:0$((i + 1))"
    cat > "$WORK/vap$i.conf" <<EOF
driver=nl80211
logger_syslog=0
logger_stdout=-1
logger_stdout_level=0
ctrl_interface=$WORK/ctrl
interface=pervap$i
bssid=02:00:00:00:00:0$((i + 1))
ssid=pervap-test$i
hw_mode=a
channel=36
auth_algs=1
ignore_broadcast_ssid=0
ap_isolate=0
EOF
done

# 4 s between starts is the production CAPAGENT_PER_VAP_SPACING_MS default.
for i in 0 1 2 3; do
    "$HOSTAPD" -dd -P "$WORK/vap$i.pid" "$WORK/vap$i.conf" \
        > "$WORK/vap$i.log" 2>&1 &
    sleep 4
done
sleep 2

fail=0
for i in 0 1 2 3; do
    if grep -q 'AP-ENABLED' "$WORK/vap$i.log"; then
        echo "ok: vap$i AP-ENABLED"
    else
        echo "FAIL: vap$i did not reach AP-ENABLED"; fail=1
    fi
    if iw dev "pervap$i" info | grep -q 'type AP'; then
        echo "ok: vap$i type AP"
    else
        echo "FAIL: vap$i is not type AP"; fail=1
    fi
done
[ "$fail" = 0 ] && echo "host-pervap: all four single-BSS processes AP-ENABLED on phy$PHY"
exit "$fail"
