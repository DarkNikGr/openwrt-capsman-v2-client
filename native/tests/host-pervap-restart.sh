#!/bin/sh
# ag46 host gate: four single-BSS hostapd processes on one real wiphy must
# survive a stop/width-change/restart cycle without stale daemons or pidfiles.
#
# This is the property vap_phy_apply_per_vap()/vap_phy_stop() rely on:
#   * one `interface=` section per process, no `bss=` siblings;
#   * every process uses the MASTER channel context (5955/160, then 5955/80);
#   * stop reaps all four, then a restart with leftover pidfiles still yields
#     exactly four new AP-ENABLED daemons and no old pid is alive.
#
# Not part of `make check`: root + hostapd + mac80211_hwsim are required.
#
#   sudo ./host-pervap-restart.sh            # 6 GHz 5955, 160 -> 80
#   sudo BAND=5g ./host-pervap-restart.sh    # 5 GHz 5180, 80 -> 40
set -eu

BAND=${BAND:-6g}
WORK=${WORK:-/tmp/capagent-pervap-restart}
HOSTAPD=${HOSTAPD:-/usr/bin/hostapd}
SPACING=${SPACING:-2}
LOADED=0

[ "$(id -u)" = 0 ] || { echo "run as root (netlink/vif creation)" >&2; exit 1; }
[ -x "$HOSTAPD" ] || { echo "no $HOSTAPD" >&2; exit 1; }
mkdir -p "$WORK"
rm -f "$WORK"/*.pid "$WORK"/*.log "$WORK"/*.conf

PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for f in "$WORK"/*.pid; do
        [ -f "$f" ] || continue
        p=$(cat "$f" 2>/dev/null || true)
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
        rm -f "$f"
    done
    sleep 1
    for i in 0 1 2 3; do
        iw dev "pvap$i" del 2>/dev/null || true
    done
    [ "$LOADED" = 1 ] && rmmod mac80211_hwsim 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Find the hwsim wiphy (do not touch any real radio).
PHY=""
for d in /sys/class/ieee80211/phy*; do
    drv=$(readlink "$d/device/driver" 2>/dev/null || true)
    case "$drv" in
    *mac80211_hwsim*) PHY=${d##*phy}; break ;;
    esac
done
if [ -z "$PHY" ]; then
    [ -f "${HWSIM_KO:-/tmp/hwsim/build/mac80211_hwsim.ko}" ] || {
        echo "no mac80211_hwsim phy and no HWSIM_KO" >&2; exit 1; }
    insmod "${HWSIM_KO:-/tmp/hwsim/build/mac80211_hwsim.ko}" radios=1
    LOADED=1
    sleep 1
    for d in /sys/class/ieee80211/phy*; do
        drv=$(readlink "$d/device/driver" 2>/dev/null || true)
        case "$drv" in *mac80211_hwsim*) PHY=${d##*phy}; break ;; esac
    done
fi
[ -n "$PHY" ] || { echo "no hwsim phy" >&2; exit 1; }
echo "hwsim: phy$PHY band=$BAND"

for i in 0 1 2 3; do
    iw phy "phy$PHY" interface add "pvap$i" type __ap
done
sleep 1
for i in 0 1 2 3; do
    ip link set "pvap$i" down
    ip link set "pvap$i" address "02:00:00:00:06:1$i"
done

# write_one <index> <width>  -- same channel context for every process.
write_one() {
    i=$1; width=$2
    if [ "$BAND" = 6g ]; then
        chan=1
        case "$width" in
        160) op=134; hw=2; ctr=15 ;;
        80)  op=133; hw=1; ctr=7 ;;
        40)  op=132; hw=0; ctr=3 ;;
        20)  op=131; hw=0; ctr=0 ;;
        esac
        cat > "$WORK/vap$i.conf" <<EOF
driver=nl80211
logger_syslog=0
logger_stdout=-1
logger_stdout_level=0
ctrl_interface=$WORK/ctrl
interface=pvap$i
bssid=02:00:00:00:06:1$i
ssid=ag46-6g-$i
hw_mode=a
channel=$chan
op_class=$op
ieee80211ax=1
he_6ghz_reg_pwr_type=0
he_oper_chwidth=$hw
he_oper_centr_freq_seg0_idx=$ctr
auth_algs=1
wpa=2
wpa_key_mgmt=SAE
sae_password=ag46testpass
rsn_pairwise=CCMP
ieee80211w=2
sae_require_mfp=1
ignore_broadcast_ssid=0
ap_isolate=0
EOF
    else
        chan=36
        case "$width" in
        80) hw=1; ctr=42 ;;
        40) hw=0; ctr=0 ;;
        *)  hw=0; ctr=0 ;;
        esac
        cat > "$WORK/vap$i.conf" <<EOF
driver=nl80211
logger_syslog=0
logger_stdout=-1
logger_stdout_level=0
ctrl_interface=$WORK/ctrl
interface=pvap$i
bssid=02:00:00:00:06:1$i
ssid=ag46-5g-$i
hw_mode=a
channel=$chan
auth_algs=1
ieee80211n=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ag46testpass
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
ap_isolate=0
EOF
        if [ "$width" != 20 ]; then
            echo 'ht_capab=[HT40+]' >> "$WORK/vap$i.conf"
        fi
        if [ "$width" = 80 ]; then
            printf 'ieee80211ac=1\nvht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=42\n' \
                >> "$WORK/vap$i.conf"
        fi
    fi
}

start_all() {
    width=$1
    PIDS=""
    for i in 0 1 2 3; do
        write_one "$i" "$width"
        # Leave a stale pidfile from a dead pid on the second round: hostapd
        # -P must replace it, and the agent must not trust it.
        [ -n "${STALE_PIDFILE:-}" ] && echo "$STALE_PIDFILE" > "$WORK/vap$i.pid"
        "$HOSTAPD" -P "$WORK/vap$i.pid" -B "$WORK/vap$i.conf" \
            > "$WORK/vap$i.log" 2>&1 || true
        sleep "$SPACING"
    done
    for i in 0 1 2 3; do
        [ -f "$WORK/vap$i.pid" ] || { echo "FAIL: vap$i has no pid file"; return 1; }
        PIDS="$PIDS $(cat "$WORK/vap$i.pid")"
    done
    # AP-ENABLED can take a moment after hostapd daemonizes.
    n=0
    for _ in $(seq 1 50); do
        n=0
        for i in 0 1 2 3; do
            grep -q 'AP-ENABLED' "$WORK/vap$i.log" 2>/dev/null && n=$((n+1))
        done
        [ "$n" = 4 ] && break
        sleep 0.2
    done
    fail=0
    for i in 0 1 2 3; do
        if grep -q 'AP-ENABLED' "$WORK/vap$i.log"; then
            echo "ok: width=$width vap$i AP-ENABLED pid=$(cat "$WORK/vap$i.pid")"
        else
            echo "FAIL: width=$width vap$i not AP-ENABLED"; fail=1
        fi
        if iw dev "pvap$i" info | grep -q 'type AP'; then
            echo "ok: width=$width vap$i type AP"
        else
            echo "FAIL: width=$width vap$i not type AP"; fail=1
        fi
        if grep -q 'Could not configure driver mode' "$WORK/vap$i.log"; then
            echo "FAIL: width=$width vap$i driver mode error"; fail=1
        fi
    done
    return "$fail"
}

stop_all() {
    for f in "$WORK"/*.pid; do
        [ -f "$f" ] || continue
        p=$(cat "$f" 2>/dev/null || true)
        [ -n "$p" ] && kill "$p" 2>/dev/null || true
    done
    sleep 1
    for f in "$WORK"/*.pid; do
        [ -f "$f" ] || continue
        p=$(cat "$f" 2>/dev/null || true)
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
        rm -f "$f"
    done
    sleep 1
    PIDS=""
}

check_clean() {
    fail=0
    for f in "$WORK"/*.pid; do
        [ -e "$f" ] || continue
        echo "FAIL: stale pidfile $f"; fail=1
    done
    for p in $(pgrep -x hostapd 2>/dev/null || true); do
        if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "$WORK"; then
            echo "FAIL: stale hostapd pid=$p"; fail=1
        fi
    done
    [ "$fail" = 0 ] && echo "ok: no stale hostapd and no stale pidfiles"
    return "$fail"
}

echo "--- round 1: width ${W1:-160}"
start_all "${W1:-160}"
OLD=$PIDS
stop_all
check_clean

echo "--- round 2: stop/width ${W2:-80}/restart with stale pidfiles"
STALE_PIDFILE=999999
start_all "${W2:-80}"
for p in $PIDS; do
    case " $OLD " in
    *" $p "*) echo "FAIL: reused old pid $p"; exit 1 ;;
    esac
    if [ "$p" = 999999 ]; then echo "FAIL: stale pid adopted"; exit 1; fi
done
echo "ok: four new pids after restart"
stop_all
check_clean

echo "host-pervap-restart: PASS (band=$BAND, ${W1:-160}->${W2:-80}, no stale pids)"
