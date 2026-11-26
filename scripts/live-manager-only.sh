#!/bin/sh
# live-manager-only.sh — run the CAP in manager-only mode on the reference
# Xiaomi and print the acceptance measurements, then restore the device.
#
# Runs ON the device (busybox sh).  Push and invoke:
#   scp scripts/live-manager-only.sh root@192.168.1.1:/tmp/
#   ssh root@192.168.1.1 'sh /tmp/live-manager-only.sh'
#
# Why a script: the inline heredocs used during W61 kept starting capagent with
# the legacy 8-iface config still in place.  The policy then classified the
# device as `legacy`, every claim fell back to the capN-M alias, and the run
# looked like an ownership bug.  This checks the precondition instead of
# assuming it.
#
# Env (all optional):
#   WAIT=45            seconds to let the manager provision
#   BIN=/usr/sbin/capagent
#   KEEP=1             do not restore/reboot at the end
#   PROFILE=2|3|4      informational only; the manager decides the VAP count
set -u

WAIT=${WAIT:-45}
BIN=${BIN:-/usr/sbin/capagent}
KEEP=${KEEP:-0}
RUNLOG=${RUNLOG:-/tmp/mo-$(date +%s).log}
WLBACK=/tmp/wireless.pre-mo

say() { echo "[mo] $*"; }
fail() { echo "[mo] FAIL: $*" >&2; exit 1; }

# --- 0. one run at a time; never inherit the lock fd into the daemon -------
exec 9>/tmp/cap-live.lock
flock -n 9 || fail "another live run holds /tmp/cap-live.lock"

# --- 1. stop everything we own -------------------------------------------
/etc/init.d/capagent stop >/dev/null 2>&1
for p in $(pidof capagent 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
for p in $(pidof hostapd 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
for f in /var/run/vap-*.pid; do [ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null; done
sleep 2
for i in $(ls /sys/class/net | grep -E '^(phy[0-9]+-ap|cap[0-9]+-|cm[0-9]+$)'); do
	iw dev "$i" del 2>/dev/null
done
rm -f /tmp/vap-*.conf /tmp/vap-*.log /var/run/vap-*.pid \
      /var/run/capagent-vaps.state /var/run/hostapd/ext-auth-* 2>/dev/null

# --- 2. back up, then write a radio-only config --------------------------
cp /etc/config/wireless "$WLBACK" 2>/dev/null || true
cat > /etc/config/wireless <<'EOF'
config wifi-device radio0
	option type mac80211
	option path 1e140000.pcie/pci0000:00/0000:00:01.0/0000:02:00.0
	option band 2g
	option channel 6
	option htmode HT20
	option disabled 0
config wifi-device radio1
	option type mac80211
	option path 1e140000.pcie/pci0000:00/0000:00:02.0/0000:03:00.0
	option band 5g
	option channel 36
	option htmode VHT80
	option disabled 0
EOF
wifi reload >/dev/null 2>&1
sleep 4

# --- 3. precondition: this must be own mode ------------------------------
IFACES=$(grep -c 'config wifi-iface' /etc/config/wireless)
[ "$IFACES" = 0 ] || fail "config still has $IFACES wifi-iface; ownership would be legacy"

# --- 4. run ---------------------------------------------------------------
setsid "$BIN" --manager auto --discovery-interfaces wan --port 5246 \
	--cert /etc/cap/client.pem --key /etc/cap/client.key --macs auto \
	--dont-verify-certificate --identity OpenWrt-CAP3 \
	--eapol-leg both --mgmt-relay --mgmt-source "${MGMT:-monitor}" \
	--ext-auth-dir /var/run/hostapd --country GR \
	>"$RUNLOG" 2>&1 </dev/null 9>&- &

say "running for ${WAIT}s, log $RUNLOG"
sleep "$WAIT"

# --- 5. measurements ------------------------------------------------------
echo "===== acceptance ====="
grep -m1 'ownership=' "$RUNLOG" || true
PHY0=$(ls /sys/class/ieee80211/phy0/device/net 2>/dev/null | tr '\n' ' ')
PHY1=$(ls /sys/class/ieee80211/phy1/device/net 2>/dev/null | tr '\n' ' ')
echo "phy0 netdevs : $PHY0"
echo "phy1 netdevs : $PHY1"
echo "ssids        : $(iw dev 2>/dev/null | grep -c 'ssid ')"
echo "monitors     : $(iw dev 2>/dev/null | grep -c 'Interface cm')"
echo "hostapd_up   : $(grep -c 'hostapd up with' "$RUNLOG")"
echo "enfile(-23)  : $(grep -c -- '-23' /tmp/vap-phy0.log /tmp/vap-phy1.log 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')"
echo "relay 0x2018 : $(grep -cE '0x2018|EXT-AUTH: AUTH|EXT-AUTH: ASSOCREQ' "$RUNLOG")"
echo "relay 0x201c : $(grep -c '0x201c' "$RUNLOG")"
echo "relay 0x201b : $(grep -c '0x201b' "$RUNLOG")"
echo "--- ssid list ---"
iw dev 2>/dev/null | grep -E 'Interface|ssid' | paste - - 2>/dev/null | sed 's/^\s*//' | head -20
echo "===== end ====="

# --- 6. restore ----------------------------------------------------------
if [ "$KEEP" = 1 ]; then
	say "KEEP=1: leaving the run in place (log $RUNLOG)"
	exit 0
fi
for p in $(pidof capagent 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
for p in $(pidof hostapd 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
sleep 2
[ -s "$WLBACK" ] && cp "$WLBACK" /etc/config/wireless
rm -f /tmp/vap-*.conf /tmp/vap-*.log /var/run/vap-*.pid \
      /var/run/capagent-vaps.state /var/run/hostapd/ext-auth-* 2>/dev/null
sync
say "restored; rebooting in 3s"
sleep 3
reboot
