#!/bin/sh
# scan.sh [interface] [--bg]
# Frequency scan helper (the OpenWrt equivalent of RouterOS
# "frequency-scan" / "bg-frequency-scan" on a CAP).
# Prints one line per visible BSS:
#   freq<TAB>channel<TAB>signal<TAB>security<TAB>bssid<TAB>ssid
# --bg triggers a background scan and returns immediately.
set -u

IF="${1:-}"
MODE="${2:-}"
[ "$IF" = "--bg" ] && { IF=""; MODE="--bg"; }

# pick the first wireless interface if none was given
if [ -z "$IF" ] || [ ! -e "/sys/class/net/$IF" ]; then
	IF=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
fi
[ -n "$IF" ] || { echo "no wireless interface" >&2; exit 1; }

if [ "$MODE" = "--bg" ]; then
	iw dev "$IF" scan trigger >/dev/null 2>&1 || exit 1
	echo "background scan triggered on $IF"
	exit 0
fi

iw dev "$IF" scan 2>/dev/null | awk '
function flush() {
	if (bssid == "") return
	ch = ""
	if (freq >= 5955) ch = (freq - 5950) / 5
	else if (freq >= 5000) ch = (freq - 5000) / 5
	else if (freq > 0) ch = (freq - 2407) / 5
	printf "%s\t%s\t%s\t%s\t%s\t%s\n", freq, ch, sig, sec, bssid, ssid
}
/^BSS / { flush(); bssid = $2; gsub(/\(.*/, "", bssid); freq=""; sig=""; ssid=""; sec="open"; next }
/^\tfreq:/ { freq = $2 }
/^\tsignal:/ { sig = $2 }
/^\tSSID:/ { ssid = substr($0, index($0,$2)); if (ssid == "") ssid = "<hidden>" }
/^\tRSN:/ { sec = "wpa2/wpa3" }
/^\tWPA:/ { sec = "wpa" }
/^\tcapability:.*Privacy/ { if (sec == "open") sec = "wep" }
END { flush() }
' | sort -t "$(printf '\t')" -k1,1n
