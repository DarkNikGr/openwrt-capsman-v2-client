#!/bin/sh
# Install / update the CAP agent on an OpenWrt device. Run as root.
#
#   MANAGER=10.0.0.1 ./install.sh
#
# Environment:
#   MANAGER   manager address, or "auto" for DHCP-138/broadcast (default: auto)
#   IDENTITY  CAP identity shown on the manager (default: device hostname)
#   CERT/KEY  certificate paths (default: /etc/cap/client.pem|key)
#
# The bundle also carries the multi-identity helpers:
#   multi-cap.sh             -> /usr/sbin/multi-cap.sh
#   identities.conf.example  -> /etc/cap/identities.conf.example
# Copy the example to /etc/cap/identities.conf and restart the service to use
# one CAP identity per SSID (see docs/MULTI-IDENTITY.md).
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARCH=$(uname -m)
case "$ARCH" in
	mips*)   BIN="${DIR}/capagent-mipsel" ;;
	aarch64) BIN="${DIR}/capagent-aarch64" ;;
	*)       BIN="${DIR}/capagent-${ARCH}" ;;
esac
[ -x "$BIN" ] || BIN="${DIR}/capagent-mipsel"
CONF_EXAMPLE="${DIR}/capagent.conf.example"
PROG=/usr/sbin/capagent
CONF=/etc/cap/capagent.conf
INIT=/etc/init.d/capagent
MANAGER=${MANAGER:-auto}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "${BIN}" ] || { echo "missing ${BIN}" >&2; exit 1; }

echo "==> installing ${BIN} -> ${PROG}"
[ -f "${PROG}" ] && cp -a "${PROG}" "${PROG}.orig-$(date +%s)" 2>/dev/null || true
install -m 0755 "${BIN}" "${PROG}"

mkdir -p /etc/cap
if [ ! -f "${CONF}" ]; then
	echo "==> writing ${CONF}"
	install -m 0600 "${CONF_EXAMPLE}" "${CONF}"
fi
sed -i "s|^MANAGER=.*|MANAGER=${MANAGER}|" "${CONF}" 2>/dev/null || true
grep -q '^MANAGER=' "${CONF}" || echo "MANAGER=${MANAGER}" >> "${CONF}"
[ -n "${IDENTITY:-}" ] && {
	grep -q '^IDENTITY=' "${CONF}" || echo "IDENTITY=${IDENTITY}" >> "${CONF}"
}

# Multi-identity helpers (optional).
[ -f "${DIR}/multi-cap.sh" ] &&
	install -m 0755 "${DIR}/multi-cap.sh" /usr/sbin/multi-cap.sh
[ -f "${DIR}/identities.conf.example" ] &&
	install -m 0600 "${DIR}/identities.conf.example" \
		/etc/cap/identities.conf.example

echo "==> certificate check"
for f in /etc/cap/client.pem /etc/cap/client.key; do
	[ -f "$f" ] || echo "WARNING: $f missing (the agent enrols on first start)"
done

echo "==> enabling and restarting capagent"
[ -x "${INIT}" ] || echo "WARNING: ${INIT} missing; install the capagent package or use the image"
[ -x "${INIT}" ] && { "${INIT}" enable 2>/dev/null || true; "${INIT}" restart 2>/dev/null || "${INIT}" start 2>/dev/null || true; }
sleep 2
ps | grep -v grep | grep "${PROG}" || echo "capagent is not running; check 'logread'"
