#!/bin/sh
# Install / update the CAP agent on an OpenWrt device. Run as root.
#
#   MANAGER=10.0.0.1 ./install.sh
#
# Environment:
#   MANAGER   manager address, or "auto" for UDP discovery (default: auto)
#   IDENTITY  CAP identity shown on the manager (default: device hostname)
#   CERT/KEY  certificate paths (default: /etc/cap/client.pem|key)
#
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

# Keep the runtime options we need.
sed -i "s|^MANAGER=.*|MANAGER=${MANAGER}|" "${CONF}" 2>/dev/null || true
grep -q '^MANAGER=' "${CONF}" || echo "MANAGER=${MANAGER}" >> "${CONF}"
grep -q '^APPLY='   "${CONF}" || echo "APPLY=yes"   >> "${CONF}"
grep -q '^DATACHAN=' "${CONF}" || echo "DATACHAN=yes" >> "${CONF}"
[ -n "${IDENTITY:-}" ] && { grep -q '^IDENTITY=' "${CONF}" || echo "IDENTITY=${IDENTITY}" >> "${CONF}"; }

# The packaged init script must pass --apply / --datachan.
if [ -f "${INIT}" ]; then
    if grep -q 'APPLY.*--apply' "${INIT}"; then :; else
        sed -i '/SLAVES_STATIC.*--slaves-static/a\	[ "${APPLY:-no}" = yes ] && set -- "$@" --apply' "${INIT}" || true
    fi
    if grep -q 'DATACHAN.*--datachan' "${INIT}"; then :; else
        sed -i '/APPLY.*--apply/a\	[ "${DATACHAN:-no}" = yes ] && set -- "$@" --datachan' "${INIT}" || true
    fi
fi

echo "==> certificate check"
for f in /etc/cap/client.pem /etc/cap/client.key; do
    [ -f "$f" ] || echo "WARNING: $f missing (enroll the CAP first)"
done

echo "==> enabling and restarting capagent"
${INIT} enable 2>/dev/null || true
${INIT} restart 2>/dev/null || ${INIT} start 2>/dev/null || true
sleep 2
ps | grep -v grep | grep "${PROG}" || echo "capagent is not running; check 'logread'"
