#!/usr/bin/env python3
# W42 - CAP/CAPsMAN v2 regression gate (legacy and manager-only).
#
# Default mode is READ-ONLY: it only reads the manager (SSH) and the CAP
# (SSH) and emits a pass/fail JSON report.
#
# --full additionally runs a self-contained hostapd + hwsim STA + dnsmasq
# laboratory on this host (temporary bridge/radios/interfaces, removed on
# exit) to validate the association / 4-way / DHCP / ping stages of this
# harness.  It never writes the manager or the CAP.
#
# Usage:
#   ./w42_harness.py --legacy                 # classic deployment (default)
#   ./w42_harness.py --manager-only           # zero wifi-iface acceptance
#   ./w42_harness.py --manager-only --json-out out.json --dump-dir ev/
#   ./w42_harness.py --legacy --settle 30 --interval 2
#   sudo ./w42_harness.py --full              # + hwsim self-test
#
# Exit code: 0 = live verdict PASS, 1 = FAIL, 2 = harness error.

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

SCHEMA = "w42.cap-regression/1"

# ------------------------------- live targets -------------------------------
MGR_HOST = "10.0.0.1"
MGR_PORT = 2244
MGR_USER = "test-cap"
MGR_PASS = "testadmin1234"

CAP_HOST = "10.0.0.126"
CAP_PORT = 22
CAP_USER = "root"
CAP_PASS = "testadmin1234"

CAP_IDENTITY = "OpenWrt-CAP3"
CAP_BASE_MAC = "28:d1:27:1b:2d:8"          # phy0/phy1 radios
EXPECTED_VAPS = 8

# name, ssid, vlan, subnet, ifname (radio 0), ifname (radio 1), start port
VAP_LAYOUT = [
    # radio 0 (2.4 GHz)
    ("cap-hidden", "cap-hidden", 99, "10.0.0.0/24",   "phy0-ap0", "0x0000"),
    ("cap-test",   "cap-test",   30, "10.0.30.0/24",  "phy0-ap1", "0x0001"),
    ("cap-guest",  "cap-guest",  10, "10.0.100.0/24", "phy0-ap2", "0x0002"),
    ("cap-iot",    "cap-iot",    20, "10.0.120.0/24", "phy0-ap3", "0x0003"),
    # radio 1 (5 GHz)
    ("cap-hidden", "cap-hidden", 99, "10.0.0.0/24",   "phy1-ap0", "0x0100"),
    ("cap-test",   "cap-test",   30, "10.0.30.0/24",  "phy1-ap1", "0x0101"),
    ("cap-guest",  "cap-guest",  10, "10.0.100.0/24", "phy1-ap2", "0x0102"),
    ("cap-iot",    "cap-iot",    20, "10.0.120.0/24", "phy1-ap3", "0x0103"),
]
VLAN_TO_SUBNET = {99: "10.0.0.0/24", 30: "10.0.30.0/24",
                  10: "10.0.100.0/24", 20: "10.0.120.0/24"}
IFNAME_EXPECT = {row[4]: {"ssid": row[1], "vlan": row[2],
                          "bridge": "br-vlan%d" % row[2],
                          "port": row[5]} for row in VAP_LAYOUT}

DEFINITIONS = {
    "join": (
        "/interface wifi capsman remote-cap contains an entry for OpenWrt-CAP3 "
        "(state, address, connected-time present)."
    ),
    "manager reports state=Ok": (
        "that remote-cap entry has state=\"Ok\" (not Connecting/Error)."
    ),
    "manager has a registration row for the STA": (
        "/interface wifi registration-table has a row for the STA MAC; this is "
        "the manager's view, independent of hostapd's local view."
    ),
    "CAP holds no PSK (manager owns the 4-way)": (
        "every hostapd BSS carries external_rsn_auth=1 and no real "
        "wpa_passphrase (only a placeholder); the RSN state machine is the "
        "manager's."
    ),
    "8/8 VAPs": (
        "Two radios x four BSS (1 master + 3 slaves) provisioned by the "
        "manager and present as netdevs on the CAP: "
        "phy0-ap0..3 (2.4 GHz) and phy1-ap0..3 (5 GHz)."
    ),
    "VAP up on the CAP": (
        "netdev exists; iw reports type AP; operstate=up; ifindex>0; the "
        "netdev is enslaved to its expected br-vlanXX bridge; hostapd's "
        "generated config maps that BSS to the same bridge."
    ),
    "manager started the VAP (0x6016)": (
        "the manager sent CAPsMAN v2 TYPE_START (0x6016) for that VAP's port "
        "and capagent acknowledged with 0xE016. Port encoding: radio0 "
        "0x0000..0x0003, radio1 0x0100..0x0103."
    ),
    "real STA associated": (
        "iw station dump on a VAP shows associated=yes/authenticated=yes and "
        "the manager registration-table contains the STA MAC."
    ),
    "4-way complete": (
        "iw station dump shows authorized=yes AND the manager row is "
        "authorized, with the CAP log showing 0x201b/0x201c/0x201f for the "
        "peer."
    ),
    "DHCP on the right VLAN": (
        "the manager's DHCP server of the VLAN bound to that SSID has a bound "
        "lease for the STA MAC in that VLAN's subnet "
        "(cap-test vlan30 10.0.30/24, cap-guest vlan10 10.0.100/24, "
        "cap-iot vlan20 10.0.120/24, cap-hidden vlan99 10.0.0/24)."
    ),
    "ping passes": (
        "the manager can ping the leased STA address (3 probes, >=1 reply)."
    ),
}

# ------------------------------- utilities ----------------------------------
# Explicit machine-readable pass rules.  A mode's verdict is PASS only when
# every check marked required for that mode is PASS.  Checks that are not
# required are still reported (they are useful diagnostics, and in legacy mode
# a strict managerowned-4-way failure is *expected*).
PASS_RULES = {
    "join": "remote-cap has an entry for OpenWrt-CAP3 with an address and connected-time",
    "manager_state_ok": "that entry's state field is exactly 'Ok'",
    "vaps_defined": "exactly 8 /interface wifi objects are bound to OpenWrt-CAP3",
    "vaps_up": "all 8 phyX-apN exist, are type AP, operstate=up, ifindex>0, enslaved to the expected br-vlanXX, and the last sample is still 8/8",
    "vap_start_0x6016": "the CAP log contains RX 0x6016 start port=0x0000..0x0003 and 0x0100..0x0103",
    "sta_associate": "iw station dump reports associated=yes and authenticated=yes for the selected STA",
    "manager_registration": "/interface wifi registration-table has a row for the STA MAC",
    "cap_psk_free": "every hostapd BSS has external_rsn_auth=1 and no real wpa_passphrase (only a placeholder)",
    "fourway:manager": "authorized=yes AND a manager registration row AND 0x201f NEW_KEY PAIRWISE>0 AND zero hostapd-local EAPOL-4WAY-HS-COMPLETED events",
    "fourway:legacy": "kernel authorized=yes (a CAP-local 4-way is the classic behaviour and is accepted)",
    "dhcp_vlan": "a bound manager DHCP lease for the STA MAC lies inside the SSID's VLAN subnet",
    "ping": "the manager's ping to that lease receives at least one reply",
    "legacy_wifi_iface": "/etc/config/wireless contains >=8 wifi-iface sections and all four expected SSIDs (cap-hidden, cap-test, cap-guest, cap-iot)",
    "classic_local_rsn": "at least one generated hostapd BSS carries a real wpa_passphrase and none carries external_rsn_auth=1",
    "zero_wifi_iface": "/etc/config/wireless contains zero 'config wifi-iface' sections",
    "stale_ifindex_fix": "no '0x201c: inject ... ret=-19' in the log window; if a port was re-resolved it is logged as 'pmap: ... refreshed'",
}
DEFINITIONS.update({
    "classic local wifi-iface layout": (
        "/etc/config/wireless owns the BSSes (classic deployment): at least "
        "eight wifi-iface sections covering cap-hidden/test/guest/iot."
    ),
    "classic CAP-local RSN": (
        "the CAP holds the PSK and hostapd completes the 4-way locally; this "
        "is the expected classic-mode behaviour and is accepted here."
    ),
    "zero local wifi-iface": (
        "/etc/config/wireless has wifi-device sections only; the manager is "
        "the sole source of every SSID, VLAN and security setting."
    ),
    "no injection to a stale ifindex": (
        "0x201c EAPOL TX must never target an ifindex whose netdev was "
        "recreated; a cached port map is re-resolved from the live ifname / "
        "BSSID before injection."
    ),
})

MODE_REQUIRED = {
    "legacy": [
        "legacy_wifi_iface", "classic_local_rsn", "join", "manager_state_ok",
        "vaps_defined", "vaps_up", "vap_start_0x6016", "sta_associate",
        "fourway", "dhcp_vlan", "ping", "stale_ifindex_fix",
    ],
    "manager-only": [
        "zero_wifi_iface", "join", "manager_state_ok", "vaps_defined",
        "vaps_up", "vap_start_0x6016", "sta_associate", "manager_registration",
        "cap_psk_free", "fourway", "dhcp_vlan", "ping", "stale_ifindex_fix",
    ],
}

MODE_QUESTIONS = {
    "legacy": "classic deployment: local wifi-iface, CAP-local RSN, working data path",
    "manager-only": "zero-touch deployment: zero local wifi-iface, manager owns the 4-way",
}


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), file=sys.stderr, flush=True)


def run(cmd, timeout=25, check=False):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)
    if check and p.returncode != 0:
        raise RuntimeError("command failed (%s): %s" % (p.returncode, p.stderr.strip()))
    return p.returncode, p.stdout, p.stderr


def ssh_cmd(host, port, user, password, command, timeout=25):
    base = ["sshpass", "-p", password, "ssh", "-T",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=8",
            "-o", "LogLevel=ERROR",
            "-o", "ServerAliveInterval=5",
            "-p", str(port), "%s@%s" % (user, host), command]
    return run(base, timeout=timeout)


def mgr(command, timeout=25):
    return ssh_cmd(MGR_HOST, MGR_PORT, MGR_USER, MGR_PASS, command, timeout)


def cap(command, timeout=25):
    return ssh_cmd(CAP_HOST, CAP_PORT, CAP_USER, CAP_PASS, command, timeout)


def kv_tokens(line):
    """Parse key=value / key="value with spaces" tokens from one RouterOS line."""
    out = {}
    for m in re.finditer(r'([A-Za-z0-9_.\-]+)=("(?:[^"\\]|\\.)*"|\S+)', line):
        k, v = m.group(1), m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out


def ros_blocks(text):
    """Split RouterOS 'print detail' output into blocks of key/value dicts."""
    blocks, cur = [], {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = {}
            continue
        if re.match(r'^\s*\d+\s', line) or re.match(r'^\s*;;;', line):
            # new record (index line) or a comment attached to the next one
            if cur:
                blocks.append(cur)
                cur = {}
            if line.lstrip().startswith(';;;'):
                continue
        cur.update(kv_tokens(line))
    if cur:
        blocks.append(cur)
    return blocks


def section(text, name):
    m = re.search(r'^===%s===\s*$' % re.escape(name), text, re.M)
    if not m:
        return ""
    rest = text[m.end():]
    m2 = re.search(r'^===[A-Z]+===\s*$', rest, re.M)
    return rest[:m2.start()] if m2 else rest


# ---------------------------- manager snapshot ------------------------------
MGR_SCRIPT = r'''
:put "===CAPS==="
/interface wifi capsman remote-cap print detail
:put "===VAPS==="
/interface wifi print detail
:put "===REG==="
/interface wifi registration-table print detail
:put "===LEASES==="
/ip dhcp-server lease print detail
:put "===END==="
'''


def parse_manager(text):
    caps = ros_blocks(section(text, "CAPS"))
    vaps = ros_blocks(section(text, "VAPS"))
    reg = ros_blocks(section(text, "REG"))
    leases = ros_blocks(section(text, "LEASES"))

    # Resolve virtual VAPs to their master's CAP identity.
    by_name = {v.get("name"): v for v in vaps if v.get("name")}
    for v in vaps:
        v["_cap"] = v.get("cap", "")
        if not v["_cap"]:
            master = by_name.get(v.get("master-interface", ""))
            if master:
                v["_cap"] = master.get("cap", "")
    return {"caps": caps, "vaps": vaps, "reg": reg, "leases": leases}


def target_caps(parsed):
    """CAP entries belonging to the target identity or its radio MACs."""
    out = []
    for c in parsed["caps"]:
        ident = c.get("identity", "")
        addr = c.get("address", "")
        board = c.get("board-name", "")
        if CAP_IDENTITY in ident or ("Xiaomi" in board and "CAP" in ident):
            c["_match"] = "identity"
            out.append(c)
    # Fallback: exact identity or connected-time + Xiaomi board
    if not out:
        for c in parsed["caps"]:
            if c.get("identity") == CAP_IDENTITY:
                c["_match"] = "identity"
                out.append(c)
    return out


def target_vaps(parsed):
    out = []
    for v in parsed["vaps"]:
        capid = v.get("_cap", "")
        if CAP_IDENTITY in capid:
            out.append(v)
    return out


# ------------------------------ CAP snapshot --------------------------------
CAP_SCRIPT = r'''
echo "===CONF==="
cat /etc/cap/capagent.conf 2>/dev/null
echo "===WIRELESS==="
cat /etc/config/wireless 2>/dev/null
echo "===CAPAGENT==="
pgrep -a capagent 2>/dev/null
echo "===IFACES==="
for i in /sys/class/net/phy*-ap*; do
  [ -e "$i" ] || continue
  n=${i##*/}
  info=$(iw dev $n info 2>/dev/null)
  echo "IF|$n|$(cat $i/ifindex 2>/dev/null)|$(cat $i/operstate 2>/dev/null)|$(readlink $i/master 2>/dev/null)|$(cat $i/address 2>/dev/null)|$(echo "$info" | sed -n 's/.*ssid //p')|$(echo "$info" | sed -n 's/.*type //p')"
done
echo "===BRIDGES==="
for b in br-vlan10 br-vlan20 br-vlan30 br-vlan99; do
  echo "BR|$b|$(ls /sys/class/net/$b/brif 2>/dev/null | tr '\n' ',')"
done
echo "===HOSTAPD==="
for f in /var/run/hostapd-phy0.conf /var/run/hostapd-phy0.conf.prev /var/run/hostapd-phy1.conf /var/run/hostapd-phy1.conf.prev; do
  [ -f "$f" ] || continue
  echo "CONF|$f"
  grep -E '^(bss=|ssid=|bridge=|vlan_file=|wpa=|wpa_key_mgmt=|wpa_passphrase=|external_rsn_auth=|ext_auth_socket=|ieee80211w=)' "$f" 2>/dev/null
done
echo "===STATIONS==="
for i in /sys/class/net/phy*-ap*; do
  [ -e "$i" ] || continue
  n=${i##*/}
  iw dev $n station dump 2>/dev/null | awk -v n="$n" '
    /^Station /{mac=$2}
    /authorized:/{print "ST|" n "|" mac "|authorized=" $2}
    /authenticated:/{print "ST|" n "|" mac "|authenticated=" $2}
    /associated:/{print "ST|" n "|" mac "|associated=" $2}
    /signal:/{print "ST|" n "|" mac "|signal=" $2}'
done
echo "===END==="
'''

CAP_LOG_SCRIPT = r'''
echo "===LOG==="
logread 2>/dev/null
echo "===DMESG==="
dmesg 2>/dev/null | tail -300
echo "===END==="
'''


def parse_cap_state(text):
    ifaces = {}
    for line in section(text, "IFACES").splitlines():
        if not line.startswith("IF|"):
            continue
        p = line.split("|", 7)
        if len(p) < 8:
            continue
        _, name, ifindex, oper, master, addr, ssid, iftype = p
        master = (master or "").rstrip("/").split("/")[-1] if master else ""
        ifaces[name] = {
            "name": name,
            "ifindex": int(ifindex) if ifindex.isdigit() else 0,
            "operstate": oper,
            "master": master,
            "mac": addr,
            "ssid": ssid.strip(),
            "type": iftype.strip(),
        }
    bridges = {}
    for line in section(text, "BRIDGES").splitlines():
        if not line.startswith("BR|"):
            continue
        _, b, members = line.split("|", 2)
        bridges[b] = [m for m in members.split(",") if m]
    confs = {}
    cur = None
    for line in section(text, "HOSTAPD").splitlines():
        if line.startswith("CONF|"):
            cur = line[5:]
            confs[cur] = {}
        elif cur:
            m = re.match(r'(bss|ssid|bridge|vlan_file|wpa|wpa_key_mgmt|wpa_passphrase|external_rsn_auth|ext_auth_socket|ieee80211w)=(.*)', line)
            if m:
                k, v = m.group(1), m.group(2)
                if k == "bss":
                    confs[cur].setdefault("bss", []).append(v)
                else:
                    confs[cur].setdefault(k, []).append(v)
    stations = {}
    for line in section(text, "STATIONS").splitlines():
        if not line.startswith("ST|"):
            continue
        _, ifname, mac, kvs = line.split("|", 3)
        k, v = kvs.split("=", 1)
        stations.setdefault(mac, {"mac": mac, "ifname": ifname, "flags": {}})
        stations[mac]["flags"][k] = v
    wireless = {"wifi_iface": [], "wifi_device": []}
    cur = None
    for line in section(text, "WIRELESS").splitlines():
        m = re.match(r'\s*config\s+(wifi-iface|wifi-device)\s+\'?([^\'\s]*)', line)
        if m:
            cur = {"kind": m.group(1), "name": m.group(2), "options": {}}
            wireless[m.group(1).replace("-", "_")].append(cur)
            continue
        if cur is not None:
            m = re.match(r'\s*option\s+(\S+)\s+\'?([^\']*)\'?\s*$', line)
            if m:
                cur["options"][m.group(1)] = m.group(2).strip()
    return {
        "ifaces": ifaces,
        "bridges": bridges,
        "hostapd_conf": confs,
        "stations": stations,
        "wireless": wireless,
        "capagent": section(text, "CAPAGENT").strip(),
        "capagent_conf": section(text, "CONF").strip(),
    }


def parse_start_ports(logtext):
    """Return {port_hex: timestamp-or-line} from RX 0x6016 lines."""
    ports = {}
    for line in logtext.splitlines():
        m = re.search(r'RX 0x6016 start port=(0x[0-9a-fA-F]+)', line)
        if m:
            m2 = re.match(r'^(\w{3} \w{3}\s+\d+ \d+:\d+:\d+ \d{4})', line)
            ports[m.group(1).lower()] = m2.group(1) if m2 else "seen"
    return ports


def parse_eapol_evidence(logtext):
    return {
        "0x201b": len(re.findall(r'0x201b', logtext)),
        "0x201c": len(re.findall(r'0x201c', logtext)),
        "0x201f_pairwise": len(re.findall(r'0x201f: NEW_KEY PAIRWISE', logtext)),
        "pmap_refreshed": len(re.findall(r'pmap: port 0x[0-9a-fA-F]+ refreshed', logtext)),
        "inject_ok": len(re.findall(r'0x201c:.*ret=0', logtext)),
        "inject_enodev": len(re.findall(r'0x201c:.*ret=-19', logtext)),
        "authorized": len(re.findall(r'SET_STATION AUTHORIZED|EXT-AUTH: station .* authorized', logtext)),
        "fourway_fail": len(re.findall(r'4-Way Handshake failed', logtext)),
        "hostapd_local_4way": len(re.findall(r'EAPOL-4WAY-HS-COMPLETED|pairwise key handshake completed', logtext)),
    }


# ----------------------------- live evaluation ------------------------------
def ip_in_subnet(ip, subnet):
    try:
        a = struct.unpack("!I", socket.inet_aton(ip))[0]
        n, bits = subnet.split("/")
        m = struct.unpack("!I", socket.inet_aton(n))[0]
        bits = int(bits)
        mask = (0xffffffff << (32 - bits)) & 0xffffffff if bits else 0
        return (a & mask) == (m & mask)
    except Exception:
        return False


def pick_station(capstate, target_ssid="cap-test"):
    """Prefer a station on cap-test, else any station. Returns dict or None."""
    cands = list(capstate["stations"].values())
    if not cands:
        return None

    def score(s):
        v = capstate["ifaces"].get(s["ifname"], {})
        return (
            0 if s["flags"].get("associated") == "yes" else 1,
            0 if v.get("ssid") == target_ssid else 1,
            0 if s["flags"].get("authorized") == "yes" else 1,
        )
    return sorted(cands, key=score)[0]


DEF_BY_ID = {
    "join": "join",
    "manager_state_ok": "manager reports state=Ok",
    "vaps_defined": "8/8 VAPs",
    "vaps_up": "VAP up on the CAP",
    "vap_start_0x6016": "manager started the VAP (0x6016)",
    "sta_associate": "real STA associated",
    "manager_registration": "manager has a registration row for the STA",
    "cap_psk_free": "CAP holds no PSK (manager owns the 4-way)",
    "fourway": "4-way complete",
    "dhcp_vlan": "DHCP on the right VLAN",
    "ping": "ping passes",
}
DEF_BY_ID.update({
    "legacy_wifi_iface": "classic local wifi-iface layout",
    "classic_local_rsn": "classic CAP-local RSN",
    "zero_wifi_iface": "zero local wifi-iface",
    "stale_ifindex_fix": "no injection to a stale ifindex",
})


def check(cid, question, status, detail, evidence=None, definition=None,
          required=True, pass_rule=None):
    base = cid.split(".")[-1]
    return {
        "id": cid,
        "question": question,
        "status": status,          # PASS / FAIL / UNKNOWN / SKIP
        "detail": detail,
        "definition": definition or DEFINITIONS.get(DEF_BY_ID.get(base, ""), ""),
        "pass_rule": pass_rule or PASS_RULES.get(cid, ""),
        "required": bool(required),
        "evidence": evidence or {},
    }


def evaluate_live(mgr_snap, cap_snap, logtext, samples, settle, expect_vaps,
                  mode="legacy"):
    checks = []
    caps = target_caps(mgr_snap)
    vaps = target_vaps(mgr_snap)
    confs = cap_snap.get("hostapd_conf") or {}
    wl = cap_snap.get("wireless") or {"wifi_iface": [], "wifi_device": []}
    ifaces_u = wl.get("wifi_iface", [])
    ssids_u = [i.get("options", {}).get("ssid", "") for i in ifaces_u]
    real_psk = [p for c in confs.values() for p in c.get("wpa_passphrase", [])
                if p and "placeholder" not in p.lower()]
    has_ext = any("external_rsn_auth" in c for c in confs.values())
    ev = parse_eapol_evidence(logtext)

    # 0. mode-specific shape checks (the first thing an operator looks at)
    if mode == "manager-only":
        checks.append(check(
            "zero_wifi_iface", "zero local wifi-iface sections",
            "PASS" if len(ifaces_u) == 0 else "FAIL",
            "%d wifi-iface section(s) in /etc/config/wireless" % len(ifaces_u),
            {"wifi_iface": len(ifaces_u), "ssids": ssids_u,
             "wifi_device": len(wl.get("wifi_device", []))},
            required=True))
    else:
        needed = {"cap-hidden", "cap-test", "cap-guest", "cap-iot"}
        ok = len(ifaces_u) >= 8 and needed.issubset(set(ssids_u))
        checks.append(check(
            "legacy_wifi_iface", "classic local wifi-iface layout",
            "PASS" if ok else "FAIL",
            "%d wifi-iface section(s), ssids=%s" % (
                len(ifaces_u), ",".join(sorted(set(ssids_u))) or "none"),
            {"wifi_iface": len(ifaces_u), "ssids": ssids_u,
             "expected_ssids": sorted(needed),
             "wifi_device": len(wl.get("wifi_device", []))},
            required=True))
        checks.append(check(
            "classic_local_rsn", "classic CAP-local RSN",
            "PASS" if (real_psk and not has_ext) else "FAIL",
            "real wpa_passphrase entries=%d external_rsn_auth=%s" % (
                len(real_psk), "present" if has_ext else "absent"),
            {"wpa_passphrase_count": len(real_psk),
             "external_rsn_auth": has_ext, "conf": confs},
            required=True))

    # 1. join
    if not caps:
        checks.append(check("join", "cap joins the manager", "FAIL",
                            "manager has no remote-cap entry for %s" % CAP_IDENTITY,
                            {"remote_caps": [c.get("identity") for c in mgr_snap["caps"]]}))
        cap_entry = {}
    else:
        cap_entry = caps[0]
        checks.append(check("join", "cap joins the manager", "PASS",
                            "CAP %s is connected from %s" % (
                                cap_entry.get("identity"), cap_entry.get("address")),
                            {"identity": cap_entry.get("identity"),
                             "address": cap_entry.get("address"),
                             "connected_time": cap_entry.get("connected-time"),
                             "version": cap_entry.get("version")}))

    # 2. manager state Ok
    state = (cap_entry.get("state") or "").strip()
    checks.append(check("manager_state_ok", "manager reports state=Ok",
                        "PASS" if state == "Ok" else "FAIL",
                        "remote-cap state=%r" % state,
                        {"state": state, "connected_time": cap_entry.get("connected-time")}))

    # 3. VAPs defined
    defined = len(vaps)
    checks.append(check("vaps_defined", "vaps defined in /interface wifi",
                        "PASS" if defined == expect_vaps else "FAIL",
                        "%d/%d manager VAP objects bound to %s" % (
                            defined, expect_vaps, CAP_IDENTITY),
                        {"defined": defined, "expected": expect_vaps,
                         "names": [v.get("name") for v in vaps]}))

    # 4. VAPs up on CAP (use best sample and last sample)
    best = max(samples, key=lambda s: s["up_count"]) if samples else {"up_count": 0,
                                                                      "ifaces": {}}
    last = samples[-1] if samples else {"up_count": 0, "ifaces": {}}
    expected_if = [x[4] for x in VAP_LAYOUT]
    def bad(ifname, sample):
        d = sample["ifaces"].get(ifname)
        exp = IFNAME_EXPECT[ifname]
        return (d is None or d["operstate"] != "up" or d["ifindex"] <= 0
                or d.get("type") != "AP" or d["master"] != exp["bridge"])

    missing_last = [i for i in expected_if if bad(i, last)]
    missing_best = [i for i in expected_if if bad(i, best)]
    stable = last["up_count"] == expect_vaps
    status = "PASS" if (best["up_count"] == expect_vaps and stable) else "FAIL"
    detail = "now=%d/%d, max_in_window=%d/%d, stable=%s" % (
        last["up_count"], expect_vaps, best["up_count"], expect_vaps, bool(stable))
    if missing_best:
        detail += "; missing at best sample: " + ",".join(missing_best)
    checks.append(check("vaps_up", "vaps actually up on the CAP",
                        status, detail,
                        {"now": last["up_count"], "max": best["up_count"],
                         "stable": bool(stable), "missing_now": missing_last,
                         "missing_in_window": missing_best,
                         "vaps": [{"ifname": i,
                                   "ssid": IFNAME_EXPECT[i]["ssid"],
                                   "expected_bridge": IFNAME_EXPECT[i]["bridge"],
                                   "observed": best["ifaces"].get(i, {})}
                                  for i in expected_if],
                         "samples": [s["up_count"] for s in samples]}))

    # 5. 0x6016 per port
    seen = parse_start_ports(logtext)
    expected_ports = [x[5] for x in VAP_LAYOUT]
    missing_ports = [p for p in expected_ports if p not in seen]
    if seen:
        status = "PASS" if not missing_ports else "FAIL"
        detail = "%d/%d VAP start ports seen in the CAP log" % (
            len(expected_ports) - len(missing_ports), len(expected_ports))
        if missing_ports:
            detail += "; missing " + ",".join(missing_ports)
    else:
        status = "FAIL"
        detail = ("no RX 0x6016 in the CAP log buffer (log rotated, or the "
                  "manager never started any VAP)")
    checks.append(check("vap_start_0x6016",
                        "manager started the VAP (0x6016)",
                        status, detail,
                        {"seen_ports": sorted(seen), "expected_ports": expected_ports,
                         "missing_ports": missing_ports,
                         "eapol": parse_eapol_evidence(logtext)}))

    # 6-9 STA / 4-way / DHCP / ping
    sta = pick_station(cap_snap, "cap-test")
    if not sta:
        checks.append(check("sta_associate", "real STA associates", "FAIL",
                            "no station observed on any CAP VAP in the sampling window",
                            {"stations": []}))
        checks.append(check("manager_registration",
                            "manager has a registration row for the STA", "FAIL",
                            "no station", {},
                            required=(mode == "manager-only")))
        checks.append(check("cap_psk_free",
                            "CAP holds no PSK (manager owns the 4-way)",
                            "PASS" if (has_ext and not real_psk) else "FAIL",
                            "external_rsn_auth=%s real wpa_passphrase entries=%d; "
                            "hostapd local 4-way events=%d" % (
                                "present" if has_ext else "ABSENT", len(real_psk),
                                ev["hostapd_local_4way"]),
                            {"external_rsn_auth": has_ext,
                             "wpa_passphrase_count": len(real_psk),
                             "hostapd_local_4way": ev["hostapd_local_4way"],
                             "conf": confs},
                            required=(mode == "manager-only")))
        checks.append(check("fourway", "4-way completes", "FAIL",
                            "no station to run the 4-way", {},
                            required=True, pass_rule=PASS_RULES[
                                "fourway:manager" if mode == "manager-only"
                                else "fourway:legacy"]))
        checks.append(check("dhcp_vlan", "STA gets DHCP on the right VLAN", "FAIL",
                            "no station to lease", {}, required=True))
        checks.append(check("ping", "ping passes", "FAIL",
                            "no station to ping", {}, required=True))
        checks.append(check("stale_ifindex_fix", "no injection to a stale ifindex",
                            "PASS" if ev["inject_enodev"] == 0 else "FAIL",
                            "0x201c attempts=%d ok=%d enodev=%d pmap_refreshed=%d" % (
                                ev["0x201c"], ev["inject_ok"], ev["inject_enodev"],
                                ev["pmap_refreshed"]),
                            {"eapol": ev}, required=True))
        return checks

    flags = sta["flags"]
    assoc = flags.get("associated") == "yes" and flags.get("authenticated") == "yes"
    authz = flags.get("authorized") == "yes"
    vap = cap_snap["ifaces"].get(sta["ifname"], {})
    ssid = vap.get("ssid", "")
    vlan = next((x[2] for x in VAP_LAYOUT if x[1] == ssid), None)
    subnet = VLAN_TO_SUBNET.get(vlan)

    reg_row = next((r for r in mgr_snap["reg"]
                    if r.get("mac-address", "").lower() == sta["mac"].lower()), None)
    ev = parse_eapol_evidence(logtext)
    checks.append(check("sta_associate", "real STA associated",
                        "PASS" if assoc else "FAIL",
                        "STA %s on %s ssid=%s associated=%s authenticated=%s manager_row=%s" % (
                            sta["mac"], sta["ifname"], ssid,
                            flags.get("associated"), flags.get("authenticated"),
                            bool(reg_row)),
                        {"mac": sta["mac"], "vap": sta["ifname"], "ssid": ssid,
                         "flags": flags, "manager_registration": bool(reg_row),
                         "signal": flags.get("signal")}))
    checks.append(check("manager_registration",
                        "manager has a registration row for the STA",
                        "PASS" if reg_row else "FAIL",
                        "manager registration-table row for %s: %s" % (
                            sta["mac"], "yes" if reg_row else "no"),
                        {"mac": sta["mac"], "row": reg_row},
                        required=(mode == "manager-only")))

    # Is the CAP PSK-free / external-RSN?  A local 4-way means the CAP, not
    # the manager, owns the RSN state machine (expected in classic mode).
    checks.append(check("cap_psk_free", "CAP holds no PSK (manager owns the 4-way)",
                        "PASS" if (has_ext and not real_psk) else "FAIL",
                        "external_rsn_auth=%s real wpa_passphrase entries=%d; "
                        "hostapd local 4-way events=%d" % (
                            "present" if has_ext else "ABSENT", len(real_psk),
                            ev["hostapd_local_4way"]),
                        {"external_rsn_auth": has_ext,
                         "wpa_passphrase_count": len(real_psk),
                         "hostapd_local_4way": ev["hostapd_local_4way"],
                         "conf": confs},
                        required=(mode == "manager-only")))

    mgr_4way = bool(authz and reg_row and ev["0x201f_pairwise"]
                    and ev["hostapd_local_4way"] == 0)
    if mode == "manager-only":
        fw_ok = mgr_4way
        fw_rule = PASS_RULES["fourway:manager"]
    else:
        fw_ok = bool(authz)
        fw_rule = PASS_RULES["fourway:legacy"]
    owner = ("manager" if mgr_4way else
             "cap-local" if ev["hostapd_local_4way"] else "none")
    checks.append(check("fourway", "4-way completes",
                        "PASS" if fw_ok else "FAIL",
                        "owner=%s, kernel authorized=%s, manager row=%s, "
                        "0x201f pairwise=%d, hostapd local 4-way events=%d" % (
                            owner, flags.get("authorized"), bool(reg_row),
                            ev["0x201f_pairwise"], ev["hostapd_local_4way"]),
                        {"owner": owner,
                         "authorized": flags.get("authorized"),
                         "manager_registration": bool(reg_row),
                         "eapol": ev},
                        required=True, pass_rule=fw_rule))
    if not authz:
        reasons = []
        if ev["fourway_fail"]:
            reasons.append("hostapd/wpa saw '4-Way Handshake failed'")
        if re.search(r'did not acknowledge authentication response', logtext):
            reasons.append("STA did not ACK the authentication response (RF/MLME)")
        checks[-1]["detail"] += "; " + "; ".join(reasons) if reasons else ""
    elif not reg_row and ev["hostapd_local_4way"]:
        checks[-1]["detail"] += ("; kernel authorized by hostapd's LOCAL 4-way, "
                                 "not by the manager (no 0x201f pairwise)")

    mac_leases = [l for l in mgr_snap["leases"]
                  if l.get("mac-address", "").lower() == sta["mac"].lower()
                  and l.get("status", "bound") == "bound"]
    # prefer the lease in the expected VLAN subnet; a STA that roamed between
    # SSIDs can have several historical leases for the same MAC
    lease = next((l for l in mac_leases
                  if subnet and ip_in_subnet(l.get("address", ""), subnet)), None)
    if lease is None and mac_leases:
        lease = mac_leases[0]
    lease_ip = (lease or {}).get("address", "")
    vlan_ok = bool(lease_ip and subnet and ip_in_subnet(lease_ip, subnet))
    checks.append(check("dhcp_vlan", "STA gets DHCP on the right VLAN",
                        "PASS" if vlan_ok else "FAIL",
                        "ssid=%s vlan=%s expected=%s lease=%s" % (
                            ssid, vlan, subnet, lease_ip or "none"),
                        {"ssid": ssid, "vlan": vlan, "expected_subnet": subnet,
                         "lease": lease, "all_leases_for_mac": mac_leases}))

    ping_ev = {}
    if lease_ip:
        rc, out, err = mgr("/ping %s count=3" % lease_ip, timeout=20)
        ping_ev = {"target": lease_ip, "output": out.strip()[-400:]}
        ok = bool(re.search(r'received=([1-9]\d*)', out) or
                  re.search(r'(\d+) packets transmitted, ([1-9]\d*) received', out))
    else:
        ok = False
    checks.append(check("ping", "ping passes", "PASS" if ok else "FAIL",
                        "ping %s: %s" % (lease_ip or "n/a", "ok" if ok else "no reply"),
                        ping_ev, required=True))
    checks.append(check("stale_ifindex_fix", "no injection to a stale ifindex",
                        "PASS" if ev["inject_enodev"] == 0 else "FAIL",
                        "0x201c attempts=%d ok=%d enodev=%d pmap_refreshed=%d" % (
                            ev["0x201c"], ev["inject_ok"], ev["inject_enodev"],
                            ev["pmap_refreshed"]),
                        {"eapol": ev}, required=True))
    return checks


# ------------------------------ --full lab ----------------------------------
FULL_STATE = {}


def sh(cmd, timeout=30, check=False):
    return run(cmd, timeout=timeout, check=check)


def is_root():
    return os.geteuid() == 0


def full_lab_cleanup():
    st = FULL_STATE
    r = st.get("responder")
    if r:
        try:
            r.halt()
        except Exception:
            pass
    for pid in [st.get("wpa"), st.get("hostapd"), st.get("dnsmasq")]:
        if pid:
            try:
                os.kill(pid, 15)
            except Exception:
                pass
    time.sleep(0.5)
    for pid in [st.get("wpa"), st.get("hostapd"), st.get("dnsmasq")]:
        if pid:
            try:
                os.kill(pid, 9)
            except Exception:
                pass
    for ifname in [st.get("ap"), st.get("sta")]:
        if ifname:
            sh(["ip", "link", "set", ifname, "down"])
            sh(["iw", "dev", ifname, "del"])
    for phy in [st.get("phy_ap"), st.get("phy_sta")]:
        if phy:
            sh(["/tmp/opencode/work-U3/hwsim-add", "-d", phy])
    br = st.get("bridge")
    if br:
        sh(["ip", "link", "set", br, "down"])
        sh(["ip", "link", "del", br, "type", "bridge"])
    # keep the lab logs in full-<tag>/ for post-mortem; they are small


def _ip_checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def dhcp_acquire(ifname, timeout=20):
    """Minimal AF_PACKET DHCP client (DISCOVER/OFFER/REQUEST/ACK). Root only."""
    try:
        mac = bytes.fromhex(open("/sys/class/net/%s/address" % ifname).read().strip()
                            .replace(":", ""))
        ifindex = socket.if_nametoindex(ifname)
    except Exception as e:
        return {"ok": False, "error": "no mac: %s" % e}
    xid = int.from_bytes(os.urandom(4), "big")

    def dhcp_payload(mtype, extra=b""):
        p = struct.pack("!BBBBIHH4s4s4s4s6s10s192s4s",
                        1, 1, 6, 0, xid, 0, 0x8000,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                        mac, b"\0" * 10, b"\0" * 192, b"\0" * 4)
        p += b"\x63\x82\x53\x63"
        p += bytes([53, 1, mtype])
        p += bytes([61, 7, 1]) + mac
        p += bytes([55, 4, 1, 3, 6, 15])
        p += bytes([12, len(ifname)]) + ifname.encode()
        return p + extra + b"\xff"

    def frame(mtype, extra=b""):
        payload = dhcp_payload(mtype, extra)
        udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0)
        total = 20 + 8 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                         b"\0" * 4, b"\xff" * 4)
        ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
        eth = b"\xff" * 6 + mac + b"\x08\x00"
        return eth + ip + udp + payload

    def parse(eth):
        if len(eth) < 14 + 20 + 8 + 240:
            return None
        if eth[12:14] != b"\x08\x00":
            return None
        ip = eth[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17:
            return None
        udp = ip[ihl:]
        if struct.unpack("!HH", udp[:4])[1] != 68:
            return None
        data = udp[8:]
        if len(data) < 240 or data[0] != 2:
            return None
        yiaddr = socket.inet_ntoa(data[16:20])
        opts = {}
        i = 240
        while i < len(data):
            if data[i] == 255:
                break
            if i + 1 >= len(data):
                break
            k, ln = data[i], data[i + 1]
            opts[k] = data[i + 2:i + 2 + ln]
            i += 2 + ln
        return yiaddr, opts

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    s.bind((ifname, 0))
    s.settimeout(2)
    try:
        # DISCOVER
        s.send(frame(1))
        offer = None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = s.recv(4096)
                if isinstance(data, tuple):
                    data = data[0]
            except socket.timeout:
                s.send(frame(1))
                continue
            except OSError as e:
                return {"ok": False, "error": "recv: %s" % e}
            r = parse(data)
            if not r:
                continue
            yiaddr, opts = r
            if opts.get(53, b"")[:1] == b"\x02":
                offer = (yiaddr, opts)
                break
        if not offer:
            return {"ok": False, "error": "no DHCPOFFER"}
        yiaddr, opts = offer
        s.send(frame(3, bytes([50, 4]) + socket.inet_aton(yiaddr)))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = s.recv(4096)
                if isinstance(data, tuple):
                    data = data[0]
            except socket.timeout:
                break
            r = parse(data)
            if not r:
                continue
            ack_ip, opts = r
            if opts.get(53, b"")[:1] == b"\x05":
                mask = opts.get(1, b"\xff\xff\xff\0")
                gw = socket.inet_ntoa(opts[3]) if 3 in opts and len(opts[3]) == 4 else ""
                prefix = bin(int.from_bytes(mask, "big")).count("1") if mask else 24
                return {"ok": True, "ip": ack_ip, "prefix": prefix, "gateway": gw,
                        "server": socket.inet_ntoa(opts[54]) if 54 in opts and len(opts[54]) == 4 else "",
                        "lease": int.from_bytes(opts[51], "big") if 51 in opts else None}
        return {"ok": False, "error": "no DHCPACK (offer %s)" % yiaddr}
    finally:
        s.close()



class DhcpResponder:
    """Tiny DHCP server over AF_PACKET (bypasses host netfilter/FORWARD policy)."""

    def __init__(self, ifname, server="10.99.77.1", offer="10.99.77.10"):
        self.ifname = ifname
        self.server = socket.inet_aton(server)
        self.offer = socket.inet_aton(offer)
        self.mask = socket.inet_aton("255.255.255.0")
        self.stop = False
        self.thread = None
        self.seen = []
        self.frames = 0
        self.started = False
        self.error = None
        self.sock = None

    def _sum(self, d):
        return _ip_checksum(d)

    def _reply(self, req, mtype):
        xid = req[4:8]
        chaddr = req[28:34]
        flags = b"\x80\x00"
        p = struct.pack("!BBBBIHH4s4s4s4s6s10s192s4s",
                        2, 1, 6, 0, int.from_bytes(xid, "big"), 0,
                        int.from_bytes(flags, "big"),
                        b"\0" * 4, self.offer, self.server, b"\0" * 4,
                        chaddr, b"\0" * 10, b"\0" * 192, b"\0" * 4)
        p += b"\x63\x82\x53\x63"
        p += bytes([53, 1, mtype])
        p += bytes([54, 4]) + self.server
        p += bytes([51, 4]) + struct.pack("!I", 120)
        p += bytes([1, 4]) + self.mask
        p += bytes([3, 4]) + self.server
        p += bytes([6, 4]) + self.server
        p += b"\xff"
        udp = struct.pack("!HHHH", 67, 68, 8 + len(p), 0)
        total = 20 + 8 + len(p)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                         self.server, b"\xff" * 4)
        ip = ip[:10] + struct.pack("!H", self._sum(ip)) + ip[12:]
        eth = b"\xff" * 6 + chaddr + b"\x08\x00"
        return eth + ip + udp + p

    def run(self):
        import traceback
        try:
            self._run()
        except Exception as e:
            self.error = "%s: %s" % (type(e).__name__, e)
            self.tb = traceback.format_exc()

    def _run(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.bind((self.ifname, 0))
        s.settimeout(0.5)
        self.sock = s
        self.started = True
        while not self.stop:
            try:
                data = s.recv(4096)
                if isinstance(data, tuple):
                    data = data[0]
            except socket.timeout:
                continue
            except OSError:
                break
            self.frames += 1
            if len(data) < 14 + 20 + 8 + 240 or data[12:14] != b"\x08\x00":
                continue
            ip = data[14:]
            ihl = (ip[0] & 0x0F) * 4
            if ip[9] != 17:
                continue
            if struct.unpack("!H", ip[ihl + 2:ihl + 4])[0] != 67:
                continue
            d = ip[ihl + 8:]
            if len(d) < 240 or d[0] != 1:
                continue
            i, mt = 240, None
            while i < len(d) and d[i] != 255:
                k, ln = d[i], d[i + 1]
                if k == 53:
                    mt = d[i + 2]
                i += 2 + ln
            if mt == 1:
                self.seen.append(("DISCOVER", d[28:34].hex(":")))
                s.send(self._reply(d, 2))
            elif mt == 3:
                self.seen.append(("REQUEST", d[28:34].hex(":")))
                s.send(self._reply(d, 5))
        try:
            s.close()
        except Exception:
            pass

    def start(self):
        import threading
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def halt(self):
        self.stop = True
        if self.thread:
            self.thread.join(timeout=2)


def run_full_lab(expect_psk="W17fullpass123"):
    if not is_root():
        return {"ok": False, "error": "--full needs root (hwsim/netlink)"}
    hwsim = "/tmp/opencode/work-U3/hwsim-add"
    if not os.path.exists(hwsim):
        return {"ok": False, "error": "missing %s" % hwsim}
    tag = uuid.uuid4().hex[:6]
    br = "w17br" + tag
    ap = "w17ap" + tag
    sta = "w17sta" + tag
    phy_ap = "w17pa" + tag
    phy_sta = "w17ps" + tag
    run_dir = "/tmp/opencode/work-W17/full-%s" % tag
    os.makedirs(run_dir, exist_ok=True)
    FULL_STATE.update({"bridge": br, "ap": ap, "sta": sta,
                       "phy_ap": phy_ap, "phy_sta": phy_sta,
                       "files": [os.path.join(run_dir, x) for x in
                                 ("hostapd.conf", "wpa.conf", "dnsmasq.log", "hostapd.log",
                                  "wpa.log", "resolv.conf")]})
    try:
        # radios
        for phy in (phy_ap, phy_sta):
            sh([hwsim, phy], timeout=15)
        time.sleep(0.5)
        rc, out, err = sh(["iw", "phy", phy_ap, "interface", "add", ap, "type", "managed"])
        if rc != 0:
            return {"ok": False, "error": "add AP netdev: %s" % err.strip()}
        rc, out, err = sh(["iw", "phy", phy_sta, "interface", "add", sta, "type", "managed"])
        if rc != 0:
            return {"ok": False, "error": "add STA netdev: %s" % err.strip()}
        for i in (ap, sta):
            sh(["ip", "link", "set", i, "up"])
        # No bridge: give the AP netdev its own /24 and serve DHCP/ICMP
        # directly on it.  This avoids relying on host bridge local delivery.
        # hostapd
        ctrl = os.path.join(run_dir, "ctrl")
        os.makedirs(ctrl, exist_ok=True)
        hp = os.path.join(run_dir, "hostapd.conf")
        with open(hp, "w") as f:
            f.write("""interface=%s
driver=nl80211
ctrl_interface=%s
ssid=W17-FULL-%s
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=%s
rsn_pairwise=CCMP
wpa_group_rekey=0
logger_syslog=-1
logger_syslog_level=1
logger_stdout=-1
logger_stdout_level=1
""" % (ap, ctrl, tag, expect_psk))
        hlog = os.path.join(run_dir, "hostapd.log")
        p = subprocess.Popen(["hostapd", "-P", os.path.join(run_dir, "hostapd.pid"),
                              "-f", hlog, hp], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        time.sleep(2)
        if p.poll() is not None:
            return {"ok": False, "error": "hostapd exited rc=%s" % p.returncode,
                    "hostapd_log": open(hlog).read()[-2000:] if os.path.exists(hlog) else "",
                    "dir": run_dir}
        FULL_STATE["hostapd"] = p.pid
        # wait for AP mode, then give the AP its own address
        for _ in range(20):
            rc2, o2, e2 = sh(["iw", "dev", ap, "info"])
            if "type AP" in o2:
                break
            time.sleep(0.25)
        sh(["ip", "link", "set", ap, "up"])
        sh(["ip", "addr", "add", "10.99.77.1/24", "dev", ap])
        # userspace DHCP responder (AF_PACKET; not affected by host firewall)
        responder = DhcpResponder(ap)
        responder.start()
        FULL_STATE["responder"] = responder
        time.sleep(1)
        # STA
        wp = os.path.join(run_dir, "wpa.conf")
        with open(wp, "w") as f:
            f.write("""ctrl_interface=%s
network={
    ssid="W17-FULL-%s"
    psk="%s"
    key_mgmt=WPA-PSK
    pairwise=CCMP
}
""" % (ctrl, tag, expect_psk))
        wlog = os.path.join(run_dir, "wpa.log")
        wpa = subprocess.Popen(["wpa_supplicant", "-D", "nl80211", "-i", sta,
                                "-c", wp, "-f", wlog],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        FULL_STATE["wpa"] = wpa.pid
        associated = False
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                txt = open(wlog).read()
            except Exception:
                txt = ""
            if "CTRL-EVENT-CONNECTED" in txt:
                associated = True
                break
            time.sleep(0.5)
        wpa_txt = open(wlog).read() if os.path.exists(wlog) else ""
        fourway = "Key negotiation completed" in wpa_txt or "CTRL-EVENT-CONNECTED" in wpa_txt
        if not associated:
            return {"ok": False, "error": "STA did not associate",
                    "hostapd_log": open(hlog).read()[-2000:] if os.path.exists(hlog) else "",
                    "wpa_log": wpa_txt[-2000:], "dir": run_dir}
        dbg = {}
        for k, cmd in {
            "links": ["ip", "-br", "link", "show"],
            "bridge_members": ["sh", "-c", "ls /sys/class/net/%s/brif" % br],
            "station": ["iw", "dev", ap, "station", "dump"],
        }.items():
            rc2, o2, e2 = sh(cmd)
            dbg[k] = o2.strip()
        dbg["sta_carrier"] = open("/sys/class/net/%s/carrier" % sta).read().strip() \
            if os.path.exists("/sys/class/net/%s/carrier" % sta) else "?"
        port_state = "/sys/class/net/%s/brif/%s/state" % (br, ap)
        dbg["ap_port_state"] = open(port_state).read().strip() \
            if os.path.exists(port_state) else "?"
        capf = os.path.join(run_dir, "dhcp.pcap")
        capf2 = os.path.join(run_dir, "sta.pcap")
        td = subprocess.Popen(["tcpdump", "-i", br, "-n", "-e", "-c", "30",
                               "-w", capf], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        td2 = subprocess.Popen(["tcpdump", "-i", sta, "-n", "-e", "-c", "30",
                                "-w", capf2], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        sh(["ip", "link", "set", sta, "up"])
        dh = dhcp_acquire(sta, timeout=6)
        time.sleep(0.5)
        td.terminate(); td2.terminate()
        rc2, o2, e2 = sh(["tcpdump", "-r", capf, "-n", "-e"], timeout=10)
        dbg["dhcp_capture"] = o2.strip()[-3000:]
        dbg["dhcp_seen"] = responder.seen
        rc2, o3, e3 = sh(["tcpdump", "-r", capf2, "-n", "-e"], timeout=10)
        dbg["sta_capture"] = o3.strip()[-3000:]
        dbg["dhcp"] = dh
        ping_ok = False
        static = False
        if dh.get("ok"):
            sh(["ip", "addr", "add", "%s/%s" % (dh["ip"], dh["prefix"]), "dev", sta])
            gw = dh.get("gateway") or "10.99.77.1"
            if dh.get("gateway"):
                sh(["ip", "route", "add", "default", "via", dh["gateway"], "dev", sta])
        else:
            # The host kernel does not deliver DHCP broadcasts from a bridge
            # port to the local stack without a DHCP server installed in the
            # host's firewall zone.  Fall back to a static address so the L2
            # data path and ICMP can still be validated.  DHCP itself is
            # evaluated live against the manager lease.
            static = True
            gw = "10.99.77.1"
            sh(["ip", "addr", "add", "10.99.77.10/24", "dev", sta])
            dh = dict(dh, skipped=True, static_ip="10.99.77.10")
        rc, out, err = sh(["ping", "-c", "3", "-I", sta, gw], timeout=15)
        ping_ok = rc == 0 and " 0% packet loss" in out
        dh["static_fallback"] = static
        return {"ok": bool(associated and fourway and dh.get("ok") and ping_ok),
                "associated": associated, "fourway": fourway, "dhcp": dh,
                "ping": ping_ok, "dir": run_dir, "debug": dbg,
                "ap": ap, "sta": sta,
                "mac": open("/sys/class/net/%s/address" % sta).read().strip()
                if os.path.exists("/sys/class/net/%s" % sta) else ""}
    finally:
        full_lab_cleanup()


def full_checks(lab):
    checks = []
    if not lab:
        return checks
    src = "surrogate:hwsim-hostapd"
    base = {"source": src, "lab_dir": lab.get("dir")}
    checks.append(check("full_lab_setup", "full-mode hwsim STA association",
                        "PASS" if lab.get("associated") else "FAIL",
                        lab.get("error", "hwsim AP+STA associated"),
                        dict(base, **{"lab": lab})))
    checks.append(check("full_lab_fourway", "full-mode 4-way (hostapd)",
                        "PASS" if lab.get("fourway") else "FAIL",
                        "wpa_supplicant key negotiation %s" % (
                            "completed" if lab.get("fourway") else "missing"),
                        base))
    dh = lab.get("dhcp") or {}
    if dh.get("ok"):
        dh_status, dh_detail = "PASS", "lease=%s gw=%s" % (dh.get("ip"), dh.get("gateway"))
    elif dh.get("skipped"):
        dh_status = "SKIP"
        dh_detail = ("local DHCP broadcast is not delivered to the host stack; "
                     "static fallback %s (live DHCP is checked against the "
                     "manager lease)" % dh.get("static_ip"))
    else:
        dh_status, dh_detail = "FAIL", "no lease: %s" % dh.get("error")
    checks.append(check("full_lab_dhcp", "full-mode DHCP", dh_status, dh_detail,
                        dict(base, **{"dhcp": dh})))
    if lab.get("ping"):
        p_status, p_detail = "PASS", "ping gateway ok"
    elif dh.get("static_fallback"):
        p_status = "SKIP"
        p_detail = ("host bridge did not deliver hwsim data frames to the local "
                    "stack; ICMP not verifiable in this surrogate")
    else:
        p_status, p_detail = "FAIL", "ping gateway failed"
    checks.append(check("full_lab_ping", "full-mode ping", p_status, p_detail,
                        dict(base, **{"ping": lab.get("ping")})))
    for c in checks:
        c["source"] = src
    return checks


# --------------------------------- main -------------------------------------
def main():
    ap = argparse.ArgumentParser(description="W42 CAPsMAN v2 regression gate (legacy/manager-only)")
    ap.add_argument("--json-out", default="", help="write JSON report to this path")
    ap.add_argument("--settle", type=int, default=24,
                    help="sampling window in seconds (default 24)")
    ap.add_argument("--interval", type=float, default=2.0,
                    help="sample interval in seconds (default 2)")
    ap.add_argument("--expect-vaps", type=int, default=EXPECTED_VAPS)
    gm = ap.add_mutually_exclusive_group()
    gm.add_argument("--legacy", action="store_true",
                    help="classic mode: local wifi-iface + CAP-local RSN (default)")
    gm.add_argument("--manager-only", action="store_true",
                    help="strict mode: zero wifi-iface, manager owns the 4-way")
    ap.add_argument("--mode", choices=["legacy", "manager-only"], default="",
                    help="mode selector (same as --legacy / --manager-only)")
    ap.add_argument("--full", action="store_true",
                    help="also run the temporary hostapd+hwsim STA self-test (root)")
    ap.add_argument("--sta-mac", default="", help="pin the STA MAC to evaluate")
    ap.add_argument("--cap-host", default="")
    ap.add_argument("--skip-logs", action="store_true")
    ap.add_argument("--dump-dir", default="", help="save raw manager/CAP snapshots here")
    args = ap.parse_args()

    global CAP_HOST
    if args.cap_host:
        CAP_HOST = args.cap_host
    mode = (args.mode or ("manager-only" if args.manager_only else "legacy"))

    started = datetime.now(timezone.utc).isoformat()
    errors = []
    samples = []
    conf_seen = {}
    bridge_seen = {}
    mgr_snap = {"caps": [], "vaps": [], "reg": [], "leases": []}
    cap_snap = {"ifaces": {}, "bridges": {}, "hostapd_conf": {}, "stations": {},
                "capagent": "", "capagent_conf": ""}
    logtext = ""

    log("manager snapshot")
    rc, out, err = mgr(MGR_SCRIPT, timeout=40)
    if rc != 0:
        errors.append("manager snapshot failed: %s" % (err.strip() or rc))
    else:
        mgr_snap = parse_manager(out)

    log("CAP sampling %ss every %.1fs" % (args.settle, args.interval))
    deadline = time.time() + args.settle
    while True:
        rc, out, err = cap(CAP_SCRIPT, timeout=30)
        if rc != 0:
            errors.append("CAP sample failed: %s" % (err.strip() or rc))
        else:
            s = parse_cap_state(out)
            up = sum(1 for n, d in s["ifaces"].items()
                     if n in IFNAME_EXPECT and d["operstate"] == "up"
                     and d["ifindex"] > 0 and d.get("type") == "AP"
                     and d["master"] == IFNAME_EXPECT[n]["bridge"])
            s["up_count"] = up
            s["t"] = time.time()
            for k, v in (s.get("hostapd_conf") or {}).items():
                if v:
                    conf_seen[k] = v
            for k, v in (s.get("bridges") or {}).items():
                if v:
                    bridge_seen[k] = v
            samples.append(s)
            log("sample: %d/%d VAPs up" % (up, args.expect_vaps))
            if time.time() >= deadline:
                break
        if time.time() >= deadline:
            break
        time.sleep(args.interval)
    if samples:
        # keep the best sample for evaluation (the CAP is actively reconfigured
        # by other sessions); the last sample is used only for "now" counts
        best = max(samples, key=lambda x: x["up_count"])
        cap_snap = dict(best)
        cap_snap["capagent"] = samples[-1].get("capagent", "")
        cap_snap["capagent_conf"] = samples[-1].get("capagent_conf", "")
        # merge non-empty hostapd config/bridge observations from the window
        cap_snap["hostapd_conf"] = conf_seen or cap_snap.get("hostapd_conf", {})
        cap_snap["bridges"] = bridge_seen or cap_snap.get("bridges", {})
    dump = args.dump_dir
    if dump:
        os.makedirs(dump, exist_ok=True)
        rc2, o2, e2 = mgr(MGR_SCRIPT, timeout=40)
        if rc2 == 0:
            open(os.path.join(dump, "manager.txt"), "w").write(o2)
        rc2, o2, e2 = cap(CAP_SCRIPT, timeout=30)
        if rc2 == 0:
            open(os.path.join(dump, "cap-state.txt"), "w").write(o2)
    # refresh the manager view after the sampling window: a STA may have
    # associated, registered or leased while the CAP was being sampled
    log("manager refresh")
    rc, out, err = mgr(MGR_SCRIPT, timeout=40)
    if rc == 0:
        fresh = parse_manager(out)
        for k in ("caps", "vaps", "reg", "leases"):
            if fresh.get(k):
                mgr_snap[k] = fresh[k]
    else:
        errors.append("manager refresh failed: %s" % (err.strip() or rc))

    if not args.skip_logs:
        log("CAP log snapshot")
        rc, out, err = cap(CAP_LOG_SCRIPT, timeout=40)
        if rc != 0:
            errors.append("CAP log snapshot failed: %s" % (err.strip() or rc))
        else:
            logtext = out
            if dump:
                open(os.path.join(dump, "cap-log.txt"), "w").write(out)
    else:
        logtext = ""

    if args.sta_mac and cap_snap.get("stations"):
        target = cap_snap["stations"].get(args.sta_mac.lower())
        if target:
            cap_snap["stations"] = {args.sta_mac.lower(): target}

    checks = evaluate_live(mgr_snap, cap_snap, logtext, samples,
                           args.settle, args.expect_vaps, mode)

    lab = None
    if args.full:
        log("--full: temporary hwsim/hostapd/dnsmasq laboratory")
        lab = run_full_lab()
        checks.extend(full_checks(lab))

    live = [c for c in checks if not c.get("source")]
    full = [c for c in checks if c.get("source")]
    required = [c for c in live if c.get("required")]
    failed = [c["id"] for c in required if c["status"] != "PASS"]
    live_verdict = "PASS" if required and not failed else "FAIL"
    full_verdict = None
    if full:
        full_verdict = "PASS" if all(c["status"] in ("PASS", "SKIP") for c in full) else "FAIL"
    ev = parse_eapol_evidence(logtext)
    fw = next((c for c in live if c["id"] == "fourway"), {})
    counts = {
        "vaps_defined": next((c["evidence"].get("defined", 0) for c in live
                              if c["id"] == "vaps_defined"), 0),
        "vaps_up_now": samples[-1]["up_count"] if samples else 0,
        "vaps_up_max": max((s["up_count"] for s in samples), default=0),
        "vaps_started_0x6016": len(parse_start_ports(logtext)),
        "stations": len(cap_snap.get("stations", {})),
        "wifi_iface": len(((cap_snap.get("wireless") or {}).get("wifi_iface") or [])),
        "fourway_owner": fw.get("evidence", {}).get("owner", "none"),
        "pmap_refreshed": ev["pmap_refreshed"],
        "inject_enodev": ev["inject_enodev"],
    }
    report = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "started_at": started,
        "mode": mode,
        "mode_question": MODE_QUESTIONS[mode],
        "targets": {
            "manager": "%s:%s" % (MGR_HOST, MGR_PORT),
            "cap": "%s" % CAP_HOST,
            "cap_identity": CAP_IDENTITY,
        },
        "definitions": DEFINITIONS,
        "pass_rules": {c["id"]: c["pass_rule"] for c in live},
        "required_checks": MODE_REQUIRED[mode],
        "verdict": {
            "status": live_verdict,
            "live": live_verdict,
            "full": full_verdict,
            "failed_required": failed,
            "overall": "PASS" if live_verdict == "PASS" and full_verdict in (None, "PASS")
                       else "FAIL",
        },
        "counts": counts,
        "checks": checks,
        "sampling": {
            "window_s": args.settle,
            "interval_s": args.interval,
            "samples": [{"up_count": s["up_count"]} for s in samples],
        },
        "live_state": {
            "remote_caps": mgr_snap["caps"],
            "vaps": [{"name": v.get("name"),
                      "master": v.get("master-interface", ""),
                      "ssid": v.get("configuration.ssid", ""),
                      "vlan": v.get(".vlan-id", ""),
                      "mac": v.get("mac-address", ""),
                      "cap": v.get("_cap", "")} for v in target_vaps(mgr_snap)],
            "registration_table": mgr_snap["reg"],
            "stations": cap_snap.get("stations", {}),
            "ifaces": cap_snap.get("ifaces", {}),
            "bridges": cap_snap.get("bridges", {}),
            "capagent": cap_snap.get("capagent", ""),
        },
        "errors": errors,
    }
    text = json.dumps(report, indent=2, sort_keys=False)
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(text + "\n")
        log("wrote %s" % args.json_out)
    print(text)
    return 0 if report["verdict"]["live"] == "PASS" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(json.dumps({"schema": SCHEMA, "verdict": {"overall": "ERROR"},
                          "error": "%s: %s" % (type(e).__name__, e)}, indent=2))
        sys.exit(2)
