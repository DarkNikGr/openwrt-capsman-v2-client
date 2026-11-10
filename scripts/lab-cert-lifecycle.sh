#!/bin/sh
# Certificate lifecycle regression test against a disposable RouterOS 7.25.1
# CHR (CAPsMAN v2).  See docs/OPEN-PROBLEMS.md for the lab setup; the manager
# must be reachable over SSH with password auth and have CAPsMAN available.
#
#   LAB_DIR=/path/to/lab CAPAGENT=/path/to/capagent ./scripts/lab-cert-lifecycle.sh
#
# LAB_DIR must contain ssh-chr.sh (prints the CHR command over SSH) and the
# host ports must forward CAPsMAN (PORT..PORT+9).  The script enables CAPsMAN,
# sets require-peer-certificate=no and rotates the CA when needed.
set -u
D=$(cd "$(dirname "$0")" && pwd)
W=$(dirname "$D")
LAB=${LAB_DIR:-$W/lab}
BIN=${CAPAGENT:-$W/native/capagent-mipsel}
SSH="$LAB/ssh-chr.sh"
PORT=${PORT:-28100}
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/w43-lifecycle.XXXXXX")
PASS=0; FAIL=0
say() { printf '%s\n' "$*"; }
ok()  { PASS=$((PASS+1)); say "PASS  $*"; }
bad() { FAIL=$((FAIL+1)); say "FAIL  $*"; }
run() { # run <dir> <port> <seconds> <log> [extra args...]
    dir=$1; port=$2; secs=$3; log=$4; shift 4
    timeout "$secs" "$BIN" --manager 127.0.0.1 --port "$port" \
        --macs "02:00:00:00:00:0$((port % 8 + 1))" --identity W43-LAB \
        --cert "$dir/client.pem" --key "$dir/client.key" \
        --ca-cert "$dir/ca.pem" "$@" > "$log" 2>&1
}
has() { grep -q "$1" "$2"; }
cn_of() { sed -n 's/.*enrolled CN=\([^ ]*\).*/\1/p' "$1" | tail -n1; }

$SSH '/interface wifi capsman set enabled=yes; /interface wifi capsman set require-peer-certificate=no' >/dev/null
[ -f "$ROOT/keep.pem" ] || true

say "== 1. empty /etc/cap: first-boot enrolment =="
mkdir -p "$ROOT/fresh"
run "$ROOT/fresh" $((PORT+1)) 25 "$ROOT/fresh.log"
CN1=$(cn_of "$ROOT/fresh.log")
if has 'cert: no usable key/certificate; enrolling' "$ROOT/fresh.log" &&
   has "cert: enrolled CN=$CN1" "$ROOT/fresh.log" &&
   [ -s "$ROOT/fresh/client.pem" ] && [ -s "$ROOT/fresh/client.key" ] &&
   [ -s "$ROOT/fresh/ca.pem" ]; then
    ok "empty dir enrolled CN=$CN1"
else bad "empty dir enrolment"; fi
[ "$(stat -c %a "$ROOT/fresh/client.key")" = 600 ] && ok "client.key mode 0600" || bad "client.key mode"

say "== 2. re-join with the stored certificate (mTLS + CA pinning) =="
run "$ROOT/fresh" $((PORT+2)) 15 "$ROOT/rejoin.log"
if has "cert: using stored certificate CN=$CN1" "$ROOT/rejoin.log" &&
   has 'joined TLS' "$ROOT/rejoin.log" &&
   has 'RX 0xc029 joinresp' "$ROOT/rejoin.log" &&
   ! has 'cert: enrolling' "$ROOT/rejoin.log"; then
    ok "re-join with stored certificate, no CSR"
else bad "stored-certificate re-join"; fi

say "== 3. factory reset (empty dir again) gets a fresh CN =="
mkdir -p "$ROOT/reset"
run "$ROOT/reset" $((PORT+3)) 25 "$ROOT/reset.log"
CN2=$(cn_of "$ROOT/reset.log")
if has "cert: enrolled CN=$CN2" "$ROOT/reset.log" && [ "$CN1" != "$CN2" ]; then
    ok "factory reset enrolled with fresh CN=$CN2 (was $CN1)"
else bad "factory reset fresh CN"; fi

say "== 4. expired stored certificate is replaced =="
mkdir -p "$ROOT/expired"
python3 - "$ROOT/expired" <<'PY'
import sys, datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
d = sys.argv[1]
k = ec.generate_private_key(ec.SECP256R1())
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "W43-EXPIRED")])
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
     .public_key(k.public_key()).serial_number(1)
     .not_valid_before(datetime.datetime(2020, 1, 1))
     .not_valid_after(datetime.datetime(2021, 1, 1)).sign(k, hashes.SHA256()))
open(d + "/client.pem", "wb").write(c.public_bytes(serialization.Encoding.PEM))
open(d + "/client.key", "wb").write(k.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
PY
chmod 600 "$ROOT/expired/client.key"
run "$ROOT/expired" $((PORT+4)) 25 "$ROOT/expired.log"
CN3=$(cn_of "$ROOT/expired.log")
if has 'cert: stored certificate is expired; re-enrolling' "$ROOT/expired.log" &&
   has "cert: enrolled CN=$CN3" "$ROOT/expired.log"; then
    ok "expired certificate replaced by CN=$CN3"
else bad "expired certificate re-enrolment"; fi

say "== 5. duplicate CN: retry with a fresh CN =="
mkdir -p "$ROOT/dup"
run "$ROOT/dup" $((PORT+5)) 30 "$ROOT/dup.log" --cert-cn "$CN3"
if has 'cert: join failed: code=2' "$ROOT/dup.log" &&
   has 'duplicate CN' "$ROOT/dup.log" &&
   has 'retrying with a random suffix' "$ROOT/dup.log" &&
   has 'cert: enrolled CN=' "$ROOT/dup.log"; then
    ok "duplicate CN detected, re-enrolled with a suffixed CN"
else bad "duplicate CN recovery"; fi

say "== 6. manager CA rotation is detected and recovered =="
cp "$ROOT/fresh/ca.pem" "$ROOT/old-ca.pem"
$SSH '/interface wifi capsman set enabled=no' >/dev/null
$SSH ':foreach i in=[/certificate find where !authority] do={/certificate remove $i}' >/dev/null 2>&1
$SSH ':foreach i in=[/certificate find] do={/certificate remove $i}' >/dev/null 2>&1
$SSH '/interface wifi capsman set enabled=yes' >/dev/null
sleep 2
run "$ROOT/fresh" $((PORT+6)) 30 "$ROOT/rotate.log"
if has 'manager CA changed, re-enrolling' "$ROOT/rotate.log" &&
   has 'cert: enrolled CN=' "$ROOT/rotate.log"; then
    ok "CA rotation -> automatic re-enrolment"
else bad "CA rotation recovery"; fi
run "$ROOT/fresh" $((PORT+7)) 15 "$ROOT/after-rotate.log"
if has 'cert: using stored certificate' "$ROOT/after-rotate.log" &&
   has 'joined TLS' "$ROOT/after-rotate.log"; then
    ok "steady-state join against the new CA"
else bad "post-rotation steady state"; fi

say "== 7. require-peer-certificate=yes: actionable failure, no crash loop =="
mkdir -p "$ROOT/strict"
$SSH '/interface wifi capsman set require-peer-certificate=yes' >/dev/null
run "$ROOT/strict" $((PORT+8)) 20 "$ROOT/strict.log"
$SSH '/interface wifi capsman set require-peer-certificate=no' >/dev/null
if has 'require-peer-certificate=yes blocks it' "$ROOT/strict.log" &&
   has 'reconnect in 5s (certificate failures: 1)' "$ROOT/strict.log" &&
   has 'reconnect in 10s (certificate failures: 2)' "$ROOT/strict.log" &&
   [ ! -s "$ROOT/strict/client.pem" ]; then
    ok "strict manager gives a bounded, actionable retry loop"
else bad "strict manager handling"; fi

say "== 8. pre-provisioned certificate, no ca.pem (current device layout) =="
mkdir -p "$ROOT/preprov"
cp "$ROOT/fresh/client.pem" "$ROOT/preprov/client.pem"
cp "$ROOT/fresh/client.key" "$ROOT/preprov/client.key"
chmod 600 "$ROOT/preprov/client.key"
CPN=$(openssl x509 -in "$ROOT/preprov/client.pem" -noout -subject |
      sed 's/^subject=//')
timeout 15 "$BIN" --manager 127.0.0.1 --port $((PORT+9)) \
    --macs 02:00:00:00:00:09 --identity W43-PREPROV \
    --cert "$ROOT/preprov/client.pem" --key "$ROOT/preprov/client.key" \
    --dont-verify-certificate > "$ROOT/preprov.log" 2>&1
if has "cert: using stored certificate $CPN" "$ROOT/preprov.log" &&
   has 'joined TLS' "$ROOT/preprov.log" &&
   ! has 'cert: enrolling' "$ROOT/preprov.log"; then
    ok "pre-provisioned certificate used without CA pinning"
else bad "pre-provisioned path"; fi

say ""
say "RESULT PASS=$PASS FAIL=$FAIL  work=$ROOT"
[ "$FAIL" -eq 0 ]
