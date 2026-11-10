#!/bin/sh
# Run the CAP/CAPsMAN v2 regression gate.
#   ./scripts/run-regression.sh --legacy [harness options]
#   ./scripts/run-regression.sh --manager-only [harness options]
set -eu
D=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$D/w42_harness.py" "$@"
