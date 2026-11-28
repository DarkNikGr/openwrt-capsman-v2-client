#!/bin/sh
# Host-only check of the 0xD00B 0x000A descriptor builder.
# Does not load modules, touch a radio or contact the manager.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${TMPDIR:-/tmp}/test_chan_desc.$$
trap 'rm -f "$out"' EXIT INT TERM
${CC:-gcc} -O2 -Wall -Wextra -Werror -o "$out" "$here/test_chan_desc.c"
"$out"
