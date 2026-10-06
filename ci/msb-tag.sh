#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Prints the msb fork tag puddle is built against (e.g. v0.7.7-puddle.6), read from the msb SDK's
# source in Cargo.lock. The root Cargo.toml's `tag =` on the SDK lines is the only place the
# version is written; puddle-runtime's build script reads the same entry (BUILT_FOR).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tag=$(awk '
    $0 == "name = \"microsandbox\"" { sdk = 1; next }
    sdk && /^source = / {
        if (match($0, /\?tag=v[^#"]+/)) print substr($0, RSTART + 5, RLENGTH - 5)
        exit
    }
    /^\[\[package\]\]/ { sdk = 0 }
' "$here/../Cargo.lock")
[ -n "$tag" ] || { echo "msb-tag: no msb SDK fork tag in Cargo.lock" >&2; exit 1; }
echo "$tag"
