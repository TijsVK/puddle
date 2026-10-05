#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Every tracked source file must carry an SPDX licence identifier in its first two lines (the
# second allows for a shebang). Generated files, lock files and documents are exempt
# (CONTRIBUTING.md, "Licence headers").
set -eu
cd "$(dirname "$0")/.."

missing=0
for f in $(git ls-files -- '*.rs' '*.toml' '*.sh' '*.ps1' '*.yml' '*.yaml' '*.ts' '*.js' \
    '*.svelte' '*.html' '*.css' '.githooks/*' '.config/*'); do
    [ -f "$f" ] || continue
    if ! head -n 2 "$f" | grep -q 'SPDX-License-Identifier:'; then
        echo "missing SPDX header: $f" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] && echo "SPDX headers ok"
exit "$missing"
