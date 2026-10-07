#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Removes stale git lock files after a crash or hard kill.
#
# Usage: sh clear-locks.sh <volume mount point> [proc dir, default /proc]
# Runs as root in the guest after a boot. A VMM kill leaves `*.lock` files (index.lock, HEAD.lock,
# refs/**.lock, packed-refs.lock, ...) in checkouts, and git then says "Another git process seems
# to be running". A lock is stale only if no git process runs, so nothing is removed while any
# process is named `git` or `git-*` (checked in the proc dir, one `comm` file per process).
#
# Only regular files named *.lock inside the .git directory of a checkout directly under the
# volume root are removed; a `.git` that is a symlink or a file is skipped, and find never
# follows symlinks. Other files in the checkout are never touched.
#
# Output, one record per line, tab-separated (puddle-workspace parses it):
#   B                  a git process runs: nothing was removed
#   L <path>           a lock file that was removed (relative to the volume root)
#   E <dir> <message>  something could not be done
#   D                  the run reached the end
# Names have tabs and newlines replaced by '?'.
set -u

proc=${2:-/proc}

fail() {
    printf 'E\t%s\t%s\n' "$1" "$2"
}

cd -- "$1" || {
    fail . "cannot enter $1"
    exit 3
}

for comm in "$proc"/[0-9]*/comm; do
    [ -r "$comm" ] || continue
    name=
    read -r name <"$comm" 2>/dev/null || true
    case $name in
        git | git-*)
            printf 'B\nD\n'
            exit 0
            ;;
    esac
done

for d in * .[!.]* ..?*; do
    case $d in .puddle | lost+found) continue ;; esac
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    [ -d "$d/.git" ] && [ ! -L "$d/.git" ] || continue
    find "$d/.git" -type f -name '*.lock' -exec sh -c '
        for f; do
            if rm -f -- "$f"; then
                printf "L\t%s\n" "$(printf %s "$f" | tr "\t\n" "??")"
            else
                printf "E\t%s\t%s\n" "$(printf %s "$f" | tr "\t\n" "??")" "cannot remove"
            fi
        done' sh {} + || fail "$(printf %s "$d" | tr '\t\n' '??')" "find failed"
done
printf 'D\n'
