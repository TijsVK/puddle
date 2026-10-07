#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# puddle's unsaved-work check before a workspace is deleted (ADR 0006 point 3).
#
# Usage: sh delete-check.sh <volume mount point>
# Runs as root in the guest. Lists, for every git checkout directly under the volume root,
# uncommitted changes, commits on no remote and stashes; and every other top-level entry (data
# outside a checkout). Skips puddle's own .puddle and ext4's lost+found.
#
# Output, one record per line, tab-separated (puddle-workspace parses it):
#   R <dir>            a checkout; the U/C/S/M lines after it belong to it
#   U <status line>    uncommitted change (git status --porcelain)
#   C <hash subject>   commit not on any remote-tracking branch
#   S <stash line>     stash entry
#   O <name>           other top-level entry
#   M <kind> <count>   <count> more lines of <kind> (U, C, S, O) left out
#   E <dir> <message>  something could not be checked
#   D                  the check ran to the end
# Names have tabs and newlines replaced by '?'. Lines are cut at 500 characters, lists at 200.
set -u

cap=200

emit() {
    awk -v k="$1" -v cap="$cap" '
        NR <= cap { print k "\t" substr($0, 1, 500) }
        END { if (NR > cap) print "M\t" k "\t" (NR - cap) }'
}

clean() {
    printf '%s' "$1" | tr '\t\n' '??' | cut -c1-300
}

# Repo config can't run anything here: fsmonitor off, any owner accepted (the checkout may belong
# to the session user, not root).
g() {
    git -c safe.directory='*' -c core.fsmonitor=false -C "$repo" "$@"
}

fail() {
    printf 'E\t%s\t%s\n' "$1" "$(clean "$2")"
}

# Lists `git <args>` output as kind $1, or an error for checkout $name.
list() {
    kind=$1
    shift
    if out=$(g "$@" 2>&1); then
        if [ -n "$out" ]; then printf '%s\n' "$out" | emit "$kind"; fi
    else
        fail "$name" "git $1 failed: $out"
    fi
}

cd -- "$1" || {
    fail . "cannot enter $1"
    exit 3
}
has_git=1
command -v git >/dev/null 2>&1 || has_git=0
others=0
for d in * .[!.]* ..?*; do
    [ -e "$d" ] || [ -L "$d" ] || continue
    case $d in .puddle | lost+found) continue ;; esac
    name=$(clean "$d")
    if [ -d "$d" ] && [ ! -L "$d" ] && [ -e "$d/.git" ]; then
        printf 'R\t%s\n' "$name"
        if [ "$has_git" = 0 ]; then
            fail "$name" "git is not installed in the image"
            continue
        fi
        repo=$d
        list U status --porcelain=v1 --untracked-files=normal
        if g rev-parse -q --verify HEAD >/dev/null 2>&1; then
            list C log --format='%h %s' HEAD --branches --not --remotes
        else
            list C log --format='%h %s' --branches --not --remotes
        fi
        list S stash list
    else
        others=$((others + 1))
        if [ "$others" -le "$cap" ]; then printf 'O\t%s\n' "$name"; fi
    fi
done
if [ "$others" -gt "$cap" ]; then printf 'M\tO\t%s\n' "$((others - cap))"; fi
printf 'D\n'
