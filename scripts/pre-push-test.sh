#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Self-test of .githooks/pre-push: runs the real hook in a scratch repository whose scripts/check.sh
# is a stub that records it was called. Cases: no pass directory runs the gates; a marker for every
# pushed commit skips them; a marker for only one of two commits, a marker for another commit and a
# deletion-only push all run them. Not seen: the real gates, and git's own stdin format.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/pre-push-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
git init -q "$tmp/repo"
mkdir "$tmp/repo/scripts" "$tmp/pass"
cp "$here/.githooks/pre-push" "$tmp/repo/hook"
printf '#!/bin/sh\necho gates-ran >>"%s/calls"\n' "$tmp" >"$tmp/repo/scripts/check.sh"
chmod +x "$tmp/repo/scripts/check.sh"
zero=0000000000000000000000000000000000000000

# expect <name> <ran|skipped> <pass dir or ""> <stdin lines>
expect() {
    name=$1 want=$2 dir=$3 input=$4
    : >"$tmp/calls"
    if [ -n "$dir" ]; then
        printf '%s\n' "$input" | (cd "$tmp/repo" && PUDDLE_GATE_PASS_DIR=$dir sh ./hook) 2>/dev/null
    else
        printf '%s\n' "$input" | (cd "$tmp/repo" && env -u PUDDLE_GATE_PASS_DIR sh ./hook) 2>/dev/null
    fi
    if [ -s "$tmp/calls" ]; then got=ran; else got=skipped; fi
    [ "$got" = "$want" ] || { echo "pre-push-test: $name: gates $got, wanted $want" >&2; exit 1; }
}

touch "$tmp/pass/aaa.pass"
one="refs/heads/x aaa refs/heads/x $zero"
two="$one
refs/heads/y bbb refs/heads/y $zero"
expect "no pass dir" ran "" "$one"
expect "marker present" skipped "$tmp/pass" "$one"
expect "marker for one of two commits" ran "$tmp/pass" "$two"
expect "marker for another commit" ran "$tmp/pass" "refs/heads/z ccc refs/heads/z $zero"
expect "deletion only" ran "$tmp/pass" "(delete) $zero refs/heads/x aaa"
expect "empty pass dir name" ran "$tmp/missing" "$one"
echo "pre-push-test: ok"
