#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Self-test of .githooks/pre-push: runs the real hook in a scratch repository whose scripts/check.sh
# is a stub that records it was called. Cases: no pass directory runs the gates; a marker for every
# pushed commit skips them; a marker for only one of two commits, a marker for another commit and a
# deletion-only push all run them. Not seen: the real gates, and git's own stdin format.
set -eu
# Run from a git hook (pre-commit, pre-push), git exports GIT_DIR, GIT_INDEX_FILE and friends; with
# them set, the `git init` below would re-initialise the calling repository, not the scratch one.
# shellcheck disable=SC2046 # the list is words by design
unset $(git rev-parse --local-env-vars)
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
# Regression: a hook in a linked worktree exports that worktree's GIT_DIR and GIT_INDEX_FILE; with
# them set, the repository behind the worktree must come out of this script unchanged (git init
# there flips its core.bare to true).
if [ -z "${PRE_PUSH_TEST_NESTED:-}" ]; then
    git init -q "$tmp/main"
    git -C "$tmp/main" -c user.email=t@example.org -c user.name=t commit -q --allow-empty -m init
    git -C "$tmp/main" worktree add -q "$tmp/linked"
    gitdir=$(git -C "$tmp/linked" rev-parse --absolute-git-dir)
    before=$(git -C "$tmp/main" config core.bare)
    GIT_DIR=$gitdir GIT_INDEX_FILE=$gitdir/index PRE_PUSH_TEST_NESTED=1 sh "$0" >/dev/null
    [ "$before" = "$(git -C "$tmp/main" config core.bare)" ] || {
        echo "pre-push-test: hook variables reached the scratch repository setup" >&2
        exit 1
    }
fi
echo "pre-push-test: ok"
