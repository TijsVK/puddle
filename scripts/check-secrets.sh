#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Secret scanning: gitleaks over the commits being checked, with the rules and the reviewed
# allowlist of fake test values in .gitleaks.toml. The gitleaks version is pinned in
# ci/gitleaks.sha256; install it with ci/fetch-gitleaks.sh <dir-on-PATH>.
# Usage: scripts/check-secrets.sh [--self-test]
#
# Scope (PUDDLE_SECRETS_SCOPE=all|head; unset means all when CI is set, else head):
#   head  HEAD's commits that its base does not have yet, which is what a push adds. The base is
#         $DIFF_BASE if it resolves (the same variable the diff-coverage gate uses), else
#         origin/develop; with neither, all of HEAD's history. A dirty commit on some other
#         local branch (another task's unlanded work) never matters.
#   all   every ref the clone has, gitleaks' own default. CI runs this, so a secret anywhere in
#         the full history, a removed one included, still fails there.
#
# --self-test proves the gate works, on throwaway repositories with the real configuration: a
# real-shaped token fails, a listed fake fixture passes, a real-shaped token in the fixture's
# own file still fails, a canary outside the listed paths fails, and each scope sees exactly the
# commits it should (a dirty side branch fails `all` and passes `head`).
#
# What it can't see: a secret with no recognisable shape (a bare password, a low-entropy value),
# one only in a stash, a file that never reached a commit, and in `head` scope a secret already
# in the base (the full CI scan covers it). A pass is a safety net, not proof.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)

command -v gitleaks >/dev/null 2>&1 || {
    echo "secrets gate needs gitleaks on PATH: ci/fetch-gitleaks.sh <dir on PATH> (docs/STANDARDS.md, \"Toolchain\")" >&2
    exit 1
}
want=$(awk '!/^#/ && NF { print $1; exit }' ci/gitleaks.sha256)
have=$(gitleaks version | tr -d '\r' | sed 's/^v//')
if [ "$have" != "$want" ]; then
    echo "secrets gate: gitleaks $have is on PATH, ci/gitleaks.sha256 pins $want (ci/fetch-gitleaks.sh <dir on PATH>)" >&2
    exit 1
fi

# default_scope <PUDDLE_SECRETS_SCOPE value> <CI value>: the scope to use; a bad value exits 2.
default_scope() {
    case ${1:-} in
    all | head) echo "$1" ;;
    "") if [ -n "${2:-}" ]; then echo all; else echo head; fi ;;
    *)
        echo "secrets gate: PUDDLE_SECRETS_SCOPE must be all or head, not '$1'" >&2
        exit 2
        ;;
    esac
}

# log_opts <repo dir> <scope> <diff base>: the `git log` arguments that select the commits to
# scan, empty for all refs. No spaces inside an argument: gitleaks splits the string on them.
log_opts() {
    [ "$2" = head ] || return 0
    base=
    if [ -n "${3:-}" ] && git -C "$1" cat-file -e "$3^{commit}" 2>/dev/null; then
        base=$3
    elif git -C "$1" rev-parse --verify -q origin/develop >/dev/null; then
        base=origin/develop
    fi
    if [ -n "$base" ]; then
        echo "--full-history $base..HEAD"
    else
        echo "--full-history HEAD"
    fi
}

scan() { # <repo dir> <scope> <diff base>: exit 1 when gitleaks reports a finding (it prints each one, secret redacted)
    opts=$(log_opts "$1" "$2" "${3:-}")
    gitleaks git --no-banner --verbose --redact --no-color --exit-code 1 --config "$root/.gitleaks.toml" ${opts:+"--log-opts=$opts"} "$1"
}

if [ "${1:-}" != "--self-test" ]; then
    scope=$(default_scope "${PUDDLE_SECRETS_SCOPE:-}" "${CI:-}")
    if [ "$scope" = head ]; then
        echo "secrets: scanning HEAD's commits that ${DIFF_BASE:-origin/develop} lacks, not other branches (PUDDLE_SECRETS_SCOPE=all scans every ref, as CI does)" >&2
    fi
    scan . "$scope" "${DIFF_BASE:-}"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
# commit_file <repo> <path> <line>: commit one file holding that line in the repo (named, under $tmp).
commit_file() {
    mkdir -p "$tmp/$1/$(dirname "$2")"
    printf '%s\n' "$3" >"$tmp/$1/$2"
    git -C "$tmp/$1" add -A
    git -C "$tmp/$1" -c user.name=t -c user.email=t@example.test -c commit.gpgsign=false commit -q -m fixture
}
# A repo with one commit holding $3 (a line) at path $2 (the repo is named $1).
make_repo() {
    git init -q "$tmp/$1"
    commit_file "$1" "$2" "$3"
}
# check <pass|fail> <label> <repo> <scope> [<diff base>]: scan the repo and compare the verdict.
check() {
    # Exit 1 is "a finding"; any other failure (bad config, crash) is neither pass nor fail.
    rc=0
    scan "$tmp/$3" "$4" "${5:-}" >/dev/null 2>&1 || rc=$?
    case $rc in 0) got=pass ;; 1) got=fail ;; *) got="error (exit $rc)" ;; esac
    if [ "$got" = "$1" ]; then
        echo "self-test ok: $2 ($got)"
    else
        echo "self-test FAILED: $2 should $1, got $got" >&2
        fail=1
    fi
}
# expect <pass|fail> <name> <path> <line>: scan a repo of that one file.
expect() {
    make_repo "$2" "$3" "$4"
    check "$1" "$2" "$2" all
}
# same <label> <want> <got>: a plain comparison.
same() {
    if [ "$2" = "$3" ]; then
        echo "self-test ok: $1 ($3)"
    else
        echo "self-test FAILED: $1 should be $2, got $3" >&2
        fail=1
    fi
}
# Built from pieces so this file never holds a token-shaped string itself.
token="gh""p_R7qL2xVn9TzK4mWb8YcD3sFh6JgA0eUoPi5N"
expect fail real-token src/app.rs "const T: &str = \"$token\";"
expect pass listed-canary crates/puddle-proxy/tests/route.rs '    .request("GET http://web.test/a?token=CANARY-route-1 HTTP/1.1")'
expect pass listed-docker-auth crates/puddle-boot/tests/vm_boot.rs 'json!({"registry.example.test": {"auth": "dXNlcjpwdWRkbGU="}});'
expect fail token-in-listed-file crates/puddle-proxy/tests/route.rs "let t = \"$token\";"
expect fail canary-outside-listed-paths src/lib.rs '    password: "CANARY-s3cret".into(),'

# Scope. A repo whose base (origin/develop) is clean, with a dirty commit on a side branch.
make_repo side README.md 'clean base'
git -C "$tmp/side" update-ref refs/remotes/origin/develop HEAD
git -C "$tmp/side" checkout -q -b dirty
commit_file side src/app.rs "const T: &str = \"$token\";"
git -C "$tmp/side" checkout -q -
commit_file side src/lib.rs '// clean'
check pass side-branch-dirty-head-clean-scope-head side head
check fail side-branch-dirty-scope-all side all
git -C "$tmp/side" checkout -q dirty
check fail dirty-commit-in-heads-range side head
commit_file side src/app.rs '// the token is gone'
check fail removed-token-still-in-heads-range side head
base=$(git -C "$tmp/side" rev-parse HEAD)
commit_file side src/lib.rs '// clean again'
check pass diff-base-after-the-dirty-commit side head "$base"
check fail no-diff-base-uses-origin-develop side head
check fail unknown-diff-base-uses-origin-develop side head 0000000000000000000000000000000000000001
git -C "$tmp/side" update-ref refs/remotes/origin/develop HEAD
check pass dirty-commit-already-on-the-base side head
check fail dirty-commit-already-on-the-base-scope-all side all
# No origin/develop to subtract: all of HEAD's history, still nothing from other branches.
git init -q "$tmp/nobase"
commit_file nobase README.md 'clean'
git -C "$tmp/nobase" checkout -q -b dirty
commit_file nobase src/app.rs "const T: &str = \"$token\";"
git -C "$tmp/nobase" checkout -q -
commit_file nobase src/lib.rs '// clean'
check pass no-base-side-branch-dirty nobase head
git -C "$tmp/nobase" -c user.name=t -c user.email=t@example.test -c commit.gpgsign=false merge -q --no-edit dirty
check fail no-base-dirty-commit-in-history nobase head
same scope-ci-default all "$(default_scope '' true)"
same scope-local-default head "$(default_scope '' '')"
same scope-explicit-wins head "$(default_scope head true)"
exit "$fail"
