#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Secret scanning: gitleaks over every commit reachable from HEAD (all history, so a secret
# removed in a later commit still fails), with the rules and the reviewed allowlist of fake
# test values in .gitleaks.toml. The gitleaks version is pinned in ci/gitleaks.sha256; install it
# with ci/fetch-gitleaks.sh <dir-on-PATH>. Usage: scripts/check-secrets.sh [--self-test]
#
# --self-test proves the gate works, on throwaway repositories with the real configuration: a
# real-shaped token fails, a listed fake fixture passes, a real-shaped token in the fixture's
# own file still fails, and a canary outside the listed paths fails.
#
# What it can't see: a secret with no recognisable shape (a bare password, a low-entropy value),
# one only in a stash, a branch gitleaks is not given, or a file that never reached a commit.
# A pass is a safety net, not proof.
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

scan() { # <repo dir>: exit 1 when gitleaks reports a finding (it prints each one, secret redacted)
    gitleaks git --no-banner --redact --no-color --exit-code 1 --config "$root/.gitleaks.toml" "$1"
}

if [ "${1:-}" != "--self-test" ]; then
    scan .
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
# A repo with one commit holding $3 (a line) at path $2 (the repo is named $1).
make_repo() {
    git init -q "$tmp/$1"
    mkdir -p "$tmp/$1/$(dirname "$2")"
    printf '%s\n' "$3" >"$tmp/$1/$2"
    git -C "$tmp/$1" add -A
    git -C "$tmp/$1" -c user.name=t -c user.email=t@example.test -c commit.gpgsign=false commit -q -m fixture
}
# expect <pass|fail> <name> <path> <line>: scan a repo of that one file.
expect() {
    make_repo "$2" "$3" "$4"
    # Exit 1 is "a finding"; any other failure (bad config, crash) is neither pass nor fail.
    rc=0
    scan "$tmp/$2" >/dev/null 2>&1 || rc=$?
    case $rc in 0) got=pass ;; 1) got=fail ;; *) got="error (exit $rc)" ;; esac
    if [ "$got" = "$1" ]; then
        echo "self-test ok: $2 ($got)"
    else
        echo "self-test FAILED: $2 should $1, got $got" >&2
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
exit "$fail"
