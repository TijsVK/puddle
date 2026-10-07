#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# This repo must read as a standalone project: nothing in a tracked file may point into a private
# planning workspace (task and decision IDs, plan package names, workspace paths, "laptop" for a
# developer's own machine; CONTRIBUTING.md). Say the reason in words, or cite an ADR
# or spec section.
#
# Allowlist: scripts/standalone-allow.txt, one entry per line, `<path><TAB><fixed substring>`;
# a hit is ignored when its line contains the substring. Keep it short, and only for real false
# positives (a hash, a third-party name), never for a reference to the workspace.
set -eu
cd "$(dirname "$0")/.."

allow=scripts/standalone-allow.txt

# Two pattern sets (ERE). `ids` is matched case-insensitively, `exact` is case-sensitive.
# `B`/`E` stand in for word boundaries, because `_` and `-` count as separators in names like
# `puddle-t165-lab` or `d37_name` (grep's \b would treat `_` as part of the word).
#   ids:   T-<n> and D-<n> with any number of digits, W-<n>, a bare t<3-4 digits> (t165,
#          PUDDLE_T144_X), and a d<2-3 digits>_ test-name prefix (d37_toggle).
#   exact: MWE, W1..W9, workspace names and files.
# Not seen: an ID spelled out ("task 165"), one split by punctuation, a bare t/d number with other
# digit counts (t42, d4; they collide with timers and NTLM "T1"/"T3"), or any reference that is
# worded rather than numbered. Those need the read-through review, not this gate.
B='(^|[^A-Za-z0-9])'
E='([^A-Za-z0-9]|$)'
ids="${B}(([TDW]-[0-9]+|T[0-9]{3,4})${E}|D[0-9]{2,3}_)"
exact='\bMWE\b|\bW[1-9]\b|huddle-next|decisions\.md|work/briefs'

# `--self-test` checks the patterns against lines they must catch and lines they must pass.
if [ "${1:-}" = "--self-test" ]; then
    fail=0
    must_catch='(D-1)
D-12 and T-7
see T-123.
x-T-9-y
puddle-t165-lab
format!("t108-{tag}")
PUDDLE_T144_DUMP_ENV
fn d37_toggle_on()
until_t093
W-4
the MWE
tier W1
huddle-next/work
decisions.md'
    must_pass='NTLM T1 then NTLM T3
let t0 = Instant::now();
caller=T42;Memory
domains d0..d49 of
/workspaces/w1
SHA-256 and UTF-8 and X-1
abcT-1 xD-2
ed25519 aes-128
d1 d2 d4
#d37 colour
a W10 b'
    while IFS= read -r l; do
        printf '%s\n' "$l" | grep -qiE -e "$ids" || printf '%s\n' "$l" | grep -qE -e "$exact" || {
            echo "self-test: should have caught: $l" >&2
            fail=1
        }
    done <<EOF
$must_catch
EOF
    while IFS= read -r l; do
        if printf '%s\n' "$l" | grep -qiE -e "$ids" || printf '%s\n' "$l" | grep -qE -e "$exact"; then
            echo "self-test: should have passed: $l" >&2
            fail=1
        fi
    done <<EOF
$must_pass
EOF
    [ "$fail" -eq 0 ] || exit 1
    echo "standalone self-test ok"
    exit 0
fi

# Lock files and generated third-party notices quote other projects' text, not ours. This script
# and its allowlist name the patterns, so they are skipped.
files=$(git ls-files -- . ':!:Cargo.lock' ':!:**/package-lock.json' ':!:**/THIRD-PARTY-NOTICES*' \
    ':!:scripts/check-standalone.sh' ':!:scripts/standalone-allow.txt' ':!:.githooks/commit-msg')

hits=$(
    # shellcheck disable=SC2086 # file names in this repo have no whitespace
    git grep -nI -E "$exact" -- $files || true
    # shellcheck disable=SC2086
    git grep -nIiE "$ids" -- $files || true
    # shellcheck disable=SC2086
    git grep -nIi -e laptop -- $files || true
)

hits=$(printf '%s\n' "$hits" | sort -u | sed '/^$/d')

if [ -n "$hits" ] && [ -f "$allow" ]; then
    hits=$(printf '%s\n' "$hits" | while IFS= read -r line; do
        path=${line%%:*}
        skip=
        while IFS="$(printf '\t')" read -r apath asub; do
            case "$apath" in '' | '#'*) continue ;; esac
            if [ "$apath" = "$path" ]; then
                case "$line" in *"$asub"*) skip=1 ;; esac
            fi
        done <"$allow"
        [ -n "$skip" ] || printf '%s\n' "$line"
    done)
fi

if [ -n "$hits" ]; then
    printf '%s\n' "$hits" >&2
    echo "standalone: the lines above refer to a private planning workspace; reword them (see scripts/check-standalone.sh)" >&2
    exit 1
fi
echo "standalone ok"
