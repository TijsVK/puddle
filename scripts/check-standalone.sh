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
patterns='\bT-[0-9]{3}\b|\bD-[0-9]{2,3}\b|\bMWE\b|\bW[1-9]\b|huddle-next|decisions\.md|work/briefs'

# Lock files and generated third-party notices quote other projects' text, not ours. This script
# and its allowlist name the patterns, so they are skipped.
files=$(git ls-files -- . ':!:Cargo.lock' ':!:**/package-lock.json' ':!:**/THIRD-PARTY-NOTICES*' \
    ':!:scripts/check-standalone.sh' ':!:scripts/standalone-allow.txt' ':!:.githooks/commit-msg')

hits=$(
    # shellcheck disable=SC2086 # file names in this repo have no whitespace
    git grep -nI -E "$patterns" -- $files || true
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
