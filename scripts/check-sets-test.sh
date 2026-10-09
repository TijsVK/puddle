#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Self-test of the gate sets in scripts/check.sh, through `--list` (which runs no gate): `all` is
# every gate, `pre-push` is `all` minus ui-e2e in the same order, `fast` is a prefix of both, a
# single gate is its own set, and the pre-push hook asks for the `pre-push` set. Not seen: that a
# listed gate runs (each gate has its own CI step), and that CI's workflow file names every gate.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
check="$here/scripts/check.sh"
fail() {
    echo "check-sets-test: $*" >&2
    exit 1
}

all=$("$check" --list all)
pre_push=$("$check" --list pre-push)
fast=$("$check" --list fast)

printf '%s\n' "$all" | grep -qx ui-e2e || fail "all lacks ui-e2e"
printf '%s\n' "$pre_push" | grep -qx ui-e2e && fail "pre-push runs ui-e2e"
[ "$(printf '%s\n' "$all" | grep -vx ui-e2e)" = "$pre_push" ] || fail "pre-push is not all minus ui-e2e, in order"
[ "$(printf '%s\n' "$all" | sort | uniq -d)" = "" ] || fail "all repeats a gate"
[ "$(printf '%s\n' "$all" | head -n "$(printf '%s\n' "$fast" | wc -l)")" = "$fast" ] || fail "fast is not the start of all"
printf '%s\n' "$pre_push" | grep -qx coverage || fail "pre-push lacks coverage"
printf '%s\n' "$pre_push" | grep -qx ui || fail "pre-push lacks ui (its coverage and thresholds)"
[ "$("$check" --list clippy)" = clippy ] || fail "a single gate is not its own set"
[ "$("$check" --list fast ui-e2e)" = "$(printf '%s\nui-e2e' "$fast")" ] || fail "sets and gates do not combine"
"$check" --list 2>/dev/null && fail "--list without a set succeeded"
grep -q 'check.sh" pre-push$' "$here/.githooks/pre-push" || fail "the pre-push hook does not run the pre-push set"
echo "check-sets-test: ok"
