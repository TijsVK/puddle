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
# The scheduler's streams: every gate of `all` has one, and a gate that waits for another is in a
# different stream (the same stream would wait on itself) or comes after it.
# shellcheck source=scripts/gate-sched.sh
. "$here/scripts/gate-sched.sh"
for g in $all; do
    case $(gate_stream "$g") in rust | node | misc) ;; *) fail "gate $g has no stream" ;; esac
    need=$(gate_needs "$g")
    [ -z "$need" ] || printf '%s\n' "$all" | grep -qx "$need" || fail "$g needs $need, which is not a gate of all"
    [ -z "$need" ] || [ "$(gate_stream "$need")" != "$(gate_stream "$g")" ] ||
        [ "$(printf '%s\n' "$all" | grep -nx "$need" | cut -d: -f1)" -lt "$(printf '%s\n' "$all" | grep -nx "$g" | cut -d: -f1)" ] ||
        fail "$g waits for $need later in its own stream"
done
# The fast gates run first and alone, so none of them may need a stream (they are the serial prefix).
echo "check-sets-test: ok"
