#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Runs a list of quality gates, the independent ones at the same time. Sourced by scripts/check.sh
# and scripts/check-sets-test.sh (which stubs the gates); the caller defines
#   run_gate <gate>     runs one gate; its exit status is the verdict
#   before_concurrent <gate>...   one-time setup before the streams start (npm ci)
# and may set `serial_gates`, the gates that run first, one at a time, stopping at the first failure.
#
# Streams (gate_stream): `rust` (compiles and tests; one cargo target dir, so these queue on its lock
# anyway), `node` (the UI chain; no cargo until ui-e2e starts its fixture) and `misc` (secrets, deny,
# notices: read-only scans). A gate that needs another gate's output waits for it (gate_needs):
# coverage runs the tests against the UI that `ui` builds. Gates keep their order within a stream; a
# failed gate stops its stream (as `set -e` stopped the old serial run) but not the others, so the
# first failure is reported with the whole picture and a retry of "the gates after it" covers all.
#
# Output: with one stream, or PUDDLE_CHECK_SERIAL=1, the gates run inline and print as they go. With
# several, each gate's output is kept and printed whole, under its own `==> <gate>` line, when the
# gate finishes, followed by `-- <gate>: ok, N s`. A failed gate prints `-- <gate>: FAILED` at once
# and its whole log at the end, in reverse run order, so the earliest failure in run order is the
# last `==> ` line, as it was when the run stopped there. The exit status is that gate's.
# On INT, TERM or HUP it stops every stream and all that they started (a process tree walk with ps).

# shellcheck disable=SC2086 # the gate lists are space-separated names by design

# The stream a gate belongs to.
gate_stream() {
    case $1 in
    ui | ui-licences | ui-audit | ui-e2e) echo node ;;
    secrets | deny | notices) echo misc ;;
    *) echo rust ;;
    esac
}

# The gate whose output a gate reads, if any (waited for when both are in the run).
gate_needs() {
    case $1 in
    coverage | coverage-ratchet) echo ui ;;
    esac
}

# True when $1 is one of the words after it.
gate_in() {
    word=$1
    shift
    case " $* " in *" $word "*) return 0 ;; esac
    return 1
}

# Writes a gate's result atomically: "<exit status | skipped> <seconds> <reason>".
gate_record() {
    printf '%s %s %s\n' "$2" "$3" "${4:-}" >"$run_tmp/$1.rc.part"
    mv "$run_tmp/$1.rc.part" "$run_tmp/$1.rc"
}

# One stream, in a background subshell: gate_stream_run <stream> <gate>...
gate_stream_run() {
    own=$1
    shift
    stopped=
    for g in "$@"; do
        if [ -n "$stopped" ]; then
            gate_record "$g" skipped 0 "$stopped"
            continue
        fi
        need=$(gate_needs "$g")
        if [ -n "$need" ] && gate_in "$need" $gate_all && [ "$(gate_stream "$need")" != "$own" ]; then
            while [ ! -e "$run_tmp/$need.rc" ]; do sleep 1; done
            read -r status _ <"$run_tmp/$need.rc"
            if [ "$status" != 0 ]; then
                gate_record "$g" skipped 0 "needs $need, which did not pass"
                continue
            fi
        fi
        start=$(date +%s)
        # In the background, so `set -e` stays on inside the gate (a `|| rc=$?` would switch it off).
        (run_gate "$g") >"$run_tmp/$g.log" 2>&1 &
        rc=0
        wait "$!" || rc=$?
        gate_record "$g" "$rc" $(($(date +%s) - start))
        [ "$rc" = 0 ] || stopped="an earlier gate of this stream failed ($g)"
    done
}

# Prints the pids of every descendant of the pids in $1. A background job of a non-interactive shell
# ignores SIGINT, and so do the tools it starts, so Ctrl-C reaches only this script: it has to stop
# the gates itself, and a plain kill of the stream shells would leave cargo and node running.
gate_descendants() {
    ps -A -o pid= -o ppid= 2>/dev/null | awk -v roots="$1" '
        { pid[NR] = $1; par[NR] = $2 }
        END {
            n = split(roots, r, " ")
            for (i = 1; i <= n; i++) known[r[i]] = 1
            do {
                grew = 0
                for (i = 1; i <= NR; i++)
                    if ((par[i] in known) && !(pid[i] in known)) { known[pid[i]] = 1; grew = 1; print pid[i] }
            } while (grew)
        }'
}

# Stops the streams and everything they started, and removes the logs (the one place the run's
# temporary directory goes).
gate_cleanup() {
    if [ -n "$gate_pids" ]; then
        victims="$(gate_descendants "$gate_pids") $gate_pids"
        # shellcheck disable=SC2086 # a list of pids
        kill -TERM $victims 2>/dev/null || true
    fi
    gate_pids=
    rm -rf "$run_tmp"
    run_tmp=
}

# Prints a finished gate's result in the parent. Sets gate_failed_list / gate_first_rc bookkeeping.
gate_report() {
    read -r status secs reason <"$run_tmp/$1.rc"
    gate_sum=$((gate_sum + secs))
    case $status in
    0)
        cat "$run_tmp/$1.log"
        echo "-- $1: ok, $secs s"
        ;;
    skipped) echo "-- $1: skipped ($reason)" ;;
    *)
        echo "-- $1: FAILED (exit $status) after $secs s; its log follows at the end"
        gate_failed="$gate_failed $1"
        ;;
    esac
}

run_gates() {
    gate_all=
    for g; do gate_in "$g" $gate_all || gate_all="$gate_all $g"; done
    # The serial prefix: leading gates named in $serial_gates.
    rest=
    for g in $gate_all; do
        if [ -z "$rest" ] && gate_in "$g" ${serial_gates:-}; then
            run_gate "$g"
        else
            rest="$rest $g"
        fi
    done
    gate_all=$rest
    rust_list='' node_list='' misc_list='' streams=0
    for g in $rest; do
        case $(gate_stream "$g") in
        rust) rust_list="$rust_list $g" ;;
        node) node_list="$node_list $g" ;;
        misc) misc_list="$misc_list $g" ;;
        esac
    done
    for l in "$rust_list" "$node_list" "$misc_list"; do
        [ -z "$l" ] || streams=$((streams + 1))
    done
    if [ -n "${PUDDLE_CHECK_SERIAL:-}" ] || [ "$streams" -lt 2 ]; then
        for g in $rest; do run_gate "$g"; done
        return 0
    fi

    run_tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-gates.XXXXXX")
    gate_pids=
    trap 'gate_cleanup; exit 130' INT
    trap 'gate_cleanup; exit 143' TERM HUP
    before_concurrent $rest
    wall_start=$(date +%s)
    for s in rust node misc; do
        eval "l=\$${s}_list"
        [ -n "$l" ] || continue
        echo "check: stream $s:$l" >&2
        # shellcheck disable=SC2086 # $l is a list of gate names
        gate_stream_run "$s" $l &
        gate_pids="$gate_pids $!"
    done
    echo "check: each gate's output is printed whole when it finishes (PUDDLE_CHECK_SERIAL=1 runs them one by one)" >&2

    gate_failed='' gate_sum=0 remaining=$rest
    while [ -n "$remaining" ]; do
        still=
        for g in $remaining; do
            if [ -e "$run_tmp/$g.rc" ]; then gate_report "$g"; else still="$still $g"; fi
        done
        remaining=$still
        [ -z "$remaining" ] || sleep 1
    done
    for p in $gate_pids; do wait "$p" || true; done
    gate_pids=

    wall=$(($(date +%s) - wall_start))
    if [ -z "$gate_failed" ]; then
        echo "check: $streams streams, wall $wall s, the gates alone add up to $gate_sum s"
        gate_cleanup
        return 0
    fi
    # Failed logs last, in reverse run order; the exit status is the earliest failed gate's.
    ordered='' reversed=''
    for g in $rest; do
        ! gate_in "$g" $gate_failed || ordered="$ordered $g"
    done
    gate_failed=$ordered
    first=${ordered# }
    first=${first%% *}
    for g in $ordered; do reversed="$g $reversed"; done
    echo "check: failed:$gate_failed"
    for g in $reversed; do
        cat "$run_tmp/$g.log"
        read -r status secs _ <"$run_tmp/$g.rc"
        echo "-- $g: FAILED (exit $status) after $secs s"
    done
    read -r status _ <"$run_tmp/$first.rc"
    gate_cleanup
    exit "$status"
}
