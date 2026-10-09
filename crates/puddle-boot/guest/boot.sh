#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# puddle's boot hook. puddle runs it as root through the runtime's
# exec after every create and every start, and serves no SSH or exec to anyone until it exits 0.
#
#   /bin/sh /puddle/boot.sh [ENTRYPOINT CMD...] < plan
#
# The plan on stdin comes from puddle-boot (crates/puddle-boot/src/plan.rs): a shell fragment
# that only calls the puddle_* functions below, with every value quoted there. The arguments, if
# any, are the image's ENTRYPOINT + CMD, chained after setup. POSIX sh (dash, bash, busybox
# ash). Idempotent: running it again converges on the same files and starts nothing twice.
#
# Exit status: 0 ready; 1 a step failed; 2 bad usage or plan. Errors go to stderr, one line
# starting with "puddle-boot: error:"; progress goes to stdout and /run/puddle/boot.log.
#
# PUDDLE_ROOT is for the unit tests only (puddle always passes it empty): it relocates every file
# the hook reads or writes, so the tests run it against a fake root. Process checks use the live
# /proc either way.
set -u
umask 022

ROOT=${PUDDLE_ROOT:-}
case $0 in */*) HERE=${0%/*} ;; *) HERE=. ;; esac
RUN=$ROOT/run/puddle
STATE=$ROOT/var/lib/puddle
LOG=$RUN/boot.log

say() {
    printf 'puddle-boot: %s\n' "$1"
    printf '%s\n' "$1" >>"$LOG" 2>/dev/null
}

die() { # die <message> [status]
    printf 'puddle-boot: error: %s\n' "$1" >&2
    printf 'error: %s\n' "$1" >>"$LOG" 2>/dev/null
    exit "${2:-1}"
}

IS_ROOT=0
[ "$(id -u)" = 0 ] && IS_ROOT=1
if [ -z "$ROOT" ] && [ "$IS_ROOT" != 1 ]; then
    die "must run as root, not as uid $(id -u)" 2
fi

mkdir -p "$RUN" "$STATE" || die "cannot create $RUN and $STATE"
: >"$LOG"
rm -f "$RUN/boot.done" "$RUN/triggers" "$RUN/steps" "$RUN/entry-env" "$RUN/changed" "$RUN/files.new" "$RUN/merge.new"
: >"$RUN/changed"
: >"$RUN/files.new"
: >"$RUN/merge.new"
: >"$RUN/triggers"
: >"$RUN/steps"


boot_id=unknown
if [ -r "$ROOT/proc/sys/kernel/random/boot_id" ]; then
    # cat, not read: dash's read takes one byte per read(2), and procfs answers a read at a
    # non-zero offset with EOF, so `read` would see only the first character.
    boot_id=$(cat "$ROOT/proc/sys/kernel/random/boot_id") || boot_id=unknown
fi

# One tick of waiting. Fractional sleep isn't POSIX, but GNU and busybox both have it.
if sleep 0.01 2>/dev/null; then TICK=0.05 TICKS_PER_S=20; else TICK=1 TICKS_PER_S=1; fi

# Whether the process recorded in <pidfile> by this boot still runs (and, if given, has
# <word> in its command line, so a reused PID doesn't count).
alive() { # alive <pidfile> [word]
    [ -f "$1" ] || return 1
    read -r bid pid <"$1" || return 1
    [ "$bid" = "$boot_id" ] || return 1
    case $pid in '' | *[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    [ -n "${2:-}" ] || return 0
    [ -r "/proc/$pid/cmdline" ] || return 1
    case $(tr '\0' ' ' <"/proc/$pid/cmdline") in *"$2"*) return 0 ;; esac
    return 1
}

say "start (boot $boot_id)"

# --- 1. The plan ------------------------------------------------------------------------------
PLAN=$RUN/plan.sh
(umask 077 && cat >"$PLAN") || die "cannot read the plan from stdin" 2
first=
IFS= read -r first <"$PLAN"
[ "$first" = "# puddle-boot-plan 1" ] || die "the plan on stdin has no '# puddle-boot-plan 1' header" 2
grep -qx 'puddle_plan_end' "$PLAN" || die "the plan on stdin is truncated (no puddle_plan_end line)" 2

# --- 2. Kernel settings: not persisted by the guest, and /etc/sysctl.d is never applied --------
setk() { # setk <key> <value>
    f=$ROOT/proc/sys/$(printf '%s' "$1" | tr . /)
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -w "$1=$2" >/dev/null || die "sysctl -w $1=$2 failed"
    else
        printf '%s\n' "$2" >"$f" || die "cannot write $f"
    fi
    got=
    [ -r "$f" ] && got=$(cat "$f") # cat: see boot_id above
    [ "$got" = "$2" ] || die "sysctl $1 is '${got:-unreadable}' after setting it to $2"
}
setk fs.inotify.max_user_instances 1024
setk fs.inotify.max_user_watches 524288
setk kernel.unprivileged_bpf_disabled 1
say "sysctls set"

# --- 3. Files, applied in plan order ----------------------------------------------------------
# Two kinds: puddle_file writes a whole file puddle owns; puddle_merge sets only puddle's keys in
# a file that belongs to the user, through the agent binary's `merge-file`, which parses
# the file (this script can't) and leaves one it can't parse untouched.
GIT_INCLUDE=
MERGE_TOOL=
AGENT=
AGENT_PORT=
ENTRY_CWD=
PLAN_DONE=

same() { command -v cmp >/dev/null 2>&1 && cmp -s "$1" "$2"; }

# Records what the merge tool did with <path>: one word, or "left: <reason>".
merge_result() { # merge_result <path> <tool output>
    case $2 in
    changed | removed)
        printf '%s\n' "$1" >>"$RUN/changed"
        say "$1: puddle's own lines were $2 (everything else in the file is as it was)"
        ;;
    unchanged) ;;
    left:*) say "$1 left as it is: ${2#left: }" ;;
    *) die "unexpected answer from the merge tool for $1: $2" ;;
    esac
}

# shellcheck disable=SC2329 # the plan calls these
{
    puddle_file() { # puddle_file <path> <octal mode> <printf format of the contents>
        dst=$ROOT$1
        dir=${dst%/*}
        mkdir -p "${dir:-/}" || die "cannot create the directory for $1"
        tmp=${dir}/.puddle-new.$$
        rm -f "$tmp"
        # shellcheck disable=SC2059 # a printf format with every special byte escaped (plan.rs)
        (umask 077 && printf "$3" >"$tmp") || die "cannot write $1"
        chmod "$2" "$tmp" || die "cannot set mode $2 on $1"
        if [ "$IS_ROOT" = 1 ]; then chown 0:0 "$tmp" || die "cannot make root own $1"; fi
        if ! { [ -f "$dst" ] && [ ! -L "$dst" ] && same "$tmp" "$dst"; }; then
            printf '%s\n' "$1" >>"$RUN/changed"
        fi
        # mv onto a link to a directory, or onto a directory, would move the file into it.
        if [ -L "$dst" ]; then rm -f "$dst" || die "cannot replace the link at $1"; fi
        [ ! -d "$dst" ] || {
            rm -f "$tmp"
            die "$1 is a directory"
        }
        mv -f "$tmp" "$dst" || die "cannot move $1 into place"
        printf '%s\n' "$1" >>"$RUN/files.new"
    }
    puddle_merge_tool() { MERGE_TOOL=$1; }
    puddle_merge() { # puddle_merge <path> <octal mode> <printf format of the merge spec (JSON)>
        [ -n "$MERGE_TOOL" ] && [ -x "$ROOT$MERGE_TOOL" ] ||
            die "cannot merge $1: the merge tool ${MERGE_TOOL:-(none)} is missing or not executable"
        dst=$ROOT$1
        dir=${dst%/*}
        mkdir -p "${dir:-/}" || die "cannot create the directory for $1"
        # shellcheck disable=SC2059 # as in puddle_file
        (umask 077 && printf "$3" >"$RUN/merge.spec") || die "cannot write the merge spec for $1"
        out=$("$ROOT$MERGE_TOOL" merge-file apply "$STATE/merge" "$1" "$dst" "$2" <"$RUN/merge.spec" 2>&1) ||
            die "cannot merge $1: $out"
        merge_result "$1" "$out"
        printf '%s\n' "$1" >>"$RUN/merge.new"
    }
    puddle_on_change() { printf '%s %s\n' "$1" "$2" >>"$RUN/triggers"; }
    puddle_step() { printf '%s\n' "$1" >>"$RUN/steps"; }
    puddle_git_include() { GIT_INCLUDE=$1; }
    puddle_agent() { AGENT=$1 AGENT_PORT=$2; }
    puddle_entrypoint_env() { printf '%s\n' "$1" >>"$RUN/entry-env"; }
    puddle_entrypoint_cwd() { ENTRY_CWD=$1; }
    puddle_plan_end() { PLAN_DONE=1; }
}

# shellcheck source=/dev/null
. "$PLAN"
[ "$PLAN_DONE" = 1 ] || die "the plan did not reach puddle_plan_end" 2

# Files an earlier plan wrote whole that this one doesn't: remove them (a provider was switched
# off). One that is merged now stays (the merge kept its content).
if [ -f "$STATE/boot-files" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        grep -Fxq -- "$p" "$RUN/files.new" && continue
        grep -Fxq -- "$p" "$RUN/merge.new" && continue
        rm -f "$ROOT$p" || die "cannot remove $p"
        printf '%s\n' "$p" >>"$RUN/changed"
        say "removed $p (no longer in the plan)"
    done <"$STATE/boot-files"
fi
mv -f "$RUN/files.new" "$STATE/boot-files" || die "cannot record the files written"

# Merged files an earlier plan listed and this one doesn't: remove only puddle's keys (and the
# file, if puddle created it and nothing else is left). One that is written whole now only loses
# its record. Without the tool, the record waits for a boot that has it.
if [ -f "$STATE/merge-files" ]; then
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        grep -Fxq -- "$p" "$RUN/merge.new" && continue
        if [ -z "$MERGE_TOOL" ] || [ ! -x "$ROOT$MERGE_TOOL" ]; then
            say "puddle's keys stay in $p for now: no merge tool at ${MERGE_TOOL:-(none)}"
            printf '%s\n' "$p" >>"$RUN/merge.new"
        elif grep -Fxq -- "$p" "$STATE/boot-files"; then
            out=$("$ROOT$MERGE_TOOL" merge-file forget "$STATE/merge" "$p" </dev/null 2>&1) ||
                die "cannot drop the merge record of $p: $out"
        else
            out=$("$ROOT$MERGE_TOOL" merge-file remove "$STATE/merge" "$p" "$ROOT$p" </dev/null 2>&1) ||
                die "cannot remove puddle's keys from $p: $out"
            merge_result "$p" "$out"
            case $out in left:*) ;; *) say "puddle's keys removed from $p (no longer in the plan): $out" ;; esac
        fi
    done <"$STATE/merge-files"
fi
mv -f "$RUN/merge.new" "$STATE/merge-files" || die "cannot record the files merged"
say "files applied ($(grep -c '' "$RUN/changed") changed)"

# git reads puddle's settings through one include in the system config, which works whether or
# not git is installed yet and never touches the image's own entries.
if [ -n "$GIT_INCLUDE" ]; then
    gc=$ROOT/etc/gitconfig
    line=$(printf '\tpath = %s' "$GIT_INCLUDE")
    if ! { [ -f "$gc" ] && grep -Fxq -- "$line" "$gc"; }; then
        printf '[include]\n%s\n' "$line" >>"$gc" || die "cannot add the include to /etc/gitconfig"
        say "git include added"
    fi
fi

# Commands to run when a file below a directory changed (update-ca-certificates).
while read -r dir cmd; do
    hit=
    while IFS= read -r p; do
        case $p in "$dir"/*) hit=1 ;; esac
    done <"$RUN/changed"
    if [ -z "$hit" ]; then
        say "$cmd skipped ($dir unchanged)"
    elif ! command -v "$cmd" >/dev/null 2>&1; then
        say "$cmd skipped (not in this image)"
    else
        out=$("$cmd" </dev/null 2>&1) || die "$cmd failed: $out"
        say "$cmd ran"
    fi
done <"$RUN/triggers"

# Provider steps: scripts the plan itself wrote, run at every boot in plan order, after the
# triggers so they see the updated system CA store (a step can merge the image's CA bundle here).
while IFS= read -r step; do
    [ -n "$step" ] || continue
    out=$(/bin/sh "$ROOT$step" </dev/null 2>&1) || die "step $step failed: $out"
    say "step $step: ${out:-done}"
done <"$RUN/steps"

# --- 4. puddle-agent under a supervisor that restarts it ----------------------------------------
if [ -n "$AGENT" ]; then
    [ -x "$ROOT$AGENT" ] || die "the agent $AGENT is missing or not executable"
    if alive "$RUN/supervisor.pid" agent-supervise; then
        say "agent supervisor already running"
    else
        # Its own session and no inherited stdout/stderr, so the exec that started us can end.
        if command -v setsid >/dev/null 2>&1; then
            setsid /bin/sh "$HERE/agent-supervise.sh" "$ROOT$AGENT" </dev/null >>"$RUN/agent.log" 2>&1 &
        else
            /bin/sh "$HERE/agent-supervise.sh" "$ROOT$AGENT" </dev/null >>"$RUN/agent.log" 2>&1 &
        fi
        printf '%s %s\n' "$boot_id" "$!" >"$RUN/supervisor.pid"
        say "agent supervisor started"
    fi
    hex=$(printf '%04X' "$AGENT_PORT")
    i=0
    until grep -Eq "^ *[0-9]+: (0100007F|00000000):$hex [0-9A-F]{8}:[0-9A-F]{4} 0A " "$ROOT/proc/net/tcp" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt $((10 * TICKS_PER_S)) ]; then
            die "puddle-agent is not listening on 127.0.0.1:$AGENT_PORT after 10 s; agent log: $(tail -n 5 "$RUN/agent.log" 2>/dev/null)"
        fi
        sleep "$TICK"
    done
    say "agent listening on 127.0.0.1:$AGENT_PORT"
fi

# --- 5. Extension steps: every boot.d/*.sh next to this script, in name order ------
# Later features add a step file (NN-name.sh, idempotent) instead of editing this script. A
# failing step fails the boot like any other step.
for step in "$HERE"/boot.d/*.sh; do
    [ -f "$step" ] || continue
    out=$(/bin/sh "$step" </dev/null 2>&1) || die "step ${step##*/} failed: $out"
    say "step ${step##*/} ran"
done

# --- 6. The image's own ENTRYPOINT (+CMD), after setup, with puddle's env, detached -------------
if [ "$#" -gt 0 ]; then
    if alive "$RUN/entrypoint.pid"; then
        say "entrypoint already running"
    else
        (
            if [ -f "$RUN/entry-env" ]; then
                while IFS= read -r f; do
                    # shellcheck source=/dev/null
                    if [ -f "$ROOT$f" ]; then . "$ROOT$f"; fi
                done <"$RUN/entry-env"
            fi
            if [ -n "$ENTRY_CWD" ]; then cd "$ROOT$ENTRY_CWD" || exit 126; fi
            if command -v setsid >/dev/null 2>&1; then exec setsid "$@"; else exec "$@"; fi
        ) </dev/null >>"$RUN/entrypoint.log" 2>&1 &
        printf '%s %s\n' "$boot_id" "$!" >"$RUN/entrypoint.pid"
        say "entrypoint chained: $1"
    fi
fi

printf '%s\n' "$boot_id" >"$RUN/boot.done"
say "ready"
