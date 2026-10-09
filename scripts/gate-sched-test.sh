#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Self-test of the concurrent gate runner (scripts/gate-sched.sh) with stub gates, and of the skip of
# the `notices` gate (scripts/check.sh, with a stub cargo in a scratch repository). What it checks:
# gates of different streams overlap; each gate's output stays whole under its `==> <gate>` line;
# any failing stream fails the run with the earliest failed gate's status and log last; a stream
# stops at its first failure; a gate that needs another waits for it and is skipped when it failed;
# PUDDLE_CHECK_SERIAL=1 and a single stream run inline in order; the serial prefix stops the run.
# What it cannot see: real gates (each has its own CI step), the timing of a loaded host (the
# overlap check allows generous slack), a signal reaching the gates' children.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gate-sched-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fail() {
    echo "gate-sched-test: $*" >&2
    exit 1
}
# A hook (git-env's victim variables) must not steer the git commands below.
# shellcheck disable=SC2046 # the list is words by design
unset $(git rev-parse --local-env-vars)

# scenario <name> <serial gates> <gate>...: runs the scheduler with stub gates in the background.
# A gate's behaviour is the file $tmp/<name>/spec/<gate>: "<seconds> <exit status>". The stub prints a
# line, waits, prints another; it records its start and end times.
scenario() {
    name=$1 serial=$2
    shift 2
    d=$tmp/$name
    mkdir -p "$d/spec"
    (
        trap 'echo $? >"$d/rc"' EXIT
        # shellcheck source=scripts/gate-sched.sh
        . "$here/scripts/gate-sched.sh"
        run_gate() {
            echo "==> $1"
            read -r secs rc <"$d/spec/$1"
            date +%s >"$d/start.$1"
            echo "$1 begins"
            sleep "$secs"
            echo "$1 ends"
            date +%s >"$d/end.$1"
            return "$rc"
        }
        before_concurrent() { :; }
        serial_gates=$serial
        run_gates "$@"
    ) >"$d/out" 2>"$d/err" &
}
spec() { printf '%s\n' "$3" >"$tmp/$1/spec/$2"; } # spec <scenario> <gate> "<seconds> <status>"

# S1: three streams of 2 s each overlap, and each gate's lines stay together.
mkdir -p "$tmp/s1/spec"
for g in clippy ui notices; do spec s1 $g "2 0"; done
start=$(date +%s)
scenario s1 "" clippy ui notices
# S2: two failures in two streams; a stream stops at its first failure; the third stream completes.
mkdir -p "$tmp/s2/spec"
spec s2 clippy "1 0"; spec s2 doc "1 3"; spec s2 coverage "1 0"
spec s2 ui "1 0"; spec s2 ui-e2e "1 4"; spec s2 notices "1 0"
scenario s2 "" clippy ui doc ui-e2e coverage notices
# S3: coverage waits for ui; ui fails: coverage is skipped, ui's status is the run's.
mkdir -p "$tmp/s3/spec" "$tmp/s3b/spec"
spec s3 ui "2 0"; spec s3 coverage "1 0"; spec s3 clippy "1 0"
scenario s3 "" clippy ui coverage
spec s3b ui "1 5"; spec s3b coverage "1 0"; spec s3b clippy "1 0"
scenario s3b "" clippy ui coverage
# S4: PUDDLE_CHECK_SERIAL=1 runs inline in the given order, with none of the scheduler's lines.
mkdir -p "$tmp/s4/spec"
spec s4 clippy "0 0"; spec s4 ui "0 0"; spec s4 notices "0 0"
PUDDLE_CHECK_SERIAL=1 scenario s4 "" clippy ui notices
# S5: the serial prefix stops the run at its first failure; the same gate twice runs once.
mkdir -p "$tmp/s5/spec"
spec s5 fmt "0 2"; spec s5 typos "0 0"; spec s5 clippy "0 0"; spec s5 ui "0 0"
scenario s5 "fmt typos" fmt typos fmt clippy ui
wait

rc_of() { cat "$tmp/$1/rc"; }
lines_of() { grep -c "$2" "$tmp/$1/out" || true; }

# S1
[ "$(rc_of s1)" = 0 ] || fail "s1: exit $(rc_of s1)"
for g in clippy ui notices; do
    [ "$(lines_of s1 "^==> $g\$")" = 1 ] || fail "s1: $g's ==> line is not there exactly once"
    # begins, ends and the ok line follow the header with nothing between them
    [ "$(grep -A3 "^==> $g\$" "$tmp/s1/out" | tail -n 3 | tr '\n' '|')" = "$g begins|$g ends|-- $g: ok, 2 s|" ] ||
        [ "$(grep -A3 "^==> $g\$" "$tmp/s1/out" | tail -n 3 | tr '\n' '|')" = "$g begins|$g ends|-- $g: ok, 3 s|" ] ||
        fail "s1: the output of $g is split or incomplete"
done
s1_secs=$(sed -n 's/^check: .* wall \([0-9]*\) s.*/\1/p' "$tmp/s1/out")
[ -n "$s1_secs" ] && [ "$s1_secs" -le 4 ] || fail "s1: three 2 s gates took ${s1_secs:-?} s: they did not overlap"
grep -q '^check: 3 streams' "$tmp/s1/out" || fail "s1: no summary line"
: "$start"

# S2
[ "$(rc_of s2)" = 3 ] || fail "s2: exit $(rc_of s2), expected the earliest failure's 3 (doc)"
grep -q '^-- coverage: skipped' "$tmp/s2/out" || fail "s2: coverage ran or was not reported after doc failed"
grep -q '^-- notices: ok' "$tmp/s2/out" || fail "s2: the misc stream did not finish"
[ ! -e "$tmp/s2/start.coverage" ] || fail "s2: coverage started after its stream failed"
[ "$(grep '^==> ' "$tmp/s2/out" | tail -n 1)" = "==> doc" ] || fail "s2: the earliest failed gate (doc) is not the last ==> line"
[ "$(grep '^==> ' "$tmp/s2/out" | tail -n 2 | head -n 1)" = "==> ui-e2e" ] || fail "s2: failures are not printed in reverse run order"
grep -q '^check: failed: doc ui-e2e' "$tmp/s2/out" || fail "s2: failed gates not listed in run order"

# S3
[ "$(rc_of s3)" = 0 ] || fail "s3: exit $(rc_of s3)"
[ "$(cat "$tmp/s3/start.coverage")" -ge "$(cat "$tmp/s3/end.ui")" ] || fail "s3: coverage started before ui finished"
[ "$(rc_of s3b)" = 5 ] || fail "s3b: exit $(rc_of s3b), expected ui's 5"
grep -q '^-- coverage: skipped (needs ui' "$tmp/s3b/out" || fail "s3b: coverage was not skipped for the failed ui"
[ ! -e "$tmp/s3b/start.coverage" ] || fail "s3b: coverage ran without ui"

# S4
[ "$(rc_of s4)" = 0 ] || fail "s4: exit $(rc_of s4)"
[ "$(grep '^==> ' "$tmp/s4/out" | tr '\n' ' ')" = "==> clippy ==> ui ==> notices " ] || fail "s4: gates not run in order"
! grep -q '^--\|^check:' "$tmp/s4/out" || fail "s4: the inline run printed scheduler lines"

# S5
[ "$(rc_of s5)" = 2 ] || fail "s5: exit $(rc_of s5), expected fmt's 2"
[ ! -e "$tmp/s5/start.typos" ] && [ ! -e "$tmp/s5/start.clippy" ] || fail "s5: a gate ran after the prefix failed"

# The notices skip: a scratch repository with this check.sh and a stub cargo and cargo-about.
n=$tmp/notices
mkdir -p "$n/scripts" "$n/bin" "$n/crates/xtask/src" "$n/ui" "$n/crates/a"
cp "$here/scripts/check.sh" "$here/scripts/gate-sched.sh" "$n/scripts/"
printf '# lock\n' >"$n/Cargo.lock"
printf 'accepted = []\n' >"$n/about.toml"
printf '{}\n' >"$n/ui/package-lock.json"
printf '[package]\nname = "a"\n' >"$n/crates/a/Cargo.toml"
printf 'fn main() {}\n' >"$n/crates/xtask/src/main.rs"
printf '#!/bin/sh\necho "cargo-about 0.0.0"\n' >"$n/bin/cargo-about"
cat >"$n/bin/cargo" <<'STUB'
#!/bin/sh
# Stub cargo: records the call; fails when asked to (STUB_OFFLINE_RC / STUB_ONLINE_RC).
echo "$*" >>"$(dirname "$0")/calls"
for a; do
    [ "$a" != --offline ] || exit "${STUB_OFFLINE_RC:-0}"
done
exit "${STUB_ONLINE_RC:-0}"
STUB
chmod +x "$n/bin/cargo" "$n/bin/cargo-about"
(cd "$n" && git init -q && git add . && git -c user.email=t@example.org -c user.name=t commit -q -m init)
notices() { # notices <rc file>: one run of the gate; prints its output
    (cd "$n" && CARGO="$n/bin/cargo" CARGO_TARGET_DIR="$n/target" PATH="$n/bin:$PATH" sh scripts/check.sh notices 2>&1)
}
calls() { [ -f "$n/bin/calls" ] && wc -l <"$n/bin/calls" || echo 0; }

out=$(notices) || fail "notices: the first run failed: $out"
[ "$(calls)" = 1 ] || fail "notices: expected one cargo call on the first run, got $(calls)"
grep -q -- '--offline' "$n/bin/calls" || fail "notices: the first call was not offline"
out=$(notices) || fail "notices: the second run failed: $out"
printf '%s\n' "$out" | grep -q 'notices: skipped' || fail "notices: an unchanged run was not skipped"
[ "$(calls)" = 1 ] || fail "notices: the skipped run called cargo"
echo "# changed" >>"$n/Cargo.lock"
out=$(notices) || fail "notices: the run after a lock change failed: $out"
[ "$(calls)" = 2 ] || fail "notices: a changed Cargo.lock did not run the gate"
for f in about.toml ui/package-lock.json crates/a/Cargo.toml crates/xtask/src/main.rs; do
    out=$(notices) # re-stamp on the current bytes
    before=$(calls)
    echo "# $f changed" >>"$n/$f"
    notices >/dev/null || fail "notices: the run after a change of $f failed"
    [ "$(calls)" = $((before + 1)) ] || fail "notices: a change of $f did not run the gate"
done
before=$(calls)
CHECK_NO_SKIP=1 notices >/dev/null || fail "notices: CHECK_NO_SKIP=1 run failed"
[ "$(calls)" = $((before + 1)) ] || fail "notices: CHECK_NO_SKIP=1 did not run the gate"
# A failing run leaves no stamp, so the next run runs again; the offline failure falls back online.
echo "# broken" >>"$n/Cargo.lock"
before=$(calls)
STUB_OFFLINE_RC=1 STUB_ONLINE_RC=1 notices >/dev/null && fail "notices: a failing gate passed"
[ "$(calls)" = $((before + 2)) ] || fail "notices: a failing offline run was not retried online"
STUB_OFFLINE_RC=1 STUB_ONLINE_RC=1 notices >/dev/null && fail "notices: a failed run left a stamp that skipped the next"
before=$(calls)
out=$(STUB_OFFLINE_RC=1 notices) || fail "notices: the online fallback did not pass: $out"
[ "$(calls)" = $((before + 2)) ] || fail "notices: the offline failure did not fall back to the online run"
echo "gate-sched-test: ok"
