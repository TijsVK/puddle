#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Gate-level check that the gates leave the repository of a calling git hook alone. A hook exports
# GIT_DIR, GIT_INDEX_FILE and GIT_WORK_TREE; a gate that runs a mutating git command (`git init`,
# `git config`, `git add`) without stripping them rewrites that repository. This runs the gates
# that spawn git under those variables, pointed at throwaway repositories, and asserts each victim's
# config, index and HEAD are byte-identical afterwards:
#   - `scripts/check.sh fast` (fmt typos spdx shellcheck hooks platform-literals standalone), which
#     covers every git-touching gate of the pre-commit list and the cheap ones of the pre-push list.
#     The `fast` run before this gate had no hook variables, so it proves nothing here; this one is
#     the pre-commit hook's situation. It runs beside the tests below, on its own victim;
#   - the process-spawning tests that create repositories (xtask's git test, puddle-workspace's
#     fixtures), run through the coverage gate's own test build: the same `cargo llvm-cov nextest`
#     arguments, so no test binary is compiled for this gate (check.sh passes its wrapper and the
#     crates it excludes in GIT_ENV_CARGO and GIT_ENV_EXCLUDE);
#   - the UI diff-coverage unit test when ui/node_modules exists.
# Not run here (a full build or the network, none of them runs a mutating git command outside the
# tests above): clippy, clippy-windows, deny, notices, openapi, ui (build), ui-licences, ui-audit,
# ui-e2e, doc, coverage. Not seen: a hook's other variables (GIT_PREFIX, GIT_COMMON_DIR) are set but
# only the three above are compared. The test run leaves profile data in the coverage build
# directory; it is removed again, so it cannot reach a coverage report.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/git-env-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
cd "$here"
cargo=${GIT_ENV_CARGO:-cargo}
exclude=${GIT_ENV_EXCLUDE:-}

# A victim: a repository with one commit, so its index is not empty.
make_victim() {
    (
        # shellcheck disable=SC2046 # the list is words by design
        unset $(git rev-parse --local-env-vars)
        git init -q "$tmp/$1"
        git -C "$tmp/$1" -c user.email=t@example.org -c user.name=t commit -q --allow-empty -m init
        echo x >"$tmp/$1/file"
        git -C "$tmp/$1" add file
    )
}
snapshot() {
    cat "$tmp/$1/.git/config" "$tmp/$1/.git/HEAD" "$tmp/$1/.git/index" | cksum
}
make_victim victim-fast
make_victim victim-tests
before_fast=$(snapshot victim-fast)
before_tests=$(snapshot victim-tests)

hook_env() { # hook_env <victim> <command>...
    victim=$tmp/$1
    shift
    GIT_DIR="$victim/.git" GIT_INDEX_FILE="$victim/.git/index" GIT_WORK_TREE="$victim" GIT_PREFIX="" "$@"
}
verify() { # verify <victim> <snapshot before> <label>
    after=$(snapshot "$1")
    [ "$2" = "$after" ] || {
        echo "git-env-test: $3 changed the repository named by GIT_DIR (config, HEAD or index)" >&2
        exit 1
    }
    grep -q 'bare = false' "$tmp/$1/.git/config" || {
        echo "git-env-test: $3 flipped core.bare in the repository named by GIT_DIR" >&2
        exit 1
    }
    echo "git-env-test: $3: the repository named by GIT_DIR is unchanged"
}

# The gates are not expected to pass here: with GIT_INDEX_FILE kept (pre-commit needs it for
# `git commit -- <paths>`) `git ls-files` reads the victim's index. Only the victim is judged.
(hook_env victim-fast scripts/check.sh fast >"$tmp/fast.log" 2>&1 || true) &
fast_pid=$!

# shellcheck disable=SC2086 # $exclude is empty or one `--exclude <crate>` pair
hook_env victim-tests "$cargo" llvm-cov nextest --workspace $exclude --all-features --locked --no-report \
    -E 'binary(git_env) | binary(delete_check_sh) | binary(clear_locks_sh)' >"$tmp/tests.log" 2>&1 ||
    { cat "$tmp/tests.log" >&2; echo "git-env-test: the git tests failed under the hook variables" >&2; exit 1; }
# A renamed binary would match nothing and pass silently: every one of the three must have run.
for bin in xtask::git_env puddle-workspace::delete_check_sh puddle-workspace::clear_locks_sh; do
    grep -q "PASS.*$bin" "$tmp/tests.log" || {
        cat "$tmp/tests.log" >&2
        echo "git-env-test: no test of $bin ran" >&2
        exit 1
    }
done
verify victim-tests "$before_tests" "the cargo git fixtures"
"$cargo" llvm-cov clean --profraw-only >/dev/null 2>&1 || true

wait "$fast_pid"
verify victim-fast "$before_fast" "scripts/check.sh fast"

if [ -d ui/node_modules ]; then
    (cd ui && hook_env victim-tests npx vitest run scripts/diff-coverage.test.ts >"$tmp/ui.log" 2>&1) ||
        { cat "$tmp/ui.log" >&2; echo "git-env-test: the UI diff-coverage test failed under the hook variables" >&2; exit 1; }
    verify victim-tests "$before_tests" "the UI diff-coverage test"
else
    echo "git-env-test: ui/node_modules missing, UI diff-coverage test skipped"
fi
