#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Gate-level check that the gates leave the repository of a calling git hook alone. A hook exports
# GIT_DIR, GIT_INDEX_FILE and GIT_WORK_TREE; a gate that runs a mutating git command (`git init`,
# `git config`, `git add`) without stripping them rewrites that repository. This runs the gates
# that spawn git under those variables, pointed at a throwaway repository, and asserts the victim's
# config, index and HEAD are byte-identical afterwards:
#   - `scripts/check.sh fast` (fmt typos spdx shellcheck hooks platform-literals standalone), which
#     covers every git-touching gate of the pre-commit list and the cheap ones of the pre-push list;
#   - the process-spawning tests that create repositories: the fixtures of puddle-workspace and the
#     xtask git-env test (already built by the `test`/`coverage` gates, so cheap), and the UI
#     diff-coverage unit test when ui/node_modules exists.
# Not run here (a full build or the network, none of them runs a mutating git command outside the
# tests above): clippy, clippy-windows, deny, notices, openapi, ui (build), ui-licences, ui-audit,
# ui-e2e, doc, coverage. Not seen: a hook's other variables (GIT_PREFIX, GIT_COMMON_DIR) are set but
# only the three above are compared.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/git-env-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
cd "$here"

# The victim: a repository with one commit, so its index is not empty.
(
    # shellcheck disable=SC2046 # the list is words by design
    unset $(git rev-parse --local-env-vars)
    git init -q "$tmp/victim"
    git -C "$tmp/victim" -c user.email=t@example.org -c user.name=t commit -q --allow-empty -m init
    echo x >"$tmp/victim/file"
    git -C "$tmp/victim" add file
)
snapshot() {
    cat "$tmp/victim/.git/config" "$tmp/victim/.git/HEAD" "$tmp/victim/.git/index" | cksum
}
before=$(snapshot)

hook_env() {
    GIT_DIR="$tmp/victim/.git" GIT_INDEX_FILE="$tmp/victim/.git/index" GIT_WORK_TREE="$tmp/victim" \
        GIT_PREFIX="" "$@"
}
verify() {
    after=$(snapshot)
    [ "$before" = "$after" ] || {
        echo "git-env-test: $1 changed the repository named by GIT_DIR (config, HEAD or index)" >&2
        exit 1
    }
    grep -q 'bare = false' "$tmp/victim/.git/config" || {
        echo "git-env-test: $1 flipped core.bare in the repository named by GIT_DIR" >&2
        exit 1
    }
    echo "git-env-test: $1: the repository named by GIT_DIR is unchanged"
}

# The gates are not expected to pass here: with GIT_INDEX_FILE kept (pre-commit needs it for
# `git commit -- <paths>`) `git ls-files` reads the victim's index. Only the victim is judged.
hook_env scripts/check.sh fast >"$tmp/fast.log" 2>&1 || true
verify "scripts/check.sh fast"

hook_env cargo test --locked -q -p xtask --test git_env >"$tmp/xtask.log" 2>&1 ||
    { cat "$tmp/xtask.log" >&2; echo "git-env-test: the xtask git test failed under the hook variables" >&2; exit 1; }
hook_env cargo test --locked -q -p puddle-workspace --test delete_check_sh --test clear_locks_sh \
    >"$tmp/ws.log" 2>&1 ||
    { cat "$tmp/ws.log" >&2; echo "git-env-test: the workspace tests failed under the hook variables" >&2; exit 1; }
verify "the cargo git fixtures"

if [ -d ui/node_modules ]; then
    (cd ui && hook_env npx vitest run scripts/diff-coverage.test.ts >"$tmp/ui.log" 2>&1) ||
        { cat "$tmp/ui.log" >&2; echo "git-env-test: the UI diff-coverage test failed under the hook variables" >&2; exit 1; }
    verify "the UI diff-coverage test"
else
    echo "git-env-test: ui/node_modules missing, UI diff-coverage test skipped"
fi
