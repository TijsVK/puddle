#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# The quality gates, in one place: git hooks, CI and humans all run this script, so the gates
# can't drift apart. Usage: scripts/check.sh <gate>...   Gates:
#   fmt, typos, spdx, clippy, clippy-windows, deny, test, doc, coverage
#   fast  = fmt typos spdx                       (pre-commit hook)
#   all   = fast clippy clippy-windows deny doc coverage   (pre-push hook, CI; coverage runs the tests)
# Coverage thresholds live here (docs/STANDARDS.md, "Coverage"); raise them, never lower them
# without the owner's OK.
set -eu

COV_LINES=85
COV_REGIONS=80

cd "$(dirname "$0")/.."

run_gate() {
    echo "==> $1"
    case "$1" in
    fmt) cargo fmt --all --check ;;
    typos) typos ;;
    spdx) scripts/check-spdx.sh ;;
    clippy) cargo clippy --workspace --all-targets --all-features --locked -- -D warnings ;;
    clippy-windows)
        cargo clippy --workspace --all-targets --all-features --locked \
            --target x86_64-pc-windows-msvc -- -D warnings
        ;;
    deny) cargo deny --locked check ;;
    test) cargo nextest run --workspace --all-features --locked ;;
    doc)
        cargo test --doc --workspace --all-features --locked
        RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
        ;;
    coverage)
        cargo llvm-cov nextest --workspace --all-features --locked \
            --profile "${NEXTEST_PROFILE:-default}" \
            --fail-under-lines "$COV_LINES" --fail-under-regions "$COV_REGIONS" \
            --lcov --output-path target/lcov.info
        cargo llvm-cov report --summary-only
        ;;
    *)
        echo "unknown gate: $1" >&2
        exit 2
        ;;
    esac
}

[ "$#" -gt 0 ] || set -- all
for arg in "$@"; do
    case "$arg" in
    fast) for g in fmt typos spdx; do run_gate "$g"; done ;;
    all) for g in fmt typos spdx clippy clippy-windows deny doc coverage; do run_gate "$g"; done ;;
    *) run_gate "$arg" ;;
    esac
done
