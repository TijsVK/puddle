#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# The quality gates, in one place: git hooks, CI and humans all run this script, so the gates
# can't drift apart. Usage: scripts/check.sh <gate>...   Gates:
#   fmt, typos, spdx, shellcheck, clippy, clippy-windows, deny, notices, openapi, test, doc, coverage
#   fast  = fmt typos spdx shellcheck            (pre-commit hook)
#   all   = fast clippy clippy-windows deny notices openapi doc coverage   (pre-push hook, CI; coverage runs the tests)
# Set CARGO to run every Cargo command through a wrapper, e.g. CARGO=mbx for the shared build
# cache (docs/STANDARDS.md, "Shared build cache"); unset, it runs plain cargo.
# Coverage thresholds live here (docs/STANDARDS.md, "Coverage"); raise them, never lower them
# without the owner's OK.
set -eu

COV_LINES=85
COV_REGIONS=80
# Unset it so the wrapper itself (mbx looks up `$CARGO` to find Cargo) doesn't call itself.
cargo="${CARGO:-cargo}"
unset CARGO

cd "$(dirname "$0")/.."

run_gate() {
    echo "==> $1"
    case "$1" in
    fmt) "$cargo" fmt --all --check ;;
    typos) typos ;;
    spdx) scripts/check-spdx.sh ;;
    shellcheck)
        # Every shell script, including the guest scripts puddle runs inside sandboxes (POSIX sh).
        command -v shellcheck >/dev/null 2>&1 || {
            echo "shellcheck gate needs shellcheck on PATH (docs/STANDARDS.md, \"Toolchain\")" >&2
            exit 1
        }
        git ls-files -z -- '*.sh' '.githooks/*' | xargs -0 shellcheck
        ;;
    clippy) "$cargo" clippy --workspace --all-targets --all-features --locked -- -D warnings ;;
    clippy-windows)
        # cargo-xwin supplies the MSVC headers and libraries, so C dependencies (bundled SQLite)
        # build for the msvc target. It drives clang as clang-cl and the toolchain's llvm-ar as
        # llvm-lib, so it needs `clang` on PATH. Run through plain cargo: the cross-check doesn't
        # share the native build's cache anyway.
        for tool in cargo-xwin clang; do
            command -v "$tool" >/dev/null 2>&1 || {
                echo "clippy-windows needs $tool on PATH (docs/STANDARDS.md, \"Toolchain\")" >&2
                exit 1
            }
        done
        cargo xwin clippy --workspace --all-targets --all-features --locked \
            --target x86_64-pc-windows-msvc -- -D warnings
        ;;
    deny) "$cargo" deny --locked check ;;
    notices)
        # Every shipped dependency has a licence entry in the third-party notices (cargo-about).
        "$cargo" run --quiet --locked -p xtask -- notices --check
        ;;
    openapi)
        # The committed API contract (openapi.json, schema.d.ts) matches the routes (ADR 0004).
        # The TypeScript half needs Node; without it locally the gate says so and checks the JSON
        # only. In CI (CI set) a missing Node fails.
        "$cargo" run --quiet --locked -p xtask -- openapi --check
        ;;
    test) "$cargo" nextest run --workspace --all-features --locked ;;
    doc)
        "$cargo" test --doc --workspace --all-features --locked --no-fail-fast
        RUSTDOCFLAGS="-D warnings" "$cargo" doc --workspace --no-deps --all-features --locked
        ;;
    coverage)
        "$cargo" llvm-cov nextest --workspace --all-features --locked \
            --profile "${NEXTEST_PROFILE:-default}" \
            --fail-under-lines "$COV_LINES" --fail-under-regions "$COV_REGIONS" \
            --lcov --output-path "${CARGO_TARGET_DIR:-target}/lcov.info"
        "$cargo" llvm-cov report --summary-only
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
    fast) for g in fmt typos spdx shellcheck; do run_gate "$g"; done ;;
    all) for g in fmt typos spdx shellcheck clippy clippy-windows deny notices openapi doc coverage; do run_gate "$g"; done ;;
    *) run_gate "$arg" ;;
    esac
done
