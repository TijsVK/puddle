#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# The quality gates, in one place: git hooks, CI and humans all run this script, so the gates
# can't drift apart. Usage: scripts/check.sh <gate>...   Gates:
#   fmt, typos, spdx, shellcheck, platform-literals, standalone, clippy, clippy-windows, deny, notices, openapi, test, doc, coverage,
#   ui, ui-licences, ui-audit, ui-e2e
#   fast  = fmt typos spdx shellcheck platform-literals standalone   (pre-commit hook)
#   all   = fast clippy clippy-windows deny notices openapi ui ui-licences ui-audit ui-e2e doc coverage
#           (pre-push hook, CI; coverage runs the tests, and must follow `ui`: the embedded UI is built there)
# The ui gates need Node 24 (the UI's package-lock.json pins every npm package). ui-e2e also needs
# the Playwright browsers: `cd ui && npx playwright install --with-deps chromium webkit`.
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

# The desktop shell (puddle-app) links the system WebKitGTK on Linux. Where its dev package is
# missing and this is not CI, the Linux gates skip that one crate and say so (clippy-windows still
# checks it for the msvc target). In CI (CI set) a missing package fails the build instead.
skip_app=
if [ "$(uname -s)" = Linux ] && [ -z "${CI:-}" ] && ! pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
    skip_app="--exclude puddle-app"
    echo "note: libwebkit2gtk-4.1-dev is not installed; skipping puddle-app in the Linux gates" \
        "(sudo apt install libwebkit2gtk-4.1-dev). CI builds and tests it." >&2
fi

# Installs the UI's npm packages from the lock file, once per run.
ui_installed=
ui_install() {
    [ -z "$ui_installed" ] || return 0
    for tool in node npm; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "the ui gates need $tool on PATH (Node 24, docs/STANDARDS.md, \"Toolchain\")" >&2
            exit 1
        }
    done
    (cd ui && npm ci --ignore-scripts --no-audit --no-fund)
    ui_installed=1
}

# The production build, which also lists the packages in the bundle for ui-licences.
ui_build() {
    ui_install
    (cd ui && npm run build)
}

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
    platform-literals)
        # The per-OS runtime file names live in puddle-runtime's table (platform.rs) and nowhere
        # else in the Rust code: a string literal naming msb or its firmware is a hard-coded OS.
        # Versioned names (libkrunfw.so.5.6.1) are msb-release facts, not table entries.
        hits=$(git grep -nE '"(msb\.exe|libkrunfw\.(dll|so(\.5)?|dylib|5\.dylib))"' -- 'crates/*.rs' ':!crates/puddle-runtime/src/platform.rs' || true)
        if [ -n "$hits" ]; then
            echo "$hits" >&2
            echo "platform-literals: use puddle_runtime::HostOs::runtime_files() instead of these literals" >&2
            exit 1
        fi
        ;;
    standalone) scripts/check-standalone.sh ;;
    clippy)
        # shellcheck disable=SC2086 # $skip_app is empty or one `--exclude <crate>` pair
        "$cargo" clippy --workspace $skip_app --all-targets --all-features --locked -- -D warnings
        ;;
    clippy-windows)
        # cargo-xwin supplies the MSVC headers and libraries, so C dependencies (bundled SQLite)
        # build for the msvc target. It drives clang as clang-cl and the toolchain's llvm-ar as
        # llvm-lib, so it needs `clang` on PATH; the shell's Windows resources need `llvm-rc`. Run through plain cargo: the cross-check doesn't
        # share the native build's cache anyway.
        for tool in cargo-xwin clang llvm-rc; do
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
    ui)
        # format, lint, types (Svelte's a11y warnings fail), unit and component tests with the
        # coverage thresholds in ui/vite.config.ts, then the production build.
        ui_install
        (cd ui && npm run format:check && npm run lint && npm run check && npm test)
        ui_build
        ;;
    ui-licences)
        # Every npm package in the bundle is on the licence allowlist and in the UI notices.
        ui_build
        (cd ui && node scripts/licences.ts --check)
        ;;
    ui-audit)
        # npm audit on production dependencies, minus ui/audit-exceptions.json.
        ui_install
        (cd ui && node scripts/audit.ts)
        ;;
    ui-e2e)
        # Playwright against the real API serving the built UI. WebKit stands in for WebKitGTK and
        # WKWebView; where it can't start locally (missing system libraries) this runs Chromium
        # only and says so. CI (CI set) never narrows.
        ui_build
        case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*) ;; # Windows runs the installed Edge, not Playwright's browsers
        *)
            if [ -z "${CI:-}" ] && [ -z "${PUDDLE_E2E_PROJECTS:-}" ] && ! (cd ui && node scripts/webkit-probe.ts); then
                echo "note: WebKit can't start here; running Chromium only (to add it: cd ui && npx playwright install --with-deps webkit)" >&2
                PUDDLE_E2E_PROJECTS=chromium
                export PUDDLE_E2E_PROJECTS
            fi
            ;;
        esac
        (cd ui && PUDDLE_CARGO="$cargo" npx playwright test)
        ;;
    test)
        # shellcheck disable=SC2086
        "$cargo" nextest run --workspace $skip_app --all-features --locked
        ;;
    doc)
        # shellcheck disable=SC2086
        "$cargo" test --doc --workspace $skip_app --all-features --locked --no-fail-fast
        # shellcheck disable=SC2086
        RUSTDOCFLAGS="-D warnings" "$cargo" doc --workspace $skip_app --no-deps --all-features --locked
        ;;
    coverage)
        # shellcheck disable=SC2086
        "$cargo" llvm-cov nextest --workspace $skip_app --all-features --locked \
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
    fast) for g in fmt typos spdx shellcheck platform-literals standalone; do run_gate "$g"; done ;;
    all) for g in fmt typos spdx shellcheck platform-literals standalone clippy clippy-windows deny notices openapi ui ui-licences ui-audit ui-e2e doc coverage; do run_gate "$g"; done ;;
    *) run_gate "$arg" ;;
    esac
done
