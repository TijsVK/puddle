#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# The quality gates, in one place: git hooks, CI and humans all run this script, so the gates
# can't drift apart. Usage: scripts/check.sh <gate>...   Gates:
#   fmt, typos, spdx, shellcheck, hooks, git-env, platform-literals, standalone, secrets, clippy, clippy-windows, deny, notices, openapi, test, doc, coverage,
#   coverage-ratchet, diff-coverage,
#   ui, ui-licences, ui-audit, ui-e2e
#   fast  = fmt typos spdx shellcheck hooks platform-literals standalone   (pre-commit hook)
#   all   = fast git-env secrets clippy clippy-windows deny notices openapi ui ui-licences ui-audit ui-e2e doc coverage
#           (pre-push hook, CI; coverage runs the tests, and must follow `ui`: the embedded UI is built there)
# The ui gates need Node 24 (the UI's package-lock.json pins every npm package). ui-e2e also needs
# the Playwright browsers: `cd ui && npx playwright install --with-deps chromium webkit`.
# Set CARGO to run every Cargo command through a wrapper, e.g. CARGO=mbx for the shared build
# cache (docs/STANDARDS.md, "Shared build cache"); unset, it runs plain cargo.
# Coverage (docs/STANDARDS.md, "Coverage"): the floors live here, the ratchet baseline in
# scripts/coverage-baseline.json; raise them, never lower them without the owner's OK. The ratchet
# lets a total measure up to 0.05 points below its baseline (run-to-run wobble); the floors are exact.
# A change's added lines must also be covered (gates `coverage` for Rust, `ui` for the UI,
# `diff-coverage` by hand); DIFF_BASE names the commit to measure from (CI sets it to the PR or push
# base), else the merge base with origin/develop.
set -eu

COV_LINES=92
COV_REGIONS=90
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

# Prints the commit a change is measured from for the diff-coverage gate: $DIFF_BASE if it
# resolves, else the merge base with origin/develop. Prints nothing when neither exists.
diff_base() {
    if [ -n "${DIFF_BASE:-}" ] && git cat-file -e "${DIFF_BASE}^{commit}" 2>/dev/null; then
        echo "$DIFF_BASE"
    elif git rev-parse --verify -q origin/develop >/dev/null; then
        git merge-base HEAD origin/develop
    fi
}

# Runs the diff-coverage script for one language: $1 label, $2 lcov file, $3 extensions, then
# extra arguments. Needs a base; without one it fails.
diff_coverage() {
    label=$1 lcov=$2 exts=$3
    shift 3
    base=$(diff_base)
    if [ -z "$base" ]; then
        echo "$label: no base commit to measure the diff from; run \`git fetch origin develop\` (CI: fetch-depth, DIFF_BASE)" >&2
        return 1
    fi
    node ui/scripts/diff-coverage.ts --base "$base" --lcov "$lcov" --exts "$exts" \
        --exclusions scripts/diff-coverage-exclusions.txt --label "$label" "$@"
}

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
    hooks) scripts/pre-push-test.sh && ci/fetch-msb-test.sh ;;
    git-env) scripts/git-env-test.sh ;;
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
    standalone) scripts/check-standalone.sh --self-test && scripts/check-standalone.sh ;;
    secrets)
        # gitleaks over all history with the reviewed allowlist (.gitleaks.toml); needs the pinned
        # gitleaks on PATH (ci/fetch-gitleaks.sh). Not in `fast`: it scans every commit.
        scripts/check-secrets.sh --self-test && scripts/check-secrets.sh
        ;;
    clippy)
        # shellcheck disable=SC2086 # $skip_app is empty or one `--exclude <crate>` pair
        "$cargo" clippy --workspace $skip_app --all-targets --all-features --locked -- -D warnings
        ;;
    clippy-windows)
        # cargo-xwin supplies the MSVC headers and libraries, so C dependencies (bundled SQLite)
        # build for the msvc target. It drives clang as clang-cl and the toolchain's llvm-ar as
        # llvm-lib, so it needs `clang` on PATH; the shell's Windows resources need `llvm-rc`. Run through plain cargo: the cross-check doesn't
        # share the native build's cache anyway.
        # Distro LLVM packages (Debian, Ubuntu) keep llvm-rc and friends in /usr/lib/llvm-N/bin, off
        # PATH; use the newest one when llvm-rc isn't already on PATH.
        if ! command -v llvm-rc >/dev/null 2>&1; then
            for dir in /usr/lib/llvm-*/bin; do
                [ ! -x "$dir/llvm-rc" ] || llvm_bin=$dir
            done
            [ -z "${llvm_bin:-}" ] || PATH="$llvm_bin:$PATH"
        fi
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
        # vitest's lcov paths are relative to ui/; the exclusion file's paths are repository-relative.
        diff_coverage "diff-coverage (ui)" ui/coverage/lcov.info .ts,.svelte --prefix ui/
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
    coverage | coverage-ratchet)
        # The tests with coverage, then the ratchet (floors above, baseline committed) and the
        # diff-coverage gate on the lcov report. `coverage-ratchet` is the same run; either raises
        # scripts/coverage-baseline.json when coverage went up (not in CI), for you to commit.
        ui_install
        target=${CARGO_TARGET_DIR:-target}
        # shellcheck disable=SC2086
        "$cargo" llvm-cov nextest --workspace $skip_app --all-features --locked \
            --profile "${NEXTEST_PROFILE:-default}" \
            --lcov --output-path "$target/lcov.info"
        "$cargo" llvm-cov report --summary-only
        "$cargo" llvm-cov report --json --summary-only --output-path "$target/coverage-summary.json"
        ratchet="--summary $target/coverage-summary.json --baseline scripts/coverage-baseline.json"
        ratchet="$ratchet --floor-lines $COV_LINES --floor-regions $COV_REGIONS"
        [ -n "${CI:-}" ] || ratchet="$ratchet --write"
        base=$(diff_base)
        # Lowering the committed baseline needs the owner's OK, recorded as this trailer in a commit
        # message of the change; the environment can't grant it.
        COVERAGE_BASELINE_LOWER_OK=0
        if [ -n "$base" ] && git log "$base..HEAD" --format=%B | grep -q '^Owner-OK: coverage-baseline$'; then
            COVERAGE_BASELINE_LOWER_OK=1
        fi
        export COVERAGE_BASELINE_LOWER_OK
        if [ -n "$base" ] && git cat-file -e "$base:scripts/coverage-baseline.json" 2>/dev/null; then
            git show "$base:scripts/coverage-baseline.json" >"$target/coverage-baseline.previous.json"
            ratchet="$ratchet --previous $target/coverage-baseline.previous.json"
        fi
        # shellcheck disable=SC2086
        node ui/scripts/coverage-ratchet.ts $ratchet
        diff_coverage "diff-coverage (rust)" "$target/lcov.info" .rs
        ;;
    diff-coverage)
        # By hand, after `coverage` and `ui` ran: both reports against the base. Untracked new
        # files are invisible to git diff; `git add -N <file>` first.
        diff_coverage "diff-coverage (rust)" "${CARGO_TARGET_DIR:-target}/lcov.info" .rs
        diff_coverage "diff-coverage (ui)" ui/coverage/lcov.info .ts,.svelte --prefix ui/
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
    fast) for g in fmt typos spdx shellcheck hooks platform-literals standalone; do run_gate "$g"; done ;;
    all) for g in fmt typos spdx shellcheck hooks platform-literals standalone git-env secrets clippy clippy-windows deny notices openapi ui ui-licences ui-audit ui-e2e doc coverage; do run_gate "$g"; done ;;
    *) run_gate "$arg" ;;
    esac
done
