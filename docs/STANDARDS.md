# puddle engineering standards

puddle is a security tool built mostly by agents, so the gates below are what make its code
trustworthy. They apply to every change, by a human or an agent. "Done" means: the behaviour is
tested at the right tiers, `scripts/check.sh` passes, and Linux CI is green on `develop`.

Contents: [layout](#1-workspace-layout) · [toolchain](#2-toolchain) · [workflow](#3-workflow-for-agents-and-humans)
· [commits](#4-commits-and-pull-requests) · [code](#5-code) · [errors](#6-error-handling) ·
[logging](#7-logging) · [testing](#8-testing) · [coverage](#9-coverage) · [CI](#10-ci) ·
[licence headers](#11-licence-headers) · [dependencies](#12-dependencies)

## 1. Workspace layout

One Cargo workspace, one crate per component of the MWE plan, so parallel work lands in
different crates and rarely collides.

| Crate | Kind | Owns | Plan |
|---|---|---|---|
| `crates/puddle-types` | lib | Shared IDs, wire types, errors that cross crate boundaries (validated names, guest files/env, memory size, events). No I/O. | all |
| `crates/puddle-settings` | lib | The settings model (T-088): global settings, per-sandbox overrides and their resolution, the consent store; versioned documents with migrations and kept unknown fields. No storage, no I/O | W3/W4 |
| `crates/puddle-compute` | lib | The compute-plane contract: `Runtime`/`Sandbox` traits, `FakeRuntime` (feature `fake`), the contract suite every runtime passes (feature `contract`). W1 rows build on it in their own crates (msb adapter, boot hook, workspace, lifecycle, ...) | W1 |
| `crates/puddle-compute-msb` | lib | The compute-plane traits over the msb SDK (the only crate that calls it): sandboxes, volumes, image pull (with puddle's registry roots, T-116), exec, SSH, the memory setting; `SDK_OPTIONS` lists every SDK option set or defaulted (D-27 review). VM tests: the contract suite, HG-01/HG-02 | W1, T-106 |
| `crates/puddle-runtime` | lib | The bundled msb runtime (D-19): runtime folder + private `MSB_HOME`, `MSB_*` environment pinning, exact `<release>-puddle.N` version check from msb's embedded `.msbver` (T-107); the proxy environment that sends msb's image pulls through puddle's pull proxy (T-116) | W1 |
| `crates/puddle-boot` | lib | Boot hook (`guest/boot.sh`, `guest/agent-supervise.sh`, POSIX sh) and the readiness gate: no SSH or exec before the hook returns 0; applies provider `GuestFile`s/env as a list (T-108) | W1 |
| `crates/puddle-netpolicy` | lib | The destination guard (T-132): strict host-name normalisation (IDNA, LDH, canonical IPs), address classes, the local-destination toggles and wildcard rule (D-1, D-37, D-44), the registry of puddle's own endpoints (D-26), block messages. Pure policy, no network I/O | W2 |
| `crates/puddle-ca` | lib | The per-sandbox CA for credential injection (T-133, D-11): name constraints as a builder input, a key that is never exported or serialised, a bounded leaf cache per sandbox (HO-4), the guest trust bundle as a list of CAs. In memory only, no I/O | W2 |
| `crates/puddle-workspace` | lib | Workspace volume lifecycle (T-112, ADR 0006): one named disk volume `ws-<id>` per workspace at `/workspaces/<id>` (checkouts in subdirectories, `.puddle/` beside them), puddle's own holder tracking (one writer, refusal names the holder), cleanup after failed creates, `fstrim` on stop and "reclaim space", delete only after the unsaved-work check (`guest/delete-check.sh`) and an explicit confirmation; short-lived maintenance sandboxes `m--<id>` for stopped workspaces | W1 |
| `crates/puddle-guest-env` | lib | Boot-time proxy config (T-109, T-030 §4): a pure function from proxy settings and the image env to the proxy `GuestEnv` and tool config `GuestFile`s (apt, sudo, Maven, Gradle, Docker CLI) the boot hook applies. No I/O | W1 |
| `crates/puddle-certs` | lib | Corporate root sync (T-110, D-24): reads the host's admin- and user-added `Root`/`CA` stores minus `Disallowed` (Windows; its `unsafe` CryptoAPI calls are in `platform/windows.rs`), selects (expired and distrusted out, each certificate once) and turns them plus puddle's CAs into guest files, env and the bundle step `guest/ca-bundle.sh` (append to the image's bundle, never replace) | W1 |
| `crates/puddle-proxy` | lib | Egress proxy: CONNECT/HTTP, pending requests, toggles, credential injection, upstream chaining, transparent capture; the image-pull proxy for puddle's own registry traffic (loopback, per-run token, guard without rules, T-116) | W1/W2 |
| `crates/puddle-store` | lib | SQLite schema and migrations, rules engine, grants, audit log, sweeper | W3 |
| `crates/puddle-api` | lib | axum API on 127.0.0.1, SSE, bearer token and Host/Origin guard, the OpenAPI contract and its generated TypeScript (`openapi/`, ADR 0004) | W4 |
| `crates/puddle-agent` | bin | Guest agent (static musl binary, ADR 0005): vsock to the host proxy | W1/W2 |
| `crates/puddle-agent-proto` | lib | Agent ↔ host wire protocol: yamux settings, stream kinds, control messages, host session, reset-preserving splice | W1/W2 |
| `crates/puddle` | bin + lib | Host program `puddle(.exe)`: CLI, daemon, wiring of the crates above | W7 |
| `crates/xtask` | bin (dev) | `cargo xtask runtime` (runtime folder from the fork release, checksums, `licenses/`), `cargo xtask notices` (third-party notices; `--check` is a gate); never shipped | W1, W7 |
| `crates/puddle-ipc` | lib | Per-sandbox host endpoints (named pipe / Unix socket) only the current user can open: owner-only DACL, first-instance check, random names, `0600` sockets in a `0700` dir (T-029 HO-1, HO-2). Its `unsafe` (Win32 security calls) is in one module, `windows/security.rs` | W1 |
| `crates/puddle-ssh` | lib | A sandbox's SSH endpoint (one runtime SSH connection per client, served only through the readiness gate, refusal line) and the `puddle ssh-bridge` relay (T-114) | W1 |
| `crates/puddle-doctor` | lib | `puddle doctor` (T-115, D-23, D-24): host prerequisites (firmware virtualization, WHP/KVM, code integrity, job object), the bundled runtime (present, permitted, exact version), msb starting, a test boot of a 132-byte probe in a tiny root file system, Global Secure Access; each finding with its exact fix, text and JSON (`schema_version`). Checks are pure over a `Probe` (faked in tests); the Win32 calls (its only `unsafe`) are in `sys/windows.rs` | W1 |
| `crates/puddle-lifecycle` | lib | Shutdown and reconcile (D-20): trim + stop of every sandbox when puddle exits, shutdown triggers (Ctrl-C, console close, signals), the front/worker split that keeps console events away from the VMs, the one kill-on-close job puddle and every msb child run in (D-27 limits go there), reconcile at start that touches only puddle-owned names. Its `unsafe` (Win32 job and console calls) is in `windows/sys.rs` (T-113) | W1 |
| `crates/puddle-e2e` | lib (tests) | Harness for end-to-end and hostile-guest tests; never a dependency of product crates | W7, T-035 |
| `crates/puddle-vm-tests` | lib (tests) | VM test harness on the msb SDK: per-run prefix, private msb home, runtime pair, scoped backend; the `vm_*` tests of tiers K/W/L. Never a dependency of product crates | W1, T-102 |

Later, not yet created: the Svelte UI (`ui/`, W5) and the Tauri shell (`crates/puddle-app` or
`src-tauri/`, W8).

**Dependency direction.** `puddle-types` ← `compute`, `proxy`, `store`, `settings` ← `api` ← `puddle`.
`netpolicy` depends on `types` and `settings`; `proxy` depends on `netpolicy` for its destination checks.
`proxy` and `store` don't depend on each other's internals: the proxy asks for decisions through a
trait defined in `puddle-types` (or the proxy crate) that `store` implements, and `puddle` wires
them. `puddle-agent` depends on `puddle-types` and `puddle-agent-proto` only (it is built for the guest); the host side (`proxy`) uses `puddle-agent-proto` too, and `puddle-ipc` for the per-sandbox route it listens on. No cycles, no
product crate depends on `puddle-e2e` or `puddle-vm-tests`.

**New crate:** only when a component doesn't fit the table (say why in the commit). Copy an
existing `Cargo.toml` (all `*.workspace = true` fields, `[lints] workspace = true`), add it to
`[workspace.dependencies]` if others use it, and add a row here.

**Inside a crate:** `src/lib.rs` keeps the public API small; modules by concept, not by kind
(`pending.rs`, not `structs.rs`). Binaries keep `main.rs` thin and put logic in the library so it
is unit-testable (see `crates/puddle/src/cli.rs`).

## 2. Toolchain

- Rust **1.99.0**, pinned in `rust-toolchain.toml`, edition **2024**, `rust-version = "1.99"`.
  Bumping it is its own commit (`build: bump toolchain to 1.x`), with every gate green on Linux
  and Windows.
- Windows releases are built with native MSVC in CI (D-35). Locally, `cargo-xwin` cross-builds the
  MSVC target from WSL; `scripts/check.sh clippy-windows` cross-checks without linking, through
  `cargo xwin clippy` so C dependencies (bundled SQLite) compile too. It needs `clang` on `PATH`
  (a distro `clang` package, or a conda-forge `clang` environment); cargo-xwin links it as
  `clang-cl` and uses the toolchain's `llvm-tools` as `llvm-lib`.
- Gate tools: `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `typos-cli`, `cargo-xwin`, `shellcheck`, `cargo-about` (with `--features cli`) (versions pinned in
  `.github/workflows/ci.yml`; use the same or newer locally).
- **Node** (22 or newer, CI uses 24) for one gate: `scripts/check.sh openapi` regenerates the API
  contract's TypeScript types with `openapi-typescript` (pinned in
  `crates/puddle-api/openapi/package-lock.json`) and compares them with the committed
  `schema.d.ts`. Without Node the gate checks `openapi.json` only and says so; CI (`CI` set)
  fails instead. After changing a route or a wire type, run `cargo xtask openapi` and commit
  both files.
- **Shared build cache** (optional, local only): `scripts/check.sh` runs Cargo as `$CARGO`
  (default `cargo`). With [mbx](https://mr-boxington.jdx.dev/) installed, run
  `CARGO=mbx MBX_CACHE_DIR=<one shared dir> scripts/check.sh` (and `mbx build|test|...` instead of
  `cargo ...`), so parallel worktrees share compiled output and one CPU/memory budget. Keep your
  own `CARGO_TARGET_DIR`; mbx leaves it alone. Cached files are read-only hard links: delete the
  cache with `mbx gc` or after `chmod -R u+w`. Don't export `CARGO=mbx` in your shell: mbx finds
  Cargo through `$CARGO` and would call itself. CI runs plain `cargo`.

## 3. Workflow for agents and humans

`develop` is the working branch and has no protection; `main` holds released versions only.
Work lands on `develop` as a **fast-forward**, never as a merge commit or a force-push.

1. **Own worktree, own branch.** From the clone:
   `git worktree add ../wt/<task> -b task/<task> origin/develop`. Use your own target dir
   (`CARGO_TARGET_DIR=<somewhere>/target/<task>`) so parallel builds don't block each other on the
   cargo lock. Set the identity in the worktree (`git config user.name`, `user.email`) if the
   clone's isn't the project one.
2. **Enable the hooks** once per clone: `git config core.hooksPath .githooks` (pre-commit runs the
   fast gates, pre-push runs all). Never skip them with `--no-verify`.
3. **Stay in your crate.** Touch other crates only where the task needs it; changes to shared files
   (`Cargo.toml`, `Cargo.lock`, `puddle-types`, this file, CI) are kept small and land early, in
   their own commit, because they are where parallel tasks collide.
4. **Test first where it pays** (D-22: risk tests first): write the test that pins the risky
   behaviour, see it fail, then make it pass.
5. **Land:** `scripts/check.sh` green → `git fetch origin` → `git rebase origin/develop` →
   `scripts/check.sh` again if the rebase pulled in changes → `git push origin HEAD:develop`.
   Rejected because someone landed first: fetch, rebase, retest, push again. Never `--force` on
   `develop` or `main`. Rebasing your own unpublished task branch is fine.
6. **Check CI** for your push (`gh run list --branch develop`, `gh run watch <id>`). A red run on
   `develop` is fixed before anything else lands on top of it, by whoever broke it.
7. **Clean up:** remove the worktree and its target dir when the task is done.

**Releases:** a pull request from `develop` to `main` (this also runs the Windows job), merged by
the owner, then tagged `vX.Y.Z` on `main`.

## 4. Commits and pull requests

- **Conventional Commits:** `<type>(<scope>): <summary>`, imperative, ≤ 72 characters. Types:
  `feat`, `fix`, `test`, `refactor`, `perf`, `docs`, `build` (Cargo, toolchain, dependencies),
  `ci`, `chore`. Scope = the crate without the `puddle-` prefix (`proxy`, `store`, `compute`,
  `api`, `agent`, `types`, `cli`, `e2e`), or `ws` for workspace-wide changes.
- The body says **why**, and names the task or decision (`T-123`, `D-47`) when there is one.
- One logical change per commit; code and its tests in the same commit. Every commit on `develop`
  builds and passes the gates (so `git bisect` works).
- Author: the project identity (`Tijs van Kampen <puddle@tijsvankampen.be>`). Agent-written
  commits end with a `Co-Authored-By:` trailer naming the model.
- No secrets, tokens, personal paths or client names in code, tests, fixtures, logs or messages.
- Pull requests (external contributors, releases) use the template in `.github/` and need the CLA
  ([CONTRIBUTING.md](../CONTRIBUTING.md)).

## 5. Code

- **Lints** (`[workspace.lints]` in `Cargo.toml`): clippy `pedantic` plus a set of restriction
  lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `todo`, `print_stdout`, …),
  all denied in CI with `-D warnings`. To silence one, use `#[expect(lint, reason = "…")]` on the
  smallest item; never `#[allow]` (itself linted), never crate-wide without a written reason.
  Tests may unwrap, expect, panic and index (`clippy.toml`).
- **Unsafe:** every crate root says `#![forbid(unsafe_code)]`. A crate that needs FFI (Windows
  pipe DACLs, say) removes the `forbid`, keeps the workspace `deny`, and puts each `unsafe` block
  in one small module behind `#[expect(unsafe_code, reason = "…")]` with a `// SAFETY:` comment
  (`undocumented_unsafe_blocks` is on) and tests for it.
- **No panics in product code.** Return errors. `expect` only for true invariants, with
  `#[expect(clippy::expect_used, reason = "…")]` and a message that states the invariant.
- **Docs:** every public item has a doc comment (`missing_docs`); fallible public functions have an
  `# Errors` section, panicking ones a `# Panics` section. Doc examples are tests.
- **Async:** tokio. Never block in async code (`spawn_blocking` for blocking I/O and SQLite).
  Every network wait has a timeout; every spawned task has an owner that ends it on shutdown.
- **Platforms:** host code builds and is tested on Linux and Windows. Platform code lives behind
  `#[cfg(windows)]` / `#[cfg(unix)]` in its own module with the same interface on both, so the
  logic above it is tested on both. Use `std::path`, never string-joined paths.
- **Security-sensitive code** (proxy decisions, credential injection, address classification, API
  auth, pipe/socket permissions, anything parsing guest input): treat all guest input as hostile,
  fail closed (deny on error), and add a hostile-guest test (§8) with the change.
- **Secrets** (credentials, API tokens) are wrapped in a type whose `Debug`/`Display` redact
  (e.g. `secrecy::SecretString`), never logged, never in errors, never in test snapshots.

## 6. Error handling

- **Libraries:** typed errors with `thiserror`, one error enum per module or concern, variants
  that say what failed and carry the context needed to act (`path`, `sandbox`, `host`). Errors
  that cross crates live in `puddle-types` or are converted at the boundary.
- **Binaries:** `puddle` maps errors to a user message and an exit code at the top; it may use
  `anyhow` only in `main`-level glue, never in the libraries.
- Don't stringly-type errors, don't discard them (`let _ =` on a `Result` needs a comment), and
  don't log *and* return the same error (the handler that consumes it logs it).
- Error messages are lower-case, no trailing period, and never contain secret values.

## 7. Logging

- `tracing` everywhere; `tracing-subscriber` is set up only in binaries. No `println!` outside CLI
  output (linted).
- Structured fields, not formatted strings: `info!(sandbox = %id, host, "request approved")`.
  Spans per sandbox and per proxied connection so a log line can be traced to its request.
- Levels: `error` = puddle can't do what the user asked; `warn` = degraded or retried; `info` =
  lifecycle and decisions (one line per approve/deny); `debug` = per-request detail; `trace` =
  bytes and protocol frames (never on by default).
- **Never log** header values, credentials, tokens, cookies, request bodies, or full URLs with
  query strings (T-002). Hostnames and ports are fine. Tests assert this (§8, redaction).
- The **audit log** (store, W3) is a product feature with its own schema and tests, not a
  `tracing` target.

## 8. Testing

### Tiers (T-032)

| Tier | What | Where it lives | Runs |
|---|---|---|---|
| L0 static | fmt, clippy (Linux + msvc), deny, typos, SPDX, shellcheck, rustdoc, API contract | `scripts/check.sh` | every push, every PR |
| L1 unit | one module's logic: parsers, rules, state machines, address classifier, path handling | `#[cfg(test)] mod tests` in the same file | every push (Linux), nightly + PRs to `main` (Windows) |
| L2 integration, no VM | real proxy + real agent over a Unix socket / named pipe, fake guest client, fake upstreams; API over loopback; the hostile-guest **tier P** | `crates/<crate>/tests/*.rs`; cross-crate ones in `crates/puddle-e2e/tests/` | every push |
| L3 Linux KVM e2e (**K**) | a real msb microVM; MWE behaviours; hostile-guest **tier V** | `crates/puddle-vm-tests/tests/`, functions or files named `vm_*` | `vm-linux.yml`: by hand on any branch, nightly on `develop` |
| L4 Windows e2e (**W**) | the L3 scenarios on WHP plus Windows-only paths; hostile-guest **tier W** | same crate, same names | `vm-windows.yml` on the hosted `windows-2025` runner: by hand on any branch, nightly on `develop` |
| L4 laptop (**L**) | what hosted runners can't show: real client OS, mains power, sleep/resume, Defender, corporate network | same crate, named `vm_laptop_*` | `ci/windows-e2e.ps1` on the laptop, posts the `puddle/windows-e2e` status; before a release (D-28) |
| L5 manual | VS Code attach, sleep/resume, network drop | release checklist | each release candidate |

### Rules

- **New behaviour is tested at the lowest tier that can catch its bug, plus the tier that proves it
  works end to end.** A bug fix starts with a test that reproduces it.
- **Hostile-guest cases** (T-029 §6, suite T-035): every case is a named test (`hostile_<id>_…`)
  asserting on the audit log, the API and the fake upstream's record. Write the tier P version
  with the feature; V and W follow as VM tests on the `puddle-vm-tests` harness, named
  `vm_hostile_<id>_…` so the VM profile picks them up.
- **Property tests** (`proptest`) for every parser and classifier that sees guest or network input;
  fuzz targets for the same once `cargo-fuzz` is set up.
- **Deterministic:** no `sleep` to wait for something (wait on the event, with a timeout); no real
  internet in gated tests (local fixtures with fixed responses, D-31); bind port 0; temp dirs per
  test; per-test `MSB_HOME` and unique sandbox/pipe names; no dependence on test order.
- **VM tests** are named `vm_*` (function or test file). The default and `ci` nextest profiles leave
  them out, so the gates never need KVM; `cargo nextest run -p puddle-vm-tests --profile vm` runs
  only them, one at a time, never retried (`.config/nextest.toml`). They need
  `PUDDLE_VM_RUNTIME_DIR` (msb + libkrunfw, from `ci/fetch-msb.sh`), and take `PUDDLE_VM_PREFIX`
  and `PUDDLE_VM_ROOT`; every sandbox name and the private msb home carry the prefix, so up to three
  runs share a host. Laptop-only tests are named `vm_laptop_*`.
- **Redaction:** tests that handle a credential use a canary value and assert it never appears in
  logs, errors, audit entries or the guest's view.
- **Flaky tests:** nextest never retries (`retries = 0`). A test that fails without a code change
  is fixed or quarantined within a day (still runs, doesn't gate, linked issue, max 14 days).
  Proxy, transparency and security tests can't be quarantined: a flaky one is the bug (D-2).
- Test names say the behaviour: `denied_request_is_held_until_approved`, not `test_pending_2`.

## 9. Coverage

- Measured by `cargo llvm-cov nextest` over the whole workspace on Linux, in every CI run.
- **Gate: lines ≥ 85 %, regions ≥ 80 %** (workspace totals, `scripts/check.sh`). The thresholds
  only go up; lowering one needs the owner's OK.
- **Expectation above the gate:** security-sensitive modules (§5) aim for ≥ 95 % lines, and every
  branch of a decision (allow/deny/pending, each toggle) has a test. A change that lowers a
  crate's coverage says why in the commit.
- Code that can't run in CI (Windows-only code on Linux, VM paths) is covered by its own tier
  (Windows job, L3/L4), not excluded. Exclusions from the report (`--ignore-filename-regex`) only
  for generated code, listed in `scripts/check.sh` with a comment.

## 10. CI

| Workflow | Trigger | Runner | Gates |
|---|---|---|---|
| `ci.yml` | push to `develop`/`main`, every PR, manual | `ubuntu-24.04` | all of `scripts/check.sh all` in one job; every gate runs even if an earlier one fails |
| `windows.yml` | nightly 02:30 UTC (skipped if unchanged since the last green nightly), PRs to `main`, manual | `windows-2025` | clippy, nextest, doc tests, release build (MSVC) |
| `vm-linux.yml` | manual on any branch (`gh workflow run vm-linux.yml --ref <branch>`), nightly 03:00 UTC on `develop` (skipped if unchanged) | `ubuntu-24.04` (KVM) | VM tests, tier K; no KVM ⇒ warning, infrastructure skip |
| `vm-windows.yml` | manual on any branch, nightly 03:15 UTC on `develop` (skipped if unchanged) | `windows-2025` (WHP) | VM tests, tier W; no WHP ⇒ warning, infrastructure skip |
| Dependabot | weekly, grouped | — | opens PRs to `develop` |

The repo is public, so standard hosted runners are free and have no minute quota. They are still
shared: keep jobs lean, don't add triggers without a reason, and keep Windows on nightly/PR-to-main.
Actions are pinned to commit SHAs; workflows get `contents: read` unless they need more.
VM jobs never run per push: dispatch them on your task branch when your change needs K/W evidence.
The msb runtime they boot is the SDK's fork tag (`ci/msb-tag.sh`, read from `Cargo.lock`): release
assets pinned by SHA-256 in `ci/msb-runtime.sha256`, and on Linux, where the fork releases no msb,
a build of the tag's pinned commit. Bumping the fork tag: see the comment above the SDK lines in
the root `Cargo.toml`; `puddle-runtime`'s expected version follows from the lock.

## 11. Licence headers

Every source file starts with `SPDX-License-Identifier: GPL-3.0-or-later` in its own comment
syntax (after a shebang, if any); manifests carry `license = "GPL-3.0-or-later"` through the
workspace. `scripts/check-spdx.sh` enforces it. Details and third-party files:
[CONTRIBUTING.md](../CONTRIBUTING.md#licence-headers).

## 12. Dependencies

- Declare versions once, in `[workspace.dependencies]`; crates use `dep = { workspace = true }`.
  Turn off default features you don't need.
- `cargo deny check` gates licences (only GPL-3.0-or-later-compatible ones, list in `deny.toml`),
  advisories (any RustSec advisory or yanked crate fails), bans (no wildcards) and sources
  (crates.io only; puddle's own forks on GitHub once added, D-53). An exception names the advisory
  or crate, the reason and a review date.
- **Third-party notices:** `cargo xtask notices --check` (gate `notices`) fails when a shipped
  dependency has no licence entry in cargo-about's report (`about.toml`, whose `accepted` list
  mirrors `deny.toml`). Release notices for puddle and the bundled msb come from
  `cargo xtask runtime` (D-35).
- Prefer well-maintained crates already in the tree; a new dependency is justified in its commit.
- Never copy code from Huddle (D-54); code from elsewhere follows CONTRIBUTING's "Work you did not
  write".
