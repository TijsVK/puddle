# puddle engineering standards

puddle is a security tool built mostly by agents, so the gates below are what make its code
trustworthy. They apply to every change, by a human or an agent. "Done" means: the behaviour is
tested at the right tiers, `scripts/check.sh` passes, Linux CI is green on `develop`, and the change
keeps the product [principles](principles.md) (a change that would break one doesn't land; open an
issue instead).

Contents: [layout](#1-workspace-layout) · [toolchain](#2-toolchain) · [workflow](#3-workflow-for-agents-and-humans)
· [commits](#4-commits-and-pull-requests) · [code](#5-code) · [errors](#6-error-handling) ·
[logging](#7-logging) · [testing](#8-testing) · [coverage](#9-coverage) · [CI](#10-ci) ·
[licence headers](#11-licence-headers) · [dependencies](#12-dependencies) · [the UI](#13-the-ui-ui)

## 1. Workspace layout

One Cargo workspace, one crate per component, so parallel work lands in
different crates and rarely collides.

| Crate | Kind | Owns |
|---|---|---|
| `crates/puddle-types` | lib | Shared IDs, wire types, errors that cross crate boundaries (validated names, guest files/env, memory size, events). No I/O. |
| `crates/puddle-settings` | lib | The settings model: global settings, per-workspace overrides and their resolution, the consent store; versioned documents with migrations and kept unknown fields. No storage, no I/O |
| `crates/puddle-compute` | lib | The compute-plane contract: `Runtime`/`Sandbox` traits, `FakeRuntime` (feature `fake`), the contract suite every runtime passes (feature `contract`). Other crates build on it (msb adapter, boot hook, workspace, lifecycle, ...) |
| `crates/puddle-compute-msb` | lib | The compute-plane traits over the msb SDK (the only crate that calls it): sandboxes, volumes, image pull (with puddle's registry roots), exec, SSH, the memory setting; `SDK_OPTIONS` lists every SDK option set or defaulted (input to a sandbox-escape review). VM tests: the contract suite and the hostile-guest cases |
| `crates/puddle-runtime` | lib | The bundled msb runtime: runtime folder + private `MSB_HOME`, `MSB_*` environment pinning, the per-OS runtime file-name table and `GuestArch` (`check.sh platform-literals` keeps the names out of other crates), exact `<release>-puddle.N` version check from msb's embedded `.msbver`; the proxy environment that sends msb's image pulls through puddle's pull proxy |
| `crates/puddle-boot` | lib | Boot hook (`guest/boot.sh`, `guest/agent-supervise.sh`, POSIX sh) and the readiness gate: no SSH or exec before the hook returns 0; applies provider `GuestFile`s/env as a list, and git author rules by remote (`includeIf hasconfig:remote.*.url`, one author file per rule) |
| `crates/puddle-netpolicy` | lib | The destination guard: strict host-name normalisation (IDNA, LDH, canonical IPs), address classes, the local-destination toggles and wildcard rule, the registry of puddle's own endpoints, block messages. Pure policy, no network I/O |
| `crates/puddle-ca` | lib | The per-workspace CA for credential injection: no name constraint (the decrypt set is the limit), `pathLen 0`, DNS names only, a key that is never exported or serialised, a bounded leaf cache per workspace, the guest trust bundle as a list of CAs. In memory only, no I/O |
| `crates/puddle-secrets` | lib | Where the host gets a secret: a closed list of sources (signed-in `gh` account, one Git credential URL with its path, a pasted token in the OS store under puddle's own name) behind one `Fetch` interface, run with every prompt off and a time limit; an in-memory cache with expiry; a fixed list of listing commands that return account names only. A source that needs a login is an error, never a window; only the user's own click can start a sign-in (`SignIns`: `gh auth login --web`, or Git Credential Manager allowed to open its window) |
| `crates/puddle-workspace` | lib | Workspace volume lifecycle (ADR 0006): one named disk volume `ws-<id>` per workspace at `/workspaces/<id>` (checkouts in subdirectories, `.puddle/` beside them), puddle's own holder tracking (one writer, refusal names the holder), cleanup after failed creates, `fstrim` on stop and "reclaim space", delete only after the unsaved-work check (`guest/delete-check.sh`) and an explicit confirmation; short-lived maintenance sandboxes `m--<id>` for stopped workspaces |
| `crates/puddle-guest-env` | lib | Boot-time proxy config: a pure function from proxy settings and the image env to the proxy `GuestEnv` and tool config `GuestFile`s (apt, sudo, Maven, Gradle, Docker CLI) the boot hook applies. No I/O |
| `crates/puddle-certs` | lib | Corporate root sync: reads the host's admin- and user-added `Root`/`CA` stores minus `Disallowed` (Windows; its `unsafe` CryptoAPI calls are in `platform/windows.rs`), selects (expired and distrusted out, each certificate once) and turns them plus puddle's CAs into guest files, env and the bundle step `guest/ca-bundle.sh` (append to the image's bundle, never replace) |
| `crates/puddle-proxy` | lib | Egress proxy: CONNECT/HTTP, pending requests, toggles, TLS termination of bound hosts (`terminate`: guest leg, upstream leg, the `Injector` hook, the registry of secret stand-ins swapped for their real values; no credential injection logic yet), the registry of what each workspace decrypts (changed while it runs), upstream chaining, transparent capture; the image-pull proxy for puddle's own registry traffic (loopback, per-run token, guard without rules) |
| `crates/puddle-upstream` | lib | The company proxy in front of puddle: discovery (WinINet, WinHTTP PAC/WPAD, policy, env, per-epoch cache, change notification) in `discovery`; the chained connect (route hops, `CONNECT`/absolute form, `407` loop, Basic, host-side `host::connect`) in `chain`; TLS on top of it (`TlsClient`, `tls_connect`: the platform verifier plus corporate roots) in `tls`; proxy sign-in: the portable Negotiate/NTLM protocol over a `TokenSource` in `negotiate`, Windows SSPI as the logged-on user in `windows/sspi.rs`, the `ProxyAuth` seam (`NoAuth` on Unix) in `auth`; a snapshot for the network-health report (`Discovery::health`, `Chain::sign_ins`) in `health` and `signin`, with `redact` for text that comes from outside; feature `testing` has `FakeOs` and a scripted `FakeProxy` |
| `crates/puddle-store` | lib | SQLite schema and migrations, rules engine, grants, audit log, sweeper; Git identities (author, credential references, what each covers) and each workspace's identities, repository table and push and pull switches |
| `crates/puddle-api` | lib | axum API on 127.0.0.1, SSE, bearer token and Host/Origin guard, the OpenAPI contract and its generated TypeScript (`openapi/`, ADR 0004); serves the built UI from the same origin (feature `embedded-ui`); the network-health report (`GET /api/network-health`) is built from `puddle-upstream` and `puddle-certs` in `network_health` |
| `crates/puddle-agent` | bin | Guest agent (static musl binary, ADR 0005): vsock to the host proxy; the stub DNS and stand-in table for tools that ignore the proxy settings (`capture/`) |
| `crates/puddle-agent-proto` | lib | Agent ↔ host wire protocol: yamux settings, stream kinds, control messages, the `resolve` lookup stream, host session, reset-preserving splice |
| `crates/puddle` | bin + lib | Host program `puddle(.exe)`: CLI (`doctor`, `ssh-bridge`, `serve` around `puddle-host`) |
| `crates/xtask` | bin (dev) | `cargo xtask runtime` (runtime folder from the fork release, checksums, `licenses/`), `cargo xtask notices` (third-party notices; `--check` is a gate); never shipped |
| `crates/puddle-fs` | lib | Per-OS file-system seams: `data_dir()` (the `dirs` crate: `%LOCALAPPDATA%\puddle`, `$XDG_DATA_HOME/puddle`, `~/Library/Application Support/puddle`) and `private` (owner-only files and folders: `0600`/`0700` on Unix; on Windows a protected ACL with one entry for the current user, set at creation). Its `unsafe` (Win32 security calls) is in one module, `win`, which `puddle-ipc` shares for its pipe descriptor. Own crate because both the API and the runtime layout need it and neither may depend on the other |
| `crates/puddle-ipc` | lib | Per-workspace host endpoints (named pipe / Unix socket) only the current user can open: owner-only DACL, first-instance check, random names, `0600` sockets in a `0700` dir. Its only `unsafe` is creating a pipe with a security descriptor (`windows/security.rs`); the descriptor helpers come from `puddle-fs` |
| `crates/puddle-ssh` | lib | A workspace's SSH endpoint (one runtime SSH connection per client, served only through the readiness gate, refusal line) and the `puddle ssh-bridge` relay |
| `crates/puddle-doctor` | lib | `puddle doctor`: host prerequisites (firmware virtualization, WHP/KVM, code integrity, job object), the bundled runtime (present, permitted, exact version), msb starting, a test boot of a 132-byte probe in a tiny root file system, Global Secure Access; each finding with its exact fix, text and JSON (`schema_version`). Checks are pure over a `Probe` (faked in tests); the Win32 calls (its only `unsafe`) are in `sys/windows.rs` |
| `crates/puddle-lifecycle` | lib | Shutdown and reconcile: trim + stop of every sandbox when puddle exits, shutdown triggers (Ctrl-C, console close, signals), the front/worker split that keeps console events away from the VMs, the one kill-on-close job puddle and every msb child run in (resource limits for sandbox escapes go there), reconcile at start that touches only puddle-owned names. Its `unsafe` (Win32 job and console calls) is in `windows/sys.rs` |
| `crates/puddle-host` | lib | The host process as a library, the one composition root: a synchronous `prepare` (bind the image-pull proxy, pin the process environment, check the runtime pin, read the corporate roots) and an asynchronous `Host::start` (store, settings files, upstream chain with system sign-in then Basic, runtime, reconcile, pull proxy, sweeper, workspace service, API last) with a documented `Step` order for start and for shutdown (refuse operations, finish them, trim and stop every sandbox, close routes, stop the API). Holds the real `WorkspaceService` over `puddle-workspace`, `puddle-boot`, the egress route and the SSH endpoint, and the file-backed settings and workspace list. `puddle serve` and the desktop app both embed it; the machine and the runtime are traits so the order is tested on fakes. Credential injection wiring: a CA for each running sandbox (in memory, dropped at stop) whose certificate goes into the guest's trust, the registry of what each workspace decrypts (from its identities' credential hosts, recomputed when they change), the commit authors in the guest by remote (rewritten live), and the injector and secret cache every workspace shares |
| `crates/puddle-app` | bin + lib | The desktop shell: Tauri 2 around the SPA that `puddle-api` serves from its own origin; the backend runs in-process (the in-memory fixture for now). The main window has no Tauri permissions (an empty capability for the label `main`, an app ACL manifest in `build.rs`, tests in `tests/acl.rs`), stays on the API origin (`navigation.rs`) and gets the token from a start-up script. Linux builds need `libwebkit2gtk-4.1-dev`; a smoke test (`e2e/smoke.mjs`, over WebView2's DevTools Protocol) runs in the `windows` workflow |
| `crates/puddle-e2e` | lib (tests) + bin `puddle-ui-fixture` | Harness for end-to-end and hostile-guest tests, and the UI fixture backend (section 13); never a dependency of product crates |
| `crates/puddle-vm-tests` | lib (tests) | VM test harness on the msb SDK: per-run prefix, private msb home, runtime pair, scoped backend; the `vm_*` tests of tiers K/W/R. Never a dependency of product crates |

`ui/` is the Svelte single-page app (section 13), not a crate.

**Dependency direction.** `puddle-types` ← `compute`, `proxy`, `store`, `settings` ← `api` ← `puddle`.
`netpolicy` depends on `types` and `settings`; `proxy` depends on `netpolicy` for its destination checks.
`proxy` and `store` don't depend on each other's internals: the proxy asks for decisions through a
trait defined in `puddle-types` (or the proxy crate) that `store` implements, and `puddle` wires
them. `puddle-agent` depends on `puddle-types` and `puddle-agent-proto` only (it is built for the guest); the host side (`proxy`) uses `puddle-agent-proto` too, and `puddle-ipc` for the per-workspace route it listens on. No cycles, no
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
- Windows releases are built with native MSVC in CI. Locally, `cargo-xwin` cross-builds the
  MSVC target from Linux; `scripts/check.sh clippy-windows` cross-checks without linking, through
  `cargo xwin clippy` so C dependencies (bundled SQLite) compile too. It needs `clang` on `PATH`
  (a distro `clang` package, or a conda-forge `clang` environment) and `llvm-rc` (the shell's Windows resources, `tauri-winres`). The gate adds the newest `/usr/lib/llvm-*/bin` (Debian and Ubuntu `llvm` package) to `PATH` when `llvm-rc` isn't on it; cargo-xwin links it as
  `clang-cl` and uses the toolchain's `llvm-tools` as `llvm-lib`.
- Gate tools: `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `typos-cli`, `cargo-xwin`, `shellcheck`, `cargo-about` (with `--features cli`) (versions pinned in
  `.github/workflows/ci.yml`; use the same or newer locally).
- **gitleaks** for the `secrets` gate (secret scanning, below): the version is pinned with a SHA-256 per
  platform in `ci/gitleaks.sha256` and the gate refuses any other. `ci/fetch-gitleaks.sh <dir on PATH>`
  downloads, verifies and installs it (Linux, macOS, Git Bash on Windows). It is a Go binary, not a Cargo
  or npm dependency, so `cargo deny` and the notices don't see it; it is MIT-licensed and only run, never shipped.
- **Node** (22 or newer, CI uses 24) for one gate: `scripts/check.sh openapi` regenerates the API
  contract's TypeScript types with `openapi-typescript` (pinned in
  `crates/puddle-api/openapi/package-lock.json`) and compares them with the committed
  `schema.d.ts`. Without Node the gate checks `openapi.json` only and says so; CI (`CI` set)
  fails instead. After changing a route or a wire type, run `cargo xtask openapi` and commit
  both files.
- **Node 24** also runs the UI gates (`ui/`, section 13): `scripts/check.sh ui ui-licences ui-audit
  ui-e2e`. Every npm package is pinned to an exact version in `ui/package.json` and
  `ui/package-lock.json`. `ui-e2e` needs Playwright's browsers (`cd ui && npx playwright install
  --with-deps chromium webkit`); where WebKit can't start locally it runs Chromium only and says so.
- **WebKitGTK** (Linux only) for `crates/puddle-app`: `sudo apt install libwebkit2gtk-4.1-dev`. CI installs it.
  Without it and outside CI, `scripts/check.sh` skips that one crate in its Linux gates (clippy, tests, docs,
  coverage) and says so; `clippy-windows` still checks it for the msvc target. Windows needs WebView2, which
  current Windows has.
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
4. **Test first where it pays** (risk tests first): write the test that pins the risky
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
- The body says **why**; cite an ADR or spec section when one applies. Never refer to private planning
  notes: no task or decision IDs (the `commit-msg` hook rejects `T-NNN`/`D-NN`).
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
  logic above it is tested on both. Use `std::path`, never string-joined paths. Per-OS code is for
  genuine OS integration only; a workaround for a dependency's bug goes in our fork or an upstream
  draft, with a task to remove any stopgap. Prefer a maintained crate (licence- and
  `cargo deny`-clean, light tree) over our own per-OS code. Linux and macOS are separate cases:
  `cfg(unix)` is not "Linux".
- **Security-sensitive code** (proxy decisions, credential injection, address classification, API
  auth, pipe/socket permissions, anything parsing guest input): treat all guest input as hostile,
  fail closed (deny on error), and add a hostile-guest test (§8) with the change.
- **Secrets** (credentials, API tokens) are wrapped in a type whose `Debug`/`Display` redact
  (e.g. `secrecy::SecretString`), never logged, never in errors, never in test snapshots.
- **Secret scanning:** `scripts/check.sh secrets` (pre-push and CI) runs gitleaks over every commit with
  the default rules plus `.gitleaks.toml`. Test credentials are made-up values, kept recognisable
  (`CANARY-<word>`, `user:puddle`), and need no special treatment unless a scanner flags them. A flagged
  fake gets an allowlist entry that fits its exact path and value, with the reason in the entry; the
  fixture itself stays as it is. The gate's self-test (`scripts/check-secrets.sh --self-test`) proves a
  real-shaped token fails and a listed fake passes. External scanners (GitGuardian on the public
  repository) may flag fakes the gate doesn't; dismiss those as false positives, don't rewrite the test.
  A real secret that reached a commit is rotated first, then removed.

## 6. Error handling

- **Libraries:** typed errors with `thiserror`, one error enum per module or concern, variants
  that say what failed and carry the context needed to act (`path`, `workspace`, `host`). Errors
  that cross crates live in `puddle-types` or are converted at the boundary.
- **Binaries:** `puddle` maps errors to a user message and an exit code at the top; it may use
  `anyhow` only in `main`-level glue, never in the libraries.
- Don't stringly-type errors, don't discard them (`let _ =` on a `Result` needs a comment), and
  don't log *and* return the same error (the handler that consumes it logs it).
- Error messages are lower-case, no trailing period, and never contain secret values.

## 7. Logging

- `tracing` everywhere; `tracing-subscriber` is set up only in binaries. No `println!` outside CLI
  output (linted).
- Structured fields, not formatted strings: `info!(workspace = %id, host, "request approved")`.
  Spans per workspace and per proxied connection so a log line can be traced to its request.
- Levels: `error` = puddle can't do what the user asked; `warn` = degraded or retried; `info` =
  lifecycle and decisions (one line per approve/deny); `debug` = per-request detail; `trace` =
  bytes and protocol frames (never on by default).
- **Never log** header values, credentials, tokens, cookies, request bodies, or full URLs with
  query strings. Hostnames and ports are fine. Tests assert this (§8, redaction).
- The **audit log** (store) is a product feature with its own schema and tests, not a
  `tracing` target.

## 8. Testing

### Tiers

| Tier | What | Where it lives | Runs |
|---|---|---|---|
| L0 static | fmt, clippy (Linux + msvc), deny, typos, SPDX, shellcheck, secrets (gitleaks), standalone (no planning-note references), rustdoc, API contract | `scripts/check.sh` | every push, every PR |
| L1 unit | one module's logic: parsers, rules, state machines, address classifier, path handling | `#[cfg(test)] mod tests` in the same file | every push (Linux), nightly + PRs to `main` (Windows) |
| L2 integration, no VM | real proxy + real agent over a Unix socket / named pipe, fake guest client, fake upstreams; API over loopback; the hostile-guest **tier P** | `crates/<crate>/tests/*.rs`; cross-crate ones in `crates/puddle-e2e/tests/` | every push |
| L3 Linux KVM e2e (**K**) | a real msb microVM; the product's behaviours; hostile-guest **tier V** | `crates/puddle-vm-tests/tests/`, functions or files named `vm_*` | `vm-linux.yml`: by hand on any branch, nightly on `develop` |
| L4 Windows e2e (**W**) | the L3 scenarios on WHP plus Windows-only paths; hostile-guest **tier W** | same crate, same names | `vm-windows.yml` on the hosted `windows-2025` runner: by hand on any branch, nightly on `develop` |
| L4 real machine (**R**) | what hosted runners can't show: real client OS, mains power, sleep/resume, Defender, corporate network | same crate, named `vm_machine_*` | `ci/windows-e2e.ps1` on a real Windows machine, posts the `puddle/windows-e2e` status; before a release |
| L5 manual | VS Code attach, sleep/resume, network drop | release checklist | each release candidate |

### Rules

- **New behaviour is tested at the lowest tier that can catch its bug, plus the tier that proves it
  works end to end.** A bug fix starts with a test that reproduces it.
- **Hostile-guest cases** (the hostile-guest suite): every case is a named test (`hostile_<id>_…`)
  asserting on the audit log, the API and the fake upstream's record. Write the tier P version
  with the feature; V and W follow as VM tests on the `puddle-vm-tests` harness, named
  `vm_hostile_<id>_…` so the VM profile picks them up.
- **Property tests** (`proptest`) for every parser and classifier that sees guest or network input;
  fuzz targets for the same once `cargo-fuzz` is set up.
- **Deterministic:** no `sleep` to wait for something (wait on the event, with a timeout); no real
  internet in gated tests (local fixtures with fixed responses); bind port 0; temp dirs per
  test; per-test `MSB_HOME` and unique sandbox/pipe names; no dependence on test order.
- **VM tests** are named `vm_*` (function or test file). The default and `ci` nextest profiles leave
  them out, so the gates never need KVM; `cargo nextest run -p puddle-vm-tests --profile vm` runs
  only them, one at a time, never retried (`.config/nextest.toml`). They need
  `PUDDLE_VM_RUNTIME_DIR` (msb + libkrunfw, from `ci/fetch-msb.sh`), and take `PUDDLE_VM_PREFIX`
  and `PUDDLE_VM_ROOT`; every sandbox name and the private msb home carry the prefix, so up to three
  runs share a host. Real-machine tests are named `vm_machine_*`.
- **Redaction:** tests that handle a credential use a canary value and assert it never appears in
  logs, errors, audit entries or the guest's view.
- **Flaky tests:** nextest never retries (`retries = 0`); only the Windows nightly retries once, to list flakes. A test that fails without a code change
  is fixed or quarantined within a day (still runs, doesn't gate, linked issue, max 14 days).
  Proxy, transparency and security tests can't be quarantined: a flaky one is the bug.
- Test names say the behaviour: `denied_request_is_held_until_approved`, not `test_pending_2`.

## 9. Coverage

- Measured by `cargo llvm-cov nextest` over the whole workspace on Linux, in every CI run; the UI by
  vitest's v8 coverage (`npm test`).
- **Gate: lines ≥ 92 %, regions ≥ 90 %** (workspace totals, floors in `scripts/check.sh`), and a
  **ratchet**: coverage may not fall more than 0.05 points below `scripts/coverage-baseline.json`, the best
  value reached so far (rounded down to 0.1). The floors and the baseline only go up; lowering either needs
  the owner's OK, and a change that lowers the committed baseline fails the gate unless one of its commits
  carries the trailer `Owner-OK: coverage-baseline` (the owner's OK; the environment can't grant it).
- **The ratchet allows 0.05 points of wobble, the floors none.** Measurement varies by a few hundredths
  between runs of the same code, and a baseline taken from one run would sometimes fail a rerun of the
  same code, which costs a full check. So each total (lines, regions) passes while the value as printed
  (two decimals) is at most 0.05 below the baseline, and the gate logs one line per total saying how far
  below it measured and the allowed wobble; anything further below fails. The allowance doesn't move the
  baseline: it is still raised to the measured value when coverage rises, and still never lowered without
  the trailer above, so repeated wobble can't wear it down. A drop of more than 0.05 points still fails;
  a smaller one passes (and is logged), and the diff gate (below) is what holds the lines a change adds.
  The owner accepted this allowance on 2026-10-08.
- **Raising the baseline is automatic.** A local `scripts/check.sh coverage` (the pre-push hook runs it)
  rewrites the baseline when coverage rose; commit the changed file with your change. CI never writes it,
  it only compares and tells you when the baseline is behind. If two branches raise it, take the higher
  value when merging. The ratchet reads two totals: a drop in one crate hidden by a gain elsewhere passes
  it, which is what the diff gate is for.
- **Diff coverage: every line a change adds or changes must be executed by a test.** Rust lines are checked
  against the llvm-cov lcov report (gate `coverage`), TypeScript and Svelte lines against vitest's lcov
  report (gate `ui`); `scripts/check.sh diff-coverage` re-runs both on existing reports. The change is the
  working tree against a base commit: locally the merge base with `origin/develop`, in CI the PR's base or
  the push's previous head (`DIFF_BASE`). Tool: `ui/scripts/diff-coverage.ts` (own code, no dependency;
  tests beside it).
  A line that legitimately can't run in CI goes in `scripts/diff-coverage-exclusions.txt`:
  `path glob | text in the line, or * | reason`, one reason per entry, reviewed like code.
  What it can't see: lines with no coverage data (comments, declarations, code compiled out of the Linux
  run such as `cfg(windows)` lines), files absent from the report (listed as "not measured", never
  failed), branch or region detail inside a covered line, and whether a covered line is asserted.
  A pass means "a test ran it".
- **Expectation above the gate:** security-sensitive modules (§5) aim for ≥ 95 % lines, and every
  branch of a decision (allow/deny/pending, each toggle) has a test. A change that lowers a
  crate's coverage says why in the commit.
- Code that can't run in CI (Windows-only code on Linux, VM paths) is covered by its own tier
  (Windows job, L3/L4), not excluded from the report. Exclusions from the report
  (`--ignore-filename-regex`) only for generated code, listed in `scripts/check.sh` with a comment;
  exclusions from the diff gate are the file above.

## 10. CI

| Workflow | Trigger | Runner | Gates |
|---|---|---|---|
| `ci.yml` | push to `develop`/`main`, every PR, manual (a newer push to a PR or `develop` cancels the run in flight; `main` never) | `ubuntu-24.04` | all of `scripts/check.sh all` in one job; every gate runs even if an earlier one fails |
| `windows.yml` | nightly 02:30 UTC (skipped if it already has a green run on that commit), PRs to `main`, manual | `windows-2025` | clippy, nextest, doc tests, release build (MSVC; not on a manual run from a task branch). The nightly retries each failed test once and lists the flaky ones in the job summary, without failing |
| `vm-linux.yml` | manual on any branch (`gh workflow run vm-linux.yml --ref <branch>`), nightly 03:00 UTC on `develop` (skipped if it already has a green run on that commit) | `ubuntu-24.04` (KVM) | VM tests, tier K; no KVM ⇒ warning, infrastructure skip |
| `vm-windows.yml` | manual on any branch, nightly 03:15 UTC on `develop` (skipped if it already has a green run on that commit) | `windows-2025` (WHP) | VM tests, tier W; no WHP ⇒ warning, infrastructure skip |
| `cache-gc.yml` | nightly 03:45 UTC, manual | `ubuntu-24.04` | deletes superseded rust-cache entries and stale branch caches (`ci/cache-gc.sh`) |
| Dependabot | weekly, grouped | — | opens PRs to `develop` |

The repo is public, so standard hosted runners are free with no minute quota. They are still
shared (20 concurrent jobs), and the Actions cache is capped at 10 GB for the whole repo: only
`develop` saves the Rust cache (`save-if`), one entry per workflow, so task branches restore it and
the cargo-xwin cache isn't evicted. The nightly workflows gate themselves inside their job
(`ci/should-run.sh`), not in a separate job that is billed a full minute. Keep Windows on
nightly/PR-to-main.
Actions are pinned to commit SHAs and must be GitHub-owned or on the repo's allow-list (selected
actions, SHA pinning required; an unpinned `uses:` ends as a `startup_failure` with no jobs).
Workflows get `contents: read` unless they need more.
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
  (crates.io only; puddle's own forks on GitHub once added). An exception names the advisory
  or crate, the reason and a review date.
- **Third-party notices:** `cargo xtask notices --check` (gate `notices`) fails when a shipped
  dependency has no licence entry in cargo-about's report (`about.toml`, whose `accepted` list
  mirrors `deny.toml`). Release notices for puddle and the bundled msb come from
  `cargo xtask runtime`.
- Prefer well-maintained crates already in the tree; a new dependency is justified in its commit.
- Never copy code from Huddle; code from elsewhere follows CONTRIBUTING's "Work you did not
  write".

## 13. The UI (`ui/`)

A SvelteKit single-page app (Svelte 5, TypeScript `strict`, `adapter-static`), served by
`puddle-api` on its own origin (feature `embedded-ui`; ADR 0003). Gates, all in `scripts/check.sh all`
and in `ci.yml` (Linux); `windows.yml` runs `ui` and `ui-e2e`:

| Gate | What |
|---|---|
| `ui` | `prettier --check`, `eslint` (with `eslint-plugin-svelte`), `svelte-check --fail-on-warnings` (Svelte's accessibility warnings fail), `vitest run --coverage`, `vite build` |
| `ui-e2e` | Playwright against the UI fixture backend (the real API on fake services, below), serving the built app: Chromium and WebKit on Linux, the installed Edge on Windows; axe (WCAG 2.0 to 2.2, A and AA) on every route in both themes; no CSP violations |
| `ui-licences` | every npm package in the bundle is MIT, ISC, Apache-2.0, BSD-2/3-Clause, 0BSD or OFL-1.1, and is in `ui/THIRD-PARTY-NOTICES.txt` (`cd ui && npm run build && npm run licences` rewrites it) |
| `ui-audit` | `npm audit --omit=dev --audit-level=moderate`, minus `ui/audit-exceptions.json` (id, reason, review-by date) |

- **The fixture backend** (`puddle-ui-fixture`, `crates/puddle-e2e/src/ui_fixture/`) is the real
  `puddle-api` router on an in-memory store, a manual clock and in-memory settings, seeded from a JSON
  scenario (`ui/e2e/fixtures/*.json`: built-ins `default`, `empty`, `lived-in`, `corporate-network`, `network-trouble`, or any file) and driven by
  scripts and a loopback control server (emit an event, advance the clock, restart, reset). Screens are
  developed with `cd ui && npm run dev:fixture`; e2e tests that only read use the shared server of
  `playwright.config.ts`, tests that change state use `e2e/fixture.ts` (a backend per worker, reset per
  test). A new API service gets its fake and a scenario field in `Fixture::build_state`; a new event needs
  nothing (an `Event` in JSON is a step). The `history` step writes N connection records over a week
  (the activity screen's long-log test).
- **Coverage** (`ui/vite.config.ts`): lines ≥ 85 %, branches ≥ 80 % overall; `src/lib/api/**` (client,
  event stream), `src/lib/decision/**` (the four-outcome model), `src/lib/rules/**` (filter, sort, expiry),
  `src/lib/audit/**` (filters, the address, how a record reads, the drawn window) and `src/lib/workspaces/**` (what each state allows, form checks, settings choices) and `src/lib/settings/**` (consent wording, global settings choices) and `src/lib/network/**` (the network report in words, with a fix per problem) and `src/lib/notify/**` (notice list, event watcher) and `src/lib/identities/**` (how a source and its coverage read, the checks a form makes, clone addresses) ≥ 95 % lines, ≥ 90 % branches.
  Thresholds only go up.
- **The API client is generated:** `cargo xtask openapi` writes `ui/src/lib/api/schema.d.ts` (and
  checks it in the `openapi` gate); never hand-write a request.
- **Tokens only:** components use the custom properties in `ui/src/lib/theme/tokens.css`, never a
  literal colour. Each section is one entry in `ui/src/lib/nav.ts`.
- **No secrets in the page:** the API token comes from `window.__PUDDLE__` (set by the shell) and
  is never read from or written to a URL, cookie or storage.
