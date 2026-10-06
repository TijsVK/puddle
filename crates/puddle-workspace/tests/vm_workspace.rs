// SPDX-License-Identifier: GPL-3.0-or-later
//! The workspace lifecycle on real microVMs (K on Linux KVM, W on Windows WHP): the T-112 VM bar.
//!
//! - a clone through the route (guest git → `puddle-agent` → vsock route → puddle's proxy → a
//!   local git server) survives stop, sandbox removal and a new sandbox on the same workspace;
//! - a VMM kill during commits, with the boot hook's `core.fsync=committed`, leaves a repository
//!   that passes `git fsck --full`, 5 of 5 times;
//! - `fstrim` on stop and "reclaim space" (in the running holder and in a maintenance sandbox)
//!   each return more than 80 % of a deleted 1 GiB to the host's disk image.
//!
//! Runs on the msb adapter over the VM harness's private msb home (T-102), with the static
//! `puddle-agent` from `PUDDLE_AGENT_BIN` (`ci/build-agent.sh`).
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    reason = "VM test: a failed step fails the test; measurements go to stderr"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use microsandbox::Sandbox as SdkSandbox;
use puddle_boot::{
    BootHook, BootPlan, Gate, GatedSandbox, GitIdentity, with_boot_mounts, write_assets,
};
use puddle_compute::{
    DiskSize, ExecOutput, ExecRequest, Runtime, Sandbox, SandboxSpec, VsockRoute,
};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticPolicy, StaticResolver};
use puddle_proxy::{Proxy, Route};
use puddle_types::{GuestEnv, Host, ImageRef, MemoryMib, NullSink, SandboxName, WorkspaceId};
use puddle_vm_tests::{DEBIAN_DEVCONTAINER, Settings, VmEnv};
use puddle_workspace::{Layout, WorkspaceConfig, Workspaces};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The guest port puddle routes (T-020 C-5); the agent's default target.
const ROUTE_PORT: u32 = 5000;
/// The agent's listener in the guest.
const GUEST_PROXY: &str = "http://127.0.0.1:3128";
const GIT_HOST: &str = "git.test";
const GIB: u64 = 1024 * 1024 * 1024;

async fn runtime() -> (MsbRuntime, Settings) {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings");
    let pair = settings.prepare().expect("msb runtime pair");
    let home = settings.home();
    let config = MsbConfig::new(&home, pair.msb, pair.libkrunfw, home.join("guest-share"));
    (MsbRuntime::open(config).await.expect("open msb"), settings)
}

/// A run-prefixed name, used for the workspace and its sandbox.
fn names(settings: &Settings, tag: &str) -> (WorkspaceId, SandboxName) {
    let n = format!("{}-t112-{tag}", settings.prefix);
    (WorkspaceId::new(&n).unwrap(), SandboxName::new(&n).unwrap())
}

fn workspaces() -> Workspaces {
    Workspaces::new(WorkspaceConfig {
        maintenance_memory: MemoryMib::new(512).unwrap(),
        ..WorkspaceConfig::default()
    })
}

fn base_spec(name: &SandboxName) -> SandboxSpec {
    SandboxSpec::new(name.clone(), ImageRef::new(DEBIAN_DEVCONTAINER).unwrap())
        .with_memory(MemoryMib::new(1024).unwrap())
}

async fn sh<S: Sandbox>(sb: &S, script: &str) -> ExecOutput {
    sb.exec(
        ExecRequest::sh(script)
            .as_user("root")
            .with_timeout(Duration::from_secs(600)),
    )
    .await
    .expect("exec")
}

async fn sh_ok<S: Sandbox>(sb: &S, script: &str) -> String {
    let out = sh(sb, script).await;
    assert!(
        out.status.success(),
        "{script}: exit {}\n{}{}",
        out.status.code,
        out.stdout_text(),
        out.stderr_text()
    );
    out.stdout_text().trim_end().to_owned()
}

/// Boot-hook pieces for one sandbox: assets under the guest-share root, the agent copied there.
struct Boot {
    plan: BootPlan,
    hook: BootHook,
    gate: Gate,
    mounts: Vec<puddle_compute::FileMount>,
    agent: Option<PathBuf>,
}

impl Boot {
    async fn new(rt: &MsbRuntime, tag: &str, env: &GuestEnv, agent: bool) -> Self {
        let image = ImageRef::new(DEBIAN_DEVCONTAINER).unwrap();
        let config = rt.pull_image(&image).await.unwrap();
        let builder = BootPlan::builder(&config)
            .env(env)
            .git_identity(GitIdentity::new("VM Test", "vm@example.org").unwrap());
        let plan = if agent { builder } else { builder.no_agent() }
            .build()
            .unwrap();
        let dir = rt.config().guest_share.join(format!("t112-{tag}"));
        let mounts = write_assets(&dir).unwrap();
        let agent = agent.then(|| {
            let built = PathBuf::from(
                std::env::var_os("PUDDLE_AGENT_BIN")
                    .expect("PUDDLE_AGENT_BIN: the static puddle-agent (ci/build-agent.sh)"),
            );
            let copy = dir.join("puddle-agent");
            std::fs::copy(&built, &copy).expect("copy the agent into the guest-share root");
            copy
        });
        Self {
            plan,
            hook: BootHook::new(),
            gate: Gate::new(),
            mounts,
            agent,
        }
    }

    /// Creates `spec` with workspace `id` through the boot hook.
    async fn create(
        &self,
        rt: &MsbRuntime,
        w: &Workspaces,
        id: &WorkspaceId,
        spec: SandboxSpec,
    ) -> GatedSandbox<puddle_compute_msb::MsbSandbox> {
        let attachment = w
            .prepare(rt, id, &spec.name, Some(DiskSize::gib(2)))
            .await
            .unwrap();
        let spec = attachment.add_to(with_boot_mounts(
            spec,
            self.mounts.clone(),
            self.agent.as_deref(),
        ));
        match self.hook.create(rt, spec, &self.plan, &self.gate).await {
            Ok(sb) => {
                attachment.commit();
                w.prepare_layout(sb.ungated(), id).await.unwrap();
                sb
            }
            Err(e) => {
                attachment.abort(rt).await.unwrap();
                panic!("create failed: {e}");
            }
        }
    }
}

/// A dumb-HTTP git server: serves files under `root`, ignores query strings.
async fn serve_files(root: PathBuf) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let root = root.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0_u8; 4096];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(buf.get(..n).unwrap_or_default()),
                    }
                }
                let text = String::from_utf8_lossy(&head);
                let target = text.split(' ').nth(1).unwrap_or("/");
                let path = target.split('?').next().unwrap_or("/");
                let file = (!path.split('/').any(|p| p == ".."))
                    .then(|| root.join(path.trim_start_matches('/')))
                    .filter(|f| f.is_file());
                let response = match file.and_then(|f| std::fs::read(f).ok()) {
                    Some(body) => {
                        let mut r = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        r.extend_from_slice(&body);
                        r
                    }
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = conn.write_all(&response).await;
                let _ = conn.shutdown().await;
            });
        }
    });
    addr
}

/// `git` without the caller's `GIT_*` variables (under a git hook `GIT_DIR` would point at
/// puddle's own repository).
fn git_command() -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

fn host_git(dir: &Path, args: &[&str]) {
    let out = git_command()
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.org")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.org")
        .output()
        .expect("git on the host");
    assert!(
        out.status.success(),
        "host git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A bare repo `repo.git` with two commits under `root`, prepared for dumb HTTP. Returns the
/// head commit.
fn host_repo(root: &Path) -> String {
    let bare = root.join("repo.git");
    std::fs::create_dir_all(&bare).unwrap();
    host_git(&bare, &["init", "-q", "--bare", "-b", "main"]);
    let seed = root.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    host_git(&seed, &["init", "-q", "-b", "main"]);
    for (file, msg) in [("README.md", "first"), ("src.txt", "second")] {
        std::fs::write(seed.join(file), format!("{msg}\n")).unwrap();
        host_git(&seed, &["add", file]);
        host_git(&seed, &["commit", "-qm", msg]);
    }
    host_git(&seed, &["push", "-q", bare.to_str().unwrap(), "main"]);
    host_git(&bare, &["update-server-info"]);
    let out = git_command()
        .args(["rev-parse", "HEAD"])
        .current_dir(&seed)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// puddle's proxy on one route, allowing only the git host (resolved to loopback).
fn proxy_route(root: &IpcRoot, sandbox: &SandboxName) -> Route {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&Host::parse_normalised(GIT_HOST).unwrap());
    let resolver = StaticResolver::new().with(GIT_HOST, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let proxy = Arc::new(
        Proxy::new(policy, Arc::new(NullSink))
            .with_resolver(Arc::new(resolver))
            .with_address_check(Arc::new(AnyAddress)),
    );
    proxy.serve_route(root.listen().unwrap(), sandbox.clone())
}

fn proxy_env() -> GuestEnv {
    let mut env = GuestEnv::new();
    for var in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"] {
        env.set(var, GUEST_PROXY).unwrap();
    }
    env.set("GIT_TERMINAL_PROMPT", "0").unwrap();
    env
}

/// Clone through the route ⇒ stop ⇒ remove the sandbox ⇒ a new sandbox on the same workspace:
/// HEAD and an untracked marker are intact. Also: the volume root has `lost+found`, so a clone
/// into it fails; the checkout goes in a subdirectory beside `.puddle`. Ends with the delete
/// check (in the running holder, then in a maintenance sandbox) and the delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_clone_through_the_route_survives_a_sandbox_rebuild() {
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let (id, name) = names(&settings, "clone");
    let files = tempfile::tempdir().unwrap();
    let head = host_repo(files.path());
    let server = serve_files(files.path().to_path_buf()).await;
    let url = format!("http://{GIT_HOST}:{}/repo.git", server.port());
    let ipc = IpcRoot::new().unwrap();
    let route = proxy_route(&ipc, &name);
    let env = proxy_env();
    let boot = Boot::new(rt, "clone", &env, true).await;
    let spec = || {
        base_spec(&name)
            .with_env(&env)
            .with_route(VsockRoute::new(ROUTE_PORT, route.endpoint().path()))
    };
    let w = workspaces();
    let layout = Layout::new(&id).unwrap();
    let mount = layout.mount().to_string();

    let sb = boot.create(rt, &w, &id, spec()).await;
    let root = sh_ok(sb.ungated(), &format!("ls -A {mount}")).await;
    assert!(
        root.lines().any(|l| l == "lost+found"),
        "volume root: {root}"
    );
    assert!(root.lines().any(|l| l == ".puddle"), "volume root: {root}");
    let into_root = sh(sb.ungated(), &format!("git clone -q {url} {mount}")).await;
    assert!(
        !into_root.status.success(),
        "a clone into the volume root worked"
    );
    assert!(
        into_root.stderr_text().contains("not an empty directory"),
        "{}",
        into_root.stderr_text()
    );

    let clone = layout.clone_request(&url).unwrap().as_user("root");
    let checkout = layout.checkout("repo").unwrap();
    let out = sb.ungated().exec(clone).await.unwrap();
    assert!(
        out.status.success(),
        "clone through the route: {}",
        out.stderr_text()
    );
    let dir = checkout.as_str();
    assert_eq!(
        sh_ok(sb.ungated(), &format!("git -C {dir} rev-parse HEAD")).await,
        head
    );
    sh_ok(
        sb.ungated(),
        &format!("echo kept > {dir}/marker.txt && git -C {dir} config core.fsync"),
    )
    .await;

    let report = w.stop(sb.ungated()).await.unwrap();
    assert!(report.trims[0].is_ok(), "trim on stop: {:?}", report.trims);
    drop(sb);
    rt.remove(&name).await.unwrap();
    w.sandbox_removed(&name);
    assert!(rt.volume(&id.volume_name()).await.unwrap().is_some());

    let again = boot.create(rt, &w, &id, spec()).await;
    assert_eq!(
        sh_ok(again.ungated(), &format!("git -C {dir} rev-parse HEAD")).await,
        head
    );
    assert_eq!(
        sh_ok(again.ungated(), &format!("cat {dir}/marker.txt")).await,
        "kept"
    );
    sh_ok(again.ungated(), &format!("git -C {dir} fsck --full")).await;

    // Delete: checked in the running holder, refused while it runs, checked again after stop.
    let report = w.check_delete(rt, &id).await.unwrap();
    eprintln!("{report}");
    assert_eq!(report.checked_in, name);
    assert_eq!(report.findings.repos.len(), 1);
    assert_eq!(
        report.findings.repos[0].uncommitted.items,
        ["?? marker.txt"]
    );
    assert!(report.findings.repos[0].unpushed.is_empty());
    assert!(w.delete(rt, &id, &report.confirm()).await.is_err());
    w.stop(again.ungated()).await.unwrap();
    drop(again);
    let deleted = w.delete(rt, &id, &report.confirm()).await.unwrap();
    assert_eq!(deleted.removed_sandbox, Some(name.clone()));
    assert!(rt.volume(&id.volume_name()).await.unwrap().is_none());
    assert!(
        rt.list()
            .await
            .unwrap()
            .iter()
            .all(|s| s.name != name.as_str())
    );
    route.shutdown().await;
}

/// The VM's process id, from msb's record.
async fn vm_pid(settings: &Settings, name: &SandboxName) -> u32 {
    let harness = VmEnv::new(settings.clone()).await.unwrap();
    let handle = harness
        .scope(Box::pin(SdkSandbox::get(name.as_str())))
        .await
        .unwrap();
    let pid = handle
        .local()
        .and_then(|l| l.pid)
        .expect("msb records the VM pid");
    u32::try_from(pid).unwrap()
}

fn kill_hard(pid: u32) {
    let status = if cfg!(windows) {
        std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .status()
    } else {
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
    };
    assert!(status.unwrap().success(), "killing VM process {pid}");
}

async fn wait_down(rt: &MsbRuntime, name: &SandboxName) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = rt
            .list()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.name == name.as_str())
            .map(|s| s.status);
        if status.is_some_and(puddle_types::SandboxStatus::is_down) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "still {status:?} 60 s after the kill"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A VMM kill in the middle of a commit loop, five times: with `core.fsync=committed` (written by
/// the boot hook) the repository passes `git fsck --full` after every restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_vmm_kill_during_commits_leaves_git_consistent() {
    const ROUNDS: usize = 5;
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let (id, name) = names(&settings, "fsync");
    let boot = Boot::new(rt, "fsync", &GuestEnv::new(), false).await;
    let w = workspaces();
    let repo = Layout::new(&id).unwrap().checkout("repo").unwrap();
    let repo = repo.as_str();
    let mut sb = boot.create(rt, &w, &id, base_spec(&name)).await;
    assert_eq!(
        sh_ok(sb.ungated(), "git config --get core.fsync").await,
        "committed"
    );
    sh_ok(
        sb.ungated(),
        &format!("git init -q -b main {repo} && cd {repo} && echo 0 > f && git add f && git commit -qm c0"),
    )
    .await;
    let mut clean = 0;
    for round in 1..=ROUNDS {
        let count = |s: String| s.parse::<u64>().unwrap();
        let before = count(
            sh_ok(
                sb.ungated(),
                &format!("git -C {repo} rev-list --count HEAD"),
            )
            .await,
        );
        sh_ok(
            sb.ungated(),
            &format!(
                "cd {repo} && rm -f .git/index.lock && setsid sh -c 'i=0; while :; do i=$((i+1)); \
                 echo $i > f$((i % 64)); git add -A && git commit -qm r{round}-$i; done' \
                 </dev/null >/dev/null 2>&1 &"
            ),
        )
        .await;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let now = sh(
                sb.ungated(),
                &format!("git -C {repo} rev-list --count HEAD"),
            )
            .await;
            if now.status.success() && count(now.stdout_text().trim().to_owned()) >= before + 25 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "round {round}: the commit loop doesn't commit"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let pid = vm_pid(&settings, &name).await;
        kill_hard(pid);
        drop(sb);
        wait_down(rt, &name).await;
        sb = boot
            .hook
            .start(rt, &name, &boot.plan, &boot.gate)
            .await
            .expect("start after the kill");
        let fsck = sh(sb.ungated(), &format!("git -C {repo} fsck --full")).await;
        let head = sh(sb.ungated(), &format!("git -C {repo} log -1 --format=%s")).await;
        let ok = fsck.status.success() && head.status.success();
        eprintln!(
            "round {round}: fsck {} (exit {}), HEAD {:?}, {}",
            if ok { "clean" } else { "FAILED" },
            fsck.status.code,
            head.stdout_text().trim(),
            fsck.stderr_text().trim()
        );
        clean += usize::from(ok);
    }
    w.stop(sb.ungated()).await.unwrap();
    drop(sb);
    rt.remove(&name).await.unwrap();
    w.sandbox_removed(&name);
    rt.remove_volume(&id.volume_name()).await.unwrap();
    assert_eq!(
        clean, ROUNDS,
        "git fsck clean after {clean} of {ROUNDS} VMM kills"
    );
}

/// Bytes the host file system has allocated for `path` (a sparse disk image).
#[cfg(unix)]
fn allocated(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().blocks() * 512
}

/// Bytes the host file system has allocated for `path` (a sparse disk image).
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "GetCompressedFileSizeW is the only way to read a sparse file's allocated size"
)]
fn allocated(path: &Path) -> u64 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut high = 0_u32;
    // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the call, and `high` is a
    // valid place for the high half of the size.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &raw mut high) };
    if low == u32::MAX {
        let e = std::io::Error::last_os_error();
        assert_eq!(e.raw_os_error(), Some(0), "GetCompressedFileSizeW: {e}");
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Writes 1 GiB of random data on the workspace, syncs, deletes it, syncs; returns the image's
/// allocation after the write.
async fn fill_and_delete<S: Sandbox>(sb: &S, mount: &str, image: &Path) -> u64 {
    sh_ok(
        sb,
        &format!("dd if=/dev/urandom of={mount}/big bs=1M count=1024 status=none && sync"),
    )
    .await;
    let full = allocated(image);
    sh_ok(sb, &format!("rm {mount}/big && sync")).await;
    full
}

#[expect(
    clippy::cast_precision_loss,
    reason = "GiB with two decimals for the log line"
)]
fn check_reclaimed(what: &str, full: u64, after: u64) {
    let reclaimed = full.saturating_sub(after);
    eprintln!(
        "{what}: image {:.2} GiB after the write, {:.2} GiB after the trim, {:.0} % of 1 GiB returned",
        full as f64 / GIB as f64,
        after as f64 / GIB as f64,
        reclaimed as f64 * 100.0 / GIB as f64
    );
    assert!(
        reclaimed * 10 > GIB * 8,
        "{what}: only {reclaimed} bytes of a deleted 1 GiB returned"
    );
}

/// `fstrim` on stop, "reclaim space" in the running holder, and "reclaim space" of a stopped
/// workspace (maintenance sandbox) each return > 80 % of a deleted 1 GiB to the host image.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_trim_returns_deleted_space_to_the_host_image() {
    let (rt, settings) = runtime().await;
    let rt = &rt;
    let (id, name) = names(&settings, "trim");
    let w = workspaces();
    let mount = Layout::new(&id).unwrap().mount().to_string();
    let image = settings
        .home()
        .join("volumes")
        .join(id.volume_name().as_str())
        .join("disk.raw");

    // 1. fstrim on stop.
    let sb = w
        .create(rt, &id, base_spec(&name), Some(DiskSize::gib(4)))
        .await
        .unwrap();
    assert!(image.is_file(), "no disk image at {}", image.display());
    let full = fill_and_delete(&sb, &mount, &image).await;
    let report = w.stop(&sb).await.unwrap();
    eprintln!("stop: {:?}", report.trims);
    assert!(report.trims[0].is_ok());
    drop(sb);
    check_reclaimed("fstrim on stop", full, allocated(&image));

    // 2. reclaim space while the sandbox runs.
    let sb = rt.start(&name).await.unwrap();
    let full = fill_and_delete(&sb, &mount, &image).await;
    let trimmed = w.reclaim_space(rt, &id).await.unwrap();
    eprintln!("reclaim (running): {trimmed:?}");
    check_reclaimed("reclaim space, running", full, allocated(&image));

    // 3. reclaim space of a stopped workspace: a maintenance sandbox does it.
    let full = fill_and_delete(&sb, &mount, &image).await;
    sb.stop().await.unwrap();
    drop(sb);
    let trimmed = w.reclaim_space(rt, &id).await.unwrap();
    eprintln!("reclaim (stopped): {trimmed:?}");
    check_reclaimed("reclaim space, stopped", full, allocated(&image));
    assert!(
        rt.list()
            .await
            .unwrap()
            .iter()
            .all(|s| !puddle_workspace::is_maintenance_name(&s.name)),
        "the maintenance sandbox is gone"
    );

    rt.remove(&name).await.unwrap();
    w.sandbox_removed(&name);
    rt.remove_volume(&id.volume_name()).await.unwrap();
}
