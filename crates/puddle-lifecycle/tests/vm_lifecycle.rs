// SPDX-License-Identifier: GPL-3.0-or-later
//! Shutdown and reconcile on real microVMs (tiers K and W).
//!
//! The "puddle" under test is this test binary itself, started again in the role of a host
//! (test `vm_role_host`): it goes through [`puddle_lifecycle::supervise`], boots one sandbox,
//! prints `PUDDLE-LC READY <worker pid>`, waits for a shutdown trigger and shuts down. The test
//! then delivers the trigger the way a user would (Ctrl-C and a closed console window on
//! Windows, `SIGTERM` on Linux) or kills it (`TerminateProcess`, `SIGKILL`) and checks msb's
//! record. Each test has its own msb home (`<run prefix>-l<n>`).
#![expect(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "VM test helpers: a failed step fails the test"
)]
#![expect(
    clippy::print_stderr,
    clippy::exit,
    reason = "helper roles report on stderr and end with their exit code"
)]

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use puddle_compute::{DiskSize, Runtime, Sandbox as _, SandboxSpec, VolumeSpec};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_lifecycle::{
    Inventory, Lifecycle, Role, ShutdownConfig, ShutdownSignals, reconcile, supervise,
};
use puddle_types::{ImageRef, MemoryMib, SandboxName, SandboxStatus, VolumeName, WorkspaceId};
use puddle_vm_tests::{RunPrefix, Settings, VmEnv};

/// Which helper role this process plays (unset: a normal test run).
const ROLE: &str = "PUDDLE_LC_TEST_ROLE";
/// The host's msb home prefix.
const PREFIX: &str = "PUDDLE_LC_TEST_PREFIX";
/// The host's sandbox.
const SANDBOX: &str = "PUDDLE_LC_TEST_SANDBOX";
/// The process a signalling helper targets.
#[cfg(windows)]
const TARGET: &str = "PUDDLE_LC_TEST_TARGET";

/// How often each scenario runs (the bar: 10/10).
const ITERATIONS: usize = 10;
/// Small and quick to boot; has busybox `fstrim`.
const IMAGE: &str = "alpine:3";
/// The first boot pulls the image.
const READY_TIMEOUT: Duration = Duration::from_secs(300);
/// The bar for a hard kill: VMs gone within 5 s.
const KILL_BAR: Duration = Duration::from_secs(5);

const SSH_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrqAVBGG1BD2K0dsi6Z6il4+PlI8R/egmhi8Ox00c0/ puddle-contract-test";

fn base_settings() -> Settings {
    Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings")
}

/// The run's settings with the prefix `<run prefix>-<suffix>`: a private home per test.
fn settings_with(prefix: &str) -> Settings {
    Settings {
        prefix: RunPrefix::new(prefix).expect("prefix"),
        ..base_settings()
    }
}

fn own_prefix(suffix: &str) -> String {
    format!("{}-{suffix}", base_settings().prefix.as_str())
}

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

async fn msb(settings: &Settings) -> MsbRuntime {
    init_logs();
    let pair = settings.prepare().expect("msb runtime pair");
    let home = settings.home();
    let config = MsbConfig::new(&home, pair.msb, pair.libkrunfw, home.join("guest-share"))
        .with_ssh_key(SSH_KEY)
        .with_runtime_log_level(settings.msb_log_level.clone())
        .with_keep_logs_dir(settings.kept_logs());
    MsbRuntime::open(config).await.expect("open msb")
}

fn spec(name: &SandboxName) -> SandboxSpec {
    SandboxSpec::new(name.clone(), ImageRef::new(IMAGE).unwrap())
        .with_memory(MemoryMib::new(512).unwrap())
}

async fn status(rt: &MsbRuntime, name: &SandboxName) -> Option<SandboxStatus> {
    rt.list()
        .await
        .expect("list")
        .into_iter()
        .find(|i| i.name == name.as_str())
        .map(|i| i.status)
}

/// The VMM process msb recorded for `name`.
async fn vmm_pid(env: &VmEnv, name: &SandboxName) -> u32 {
    let handle = env
        .scope(Box::pin(microsandbox::Sandbox::get(name.as_str())))
        .await
        .expect("sandbox record");
    let pid = handle.local().and_then(|l| l.pid).expect("recorded pid");
    u32::try_from(pid).unwrap()
}

// ---------------------------------------------------------------------------------------------
// The host role: a minimal puddle.

/// Plays the host when [`ROLE`] says so; as a normal test it does nothing.
#[test]
fn vm_role_host() {
    if std::env::var(ROLE).as_deref() != Ok("host") {
        return;
    }
    #[cfg(windows)]
    win::process_ctrl_c();
    std::process::exit(host());
}

fn host() -> i32 {
    // The front logs its console events too.
    init_logs();
    match supervise() {
        Ok(Role::Front { exit_code }) => return exit_code,
        Ok(Role::Worker) => {}
        Err(e) => {
            eprintln!("supervise: {e}");
            return 10;
        }
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(Box::pin(host_worker()))
}

/// Writes one protocol line; the reader may be gone (a closed console), which is fine.
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

async fn host_worker() -> i32 {
    let mut signals = ShutdownSignals::install().expect("signal handlers");
    let settings = settings_with(&std::env::var(PREFIX).unwrap());
    let rt = msb(&settings).await;
    let name = SandboxName::new(&std::env::var(SANDBOX).unwrap()).unwrap();
    let boot = if status(&rt, &name).await.is_some() {
        rt.start(&name).await
    } else {
        rt.create(spec(&name)).await
    };
    let handle = match boot {
        Ok(h) => h,
        Err(e) => {
            say(&format!("PUDDLE-LC FAILED boot: {e}"));
            return 11;
        }
    };
    let lc = Lifecycle::new(
        rt,
        ShutdownConfig {
            trim_timeout: Duration::from_secs(3),
            stop_timeout: Duration::from_secs(40),
        },
    );
    if lc.manage(handle, Vec::new()).is_err() {
        return 12;
    }
    say(&format!("PUDDLE-LC READY {}", std::process::id()));
    let cause = signals.recv().await;
    say(&format!("PUDDLE-LC CAUSE {cause}"));
    let started = Instant::now();
    let report = lc.shutdown().await;
    say(&format!(
        "PUDDLE-LC REPORT {:?} in {:?}",
        report.sandboxes,
        started.elapsed()
    ));
    if !report.all_stopped() {
        return 3;
    }
    // Every sandbox got its trim before the stop (the bar for this test), not only a stop.
    if report
        .sandboxes
        .iter()
        .any(|s| s.trim != puddle_lifecycle::TrimOutcome::Trimmed)
    {
        return 4;
    }
    0
}

// ---------------------------------------------------------------------------------------------
// Driving a host.

/// The host process: started by `std` (a console window of its own), or on Windows inside a
/// pseudoconsole the test owns, the way Windows Terminal runs a tab.
enum HostProcess {
    Std(Child),
    #[cfg(windows)]
    Pty(win::PtyChild),
}

impl HostProcess {
    fn id(&self) -> u32 {
        match self {
            Self::Std(c) => c.id(),
            #[cfg(windows)]
            Self::Pty(c) => c.id(),
        }
    }

    fn kill(&mut self) -> std::io::Result<()> {
        match self {
            Self::Std(c) => c.kill(),
            #[cfg(windows)]
            Self::Pty(c) => c.kill(),
        }
    }

    fn wait(&mut self) -> Option<i32> {
        match self {
            Self::Std(c) => c.wait().unwrap().code(),
            #[cfg(windows)]
            Self::Pty(c) => c.wait(),
        }
    }
}

struct Host {
    child: HostProcess,
    lines: Receiver<String>,
}

/// Echoes the host's output lines to stderr and passes them on.
fn relay_lines(out: impl std::io::Read + Send + 'static) -> Receiver<String> {
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            eprintln!("host> {line}");
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

/// The host's command line arguments after the executable.
const HOST_ARGS: [&str; 5] = [
    "--exact",
    "vm_role_host",
    "--nocapture",
    "--test-threads",
    "1",
];

impl Host {
    /// Starts a host inside a pseudoconsole; [`win::PtyChild::close_console`] then closes it
    /// like closing a Windows Terminal tab (`CTRL_CLOSE_EVENT`).
    #[cfg(windows)]
    fn spawn_in_pty(prefix: &str, name: &SandboxName) -> Self {
        let exe = std::env::current_exe().unwrap();
        let (child, out) = win::PtyChild::spawn(
            &exe,
            &HOST_ARGS,
            &[(ROLE, "host"), (PREFIX, prefix), (SANDBOX, name.as_str())],
        )
        .expect("start host in a pseudoconsole");
        Self {
            child: HostProcess::Pty(child),
            lines: relay_lines(out),
        }
    }

    fn spawn(prefix: &str, name: &SandboxName) -> Self {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(HOST_ARGS)
            .env(ROLE, "host")
            .env(PREFIX, prefix)
            .env(SANDBOX, name.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            // A console of its own, like a terminal window the user started puddle in.
            cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE);
        }
        let mut child = cmd.spawn().expect("start host");
        let out = child.stdout.take().unwrap();
        Self {
            child: HostProcess::Std(child),
            lines: relay_lines(out),
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The rest of the first line containing `prefix`, within `timeout`; `None` at EOF or timeout.
    fn line(&self, prefix: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.checked_duration_since(Instant::now())?;
            let line = self.lines.recv_timeout(left).ok()?;
            // libtest may have written `test vm_role_host ... ` on the same line first.
            if let Some((_, rest)) = line.split_once(prefix) {
                return Some(rest.trim().to_owned());
            }
            assert!(!line.contains("PUDDLE-LC FAILED"), "host failed: {line}");
        }
    }

    /// Waits for READY and returns the worker's pid.
    fn ready(&self) -> u32 {
        self.line("PUDDLE-LC READY", READY_TIMEOUT)
            .expect("host never became ready")
            .parse()
            .unwrap()
    }

    /// Waits for the host process to exit and returns its exit code.
    fn exit_code(mut self, timeout: Duration) -> Option<i32> {
        // EOF on stdout comes with the exit (or a kill); drain until then.
        let deadline = Instant::now() + timeout;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(_) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _ = self.child.kill();
                    panic!("host still running after {timeout:?}");
                }
            }
        }
        self.child.wait()
    }
}

/// One test's msb world: own home, the sandbox name, the adapter and the harness backend.
struct World {
    prefix: String,
    name: SandboxName,
    rt: MsbRuntime,
    env: VmEnv,
}

impl World {
    async fn new(suffix: &str) -> Self {
        let prefix = own_prefix(suffix);
        let settings = settings_with(&prefix);
        let rt = msb(&settings).await;
        let env = VmEnv::new(settings).await.expect("harness");
        let name = env.sandbox_name("box").unwrap();
        Self {
            prefix,
            name,
            rt,
            env,
        }
    }

    async fn status(&self) -> Option<SandboxStatus> {
        status(&self.rt, &self.name).await
    }

    async fn finish(self) {
        self.env.cleanup().await.expect("cleanup");
        drop(self.rt);
        self.env.remove_home().await.expect("remove home");
    }
}

/// Runs `ITERATIONS` rounds of: start a host with `spawn`, let `trigger` end it, check the
/// record is `Stopped`. `trigger` gets the host and the worker's pid and returns when the
/// worker has exited.
async fn graceful_rounds(
    suffix: &str,
    spawn: impl Fn(&str, &SandboxName) -> Host,
    trigger: impl Fn(Host, u32),
) {
    let world = World::new(suffix).await;
    let mut results = Vec::new();
    for round in 1..=ITERATIONS {
        let host = spawn(&world.prefix, &world.name);
        let worker = host.ready();
        assert_eq!(world.status().await, Some(SandboxStatus::Running));
        trigger(host, worker);
        let after = world.status().await;
        eprintln!("round {round}: record {after:?}");
        results.push(after);
    }
    let stopped = results
        .iter()
        .filter(|s| **s == Some(SandboxStatus::Stopped))
        .count();
    assert_eq!(stopped, ITERATIONS, "records after each round: {results:?}");
    world.finish().await;
}

/// Runs `ITERATIONS` rounds of: start a host, `kill` it, check the VM process is gone within
/// [`KILL_BAR`], then reconcile as the next start would.
async fn hard_kill_rounds(suffix: &str, kill: impl Fn(&mut Host)) {
    let world = World::new(suffix).await;
    let inventory = Inventory {
        sandboxes: BTreeSet::from([world.name.clone()]),
        ..Inventory::default()
    };
    let mut gone_after = Vec::new();
    for round in 1..=ITERATIONS {
        let mut host = Host::spawn(&world.prefix, &world.name);
        let worker = host.ready();
        let vmm = vmm_pid(&world.env, &world.name).await;
        let watch = proc::Watch::new(&[worker, vmm]);
        let killed = Instant::now();
        kill(&mut host);
        let gone = watch.all_gone_within(KILL_BAR);
        let took = killed.elapsed();
        eprintln!("round {round}: worker {worker} + vmm {vmm} gone: {gone} after {took:?}");
        assert!(
            gone,
            "round {round}: VM process {vmm} still alive {KILL_BAR:?} after the kill"
        );
        gone_after.push(took);
        let _ = host.exit_code(Duration::from_secs(30));

        // The next puddle start.
        let report = reconcile(&world.rt, &inventory, &ShutdownConfig::default())
            .await
            .expect("reconcile");
        eprintln!("round {round}: reconcile {report:?}");
        assert_eq!(report.failures.len(), 0, "{report:?}");
        assert_eq!(
            report.removed.len(),
            0,
            "a known sandbox was removed: {report:?}"
        );
        let after = world.status().await.expect("record kept");
        assert!(after.is_down(), "round {round}: record {after}");
    }
    eprintln!("VM gone after: {gone_after:?}");
    world.finish().await;
}

// ---------------------------------------------------------------------------------------------
// Windows (tier W).

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_ctrl_c_stops_the_sandboxes_10_of_10() {
    Box::pin(graceful_rounds("l1", Host::spawn, |host, worker| {
        let watch = proc::Watch::new(&[worker]);
        signal_helper("ctrl-c", host.pid());
        assert!(
            watch.all_gone_within(Duration::from_secs(90)),
            "worker still running"
        );
        assert_eq!(host.exit_code(Duration::from_secs(30)), Some(0));
    }))
    .await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_console_close_stops_the_sandboxes_10_of_10() {
    // A pseudoconsole, not a console window: the hosted runner's console windows are
    // pseudoconsoles already and ignore WM_CLOSE (class `PseudoConsoleWindow`), and closing a
    // pseudoconsole is what Windows Terminal does when a tab closes. Both send
    // CTRL_CLOSE_EVENT; the classic conhost window's X button is an L case.
    Box::pin(graceful_rounds(
        "l2",
        Host::spawn_in_pty,
        |mut host, worker| {
            let watch = proc::Watch::new(&[worker]);
            let HostProcess::Pty(pty) = &mut host.child else {
                unreachable!("spawned in a pseudoconsole")
            };
            pty.close_console();
            // Windows ends the front ~5 s after the close; the worker finishes on its own.
            assert!(
                watch.all_gone_within(Duration::from_secs(90)),
                "worker still running"
            );
            let _ = host.exit_code(Duration::from_secs(30));
        },
    ))
    .await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_terminate_process_ends_the_vms_within_5s_10_of_10() {
    Box::pin(hard_kill_rounds("l3", |host| {
        host.child.kill().expect("TerminateProcess");
    }))
    .await;
}

/// Starts this binary as a signalling helper (`ctrl-c`) aimed at `target`'s console and waits
/// for it.
#[cfg(windows)]
fn signal_helper(role: &str, target: u32) {
    use std::os::windows::process::CommandExt as _;
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "vm_role_signal", "--nocapture", "--test-threads", "1"])
        .env(ROLE, role)
        .env(TARGET, target.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        // No console of its own: it attaches to the target's.
        .creation_flags(windows_sys::Win32::System::Threading::DETACHED_PROCESS)
        .status()
        .unwrap();
    // 4: attach failed, 5: send failed.
    assert_eq!(status.code(), Some(0), "{role} helper failed");
}

/// Plays a signalling helper when [`ROLE`] says so; as a normal test it does nothing.
#[test]
fn vm_role_signal() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    #[cfg(windows)]
    if role == "ctrl-c" {
        let target: u32 = std::env::var(TARGET).unwrap().parse().unwrap();
        std::process::exit(win::send_ctrl_c(target));
    }
    let _ = role;
}

// ---------------------------------------------------------------------------------------------
// Linux (tier K).

#[cfg(unix)]
fn kill(signal: &str, pid: u32) {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill {signal} {pid}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_sigterm_stops_the_sandboxes_10_of_10() {
    Box::pin(graceful_rounds("l1", Host::spawn, |host, worker| {
        kill("-TERM", worker);
        assert_eq!(host.exit_code(Duration::from_secs(90)), Some(0));
    }))
    .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_sigkill_ends_the_vms_within_5s_10_of_10() {
    Box::pin(hard_kill_rounds("l3", |host| kill("-KILL", host.pid()))).await;
}

// ---------------------------------------------------------------------------------------------
// Reconcile (K and W).

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vm_reconcile_touches_only_what_puddle_owns() {
    let world = World::new("l4").await;
    let rt = &world.rt;
    let env = &world.env;
    let sb = |tag: &str| env.sandbox_name(tag).unwrap();

    // puddle-owned: known and stopped, unknown and stopped, unknown and left running.
    for tag in ["known", "unknown"] {
        rt.create(spec(&sb(tag)))
            .await
            .unwrap()
            .stop()
            .await
            .unwrap();
    }
    let left_running = rt.create(spec(&sb("running"))).await.unwrap();
    // Foreign: created without puddle's owner label, then stopped.
    let foreign = sb("foreign");
    env.scope(Box::pin(async {
        let s = env
            .sandbox("foreign", IMAGE)
            .unwrap()
            .create()
            .await
            .expect("foreign sandbox");
        s.stop_with_timeout(Duration::from_secs(30))
            .await
            .expect("stop foreign");
    }))
    .await;
    // Stale directories: one with a puddle name, one foreign.
    let sandboxes_dir = env.settings().home().join("sandboxes");
    std::fs::create_dir_all(sandboxes_dir.join(sb("stale").as_str())).unwrap();
    std::fs::create_dir_all(sandboxes_dir.join("Foreign_Dir")).unwrap();
    // Volumes: a known workspace, an unfinished create, one no workspace claims, a foreign one.
    let ws = |id: &str| WorkspaceId::new(&format!("{}-{id}", world.prefix)).unwrap();
    for v in [
        ws("known").volume_name(),
        ws("half").volume_name(),
        ws("unknown").volume_name(),
        VolumeName::new("data").unwrap(),
    ] {
        rt.create_volume(VolumeSpec {
            name: v,
            size: DiskSize::mib(256),
        })
        .await
        .unwrap();
    }

    let inventory = Inventory {
        sandboxes: BTreeSet::from([sb("known")]),
        workspaces: BTreeSet::from([ws("known")]),
        interrupted: BTreeSet::from([ws("half")]),
        ..Inventory::default()
    };
    let report = reconcile(rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();
    eprintln!("{report:?}");

    assert_eq!(report.failures.len(), 0, "{report:?}");
    assert_eq!(report.stopped, [sb("running")]);
    assert_eq!(report.removed, [sb("running"), sb("unknown")]);
    assert_eq!(report.stale_dirs_removed, [sb("stale")]);
    assert_eq!(report.volumes_removed, [ws("half").volume_name()]);
    assert_eq!(report.unknown_volumes, [ws("unknown").volume_name()]);
    for f in [foreign.as_str(), "Foreign_Dir", "data"] {
        assert!(
            report.foreign.iter().any(|x| x == f),
            "{f} not reported foreign: {report:?}"
        );
    }
    assert_eq!(status(rt, &sb("known")).await, Some(SandboxStatus::Stopped));
    assert_eq!(status(rt, &foreign).await, Some(SandboxStatus::Stopped));
    assert_eq!(status(rt, &sb("unknown")).await, None);
    assert!(sandboxes_dir.join("Foreign_Dir").is_dir());
    assert!(
        rt.volume(&ws("known").volume_name())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        rt.volume(&VolumeName::new("data").unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        rt.volume(&ws("unknown").volume_name())
            .await
            .unwrap()
            .is_some()
    );
    drop(left_running);

    for v in [
        ws("known").volume_name(),
        ws("unknown").volume_name(),
        VolumeName::new("data").unwrap(),
    ] {
        rt.remove_volume(&v).await.unwrap();
    }
    let _ = std::fs::remove_dir(sandboxes_dir.join("Foreign_Dir"));
    world.finish().await;
}

// ---------------------------------------------------------------------------------------------
// Process watching.

#[cfg(windows)]
mod proc {
    pub(crate) use super::win::Watch;
}

#[cfg(unix)]
mod proc {
    use std::time::{Duration, Instant};

    /// Linux: a process is gone when `/proc/<pid>` is gone or a zombie.
    pub(crate) struct Watch(Vec<u32>);

    impl Watch {
        pub(crate) fn new(pids: &[u32]) -> Self {
            Self(pids.to_vec())
        }

        fn alive(pid: u32) -> bool {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
                s.rsplit_once(") ")
                    .is_some_and(|(_, rest)| !rest.starts_with('Z'))
            })
        }

        /// Polls (there is no exit event for a process that isn't our child) every 20 ms.
        pub(crate) fn all_gone_within(&self, limit: Duration) -> bool {
            let deadline = Instant::now() + limit;
            loop {
                if !self.0.iter().any(|p| Self::alive(*p)) {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "Win32 console and process calls for the test helpers"
)]
mod win {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Console::{
        AttachConsole, COORD, CTRL_C_EVENT, ClosePseudoConsole, CreatePseudoConsole, FreeConsole,
        GenerateConsoleCtrlEvent, HPCON, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        PROCESS_INFORMATION, PROCESS_SYNCHRONIZE, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows_sys::core::BOOL;

    /// Makes Ctrl-C reach this process's handlers even if its parent disabled it (a process
    /// started in a new process group ignores Ctrl-C, and children inherit that).
    pub(crate) fn process_ctrl_c() {
        // SAFETY: a null handler with FALSE only clears the ignore flag.
        unsafe { SetConsoleCtrlHandler(None, 0) };
    }

    /// Attaches to `target`'s console and sends Ctrl-C to it. Returns the helper's exit code:
    /// 0 sent, 4 attach failed, 5 send failed.
    pub(crate) fn send_ctrl_c(target: u32) -> i32 {
        // SAFETY: plain console calls without pointers; this helper process does nothing else.
        unsafe {
            FreeConsole();
            if AttachConsole(target) == 0 {
                return 4;
            }
            // Ignore it here; every other process on the console gets it.
            SetConsoleCtrlHandler(None, 1);
            let sent = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
            FreeConsole();
            if sent == 0 { 5 } else { 0 }
        }
    }

    fn check(ok: BOOL) -> std::io::Result<()> {
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// An anonymous pipe: (read end, write end), neither inheritable.
    fn pipe() -> std::io::Result<(OwnedHandle, OwnedHandle)> {
        let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: two out pointers to locals; no security attributes.
        check(unsafe { CreatePipe(&raw mut read, &raw mut write, std::ptr::null(), 0) })?;
        // SAFETY: both handles were just created and are owned from here on.
        Ok(unsafe {
            (
                OwnedHandle::from_raw_handle(read),
                OwnedHandle::from_raw_handle(write),
            )
        })
    }

    /// Opens a pseudoconsole and drains its screen output on a thread (a console whose output
    /// isn't read blocks); nothing in that output matters here.
    fn open_console() -> std::io::Result<HPCON> {
        let (console_in, input) = pipe()?;
        let (screen, console_out) = pipe()?;
        let mut console: HPCON = 0;
        // SAFETY: valid pipe handles and an out pointer to a local.
        let hr = unsafe {
            CreatePseudoConsole(
                COORD { X: 120, Y: 30 },
                console_in.as_raw_handle(),
                console_out.as_raw_handle(),
                0,
                &raw mut console,
            )
        };
        if hr < 0 {
            return Err(std::io::Error::from_raw_os_error(hr));
        }
        // The pseudoconsole holds its own duplicates of its ends.
        drop((console_in, console_out));
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::fs::File::from(screen), &mut std::io::sink());
            drop(input);
        });
        Ok(console)
    }

    /// `"exe" args...`, NUL-terminated UTF-16 (the arguments need no quoting).
    fn command_line(exe: &std::path::Path, args: &[&str]) -> Vec<u16> {
        std::iter::once(format!("\"{}\"", exe.display()))
            .chain(args.iter().map(|a| (*a).to_owned()))
            .collect::<Vec<_>>()
            .join(" ")
            .encode_utf16()
            .chain([0])
            .collect()
    }

    /// This process's environment with `vars` set, as a sorted UTF-16 environment block.
    fn env_block(vars: &[(&str, &str)]) -> Vec<u16> {
        let mut env: Vec<(std::ffi::OsString, std::ffi::OsString)> = std::env::vars_os()
            .filter(|(k, _)| !vars.iter().any(|(v, _)| k.eq_ignore_ascii_case(v)))
            .collect();
        env.extend(vars.iter().map(|(k, v)| ((*k).into(), (*v).into())));
        env.sort_by_key(|(k, _)| k.to_ascii_uppercase());
        let mut block: Vec<u16> = Vec::new();
        for (k, v) in &env {
            block.extend(k.encode_wide());
            block.push(u16::from(b'='));
            block.extend(v.encode_wide());
            block.push(0);
        }
        block.push(0);
        block
    }

    /// A process started inside a pseudoconsole the test owns (what Windows Terminal does for
    /// a tab). Its stdout and stderr go to a plain pipe, not through the pseudoconsole.
    pub(crate) struct PtyChild {
        pid: u32,
        process: OwnedHandle,
        console: Option<HPCON>,
    }

    impl PtyChild {
        /// Starts `exe args` with `vars` added to this process's environment. Returns the
        /// child and the read end of its stdout/stderr.
        pub(crate) fn spawn(
            exe: &std::path::Path,
            args: &[&str],
            vars: &[(&str, &str)],
        ) -> std::io::Result<(Self, std::fs::File)> {
            let console = open_console()?;

            // The child's stdout and stderr: the write end, inherited (and only it).
            let (out_read, out_write) = pipe()?;
            // SAFETY: a handle owned above.
            check(unsafe {
                SetHandleInformation(
                    out_write.as_raw_handle(),
                    HANDLE_FLAG_INHERIT,
                    HANDLE_FLAG_INHERIT,
                )
            })?;

            let mut size = 0usize;
            // SAFETY: the documented size query (fails with ERROR_INSUFFICIENT_BUFFER).
            unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &raw mut size) };
            let mut list = vec![0u8; size];
            let attrs: LPPROC_THREAD_ATTRIBUTE_LIST = list.as_mut_ptr().cast();
            // SAFETY: `list` is `size` bytes and outlives every use of `attrs`.
            check(unsafe { InitializeProcThreadAttributeList(attrs, 2, 0, &raw mut size) })?;
            let inherit = [out_write.as_raw_handle()];
            // SAFETY: the values live until CreateProcessW below returns.
            let updated = unsafe {
                check(UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                    console as *const c_void,
                    size_of::<HPCON>(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ))
                .and_then(|()| {
                    check(UpdateProcThreadAttribute(
                        attrs,
                        0,
                        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                        inherit.as_ptr().cast(),
                        size_of_val(&inherit),
                        std::ptr::null_mut(),
                        std::ptr::null(),
                    ))
                })
            };

            // SAFETY: a plain C struct for which all zeroes is valid.
            let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
            startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap();
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdOutput = out_write.as_raw_handle();
            startup.StartupInfo.hStdError = out_write.as_raw_handle();
            startup.lpAttributeList = attrs;

            let mut line = command_line(exe, args);
            let block = env_block(vars);

            // SAFETY: a plain C struct for which all zeroes is valid.
            let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
            let created = updated.and_then(|()| {
                // SAFETY: every pointer refers to a local that outlives the call.
                check(unsafe {
                    CreateProcessW(
                        std::ptr::null(),
                        line.as_mut_ptr(),
                        std::ptr::null(),
                        std::ptr::null(),
                        1,
                        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                        block.as_ptr().cast(),
                        std::ptr::null(),
                        &raw const startup.StartupInfo,
                        &raw mut info,
                    )
                })
            });
            // SAFETY: initialised above; nothing uses it after this.
            unsafe { DeleteProcThreadAttributeList(attrs) };
            drop(list);
            drop(out_write);
            if let Err(e) = created {
                // SAFETY: created above, closed once.
                unsafe { ClosePseudoConsole(console) };
                return Err(e);
            }
            // SAFETY: CreateProcessW returned both handles; the thread one isn't needed.
            let process = unsafe {
                CloseHandle(info.hThread);
                OwnedHandle::from_raw_handle(info.hProcess)
            };
            Ok((
                Self {
                    pid: info.dwProcessId,
                    process,
                    console: Some(console),
                },
                std::fs::File::from(out_read),
            ))
        }

        pub(crate) fn id(&self) -> u32 {
            self.pid
        }

        /// Closes the pseudoconsole: every process on it gets `CTRL_CLOSE_EVENT`. Doesn't wait
        /// (the close itself may wait for the clients on newer Windows builds).
        pub(crate) fn close_console(&mut self) {
            if let Some(console) = self.console.take() {
                // SAFETY: created in `spawn`, closed once.
                std::thread::spawn(move || unsafe { ClosePseudoConsole(console) });
            }
        }

        pub(crate) fn kill(&mut self) -> std::io::Result<()> {
            // SAFETY: the process handle owned by `self`.
            check(unsafe { TerminateProcess(self.process.as_raw_handle(), 1) })
        }

        pub(crate) fn wait(&mut self) -> Option<i32> {
            let mut code = 0u32;
            // SAFETY: the process handle owned by `self`; an out pointer to a local.
            unsafe {
                WaitForSingleObject(self.process.as_raw_handle(), INFINITE);
                if GetExitCodeProcess(self.process.as_raw_handle(), &raw mut code) == 0 {
                    return None;
                }
            }
            Some(code.cast_signed())
        }
    }

    impl Drop for PtyChild {
        fn drop(&mut self) {
            self.close_console();
        }
    }

    /// Process handles opened now, waited on later (so an exit in between isn't missed).
    pub(crate) struct Watch(Vec<(u32, HANDLE)>);

    impl Watch {
        pub(crate) fn new(pids: &[u32]) -> Self {
            Self(
                pids.iter()
                    .map(|&pid| {
                        // SAFETY: OpenProcess has no pointer arguments; a null result (already
                        // gone) is handled by the waiter.
                        (pid, unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) })
                    })
                    .collect(),
            )
        }

        pub(crate) fn all_gone_within(&self, limit: Duration) -> bool {
            let deadline = Instant::now() + limit;
            self.0.iter().all(|&(_, handle)| {
                if handle.is_null() {
                    return true;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                let ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX);
                // SAFETY: a live process handle opened in `new`.
                unsafe { WaitForSingleObject(handle, ms) == WAIT_OBJECT_0 }
            })
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            for &(_, handle) in &self.0 {
                if !handle.is_null() {
                    // SAFETY: opened in `new`, closed once.
                    unsafe { CloseHandle(handle) };
                }
            }
        }
    }
}
