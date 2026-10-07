// SPDX-License-Identifier: GPL-3.0-or-later
//! The endpoint and the bridge over a real owner-only endpoint (Unix socket, Windows named
//! pipe): the readiness gate, refusals, one connection per client, large transfers, closing,
//! and the end-of-stream behaviour that differs between the two (a pipe has no half-close).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use puddle_boot::{BOOT_SH_GUEST, BootHook, BootPlan, Gate, GateState, with_boot_mounts};
use puddle_compute::fake::{ExecContext, FakeRuntime, SSH_BANNER};
use puddle_compute::{ExecOutput, ExecRequest, FileMount, Runtime, SandboxSpec, SshStream};
use puddle_ipc::IpcRoot;
use puddle_ssh::bridge::{self, BridgeError, Report, SessionEnd};
use puddle_ssh::{SshEndpoint, SshTarget};
use puddle_types::{GuestPath, ImageRef, SandboxName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(30);

/// A fake `boot.sh` whose exit code the test sets.
fn install_hook(rt: &FakeRuntime, stderr: &'static str) -> Arc<AtomicI32> {
    let code = Arc::new(AtomicI32::new(0));
    let c = code.clone();
    rt.on_exec(
        move |_: &mut ExecContext<'_>, r: &ExecRequest| -> Option<ExecOutput> {
            (r.args.first().map(String::as_str) == Some(BOOT_SH_GUEST)).then(|| {
                let code = c.load(Ordering::SeqCst);
                ExecOutput::new(code, "", if code == 0 { "" } else { stderr })
            })
        },
    );
    code
}

fn spec(name: &str) -> SandboxSpec {
    let mounts = ["/puddle/boot.sh", "/puddle/agent-supervise.sh"]
        .map(|g| FileMount::read_only("host-file", GuestPath::new(g).unwrap()))
        .to_vec();
    let spec = SandboxSpec::new(
        SandboxName::new(name).unwrap(),
        ImageRef::new(FakeRuntime::DEBIAN).unwrap(),
    );
    // Every plan merges VS Code's Machine settings, so the agent binary is mounted.
    with_boot_mounts(spec, mounts, Some(Path::new("agent")))
}

async fn plan(rt: &FakeRuntime) -> BootPlan {
    let config = rt
        .pull_image(&ImageRef::new(FakeRuntime::DEBIAN).unwrap())
        .await
        .unwrap();
    BootPlan::builder(&config).no_agent().build().unwrap()
}

/// `ssh`'s side of a bridge: the test writes `stdin` and reads `stdout`.
struct Client {
    stdin: DuplexStream,
    stdout: DuplexStream,
    bridge: JoinHandle<Result<Report, BridgeError>>,
}

fn bridge_to(endpoint: &Path) -> Client {
    let (stdin, bridge_in) = duplex(1 << 20);
    let (bridge_out, stdout) = duplex(1 << 20);
    let endpoint = endpoint.to_path_buf();
    let bridge = tokio::spawn(async move { bridge::run(&endpoint, bridge_in, bridge_out).await });
    Client {
        stdin,
        stdout,
        bridge,
    }
}

async fn read_line(r: &mut DuplexStream) -> String {
    let mut line = Vec::new();
    let mut b = [0_u8; 1];
    while !line.ends_with(b"\n") {
        assert_eq!(timeout(WAIT, r.read(&mut b)).await.unwrap().unwrap(), 1);
        line.push(b[0]);
    }
    String::from_utf8(line).unwrap()
}

async fn refusal(endpoint: &Path) -> String {
    let mut client = bridge_to(endpoint);
    let err = timeout(WAIT, &mut client.bridge)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let mut out = Vec::new();
    client.stdout.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"", "a refused client gets nothing on stdout");
    match err {
        BridgeError::Refused { reason } => reason,
        other => panic!("not a refusal: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ready_sandbox_is_served_and_the_session_ends_by_platform_rules() {
    let rt = FakeRuntime::new();
    let _code = install_hook(&rt, "");
    let gate = Gate::new();
    let sb = BootHook::new()
        .create(&rt, spec("box"), &plan(&rt).await, &gate)
        .await
        .unwrap();
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), Arc::new(sb)).unwrap();

    let mut client = bridge_to(endpoint.endpoint().path());
    assert_eq!(read_line(&mut client.stdout).await, SSH_BANNER);
    client.stdin.write_all(b"SSH-2.0-client\r\n").await.unwrap();
    client.stdin.shutdown().await.unwrap();
    if cfg!(windows) {
        // No half-close on a pipe: the fake server (which waits for EOF) never learns the
        // input ended, so the session runs on until the server side closes. A real SSH server
        // ends it on the client's DISCONNECT; here closing the endpoint does.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!client.bridge.is_finished());
        endpoint.close().await;
        let report = timeout(WAIT, client.bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(report.end, SessionEnd::ServerClosed);
        assert!(report.input_ended);
    } else {
        // A socket half-closes: the server sees EOF, ends the session, and the bridge ends.
        let report = timeout(WAIT, client.bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(report.end, SessionEnd::ServerClosed);
        assert!(report.input_ended);
        assert_eq!(report.received, SSH_BANNER.len() as u64);
        assert_eq!(report.sent, 16);
        endpoint.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_sandbox_refuses_with_a_reason() {
    let rt = FakeRuntime::new();
    let _code = install_hook(&rt, "");
    let gate = Gate::new();
    let sb = Arc::new(
        BootHook::new()
            .create(&rt, spec("box"), &plan(&rt).await, &gate)
            .await
            .unwrap(),
    );
    sb.stop().await.unwrap();
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), sb).unwrap();
    assert_eq!(
        refusal(endpoint.endpoint().path()).await,
        "sandbox \"box\": sandbox is not running"
    );
    endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_boot_refuses_with_its_cleaned_stderr() {
    let rt = FakeRuntime::new();
    let code = install_hook(&rt, "apt: \x1b[31mbroken\x1b[0m\nsecond line\u{202E}\n");
    let gate = Gate::new();
    let plan = plan(&rt).await;
    let hook = BootHook::new();
    let first = Arc::new(hook.create(&rt, spec("box"), &plan, &gate).await.unwrap());
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), first.clone()).unwrap();
    // The next boot's hook fails; the endpoint shares the sandbox's gate.
    first.stop().await.unwrap();
    code.store(1, Ordering::SeqCst);
    let name = SandboxName::new("box").unwrap();
    assert!(hook.start(&rt, &name, &plan, &gate).await.is_err());
    assert!(matches!(gate.state(), GateState::Failed(_)));
    assert_eq!(
        refusal(endpoint.endpoint().path()).await,
        "sandbox \"box\": sandbox failed to boot: boot hook exited with status 1: apt: [31mbroken [0m second line"
    );
    endpoint.close().await;
}

/// An SSH-like server for the tests: banner `SSH-2.0-test-<n>`, then echoes until `quota` bytes
/// came back or the client's EOF, then closes (the way an SSH server ends a session itself).
struct Echo {
    served: AtomicUsize,
    live: AtomicUsize,
    peak: AtomicUsize,
    saw_eof: AtomicBool,
    quota: u64,
    release: Semaphore,
    hold: bool,
}

impl Echo {
    fn new(quota: u64, hold: bool) -> Arc<Self> {
        Arc::new(Self {
            served: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            saw_eof: AtomicBool::new(false),
            quota,
            release: Semaphore::new(0),
            hold,
        })
    }
}

impl SshTarget for Echo {
    type Error = std::io::Error;

    fn label(&self) -> String {
        "echo".into()
    }

    fn admit(&self) -> impl Future<Output = Result<(), String>> {
        std::future::ready(Ok(()))
    }

    async fn serve<S: SshStream>(&self, mut stream: S) -> Result<(), std::io::Error> {
        let n = self.served.fetch_add(1, Ordering::SeqCst) + 1;
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        stream
            .write_all(format!("SSH-2.0-test-{n}\r\n").as_bytes())
            .await?;
        if self.hold {
            self.release.acquire().await.unwrap().forget();
        }
        let mut buf = vec![0_u8; 64 * 1024];
        let mut echoed = 0_u64;
        while echoed < self.quota {
            let got = stream.read(&mut buf).await?;
            if got == 0 {
                self.saw_eof.store(true, Ordering::SeqCst);
                break;
            }
            stream.write_all(&buf[..got]).await?;
            echoed += got as u64;
        }
        self.live.fetch_sub(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_client_gets_its_own_connection() {
    const CLIENTS: usize = 16;
    let echo = Echo::new(4, true);
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), echo.clone()).unwrap();
    let mut clients = Vec::new();
    for _ in 0..CLIENTS {
        clients.push(bridge_to(endpoint.endpoint().path()));
    }
    let mut banners = Vec::new();
    for c in &mut clients {
        banners.push(read_line(&mut c.stdout).await);
    }
    banners.sort();
    banners.dedup();
    assert_eq!(banners.len(), CLIENTS, "{banners:?}");
    // All sixteen are served at the same time, each by its own serve call.
    assert_eq!(echo.peak.load(Ordering::SeqCst), CLIENTS);
    echo.release.add_permits(CLIENTS);
    for mut c in clients {
        c.stdin.write_all(b"ping").await.unwrap();
        let mut back = [0_u8; 4];
        timeout(WAIT, c.stdout.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, b"ping");
        let report = timeout(WAIT, c.bridge).await.unwrap().unwrap().unwrap();
        assert_eq!(report.end, SessionEnd::ServerClosed);
    }
    assert_eq!(echo.served.load(Ordering::SeqCst), CLIENTS);
    endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_transfer_through_the_endpoint_arrives_intact() {
    const LEN: u64 = 32 * 1024 * 1024;
    let echo = Echo::new(LEN, false);
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), echo).unwrap();
    let Client {
        mut stdin,
        mut stdout,
        bridge,
    } = bridge_to(endpoint.endpoint().path());
    assert_eq!(read_line(&mut stdout).await, "SSH-2.0-test-1\r\n");
    let send = async move {
        let mut chunk = vec![0_u8; 40_000];
        let mut off = 0_u64;
        while off < LEN {
            let n = usize::try_from((LEN - off).min(chunk.len() as u64)).unwrap();
            for (j, b) in chunk[..n].iter_mut().enumerate() {
                *b = byte_at(off + j as u64);
            }
            stdin.write_all(&chunk[..n]).await.unwrap();
            off += n as u64;
        }
        stdin
    };
    let receive = async move {
        let mut buf = vec![0_u8; 50_000];
        let mut off = 0_u64;
        loop {
            let n = stdout.read(&mut buf).await.unwrap();
            if n == 0 {
                return off;
            }
            for (j, b) in buf[..n].iter().enumerate() {
                assert_eq!(*b, byte_at(off + j as u64), "byte {}", off + j as u64);
            }
            off += n as u64;
        }
    };
    let (stdin, got) = timeout(WAIT * 4, async { tokio::join!(send, receive) })
        .await
        .unwrap();
    assert_eq!(got, LEN);
    let report = timeout(WAIT, bridge).await.unwrap().unwrap().unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert_eq!(report.sent, LEN);
    assert_eq!(report.received, LEN + "SSH-2.0-test-1\r\n".len() as u64);
    drop(stdin);
    endpoint.close().await;
}

fn byte_at(i: u64) -> u8 {
    let x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (x >> 56).to_le_bytes()[0]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_eof_reaches_the_server_only_on_unix() {
    let echo = Echo::new(u64::MAX, false);
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), echo.clone()).unwrap();
    let mut client = bridge_to(endpoint.endpoint().path());
    read_line(&mut client.stdout).await;
    client.stdin.write_all(b"last").await.unwrap();
    client.stdin.shutdown().await.unwrap();
    // Either way the server's answer to the last input still arrives.
    let mut back = [0_u8; 4];
    timeout(WAIT, client.stdout.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"last");
    if cfg!(windows) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!echo.saw_eof.load(Ordering::SeqCst));
        assert!(!client.bridge.is_finished());
        endpoint.close().await;
        timeout(WAIT, client.bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    } else {
        let report = timeout(WAIT, client.bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(echo.saw_eof.load(Ordering::SeqCst));
        assert!(report.input_ended);
        endpoint.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_endpoint_ends_sessions_and_removes_it() {
    let echo = Echo::new(u64::MAX, false);
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), echo).unwrap();
    let path: PathBuf = endpoint.endpoint().path().to_path_buf();
    let mut client = bridge_to(&path);
    read_line(&mut client.stdout).await;
    timeout(WAIT, endpoint.close())
        .await
        .expect("close returns");
    // The live session ends (stdin stays open), and nobody can connect any more.
    let report = timeout(WAIT, client.bridge)
        .await
        .expect("the live session ends")
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    assert!(!report.input_ended);
    // A late client is told so, never left hanging: NotFound, or on Windows possibly no answer,
    // because a pipe instance whose last read was cancelled can briefly outlive the listener
    // and take a client that nobody serves.
    let (_stdin, input) = duplex(64);
    let (output, _stdout) = duplex(64);
    let late = timeout(
        WAIT,
        bridge::run_with(&path, input, output, Duration::from_secs(2)),
    )
    .await
    .expect("a late client is answered");
    assert!(
        matches!(late, Err(BridgeError::NotFound { .. }))
            || (cfg!(windows) && matches!(late, Err(BridgeError::NoAnswer { .. }))),
        "{late:?}"
    );
    drop(client.stdin);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_endpoint_ends_its_sessions() {
    let echo = Echo::new(u64::MAX, false);
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), echo).unwrap();
    let mut client = bridge_to(endpoint.endpoint().path());
    read_line(&mut client.stdout).await;
    drop(endpoint);
    let report = timeout(WAIT, client.bridge)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.end, SessionEnd::ServerClosed);
    drop(client.stdin);
}

/// Refuses every client with guest-controlled text.
struct Hostile;

impl SshTarget for Hostile {
    type Error = std::io::Error;

    fn label(&self) -> String {
        "hostile".into()
    }

    fn admit(&self) -> impl Future<Output = Result<(), String>> {
        let mut reason = String::from("evil\r\n\x1b]0;title\x07SSH-2.0-fake\r\n");
        reason.push_str(&"x".repeat(10_000));
        std::future::ready(Err(reason))
    }

    fn serve<S: SshStream>(&self, _stream: S) -> impl Future<Output = Result<(), std::io::Error>> {
        std::future::ready(Err(std::io::Error::other("never admitted")))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_refusal_text_is_one_capped_line() {
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), Arc::new(Hostile)).unwrap();
    let reason = refusal(endpoint.endpoint().path()).await;
    assert!(
        reason.starts_with("evil ]0;title SSH-2.0-fake xxx"),
        "{reason}"
    );
    assert!(reason.chars().all(|c| !c.is_control()));
    assert_eq!(reason.chars().count(), 1024);
    endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_endpoint_says_so() {
    let root = IpcRoot::new().unwrap();
    let path = root.endpoint().unwrap().path().to_path_buf();
    let err = bridge_to(&path).bridge.await.unwrap().unwrap_err();
    let BridgeError::NotFound { endpoint } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(endpoint, &path);
    let msg = err.to_string();
    assert!(msg.starts_with("no puddle SSH endpoint at "), "{msg}");
    assert!(msg.contains("the sandbox is not running"), "{msg}");
}

/// Sends a banner, then fails the session.
struct Failing;

impl SshTarget for Failing {
    type Error = std::io::Error;

    fn label(&self) -> String {
        "failing".into()
    }

    fn admit(&self) -> impl Future<Output = Result<(), String>> {
        std::future::ready(Ok(()))
    }

    async fn serve<S: SshStream>(&self, mut stream: S) -> Result<(), std::io::Error> {
        stream.write_all(b"SSH-2.0-failing\r\n").await?;
        Err(std::io::Error::other("runtime lost the VM"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_session_closes_the_client_and_the_endpoint_keeps_serving() {
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), Arc::new(Failing)).unwrap();
    // Each ends server-side with a read in flight; later clients must still be served.
    for _ in 0..20 {
        let mut client = bridge_to(endpoint.endpoint().path());
        assert_eq!(read_line(&mut client.stdout).await, "SSH-2.0-failing\r\n");
        let report = timeout(WAIT, client.bridge)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(report.end, SessionEnd::ServerClosed);
    }
    endpoint.close().await;
}

/// Refuses, but only once the test lets it decide.
struct SlowRefusal {
    decide: Semaphore,
}

impl SshTarget for SlowRefusal {
    type Error = std::io::Error;

    fn label(&self) -> String {
        "slow".into()
    }

    async fn admit(&self) -> Result<(), String> {
        self.decide.acquire().await.unwrap().forget();
        Err("stopped".into())
    }

    fn serve<S: SshStream>(&self, _stream: S) -> impl Future<Output = Result<(), std::io::Error>> {
        std::future::ready(Err(std::io::Error::other("never admitted")))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_leaves_early_doesnt_disturb_the_endpoint() {
    let target = Arc::new(SlowRefusal {
        decide: Semaphore::new(0),
    });
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), target.clone()).unwrap();
    // Gone before the hello or before the refusal, whichever the race gives.
    let gone = puddle_ipc::connect(endpoint.endpoint().path())
        .await
        .unwrap();
    drop(gone);
    target.decide.add_permits(2);
    // The next client still gets its refusal.
    assert_eq!(refusal(endpoint.endpoint().path()).await, "stopped");
    endpoint.close().await;
}
