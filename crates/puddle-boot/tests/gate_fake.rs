// SPDX-License-Identifier: GPL-3.0-or-later
//! The readiness gate on the fake runtime: the hook runs as root after every create, start and
//! adoption; nobody gets exec or SSH before it returns 0; a failure stops the sandbox and shows
//! the hook's stderr.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use puddle_boot::{
    BOOT_SH_GUEST, BootError, BootFailure, BootHook, BootPlan, Gate, GateState, GatedError,
    NotReady, PLAN_HEADER, with_boot_mounts,
};
use puddle_compute::fake::{Call, ExecContext, FakeRuntime, Fault, Op};
use puddle_compute::{
    ComputeError, ExecOutput, ExecRequest, FileMount, ImageConfig, Runtime, Sandbox, SandboxSpec,
};
use puddle_types::{GuestPath, ImageRef, SandboxName, SandboxStatus};
use tokio::io::AsyncReadExt as _;

fn name(n: &str) -> SandboxName {
    SandboxName::new(n).unwrap()
}

fn spec(n: &str) -> SandboxSpec {
    let mounts = ["/puddle/boot.sh", "/puddle/agent-supervise.sh"]
        .map(|g| FileMount::read_only("host-file", GuestPath::new(g).unwrap()))
        .to_vec();
    let spec = SandboxSpec::new(name(n), ImageRef::new(FakeRuntime::DEBIAN).unwrap());
    with_boot_mounts(spec, mounts, Some(std::path::Path::new("agent-bin")))
}

fn plan() -> BootPlan {
    BootPlan::builder(&ImageConfig::default()).build().unwrap()
}

fn is_hook(r: &ExecRequest) -> bool {
    r.args.first().map(String::as_str) == Some(BOOT_SH_GUEST)
}

/// A fake `boot.sh`: checks how it was called, counts runs, answers with `code` and `stderr`.
struct FakeHook {
    runs: Arc<AtomicU32>,
}

impl FakeHook {
    fn install(rt: &FakeRuntime, code: i32, stderr: &'static str, delay: Duration) -> Self {
        let runs = Arc::new(AtomicU32::new(0));
        let counter = runs.clone();
        rt.on_exec(
            move |_: &mut ExecContext<'_>, r: &ExecRequest| -> Option<ExecOutput> {
                if !is_hook(r) {
                    return None;
                }
                assert_eq!(r.program, "/bin/sh");
                assert_eq!(r.user.as_deref(), Some("root"));
                assert!(r.stdin.starts_with(PLAN_HEADER.as_bytes()));
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(delay);
                Some(ExecOutput::new(code, "puddle-boot: ready\n", stderr))
            },
        );
        Self { runs }
    }

    fn runs(&self) -> u32 {
        self.runs.load(Ordering::SeqCst)
    }
}

fn exec_calls(calls: &[Call]) -> Vec<String> {
    calls
        .iter()
        .filter(|c| c.op == Op::Exec)
        .filter_map(|c| c.detail.clone())
        .collect()
}

#[tokio::test]
async fn hook_runs_after_create_before_any_user_exec() {
    let rt = FakeRuntime::new();
    let hook = FakeHook::install(&rt, 0, "", Duration::ZERO);
    let gate = Gate::new();
    let sb = BootHook::new()
        .create(&rt, spec("a"), &plan(), &gate)
        .await
        .unwrap();
    assert_eq!(gate.state(), GateState::Ready);
    assert_eq!(hook.runs(), 1);
    assert_eq!(sb.name().as_str(), "a");
    assert!(sb.boot_report().stdout.contains("ready"));
    assert_eq!(sb.status().await.unwrap(), SandboxStatus::Running);
    let out = sb.exec(ExecRequest::sh("echo hi")).await.unwrap();
    assert_eq!(out.stdout_text(), "hi\n");
    let calls = rt.calls();
    let first_exec = calls.iter().position(|c| c.op == Op::Exec).unwrap();
    let create = calls.iter().position(|c| c.op == Op::Create).unwrap();
    assert!(create < first_exec);
    assert_eq!(
        exec_calls(&calls),
        ["/bin/sh /puddle/boot.sh", "sh -c echo hi"]
    );
    sb.stop().await.unwrap();
    assert_eq!(gate.state(), GateState::Down);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn callers_wait_while_booting_then_pass() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(&rt, 0, "", Duration::from_millis(300));
    let gate = Gate::new();
    let booting = {
        let (rt, gate) = (rt.clone(), gate.clone());
        tokio::spawn(async move { BootHook::new().create(&rt, spec("b"), &plan(), &gate).await })
    };
    // An SSH endpoint holding the gate sees `Booting` and waits instead of being refused.
    while gate.state() != GateState::Booting {
        tokio::task::yield_now().await;
    }
    gate.wait_ready(Duration::from_secs(10)).await.unwrap();
    let sb = booting.await.unwrap().unwrap();
    assert_eq!(exec_calls(&rt.calls()).len(), 1, "only the hook ran so far");
    sb.stop().await.unwrap();
}

#[tokio::test]
async fn a_failed_hook_stops_the_sandbox_and_shows_its_stderr() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(
        &rt,
        1,
        "puddle-boot: error: update-ca-certificates failed: boom\n",
        Duration::ZERO,
    );
    let gate = Gate::new();
    let err = BootHook::new()
        .create(&rt, spec("c"), &plan(), &gate)
        .await
        .unwrap_err();
    let failure = BootFailure::Exited {
        code: 1,
        stderr: "puddle-boot: error: update-ca-certificates failed: boom".into(),
    };
    assert_eq!(
        err,
        BootError::Hook {
            sandbox: "c".into(),
            failure: Box::new(failure.clone()),
            stop_error: None
        }
    );
    assert!(
        err.to_string()
            .contains("update-ca-certificates failed: boom"),
        "{err}"
    );
    assert_eq!(gate.state(), GateState::Failed(failure.clone()));
    assert_eq!(
        gate.wait_ready(Duration::from_secs(1)).await,
        Err(NotReady::Failed(failure))
    );
    let info = rt.list().await.unwrap();
    assert_eq!(info[0].status, SandboxStatus::Stopped);
}

#[tokio::test]
async fn a_failed_stop_after_a_failed_hook_is_reported_too() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(&rt, 3, "x", Duration::ZERO);
    let boom = ComputeError::Runtime {
        op: "stop",
        message: "injected".into(),
    };
    rt.inject(Op::Stop, Fault::once(boom.clone()));
    let err = BootHook::new()
        .create(&rt, spec("d"), &plan(), &Gate::new())
        .await
        .unwrap_err();
    assert!(matches!(err, BootError::Hook { stop_error: Some(e), .. } if *e == boom));
}

#[tokio::test]
async fn start_and_adopt_rerun_the_hook_and_stop_closes_the_gate() {
    let rt = FakeRuntime::new();
    let hook = FakeHook::install(&rt, 0, "", Duration::ZERO);
    let gate = Gate::new();
    let boot = BootHook::new();
    let sb = boot.create(&rt, spec("e"), &plan(), &gate).await.unwrap();
    sb.stop().await.unwrap();
    assert_eq!(
        gate.wait_ready(Duration::from_secs(1)).await,
        Err(NotReady::Down)
    );
    let refused = sb.exec(ExecRequest::sh("true")).await.unwrap_err();
    assert_eq!(
        refused,
        GatedError::NotReady {
            sandbox: "e".into(),
            reason: NotReady::Down
        }
    );

    let sb = boot.start(&rt, &name("e"), &plan(), &gate).await.unwrap();
    assert_eq!(hook.runs(), 2, "the hook runs on every start");
    assert_eq!(gate.state(), GateState::Ready);

    // A new puddle re-adopts the running sandbox and runs the hook again.
    let adopted = boot.adopt(&rt, &name("e"), &plan(), &gate).await.unwrap();
    assert_eq!(hook.runs(), 3);
    assert!(!adopted.ungated().owns_lifecycle());
    sb.stop().await.unwrap();
}

#[tokio::test]
async fn gated_ssh_is_refused_when_closed_and_served_when_ready() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(&rt, 0, "", Duration::ZERO);
    let gate = Gate::new();
    let sb = BootHook::new()
        .create(&rt, spec("f"), &plan(), &gate)
        .await
        .unwrap();
    let (client, server) = tokio::io::duplex(1024);
    let serving = sb.serve_ssh(server);
    let reading = async move {
        let mut client = client;
        let mut banner = [0_u8; 8];
        client.read_exact(&mut banner).await.unwrap();
        drop(client);
        banner
    };
    let (ssh_result, banner) = tokio::join!(serving, reading);
    ssh_result.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");

    gate.close();
    let (_client, server) = tokio::io::duplex(64);
    assert!(matches!(
        sb.serve_ssh(server).await,
        Err(GatedError::NotReady {
            reason: NotReady::Down,
            ..
        })
    ));
    sb.ungated().stop().await.unwrap();
}

#[tokio::test]
async fn runtime_errors_pass_through_the_gate() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(&rt, 0, "", Duration::ZERO);
    let sb = BootHook::new()
        .create(&rt, spec("g"), &plan(), &Gate::new())
        .await
        .unwrap();
    let boom = ComputeError::Runtime {
        op: "exec",
        message: "injected".into(),
    };
    rt.inject(Op::Exec, Fault::once(boom.clone()));
    assert_eq!(
        sb.exec(ExecRequest::sh("true")).await.unwrap_err(),
        GatedError::Compute(boom)
    );
    sb.stop().await.unwrap();
}

#[tokio::test]
async fn missing_mounts_are_refused_before_anything_is_created() {
    let rt = FakeRuntime::new();
    let bare = SandboxSpec::new(name("h"), ImageRef::new(FakeRuntime::DEBIAN).unwrap());
    let err = BootHook::new()
        .create(&rt, bare, &plan(), &Gate::new())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        BootError::MissingMount {
            guest: BOOT_SH_GUEST.into()
        }
    );
    // The agent is checked too, unless the plan starts none.
    let no_agent_mount = with_boot_mounts(
        SandboxSpec::new(name("h"), ImageRef::new(FakeRuntime::DEBIAN).unwrap()),
        ["/puddle/boot.sh", "/puddle/agent-supervise.sh"]
            .map(|g| FileMount::read_only("x", GuestPath::new(g).unwrap()))
            .to_vec(),
        None,
    );
    let err = BootHook::new()
        .create(&rt, no_agent_mount, &plan(), &Gate::new())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("/puddle/puddle-agent"), "{err}");
    assert!(rt.calls().iter().all(|c| c.op != Op::Create));
}

#[tokio::test]
async fn a_failed_runtime_call_restores_the_gate() {
    let rt = FakeRuntime::new();
    let _hook = FakeHook::install(&rt, 0, "", Duration::ZERO);
    let gate = Gate::new();
    let hook_runner = BootHook::new();
    let boom = ComputeError::Runtime {
        op: "create",
        message: "injected".into(),
    };
    rt.inject(Op::Create, Fault::once(boom.clone()));
    let err = hook_runner
        .create(&rt, spec("i"), &plan(), &gate)
        .await
        .unwrap_err();
    assert_eq!(err, BootError::Compute(boom));
    assert_eq!(gate.state(), GateState::Down);

    // A second start of a running sandbox is refused by the runtime and leaves it Ready.
    let sb = hook_runner
        .create(&rt, spec("i"), &plan(), &gate)
        .await
        .unwrap();
    assert!(matches!(
        hook_runner.start(&rt, &name("i"), &plan(), &gate).await,
        Err(BootError::Compute(ComputeError::InvalidState { .. }))
    ));
    assert_eq!(gate.state(), GateState::Ready);
    sb.stop().await.unwrap();
    assert!(
        hook_runner
            .adopt(&rt, &name("i"), &plan(), &gate)
            .await
            .is_err()
    );
    assert_eq!(gate.state(), GateState::Down);
}

#[tokio::test]
async fn an_image_without_sh_gives_a_clear_error() {
    // No handler: the fake answers like an image without /bin/sh (127, "not found").
    let rt = FakeRuntime::new();
    let gate = Gate::new();
    let err = BootHook::new()
        .create(&rt, spec("j"), &plan(), &gate)
        .await
        .unwrap_err();
    let BootError::Hook { failure, .. } = &err else {
        panic!("{err:?}")
    };
    assert!(
        matches!(**failure, BootFailure::NoShell { .. }),
        "{failure:?}"
    );
    assert!(
        err.to_string().contains("no POSIX shell at /bin/sh"),
        "{err}"
    );
}

#[tokio::test]
async fn a_hook_that_hangs_times_out_as_a_failure() {
    let rt = FakeRuntime::new();
    // The fake's built-in `sh` isn't the hook; make the hook's exec time out instead.
    rt.inject(
        Op::Exec,
        Fault::once(ComputeError::ExecTimeout {
            sandbox: "k".into(),
            program: "/bin/sh".into(),
            timeout: Duration::from_secs(1),
        }),
    );
    let err = BootHook::new()
        .with_timeout(Duration::from_secs(1))
        .create(&rt, spec("k"), &plan(), &Gate::new())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("boot hook could not run"), "{err}");
}
