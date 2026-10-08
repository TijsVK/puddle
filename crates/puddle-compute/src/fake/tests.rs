// SPDX-License-Identifier: GPL-3.0-or-later
//! The fake's own controls and the built-ins; the shared behaviour is in the contract suite.

use std::time::Duration;

use puddle_types::{GuestPath, ImageRef, SandboxName, VolumeName, WorkspaceStatus};

use super::*;
use crate::{FileMount, OwnedDisk, VolumeMount};

fn name(s: &str) -> SandboxName {
    SandboxName::new(s).unwrap()
}

fn path(s: &str) -> GuestPath {
    GuestPath::new(s).unwrap()
}

fn vol(s: &str) -> VolumeName {
    VolumeName::new(s).unwrap()
}

fn spec(n: &str) -> SandboxSpec {
    SandboxSpec::new(name(n), ImageRef::new(FakeRuntime::DEBIAN).unwrap())
}

fn boom(op: &'static str) -> ComputeError {
    ComputeError::Runtime {
        op,
        message: "injected".into(),
    }
}

async fn run(sb: &FakeSandbox, program: &str, args: &[&str]) -> ExecOutput {
    sb.exec(ExecRequest::new(program, args.iter().copied()))
        .await
        .unwrap()
}

#[tokio::test]
async fn fault_once_fails_one_call_then_clears() {
    let rt = FakeRuntime::new();
    rt.inject(Op::Probe, Fault::once(boom("probe")));
    assert_eq!(rt.probe().await.unwrap_err(), boom("probe"));
    assert!(rt.probe().await.is_ok());
}

#[tokio::test]
async fn fault_after_times_and_always() {
    let rt = FakeRuntime::new();
    rt.inject(Op::List, Fault::once(boom("list")).after(1).times(2));
    assert!(rt.list().await.is_ok());
    assert!(rt.list().await.is_err());
    assert!(rt.list().await.is_err());
    assert!(rt.list().await.is_ok());
    rt.inject(Op::List, Fault::always(boom("list")));
    for _ in 0..5 {
        assert!(rt.list().await.is_err());
    }
    rt.clear_faults();
    assert!(rt.list().await.is_ok());
}

#[tokio::test]
async fn fault_only_for_matches_its_target() {
    let rt = FakeRuntime::new();
    rt.inject(Op::Create, Fault::once(boom("create")).only_for("b"));
    let _a = rt.create(spec("a")).await.unwrap();
    assert_eq!(rt.create(spec("b")).await.unwrap_err(), boom("create"));
    let _b = rt.create(spec("b")).await.unwrap();
}

#[tokio::test]
async fn every_operation_can_fail() {
    let rt = FakeRuntime::new();
    let sb = rt.create(spec("a")).await.unwrap();
    let n = name("a");
    let v = vol("v");
    let ops = [
        Op::Probe,
        Op::PullImage,
        Op::Create,
        Op::Start,
        Op::Get,
        Op::SetMemory,
        Op::List,
        Op::Remove,
        Op::StaleDirs,
        Op::RemoveStaleDir,
        Op::CreateVolume,
        Op::Volume,
        Op::ListVolumes,
        Op::RemoveVolume,
        Op::Status,
        Op::Stop,
        Op::Exec,
        Op::ServeSsh,
    ];
    for op in ops {
        rt.inject(op, Fault::once(boom("x")));
    }
    let image = ImageRef::new(FakeRuntime::DEBIAN).unwrap();
    let vspec = VolumeSpec {
        name: v.clone(),
        size: DiskSize::mib(1),
    };
    let (_client, server) = tokio::io::duplex(64);
    let results = [
        rt.probe().await.err(),
        rt.pull_image(&image).await.err(),
        rt.create(spec("b")).await.err(),
        rt.start(&n).await.err(),
        rt.get(&n).await.err(),
        rt.set_memory(&n, MemoryMib::MIN).await.err(),
        rt.list().await.err(),
        rt.remove(&n).await.err(),
        rt.stale_dirs().await.err(),
        rt.remove_stale_dir(&n).await.err(),
        rt.create_volume(vspec).await.err(),
        rt.volume(&v).await.err(),
        rt.list_volumes().await.err(),
        rt.remove_volume(&v).await.err(),
        sb.status().await.err(),
        sb.stop().await.err(),
        sb.exec(ExecRequest::sh("exit 0")).await.err(),
        sb.serve_ssh(server).await.err(),
    ];
    for (op, result) in ops.iter().zip(results) {
        assert_eq!(result, Some(boom("x")), "{op:?}");
    }
    assert_eq!(sb.status().await.unwrap(), WorkspaceStatus::Running);
}

#[tokio::test]
async fn calls_are_logged_in_order_with_targets() {
    let rt = FakeRuntime::new();
    let sb = rt.create(spec("a")).await.unwrap();
    sb.exec(ExecRequest::new("fstrim", ["/workspaces"]))
        .await
        .unwrap();
    sb.stop().await.unwrap();
    let calls = rt.calls();
    let ops: Vec<Op> = calls.iter().map(|c| c.op).collect();
    assert_eq!(ops, [Op::Create, Op::Exec, Op::Stop]);
    assert!(calls.iter().all(|c| c.target.as_deref() == Some("a")));
    assert_eq!(calls[1].detail.as_deref(), Some("fstrim /workspaces"));
}

#[tokio::test]
async fn handlers_run_before_builtins_newest_first() {
    let rt = FakeRuntime::new();
    rt.on_exec(|_: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "fstrim").then(|| ExecOutput::new(0, "old", ""))
    });
    rt.on_exec(|ctx: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "fstrim").then(|| ExecOutput::new(0, format!("new {}", ctx.sandbox()), ""))
    });
    rt.on_exec(|ctx: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "true").then(|| {
            ctx.write(&GuestPath::new("/hook-ran").unwrap(), b"y".to_vec())
                .unwrap();
            ExecOutput::new(5, "", "")
        })
    });
    let sb = rt.create(spec("a")).await.unwrap();
    assert_eq!(run(&sb, "fstrim", &[]).await.stdout_text(), "new a");
    assert_eq!(run(&sb, "true", &[]).await.status.code, 5);
    assert_eq!(run(&sb, "cat", &["/hook-ran"]).await.stdout_text(), "y");
}

#[tokio::test]
async fn handlers_see_the_merged_env() {
    let rt = FakeRuntime::new();
    rt.on_exec(|ctx: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "env-count").then(|| ExecOutput::new(0, ctx.env().len().to_string(), ""))
    });
    let mut env = puddle_types::GuestEnv::new();
    env.set("A", "1").unwrap();
    let sb = rt.create(spec("a").with_env(&env)).await.unwrap();
    let mut more = puddle_types::GuestEnv::new();
    more.set("B", "2").unwrap();
    let out = sb
        .exec(ExecRequest::new("env-count", Vec::<String>::new()).with_env(&more))
        .await
        .unwrap();
    assert_eq!(out.stdout_text(), "2");
}

#[tokio::test]
async fn builtins() {
    let rt = FakeRuntime::new();
    let mut env = puddle_types::GuestEnv::new();
    env.set("A", "1").unwrap();
    let sb = rt.create(spec("a").with_env(&env)).await.unwrap();
    assert_eq!(run(&sb, "/bin/true", &[]).await.status.code, 0);
    assert_eq!(run(&sb, "false", &[]).await.status.code, 1);
    assert_eq!(run(&sb, "echo", &["a", "b"]).await.stdout_text(), "a b\n");
    assert_eq!(run(&sb, "printenv", &[]).await.stdout_text(), "A=1\n");
    assert_eq!(run(&sb, "printenv", &["NOPE"]).await.status.code, 1);
    assert_eq!(run(&sb, "sh", &["-c", ""]).await.status.code, 0);
    assert_eq!(run(&sb, "sh", &["-c", "exit"]).await.status.code, 0);
    assert_eq!(run(&sb, "sh", &["-c", "exit x"]).await.status.code, 2);
    assert_eq!(
        run(&sb, "bash", &["-c", "kill -KILL $$"]).await.status.code,
        -1
    );
    assert_eq!(
        run(&sb, "sh", &["-c", "echo hi"]).await.stdout_text(),
        "hi\n"
    );
    let unknown = run(&sb, "frobnicate", &[]).await;
    assert_eq!(unknown.status.code, 127);
    assert!(unknown.stderr_text().contains("frobnicate: not found"));
    assert_eq!(run(&sb, "test", &["-e", "/"]).await.status.code, 0);
    assert_eq!(run(&sb, "test", &["-f", "/nope"]).await.status.code, 1);
    assert_eq!(run(&sb, "test", &["-e", "relative"]).await.status.code, 1);
    assert_eq!(run(&sb, "sleep", &["1"]).await.status.code, 0);
    assert_eq!(run(&sb, "sleep", &["soon"]).await.status.code, 1);
    let missing = run(&sb, "cat", &["/a", "rel"]).await;
    assert_eq!(missing.status.code, 1);
    assert!(missing.stderr_text().contains("/a: No such file"));
    assert!(missing.stderr_text().contains("rel: No such file"));
    let tee = sb
        .exec(ExecRequest::new("tee", ["rel"]).with_stdin("x"))
        .await
        .unwrap();
    assert_eq!(tee.status.code, 1);
}

#[tokio::test]
async fn sleep_longer_than_the_timeout_times_out() {
    let rt = FakeRuntime::new();
    let sb = rt.create(spec("a")).await.unwrap();
    let err = sb
        .exec(ExecRequest::new("sleep", ["0.5"]).with_timeout(Duration::from_millis(100)))
        .await
        .unwrap_err();
    assert!(matches!(err, ComputeError::ExecTimeout { ref program, .. } if program == "sleep"));
}

#[tokio::test]
async fn filesystem_layout() {
    let rt = FakeRuntime::new();
    let host_dir = std::env::temp_dir().join(format!("puddle-fake-fs-{}", std::process::id()));
    std::fs::create_dir_all(&host_dir).unwrap();
    let present = host_dir.join("present");
    std::fs::write(&present, b"p").unwrap();
    let s = spec("a")
        .with_file_mount(FileMount::read_only(&present, path("/m/present")))
        .with_file_mount(FileMount::read_only(
            host_dir.join("absent"),
            path("/m/absent"),
        ))
        .with_file_mount(FileMount::read_only(&host_dir, path("/m/dir")))
        .with_volume(VolumeMount::named(vol("v"), path("/w")).ensure_size(DiskSize::mib(1)))
        .with_owned_disk(OwnedDisk {
            guest: path("/var/lib/d"),
            size: DiskSize::mib(1),
        });
    let sb = rt.create(s).await.unwrap();
    let exists = |p: &'static str| {
        let sb = &sb;
        async move { run(sb, "test", &["-e", p]).await.status.success() }
    };
    assert!(exists("/m/present").await);
    assert!(!exists("/m/absent").await);
    assert!(!exists("/m/present/below").await);
    assert!(exists("/m").await, "parent of a mount");
    assert!(exists("/var/lib").await, "parent of an owned disk");
    assert!(exists("/w").await, "volume mount point");
    assert!(!exists("/w/x").await);
    assert_eq!(run(&sb, "cat", &["/m/absent"]).await.status.code, 1);
    let dir_read = run(&sb, "cat", &["/m/dir"]).await;
    assert_eq!(dir_read.status.code, 1, "reading a directory fails");
    assert!(!dir_read.stderr_text().contains("No such file"));
    let write = |p: &'static str| {
        let sb = &sb;
        async move {
            sb.exec(ExecRequest::new("tee", [p]).with_stdin("d"))
                .await
                .unwrap()
        }
    };
    assert!(
        write("/m/present/below")
            .await
            .stderr_text()
            .contains("No such file")
    );
    assert!(write("/w").await.stderr_text().contains("No such file"));
    assert!(write("/w/sub/f").await.status.success());
    assert!(exists("/w/sub").await, "directory implied by a file");
    assert!(write("/var/lib/d/f").await.status.success());
    assert!(exists("/var/lib/d/f").await);
    std::fs::remove_file(&present).unwrap();
    std::fs::remove_dir(&host_dir).unwrap();
}

#[tokio::test]
async fn writes_into_a_removed_volume_fail() {
    let rt = FakeRuntime::new();
    let s = spec("a")
        .with_volume(VolumeMount::named(vol("v"), path("/w")).ensure_size(DiskSize::mib(1)));
    let sb = rt.create(s).await.unwrap();
    rt.inner.state.lock().unwrap().volumes.remove("v");
    let out = sb
        .exec(ExecRequest::new("tee", ["/w/f"]).with_stdin("d"))
        .await
        .unwrap();
    assert_eq!(out.status.code, 1);
    assert_eq!(run(&sb, "cat", &["/w/f"]).await.status.code, 1);
    assert!(!run(&sb, "test", &["-e", "/w/f"]).await.status.success());
}

#[tokio::test]
async fn crash_and_drop_semantics() {
    let rt = FakeRuntime::new();
    let n = name("a");
    let sb = rt.create(spec("a")).await.unwrap();
    assert!(rt.crash(&n));
    assert!(!rt.crash(&n), "already down");
    assert!(!rt.crash(&name("nope")));
    assert_eq!(sb.status().await.unwrap(), WorkspaceStatus::Crashed);
    let restarted = rt.start(&n).await.unwrap();
    drop(sb);
    assert_eq!(
        restarted.status().await.unwrap(),
        WorkspaceStatus::Running,
        "dropping the earlier boot's handle must not touch the new boot"
    );
    let err = rt.start(&n).await.unwrap_err();
    assert!(matches!(
        err,
        ComputeError::InvalidState { op: "start", .. }
    ));
}

#[tokio::test]
async fn stale_handles_cannot_stop_a_newer_boot() {
    let rt = FakeRuntime::new();
    let n = name("a");
    let first = rt.create(spec("a")).await.unwrap();
    assert!(rt.crash(&n));
    let _second = rt.start(&n).await.unwrap();
    assert!(matches!(
        first.stop().await,
        Err(ComputeError::StaleHandle { .. })
    ));
    let (_c, server) = tokio::io::duplex(64);
    assert!(matches!(
        first.serve_ssh(server).await,
        Err(ComputeError::StaleHandle { .. })
    ));
}

#[tokio::test]
async fn handles_of_removed_sandboxes_report_not_found() {
    let rt = FakeRuntime::new();
    let sb = rt.create(spec("a")).await.unwrap();
    sb.stop().await.unwrap();
    rt.remove(&name("a")).await.unwrap();
    assert!(matches!(
        sb.status().await,
        Err(ComputeError::NotFound { .. })
    ));
    assert!(matches!(
        sb.stop().await,
        Err(ComputeError::NotFound { .. })
    ));
    assert!(matches!(
        sb.exec(ExecRequest::sh("exit 0")).await,
        Err(ComputeError::NotFound { .. })
    ));
}

#[tokio::test]
async fn start_checks_volumes_again() {
    let rt = FakeRuntime::new();
    let mount = |n: &str| {
        spec(n).with_volume(VolumeMount::named(vol("v"), path("/w")).ensure_size(DiskSize::mib(1)))
    };
    let a = rt.create(mount("a")).await.unwrap();
    a.stop().await.unwrap();
    let b = rt.create(mount("b")).await.unwrap();
    let err = rt.start(&name("a")).await.unwrap_err();
    assert_eq!(
        err,
        ComputeError::VolumeInUse {
            volume: "v".into(),
            holder: "b".into()
        }
    );
    drop(b);
    rt.remove(&name("b")).await.unwrap();
    rt.remove_volume(&vol("v")).await.unwrap();
    let err = rt.start(&name("a")).await.unwrap_err();
    assert!(matches!(err, ComputeError::VolumeNotFound { .. }));
}

#[tokio::test]
async fn images_and_probe() {
    let rt = FakeRuntime::with_config(FakeConfig {
        runtime_version: "0.7.7-puddle.1".into(),
        stale_dir_fixed: true,
        ssh_reports_signal_exit: true,
    });
    let caps = rt.probe().await.unwrap();
    assert_eq!(caps.runtime_version, "0.7.7-puddle.1");
    assert!(caps.stale_dir_fixed && caps.ssh_reports_signal_exit);
    let dind = rt
        .pull_image(&ImageRef::new(FakeRuntime::DIND).unwrap())
        .await
        .unwrap();
    assert_eq!(dind.entrypoint, ["dockerd-entrypoint.sh"]);
    let custom = ImageRef::new("example.invalid/custom:1").unwrap();
    assert!(rt.pull_image(&custom).await.is_err());
    rt.add_image(
        &custom,
        ImageConfig {
            cmd: vec!["x".into()],
            ..ImageConfig::default()
        },
    );
    assert_eq!(rt.pull_image(&custom).await.unwrap().cmd, ["x"]);
    assert!(format!("{rt:?}").contains("0.7.7-puddle.1"));
    assert!(format!("{:?}", FakeRuntime::default()).contains("fake"));
}

#[tokio::test]
async fn volume_size_zero_is_refused() {
    let rt = FakeRuntime::new();
    let err = rt
        .create_volume(VolumeSpec {
            name: vol("v"),
            size: DiskSize::mib(0),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, ComputeError::InvalidSpec { .. }));
}

#[tokio::test]
async fn ssh_reports_io_errors() {
    struct Broken;
    impl tokio::io::AsyncRead for Broken {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("read broke")))
        }
    }
    impl tokio::io::AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::other("write broke")))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    let rt = FakeRuntime::new();
    let sb = rt.create(spec("a")).await.unwrap();
    let err = sb.serve_ssh(Broken).await.unwrap_err();
    assert!(err.to_string().contains("write broke"), "{err}");
}

#[tokio::test]
async fn foreign_sandboxes_dirs_and_volumes_are_listed_but_not_owned() {
    let rt = FakeRuntime::new();
    let _ours = rt.create(spec("ours")).await.unwrap();
    rt.add_foreign_sandbox("Other_Tool", WorkspaceStatus::Running);
    rt.add_foreign_sandbox("valid-but-foreign", WorkspaceStatus::Stopped);
    let listed = rt.list().await.unwrap();
    let owned: Vec<(&str, bool)> = listed
        .iter()
        .map(|i| (i.name.as_str(), i.puddle_owned))
        .collect();
    assert_eq!(
        owned,
        [
            ("Other_Tool", false),
            ("ours", true),
            ("valid-but-foreign", false)
        ]
    );
    // Only listed: other operations don't see a foreign sandbox.
    assert!(matches!(
        rt.get(&name("valid-but-foreign")).await,
        Err(ComputeError::NotFound { .. })
    ));

    rt.add_stale_dir("Odd_Dir");
    rt.add_stale_dir("left");
    assert_eq!(rt.stale_dirs().await.unwrap(), ["Odd_Dir", "left"]);
    rt.remove_stale_dir(&name("left")).await.unwrap();
    assert_eq!(rt.stale_dirs().await.unwrap(), ["Odd_Dir"]);

    rt.add_foreign_volume("Data_Disk", DiskSize::mib(8));
    let vols = rt.list_volumes().await.unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].name, "Data_Disk");
    assert_eq!(vols[0].size, DiskSize::mib(8));
    assert!(vols[0].volume_name().is_none());
    assert!(rt.volume(&vol("data-disk")).await.unwrap().is_none());
}
