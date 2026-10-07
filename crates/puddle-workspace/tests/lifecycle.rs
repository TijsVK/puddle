// SPDX-License-Identifier: GPL-3.0-or-later
//! U tests of the workspace lifecycle on the msb fake ("on the fake").
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::sync::{Arc, Mutex};

use puddle_compute::fake::{ExecContext, FakeConfig, FakeRuntime, Fault, Op};
use puddle_compute::{
    ComputeError, DiskSize, ExecOutput, ExecRequest, Runtime, Sandbox, SandboxSpec, VolumeMount,
    VolumeSpec,
};
use puddle_types::{GuestPath, ImageRef, SandboxName, SandboxStatus, WorkspaceId};
use puddle_workspace::{DELETE_CHECK_SH, HoldKind, WorkspaceConfig, WorkspaceError, Workspaces};

fn ws(s: &str) -> WorkspaceId {
    WorkspaceId::new(s).unwrap()
}

fn name(s: &str) -> SandboxName {
    SandboxName::new(s).unwrap()
}

fn spec(n: &str) -> SandboxSpec {
    SandboxSpec::new(name(n), ImageRef::new(FakeRuntime::DEBIAN).unwrap())
}

fn path(p: &str) -> GuestPath {
    GuestPath::new(p).unwrap()
}

async fn sh<S: Sandbox>(sb: &S, script: &str) -> ExecOutput {
    sb.exec(ExecRequest::sh(script)).await.unwrap()
}

async fn names(rt: &FakeRuntime) -> Vec<String> {
    rt.list()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect()
}

/// No names: what an emptiness check compares with.
const NONE: [String; 0] = [];

async fn volumes(rt: &FakeRuntime) -> Vec<String> {
    rt.list_volumes()
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect()
}

async fn status(rt: &FakeRuntime, n: &str) -> Option<SandboxStatus> {
    rt.list()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == n)
        .map(|s| s.status)
}

/// The sandboxes the calls of `op` were about, in order.
fn targets(rt: &FakeRuntime, op: Op) -> Vec<String> {
    rt.calls()
        .into_iter()
        .filter(|c| c.op == op)
        .filter_map(|c| c.target)
        .collect()
}

/// Answers the delete check with whatever `output` holds, and records where it ran.
#[derive(Clone, Default)]
struct CheckStub {
    output: Arc<Mutex<String>>,
    ran_in: Arc<Mutex<Vec<String>>>,
}

impl CheckStub {
    fn install(rt: &FakeRuntime, output: &str) -> Self {
        let stub = Self::default();
        stub.set(output);
        let s = stub.clone();
        rt.on_exec(move |ctx: &mut ExecContext<'_>, r: &ExecRequest| {
            (r.program == "sh" && r.args.get(1).map(String::as_str) == Some(DELETE_CHECK_SH)).then(
                || {
                    s.ran_in.lock().unwrap().push(ctx.sandbox().to_string());
                    assert_eq!(r.user.as_deref(), Some("root"));
                    ExecOutput::new(0, s.output.lock().unwrap().clone(), "")
                },
            )
        });
        stub
    }

    fn set(&self, output: &str) {
        output.clone_into(&mut self.output.lock().unwrap());
    }

    fn ran_in(&self) -> Vec<String> {
        self.ran_in.lock().unwrap().clone()
    }
}

/// Answers `fstrim -v <mount>` like util-linux, or with exit `code`.
fn stub_fstrim(rt: &FakeRuntime, code: i32) {
    rt.on_exec(move |_: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "fstrim").then(|| {
            let mount = r.args.get(1).cloned().unwrap_or_default();
            if code == 0 {
                ExecOutput::new(0, format!("{mount}: 1 MiB (1048576 bytes) trimmed\n"), "")
            } else {
                ExecOutput::new(code, "", "fstrim: the discard operation is not supported\n")
            }
        })
    });
}

const DIRTY: &str = "R\tapi\nU\t?? notes.txt\nC\tabc1234 wip\nS\tstash@{0}: WIP on main\nD\n";
const CLEAN: &str = "R\tapi\nD\n";

#[tokio::test]
async fn a_new_workspace_gets_its_volume_mounted_with_kind_and_size() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let att = w.prepare(&rt, &id, &name("box"), None).await.unwrap();
    assert!(att.created_volume());
    assert_eq!(
        att.mount(),
        &VolumeMount::named(id.volume_name(), path("/workspaces/acme"))
            .ensure_size(WorkspaceConfig::DEFAULT_SIZE)
    );
    let sb = rt.create(att.add_to(spec("box"))).await.unwrap();
    att.commit();
    let vol = rt.volume(&id.volume_name()).await.unwrap().unwrap();
    assert_eq!(vol.size, WorkspaceConfig::DEFAULT_SIZE);
    assert_eq!(vol.holder.as_deref(), Some("box"));
    let holder = w.holder(&id).unwrap();
    assert_eq!(
        (holder.sandbox, holder.kind),
        (name("box"), HoldKind::Attached)
    );
    assert_eq!(sb.status().await.unwrap(), SandboxStatus::Running);
}

#[tokio::test]
async fn a_recreated_sandbox_reuses_the_volume_and_its_files() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w
        .create(&rt, &id, spec("box"), Some(DiskSize::gib(2)))
        .await
        .unwrap();
    let out = sb
        .exec(ExecRequest::new("tee", ["/workspaces/acme/api/marker"]).with_stdin("kept\n"))
        .await
        .unwrap();
    assert!(out.status.success());
    sb.stop().await.unwrap();
    rt.remove(&name("box")).await.unwrap();
    w.sandbox_removed(&name("box"));
    assert_eq!(w.holder(&id), None);

    // A rebuild under another name, asking for another size: same volume, same size, same data.
    let again = w
        .create(&rt, &id, spec("box2"), Some(DiskSize::gib(8)))
        .await
        .unwrap();
    assert_eq!(
        sh(&again, "cat /workspaces/acme/api/marker")
            .await
            .stdout_text(),
        "kept\n"
    );
    let vols = rt.list_volumes().await.unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].size, DiskSize::gib(2));
    assert_eq!(targets(&rt, Op::CreateVolume), ["ws-acme"]);
}

#[tokio::test]
async fn a_second_attach_is_refused_naming_the_holder_running_or_stopped() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let first = w.create(&rt, &id, spec("one"), None).await.unwrap();
    let creates_before = targets(&rt, Op::Create).len();

    let err = w.create(&rt, &id, spec("two"), None).await.unwrap_err();
    assert_eq!(
        err,
        WorkspaceError::InUse {
            workspace: "acme".into(),
            holder: "one".into()
        }
    );
    assert_eq!(
        err.to_string(),
        r#"workspace "acme" is in use by sandbox "one""#
    );

    // Stopped, the first sandbox still holds it: a start would attach it again.
    first.stop().await.unwrap();
    let err = w.create(&rt, &id, spec("two"), None).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "one"));

    // puddle refused before msb was asked, so nothing was left under the refused name.
    assert_eq!(targets(&rt, Op::Create).len(), creates_before);
    assert_eq!(names(&rt).await, ["one"]);
}

#[tokio::test]
async fn a_running_holder_puddle_does_not_track_is_found_through_the_runtime() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    // Another puddle (or one before a restart) created this one.
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    let _other = rt
        .create(spec("foreign").with_volume(VolumeMount::named(
            id.volume_name(),
            path("/workspaces/acme"),
        )))
        .await
        .unwrap();
    let err = w.create(&rt, &id, spec("mine"), None).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "foreign"));
    assert_eq!(w.holder(&id), None, "the refusal leaves no reservation");
}

#[tokio::test]
async fn a_holder_removed_behind_puddles_back_no_longer_blocks() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("one"), None).await.unwrap();
    sb.stop().await.unwrap();
    rt.remove(&name("one")).await.unwrap(); // without sandbox_removed
    let _two = w.create(&rt, &id, spec("two"), None).await.unwrap();
    assert_eq!(w.holder(&id).unwrap().sandbox, name("two"));
}

#[tokio::test]
async fn adopted_attachments_block_like_created_ones() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("one"), None).await.unwrap();
    sb.stop().await.unwrap();
    // A restarted puddle: empty registry, rebuilt by reconcile.
    let fresh = Workspaces::default();
    fresh.adopt(&id, &name("one"));
    let err = fresh.create(&rt, &id, spec("two"), None).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "one"));
}

#[tokio::test]
async fn a_failed_create_leaves_no_record_dir_or_volume() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    rt.inject(
        Op::Create,
        Fault::once(ComputeError::Runtime {
            op: "create",
            message: "injected".into(),
        }),
    );
    let err = w.create(&rt, &id, spec("box"), None).await.unwrap_err();
    assert!(err.to_string().contains("injected"), "{err}");
    assert_eq!(names(&rt).await, NONE);
    assert_eq!(rt.stale_dirs().await.unwrap(), NONE);
    assert_eq!(volumes(&rt).await, NONE);
    assert_eq!(w.holder(&id), None);
    // The name and the workspace are free again.
    w.create(&rt, &id, spec("box"), None).await.unwrap();
}

#[tokio::test]
async fn an_abort_removes_the_stale_dir_a_refused_create_leaves() {
    // msb 0.7.6 has an upstream bug: a create that fails its volume check leaves a
    // directory.
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let att = w.prepare(&rt, &id, &name("box"), None).await.unwrap();
    let mut s = att.add_to(spec("box"));
    s.volumes[0].ensure_size = Some(DiskSize::mib(1)); // disagrees with the catalog
    let err = rt.create(s).await.unwrap_err();
    assert!(matches!(err, ComputeError::VolumeSizeMismatch { .. }));
    assert_eq!(rt.stale_dirs().await.unwrap(), ["box"]);
    att.abort(&rt).await.unwrap();
    assert_eq!(rt.stale_dirs().await.unwrap(), NONE);
    assert_eq!(volumes(&rt).await, NONE);
    assert_eq!(names(&rt).await, NONE);
}

#[tokio::test]
async fn an_abort_removes_the_record_a_refused_attach_leaves_and_keeps_an_old_volume() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    // The workspace exists from an earlier session.
    let old = w.create(&rt, &id, spec("old"), None).await.unwrap();
    old.stop().await.unwrap();
    rt.remove(&name("old")).await.unwrap();
    w.sandbox_removed(&name("old"));

    let att = w.prepare(&rt, &id, &name("box"), None).await.unwrap();
    assert!(!att.created_volume());
    // A racing sandbox outside puddle grabs the volume between prepare and create.
    let _racer = rt
        .create(spec("racer").with_volume(att.mount().clone()))
        .await
        .unwrap();
    let err = rt.create(att.add_to(spec("box"))).await.unwrap_err();
    assert!(matches!(err, ComputeError::VolumeInUse { .. }));
    assert_eq!(status(&rt, "box").await, Some(SandboxStatus::Stopped));
    att.abort(&rt).await.unwrap();
    assert_eq!(status(&rt, "box").await, None);
    assert_eq!(
        rt.list_volumes().await.unwrap().len(),
        1,
        "an old volume stays"
    );
}

#[tokio::test]
async fn an_abort_removes_a_sandbox_whose_boot_hook_failed() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let att = w.prepare(&rt, &id, &name("box"), None).await.unwrap();
    // The boot hook created the sandbox, its hook failed, and it stopped it (fail closed).
    let sb = rt.create(att.add_to(spec("box"))).await.unwrap();
    sb.stop().await.unwrap();
    drop(sb);
    att.abort(&rt).await.unwrap();
    assert_eq!(names(&rt).await, NONE);
    assert_eq!(volumes(&rt).await, NONE);
}

#[tokio::test]
async fn an_abort_never_touches_what_existed_before() {
    let rt = FakeRuntime::with_config(FakeConfig::default());
    let w = Workspaces::default();
    // "busy" exists and has nothing to do with workspace b.
    let busy = rt.create(spec("busy")).await.unwrap();
    busy.stop().await.unwrap();
    let id = ws("b");
    let err = w.create(&rt, &id, spec("busy"), None).await.unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(status(&rt, "busy").await, Some(SandboxStatus::Stopped));
    assert_eq!(volumes(&rt).await, NONE);
}

#[tokio::test]
async fn a_dropped_attachment_releases_its_reservation() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let att = w.prepare(&rt, &id, &name("one"), None).await.unwrap();
    assert_eq!(w.holder(&id).unwrap().kind, HoldKind::Attaching);
    let err = w.prepare(&rt, &id, &name("two"), None).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "one"));
    drop(att);
    assert_eq!(w.holder(&id), None);
}

#[tokio::test]
async fn a_failed_runtime_lookup_releases_the_reservation() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    for op in [Op::Volume, Op::List, Op::StaleDirs, Op::CreateVolume] {
        rt.inject(
            op,
            Fault::once(ComputeError::Runtime {
                op: "x",
                message: "down".into(),
            }),
        );
        let err = w.create(&rt, &id, spec("box"), None).await.unwrap_err();
        assert!(
            matches!(err, WorkspaceError::Runtime { .. }),
            "{op:?}: {err}"
        );
        assert_eq!(w.holder(&id), None, "{op:?}");
    }
    assert_eq!(volumes(&rt).await, NONE);
}

#[tokio::test]
async fn stop_trims_every_owned_workspace_first() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 0);
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let report = w.stop(&sb).await.unwrap();
    assert_eq!(report.trims.len(), 1);
    let trim = report.trims[0].as_ref().unwrap();
    assert_eq!(trim.workspace, id);
    assert_eq!(trim.trimmed_bytes, Some(1_048_576));
    let calls = rt.calls();
    let fstrim = calls
        .iter()
        .position(|c| c.detail.as_deref() == Some("fstrim -v /workspaces/acme"))
        .unwrap();
    let stop = calls.iter().position(|c| c.op == Op::Stop).unwrap();
    assert!(fstrim < stop, "trim before stop");
    assert_eq!(sb.status().await.unwrap(), SandboxStatus::Stopped);

    // Already down: nothing to trim, the stop is a no-op.
    let report = w.stop(&sb).await.unwrap();
    assert_eq!(report.trims.len(), 0);
}

#[tokio::test]
async fn a_failed_trim_does_not_stop_the_stop() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 1);
    let w = Workspaces::default();
    let sb = w.create(&rt, &ws("acme"), spec("box"), None).await.unwrap();
    let report = w.stop(&sb).await.unwrap();
    let err = report.trims[0].as_ref().unwrap_err();
    assert!(err.to_string().contains("not supported"), "{err}");
    assert_eq!(sb.status().await.unwrap(), SandboxStatus::Stopped);

    // No fstrim in the image at all.
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let sb = w
        .create(&rt, &ws("other"), spec("box"), None)
        .await
        .unwrap();
    let report = w.stop(&sb).await.unwrap();
    let err = report.trims[0].as_ref().unwrap_err();
    assert!(err.to_string().contains("not installed"), "{err}");

    // A failing stop is an error.
    let sb = rt.start(&name("box")).await.unwrap();
    rt.inject(
        Op::Stop,
        Fault::once(ComputeError::Runtime {
            op: "stop",
            message: "stuck".into(),
        }),
    );
    let err = w.stop(&sb).await.unwrap_err();
    assert!(err.to_string().contains("stuck"), "{err}");
}

#[tokio::test]
async fn reclaim_space_trims_in_the_running_holder() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 0);
    let w = Workspaces::default();
    let id = ws("acme");
    let _sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let report = w.reclaim_space(&rt, &id).await.unwrap();
    assert_eq!(report.trimmed_bytes, Some(1_048_576));
    assert_eq!(targets(&rt, Op::Create), ["box"], "no maintenance sandbox");
    assert_eq!(targets(&rt, Op::Exec), ["box"]);
}

#[tokio::test]
async fn reclaim_space_of_a_stopped_workspace_uses_a_short_lived_sandbox() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 0);
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w
        .create(&rt, &id, spec("box"), Some(DiskSize::gib(3)))
        .await
        .unwrap();
    sb.stop().await.unwrap();
    let report = w.reclaim_space(&rt, &id).await.unwrap();
    assert_eq!(report.trimmed_bytes, Some(1_048_576));
    assert_eq!(targets(&rt, Op::Create), ["box", "m--acme"]);
    assert_eq!(targets(&rt, Op::Exec), ["m--acme"]);
    assert_eq!(targets(&rt, Op::Remove), ["m--acme"]);
    assert_eq!(names(&rt).await, ["box"], "the maintenance sandbox is gone");
    assert_eq!(w.holder(&id).unwrap().sandbox, name("box"));
    // The owner can start again.
    rt.start(&name("box")).await.unwrap();
}

#[tokio::test]
async fn the_maintenance_sandbox_uses_the_configured_image_and_memory() {
    let rt = FakeRuntime::new();
    let seen = Arc::new(Mutex::new(None));
    let s = seen.clone();
    rt.on_exec(move |ctx: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "fstrim").then(|| {
            let meminfo = ctx.read(&path("/proc/meminfo")).unwrap();
            *s.lock().unwrap() = Some((ctx.env().len(), String::from_utf8(meminfo).unwrap()));
            ExecOutput::new(0, "", "")
        })
    });
    let config = WorkspaceConfig {
        maintenance_image: ImageRef::new(FakeRuntime::ALPINE).unwrap(),
        ..WorkspaceConfig::default()
    };
    let w = Workspaces::new(config);
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(5),
    })
    .await
    .unwrap();
    let report = w.reclaim_space(&rt, &id).await.unwrap();
    assert_eq!(report.trimmed_bytes, None);
    let (env, meminfo) = seen.lock().unwrap().clone().unwrap();
    assert_eq!(env, 0, "no env given to the guest");
    assert!(meminfo.contains("MemTotal:       1048576 kB"), "{meminfo}");
    assert_eq!(w.config().maintenance_image.as_str(), FakeRuntime::ALPINE);
}

#[tokio::test]
async fn a_failed_maintenance_create_leaves_nothing() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    rt.inject(
        Op::Create,
        Fault::once(ComputeError::ImagePull {
            image: "x".into(),
            reason: "offline".into(),
        }),
    );
    let err = w.reclaim_space(&rt, &id).await.unwrap_err();
    assert!(err.to_string().contains("offline"), "{err}");
    assert_eq!(names(&rt).await, NONE);
    assert_eq!(w.holder(&id), None);
}

#[tokio::test]
async fn a_leftover_maintenance_sandbox_is_cleared_unless_it_runs() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 0);
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    // A crashed earlier run left its sandbox (down) and, elsewhere, a stale directory.
    let left = rt.create(spec("m--acme")).await.unwrap();
    left.stop().await.unwrap();
    drop(left);
    w.reclaim_space(&rt, &id).await.unwrap();
    assert_eq!(names(&rt).await, NONE);

    // A running one is another run in progress.
    let _running = rt.create(spec("m--acme")).await.unwrap();
    let err = w.reclaim_space(&rt, &id).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "m--acme"));
}

#[tokio::test]
async fn a_leftover_stale_dir_of_the_maintenance_name_is_cleared() {
    let rt = FakeRuntime::new();
    stub_fstrim(&rt, 0);
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    // A create under the maintenance name that failed its volume check left a directory.
    let missing = puddle_types::VolumeName::new("ws-gone").unwrap();
    let _ = rt
        .create(spec("m--acme").with_volume(VolumeMount::named(missing, path("/x"))))
        .await
        .unwrap_err();
    assert_eq!(rt.stale_dirs().await.unwrap(), ["m--acme"]);
    w.reclaim_space(&rt, &id).await.unwrap();
    assert_eq!(rt.stale_dirs().await.unwrap(), NONE);
}

#[tokio::test]
async fn delete_lists_unsaved_work_then_needs_the_confirmation() {
    let rt = FakeRuntime::new();
    let stub = CheckStub::install(&rt, DIRTY);
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    sb.stop().await.unwrap();
    drop(sb);

    let report = w.check_delete(&rt, &id).await.unwrap();
    assert!(!report.is_clean());
    let api = &report.findings.repos[0];
    assert_eq!(api.uncommitted.items, ["?? notes.txt"]);
    assert_eq!(api.unpushed.items, ["abc1234 wip"]);
    assert_eq!(api.stashes.items, ["stash@{0}: WIP on main"]);
    assert_eq!(report.checked_in, name("m--acme"));
    assert_eq!(report.removes_sandbox, Some(name("box")));
    // Checking deletes nothing.
    assert_eq!(names(&rt).await, ["box"]);
    assert_eq!(rt.list_volumes().await.unwrap().len(), 1);

    let deleted = w.delete(&rt, &id, &report.confirm()).await.unwrap();
    assert_eq!(deleted.workspace, id);
    assert_eq!(deleted.removed_sandbox, Some(name("box")));
    assert_eq!(names(&rt).await, NONE);
    assert_eq!(volumes(&rt).await, NONE);
    assert_eq!(w.holder(&id), None);
    // Both checks ran in a short-lived sandbox.
    assert_eq!(stub.ran_in(), ["m--acme", "m--acme"]);
    assert_eq!(targets(&rt, Op::Remove), ["m--acme", "m--acme", "box"]);
}

#[tokio::test]
async fn delete_refuses_when_the_findings_changed_since_the_confirmation() {
    let rt = FakeRuntime::new();
    let stub = CheckStub::install(&rt, CLEAN);
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    let report = w.check_delete(&rt, &id).await.unwrap();
    assert!(report.is_clean());
    assert_eq!(report.removes_sandbox, None);
    stub.set(DIRTY);
    let err = w.delete(&rt, &id, &report.confirm()).await.unwrap_err();
    let WorkspaceError::Changed { report: now, .. } = err else {
        panic!("expected Changed, got {err:?}");
    };
    assert!(!now.is_clean());
    assert_eq!(rt.list_volumes().await.unwrap().len(), 1, "nothing deleted");
    assert_eq!(names(&rt).await, NONE);
    assert_eq!(w.holder(&id), None);
    // Confirming the new report works.
    w.delete(&rt, &id, &now.confirm()).await.unwrap();
    assert_eq!(volumes(&rt).await, NONE);
}

#[tokio::test]
async fn delete_refuses_when_an_owner_appeared_since_the_confirmation() {
    let rt = FakeRuntime::new();
    CheckStub::install(&rt, CLEAN);
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    let report = w.check_delete(&rt, &id).await.unwrap();
    let sb = w.create(&rt, &id, spec("new"), None).await.unwrap();
    sb.stop().await.unwrap();
    let err = w.delete(&rt, &id, &report.confirm()).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::Changed { .. }), "{err:?}");
    assert_eq!(status(&rt, "new").await, Some(SandboxStatus::Stopped));
}

#[tokio::test]
async fn a_running_workspace_is_checked_in_place_and_must_stop_before_delete() {
    let rt = FakeRuntime::new();
    let stub = CheckStub::install(&rt, DIRTY);
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let report = w.check_delete(&rt, &id).await.unwrap();
    assert_eq!(report.checked_in, name("box"));
    assert_eq!(stub.ran_in(), ["box"]);
    let err = w.delete(&rt, &id, &report.confirm()).await.unwrap_err();
    assert_eq!(
        err,
        WorkspaceError::InUse {
            workspace: "acme".into(),
            holder: "box".into()
        }
    );
    sb.stop().await.unwrap();
    w.delete(&rt, &id, &report.confirm()).await.unwrap();
    assert_eq!(names(&rt).await, NONE);
}

#[tokio::test]
async fn a_confirmation_only_deletes_its_own_workspace() {
    let rt = FakeRuntime::new();
    CheckStub::install(&rt, CLEAN);
    let w = Workspaces::default();
    for id in ["a", "b"] {
        rt.create_volume(VolumeSpec {
            name: ws(id).volume_name(),
            size: DiskSize::gib(1),
        })
        .await
        .unwrap();
    }
    let report = w.check_delete(&rt, &ws("a")).await.unwrap();
    let err = w
        .delete(&rt, &ws("b"), &report.confirm())
        .await
        .unwrap_err();
    assert!(matches!(err, WorkspaceError::WrongConfirmation { .. }));
    assert_eq!(rt.list_volumes().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_check_that_fails_or_is_cut_short_blocks_the_delete() {
    let rt = FakeRuntime::new();
    let stub = CheckStub::install(&rt, "R\tapi\nU\t?? x\n");
    let w = Workspaces::default();
    let id = ws("acme");
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    let err = w.check_delete(&rt, &id).await.unwrap_err();
    assert!(err.to_string().contains("did not finish"), "{err}");
    assert_eq!(names(&rt).await, NONE, "the maintenance sandbox is gone");
    assert_eq!(w.holder(&id), None);

    stub.set(CLEAN);
    let report = w.check_delete(&rt, &id).await.unwrap();
    stub.set("garbage\n");
    let err = w.delete(&rt, &id, &report.confirm()).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::Check { .. }), "{err:?}");
    assert_eq!(rt.list_volumes().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_check_script_that_exits_non_zero_is_an_error() {
    let rt = FakeRuntime::new();
    rt.on_exec(|_: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "sh" && r.args.get(1).map(String::as_str) == Some(DELETE_CHECK_SH))
            .then(|| ExecOutput::new(3, "E\t.\tcannot enter /workspaces/acme\n", ""))
    });
    let w = Workspaces::default();
    let id = ws("acme");
    let _sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let err = w.check_delete(&rt, &id).await.unwrap_err();
    assert!(err.to_string().contains("cannot enter"), "{err}");
}

#[tokio::test]
async fn unknown_workspaces_are_not_found() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("nope");
    for err in [
        w.check_delete(&rt, &id).await.unwrap_err(),
        w.reclaim_space(&rt, &id).await.unwrap_err(),
    ] {
        assert_eq!(
            err,
            WorkspaceError::NotFound {
                workspace: "nope".into()
            }
        );
    }
}

#[tokio::test]
async fn maintenance_waits_for_a_create_in_progress() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let att = w.prepare(&rt, &id, &name("box"), None).await.unwrap();
    let err = w.reclaim_space(&rt, &id).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { ref holder, .. } if holder == "box"));
    let err = w.check_delete(&rt, &id).await.unwrap_err();
    assert!(matches!(err, WorkspaceError::InUse { .. }));
    att.abort(&rt).await.unwrap();
}

#[tokio::test]
async fn prepare_layout_makes_the_puddle_dir() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    // The fake has no mkdir.
    let err = w.prepare_layout(&sb, &id).await.unwrap_err();
    assert!(err.to_string().contains("mkdir failed"), "{err}");
    rt.on_exec(|_: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "mkdir").then(|| ExecOutput::new(0, "", ""))
    });
    w.prepare_layout(&sb, &id).await.unwrap();
    assert!(
        rt.calls()
            .iter()
            .any(|c| c.detail.as_deref() == Some("mkdir -p -m 0700 /workspaces/acme/.puddle"))
    );
}

/// Records every exec's program (and first args) in order, answering with `code` for `program`.
fn record_execs(
    rt: &FakeRuntime,
    answers: &'static [(&'static str, i32, &'static str)],
) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    rt.on_exec(move |_: &mut ExecContext<'_>, r: &ExecRequest| {
        let answer = answers.iter().find(|(p, _, _)| *p == r.program)?;
        s.lock().unwrap().push(format!(
            "{} {} [{}]",
            r.program,
            r.args.join(" "),
            r.user.as_deref().unwrap_or("default")
        ));
        Some(ExecOutput::new(answer.1, "", answer.2))
    });
    seen
}

#[tokio::test]
async fn a_clone_is_synced_before_it_is_reported_done() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let seen = record_execs(&rt, &[("git", 0, ""), ("sync", 0, "")]);
    let dir = w
        .clone_checkout(&sb, &id, "https://h.example/acme/api.git", Some("root"))
        .await
        .unwrap();
    assert_eq!(dir.as_str(), "/workspaces/acme/api");
    assert_eq!(
        *seen.lock().unwrap(),
        [
            "git clone -- https://h.example/acme/api.git /workspaces/acme/api [root]",
            "sync  [root]"
        ]
    );
}

#[tokio::test]
async fn a_failed_clone_is_an_error_and_is_not_synced() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    let seen = record_execs(
        &rt,
        &[
            ("git", 128, "fatal: repository not found\n"),
            ("sync", 0, ""),
        ],
    );
    let err = w
        .clone_checkout(&sb, &id, "https://h.example/acme/api.git", None)
        .await
        .unwrap_err();
    assert!(matches!(err, WorkspaceError::Clone { .. }), "{err}");
    assert!(err.to_string().contains("repository not found"), "{err}");
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "sync ran after a failed clone"
    );
    assert!(seen.lock().unwrap()[0].ends_with("[default]"));
}

#[tokio::test]
async fn a_failed_sync_is_an_error_not_a_silent_success() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    record_execs(&rt, &[("git", 0, ""), ("sync", 1, "sync: I/O error\n")]);
    let err = w
        .clone_checkout(&sb, &id, "https://h.example/acme/api.git", None)
        .await
        .unwrap_err();
    assert!(matches!(err, WorkspaceError::Sync { .. }), "{err}");
    assert!(err.to_string().contains("I/O error"), "{err}");
}

/// Answers the lock-clearing script with `output`.
fn stub_clear_locks(rt: &FakeRuntime, code: i32, output: &'static str) {
    rt.on_exec(move |ctx: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "sh"
            && r.args.get(1).map(String::as_str) == Some(puddle_workspace::CLEAR_LOCKS_SH))
        .then(|| {
            assert_eq!(r.user.as_deref(), Some("root"));
            assert_eq!(r.args.get(3).map(String::as_str), Some("/workspaces/acme"));
            let _ = ctx;
            ExecOutput::new(code, output, "")
        })
    });
}

#[tokio::test]
async fn after_a_boot_the_layout_is_made_and_stale_locks_are_cleared() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    record_execs(&rt, &[("mkdir", 0, "")]);
    stub_clear_locks(&rt, 0, "L\tapi/.git/index.lock\nL\tapi/.git/HEAD.lock\nD\n");
    let report = w.after_boot(&sb, &id).await.unwrap().unwrap();
    assert_eq!(
        report.removed,
        ["api/.git/index.lock", "api/.git/HEAD.lock"]
    );
    assert!(!report.skipped_busy);
    let programs: Vec<_> = rt
        .calls()
        .into_iter()
        .filter_map(|c| c.detail)
        .filter(|d| d.starts_with("mkdir") || d.starts_with("sh -c"))
        .map(|d| d.split(' ').next().unwrap().to_owned())
        .collect();
    assert_eq!(programs, ["mkdir", "sh"], "layout first, then the locks");
}

#[tokio::test]
async fn a_lock_clearing_failure_does_not_fail_the_boot() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    record_execs(&rt, &[("mkdir", 0, "")]);
    stub_clear_locks(&rt, 3, "E\t.\tcannot enter /workspaces/acme\n");
    let locks = w.after_boot(&sb, &id).await.unwrap();
    let err = locks.unwrap_err();
    assert!(matches!(err, WorkspaceError::Locks { .. }), "{err}");
    assert!(err.to_string().contains("cannot enter"), "{err}");
    // Garbage output fails closed too.
    let rt2 = FakeRuntime::new();
    let sb2 = w
        .create(&rt2, &ws("other"), spec("box2"), None)
        .await
        .unwrap();
    rt2.on_exec(|_: &mut ExecContext<'_>, r: &ExecRequest| {
        (r.program == "sh").then(|| ExecOutput::new(0, "L\tx.lock\n", ""))
    });
    let err = w.clear_stale_locks(&sb2, &ws("other")).await.unwrap_err();
    assert!(err.to_string().contains("no end marker"), "{err}");
}

#[tokio::test]
async fn a_busy_guest_keeps_its_locks() {
    let rt = FakeRuntime::new();
    let w = Workspaces::default();
    let id = ws("acme");
    let sb = w.create(&rt, &id, spec("box"), None).await.unwrap();
    stub_clear_locks(&rt, 0, "B\nD\n");
    let report = w.clear_stale_locks(&sb, &id).await.unwrap();
    assert!(report.skipped_busy);
    assert_eq!(report.removed_count(), 0);
}
