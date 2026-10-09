// SPDX-License-Identifier: GPL-3.0-or-later
//! Shutdown and reconcile on the fake runtime (tier U).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: a failed step fails the test"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use puddle_compute::fake::{Call, ExecContext, FakeRuntime, Fault, Op};
use puddle_compute::{
    ComputeError, DiskSize, ExecOutput, ExecRequest, Runtime, Sandbox, SandboxSpec, VolumeMount,
    VolumeSpec,
};
use puddle_lifecycle::{
    Inventory, Lifecycle, ShutdownConfig, StopOutcome, TrimOutcome, adopt_workspaces, reconcile,
};
use puddle_types::{GuestPath, ImageRef, SandboxName, VolumeName, WorkspaceId, WorkspaceStatus};
use puddle_workspace::{WorkspaceError, Workspaces};

fn name(s: &str) -> SandboxName {
    SandboxName::new(s).unwrap()
}

fn vol(s: &str) -> VolumeName {
    VolumeName::new(s).unwrap()
}

fn spec(n: &str) -> SandboxSpec {
    SandboxSpec::new(name(n), ImageRef::new(FakeRuntime::DEBIAN).unwrap())
}

/// Makes `fstrim` known in every fake sandbox (exit 0) and logs each run as `sandbox: args`.
fn fstrim_ok(rt: &FakeRuntime) -> Arc<Mutex<Vec<String>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&log);
    rt.on_exec(move |ctx: &mut ExecContext<'_>, req: &ExecRequest| {
        let is_trim = req.program == "fstrim" || req.args.iter().any(|a| a.contains("fstrim"));
        if !is_trim {
            return None;
        }
        seen.lock().unwrap().push(format!(
            "{}: {} {}",
            ctx.sandbox(),
            req.program,
            req.args.join(" ")
        ));
        Some(ExecOutput::new(
            0,
            "/: 1 GiB (1073741824 bytes) trimmed\n",
            "",
        ))
    });
    log
}

/// The ops the fake saw for `target`, in order.
fn ops_for(rt: &FakeRuntime, target: &str) -> Vec<Op> {
    rt.calls()
        .into_iter()
        .filter(|c: &Call| c.target.as_deref() == Some(target))
        .map(|c| c.op)
        .collect()
}

async fn status_of(rt: &FakeRuntime, n: &str) -> Option<WorkspaceStatus> {
    rt.list()
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.name == n)
        .map(|i| i.status)
}

fn runtime_error(op: &'static str) -> ComputeError {
    ComputeError::Runtime {
        op,
        message: "injected".into(),
    }
}

#[tokio::test]
async fn every_sandbox_is_trimmed_then_stopped_and_records_stopped() {
    let rt = FakeRuntime::new();
    let trims = fstrim_ok(&rt);
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    for n in ["a", "b", "c"] {
        let sb = rt.create(spec(n)).await.unwrap();
        assert!(lc.manage(sb, Vec::new()).unwrap().is_none());
    }
    assert_eq!(lc.managed(), [name("a"), name("b"), name("c")]);

    let report = lc.shutdown().await;

    assert!(report.all_stopped(), "{report:?}");
    assert_eq!(report.sandboxes.len(), 3);
    for (outcome, n) in report.sandboxes.iter().zip(["a", "b", "c"]) {
        assert_eq!(outcome.sandbox, name(n));
        assert_eq!(outcome.trim, TrimOutcome::Trimmed);
        assert_eq!(outcome.stop, StopOutcome::Stopped);
        assert_eq!(status_of(&rt, n).await, Some(WorkspaceStatus::Stopped));
        // fstrim ran while the VM was up, and the stop came after it.
        let ops = ops_for(&rt, n);
        let exec = ops.iter().position(|o| *o == Op::Exec).unwrap();
        let stop = ops.iter().position(|o| *o == Op::Stop).unwrap();
        assert!(exec < stop, "{n}: {ops:?}");
    }
    // The trim-all script (sh -c ...) ran once per sandbox.
    let mut trims: Vec<String> = trims
        .lock()
        .unwrap()
        .iter()
        .map(|t| t.split(" -c").next().unwrap().to_owned())
        .collect();
    trims.sort();
    assert_eq!(trims, ["a: sh", "b: sh", "c: sh"]);
    assert_eq!(lc.managed().len(), 0);
}

#[tokio::test]
async fn given_trim_paths_are_trimmed_instead_of_every_filesystem() {
    let rt = FakeRuntime::new();
    let trims = fstrim_ok(&rt);
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    let sb = rt.create(spec("ws")).await.unwrap();
    let mount = GuestPath::new("/workspaces/w1").unwrap();
    lc.manage(sb, vec![mount]).unwrap();
    let report = lc.shutdown().await;
    assert!(report.all_stopped());
    let trims = trims.lock().unwrap().clone();
    assert_eq!(trims.len(), 1);
    assert!(trims[0].starts_with("ws: sh -c "), "{trims:?}");
    assert!(trims[0].ends_with(" fstrim /workspaces/w1"), "{trims:?}");
}

#[tokio::test]
async fn a_failed_trim_or_stop_does_not_hold_up_the_others() {
    let rt = FakeRuntime::new();
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    for n in ["notrim", "badexec", "badstop", "fine"] {
        lc.manage(rt.create(spec(n)).await.unwrap(), Vec::new())
            .unwrap();
    }
    // No fstrim handler for "notrim": the fake answers 127 like a missing command.
    let trims = fstrim_ok(&rt);
    rt.on_exec(|ctx: &mut ExecContext<'_>, _req: &ExecRequest| {
        (ctx.sandbox().as_str() == "notrim").then(|| ExecOutput::new(127, "", "fstrim: not found"))
    });
    rt.inject(
        Op::Exec,
        Fault::always(runtime_error("exec")).only_for("badexec"),
    );
    rt.inject(
        Op::Stop,
        Fault::always(runtime_error("stop")).only_for("badstop"),
    );

    let report = lc.shutdown().await;

    let by_name = |n: &str| {
        report
            .sandboxes
            .iter()
            .find(|s| s.sandbox.as_str() == n)
            .unwrap()
            .clone()
    };
    assert_eq!(
        by_name("notrim").trim,
        TrimOutcome::Failed {
            code: 127,
            stderr: "fstrim: not found".into()
        }
    );
    assert_eq!(by_name("notrim").stop, StopOutcome::Stopped);
    assert!(matches!(by_name("badexec").trim, TrimOutcome::Error(_)));
    assert_eq!(by_name("badexec").stop, StopOutcome::Stopped);
    assert_eq!(by_name("badstop").trim, TrimOutcome::Trimmed);
    assert_eq!(
        by_name("badstop").stop,
        StopOutcome::Failed(runtime_error("stop"))
    );
    assert_eq!(by_name("fine").stop, StopOutcome::Stopped);
    assert!(!report.all_stopped());
    assert_eq!(status_of(&rt, "fine").await, Some(WorkspaceStatus::Stopped));
    assert_eq!(
        status_of(&rt, "badexec").await,
        Some(WorkspaceStatus::Stopped)
    );
    drop(trims);
}

#[tokio::test]
async fn a_crashed_sandbox_is_not_trimmed() {
    let rt = FakeRuntime::new();
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    lc.manage(rt.create(spec("gone")).await.unwrap(), Vec::new())
        .unwrap();
    assert!(rt.crash(&name("gone")));
    let report = lc.shutdown().await;
    assert_eq!(report.sandboxes[0].trim, TrimOutcome::NotRunning);
    assert_eq!(report.sandboxes[0].stop, StopOutcome::Stopped);
    assert!(!ops_for(&rt, "gone").contains(&Op::Exec));
}

#[tokio::test]
async fn after_shutdown_new_sandboxes_are_handed_back() {
    let rt = FakeRuntime::new();
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    assert_eq!(lc.shutdown().await.sandboxes.len(), 0);
    let late = rt.create(spec("late")).await.unwrap();
    let back = lc.manage(late, Vec::new()).unwrap_err();
    assert_eq!(back.name(), &name("late"));
    back.stop().await.unwrap();
}

#[tokio::test]
async fn released_and_replaced_handles_are_not_stopped_by_shutdown() {
    let rt = FakeRuntime::new();
    let lc = Lifecycle::new(rt.clone(), ShutdownConfig::default());
    lc.manage(rt.create(spec("mine")).await.unwrap(), Vec::new())
        .unwrap();
    let user_stops = lc.release(&name("mine")).unwrap();
    assert!(lc.release(&name("mine")).is_none());
    user_stops.stop().await.unwrap();
    let again = rt.start(&name("mine")).await.unwrap();
    lc.manage(again, Vec::new()).unwrap();
    let newer = rt.get(&name("mine")).await.unwrap();
    let older = lc.manage(newer, Vec::new()).unwrap().unwrap();
    assert!(older.owns_lifecycle());
    assert!(format!("{lc:?}").contains("mine"));
    let report = lc.shutdown().await;
    assert!(report.all_stopped());
    assert_eq!(status_of(&rt, "mine").await, Some(WorkspaceStatus::Stopped));
    drop(older);
}

/// The world after a puddle that was killed: one sandbox of each kind reconcile must handle.
struct World {
    rt: FakeRuntime,
    /// Owning handles that keep "VMs left running" running, as a dead puddle's VMs would be.
    _left_running: Vec<puddle_compute::fake::FakeSandbox>,
    inventory: Inventory,
}

async fn killed_puddle_world() -> World {
    let rt = FakeRuntime::new();
    fstrim_ok(&rt);
    let mut left_running = Vec::new();
    // Known, left running.
    left_running.push(rt.create(spec("known-running")).await.unwrap());
    // Unknown (puddle died before recording it), left running.
    left_running.push(rt.create(spec("unknown-running")).await.unwrap());
    // Known and stopped, unknown and stopped.
    for n in ["known-stopped", "unknown-stopped"] {
        rt.create(spec(n)).await.unwrap().stop().await.unwrap();
    }
    // Known, crashed.
    let crashed = rt.create(spec("known-crashed")).await.unwrap();
    assert!(rt.crash(&name("known-crashed")));
    drop(crashed);
    // Foreign sandboxes: one with a valid name, one with a name puddle can't even parse.
    rt.add_foreign_sandbox("other-tool", WorkspaceStatus::Running);
    rt.add_foreign_sandbox("Other_Tool", WorkspaceStatus::Stopped);
    // Stale directories.
    rt.add_stale_dir("failed-create");
    rt.add_stale_dir("Foreign_Dir");
    // Volumes: a known workspace, an unfinished create, one no workspace claims, and foreign
    // ones.
    for v in ["ws-known", "ws-half", "ws-unknown", "data"] {
        rt.create_volume(VolumeSpec {
            name: vol(v),
            size: DiskSize::mib(8),
        })
        .await
        .unwrap();
    }
    rt.add_foreign_volume("Data_Disk", DiskSize::mib(8));

    let inventory = Inventory {
        sandboxes: ["known-running", "known-stopped", "known-crashed"]
            .into_iter()
            .map(name)
            .collect(),
        workspaces: BTreeSet::from([WorkspaceId::new("known").unwrap()]),
        interrupted: BTreeSet::from([WorkspaceId::new("half").unwrap()]),
        ..Inventory::default()
    };
    World {
        rt,
        _left_running: left_running,
        inventory,
    }
}

#[tokio::test]
async fn reconcile_cleans_up_only_what_puddle_owns() {
    let w = killed_puddle_world().await;
    let rt = &w.rt;
    let before = rt.calls().len();

    let report = reconcile(rt, &w.inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    assert_eq!(
        report.stopped,
        [name("known-running"), name("unknown-running")]
    );
    assert_eq!(
        report.removed,
        [name("unknown-running"), name("unknown-stopped")]
    );
    assert_eq!(report.crashed, [name("known-crashed")]);
    assert_eq!(report.stale_dirs_removed, [name("failed-create")]);
    assert_eq!(report.volumes_removed, [vol("ws-half")]);
    assert_eq!(report.unknown_volumes, [vol("ws-unknown")]);
    assert_eq!(
        report.foreign,
        [
            "Data_Disk",
            "Foreign_Dir",
            "Other_Tool",
            "data",
            "other-tool"
        ]
    );
    assert!(report.failures.is_empty(), "{:?}", report.failures);

    // Known sandboxes keep their records; the running one is stopped, not crashed.
    assert_eq!(
        status_of(rt, "known-running").await,
        Some(WorkspaceStatus::Stopped)
    );
    assert_eq!(
        status_of(rt, "known-stopped").await,
        Some(WorkspaceStatus::Stopped)
    );
    assert_eq!(
        status_of(rt, "known-crashed").await,
        Some(WorkspaceStatus::Crashed)
    );
    assert_eq!(status_of(rt, "unknown-running").await, None);
    assert_eq!(status_of(rt, "unknown-stopped").await, None);
    // The orphan was trimmed before its stop.
    let later: Vec<Call> = rt.calls().split_off(before);
    let orphan: Vec<Op> = later
        .iter()
        .filter(|c| c.target.as_deref() == Some("known-running"))
        .map(|c| c.op)
        .collect();
    let exec = orphan.iter().position(|o| *o == Op::Exec).unwrap();
    let stop = orphan.iter().position(|o| *o == Op::Stop).unwrap();
    assert!(exec < stop, "{orphan:?}");
    // Nothing touched a foreign item, or a known stopped/crashed sandbox, beyond listing.
    for untouched in [
        "other-tool",
        "Other_Tool",
        "Foreign_Dir",
        "data",
        "Data_Disk",
        "known-stopped",
        "known-crashed",
    ] {
        assert!(
            later.iter().all(|c| c.target.as_deref() != Some(untouched)),
            "{untouched} was touched: {later:?}"
        );
    }
    assert_eq!(rt.stale_dirs().await.unwrap(), ["Foreign_Dir"]);
    let volumes: Vec<String> = rt
        .list_volumes()
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(volumes, ["Data_Disk", "data", "ws-known", "ws-unknown"]);

    // A second reconcile finds nothing left to do.
    let again = reconcile(rt, &w.inventory, &ShutdownConfig::default())
        .await
        .unwrap();
    assert!(again.stopped.is_empty() && again.removed.is_empty());
    assert!(again.stale_dirs_removed.is_empty() && again.volumes_removed.is_empty());
    assert_eq!(again.crashed, [name("known-crashed")]);
    assert_eq!(again.unknown_volumes, [vol("ws-unknown")]);
}

#[tokio::test]
async fn reconcile_reports_failed_steps_and_carries_on() {
    let w = killed_puddle_world().await;
    let rt = &w.rt;
    rt.inject(
        Op::Remove,
        Fault::always(runtime_error("remove")).only_for("unknown-stopped"),
    );
    rt.inject(Op::RemoveStaleDir, Fault::once(runtime_error("rmdir")));
    rt.inject(Op::RemoveVolume, Fault::once(runtime_error("rmvol")));

    let report = reconcile(rt, &w.inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    let failed: Vec<(&str, &str)> = report
        .failures
        .iter()
        .map(|f| (f.item.as_str(), f.action))
        .collect();
    assert_eq!(
        failed,
        [
            ("unknown-stopped", "remove"),
            ("failed-create", "remove stale dir"),
            ("ws-half", "remove volume"),
        ]
    );
    assert!(report.failures[0].error.contains("injected"));
    // The rest still happened.
    assert_eq!(report.removed, [name("unknown-running")]);
    assert_eq!(report.stopped.len(), 2);
}

#[tokio::test]
async fn an_orphan_whose_stop_fails_keeps_its_record_and_its_volume() {
    let rt = FakeRuntime::new();
    rt.create_volume(VolumeSpec {
        name: vol("ws-held"),
        size: DiskSize::mib(8),
    })
    .await
    .unwrap();
    let holder = rt
        .create(spec("holder").with_volume(VolumeMount::named(
            vol("ws-held"),
            GuestPath::new("/w").unwrap(),
        )))
        .await
        .unwrap();
    rt.inject(Op::Stop, Fault::always(runtime_error("stop")));
    let inventory = Inventory {
        interrupted: BTreeSet::from([WorkspaceId::new("held").unwrap()]),
        ..Inventory::default()
    };

    let report = reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    assert!(report.stopped.is_empty() && report.removed.is_empty());
    assert_eq!(report.volumes_removed.len(), 0);
    let failed: Vec<(&str, &str)> = report
        .failures
        .iter()
        .map(|f| (f.item.as_str(), f.action))
        .collect();
    assert_eq!(failed, [("holder", "stop"), ("ws-held", "remove volume")]);
    assert!(report.failures[1].error.contains("holder"));
    assert_eq!(
        status_of(&rt, "holder").await,
        Some(WorkspaceStatus::Running)
    );
    drop(holder);
}

#[tokio::test]
async fn an_orphan_whose_get_says_it_is_down_is_not_stopped() {
    let rt = FakeRuntime::new();
    let left = rt.create(spec("racing")).await.unwrap();
    rt.inject(
        Op::Get,
        Fault::once(ComputeError::InvalidState {
            sandbox: "racing".into(),
            op: "connect to",
            status: WorkspaceStatus::Crashed,
        }),
    );
    // The VM went down between list and get (the fault stands in for that race): no stop.
    let report = reconcile(&rt, &Inventory::default(), &ShutdownConfig::default())
        .await
        .unwrap();
    // The fake still says Running, so the remove is refused and reported; after a real race
    // the remove goes through.
    assert_eq!(report.stopped.len(), 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].action, "remove");
    drop(left);
}

#[tokio::test]
async fn reconcile_fails_only_when_the_runtime_cannot_list() {
    for op in [Op::List, Op::StaleDirs, Op::ListVolumes] {
        let rt = FakeRuntime::new();
        rt.inject(op, Fault::once(runtime_error("list")));
        let err = reconcile(&rt, &Inventory::default(), &ShutdownConfig::default())
            .await
            .unwrap_err();
        assert_eq!(err, runtime_error("list"), "{op:?}");
    }
}

#[tokio::test]
async fn an_orphan_that_cannot_be_reached_is_reported() {
    let rt = FakeRuntime::new();
    let left = rt.create(spec("unreachable")).await.unwrap();
    rt.inject(Op::Get, Fault::once(runtime_error("get")));
    let report = reconcile(&rt, &Inventory::default(), &ShutdownConfig::default())
        .await
        .unwrap();
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].item, "unreachable");
    assert_eq!(report.failures[0].action, "stop");
    assert_eq!(report.removed.len(), 0);
    drop(left);
}

#[tokio::test]
async fn leftover_maintenance_sandboxes_go_even_when_listed() {
    let rt = FakeRuntime::new();
    fstrim_ok(&rt);
    // A maintenance run puddle died in (running), one that finished but wasn't removed, and a
    // foreign sandbox that only looks like one.
    let running = rt.create(spec("m--acme")).await.unwrap();
    rt.create(spec("m--beta"))
        .await
        .unwrap()
        .stop()
        .await
        .unwrap();
    rt.add_foreign_sandbox("m--other", WorkspaceStatus::Running);
    let inventory = Inventory {
        // Even a store that lists one doesn't keep it.
        sandboxes: BTreeSet::from([name("m--beta")]),
        ..Inventory::default()
    };

    let report = reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    assert_eq!(report.stopped, [name("m--acme")]);
    assert_eq!(report.removed, [name("m--acme"), name("m--beta")]);
    assert_eq!(report.foreign, ["m--other"]);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(status_of(&rt, "m--acme").await, None);
    assert_eq!(
        status_of(&rt, "m--other").await,
        Some(WorkspaceStatus::Running)
    );
    drop(running);
}

#[tokio::test]
async fn adopted_workspaces_refuse_a_second_sandbox_after_a_restart() {
    let rt = FakeRuntime::new();
    fstrim_ok(&rt);
    let acme = WorkspaceId::new("acme").unwrap();
    let beta = WorkspaceId::new("beta").unwrap();
    // Before the restart: "one" runs with workspace acme.
    let before = Workspaces::default();
    let one = before.create(&rt, &acme, spec("one"), None).await.unwrap();
    drop(one);
    drop(before);

    // After it: the registry is empty until reconcile adopts the store's attachments.
    let inventory = Inventory {
        sandboxes: BTreeSet::from([name("one")]),
        workspaces: BTreeSet::from([acme.clone(), beta.clone()]),
        attached: BTreeMap::from([
            (acme.clone(), name("one")),
            // Stale store rows are skipped, not adopted.
            (beta.clone(), name("gone")),
            (WorkspaceId::new("unknown").unwrap(), name("one")),
        ]),
        ..Inventory::default()
    };
    reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();
    let workspaces = Workspaces::default();
    let adopted = adopt_workspaces(&workspaces, &inventory);

    assert_eq!(adopted, [(acme.clone(), name("one"))]);
    assert_eq!(status_of(&rt, "one").await, Some(WorkspaceStatus::Stopped));
    let refused = workspaces
        .create(&rt, &acme, spec("two"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&refused, WorkspaceError::InUse { holder, .. } if holder == "one"),
        "{refused}"
    );
    assert!(workspaces.holder(&beta).is_none());
}

#[tokio::test]
async fn a_workspace_volume_the_inventory_does_not_list_is_kept() {
    let rt = FakeRuntime::new();
    rt.create_volume(VolumeSpec {
        name: vol("ws-lost"),
        size: DiskSize::mib(8),
    })
    .await
    .unwrap();

    // An empty inventory is what a missing or outdated workspace list gives.
    let report = reconcile(&rt, &Inventory::default(), &ShutdownConfig::default())
        .await
        .unwrap();

    assert!(report.volumes_removed.is_empty(), "{report:?}");
    assert_eq!(report.unknown_volumes, [vol("ws-lost")]);
    assert!(report.failures.is_empty(), "{report:?}");
    assert!(rt.volume(&vol("ws-lost")).await.unwrap().is_some());
}

#[tokio::test]
async fn a_known_workspace_wins_over_an_interrupted_mark() {
    let rt = FakeRuntime::new();
    rt.create_volume(VolumeSpec {
        name: vol("ws-both"),
        size: DiskSize::mib(8),
    })
    .await
    .unwrap();
    let both = WorkspaceId::new("both").unwrap();
    let inventory = Inventory {
        workspaces: BTreeSet::from([both.clone()]),
        interrupted: BTreeSet::from([both]),
        ..Inventory::default()
    };

    let report = reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    assert!(report.volumes_removed.is_empty() && report.unknown_volumes.is_empty());
    assert!(rt.volume(&vol("ws-both")).await.unwrap().is_some());
}

#[tokio::test]
async fn a_known_workspace_with_no_volume_is_reported_missing_and_nothing_is_changed() {
    let rt = FakeRuntime::new();
    rt.create_volume(VolumeSpec {
        name: vol("ws-here"),
        size: DiskSize::mib(8),
    })
    .await
    .unwrap();
    let (here, gone) = (
        WorkspaceId::new("here").unwrap(),
        WorkspaceId::new("gone").unwrap(),
    );
    let inventory = Inventory {
        workspaces: BTreeSet::from([here, gone.clone()]),
        ..Inventory::default()
    };

    let report = reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();

    assert_eq!(report.missing_volumes, [gone]);
    assert!(report.volumes_removed.is_empty() && report.failures.is_empty());
    assert!(rt.volume(&vol("ws-here")).await.unwrap().is_some());
}

#[tokio::test]
async fn finding_missing_volumes_costs_one_listing_however_many_workspaces_there_are() {
    let rt = FakeRuntime::new();
    let ids: Vec<_> = (0..50)
        .map(|n| WorkspaceId::new(&format!("w{n}")).unwrap())
        .collect();
    // Every other workspace has lost its volume.
    for id in ids.iter().step_by(2) {
        rt.create_volume(VolumeSpec {
            name: id.volume_name(),
            size: DiskSize::mib(8),
        })
        .await
        .unwrap();
    }
    let inventory = Inventory {
        workspaces: ids.iter().cloned().collect(),
        ..Inventory::default()
    };
    let before = rt.calls().len();

    let started = std::time::Instant::now();
    let report = reconcile(&rt, &inventory, &ShutdownConfig::default())
        .await
        .unwrap();
    let took = started.elapsed();

    let expected: BTreeSet<_> = ids.iter().skip(1).step_by(2).cloned().collect();
    assert_eq!(
        report
            .missing_volumes
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected
    );
    let calls = rt.calls().split_off(before);
    let count = |op: Op| calls.iter().filter(|c| c.op == op).count();
    assert_eq!(count(Op::ListVolumes), 1, "{calls:?}");
    assert_eq!(count(Op::Volume), 0, "{calls:?}");
    eprintln!(
        "missing-volume scan, 50 workspaces: {} calls, {took:?}",
        calls.len()
    );
}
