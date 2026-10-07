// SPDX-License-Identifier: GPL-3.0-or-later
//! An in-memory [`WorkspaceService`] for tests and the UI fixture, with scripted progress.
//!
//! It follows the trait's contract the way the real service does: a call checks the request,
//! marks the workspace busy, returns it, and a background task walks the operation's steps,
//! emitting [`Event::StatusChanged`] and [`Event::WorkspaceProgress`] as it goes. Tests wait for
//! the end with [`FakeWorkspaces::idle`], and can make the next operation fail.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::BoxFuture;
use puddle_store::Clock;
use puddle_types::{Event, EventSink, SandboxStatus, WorkspaceId, WorkspaceStep};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use crate::workspaces::{
    AttachMode, Attached, DEFAULT_DISK_MIB, DEFAULT_IMAGE, DeleteCheck, LaunchError, Launcher,
    Listing, NewWorkspace, Operation, RepoFindings, WorkspaceError, WorkspaceRecord,
    WorkspaceService,
};

/// A [`Launcher`] that opens nothing and remembers what it was asked to open.
#[derive(Debug, Default)]
pub struct FakeLauncher {
    opened: Mutex<Vec<WorkspaceId>>,
    fail_with: Mutex<Option<String>>,
}

impl FakeLauncher {
    /// A launcher that succeeds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the next launch fail with this message (once).
    pub fn fail_next(&self, message: impl Into<String>) {
        *lock(&self.fail_with) = Some(message.into());
    }

    /// The workspaces opened so far, in order.
    #[must_use]
    pub fn opened(&self) -> Vec<WorkspaceId> {
        lock(&self.opened).clone()
    }
}

impl Launcher for FakeLauncher {
    fn open_desktop<'a>(
        &'a self,
        workspace: &'a WorkspaceRecord,
    ) -> BoxFuture<'a, Result<(), LaunchError>> {
        Box::pin(async move {
            if let Some(message) = lock(&self.fail_with).take() {
                return Err(LaunchError::new(message));
            }
            lock(&self.opened).push(workspace.id.clone());
            Ok(())
        })
    }
}

/// What a seeded workspace would lose if it were deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unsaved {
    /// Per checkout.
    pub repos: Vec<RepoFindings>,
    /// Data outside any checkout.
    pub other: Listing,
    /// What the check could not read.
    pub errors: Vec<String>,
}

struct Entry {
    record: WorkspaceRecord,
    unsaved: Unsaved,
}

struct State {
    entries: BTreeMap<WorkspaceId, Entry>,
    fail_next: BTreeMap<Operation, String>,
}

struct Inner {
    state: Mutex<State>,
    events: Arc<dyn EventSink>,
    clock: Arc<dyn Clock>,
    launcher: Arc<dyn Launcher>,
    step_delay: Duration,
    browser_base: String,
    in_flight: watch::Sender<usize>,
    /// Operations wait here while it is `true`.
    held: watch::Sender<bool>,
}

/// The in-memory service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct FakeWorkspaces {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for FakeWorkspaces {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeWorkspaces")
            .field("workspaces", &lock(&self.inner.state).entries.len())
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeWorkspaces {
    /// An empty service that emits into `events` and stamps creations from `clock`.
    #[must_use]
    pub fn new(events: Arc<dyn EventSink>, clock: Arc<dyn Clock>) -> Self {
        Self::with_options(events, clock, Arc::new(FakeLauncher::new()), Duration::ZERO)
    }

    /// Like [`FakeWorkspaces::new`], with the launcher desktop attaches go through and a pause
    /// between operation steps (zero for none; a few hundred milliseconds lets a page show them).
    #[must_use]
    pub fn with_options(
        events: Arc<dyn EventSink>,
        clock: Arc<dyn Clock>,
        launcher: Arc<dyn Launcher>,
        step_delay: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    entries: BTreeMap::new(),
                    fail_next: BTreeMap::new(),
                }),
                events,
                clock,
                launcher,
                step_delay,
                browser_base: "http://127.0.0.1:18080".to_owned(),
                in_flight: watch::channel(0).0,
                held: watch::channel(false).0,
            }),
        }
    }

    /// Adds a workspace as it is (no events). Replaces one with the same id.
    pub fn seed(&self, record: WorkspaceRecord, unsaved: Unsaved) {
        lock(&self.inner.state)
            .entries
            .insert(record.id.clone(), Entry { record, unsaved });
    }

    /// Makes the next `operation` fail after its steps with this reason, once. The workspace
    /// goes back to where it was (a failed create leaves nothing behind) and a
    /// [`WorkspaceStep::Failed`] event carries the reason.
    pub fn fail_next(&self, operation: Operation, reason: impl Into<String>) {
        lock(&self.inner.state)
            .fail_next
            .insert(operation, reason.into());
    }

    /// Replaces what deleting `id` would lose. `false` if there is no such workspace.
    #[must_use]
    pub fn set_unsaved(&self, id: &WorkspaceId, unsaved: Unsaved) -> bool {
        lock(&self.inner.state)
            .entries
            .get_mut(id)
            .map(|e| e.unsaved = unsaved)
            .is_some()
    }

    /// Holds every operation before its next step until [`FakeWorkspaces::release`], so a test
    /// can look at the busy state.
    pub fn hold(&self) {
        self.inner.held.send_replace(true);
    }

    /// Lets held operations go on.
    pub fn release(&self) {
        self.inner.held.send_replace(false);
    }

    /// Resolves when no operation is running.
    pub async fn idle(&self) {
        let mut rx = self.inner.in_flight.subscribe();
        // The sender lives in `inner`, which this borrow keeps alive.
        let _ = rx.wait_for(|n| *n == 0).await;
    }

    fn emit_status(&self, record: &WorkspaceRecord) {
        self.inner.events.emit(Event::StatusChanged {
            sandbox: record.name.clone(),
            status: record.status,
        });
    }

    fn progress(&self, record: &WorkspaceRecord, step: WorkspaceStep, detail: Option<String>) {
        self.inner.events.emit(Event::WorkspaceProgress {
            sandbox: record.name.clone(),
            step,
            detail,
        });
    }

    /// Marks `id` busy with `op` after `check`, runs `enter` on the record (the immediate
    /// state change) and returns the record.
    fn accept(
        &self,
        id: &WorkspaceId,
        op: Operation,
        check: impl FnOnce(&WorkspaceRecord) -> Result<(), WorkspaceError>,
        enter: impl FnOnce(&mut WorkspaceRecord),
    ) -> Result<WorkspaceRecord, WorkspaceError> {
        let mut state = lock(&self.inner.state);
        let entry = state.entries.get_mut(id).ok_or_else(|| not_found(id))?;
        if let Some(busy) = entry.record.busy {
            return Err(WorkspaceError::Conflict(format!(
                "{} is busy ({busy}); wait for it to finish",
                entry.record.name
            )));
        }
        check(&entry.record)?;
        entry.record.busy = Some(op);
        enter(&mut entry.record);
        Ok(entry.record.clone())
    }

    /// Runs the rest of an operation on a task: the steps, then the end state.
    fn run(
        &self,
        record: &WorkspaceRecord,
        op: Operation,
        steps: Vec<(WorkspaceStep, Option<String>)>,
    ) {
        let this = self.clone();
        let record = record.clone();
        self.inner.in_flight.send_modify(|n| *n += 1);
        tokio::spawn(async move {
            for (step, detail) in steps {
                this.pause().await;
                this.progress(&record, step, detail);
            }
            this.pause().await;
            this.finish(&record.id, op);
            this.inner.in_flight.send_modify(|n| *n -= 1);
        });
    }

    async fn pause(&self) {
        let mut held = self.inner.held.subscribe();
        // The sender lives in `inner`, which `self` keeps alive.
        let _ = held.wait_for(|held| !*held).await;
        if self.inner.step_delay.is_zero() {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(self.inner.step_delay).await;
        }
    }

    fn finish(&self, id: &WorkspaceId, op: Operation) {
        let mut state = lock(&self.inner.state);
        let failure = state.fail_next.remove(&op);
        let Some(entry) = state.entries.get_mut(id) else {
            return;
        };
        entry.record.busy = None;
        let mut record = entry.record.clone();
        let mut status_changed = false;
        if let Some(reason) = failure {
            match op {
                Operation::Creating => {
                    state.entries.remove(id);
                }
                Operation::Starting => {
                    status_changed = true;
                    record.status = SandboxStatus::Crashed;
                }
                Operation::Stopping => {
                    // A failed graceful stop leaves the VM up.
                    status_changed = true;
                    record.status = SandboxStatus::Running;
                }
                Operation::Reclaiming | Operation::Deleting => {}
            }
            if let Some(entry) = state.entries.get_mut(id) {
                entry.record = record.clone();
            }
            drop(state);
            if status_changed {
                self.emit_status(&record);
            }
            self.progress(&record, WorkspaceStep::Failed, Some(reason));
            return;
        }
        match op {
            Operation::Creating => {}
            Operation::Starting => {
                record.status = SandboxStatus::Running;
                status_changed = true;
            }
            Operation::Stopping => {
                record.status = SandboxStatus::Stopped;
                status_changed = true;
            }
            Operation::Reclaiming => {
                record.disk_used_mib = record.disk_used_mib.map(|used| used / 2);
            }
            Operation::Deleting => {
                state.entries.remove(id);
            }
        }
        if op != Operation::Deleting
            && let Some(entry) = state.entries.get_mut(id)
        {
            entry.record = record.clone();
        }
        drop(state);
        if status_changed {
            self.emit_status(&record);
        }
        self.progress(&record, WorkspaceStep::Done, None);
    }

    fn check_for(&self, id: &WorkspaceId) -> Result<DeleteCheck, WorkspaceError> {
        let state = lock(&self.inner.state);
        let entry = state.entries.get(id).ok_or_else(|| not_found(id))?;
        Ok(delete_check(entry))
    }
}

fn not_found(id: &WorkspaceId) -> WorkspaceError {
    WorkspaceError::NotFound(format!("no workspace {id}"))
}

fn delete_check(entry: &Entry) -> DeleteCheck {
    let removes_sandbox = entry
        .record
        .status
        .is_down()
        .then(|| entry.record.name.clone());
    let mut check = DeleteCheck {
        workspace: entry.record.id.clone(),
        repos: entry.unsaved.repos.clone(),
        other: entry.unsaved.other.clone(),
        errors: entry.unsaved.errors.clone(),
        removes_sandbox,
        fingerprint: String::new(),
    };
    check.fingerprint = fingerprint(&check);
    check
}

/// A digest over everything a user sees in the report, so a delete can prove it is for that
/// report.
fn fingerprint(check: &DeleteCheck) -> String {
    let mut hash = Sha256::new();
    let mut put = |text: &str| {
        hash.update(u64::try_from(text.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(text.as_bytes());
    };
    let mut list = |name: &str, l: &Listing| {
        put(name);
        for item in &l.items {
            put(item);
        }
        put(&l.more.to_string());
    };
    for repo in &check.repos {
        list(&format!("dir:{}", repo.dir), &Listing::default());
        list("uncommitted", &repo.uncommitted);
        list("unpushed", &repo.unpushed);
        list("stashes", &repo.stashes);
    }
    list("other", &check.other);
    let mut errors = Listing::default();
    errors.items.clone_from(&check.errors);
    list("errors", &errors);
    hash.finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

impl WorkspaceService for FakeWorkspaces {
    fn list(&self) -> BoxFuture<'_, Result<Vec<WorkspaceRecord>, WorkspaceError>> {
        Box::pin(async move {
            Ok(lock(&self.inner.state)
                .entries
                .values()
                .map(|e| e.record.clone())
                .collect())
        })
    }

    fn get<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            lock(&self.inner.state)
                .entries
                .get(id)
                .map(|e| e.record.clone())
                .ok_or_else(|| not_found(id))
        })
    }

    fn create(&self, new: NewWorkspace) -> BoxFuture<'_, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let id = WorkspaceId::new(new.name.as_str()).map_err(|e| {
                WorkspaceError::Invalid(format!("this name can't be a workspace: {e}"))
            })?;
            let mut record =
                WorkspaceRecord::new(id.clone(), new.name.clone(), new.repo_url.as_str());
            record.image = new
                .image
                .as_ref()
                .map_or_else(|| DEFAULT_IMAGE.to_owned(), |i| i.as_str().to_owned());
            if let Some(memory) = new.memory {
                record.memory = memory;
            }
            record.created_at = self.inner.clock.now_ms();
            record.disk_size_mib = DEFAULT_DISK_MIB;
            record.disk_used_mib = Some(0);
            record.busy = Some(Operation::Creating);
            {
                let mut state = lock(&self.inner.state);
                if state.entries.contains_key(&id) {
                    return Err(WorkspaceError::Conflict(format!(
                        "a workspace named {} already exists",
                        new.name
                    )));
                }
                state.entries.insert(
                    id,
                    Entry {
                        record: record.clone(),
                        unsaved: Unsaved::default(),
                    },
                );
            }
            self.emit_status(&record);
            self.run(
                &record,
                Operation::Creating,
                vec![
                    (WorkspaceStep::PreparingVolume, None),
                    (WorkspaceStep::PullingImage, Some(record.image.clone())),
                    (WorkspaceStep::Cloning, Some(record.repo_url.clone())),
                ],
            );
            Ok(record)
        })
    }

    fn start<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let record = self.accept(
                id,
                Operation::Starting,
                |r| {
                    if r.status.is_down() {
                        Ok(())
                    } else {
                        Err(WorkspaceError::Conflict(format!(
                            "{} is already {}",
                            r.name, r.status
                        )))
                    }
                },
                |r| r.status = SandboxStatus::Starting,
            )?;
            self.emit_status(&record);
            self.run(
                &record,
                Operation::Starting,
                vec![
                    (WorkspaceStep::Starting, None),
                    (WorkspaceStep::Syncing, None),
                ],
            );
            Ok(record)
        })
    }

    fn stop<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let record = self.accept(
                id,
                Operation::Stopping,
                |r| {
                    if r.status == SandboxStatus::Running {
                        Ok(())
                    } else {
                        Err(WorkspaceError::Conflict(format!(
                            "{} is not running ({})",
                            r.name, r.status
                        )))
                    }
                },
                |r| r.status = SandboxStatus::Draining,
            )?;
            self.emit_status(&record);
            self.run(
                &record,
                Operation::Stopping,
                vec![
                    (WorkspaceStep::Stopping, None),
                    (WorkspaceStep::Reclaiming, None),
                ],
            );
            Ok(record)
        })
    }

    fn reclaim<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let record = self.accept(
                id,
                Operation::Reclaiming,
                |r| {
                    if r.status == SandboxStatus::Starting || r.status == SandboxStatus::Draining {
                        Err(WorkspaceError::Conflict(format!(
                            "{} is {}; try again in a moment",
                            r.name, r.status
                        )))
                    } else {
                        Ok(())
                    }
                },
                |_| {},
            )?;
            self.run(
                &record,
                Operation::Reclaiming,
                vec![(WorkspaceStep::Reclaiming, None)],
            );
            Ok(record)
        })
    }

    fn delete_check<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<DeleteCheck, WorkspaceError>> {
        Box::pin(async move { self.check_for(id) })
    }

    fn delete<'a>(
        &'a self,
        id: &'a WorkspaceId,
        fingerprint: Option<&'a str>,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let check = self.check_for(id)?;
            let record = self.accept(
                id,
                Operation::Deleting,
                |r| {
                    if !r.status.is_down() {
                        return Err(WorkspaceError::Conflict(format!(
                            "{} is {}; stop it before deleting it",
                            r.name, r.status
                        )));
                    }
                    match fingerprint {
                        Some(seen) if seen == check.fingerprint => Ok(()),
                        Some(_) => Err(WorkspaceError::Conflict(format!(
                            "{} has changed since it was checked; check it again",
                            r.name
                        ))),
                        None if check.is_clean() => Ok(()),
                        None => Err(WorkspaceError::Conflict(format!(
                            "{} has work that is not saved on a remote; review it and confirm",
                            r.name
                        ))),
                    }
                },
                |_| {},
            )?;
            self.run(
                &record,
                Operation::Deleting,
                vec![
                    (WorkspaceStep::Checking, None),
                    (WorkspaceStep::Removing, None),
                ],
            );
            Ok(record)
        })
    }

    fn attach<'a>(
        &'a self,
        id: &'a WorkspaceId,
        mode: AttachMode,
    ) -> BoxFuture<'a, Result<Attached, WorkspaceError>> {
        Box::pin(async move {
            let record = self.get(id).await?;
            if record.busy.is_some() || record.status != SandboxStatus::Running {
                return Err(WorkspaceError::Conflict(format!(
                    "{} is not running; start it first",
                    record.name
                )));
            }
            match mode {
                AttachMode::Browser => Ok(Attached::at(format!(
                    "{}/workspaces/{}/",
                    self.inner.browser_base, record.id
                ))),
                AttachMode::Desktop => match self.inner.launcher.open_desktop(&record).await {
                    Ok(()) => {
                        if let Some(entry) = lock(&self.inner.state).entries.get_mut(id) {
                            entry.record.first_connect_notice_due = false;
                        }
                        Ok(Attached::opened())
                    }
                    Err(err) => Ok(Attached::not_opened(err.to_string())),
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use puddle_store::ManualClock;
    use puddle_types::{CollectingSink, SandboxName};

    use super::*;
    use crate::workspaces::RepoUrl;

    fn id(s: &str) -> WorkspaceId {
        WorkspaceId::new(s).unwrap()
    }

    fn fake() -> (FakeWorkspaces, Arc<CollectingSink>) {
        let sink = Arc::new(CollectingSink::default());
        let fake = FakeWorkspaces::new(sink.clone(), Arc::new(ManualClock::new(7)));
        (fake, sink)
    }

    fn new_ws(name: &str) -> NewWorkspace {
        NewWorkspace::new(
            SandboxName::new(name).unwrap(),
            RepoUrl::parse("https://example.com/a/b").unwrap(),
        )
    }

    fn seeded(fake: &FakeWorkspaces, name: &str, status: SandboxStatus) {
        let mut record = WorkspaceRecord::new(
            id(name),
            SandboxName::new(name).unwrap(),
            "https://x.test/a",
        );
        record.status = status;
        fake.seed(record, Unsaved::default());
    }

    fn steps(sink: &CollectingSink) -> Vec<WorkspaceStep> {
        sink.events()
            .into_iter()
            .filter_map(|e| match e {
                Event::WorkspaceProgress { step, .. } => Some(step),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn a_failed_stop_leaves_the_workspace_running() {
        let (fake, sink) = fake();
        seeded(&fake, "w", SandboxStatus::Running);
        fake.fail_next(Operation::Stopping, "the VM would not stop");
        fake.stop(&id("w")).await.unwrap();
        fake.idle().await;
        assert_eq!(
            fake.get(&id("w")).await.unwrap().status,
            SandboxStatus::Running
        );
        assert_eq!(steps(&sink).last(), Some(&WorkspaceStep::Failed));
    }

    #[tokio::test]
    async fn failed_reclaim_and_delete_change_nothing() {
        let (fake, sink) = fake();
        seeded(&fake, "w", SandboxStatus::Stopped);
        fake.fail_next(Operation::Reclaiming, "trim failed");
        fake.reclaim(&id("w")).await.unwrap();
        fake.idle().await;
        fake.fail_next(Operation::Deleting, "volume busy");
        fake.delete(&id("w"), None).await.unwrap();
        fake.idle().await;
        let record = fake.get(&id("w")).await.unwrap();
        assert_eq!(record.busy, None);
        assert_eq!(record.status, SandboxStatus::Stopped);
        let failed = steps(&sink)
            .iter()
            .filter(|s| **s == WorkspaceStep::Failed)
            .count();
        assert_eq!(failed, 2);
    }

    #[tokio::test]
    async fn reclaim_waits_out_a_boot_or_shutdown() {
        let (fake, _) = fake();
        seeded(&fake, "a", SandboxStatus::Starting);
        seeded(&fake, "b", SandboxStatus::Draining);
        seeded(&fake, "c", SandboxStatus::Running);
        for name in ["a", "b"] {
            assert!(matches!(
                fake.reclaim(&id(name)).await,
                Err(WorkspaceError::Conflict(_))
            ));
        }
        assert!(fake.reclaim(&id("c")).await.is_ok());
        fake.idle().await;
    }

    #[tokio::test]
    async fn a_long_name_cannot_be_a_workspace() {
        let (fake, _) = fake();
        let long = "n".repeat(WorkspaceId::MAX_LEN + 1);
        let err = fake.create(new_ws(&long)).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::Invalid(_)), "{err}");
    }

    #[tokio::test]
    async fn operations_on_unknown_workspaces_are_not_found() {
        let (fake, _) = fake();
        let ghost = id("ghost");
        assert!(matches!(
            fake.get(&ghost).await,
            Err(WorkspaceError::NotFound(_))
        ));
        assert!(matches!(
            fake.start(&ghost).await,
            Err(WorkspaceError::NotFound(_))
        ));
        assert!(matches!(
            fake.delete(&ghost, None).await,
            Err(WorkspaceError::NotFound(_))
        ));
        assert!(!fake.set_unsaved(&ghost, Unsaved::default()));
        assert_eq!(fake.list().await.unwrap(), []);
    }

    #[tokio::test]
    async fn steps_pause_for_the_configured_delay() {
        tokio::time::pause();
        let sink = Arc::new(CollectingSink::default());
        let fake = FakeWorkspaces::with_options(
            sink.clone(),
            Arc::new(ManualClock::new(0)),
            Arc::new(FakeLauncher::new()),
            Duration::from_millis(300),
        );
        fake.create(new_ws("slow")).await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            steps(&sink).is_empty(),
            "nothing before the first pause ends"
        );
        fake.idle().await;
        assert_eq!(steps(&sink).len(), 4);
        assert!(format!("{fake:?}").contains("workspaces"));
    }

    #[tokio::test]
    async fn the_fingerprint_follows_every_part_of_the_report() {
        let (fake, _) = fake();
        seeded(&fake, "w", SandboxStatus::Stopped);
        let base = fake.delete_check(&id("w")).await.unwrap();
        let mut seen = vec![base.fingerprint.clone()];
        let variants = [
            Unsaved {
                repos: vec![RepoFindings {
                    dir: "r".into(),
                    ..RepoFindings::default()
                }],
                ..Unsaved::default()
            },
            Unsaved {
                other: Listing {
                    items: vec![],
                    more: 1,
                },
                ..Unsaved::default()
            },
            Unsaved {
                errors: vec!["r: unreadable".into()],
                ..Unsaved::default()
            },
            Unsaved {
                repos: vec![RepoFindings {
                    dir: "r".into(),
                    stashes: Listing {
                        items: vec!["s".into()],
                        more: 0,
                    },
                    ..RepoFindings::default()
                }],
                ..Unsaved::default()
            },
        ];
        for unsaved in variants {
            assert!(fake.set_unsaved(&id("w"), unsaved));
            seen.push(fake.delete_check(&id("w")).await.unwrap().fingerprint);
        }
        let unique: std::collections::BTreeSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), seen.len(), "{seen:?}");
    }

    #[tokio::test]
    async fn the_launcher_records_what_it_opened() {
        let launcher = FakeLauncher::new();
        let record =
            WorkspaceRecord::new(id("w"), SandboxName::new("w").unwrap(), "https://x.test/a");
        launcher.open_desktop(&record).await.unwrap();
        launcher.fail_next("nope");
        assert_eq!(
            launcher
                .open_desktop(&record)
                .await
                .unwrap_err()
                .to_string(),
            "nope"
        );
        launcher.open_desktop(&record).await.unwrap();
        assert_eq!(launcher.opened(), [id("w"), id("w")]);
    }
}
