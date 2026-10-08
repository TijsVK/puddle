// SPDX-License-Identifier: GPL-3.0-or-later
//! The real [`WorkspaceService`]: workspaces on the sandbox runtime.
//!
//! A call checks the request, marks the workspace busy, returns it, and a task owned by the
//! service does the work, reporting each step as an event (the contract of
//! [`WorkspaceService`]). The work is `puddle-workspace` (volumes, holders, trim, delete check),
//! `puddle-boot` (the boot hook and its gate), the egress route of `puddle-proxy` and the SSH
//! endpoint of `puddle-ssh`; the sandboxes are handed to the [`Lifecycle`] so they are trimmed
//! and stopped when the host exits.
//!
//! A sandbox boots from the spec it was created with, and that spec holds the endpoint of its
//! egress route, which only lives as long as this process. So a stopped workspace starts again in
//! the same sandbox only while this process still serves that route; otherwise (after a restart
//! of the host) its sandbox is rebuilt on the same volume. Everything on the volume survives,
//! the root disk does not (ADR 0006, point 3).
//!
//! The workspace list on disk is what the next start keeps volumes for, so it is saved before
//! anything it must cover exists or goes: a create is refused when its entry can't be written,
//! a create whose final save fails is undone before anyone works in it, and a delete is refused
//! when the entry can't be taken out first (principle 7, "your work is never lost by accident").

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::BoxFuture;
use puddle_api::{
    AttachMode, Attached, DEFAULT_IMAGE, DeleteCheck, LaunchError, Launcher, Listing, NewWorkspace,
    Operation, RepoFindings, WorkspaceError, WorkspaceRecord, WorkspaceService,
};
use puddle_boot::{BootError, Gate, GatedSandbox};
use puddle_ca::CaCertificate;
use puddle_compute::{ComputeError, DiskSize, ImageConfig, Runtime};
use puddle_lifecycle::Lifecycle;
use puddle_proxy::Route;
use puddle_settings::{WorkspaceSettings, resolve};
use puddle_ssh::SshEndpoint;
use puddle_store::Clock;
use puddle_types::{
    Event, EventSink, GuestEnv, ImageRef, MemoryMib, WorkspaceId, WorkspaceName, WorkspaceStatus,
    WorkspaceStep,
};
use puddle_workspace::{Findings, Layout, Workspaces};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::HostError;
use crate::boot::{BootKit, GuestInputs};
use crate::files::{Stored, WorkspaceBook};
use crate::git_hosts::{Authors, authors};
use crate::injection::Injection;

impl<R: Runtime + Clone> crate::changes::GitChanges for HostWorkspaces<R> {
    fn decrypt_changed(&self, workspace: &WorkspaceName) -> Option<puddle_store::WorkspaceGit> {
        Self::decrypt_changed(self, workspace)
    }

    async fn rewrite_authors(&self, workspace: WorkspaceName, git: puddle_store::WorkspaceGit) {
        Self::rewrite_authors(self, &workspace, &git).await;
    }

    async fn all_git_changed(&self) {
        Self::all_git_changed(self).await;
    }
}

/// A [`Launcher`] for a host with no desktop shell: every attach says so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoLauncher;

impl Launcher for NoLauncher {
    fn open_desktop<'a>(
        &'a self,
        _workspace: &'a WorkspaceRecord,
    ) -> BoxFuture<'a, Result<(), LaunchError>> {
        Box::pin(async {
            Err(LaunchError::new(
                "this puddle has no desktop shell to open an editor from",
            ))
        })
    }
}

/// What the service is built from.
pub(crate) struct Parts<R: Runtime + Clone> {
    pub(crate) runtime: R,
    pub(crate) workspaces: Workspaces,
    pub(crate) lifecycle: Arc<Lifecycle<R>>,
    pub(crate) kit: BootKit,
    pub(crate) events: Arc<dyn EventSink>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) settings: Arc<dyn puddle_api::SettingsRepo>,
    pub(crate) launcher: Arc<dyn Launcher>,
    pub(crate) book: WorkspaceBook,
    pub(crate) injection: Arc<Injection>,
}

struct Slot {
    record: WorkspaceRecord,
    creating: bool,
    /// Being deleted: left out of the saved list, so a delete that went through can't come
    /// back as a workspace without a volume.
    deleting: bool,
    /// The start that is running was refused because the volume is gone; `conclude` turns it
    /// into the `volume_missing` state instead of `crashed`.
    volume_missing: bool,
}

struct State {
    slots: BTreeMap<WorkspaceId, Slot>,
    closed: bool,
}

/// What the running guest was set up with, kept to set it up again with one thing changed.
#[derive(Clone)]
struct GuestState {
    /// The image's config, so a plan can be rebuilt without pulling.
    image: ImageConfig,
    /// This start's CA certificate.
    ca: CaCertificate,
    /// The commit authors the guest holds now.
    authors: Authors,
}

/// What a sandbox owns while this process serves it.
struct Live<R: Runtime> {
    /// The egress route baked into the sandbox's spec; it outlives stops.
    route: Route,
    gate: Gate,
    /// The booted sandbox, while it runs.
    gated: Option<Arc<GatedSandbox<R::Sandbox>>>,
    ssh: Option<SshEndpoint>,
    /// What the running guest was given at boot; `None` while it does not run.
    guest: Option<GuestState>,
    /// Held while the running guest's author files are rewritten, so two changes never run the
    /// boot hook at once.
    rewrite: Arc<tokio::sync::Mutex<()>>,
}

struct Inner<R: Runtime + Clone> {
    runtime: R,
    workspaces: Workspaces,
    lifecycle: Arc<Lifecycle<R>>,
    kit: BootKit,
    events: Arc<dyn EventSink>,
    clock: Arc<dyn Clock>,
    settings: Arc<dyn puddle_api::SettingsRepo>,
    launcher: Arc<dyn Launcher>,
    book: WorkspaceBook,
    injection: Arc<Injection>,
    state: Mutex<State>,
    live: tokio::sync::Mutex<BTreeMap<WorkspaceName, Live<R>>>,
    tasks: tokio::sync::Mutex<JoinSet<()>>,
    running: watch::Sender<usize>,
}

/// The workspaces service. Cheap to clone; clones share state.
pub struct HostWorkspaces<R: Runtime + Clone> {
    inner: Arc<Inner<R>>,
}

impl<R: Runtime + Clone> Clone for HostWorkspaces<R> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<R: Runtime + Clone> std::fmt::Debug for HostWorkspaces<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostWorkspaces")
            .field("workspaces", &self.state().slots.len())
            .finish_non_exhaustive()
    }
}

/// The way out after the workspace list could not be saved; the error already names the file.
const SAVE_HINT: &str =
    "check the free disk space and that puddle may write that file, then try again";

fn not_found(id: &WorkspaceId) -> WorkspaceError {
    WorkspaceError::NotFound(format!("no workspace {id}"))
}

fn workspace_error(e: &puddle_workspace::WorkspaceError) -> WorkspaceError {
    match e {
        puddle_workspace::WorkspaceError::InUse { .. } => WorkspaceError::Conflict(e.to_string()),
        puddle_workspace::WorkspaceError::NotFound { .. } => {
            WorkspaceError::NotFound(e.to_string())
        }
        other => WorkspaceError::Internal(other.to_string()),
    }
}

fn listing(l: &puddle_workspace::Listing) -> Listing {
    let mut out = Listing::default();
    out.items.clone_from(&l.items);
    out.more = l.more;
    out
}

fn delete_check(report: &puddle_workspace::DeleteReport) -> DeleteCheck {
    let Findings {
        repos,
        other,
        errors,
    } = &report.findings;
    let check = DeleteCheck::new(
        report.workspace.clone(),
        repos
            .iter()
            .map(|r| {
                let mut out = RepoFindings::default();
                out.dir.clone_from(&r.dir);
                out.uncommitted = listing(&r.uncommitted);
                out.unpushed = listing(&r.unpushed);
                out.stashes = listing(&r.stashes);
                out
            })
            .collect(),
        listing(other),
        errors.clone(),
        report.removes_sandbox.clone(),
    );
    if report.volume_missing {
        check.with_volume_missing()
    } else {
        check
    }
}

/// Holds the count of running operations up for as long as it lives.
struct Running(watch::Sender<usize>);

impl Running {
    fn new(sender: &watch::Sender<usize>) -> Self {
        sender.send_modify(|n| *n += 1);
        Self(sender.clone())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl<R: Runtime + Clone> HostWorkspaces<R> {
    /// The service over `parts`, with the workspaces the book held and the state each sandbox
    /// was left in by reconcile (no sandbox: stopped).
    pub(crate) fn new(
        parts: Parts<R>,
        restored: Vec<Stored>,
        status: &BTreeMap<WorkspaceName, WorkspaceStatus>,
    ) -> Result<Self, HostError> {
        let mut slots = BTreeMap::new();
        let mut interrupted = false;
        for stored in restored {
            if stored.creating {
                // A create that never finished (puddle died in it): there is no workspace, and
                // reconcile removes the half-made volume.
                tracing::warn!(workspace = %stored.id, "dropping a workspace whose create never finished");
                interrupted = true;
                continue;
            }
            let state = |e: &dyn std::fmt::Display| HostError::State {
                what: "the workspace list",
                reason: e.to_string(),
            };
            let id = WorkspaceId::new(&stored.id).map_err(|e| state(&e))?;
            let name = WorkspaceName::new(&stored.name).map_err(|e| state(&e))?;
            let mut record = WorkspaceRecord::new(id.clone(), name.clone(), stored.repo_url);
            record.image = stored.image;
            record.memory = MemoryMib::new(stored.memory_mib).map_err(|e| HostError::State {
                what: "the workspace list",
                reason: format!(
                    "workspace {name} has an invalid memory size ({e}); fix it in workspaces.json in puddle's data folder, or remove that entry (its volume is kept)"
                ),
            })?;
            record.created_at = stored.created_at;
            record.disk_size_mib = stored.disk_size_mib;
            record.status = match status.get(&name) {
                Some(WorkspaceStatus::Crashed) => WorkspaceStatus::Crashed,
                _ => WorkspaceStatus::Stopped,
            };
            slots.insert(
                id,
                Slot {
                    record,
                    creating: false,
                    deleting: false,
                    volume_missing: false,
                },
            );
        }
        let service = Self {
            inner: Arc::new(Inner {
                runtime: parts.runtime,
                workspaces: parts.workspaces,
                lifecycle: parts.lifecycle,
                kit: parts.kit,
                events: parts.events,
                clock: parts.clock,
                settings: parts.settings,
                launcher: parts.launcher,
                book: parts.book,
                injection: parts.injection,
                state: Mutex::new(State {
                    slots,
                    closed: false,
                }),
                live: tokio::sync::Mutex::new(BTreeMap::new()),
                tasks: tokio::sync::Mutex::new(JoinSet::new()),
                running: watch::channel(0).0,
            }),
        };
        if interrupted && let Err(e) = service.persist(&service.state()) {
            // Harmless: the entries still say "being created", so the next start drops them
            // again, and every later save writes the list without them.
            tracing::warn!(error = %e, "the workspace list was not saved after dropping unfinished creates");
        }
        Ok(service)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the book. Called with the state lock held, so saves cannot reorder.
    fn persist(&self, state: &State) -> Result<(), HostError> {
        let stored = state
            .slots
            .values()
            .filter(|slot| !slot.deleting)
            .map(|slot| Stored {
                id: slot.record.id.to_string(),
                name: slot.record.name.to_string(),
                repo_url: slot.record.repo_url.clone(),
                image: slot.record.image.clone(),
                memory_mib: slot.record.memory.get(),
                created_at: slot.record.created_at,
                disk_size_mib: slot.record.disk_size_mib,
                creating: slot.creating,
            })
            .collect();
        self.inner.book.save(stored)
    }

    /// The create of `id` finished: saves its entry as complete. Until this succeeds the list
    /// says the create never finished, and the next start would remove its volume.
    fn mark_created(&self, id: &WorkspaceId) -> Result<(), String> {
        let mut state = self.state();
        let Some(slot) = state.slots.get_mut(id) else {
            return Err(not_found(id).to_string());
        };
        slot.creating = false;
        let saved = self.persist(&state);
        if saved.is_err()
            && let Some(slot) = state.slots.get_mut(id)
        {
            slot.creating = true;
        }
        saved.map_err(|e| e.to_string())
    }

    fn status_event(&self, record: &WorkspaceRecord) {
        self.inner.events.emit(Event::StatusChanged {
            workspace: record.name.clone(),
            status: record.status,
        });
    }

    fn progress(&self, name: &WorkspaceName, step: WorkspaceStep, detail: Option<String>) {
        self.inner.events.emit(Event::WorkspaceProgress {
            workspace: name.clone(),
            step,
            detail,
        });
    }

    /// Stops taking new operations (they get "shutting down"). Running ones go on.
    pub fn close(&self) {
        self.state().closed = true;
    }

    /// Waits until no operation runs, at most `grace`; then ends the ones still running.
    /// Returns how many had to be ended.
    pub(crate) async fn finish_operations(&self, grace: Duration) -> usize {
        let mut count = self.inner.running.subscribe();
        let idle = tokio::time::timeout(grace, count.wait_for(|n| *n == 0)).await;
        if idle.is_ok() {
            return 0;
        }
        let ended = *self.inner.running.borrow();
        tracing::warn!(ended, "shutdown: ending workspace operations still running");
        let mut tasks = self.inner.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        ended
    }

    /// Closes what the sandboxes own: SSH endpoints and egress routes. The sandboxes are
    /// stopped by the [`Lifecycle`] before this.
    pub(crate) async fn release_all(&self) {
        let live = std::mem::take(&mut *self.inner.live.lock().await);
        for (_, entry) in live {
            let Live { route, ssh, .. } = entry;
            if let Some(ssh) = ssh {
                ssh.close().await;
            }
            route.shutdown().await;
        }
    }

    /// What `workspace` decrypts, and the CA that certifies it, while its sandbox runs: `None`
    /// for a workspace that is stopped or never started.
    #[must_use]
    pub fn termination(&self, workspace: &WorkspaceName) -> Option<Arc<puddle_proxy::Termination>> {
        self.inner.injection.termination(workspace)
    }

    /// The SSH endpoint of a running workspace's sandbox.
    pub async fn ssh_endpoint(&self, workspace: &WorkspaceName) -> Option<std::path::PathBuf> {
        let live = self.inner.live.lock().await;
        let ssh = live.get(workspace)?.ssh.as_ref()?;
        Some(ssh.endpoint().path().to_path_buf())
    }

    fn accept(
        &self,
        id: &WorkspaceId,
        op: Operation,
        check: impl FnOnce(&WorkspaceRecord) -> Result<(), WorkspaceError>,
        enter: impl FnOnce(&mut WorkspaceRecord),
    ) -> Result<WorkspaceRecord, WorkspaceError> {
        let mut state = self.state();
        if state.closed {
            return Err(WorkspaceError::Unavailable(
                "puddle is shutting down".to_owned(),
            ));
        }
        let slot = state.slots.get_mut(id).ok_or_else(|| not_found(id))?;
        if let Some(busy) = slot.record.busy {
            return Err(WorkspaceError::Conflict(format!(
                "{} is busy ({busy}); wait for it to finish",
                slot.record.name
            )));
        }
        check(&slot.record)?;
        slot.record.busy = Some(op);
        enter(&mut slot.record);
        Ok(slot.record.clone())
    }

    /// Runs `work` on a task the service owns and settles the workspace when it ends.
    async fn run<F>(&self, record: &WorkspaceRecord, op: Operation, work: F)
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        let this = self.clone();
        let id = record.id.clone();
        let running = Running::new(&self.inner.running);
        let mut tasks = self.inner.tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _running = running;
            let result = work.await;
            this.conclude(&id, op, result);
        });
    }

    /// Ends an operation: the busy mark goes, the state follows the outcome, and the last event
    /// of the operation says how it went.
    fn conclude(&self, id: &WorkspaceId, op: Operation, result: Result<(), String>) {
        let mut state = self.state();
        let Some(slot) = state.slots.get_mut(id) else {
            return;
        };
        slot.record.busy = None;
        slot.deleting = false;
        let name = slot.record.name.clone();
        let mut status_changed = false;
        // Only a failed create or delete leaves the list different from what is saved: the
        // failed create's entry goes, the failed delete's entry comes back.
        let save = matches!(
            (&result, op),
            (Err(_), Operation::Creating | Operation::Deleting)
        );
        let mut result = result;
        let old_entry = slot.creating;
        match (&result, op) {
            (Err(_), Operation::Creating) | (Ok(()), Operation::Deleting) => {
                state.slots.remove(id);
            }
            (Err(_), Operation::Starting) => {
                slot.record.status = if std::mem::take(&mut slot.volume_missing) {
                    WorkspaceStatus::VolumeMissing
                } else {
                    WorkspaceStatus::Crashed
                };
                status_changed = true;
            }
            (Err(_), Operation::Stopping) => {
                slot.record.status = WorkspaceStatus::Running;
                status_changed = true;
            }
            (Err(_), Operation::Reclaiming | Operation::Deleting)
            | (Ok(()), Operation::Reclaiming) => {}
            (Ok(()), Operation::Creating | Operation::Starting) => {
                slot.record.status = WorkspaceStatus::Running;
                slot.creating = false;
                status_changed = true;
            }
            (Ok(()), Operation::Stopping) => {
                slot.record.status = WorkspaceStatus::Stopped;
                status_changed = true;
            }
        }
        let record = state.slots.get(id).map(|s| s.record.clone());
        if save && let Err(e) = self.persist(&state) {
            if old_entry {
                // The entry still says "being created", so the next start drops it and removes
                // what is left of the volume: nothing the user worked on.
                tracing::warn!(workspace = %id, error = %e, "the workspace list was not saved after a failed create");
            } else if let Err(reason) = &mut result {
                // The workspace is now missing from the saved list: the next start keeps its
                // volume and reports it, but doesn't list the workspace.
                *reason = format!("{reason}; {e}; {SAVE_HINT}");
            }
        }
        drop(state);
        if let (true, Some(record)) = (status_changed, &record) {
            self.status_event(record);
        }
        match result {
            Ok(()) => self.progress(&name, WorkspaceStep::Done, None),
            Err(reason) => {
                tracing::warn!(workspace = %id, %op, %reason, "workspace operation failed");
                self.progress(&name, WorkspaceStep::Failed, Some(reason));
            }
        }
    }

    /// The default memory for a workspace made without one: the settings' value. An unreadable
    /// settings document is an error, so the workspace is not made with a size the user never
    /// chose.
    fn default_memory(&self) -> Result<MemoryMib, String> {
        let global = crate::settings_read::global(self.inner.settings.as_ref())?;
        Ok(resolve(&global, None::<&WorkspaceSettings>).memory.value)
    }

    /// The image config of `image`, pulling it if needed.
    async fn image_config(&self, image: &ImageRef) -> Result<ImageConfig, String> {
        self.inner
            .runtime
            .pull_image(image)
            .await
            .map_err(|e| e.to_string())
    }

    /// Creates a sandbox on workspace `record`'s volume and boots it through the hook.
    fn mark_volume_missing(&self, id: &WorkspaceId) {
        if let Some(slot) = self.state().slots.get_mut(id) {
            slot.volume_missing = true;
        }
    }

    async fn boot_new(
        &self,
        record: &WorkspaceRecord,
        created_volume: &mut bool,
        announce_pull: bool,
        fresh: bool,
    ) -> Result<(), String> {
        let inner = &self.inner;
        let (id, name) = (&record.id, &record.name);
        let size = DiskSize::mib(u32::try_from(record.disk_size_mib).unwrap_or(u32::MAX));
        if announce_pull {
            self.progress(name, WorkspaceStep::PreparingVolume, None);
        }
        // A start must find the volume it left; only a create makes one.
        let attachment = if fresh {
            inner
                .workspaces
                .prepare(&inner.runtime, id, &name.sandbox_name(), Some(size))
                .await
        } else {
            inner
                .workspaces
                .prepare_existing(&inner.runtime, id, &name.sandbox_name())
                .await
        }
        .map_err(|e| {
            if matches!(e, puddle_workspace::WorkspaceError::VolumeMissing { .. }) {
                self.mark_volume_missing(id);
            }
            e.to_string()
        })?;
        *created_volume = attachment.created_volume();
        let image = ImageRef::new(&record.image).map_err(|e| e.to_string());
        let config = match &image {
            Ok(image) => {
                if announce_pull {
                    self.progress(
                        name,
                        WorkspaceStep::PullingImage,
                        Some(record.image.clone()),
                    );
                }
                self.image_config(image).await
            }
            Err(e) => Err(e.clone()),
        };
        let (plan, env, guest) = match config.and_then(|c| self.plan_guest(name, c)) {
            Ok(ready) => ready,
            Err(reason) => {
                self.abort_attachment(attachment).await;
                return Err(reason);
            }
        };
        let image = image.map_err(|e| e.clone())?;
        self.progress(name, WorkspaceStep::Starting, None);
        let route = match inner.kit.route(name) {
            Ok(route) => route,
            Err(reason) => {
                inner.injection.end(name);
                self.abort_attachment(attachment).await;
                return Err(reason);
            }
        };
        let spec = attachment.add_to(inner.kit.spec(name, image, record.memory, &env, &route));
        let gate = Gate::new();
        match inner
            .kit
            .hook()
            .create(&inner.runtime, spec, &plan, &gate)
            .await
        {
            Ok(gated) => {
                attachment.commit();
                inner.live.lock().await.insert(
                    name.clone(),
                    Live {
                        route,
                        gate,
                        gated: Some(Arc::new(gated)),
                        ssh: None,
                        guest: Some(guest),
                        rewrite: Arc::default(),
                    },
                );
                Ok(())
            }
            Err(e) => {
                inner.injection.end(name);
                self.abort_attachment(attachment).await;
                route.shutdown().await;
                Err(boot_message(&e))
            }
        }
    }

    /// Makes this start's CA for `name`, registers what it decrypts and plans the guest's boot
    /// with the CA in its trust and the authors of the workspace's identities. A start that fails
    /// after this must call `Injection::end`.
    fn plan_guest(
        &self,
        name: &WorkspaceName,
        image: ImageConfig,
    ) -> Result<(puddle_boot::BootPlan, GuestEnv, GuestState), String> {
        let inner = &self.inner;
        let began = inner.injection.begin(name)?;
        let state = GuestState {
            image,
            ca: began.certificate,
            authors: authors(&began.git),
        };
        match inner.kit.plan(
            &state.image,
            &GuestInputs {
                ca: &state.ca,
                authors: &state.authors,
            },
        ) {
            Ok((plan, env)) => Ok((plan, env, state)),
            Err(reason) => {
                inner.injection.end(name);
                Err(reason)
            }
        }
    }

    /// A change to `name`'s Git settings (an identity attached, detached or edited, a coverage
    /// changed): what the running workspace decrypts follows at once, and its guest gets the
    /// authors of the new identities. A workspace that does not run reads the settings at its
    /// next start.
    pub(crate) async fn git_changed(&self, name: &WorkspaceName) {
        if let Some(git) = self.decrypt_changed(name) {
            self.rewrite_authors(name, &git).await;
        }
    }

    /// Recomputes what the running `name` decrypts from the database: the next connection sees
    /// the new set. The settings of a workspace that does not run, or that cannot be read, change
    /// nothing here.
    pub(crate) fn decrypt_changed(
        &self,
        name: &WorkspaceName,
    ) -> Option<puddle_store::WorkspaceGit> {
        let injection = &self.inner.injection;
        let git = match injection.git(name) {
            Ok(git) => git,
            Err(reason) => {
                tracing::warn!(workspace = %name, %reason, "what the workspace decrypts is not updated");
                return None;
            }
        };
        injection.refresh(name, &git).then_some(git)
    }

    /// Runs the boot plan again in the running guest when its authors differ from what the guest
    /// holds (the hook is idempotent: only the author files change).
    pub(crate) async fn rewrite_authors(
        &self,
        name: &WorkspaceName,
        git: &puddle_store::WorkspaceGit,
    ) {
        let inner = &self.inner;
        let wanted = authors(git);
        let rewrite = {
            let live = inner.live.lock().await;
            match live.get(name) {
                Some(entry) => Arc::clone(&entry.rewrite),
                None => return,
            }
        };
        let _one_at_a_time = rewrite.lock().await;
        let (gated, guest) = {
            let live = inner.live.lock().await;
            match live
                .get(name)
                .and_then(|e| Some((e.gated.clone()?, e.guest.clone()?)))
            {
                Some(running) => running,
                // Not booted yet (the start reads the settings itself, and `settle` looks again)
                // or stopped.
                None => return,
            }
        };
        if guest.authors == wanted {
            return;
        }
        let planned = inner.kit.plan(
            &guest.image,
            &GuestInputs {
                ca: &guest.ca,
                authors: &wanted,
            },
        );
        let plan = match planned {
            Ok((plan, _)) => plan,
            Err(reason) => {
                tracing::warn!(workspace = %name, %reason, "the commit authors in the workspace are not updated");
                return;
            }
        };
        match inner.kit.hook().run(gated.ungated(), &plan).await {
            Ok(_) => {
                if let Some(entry) = inner.live.lock().await.get_mut(name)
                    && let Some(state) = entry.guest.as_mut()
                {
                    state.authors = wanted;
                }
            }
            Err(failure) => {
                tracing::warn!(workspace = %name, %failure, "the commit authors in the workspace are not updated");
            }
        }
    }

    /// Looks at every running workspace again (after events were missed).
    pub(crate) async fn all_git_changed(&self) {
        for name in self.inner.injection.running_workspaces() {
            self.git_changed(&name).await;
        }
    }

    async fn abort_attachment(&self, attachment: puddle_workspace::Attachment<'_>) {
        if let Err(e) = attachment.abort(&self.inner.runtime).await {
            tracing::warn!(error = %e, "cleanup after a failed create failed");
        }
    }

    /// After a boot: puddle's directory and stale locks on the volume, the SSH endpoint, and the
    /// handle the lifecycle stops at exit.
    async fn settle(&self, record: &WorkspaceRecord) -> Result<(), String> {
        let inner = &self.inner;
        let (id, name) = (&record.id, &record.name);
        self.progress(name, WorkspaceStep::Syncing, None);
        let gated = {
            let live = inner.live.lock().await;
            live.get(name)
                .and_then(|l| l.gated.clone())
                .ok_or_else(|| format!("{name} is not running"))?
        };
        inner
            .workspaces
            .after_boot(gated.ungated(), id)
            .await
            .map_err(|e| e.to_string())?
            .map_or_else(
                |e| tracing::warn!(workspace = %id, error = %e, "stale git locks not cleared"),
                |report| tracing::debug!(workspace = %id, ?report, "after boot"),
            );
        let mount = Layout::new(id).map_err(|e| e.to_string())?.mount().clone();
        let handle = inner
            .runtime
            .get(&name.sandbox_name())
            .await
            .map_err(|e| e.to_string())?;
        if inner.lifecycle.manage(handle, vec![mount]).is_err() {
            return Err("puddle is shutting down".to_owned());
        }
        // Direct SSH is off unless the user allowed it: then there is no endpoint to connect to
        // and no ssh config entry, however the guest behaves.
        if self.direct_ssh_allowed(name) {
            self.open_ssh(name, gated).await;
        }
        // A change made while the guest booted found no guest to rewrite: look again.
        self.git_changed(name).await;
        Ok(())
    }

    /// The single gate for direct SSH: whether the user allowed it for `name`. Whatever opens an
    /// SSH way into a workspace (the endpoint, and any ssh config entry) must check this first.
    /// It is its override over the global default over off. Settings that cannot be read count as
    /// off, with the reason logged (and shown on the workspace by the API).
    #[must_use]
    pub fn direct_ssh_allowed(&self, name: &WorkspaceName) -> bool {
        match self.direct_ssh_setting(name) {
            Ok(on) => on,
            Err(reason) => {
                tracing::warn!(workspace = %name, %reason, "direct SSH stays off: the settings cannot be read");
                false
            }
        }
    }

    fn direct_ssh_setting(&self, name: &WorkspaceName) -> Result<bool, String> {
        let settings = self.inner.settings.as_ref();
        let global = crate::settings_read::global(settings)?;
        let own = crate::settings_read::workspace(settings, name)?;
        Ok(resolve(&global, Some(&own)).direct_ssh.value)
    }

    /// Opens the SSH endpoint of a running sandbox Failures are logged: the workspace
    /// runs without direct SSH.
    async fn open_ssh(&self, name: &WorkspaceName, gated: Arc<GatedSandbox<R::Sandbox>>) {
        let inner = &self.inner;
        let listener = match inner.kit.ipc().listen() {
            Ok(listener) => listener,
            Err(e) => {
                tracing::warn!(workspace = %name, error = %e, "no SSH endpoint");
                return;
            }
        };
        let ssh = match SshEndpoint::start(listener, gated) {
            Ok(ssh) => ssh,
            Err(e) => {
                tracing::warn!(workspace = %name, error = %e, "no SSH endpoint");
                return;
            }
        };
        let stale = {
            let mut live = inner.live.lock().await;
            if let Some(entry) = live.get_mut(name) {
                entry.ssh.replace(ssh)
            } else {
                drop(live);
                ssh.close().await;
                return;
            }
        };
        if let Some(stale) = stale {
            stale.close().await;
        }
    }

    /// Makes every running sandbox's SSH endpoint and ssh config entry match its direct SSH
    /// setting, at once and without a restart.
    async fn apply_direct_ssh(&self) {
        type Running<S> = (WorkspaceName, Option<Arc<GatedSandbox<S>>>, bool);
        let running: Vec<Running<R::Sandbox>> = {
            let live = self.inner.live.lock().await;
            live.iter()
                .filter_map(|(name, entry)| {
                    Some((
                        name.clone(),
                        Some(entry.gated.clone()?),
                        entry.ssh.is_some(),
                    ))
                })
                .collect()
        };
        for (name, gated, open) in running {
            let allowed = self.direct_ssh_allowed(&name);
            match (allowed, open, gated) {
                (true, false, Some(gated)) => self.open_ssh(&name, gated).await,
                (false, true, _) => {
                    let ssh = self
                        .inner
                        .live
                        .lock()
                        .await
                        .get_mut(&name)
                        .and_then(|entry| entry.ssh.take());
                    if let Some(ssh) = ssh {
                        ssh.close().await;
                    }
                }
                _ => {}
            }
        }
    }

    /// Stops what a failed boot or a finished stop leaves: the SSH endpoint and the lifecycle's
    /// handle. The route stays (the sandbox may start again); `drop_route` ends it too.
    async fn quiesce(&self, name: &WorkspaceName, drop_route: bool) {
        self.inner.lifecycle.release(&name.sandbox_name());
        // The CA belongs to one start: a stopped or failed sandbox decrypts nothing.
        self.inner.injection.end(name);
        let (ssh, route) = {
            let mut live = self.inner.live.lock().await;
            if drop_route {
                match live.remove(name) {
                    Some(entry) => (entry.ssh, Some(entry.route)),
                    None => (None, None),
                }
            } else {
                match live.get_mut(name) {
                    Some(entry) => {
                        entry.gated = None;
                        entry.guest = None;
                        (entry.ssh.take(), None)
                    }
                    None => (None, None),
                }
            }
        };
        if let Some(ssh) = ssh {
            ssh.close().await;
        }
        if let Some(route) = route {
            route.shutdown().await;
        }
    }

    /// Takes a sandbox that failed after it booted all the way down again.
    async fn undo_boot(&self, record: &WorkspaceRecord, remove: bool, created_volume: bool) {
        let inner = &self.inner;
        let name = &record.name;
        let gated = inner
            .live
            .lock()
            .await
            .get(name)
            .and_then(|l| l.gated.clone());
        if let Some(gated) = gated
            && let Err(e) = gated.stop().await
        {
            tracing::warn!(workspace = %name, error = %e, "stopping a failed workspace failed");
        }
        self.quiesce(name, remove).await;
        if remove {
            match inner.runtime.remove(&name.sandbox_name()).await {
                Ok(()) | Err(ComputeError::NotFound { .. }) => {}
                Err(e) => {
                    tracing::warn!(workspace = %name, error = %e, "removing a failed sandbox failed");
                }
            }
            inner.workspaces.sandbox_removed(&name.sandbox_name());
        }
        if created_volume
            && let Err(e) = inner.runtime.remove_volume(&record.id.volume_name()).await
        {
            tracing::warn!(workspace = %record.id, error = %e, "removing a new volume failed");
        }
    }

    async fn create_work(&self, record: WorkspaceRecord) -> Result<(), String> {
        let mut created_volume = false;
        self.boot_new(&record, &mut created_volume, true, true)
            .await?;
        if let Err(reason) = self.settle(&record).await {
            self.undo_boot(&record, true, created_volume).await;
            return Err(reason);
        }
        self.progress(
            &record.name,
            WorkspaceStep::Cloning,
            Some(record.repo_url.clone()),
        );
        let gated = self.gated(&record.name).await?;
        if let Err(e) = self
            .inner
            .workspaces
            .clone_checkout(gated.ungated(), &record.id, &record.repo_url, None)
            .await
        {
            self.undo_boot(&record, true, created_volume).await;
            return Err(e.to_string());
        }
        // Nobody has worked in it yet, so undoing it now loses nothing; keeping it would leave
        // a workspace the next start takes for an unfinished create.
        if let Err(e) = self.mark_created(&record.id) {
            self.undo_boot(&record, true, created_volume).await;
            return Err(format!(
                "{e}; the new workspace was removed again; {SAVE_HINT}"
            ));
        }
        Ok(())
    }

    async fn gated(&self, name: &WorkspaceName) -> Result<Arc<GatedSandbox<R::Sandbox>>, String> {
        self.inner
            .live
            .lock()
            .await
            .get(name)
            .and_then(|l| l.gated.clone())
            .ok_or_else(|| format!("{name} is not running"))
    }

    async fn start_work(&self, record: WorkspaceRecord) -> Result<(), String> {
        let inner = &self.inner;
        let name = &record.name;
        self.progress(name, WorkspaceStep::Starting, None);
        let exists = inner
            .runtime
            .list()
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .any(|s| s.name == name.as_str());
        let route_alive = inner.live.lock().await.contains_key(name);
        if exists && route_alive {
            self.restart_in_place(&record).await?;
        } else {
            if exists {
                inner
                    .runtime
                    .remove(&name.sandbox_name())
                    .await
                    .map_err(|e| e.to_string())?;
                inner.workspaces.sandbox_removed(&name.sandbox_name());
            }
            // A route left from an earlier boot belongs to a sandbox that no longer exists.
            self.quiesce(name, true).await;
            let mut created_volume = false;
            self.boot_new(&record, &mut created_volume, false, false)
                .await?;
        }
        if let Err(reason) = self.settle(&record).await {
            self.undo_boot(&record, false, false).await;
            return Err(reason);
        }
        Ok(())
    }

    async fn restart_in_place(&self, record: &WorkspaceRecord) -> Result<(), String> {
        let inner = &self.inner;
        let name = &record.name;
        let image = ImageRef::new(&record.image).map_err(|e| e.to_string())?;
        let config = self.image_config(&image).await?;
        let (plan, _, guest) = self.plan_guest(name, config)?;
        let started = self.start_planned(record, &plan).await;
        match started {
            Ok(gated) => {
                if let Some(live) = inner.live.lock().await.get_mut(name) {
                    live.gated = Some(Arc::new(gated));
                    live.guest = Some(guest);
                }
                Ok(())
            }
            Err(reason) => {
                inner.injection.end(name);
                Err(reason)
            }
        }
    }

    /// Starts the stopped sandbox of `record` through the boot hook with `plan`.
    async fn start_planned(
        &self,
        record: &WorkspaceRecord,
        plan: &puddle_boot::BootPlan,
    ) -> Result<GatedSandbox<R::Sandbox>, String> {
        let inner = &self.inner;
        let name = &record.name;
        let gate = inner
            .live
            .lock()
            .await
            .get(name)
            .map(|l| l.gate.clone())
            .ok_or_else(|| format!("{name} has no route"))?;
        // The memory setting applies at the next start (ADR 0006 and the memory setting).
        inner
            .runtime
            .set_memory(&name.sandbox_name(), record.memory)
            .await
            .map_err(|e| e.to_string())?;
        inner
            .kit
            .hook()
            .start(&inner.runtime, &name.sandbox_name(), plan, &gate)
            .await
            .map_err(|e| boot_message(&e))
    }

    async fn stop_work(&self, record: WorkspaceRecord) -> Result<(), String> {
        let name = &record.name;
        let gated = self.gated(name).await?;
        self.progress(name, WorkspaceStep::Reclaiming, None);
        // A failed trim only costs disk space; the VM still stops.
        if let Err(e) = self
            .inner
            .workspaces
            .trim(gated.ungated(), &record.id)
            .await
        {
            tracing::warn!(workspace = %record.id, error = %e, "trim before stop failed");
        }
        self.progress(name, WorkspaceStep::Stopping, None);
        gated.stop().await.map_err(|e| e.to_string())?;
        self.quiesce(name, false).await;
        Ok(())
    }

    async fn delete_work(
        &self,
        record: WorkspaceRecord,
        report: puddle_workspace::DeleteReport,
    ) -> Result<(), String> {
        let inner = &self.inner;
        self.progress(&record.name, WorkspaceStep::Checking, None);
        self.progress(&record.name, WorkspaceStep::Removing, None);
        inner
            .workspaces
            .delete(&inner.runtime, &record.id, &report.confirm())
            .await
            .map_err(|e| e.to_string())?;
        self.quiesce(&record.name, true).await;
        Ok(())
    }
}

/// Why a boot failed, for the user.
fn boot_message(e: &BootError) -> String {
    e.to_string()
}

impl<R: Runtime + Clone> WorkspaceService for HostWorkspaces<R> {
    fn list(&self) -> BoxFuture<'_, Result<Vec<WorkspaceRecord>, WorkspaceError>> {
        Box::pin(async move {
            Ok(self
                .state()
                .slots
                .values()
                .map(|s| s.record.clone())
                .collect())
        })
    }

    fn get<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            self.state()
                .slots
                .get(id)
                .map(|s| s.record.clone())
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
            record.memory = match new.memory {
                Some(memory) => memory,
                None => self.default_memory().map_err(|reason| {
                    WorkspaceError::Conflict(format!(
                        "{reason}, so puddle can't tell how much memory the new workspace gets; \
                         fix or reset the settings, or choose a memory size for it"
                    ))
                })?,
            };
            record.created_at = self.inner.clock.now_ms();
            record.disk_size_mib = u64::from(self.inner.workspaces.config().default_size.as_mib());
            record.disk_used_mib = None;
            record.busy = Some(Operation::Creating);
            // A volume of this name that the list does not name holds someone's work (reconcile
            // keeps it); a create would clone into the old checkout. Refuse before anything exists.
            let volume = id.volume_name();
            if self
                .inner
                .runtime
                .volume(&volume)
                .await
                .map_err(|e| {
                    WorkspaceError::Unavailable(format!(
                        "cannot check for an existing volume {volume}: {e}"
                    ))
                })?
                .is_some()
            {
                return Err(WorkspaceError::Conflict(format!(
                    "a volume named {volume} already exists, left from an earlier workspace, and may hold its work; \
                     {} was not created. Choose another name; puddle does not reuse or delete that volume",
                    new.name
                )));
            }
            {
                let mut state = self.state();
                if state.closed {
                    return Err(WorkspaceError::Unavailable(
                        "puddle is shutting down".to_owned(),
                    ));
                }
                if state.slots.contains_key(&id) {
                    return Err(WorkspaceError::Conflict(format!(
                        "a workspace named {} already exists",
                        new.name
                    )));
                }
                state.slots.insert(
                    id.clone(),
                    Slot {
                        record: record.clone(),
                        creating: true,
                        deleting: false,
                        volume_missing: false,
                    },
                );
                if let Err(e) = self.persist(&state) {
                    state.slots.remove(&id);
                    return Err(WorkspaceError::Unavailable(format!(
                        "{} was not created: {e}; {SAVE_HINT}",
                        new.name
                    )));
                }
            }
            self.status_event(&record);
            let this = self.clone();
            let work = record.clone();
            self.run(&record, Operation::Creating, async move {
                this.create_work(work).await
            })
            .await;
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
                |r| r.status = WorkspaceStatus::Starting,
            )?;
            self.status_event(&record);
            let this = self.clone();
            let work = record.clone();
            self.run(&record, Operation::Starting, async move {
                this.start_work(work).await
            })
            .await;
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
                    if r.status == WorkspaceStatus::Running {
                        Ok(())
                    } else {
                        Err(WorkspaceError::Conflict(format!(
                            "{} is not running ({})",
                            r.name, r.status
                        )))
                    }
                },
                |r| r.status = WorkspaceStatus::Draining,
            )?;
            self.status_event(&record);
            let this = self.clone();
            let work = record.clone();
            self.run(&record, Operation::Stopping, async move {
                this.stop_work(work).await
            })
            .await;
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
                    if matches!(
                        r.status,
                        WorkspaceStatus::Starting | WorkspaceStatus::Draining
                    ) {
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
            let this = self.clone();
            let work = record.clone();
            self.run(&record, Operation::Reclaiming, async move {
                this.progress(&work.name, WorkspaceStep::Reclaiming, None);
                this.inner
                    .workspaces
                    .reclaim_space(&this.inner.runtime, &work.id)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
            .await;
            Ok(record)
        })
    }

    fn delete_check<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<DeleteCheck, WorkspaceError>> {
        Box::pin(async move {
            if !self.state().slots.contains_key(id) {
                return Err(not_found(id));
            }
            let report = self
                .inner
                .workspaces
                .check_delete(&self.inner.runtime, id)
                .await
                .map_err(|e| workspace_error(&e))?;
            Ok(delete_check(&report))
        })
    }

    fn delete<'a>(
        &'a self,
        id: &'a WorkspaceId,
        fingerprint: Option<&'a str>,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        Box::pin(async move {
            let record = self.accept(
                id,
                Operation::Deleting,
                |r| {
                    if r.status.is_down() {
                        Ok(())
                    } else {
                        Err(WorkspaceError::Conflict(format!(
                            "{} is {}; stop it before deleting it",
                            r.name, r.status
                        )))
                    }
                },
                |_| {},
            )?;
            // The check runs before the call returns, so a refusal reaches the caller.
            let checked = self
                .inner
                .workspaces
                .check_delete(&self.inner.runtime, id)
                .await;
            let verdict = match checked {
                Err(e) => Err(workspace_error(&e)),
                Ok(report) => {
                    let fresh = delete_check(&report);
                    match fingerprint {
                        Some(seen) if seen == fresh.fingerprint => Ok(report),
                        Some(_) => Err(WorkspaceError::Conflict(format!(
                            "{} has changed since it was checked; check it again",
                            record.name
                        ))),
                        None if fresh.is_clean() => Ok(report),
                        None => Err(WorkspaceError::Conflict(format!(
                            "{} has work that is not saved on a remote; review it and confirm",
                            record.name
                        ))),
                    }
                }
            };
            // The entry leaves the saved list before the volume goes, so a delete that can't be
            // saved deletes nothing.
            let verdict = verdict.and_then(|report| {
                let mut state = self.state();
                if let Some(slot) = state.slots.get_mut(id) {
                    slot.deleting = true;
                }
                match self.persist(&state) {
                    Ok(()) => Ok(report),
                    Err(e) => Err(WorkspaceError::Unavailable(format!(
                        "{} was not deleted: {e}; {SAVE_HINT}",
                        record.name
                    ))),
                }
            });
            let report = match verdict {
                Ok(report) => report,
                Err(e) => {
                    if let Some(slot) = self.state().slots.get_mut(id) {
                        slot.record.busy = None;
                        slot.deleting = false;
                    }
                    return Err(e);
                }
            };
            let this = self.clone();
            let work = record.clone();
            self.run(&record, Operation::Deleting, async move {
                this.delete_work(work, report).await
            })
            .await;
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
            if record.busy.is_some() || record.status != WorkspaceStatus::Running {
                return Err(WorkspaceError::Conflict(format!(
                    "{} is not running; start it first",
                    record.name
                )));
            }
            match mode {
                AttachMode::Browser => Ok(Attached::not_opened(
                    "the editor in the browser is not available in this build",
                )),
                AttachMode::Desktop => match self.inner.launcher.open_desktop(&record).await {
                    Ok(()) => Ok(Attached::opened()),
                    Err(err) => Ok(Attached::not_opened(err.to_string())),
                },
            }
        })
    }

    fn settings_changed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.apply_direct_ssh().await })
    }
}

/// The workspace ids a book entry set names, for the inventory reconcile works from. An entry
/// whose create never finished is left out: reconcile removes its volume.
pub(crate) fn known_ids(stored: &[Stored]) -> BTreeSet<WorkspaceId> {
    stored
        .iter()
        .filter(|s| !s.creating)
        .filter_map(|s| WorkspaceId::new(&s.id).ok())
        .collect()
}
