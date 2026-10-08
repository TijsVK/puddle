// SPDX-License-Identifier: GPL-3.0-or-later
//! [`Workspaces`]: create or reuse a workspace's volume, attach it to one sandbox at a time,
//! trim it, and delete it only after the user confirmed what would be lost.

use std::time::Duration;

use puddle_compute::{
    ComputeError, DiskSize, Runtime, Sandbox, SandboxSpec, VolumeInfo, VolumeMount, VolumeSpec,
};
use puddle_types::{
    GuestPath, ImageRef, MemoryMib, SandboxName, VolumeName, WorkspaceId, WorkspaceStatus,
};
use tracing::{debug, info, warn};

use crate::check::{self, DeleteConfirmation, DeleteReport, Findings};
use crate::locks::{self, LockReport};
use crate::registry::{HoldKind, Holder, Registry};
use crate::trim::{self, TrimReport, tail};
use crate::{Layout, WorkspaceError, checkout_name};

/// Prefix of puddle's short-lived maintenance sandboxes: `m--<workspace id>` (fits the 63
/// characters of a sandbox name for the longest workspace id). Reconcile may remove
/// leftovers with this prefix.
pub const MAINTENANCE_PREFIX: &str = "m--";

/// Whether `name` is one of puddle's maintenance sandboxes.
#[must_use]
pub fn is_maintenance_name(name: &str) -> bool {
    name.strip_prefix(MAINTENANCE_PREFIX)
        .is_some_and(|id| WorkspaceId::new(id).is_ok())
}

/// The maintenance sandbox for workspace `id`.
fn maintenance_name(id: &WorkspaceId) -> Result<SandboxName, WorkspaceError> {
    SandboxName::new(&format!("{MAINTENANCE_PREFIX}{id}")).map_err(|e| WorkspaceError::Layout {
        reason: e.to_string(),
    })
}

/// How long a `git clone` may take.
const CLONE_TIMEOUT: Duration = Duration::from_secs(600);

/// Settings of the workspace lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfig {
    /// Size of a new workspace volume. Sparse on the host: it only takes what the guest writes
    /// (and keeps after a trim). msb can't resize a volume, so this is the most a workspace can
    /// ever hold.
    pub default_size: DiskSize,
    /// Image of the short-lived sandbox that checks or trims a workspace no running sandbox
    /// has. Needs `sh`, `git`, `awk`, `fstrim`.
    pub maintenance_image: ImageRef,
    /// Its memory.
    pub maintenance_memory: MemoryMib,
}

impl WorkspaceConfig {
    /// Default [`WorkspaceConfig::default_size`]: 32 GiB.
    pub const DEFAULT_SIZE: DiskSize = DiskSize::gib(32);
    /// Default [`WorkspaceConfig::maintenance_image`]: the stock devcontainer image.
    pub const DEFAULT_MAINTENANCE_IMAGE: &'static str =
        "mcr.microsoft.com/devcontainers/base:debian";
    /// Default [`WorkspaceConfig::maintenance_memory`], in MiB.
    pub const DEFAULT_MAINTENANCE_MEMORY_MIB: u32 = 1024;
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            default_size: Self::DEFAULT_SIZE,
            #[expect(
                clippy::expect_used,
                reason = "invariant: the constant is a valid image reference (unit-tested)"
            )]
            maintenance_image: ImageRef::new(Self::DEFAULT_MAINTENANCE_IMAGE)
                .expect("the default maintenance image is a valid reference"),
            maintenance_memory: MemoryMib::new(Self::DEFAULT_MAINTENANCE_MEMORY_MIB)
                .unwrap_or(MemoryMib::DEFAULT),
        }
    }
}

/// What [`Workspaces::stop`] did.
#[derive(Debug)]
pub struct StopReport {
    /// One entry per workspace the sandbox owns: its trim, or why it failed. A failed trim
    /// doesn't stop the stop.
    pub trims: Vec<Result<TrimReport, WorkspaceError>>,
}

/// What [`Workspaces::delete`] removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deleted {
    /// The workspace, whose volume is gone.
    pub workspace: WorkspaceId,
    /// The stopped sandbox that owned it, removed too.
    pub removed_sandbox: Option<SandboxName>,
}

/// The work a maintenance sandbox does.
enum Job {
    Check,
    Trim,
}

enum JobOutput {
    Check(Findings),
    Trim(TrimReport),
}

/// The workspace lifecycle (ADR 0006): one named disk volume `ws-<id>` per workspace, mounted at
/// `/workspaces/<id>` (see [`Layout`]), attached to one sandbox at a time.
///
/// Holder tracking is puddle's own (point 8): a sandbox created with a workspace holds it until
/// [`Workspaces::sandbox_removed`], running or stopped, and any other attach is refused with
/// [`WorkspaceError::InUse`] naming it, before msb is asked. A running holder the registry doesn't
/// know (another puddle, or one before a restart) is found through the runtime's own holder
/// lookup. The registry lives in memory; reconcile rebuilds it with [`Workspaces::adopt`].
///
/// Generic over the runtime: every method takes the [`Runtime`] it works on.
#[derive(Debug, Default)]
pub struct Workspaces {
    config: WorkspaceConfig,
    registry: Registry,
}

impl Workspaces {
    /// A lifecycle with `config` and nothing attached.
    #[must_use]
    pub fn new(config: WorkspaceConfig) -> Self {
        Self {
            config,
            registry: Registry::default(),
        }
    }

    /// Its settings.
    #[must_use]
    pub fn config(&self) -> &WorkspaceConfig {
        &self.config
    }

    /// Who holds workspace `id`, as far as puddle tracks it.
    #[must_use]
    pub fn holder(&self, id: &WorkspaceId) -> Option<Holder> {
        self.registry.holder(id)
    }

    /// Records that `sandbox` (which exists already) was created with workspace `id`: for
    /// reconcile after a restart.
    pub fn adopt(&self, id: &WorkspaceId, sandbox: &SandboxName) {
        self.registry.attach(id, sandbox);
    }

    /// Releases every workspace `sandbox` held; call it after removing the sandbox.
    pub fn sandbox_removed(&self, sandbox: &SandboxName) {
        for id in self.registry.owned_by(sandbox) {
            self.registry.release(&id, sandbox);
        }
    }

    /// Gets workspace `id` ready to attach to the sandbox about to be created as `sandbox`:
    /// checks no other sandbox holds it, reserves it, and creates its volume (`size`, or
    /// [`WorkspaceConfig::default_size`]) if it has none yet. An existing volume keeps its size.
    ///
    /// Add [`Attachment::mount`] to the spec, create the sandbox (with [`Runtime::create`] or
    /// the boot hook), then [`Attachment::commit`] on success or [`Attachment::abort`] on
    /// failure. [`Workspaces::create`] does all of that for a plain create.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::InUse`] naming the holder; [`WorkspaceError::Runtime`].
    pub async fn prepare<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        sandbox: &SandboxName,
        size: Option<DiskSize>,
    ) -> Result<Attachment<'_>, WorkspaceError> {
        self.reserve(rt, id, sandbox).await?;
        let mut attachment = Attachment {
            workspaces: self,
            id: id.clone(),
            sandbox: sandbox.clone(),
            mount: None,
            created_volume: false,
            before: Before {
                record: true,
                stale_dir: true,
            },
            open: true,
        };
        // On error the attachment drops here, which releases the reservation.
        let volume = id.volume_name();
        let existing = rt
            .volume(&volume)
            .await
            .map_err(|e| WorkspaceError::runtime("look up the volume", id, e))?;
        if let Some(holder) = existing.as_ref().and_then(|v| v.holder.as_ref())
            && holder != sandbox.as_str()
        {
            return Err(WorkspaceError::InUse {
                workspace: id.to_string(),
                holder: holder.clone(),
            });
        }
        let sandboxes = rt
            .list()
            .await
            .map_err(|e| WorkspaceError::runtime("list sandboxes", id, e))?;
        attachment.before.record = sandboxes.iter().any(|s| s.name == sandbox.as_str());
        let stale = rt
            .stale_dirs()
            .await
            .map_err(|e| WorkspaceError::runtime("list stale directories", id, e))?;
        attachment.before.stale_dir = stale.iter().any(|s| s == sandbox.as_str());
        let info = if let Some(info) = existing {
            if size.is_some_and(|s| s != info.size) {
                info!(workspace = %id, size = %info.size, "workspace volume exists; keeping its size");
            }
            info
        } else {
            let size = size.unwrap_or(self.config.default_size);
            let info = rt
                .create_volume(VolumeSpec {
                    name: volume.clone(),
                    size,
                })
                .await
                .map_err(|e| WorkspaceError::runtime("create the volume", id, e))?;
            attachment.created_volume = true;
            info!(workspace = %id, %size, "workspace volume created");
            info
        };
        attachment.mount = Some(mount_for(id, &volume, &info)?);
        Ok(attachment)
    }

    /// Reserves `id` for `sandbox`, dropping a registry holder that no longer exists.
    async fn reserve<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        sandbox: &SandboxName,
    ) -> Result<(), WorkspaceError> {
        let in_use = |h: Holder| WorkspaceError::InUse {
            workspace: id.to_string(),
            holder: h.sandbox.to_string(),
        };
        match self.registry.reserve(id, sandbox) {
            Ok(()) => Ok(()),
            Err(h) if h.kind == HoldKind::Attached => {
                let exists = rt
                    .list()
                    .await
                    .map_err(|e| WorkspaceError::runtime("list sandboxes", id, e))?
                    .iter()
                    .any(|s| s.name == h.sandbox.as_str());
                if exists {
                    return Err(in_use(h));
                }
                debug!(workspace = %id, holder = %h.sandbox, "holder is gone; releasing it");
                self.registry.release(id, &h.sandbox);
                self.registry.reserve(id, sandbox).map_err(in_use)
            }
            Err(h) => Err(in_use(h)),
        }
    }

    /// Creates sandbox `spec` with workspace `id` attached ([`Workspaces::prepare`] +
    /// [`Runtime::create`]). On failure nothing is left: no sandbox record, no stale directory,
    /// and no volume if this call created it.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::InUse`]; [`WorkspaceError::Runtime`] (the create's error; a cleanup
    /// failure after it is logged).
    pub async fn create<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        spec: SandboxSpec,
        size: Option<DiskSize>,
    ) -> Result<R::Sandbox, WorkspaceError> {
        let attachment = self.prepare(rt, id, &spec.name, size).await?;
        let spec = attachment.add_to(spec);
        match rt.create(spec).await {
            Ok(sandbox) => {
                attachment.commit();
                Ok(sandbox)
            }
            Err(e) => {
                if let Err(cleanup) = attachment.abort(rt).await {
                    warn!(workspace = %id, error = %cleanup, "cleanup after a failed create failed");
                }
                Err(WorkspaceError::runtime("create the sandbox", id, e))
            }
        }
    }

    /// Creates puddle's directory on the volume (see [`Layout`]); run after every boot. Idempotent.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Runtime`]; [`WorkspaceError::Layout`] when `mkdir` fails.
    pub async fn prepare_layout<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
    ) -> Result<(), WorkspaceError> {
        let request = Layout::new(id)?.prepare_request()?;
        let out = sandbox
            .exec(request)
            .await
            .map_err(|e| WorkspaceError::runtime("prepare the layout", id, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(WorkspaceError::Layout {
                reason: format!("mkdir failed: {}", out.stderr_text().trim()),
            })
        }
    }

    /// Clones `url` into a checkout directory of workspace `id` (named by [`checkout_name`])
    /// and then runs `sync`, so the clone is on the volume before this returns: a VMM kill
    /// within seconds of a clone could otherwise lose the whole repository (directory
    /// entries aren't covered by `core.fsync=committed` until the first fsync).
    /// Runs as `user` (the sandbox's default user if `None`), with the sandbox's own
    /// environment (the proxy settings). Returns the checkout's path.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Clone`] when `git clone` fails (nothing is synced);
    /// [`WorkspaceError::Sync`] when the sync fails (the clone exists but isn't known to be on
    /// disk); [`WorkspaceError::Layout`]; [`WorkspaceError::Runtime`].
    pub async fn clone_checkout<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
        url: &str,
        user: Option<&str>,
    ) -> Result<GuestPath, WorkspaceError> {
        let layout = Layout::new(id)?;
        let checkout = layout.checkout(&checkout_name(url))?;
        let mut request = layout.clone_request(url)?.with_timeout(CLONE_TIMEOUT);
        if let Some(user) = user {
            request = request.as_user(user);
        }
        let out = sandbox
            .exec(request)
            .await
            .map_err(|e| WorkspaceError::runtime("clone", id, e))?;
        if !out.status.success() {
            return Err(WorkspaceError::Clone {
                workspace: id.to_string(),
                reason: format!(
                    "git exited {}: {}",
                    out.status.code,
                    tail(&out.stderr_text())
                ),
            });
        }
        self.sync(sandbox, id).await?;
        info!(workspace = %id, "checkout cloned and synced");
        Ok(checkout)
    }

    /// Runs `sync` in `sandbox` (see [`Layout::sync_request`]); call it after anything that
    /// must survive a hard kill at once (a `git init`, a clone).
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Sync`]; [`WorkspaceError::Runtime`].
    pub async fn sync<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
    ) -> Result<(), WorkspaceError> {
        let out = sandbox
            .exec(Layout::sync_request())
            .await
            .map_err(|e| WorkspaceError::runtime("sync", id, e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(WorkspaceError::Sync {
                workspace: id.to_string(),
                reason: format!(
                    "sync exited {}: {}",
                    out.status.code,
                    tail(&out.stderr_text())
                ),
            })
        }
    }

    /// Removes the stale git lock files a crash left in workspace `id`'s checkouts, so the user
    /// doesn't meet "Another git process seems to be running". Run it right after a boot (see
    /// [`Workspaces::after_boot`]): nothing removed while a `git` process runs in the guest
    /// ([`LockReport::skipped_busy`]).
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Locks`] when the script fails or its output can't be read;
    /// [`WorkspaceError::Runtime`].
    pub async fn clear_stale_locks<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
    ) -> Result<LockReport, WorkspaceError> {
        let report = locks::run(sandbox, id).await?;
        if report.skipped_busy {
            info!(workspace = %id, "git is running; stale lock files left alone");
        } else if report.removed_count() > 0 {
            info!(workspace = %id, removed = report.removed_count(), "stale git locks cleared");
        }
        Ok(report)
    }

    /// What every boot of a sandbox with workspace `id` runs: [`Workspaces::prepare_layout`],
    /// then [`Workspaces::clear_stale_locks`]. A lock failure is logged and doesn't fail the
    /// boot; it is in the report.
    ///
    /// # Errors
    ///
    /// The errors of [`Workspaces::prepare_layout`].
    pub async fn after_boot<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
    ) -> Result<Result<LockReport, WorkspaceError>, WorkspaceError> {
        self.prepare_layout(sandbox, id).await?;
        let locks = self.clear_stale_locks(sandbox, id).await;
        if let Err(e) = &locks {
            warn!(workspace = %id, error = %e, "clearing stale git locks failed");
        }
        Ok(locks)
    }

    /// Trims workspace `id` in `sandbox`, which must be running and have it mounted.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Trim`]; [`WorkspaceError::Runtime`].
    pub async fn trim<S: Sandbox>(
        &self,
        sandbox: &S,
        id: &WorkspaceId,
    ) -> Result<TrimReport, WorkspaceError> {
        let report = trim::run(sandbox, id).await?;
        info!(workspace = %id, trimmed = ?report.trimmed_bytes, "workspace trimmed");
        Ok(report)
    }

    /// Stops `sandbox` the puddle way: `fstrim` on every workspace it owns first (ADR 0006
    /// point 7), then [`Sandbox::stop`]. A failed trim is logged and reported, and the stop goes
    /// ahead. A sandbox that is already down is just stopped (a no-op).
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Runtime`] when the stop fails.
    pub async fn stop<S: Sandbox>(&self, sandbox: &S) -> Result<StopReport, WorkspaceError> {
        let name = sandbox.name();
        let mut trims = Vec::new();
        let running = matches!(sandbox.status().await, Ok(WorkspaceStatus::Running));
        if running {
            for id in self.registry.owned_by(name) {
                let result = self.trim(sandbox, &id).await;
                if let Err(e) = &result {
                    warn!(sandbox = %name, workspace = %id, error = %e, "trim before stop failed");
                }
                trims.push(result);
            }
        }
        sandbox
            .stop()
            .await
            .map_err(|e| WorkspaceError::runtime("stop the sandbox", name, e))?;
        Ok(StopReport { trims })
    }

    /// "Reclaim space" for workspace `id`: trims it in its running holder, or in a short-lived
    /// maintenance sandbox when no sandbox runs with it.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::NotFound`]; [`WorkspaceError::InUse`] while a create or another
    /// maintenance run has it; [`WorkspaceError::Trim`]; [`WorkspaceError::Runtime`].
    pub async fn reclaim_space<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
    ) -> Result<TrimReport, WorkspaceError> {
        let info = self.volume(rt, id).await?;
        if let Some(holder) = self.running_holder(id, &info)? {
            let sandbox = rt
                .get(&holder)
                .await
                .map_err(|e| WorkspaceError::runtime("connect to the holder", id, e))?;
            return self.trim(&sandbox, id).await;
        }
        match self.maintenance(rt, id, &info, Job::Trim).await? {
            JobOutput::Trim(report) => Ok(report),
            JobOutput::Check(_) => unreachable_job(id),
        }
    }

    /// Step one of a delete: lists what deleting workspace `id` would lose (uncommitted changes,
    /// unpushed commits, stashes, data outside any checkout), checked in its running holder or
    /// in a short-lived maintenance sandbox. Show it, and pass [`DeleteReport::confirm`] to
    /// [`Workspaces::delete`] if the user agrees.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::NotFound`]; [`WorkspaceError::Check`] when the check can't run or its
    /// output can't be read (fail closed); [`WorkspaceError::InUse`] while a create or another
    /// maintenance run has it; [`WorkspaceError::Runtime`].
    pub async fn check_delete<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
    ) -> Result<DeleteReport, WorkspaceError> {
        let info = self.volume(rt, id).await?;
        let removes_sandbox = self.existing_owner(rt, id).await?;
        if let Some(holder) = self.running_holder(id, &info)? {
            let sandbox = rt
                .get(&holder)
                .await
                .map_err(|e| WorkspaceError::runtime("connect to the holder", id, e))?;
            let findings = check::run(&sandbox, id).await?;
            return Ok(DeleteReport {
                workspace: id.clone(),
                findings,
                checked_in: holder,
                removes_sandbox,
            });
        }
        let checked_in = maintenance_name(id)?;
        match self.maintenance(rt, id, &info, Job::Check).await? {
            JobOutput::Check(findings) => Ok(DeleteReport {
                workspace: id.clone(),
                findings,
                checked_in,
                removes_sandbox,
            }),
            JobOutput::Trim(_) => unreachable_job(id),
        }
    }

    /// Step two: deletes workspace `id` (its volume and the stopped sandbox that owns it), after
    /// checking again in a short-lived maintenance sandbox that nothing changed since `confirmed`.
    ///
    /// # Errors
    ///
    /// - [`WorkspaceError::WrongConfirmation`]: `confirmed` is for another workspace;
    /// - [`WorkspaceError::InUse`]: a sandbox runs with it (stop it first), or a create or
    ///   maintenance run has it;
    /// - [`WorkspaceError::Changed`]: the check finds something else now (nothing deleted);
    /// - [`WorkspaceError::NotFound`], [`WorkspaceError::Check`], [`WorkspaceError::Runtime`].
    pub async fn delete<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        confirmed: &DeleteConfirmation,
    ) -> Result<Deleted, WorkspaceError> {
        if confirmed.workspace != *id {
            return Err(WorkspaceError::WrongConfirmation {
                workspace: id.to_string(),
                confirmed: confirmed.workspace.to_string(),
            });
        }
        let info = self.volume(rt, id).await?;
        if let Some(holder) = self.running_holder(id, &info)? {
            return Err(WorkspaceError::InUse {
                workspace: id.to_string(),
                holder: holder.to_string(),
            });
        }
        let owner = self.existing_owner(rt, id).await?;
        let checked_in = maintenance_name(id)?;
        self.borrow(id, &checked_in)?;
        let result = self
            .delete_borrowed(rt, id, &info, confirmed, owner, checked_in)
            .await;
        self.registry.give_back(id);
        if result.is_ok() {
            self.registry.forget(id);
        }
        result
    }

    async fn delete_borrowed<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        info: &VolumeInfo,
        confirmed: &DeleteConfirmation,
        owner: Option<SandboxName>,
        checked_in: SandboxName,
    ) -> Result<Deleted, WorkspaceError> {
        let findings = match self.run_maintenance(rt, id, info, Job::Check).await? {
            JobOutput::Check(f) => f,
            JobOutput::Trim(_) => return unreachable_job(id),
        };
        if findings != confirmed.findings || owner != confirmed.removes_sandbox {
            return Err(WorkspaceError::Changed {
                workspace: id.to_string(),
                report: Box::new(DeleteReport {
                    workspace: id.clone(),
                    findings,
                    checked_in,
                    removes_sandbox: owner,
                }),
            });
        }
        if let Some(sandbox) = &owner {
            rt.remove(sandbox)
                .await
                .map_err(|e| WorkspaceError::runtime("remove the owning sandbox", id, e))?;
            self.sandbox_removed(sandbox);
        }
        let volume = id.volume_name();
        rt.remove_volume(&volume)
            .await
            .map_err(|e| WorkspaceError::runtime("remove the volume", id, e))?;
        info!(workspace = %id, removed_sandbox = ?owner.as_ref().map(SandboxName::as_str), "workspace deleted");
        Ok(Deleted {
            workspace: id.clone(),
            removed_sandbox: owner,
        })
    }

    /// The volume of `id`, or [`WorkspaceError::NotFound`].
    async fn volume<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
    ) -> Result<VolumeInfo, WorkspaceError> {
        rt.volume(&id.volume_name())
            .await
            .map_err(|e| WorkspaceError::runtime("look up the volume", id, e))?
            .ok_or_else(|| WorkspaceError::NotFound {
                workspace: id.to_string(),
            })
    }

    /// The running sandbox that has the volume (the runtime knows), or `None`. A create or a
    /// maintenance run in progress is [`WorkspaceError::InUse`].
    fn running_holder(
        &self,
        id: &WorkspaceId,
        info: &VolumeInfo,
    ) -> Result<Option<SandboxName>, WorkspaceError> {
        if let Some(h) = self
            .registry
            .holder(id)
            .filter(|h| h.kind != HoldKind::Attached)
        {
            return Err(WorkspaceError::InUse {
                workspace: id.to_string(),
                holder: h.sandbox.to_string(),
            });
        }
        match &info.holder {
            None => Ok(None),
            Some(name) => SandboxName::new(name).map(Some).map_err(|_| {
                // Not a name puddle could have made: someone else's sandbox has it.
                WorkspaceError::InUse {
                    workspace: id.to_string(),
                    holder: name.clone(),
                }
            }),
        }
    }

    /// The sandbox that owns `id`, if it still exists.
    async fn existing_owner<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
    ) -> Result<Option<SandboxName>, WorkspaceError> {
        let Some(owner) = self
            .registry
            .owner(id)
            .filter(|h| h.kind == HoldKind::Attached)
        else {
            return Ok(None);
        };
        let exists = rt
            .list()
            .await
            .map_err(|e| WorkspaceError::runtime("list sandboxes", id, e))?
            .iter()
            .any(|s| s.name == owner.sandbox.as_str());
        Ok(exists.then_some(owner.sandbox))
    }

    fn borrow(&self, id: &WorkspaceId, sandbox: &SandboxName) -> Result<(), WorkspaceError> {
        self.registry
            .borrow(id, sandbox)
            .map_err(|h| WorkspaceError::InUse {
                workspace: id.to_string(),
                holder: h.sandbox.to_string(),
            })
    }

    /// Runs `job` in a maintenance sandbox, holding the registry loan for its duration.
    async fn maintenance<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        info: &VolumeInfo,
        job: Job,
    ) -> Result<JobOutput, WorkspaceError> {
        let name = maintenance_name(id)?;
        self.borrow(id, &name)?;
        let result = self.run_maintenance(rt, id, info, job).await;
        self.registry.give_back(id);
        result
    }

    /// Creates the maintenance sandbox with the workspace, runs `job`, and stops and removes the
    /// sandbox again, whatever the job's outcome.
    async fn run_maintenance<R: Runtime>(
        &self,
        rt: &R,
        id: &WorkspaceId,
        info: &VolumeInfo,
        job: Job,
    ) -> Result<JobOutput, WorkspaceError> {
        let name = maintenance_name(id)?;
        clear_leftover(rt, id, &name).await?;
        let volume = id.volume_name();
        let spec = SandboxSpec::new(name.clone(), self.config.maintenance_image.clone())
            .with_memory(self.config.maintenance_memory)
            .with_cpus(1)
            .with_volume(mount_for(id, &volume, info)?);
        debug!(workspace = %id, sandbox = %name, "starting a maintenance sandbox");
        let sandbox = match rt.create(spec).await {
            Ok(s) => s,
            Err(e) => {
                if let Err(cleanup) = cleanup_failed_create(rt, &name, false, false).await {
                    warn!(workspace = %id, error = %cleanup, "cleanup after a failed maintenance create failed");
                }
                return Err(WorkspaceError::runtime(
                    "create the maintenance sandbox",
                    id,
                    e,
                ));
            }
        };
        let output = match job {
            Job::Check => check::run(&sandbox, id).await.map(JobOutput::Check),
            Job::Trim => self.trim(&sandbox, id).await.map(JobOutput::Trim),
        };
        let stopped = sandbox.stop().await;
        drop(sandbox);
        let removed = rt.remove(&name).await;
        let output = output?;
        stopped.map_err(|e| WorkspaceError::runtime("stop the maintenance sandbox", id, e))?;
        removed.map_err(|e| WorkspaceError::runtime("remove the maintenance sandbox", id, e))?;
        Ok(output)
    }
}

/// The mount of `volume` at the workspace's mount point, always with kind disk and the size
/// (ADR 0006 point 9).
fn mount_for(
    id: &WorkspaceId,
    volume: &VolumeName,
    info: &VolumeInfo,
) -> Result<VolumeMount, WorkspaceError> {
    let layout = Layout::new(id)?;
    let mount = VolumeMount::named(volume.clone(), layout.mount().clone());
    Ok(if info.size.as_mib() > 0 {
        mount.ensure_size(info.size)
    } else {
        mount
    })
}

/// Removes a maintenance sandbox an earlier run left behind (down), and a stale directory with
/// its name. A running one is a maintenance run in progress elsewhere: [`WorkspaceError::InUse`].
async fn clear_leftover<R: Runtime>(
    rt: &R,
    id: &WorkspaceId,
    name: &SandboxName,
) -> Result<(), WorkspaceError> {
    let err = |op, e| WorkspaceError::runtime(op, id, e);
    let sandboxes = rt.list().await.map_err(|e| err("list sandboxes", e))?;
    if let Some(left) = sandboxes.iter().find(|s| s.name == name.as_str()) {
        if !left.status.is_down() {
            return Err(WorkspaceError::InUse {
                workspace: id.to_string(),
                holder: name.to_string(),
            });
        }
        rt.remove(name)
            .await
            .map_err(|e| err("remove a leftover maintenance sandbox", e))?;
    }
    if rt
        .stale_dirs()
        .await
        .map_err(|e| err("list stale directories", e))?
        .iter()
        .any(|s| s == name.as_str())
    {
        rt.remove_stale_dir(name)
            .await
            .map_err(|e| err("remove a stale directory", e))?;
    }
    Ok(())
}

/// Removes what a failed create of `name` left behind: a down sandbox record and a stale
/// directory, unless they were there before. Tries both; returns the first failure.
async fn cleanup_failed_create<R: Runtime>(
    rt: &R,
    name: &SandboxName,
    had_record: bool,
    had_stale_dir: bool,
) -> Result<(), ComputeError> {
    let mut first = Ok(());
    if !had_record {
        match rt.list().await {
            Ok(list) => {
                if let Some(left) = list.iter().find(|s| s.name == name.as_str()) {
                    if left.status.is_down() {
                        debug!(sandbox = %name, "removing the record a failed create left");
                        first = first.and(rt.remove(name).await);
                    } else {
                        warn!(sandbox = %name, status = %left.status, "a failed create left a sandbox that is not down; leaving it");
                    }
                }
            }
            Err(e) => first = first.and(Err(e)),
        }
    }
    if !had_stale_dir {
        match rt.stale_dirs().await {
            Ok(dirs) if dirs.iter().any(|d| d == name.as_str()) => {
                debug!(sandbox = %name, "removing the directory a failed create left");
                first = first.and(rt.remove_stale_dir(name).await);
            }
            Ok(_) => {}
            Err(e) => first = first.and(Err(e)),
        }
    }
    first
}

fn unreachable_job<T>(id: &WorkspaceId) -> Result<T, WorkspaceError> {
    Err(WorkspaceError::Check {
        workspace: id.to_string(),
        reason: "internal error: the maintenance job returned the wrong output".into(),
    })
}

/// A workspace reserved for a sandbox that is being created (from [`Workspaces::prepare`]).
/// Finish it with [`Attachment::commit`] or [`Attachment::abort`]; dropping it unfinished only
/// releases the reservation (and logs a warning), leaving the runtime as it is.
#[derive(Debug)]
#[must_use = "commit or abort the attachment"]
pub struct Attachment<'w> {
    workspaces: &'w Workspaces,
    id: WorkspaceId,
    sandbox: SandboxName,
    mount: Option<VolumeMount>,
    created_volume: bool,
    before: Before,
    open: bool,
}

/// What existed under the sandbox's name before the create, so an abort leaves it alone.
#[derive(Debug, Clone, Copy)]
struct Before {
    record: bool,
    stale_dir: bool,
}

impl Attachment<'_> {
    /// The workspace.
    #[must_use]
    pub fn workspace(&self) -> &WorkspaceId {
        &self.id
    }

    /// The volume mount to add to the sandbox's spec.
    ///
    /// # Panics
    ///
    /// Never: an [`Attachment`] only leaves [`Workspaces::prepare`] with its mount set.
    #[must_use]
    pub fn mount(&self) -> &VolumeMount {
        #[expect(
            clippy::expect_used,
            reason = "invariant: prepare sets the mount before returning the attachment"
        )]
        self.mount
            .as_ref()
            .expect("prepare sets the mount before returning")
    }

    /// Whether [`Workspaces::prepare`] created the volume (an abort deletes it again).
    #[must_use]
    pub fn created_volume(&self) -> bool {
        self.created_volume
    }

    /// `spec` with the workspace's volume mount added.
    #[must_use]
    pub fn add_to(&self, spec: SandboxSpec) -> SandboxSpec {
        spec.with_volume(self.mount().clone())
    }

    /// The sandbox was created: it holds the workspace from now on.
    pub fn commit(mut self) {
        self.open = false;
        self.workspaces.registry.attach(&self.id, &self.sandbox);
        info!(workspace = %self.id, sandbox = %self.sandbox, "workspace attached");
    }

    /// The create failed: removes what it left (a down sandbox record, a stale directory,
    /// unless they were there before) and the volume if [`Workspaces::prepare`] created it, then
    /// releases the reservation.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Runtime`] with the first cleanup step that failed (the others still ran).
    pub async fn abort<R: Runtime>(mut self, rt: &R) -> Result<(), WorkspaceError> {
        self.open = false;
        let mut result =
            cleanup_failed_create(rt, &self.sandbox, self.before.record, self.before.stale_dir)
                .await
                .map_err(|e| {
                    WorkspaceError::runtime("clean up after a failed create", &self.id, e)
                });
        if self.created_volume {
            match rt.remove_volume(&self.id.volume_name()).await {
                Ok(()) | Err(ComputeError::VolumeNotFound { .. }) => {}
                Err(e) => {
                    result = result.and(Err(WorkspaceError::runtime(
                        "remove the new volume",
                        &self.id,
                        e,
                    )));
                }
            }
        }
        self.workspaces.registry.release(&self.id, &self.sandbox);
        result
    }
}

impl Drop for Attachment<'_> {
    fn drop(&mut self) {
        if self.open {
            if self.mount.is_some() {
                warn!(workspace = %self.id, sandbox = %self.sandbox, "attachment dropped without commit or abort");
            }
            self.workspaces.registry.release(&self.id, &self.sandbox);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let c = WorkspaceConfig::default();
        assert_eq!(c.default_size, DiskSize::gib(32));
        assert_eq!(
            c.maintenance_image.as_str(),
            WorkspaceConfig::DEFAULT_MAINTENANCE_IMAGE
        );
        assert_eq!(c.maintenance_memory.get(), 1024);
    }

    #[test]
    fn maintenance_names_fit_every_workspace_id() {
        let longest = WorkspaceId::new(&"w".repeat(WorkspaceId::MAX_LEN)).unwrap();
        let name = maintenance_name(&longest).unwrap();
        assert!(is_maintenance_name(name.as_str()));
        assert!(is_maintenance_name("m--acme"));
        assert!(!is_maintenance_name("acme"));
        assert!(!is_maintenance_name("m--"));
        assert!(!is_maintenance_name("m---a"));
    }
}
