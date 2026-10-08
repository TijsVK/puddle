// SPDX-License-Identifier: GPL-3.0-or-later
//! Reconcile at start: clean up after a puddle that died without its shutdown.
//!
//! puddle-owned means: a sandbox the runtime lists with [`SandboxInfo::puddle_owned`] (msb: the
//! owner label) **and** a valid [`SandboxName`]; a stale directory with a valid [`SandboxName`]
//! (it has no record that could carry the label; puddle's msb home is private); a volume
//! named `ws-<workspace id>`. Everything else is foreign and only reported.
//!
//! A workspace volume holds work that may exist nowhere else, so reconcile removes one only when
//! the inventory names it as a create that never finished. A `ws-*` volume the inventory doesn't
//! know is kept and reported ([`ReconcileReport::unknown_volumes`]): a missing or outdated list
//! of workspaces must never cost a workspace its data (principle 7, "your work is never lost by
//! accident").
//!
//! A puddle-owned maintenance sandbox (`m--<workspace id>`) only lives while puddle checks
//! or trims a workspace, so one found at start is always a leftover: it is stopped and removed
//! even if the inventory lists it. After reconcile, [`adopt_workspaces`] rebuilds the workspace
//! holder registry (it lives in memory) from the inventory.

use std::collections::{BTreeMap, BTreeSet};

use puddle_compute::{ComputeError, Runtime, SandboxInfo};
use puddle_types::{SandboxName, VolumeName, WorkspaceId, WorkspaceStatus};
use puddle_workspace::{Workspaces, is_maintenance_name};

use crate::shutdown::{ShutdownConfig, StopOutcome, trim_and_stop};

/// What puddle's own records say exists: the sandboxes and workspaces it knows. A puddle-owned
/// sandbox record the runtime has and this doesn't list is stale and removed. Workspace volumes
/// are different: only those of [`Inventory::interrupted`] are removed; any other volume this
/// doesn't list is kept and reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Sandboxes puddle has a record of; their runtime records are kept.
    pub sandboxes: BTreeSet<SandboxName>,
    /// Workspaces puddle has a record of; their `ws-*` volumes are kept.
    pub workspaces: BTreeSet<WorkspaceId>,
    /// The sandbox each known workspace is attached to, from puddle's store; read by
    /// [`adopt_workspaces`].
    pub attached: BTreeMap<WorkspaceId, SandboxName>,
    /// Workspaces whose create started and never finished (puddle stopped in the middle of
    /// it). Their volumes hold only what that create made, nothing the user worked on, and are
    /// removed. A workspace in [`Inventory::workspaces`] too counts as known and is kept.
    pub interrupted: BTreeSet<WorkspaceId>,
}

/// One reconcile step that failed; the others still ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The sandbox, directory or volume.
    pub item: String,
    /// What was being done (`stop`, `remove`, `remove stale dir`, `remove volume`).
    pub action: &'static str,
    /// Why it failed.
    pub error: String,
}

/// What [`reconcile`] did. Every list is in name order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Running sandboxes a previous puddle left behind, now trimmed and stopped.
    pub stopped: Vec<SandboxName>,
    /// Records of sandboxes puddle no longer knows, removed.
    pub removed: Vec<SandboxName>,
    /// Known sandboxes found `Crashed`: kept, and reported so the UI can say so.
    pub crashed: Vec<SandboxName>,
    /// Stale directories (a failed create's leftovers), removed.
    pub stale_dirs_removed: Vec<SandboxName>,
    /// Volumes of creates that never finished ([`Inventory::interrupted`]), removed.
    pub volumes_removed: Vec<VolumeName>,
    /// `ws-*` volumes no known workspace claims, kept: they may hold work, and the list that
    /// lacks them may be the thing that is wrong. The caller reports them (the host logs them).
    pub unknown_volumes: Vec<VolumeName>,
    /// Foreign sandboxes, directories and volumes, left untouched.
    pub foreign: Vec<String>,
    /// Steps that failed.
    pub failures: Vec<Failure>,
}

/// Brings the runtime in line with `inventory` after a puddle that may have died: stops every
/// puddle-owned sandbox still running (`fstrim` first), removes puddle-owned records and stale
/// directories puddle doesn't know, then removes the `ws-*` volumes of creates that never
/// finished (only when no running sandbox holds them). Any other `ws-*` volume no known
/// workspace claims is kept and reported. Foreign names are never touched. Run it before puddle starts any sandbox
/// and while no other puddle runs (single instance).
///
/// # Errors
///
/// Only when the runtime can't list its sandboxes, stale directories or volumes; a failed step
/// on one item is in [`ReconcileReport::failures`].
pub async fn reconcile<R: Runtime>(
    runtime: &R,
    inventory: &Inventory,
    config: &ShutdownConfig,
) -> Result<ReconcileReport, ComputeError> {
    let mut report = ReconcileReport::default();
    for info in runtime.list().await? {
        let Some(name) = owned(&info) else {
            report.foreign.push(info.name);
            continue;
        };
        reconcile_sandbox(runtime, inventory, config, name, info.status, &mut report).await;
    }

    for dir in runtime.stale_dirs().await? {
        let Ok(name) = SandboxName::new(&dir) else {
            report.foreign.push(dir);
            continue;
        };
        match runtime.remove_stale_dir(&name).await {
            Ok(()) => {
                tracing::info!(sandbox = %name, "reconcile: stale directory removed");
                report.stale_dirs_removed.push(name);
            }
            Err(e) => report.fail(name.as_str(), "remove stale dir", &e),
        }
    }

    for volume in runtime.list_volumes().await? {
        let Some((name, workspace)) = volume
            .volume_name()
            .and_then(|v| v.workspace_id().map(|w| (v, w)))
        else {
            report.foreign.push(volume.name);
            continue;
        };
        if inventory.workspaces.contains(&workspace) {
            continue;
        }
        if !inventory.interrupted.contains(&workspace) {
            tracing::warn!(volume = %name, "reconcile: a workspace volume no known workspace claims; kept");
            report.unknown_volumes.push(name);
            continue;
        }
        if let Some(holder) = volume.holder {
            // Only a sandbox that is still running holds a volume, and every puddle-owned one
            // was stopped above, so this holder is foreign (or its stop failed).
            report.failures.push(Failure {
                item: name.to_string(),
                action: "remove volume",
                error: format!("held by running sandbox {holder}"),
            });
            continue;
        }
        match runtime.remove_volume(&name).await {
            Ok(()) => {
                tracing::info!(volume = %name, "reconcile: volume of an unfinished create removed");
                report.volumes_removed.push(name);
            }
            Err(e) => report.fail(name.as_str(), "remove volume", &e),
        }
    }

    report.foreign.sort();
    report.unknown_volumes.sort();
    tracing::info!(
        stopped = report.stopped.len(),
        removed = report.removed.len(),
        stale_dirs = report.stale_dirs_removed.len(),
        volumes = report.volumes_removed.len(),
        unknown_volumes = report.unknown_volumes.len(),
        foreign = report.foreign.len(),
        failures = report.failures.len(),
        "reconcile done"
    );
    Ok(report)
}

/// Rebuilds `workspaces`' holder registry after a restart: every attachment in
/// `inventory.attached` whose workspace and sandbox are both known is adopted, so a second
/// sandbox can't take a workspace a stopped one still holds. Call it after [`reconcile`] and
/// before any sandbox starts. Returns the adopted pairs; an attachment naming an unknown
/// workspace or sandbox is skipped with a warning.
pub fn adopt_workspaces(
    workspaces: &Workspaces,
    inventory: &Inventory,
) -> Vec<(WorkspaceId, SandboxName)> {
    let mut adopted = Vec::new();
    for (id, sandbox) in &inventory.attached {
        if !inventory.workspaces.contains(id)
            || !inventory.sandboxes.contains(sandbox)
            || is_maintenance_name(sandbox.as_str())
        {
            tracing::warn!(workspace = %id, %sandbox, "reconcile: attachment to an unknown workspace or sandbox; skipped");
            continue;
        }
        workspaces.adopt(id, sandbox);
        adopted.push((id.clone(), sandbox.clone()));
    }
    adopted
}

/// The sandbox's name if puddle owns it.
fn owned(info: &SandboxInfo) -> Option<SandboxName> {
    if info.puddle_owned {
        info.sandbox_name()
    } else {
        None
    }
}

async fn reconcile_sandbox<R: Runtime>(
    runtime: &R,
    inventory: &Inventory,
    config: &ShutdownConfig,
    name: SandboxName,
    status: WorkspaceStatus,
    report: &mut ReconcileReport,
) {
    let mut down = status.is_down();
    if !down {
        // Left running by a puddle that died (VMs never outlive puddle). Starting,
        // Draining and Paused are treated the same: stop is the only way back to a known state.
        match runtime.get(&name).await {
            Ok(handle) => match trim_and_stop(&handle, &[], config).await.1 {
                StopOutcome::Stopped => {
                    tracing::info!(sandbox = %name, %status, "reconcile: orphaned VM stopped");
                    report.stopped.push(name.clone());
                    down = true;
                }
                StopOutcome::Failed(e) => report.fail(name.as_str(), "stop", &e),
                StopOutcome::TimedOut => report.failures.push(Failure {
                    item: name.to_string(),
                    action: "stop",
                    error: format!("no answer within {:?}", config.stop_timeout),
                }),
            },
            // The VM went down between list and get: nothing left to stop.
            Err(ComputeError::InvalidState { .. }) => down = true,
            Err(e) => report.fail(name.as_str(), "stop", &e),
        }
    }
    if inventory.sandboxes.contains(&name) && !is_maintenance_name(name.as_str()) {
        if status == WorkspaceStatus::Crashed {
            report.crashed.push(name);
        }
        return;
    }
    if !down {
        return;
    }
    match runtime.remove(&name).await {
        Ok(()) => {
            tracing::info!(sandbox = %name, %status, "reconcile: stale record removed");
            report.removed.push(name);
        }
        Err(e) => report.fail(name.as_str(), "remove", &e),
    }
}

impl ReconcileReport {
    fn fail(&mut self, item: &str, action: &'static str, error: &ComputeError) {
        tracing::warn!(item, action, error = %error, "reconcile step failed");
        self.failures.push(Failure {
            item: item.to_owned(),
            action,
            error: error.to_string(),
        });
    }
}
