// SPDX-License-Identifier: GPL-3.0-or-later
//! The workspace lifecycle's error type.

use puddle_compute::ComputeError;

use crate::DeleteReport;

/// Why a workspace operation failed. Workspace and sandbox names are plain strings: a holder
/// may be a sandbox puddle didn't create.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// Another sandbox has the workspace's volume (ADR 0006 point 8: one writer). puddle refuses
    /// before msb would, so the message can name the holder.
    #[error("workspace {workspace:?} is in use by sandbox {holder:?}")]
    InUse {
        /// The workspace.
        workspace: String,
        /// The sandbox that holds it (running, stopped, or puddle's short-lived maintenance
        /// sandbox).
        holder: String,
    },
    /// The workspace has no volume.
    #[error("workspace {workspace:?} not found")]
    NotFound {
        /// The workspace.
        workspace: String,
    },
    /// A workspace that should have data has no volume, and puddle did not make an empty one
    /// in its place.
    #[error(
        "workspace {workspace:?} has no volume ({volume}); it was not started, and no new empty volume was made in its place; restore the volume, then start it again"
    )]
    VolumeMissing {
        /// The workspace.
        workspace: String,
        /// The volume that should hold it.
        volume: String,
    },
    /// A guest path could not be formed (a checkout name that isn't usable).
    #[error("invalid workspace path: {reason}")]
    Layout {
        /// What is wrong.
        reason: String,
    },
    /// A runtime call failed.
    #[error("cannot {op} for workspace {workspace:?}: {source}")]
    Runtime {
        /// What was attempted.
        op: &'static str,
        /// The workspace.
        workspace: String,
        /// The runtime's error.
        source: ComputeError,
    },
    /// The unsaved-work check couldn't run or its output couldn't be read. Fails closed: no
    /// report, so no confirmation, so no delete.
    #[error("cannot check workspace {workspace:?} for unsaved work: {reason}")]
    Check {
        /// The workspace.
        workspace: String,
        /// Why.
        reason: String,
    },
    /// `fstrim` failed in the guest.
    #[error("cannot trim workspace {workspace:?}: {reason}")]
    Trim {
        /// The workspace.
        workspace: String,
        /// Why (the command's stderr, shortened).
        reason: String,
    },
    /// `git clone` failed in the guest.
    #[error("cannot clone into workspace {workspace:?}: {reason}")]
    Clone {
        /// The workspace.
        workspace: String,
        /// Why (git's stderr, shortened).
        reason: String,
    },
    /// `sync` failed in the guest, so a fresh clone isn't known to be on disk.
    #[error("cannot sync workspace {workspace:?}: {reason}")]
    Sync {
        /// The workspace.
        workspace: String,
        /// Why.
        reason: String,
    },
    /// Clearing the stale git locks failed (the script couldn't run or its output couldn't be
    /// read).
    #[error("cannot clear stale git locks of workspace {workspace:?}: {reason}")]
    Locks {
        /// The workspace.
        workspace: String,
        /// Why.
        reason: String,
    },
    /// The confirmation was for another workspace.
    #[error("the delete confirmation is for workspace {confirmed:?}, not {workspace:?}")]
    WrongConfirmation {
        /// The workspace being deleted.
        workspace: String,
        /// The workspace the confirmation names.
        confirmed: String,
    },
    /// What the delete check finds now differs from what the user confirmed. Nothing was
    /// deleted; show the new report and ask again.
    #[error("workspace {workspace:?} changed since the delete was confirmed; confirm again")]
    Changed {
        /// The workspace.
        workspace: String,
        /// What the check finds now.
        report: Box<DeleteReport>,
    },
}

impl WorkspaceError {
    pub(crate) fn runtime(
        op: &'static str,
        workspace: &impl ToString,
        source: ComputeError,
    ) -> Self {
        Self::Runtime {
            op,
            workspace: workspace.to_string(),
            source,
        }
    }
}
