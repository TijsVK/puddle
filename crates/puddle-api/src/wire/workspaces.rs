// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire types of the workspaces resource.

use puddle_types::{ImageRef, MemoryMib, SandboxName, WorkspaceName, WorkspaceStatus};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::workspaces as domain;

/// The long operation a workspace is in the middle of; progress comes as
/// `workspace_progress` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOperation {
    /// Creating the volume and cloning the repository.
    Creating,
    /// Booting.
    Starting,
    /// Shutting down.
    Stopping,
    /// Giving freed disk space back to the host.
    Reclaiming,
    /// Checking for unsaved work and removing the workspace.
    Deleting,
}

impl From<domain::Operation> for WorkspaceOperation {
    fn from(op: domain::Operation) -> Self {
        match op {
            domain::Operation::Creating => Self::Creating,
            domain::Operation::Starting => Self::Starting,
            domain::Operation::Stopping => Self::Stopping,
            domain::Operation::Reclaiming => Self::Reclaiming,
            domain::Operation::Deleting => Self::Deleting,
        }
    }
}

/// A workspace: a repository checkout on its own disk, and the workspace that runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Workspace {
    /// The id used in paths. Today it is the workspace's name.
    pub id: String,
    /// The name of the workspace that runs it; events and per-workspace settings use this name.
    pub name: WorkspaceName,
    /// The HTTPS URL it was cloned from.
    pub repo_url: String,
    /// The image its workspace boots.
    pub image: String,
    /// Memory in MiB, applied at the next start.
    pub memory_mib: u32,
    /// The workspace's state.
    pub status: WorkspaceStatus,
    /// The operation in progress; `null` when idle.
    #[schema(required = true)]
    pub busy: Option<WorkspaceOperation>,
    /// Epoch ms it was created.
    pub created_at: u64,
    /// The disk's size in MiB: the most the workspace can hold.
    pub disk_size_mib: u64,
    /// What the disk holds in MiB; `null` when not known.
    #[schema(required = true)]
    pub disk_used_mib: Option<u64>,
    /// Whether direct SSH is on for this workspace (its effective setting, `direct_ssh` in the
    /// settings). The workspace is then "trusted": desktop VS Code and other SSH tools can
    /// connect, and what runs in the workspace can reach this computer through them.
    pub direct_ssh: bool,
    /// Deprecated and always `false`: the first-connect notice is the "Allow direct SSH"
    /// confirmation now. Read `direct_ssh` instead.
    #[deprecated(note = "always false; read `direct_ssh`")]
    pub first_connect_notice_due: bool,
}

impl Workspace {
    /// The workspace as the API shows it, with whether direct SSH is on for it.
    #[must_use]
    pub fn new(record: domain::WorkspaceRecord, direct_ssh: bool) -> Self {
        let domain::WorkspaceRecord {
            id,
            name,
            repo_url,
            image,
            memory,
            status,
            busy,
            created_at,
            disk_size_mib,
            disk_used_mib,
            ..
        } = record;
        #[expect(deprecated, reason = "the field stays on the wire, always false")]
        Self {
            id: id.to_string(),
            name,
            repo_url,
            image,
            memory_mib: memory.get(),
            status,
            busy: busy.map(Into::into),
            created_at,
            disk_size_mib,
            disk_used_mib,
            direct_ssh,
            first_connect_notice_due: false,
        }
    }
}

/// `GET /api/workspaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceList {
    /// Every workspace, ordered by id.
    pub workspaces: Vec<Workspace>,
}

/// `POST /api/workspaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWorkspaceRequest {
    /// The workspace's name, which is also its workspace's name.
    pub name: WorkspaceName,
    /// The repository to clone, as an `https://` URL without credentials. SSH remotes
    /// (`git@host:path`, `ssh://`) are refused with a message saying so.
    pub repo_url: String,
    /// The image to boot; left out or `null` is the default devcontainer image.
    #[serde(default)]
    pub image: Option<String>,
    /// Memory in MiB (256 to 1048576); left out or `null` is the default.
    #[serde(default)]
    #[schema(minimum = 256, maximum = 1_048_576)]
    pub memory_mib: Option<u32>,
}

/// Names starting with this are puddle's own short-lived maintenance workspaces.
const RESERVED_PREFIX: &str = "m--";

impl NewWorkspaceRequest {
    pub(crate) fn into_new(self) -> Result<domain::NewWorkspace, ApiError> {
        if self.name.as_str().starts_with(RESERVED_PREFIX) {
            return Err(ApiError::invalid(format!(
                "names starting with {RESERVED_PREFIX} are reserved for puddle"
            )));
        }
        let repo_url = domain::RepoUrl::parse(&self.repo_url).map_err(ApiError::invalid)?;
        let image = self
            .image
            .as_deref()
            .map(ImageRef::new)
            .transpose()
            .map_err(|e| ApiError::invalid(e.to_string()))?;
        let memory = self
            .memory_mib
            .map(MemoryMib::new)
            .transpose()
            .map_err(|e| ApiError::invalid(e.to_string()))?;
        Ok(domain::NewWorkspace {
            name: self.name,
            repo_url,
            image,
            memory,
        })
    }
}

/// A bounded list of lines from the unsaved-work check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct FindingList {
    /// The first items.
    pub items: Vec<String>,
    /// How many more there are.
    pub more: u64,
}

impl From<domain::Listing> for FindingList {
    fn from(l: domain::Listing) -> Self {
        Self {
            items: l.items,
            more: l.more,
        }
    }
}

/// What one checkout holds that is not on a remote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoFindings {
    /// The checkout's directory in the workspace.
    pub dir: String,
    /// Whether nothing in it would be lost.
    pub clean: bool,
    /// Uncommitted changes and untracked files (`git status --porcelain` lines).
    pub uncommitted: FindingList,
    /// Commits on no remote branch (`<hash> <subject>`).
    pub unpushed: FindingList,
    /// Stashes.
    pub stashes: FindingList,
}

/// `GET /api/workspaces/{id}/delete-check`: what deleting the workspace would lose. Text comes
/// from the guest: escape it when rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DeleteCheck {
    /// The workspace's id.
    pub workspace: String,
    /// Whether deleting loses nothing the check can see.
    pub clean: bool,
    /// Every checkout, clean or not.
    pub repos: Vec<RepoFindings>,
    /// Data outside any checkout.
    pub other: FindingList,
    /// What could not be checked. Anything here makes `clean` false.
    pub errors: Vec<String>,
    /// The stopped workspace that is removed together with the workspace.
    #[schema(required = true)]
    pub removes_sandbox: Option<SandboxName>,
    /// The workspace's volume is already gone: nothing was inspected and deleting loses
    /// nothing. `clean` is `true` then.
    pub volume_missing: bool,
    /// Identifies exactly this report: send it back in the delete request, which is refused if
    /// the workspace has changed since.
    pub fingerprint: String,
}

impl From<domain::DeleteCheck> for DeleteCheck {
    fn from(check: domain::DeleteCheck) -> Self {
        let clean = check.is_clean();
        Self {
            workspace: check.workspace.to_string(),
            clean,
            repos: check
                .repos
                .into_iter()
                .map(|r| RepoFindings {
                    clean: r.is_clean(),
                    dir: r.dir,
                    uncommitted: r.uncommitted.into(),
                    unpushed: r.unpushed.into(),
                    stashes: r.stashes.into(),
                })
                .collect(),
            other: check.other.into(),
            errors: check.errors,
            removes_sandbox: check.removes_sandbox,
            volume_missing: check.volume_missing,
            fingerprint: check.fingerprint,
        }
    }
}

/// `DELETE /api/workspaces/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteWorkspaceRequest {
    /// Must be `true`: the user confirmed.
    pub confirm: bool,
    /// The `fingerprint` of the delete check the user saw. Left out or `null` means "I saw
    /// nothing to lose": the delete goes ahead only if a fresh check is clean.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// How to open the workspace in an editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttachMode {
    /// VS Code on the desktop.
    Desktop,
    /// VS Code in the browser.
    Browser,
}

impl From<AttachMode> for domain::AttachMode {
    fn from(mode: AttachMode) -> Self {
        match mode {
            AttachMode::Desktop => Self::Desktop,
            AttachMode::Browser => Self::Browser,
        }
    }
}

/// `POST /api/workspaces/{id}/attach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AttachRequest {
    /// Where to open it.
    pub mode: AttachMode,
}

/// What an attach did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AttachResponse {
    /// Whether puddle opened an editor itself (desktop mode, when it worked).
    pub opened: bool,
    /// Where the browser editor is, in browser mode; the caller opens it.
    #[schema(required = true)]
    pub url: Option<String>,
    /// Why nothing was opened, when that is not an error (for example VS Code is not
    /// installed).
    #[schema(required = true)]
    pub message: Option<String>,
}

impl From<domain::Attached> for AttachResponse {
    fn from(a: domain::Attached) -> Self {
        Self {
            opened: a.opened,
            url: a.url,
            message: a.message,
        }
    }
}
