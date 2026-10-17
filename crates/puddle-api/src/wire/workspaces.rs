// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire types of the workspaces resource.

use puddle_types::{CheckoutDir, ImageRef, MemoryMib, SandboxName, WorkspaceName, WorkspaceStatus};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::error::ApiError;
use crate::workspaces as domain;

/// The long operation a workspace is in the middle of; progress comes as
/// `workspace_progress` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOperation {
    /// Creating the volume and cloning the repositories.
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

/// One repository Puddle manages for a workspace. Its identity and its Pull and Push toggles are
/// the workspace's Git settings (`GET /api/workspaces/{id}/git`), matched in the repository
/// table's spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceRepository {
    /// The HTTPS address it is cloned from, without credentials.
    pub url: String,
    /// The checkout it is cloned into, directly under the volume root.
    pub directory: CheckoutDir,
}

impl From<domain::Repository> for WorkspaceRepository {
    fn from(r: domain::Repository) -> Self {
        Self {
            url: r.url.as_str().to_owned(),
            directory: r.directory,
        }
    }
}

/// A workspace: its own disk with the repositories Puddle manages for it (and anything else the
/// user put there), and the sandbox that runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Workspace {
    /// The id used in paths. Today it is the workspace's name.
    pub id: String,
    /// The name of the workspace that runs it; events and per-workspace settings use this name.
    pub name: WorkspaceName,
    /// What the user calls the workspace: the name until they rename it (`PATCH
    /// /api/workspaces/{id}`). Show this one; `name` and `id` never change.
    pub display_name: String,
    /// The repositories Puddle manages for it, in the order they were added (0 to 100).
    pub repositories: Vec<WorkspaceRepository>,
    /// Where new terminals land and what the editor opens: a path under the volume, or `null`
    /// for the volume root.
    #[schema(required = true)]
    pub start_folder: Option<String>,
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
    /// Why `direct_ssh` is only a guess: the settings could not be read, so it counts as off.
    /// `null` when the settings were read.
    #[schema(required = true)]
    pub settings_error: Option<String>,
    /// Deprecated and always `false`: the first-connect notice is the "Allow direct SSH"
    /// confirmation now. Read `direct_ssh` instead.
    #[deprecated(note = "always false; read `direct_ssh`")]
    pub first_connect_notice_due: bool,
    /// Which identity each repository of a new workspace got and why, one per repository of the
    /// request, in its order. Only the answer to creating a workspace fills it; every other answer
    /// has an empty list, and the Git tab shows the same afterwards.
    #[serde(default)]
    #[schema(required = true)]
    pub identities: Vec<crate::wire::NewWorkspaceIdentity>,
}

impl Workspace {
    /// The workspace as the API shows it, with whether direct SSH is on for it.
    #[must_use]
    pub fn new(record: domain::WorkspaceRecord, direct_ssh: bool) -> Self {
        let display_name = record.label().to_owned();
        let domain::WorkspaceRecord {
            id,
            name,
            repositories,
            start_folder,
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
            display_name,
            repositories: repositories.into_iter().map(Into::into).collect(),
            start_folder: start_folder.map(|f| f.as_str().to_owned()),
            image,
            memory_mib: memory.get(),
            status,
            busy: busy.map(Into::into),
            created_at,
            disk_size_mib,
            disk_used_mib,
            direct_ssh,
            settings_error: None,
            first_connect_notice_due: false,
            identities: Vec::new(),
        }
    }

    /// The same workspace, with what its Git settings started with (the answer to creating it).
    #[must_use]
    pub fn with_identities(mut self, identities: Vec<crate::wire::NewWorkspaceIdentity>) -> Self {
        self.identities = identities;
        self
    }

    /// The same workspace, with the reason its settings could not be read (if they could not).
    #[must_use]
    pub fn with_settings_error(mut self, error: Option<String>) -> Self {
        self.settings_error = error;
        self
    }
}

/// `GET /api/workspaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceList {
    /// Every workspace, ordered by id.
    pub workspaces: Vec<Workspace>,
}

/// One repository of `POST /api/workspaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewRepositoryRequest {
    /// The repository to clone, as an `https://` URL without credentials. SSH remotes
    /// (`git@host:path`, `ssh://`) are refused with a message saying so.
    pub url: String,
    /// The checkout's directory under the volume root; left out or `null` is the last part of
    /// the address (`api` for `https://github.com/acme/api.git`), or `src` when that is no usable
    /// name.
    #[serde(default)]
    pub directory: Option<String>,
    /// The identity that serves it (`id` of `GET /api/identities`); left out or `null` is the
    /// identity that covers its owner, else the default identity.
    #[serde(default)]
    pub identity_id: Option<i64>,
    /// Pull on its new repository table row; left out or `null` is on. A row the table already
    /// has keeps its toggles.
    #[serde(default)]
    pub pull: Option<bool>,
    /// Push on its new repository table row; left out or `null` is on.
    #[serde(default)]
    pub push: Option<bool>,
}

/// A field a request may no longer send: present whatever its value, `null` included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retired;

fn retired<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Retired>, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| Some(Retired))
}

/// `POST /api/workspaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewWorkspaceRequest {
    /// The workspace's name, which is also its workspace's name.
    pub name: WorkspaceName,
    /// The repositories to clone, in order (0 to 100); left out is none. The list is checked
    /// whole before anything exists.
    #[serde(default)]
    #[schema(max_items = 100)]
    pub repositories: Vec<NewRepositoryRequest>,
    /// Where new terminals land and what the editor opens: a path under the volume (relative,
    /// `/` between its parts, at most 255 bytes, not inside `.puddle`); left out or `null` is the
    /// volume root.
    #[serde(default)]
    pub start_folder: Option<String>,
    /// The image to boot; left out or `null` is the default devcontainer image.
    #[serde(default)]
    pub image: Option<String>,
    /// Memory in MiB (256 to 1048576); left out or `null` is the default.
    #[serde(default)]
    #[schema(minimum = 256, maximum = 1_048_576)]
    pub memory_mib: Option<u32>,
    /// Replaced by `repositories`; a body that sends it is refused with a message saying so.
    #[serde(default, deserialize_with = "retired", skip_serializing)]
    // skip-ok: leaves the retired field out of the contract; no test is skipped.
    #[schema(ignore)]
    pub repo_url: Option<Retired>,
}

/// Names starting with this are Puddle's own short-lived maintenance workspaces.
const RESERVED_PREFIX: &str = "m--";

impl NewWorkspaceRequest {
    /// The checked request; `identity_exists` says whether an identity id names one.
    pub(crate) fn into_new(
        self,
        identity_exists: impl Fn(puddle_store::IdentityId) -> bool,
    ) -> Result<domain::NewWorkspace, ApiError> {
        if self.repo_url.is_some() {
            return Err(ApiError::invalid(
                "repo_url was replaced by repositories, a list of {url}",
            ));
        }
        if self.name.as_str().starts_with(RESERVED_PREFIX) {
            return Err(ApiError::invalid(format!(
                "names starting with {RESERVED_PREFIX} are reserved for Puddle"
            )));
        }
        let drafts: Vec<domain::RepositoryDraft> = self
            .repositories
            .into_iter()
            .map(|r| domain::RepositoryDraft {
                url: r.url,
                directory: r.directory,
                identity: r.identity_id.map(puddle_store::IdentityId),
                pull: r.pull,
                push: r.push,
            })
            .collect();
        let repositories =
            domain::check_repositories(&drafts, identity_exists).map_err(ApiError::invalid)?;
        let start_folder = self
            .start_folder
            .as_deref()
            .map(domain::StartFolder::parse)
            .transpose()
            .map_err(ApiError::invalid)?;
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
            repositories,
            start_folder,
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

/// `PATCH /api/workspaces/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameWorkspaceRequest {
    /// The new display name: 1 to 60 characters, spaces at the ends dropped, no line breaks.
    /// `null` goes back to the workspace's name. Required, so an empty body never resets it.
    #[serde(deserialize_with = "Option::deserialize")]
    #[schema(required = true)]
    pub display_name: Option<String>,
}

impl RenameWorkspaceRequest {
    pub(crate) fn into_display_name(self) -> Result<Option<domain::DisplayName>, ApiError> {
        self.display_name
            .as_deref()
            .map(domain::DisplayName::parse)
            .transpose()
            .map_err(ApiError::invalid)
    }
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
    /// Whether Puddle opened an editor itself (desktop mode, when it worked).
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
