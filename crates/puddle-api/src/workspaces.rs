// SPDX-License-Identifier: GPL-3.0-or-later
//! The workspaces the API serves: the [`WorkspaceService`] trait the routes call, the domain
//! types it speaks, and the [`Launcher`] that opens a desktop editor.
//!
//! The routes know nothing about volumes, sandboxes or the runtime. The real service (over
//! `puddle-workspace` and `puddle-lifecycle`) is wired in by the application; [`crate::FakeWorkspaces`]
//! is the in-memory one for tests and the UI fixture. Every method returns promptly: a long
//! operation (create, start, stop, reclaim, delete) is *accepted* by the call, returns the
//! workspace with [`WorkspaceRecord::busy`] set, and reports the rest through
//! [`puddle_types::Event::StatusChanged`] and [`puddle_types::Event::WorkspaceProgress`].

use std::fmt;

use futures_util::future::BoxFuture;
use puddle_types::{ImageRef, MemoryMib, SandboxName, SandboxStatus, WorkspaceId};

/// The long operation a workspace is in the middle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
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

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Creating => "creating",
            Self::Starting => "starting",
            Self::Stopping => "stopping",
            Self::Reclaiming => "reclaiming",
            Self::Deleting => "deleting",
        })
    }
}

/// One workspace as the service reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceRecord {
    /// The workspace's id (its volume is `ws-<id>`).
    pub id: WorkspaceId,
    /// The sandbox that runs it; events and settings use this name.
    pub name: SandboxName,
    /// The repository it was created from (HTTPS, no credentials).
    pub repo_url: String,
    /// The image its sandbox boots.
    pub image: String,
    /// Its memory, applied at the next start.
    pub memory: MemoryMib,
    /// The sandbox's state.
    pub status: SandboxStatus,
    /// The operation in progress, if any.
    pub busy: Option<Operation>,
    /// Epoch ms it was created.
    pub created_at: u64,
    /// The volume's size in MiB: the most the workspace can hold.
    pub disk_size_mib: u64,
    /// What the volume holds now in MiB, when known.
    pub disk_used_mib: Option<u64>,
    /// Whether the first-connect notice must be shown before the first desktop attach
    /// (the editor runs project code with the workspace's reach). Cleared by a successful
    /// desktop attach.
    pub first_connect_notice_due: bool,
}

impl WorkspaceRecord {
    /// A record with the defaults the fake and the tests start from.
    #[must_use]
    pub fn new(id: WorkspaceId, name: SandboxName, repo_url: impl Into<String>) -> Self {
        Self {
            id,
            name,
            repo_url: repo_url.into(),
            image: DEFAULT_IMAGE.to_owned(),
            memory: MemoryMib::DEFAULT,
            status: SandboxStatus::Created,
            busy: None,
            created_at: 0,
            disk_size_mib: DEFAULT_DISK_MIB,
            disk_used_mib: None,
            first_connect_notice_due: true,
        }
    }
}

/// The image a workspace gets when the request names none.
pub const DEFAULT_IMAGE: &str = "mcr.microsoft.com/devcontainers/base:debian";

/// The volume size a new workspace gets (32 GiB, sparse on the host).
pub const DEFAULT_DISK_MIB: u64 = 32 * 1024;

/// A checked HTTPS repository URL: no credentials, no whitespace, a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoUrl(String);

/// Longest repository URL accepted.
pub const MAX_REPO_URL_LEN: usize = 2048;

impl RepoUrl {
    /// Checks a repository URL.
    ///
    /// # Errors
    ///
    /// A message for the user: SSH remotes get the "not supported yet" one, anything else that
    /// is not a plain `https://` URL says what to change.
    pub fn parse(url: &str) -> Result<Self, String> {
        let url = url.trim();
        let lower = url.to_ascii_lowercase();
        if lower.starts_with("ssh://") || is_scp_like(url) {
            return Err(
                "SSH remotes are not supported yet; use the repository's HTTPS URL instead".into(),
            );
        }
        if url.len() > MAX_REPO_URL_LEN {
            return Err(format!(
                "the repository URL is longer than {MAX_REPO_URL_LEN} characters"
            ));
        }
        if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("the repository URL must not contain spaces or control characters".into());
        }
        let Some(rest) = lower.strip_prefix("https://") else {
            return Err("use an https:// URL for the repository".into());
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') {
            return Err(
                "remove the user name and password from the URL; puddle supplies credentials itself"
                    .into(),
            );
        }
        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        if host.is_empty() {
            return Err("the repository URL has no host".into());
        }
        Ok(Self(url.to_owned()))
    }

    /// The URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `git@host:owner/repo`-style remotes: no scheme, a `:` before any `/`.
fn is_scp_like(url: &str) -> bool {
    if url.contains("://") || url.to_ascii_lowercase().starts_with("http") {
        return false;
    }
    match (url.find(':'), url.find('/')) {
        // A colon at index 1 is a Windows drive letter, not a host.
        (Some(colon), Some(slash)) => colon > 1 && colon < slash,
        (Some(colon), None) => colon > 1,
        _ => false,
    }
}

/// What `create` needs. Build it from a request with [`RepoUrl::parse`] and the typed names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewWorkspace {
    /// The workspace's sandbox name; its id is derived from it.
    pub name: SandboxName,
    /// Where to clone from.
    pub repo_url: RepoUrl,
    /// The image, or the default.
    pub image: Option<ImageRef>,
    /// The memory, or the default.
    pub memory: Option<MemoryMib>,
}

impl NewWorkspace {
    /// A request for a workspace with the defaults.
    #[must_use]
    pub fn new(name: SandboxName, repo_url: RepoUrl) -> Self {
        Self {
            name,
            repo_url,
            image: None,
            memory: None,
        }
    }
}

/// A bounded list of lines, as the unsaved-work check reports them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The first items.
    pub items: Vec<String>,
    /// How many more there are.
    pub more: u64,
}

impl Listing {
    /// Whether nothing is listed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.more == 0
    }
}

/// What one checkout holds that isn't on a remote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoFindings {
    /// The checkout's directory under the workspace.
    pub dir: String,
    /// Uncommitted changes and untracked files.
    pub uncommitted: Listing,
    /// Commits on no remote branch.
    pub unpushed: Listing,
    /// Stashes.
    pub stashes: Listing,
}

impl RepoFindings {
    /// Whether nothing in this checkout would be lost.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.uncommitted.is_empty() && self.unpushed.is_empty() && self.stashes.is_empty()
    }
}

/// What deleting a workspace would lose.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeleteCheck {
    /// The workspace.
    pub workspace: WorkspaceId,
    /// Every checkout, clean or not.
    pub repos: Vec<RepoFindings>,
    /// Data outside any checkout.
    pub other: Listing,
    /// What could not be checked. A check that could not run counts as unsafe.
    pub errors: Vec<String>,
    /// The stopped sandbox that is removed together with the workspace.
    pub removes_sandbox: Option<SandboxName>,
    /// A digest of exactly this report. A delete that passes it is refused when the workspace
    /// has changed since.
    pub fingerprint: String,
}

impl DeleteCheck {
    /// Whether deleting loses nothing the check can see.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.repos.iter().all(RepoFindings::is_clean)
            && self.other.is_empty()
            && self.errors.is_empty()
    }
}

/// How to open the workspace in an editor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// VS Code on the desktop, through the [`Launcher`].
    Desktop,
    /// VS Code in the browser; the call returns the URL and the shell opens it.
    Browser,
}

/// The result of an attach.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attached {
    /// Whether puddle opened an editor itself (desktop mode, when it worked).
    pub opened: bool,
    /// Where the browser editor is, in browser mode.
    pub url: Option<String>,
    /// Why nothing was opened, when that is not an error.
    pub message: Option<String>,
}

impl Attached {
    /// An editor was opened.
    #[must_use]
    pub fn opened() -> Self {
        Self {
            opened: true,
            url: None,
            message: None,
        }
    }

    /// The editor is at `url`; the caller opens it.
    #[must_use]
    pub fn at(url: impl Into<String>) -> Self {
        Self {
            opened: false,
            url: Some(url.into()),
            message: None,
        }
    }

    /// Nothing was opened, for this reason.
    #[must_use]
    pub fn not_opened(message: impl Into<String>) -> Self {
        Self {
            opened: false,
            url: None,
            message: Some(message.into()),
        }
    }
}

/// Why a workspace call failed. Messages are for the user: lower case, no trailing period.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WorkspaceError {
    /// No such workspace.
    #[error("{0}")]
    NotFound(String),
    /// The workspace is in a state that doesn't allow this: running, busy, name taken, or
    /// changed since the user looked.
    #[error("{0}")]
    Conflict(String),
    /// A value was refused.
    #[error("{0}")]
    Invalid(String),
    /// The service can't do it now (no runtime, not wired in).
    #[error("{0}")]
    Unavailable(String),
    /// puddle failed; the text goes to the log, not to the client.
    #[error("{0}")]
    Internal(String),
}

/// The workspaces resource. Implemented by the application over the runtime, and by
/// [`crate::FakeWorkspaces`].
///
/// Contract:
///
/// - Calls return after the request is checked and accepted, not after the work: the record they
///   return has [`WorkspaceRecord::busy`] set. Progress and the end of the operation arrive as
///   events; a failure is a [`puddle_types::WorkspaceStep::Failed`] event, not a late error.
/// - [`WorkspaceError::Conflict`] when the workspace is busy or already in the wanted state.
/// - [`WorkspaceService::delete`] never removes work the user hasn't seen: see its docs.
pub trait WorkspaceService: Send + Sync {
    /// Every workspace, ordered by id.
    fn list(&self) -> BoxFuture<'_, Result<Vec<WorkspaceRecord>, WorkspaceError>>;

    /// One workspace.
    fn get<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Creates a workspace: its volume, then a clone of the repository.
    /// [`WorkspaceError::Conflict`] if the name is taken.
    fn create(&self, new: NewWorkspace) -> BoxFuture<'_, Result<WorkspaceRecord, WorkspaceError>>;

    /// Boots a workspace that is down.
    fn start<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Shuts a running workspace down.
    fn stop<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Gives freed disk space back to the host.
    fn reclaim<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Looks for what deleting the workspace would lose. Works on a running or a stopped
    /// workspace.
    fn delete_check<'a>(
        &'a self,
        id: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<DeleteCheck, WorkspaceError>>;

    /// Deletes a workspace that is stopped. It checks again first: with `fingerprint` it goes
    /// ahead only if the fresh check has exactly that fingerprint (the user saw this report);
    /// without one it goes ahead only if the fresh check is clean. Otherwise
    /// [`WorkspaceError::Conflict`] and nothing is deleted.
    fn delete<'a>(
        &'a self,
        id: &'a WorkspaceId,
        fingerprint: Option<&'a str>,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Opens the workspace in an editor. The workspace must be running.
    fn attach<'a>(
        &'a self,
        id: &'a WorkspaceId,
        mode: AttachMode,
    ) -> BoxFuture<'a, Result<Attached, WorkspaceError>>;
}

/// Opens VS Code on the desktop for a workspace; the desktop shell implements it.
pub trait Launcher: Send + Sync {
    /// Opens an editor window attached to the workspace.
    ///
    /// # Errors
    ///
    /// [`LaunchError`] with a message for the user (VS Code is not installed, the remote
    /// extension is missing, ...).
    fn open_desktop<'a>(
        &'a self,
        workspace: &'a WorkspaceRecord,
    ) -> BoxFuture<'a, Result<(), LaunchError>>;
}

/// The desktop editor could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct LaunchError {
    message: String,
}

impl LaunchError {
    /// An error with this message for the user.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// The service when none is wired in: every call says so. The API uses it until the
/// application provides the real one.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoWorkspaces;

fn unavailable<T: Send + 'static>() -> BoxFuture<'static, Result<T, WorkspaceError>> {
    Box::pin(async {
        Err(WorkspaceError::Unavailable(
            "workspaces are not available in this build yet".into(),
        ))
    })
}

impl WorkspaceService for NoWorkspaces {
    fn list(&self) -> BoxFuture<'_, Result<Vec<WorkspaceRecord>, WorkspaceError>> {
        unavailable()
    }
    fn get<'a>(
        &'a self,
        _: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn create(&self, _: NewWorkspace) -> BoxFuture<'_, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn start<'a>(
        &'a self,
        _: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn stop<'a>(
        &'a self,
        _: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn reclaim<'a>(
        &'a self,
        _: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn delete_check<'a>(
        &'a self,
        _: &'a WorkspaceId,
    ) -> BoxFuture<'a, Result<DeleteCheck, WorkspaceError>> {
        unavailable()
    }
    fn delete<'a>(
        &'a self,
        _: &'a WorkspaceId,
        _: Option<&'a str>,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
        unavailable()
    }
    fn attach<'a>(
        &'a self,
        _: &'a WorkspaceId,
        _: AttachMode,
    ) -> BoxFuture<'a, Result<Attached, WorkspaceError>> {
        unavailable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_urls_pass() {
        for ok in [
            "https://github.com/acme/api",
            "https://github.com/acme/api.git",
            "HTTPS://GitHub.com/acme/api",
            "https://dev.azure.com/org/proj/_git/repo",
            "https://git.example.com:8443/a/b",
            "  https://github.com/acme/api  ",
        ] {
            assert_eq!(RepoUrl::parse(ok).unwrap().as_str(), ok.trim());
        }
    }

    #[test]
    fn ssh_remotes_get_the_not_supported_message() {
        for ssh in [
            "git@github.com:acme/api.git",
            "ssh://git@github.com/acme/api.git",
            "SSH://github.com/acme/api",
            "github.com:acme/api",
            "user@host:path",
        ] {
            let err = RepoUrl::parse(ssh).unwrap_err();
            assert!(
                err.contains("SSH remotes are not supported yet"),
                "{ssh}: {err}"
            );
            assert!(err.contains("HTTPS"), "{err}");
        }
    }

    #[test]
    fn other_urls_say_what_to_change() {
        let cases = [
            ("http://github.com/a/b", "https://"),
            ("git://github.com/a/b", "https://"),
            ("/home/me/repo", "https://"),
            ("C:\\repos\\api", "https://"),
            ("file:///repo", "https://"),
            ("", "https://"),
            ("https://", "no host"),
            ("https:///path", "no host"),
            ("https://:443/x", "no host"),
            (
                "https://user:secret@github.com/a/b",
                "user name and password",
            ),
            ("https://token@github.com/a/b", "user name and password"),
            ("https://github.com/a b", "spaces"),
            ("https://github.com/a\nb", "control"),
        ];
        for (url, wants) in cases {
            let err = RepoUrl::parse(url).unwrap_err();
            assert!(err.contains(wants), "{url:?}: {err}");
            assert!(!err.contains("secret"), "{err}");
        }
        let long = format!("https://github.com/{}", "a".repeat(MAX_REPO_URL_LEN));
        assert!(RepoUrl::parse(&long).unwrap_err().contains("longer than"));
    }

    #[test]
    fn a_check_is_clean_only_without_findings_or_errors() {
        let id = WorkspaceId::new("w").unwrap();
        let mut check = DeleteCheck {
            workspace: id,
            repos: vec![RepoFindings::default()],
            other: Listing::default(),
            errors: vec![],
            removes_sandbox: None,
            fingerprint: String::new(),
        };
        assert!(check.is_clean());
        check.repos[0].stashes.more = 1;
        assert!(!check.is_clean());
        check.repos[0].stashes.more = 0;
        check.other.items.push("notes.txt".into());
        assert!(!check.is_clean());
        check.other = Listing::default();
        check.errors.push("repo: unreadable".into());
        assert!(!check.is_clean());
    }

    #[tokio::test]
    async fn the_empty_service_says_it_is_unavailable() {
        let svc = NoWorkspaces;
        let id = WorkspaceId::new("w").unwrap();
        let name = SandboxName::new("w").unwrap();
        let url = RepoUrl::parse("https://example.com/a").unwrap();
        let all = [
            svc.list().await.map(|_| ()),
            svc.get(&id).await.map(|_| ()),
            svc.create(NewWorkspace::new(name, url)).await.map(|_| ()),
            svc.start(&id).await.map(|_| ()),
            svc.stop(&id).await.map(|_| ()),
            svc.reclaim(&id).await.map(|_| ()),
            svc.delete_check(&id).await.map(|_| ()),
            svc.delete(&id, None).await.map(|_| ()),
            svc.attach(&id, AttachMode::Browser).await.map(|_| ()),
        ];
        for result in all {
            assert!(matches!(result, Err(WorkspaceError::Unavailable(_))));
        }
    }

    #[test]
    fn operations_have_wire_names() {
        assert_eq!(Operation::Reclaiming.to_string(), "reclaiming");
        assert_eq!(Operation::Deleting.to_string(), "deleting");
    }
}
