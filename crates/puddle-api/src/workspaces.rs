// SPDX-License-Identifier: GPL-3.0-or-later
//! The workspaces the API serves: the [`WorkspaceService`] trait the routes call, the domain
//! types it speaks, and the [`Launcher`] that opens a desktop editor.
//!
//! The routes know nothing about volumes, workspaces or the runtime. The real service (over
//! `puddle-workspace` and `puddle-lifecycle`) is wired in by the application; [`crate::FakeWorkspaces`]
//! is the in-memory one for tests and the UI fixture. Every method returns promptly: a long
//! operation (create, start, stop, reclaim, delete) is *accepted* by the call, returns the
//! workspace with [`WorkspaceRecord::busy`] set, and reports the rest through
//! [`puddle_types::Event::StatusChanged`] and [`puddle_types::Event::WorkspaceProgress`].

use std::fmt;

use futures_util::future::BoxFuture;
use puddle_store::{IdentityId, RepoRef};
use puddle_types::{
    CheckoutDir, ImageRef, MemoryMib, SandboxName, WorkspaceId, WorkspaceName, WorkspaceStatus,
};
use sha2::{Digest, Sha256};

/// The long operation a workspace is in the middle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
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
    /// The workspace that runs it; events and settings use this name. It never changes.
    pub name: WorkspaceName,
    /// What the user renamed the workspace to; `None` until they do. Only a label: nothing
    /// else (sandbox, volume, rules, settings) uses it.
    pub display_name: Option<DisplayName>,
    /// The repositories Puddle manages for it, in the order they were added.
    pub repositories: Vec<Repository>,
    /// Where new terminals land and what the editor opens; `None` is the volume root.
    pub start_folder: Option<StartFolder>,
    /// The image its workspace boots.
    pub image: String,
    /// Its memory, applied at the next start.
    pub memory: MemoryMib,
    /// The workspace's state.
    pub status: WorkspaceStatus,
    /// The operation in progress, if any.
    pub busy: Option<Operation>,
    /// Epoch ms it was created.
    pub created_at: u64,
    /// The volume's size in MiB: the most the workspace can hold.
    pub disk_size_mib: u64,
    /// What the volume holds now in MiB, when known.
    pub disk_used_mib: Option<u64>,
}

impl WorkspaceRecord {
    /// A record with the defaults the fake and the tests start from.
    #[must_use]
    pub fn new(id: WorkspaceId, name: WorkspaceName, repositories: Vec<Repository>) -> Self {
        Self {
            id,
            name,
            display_name: None,
            repositories,
            start_folder: None,
            image: DEFAULT_IMAGE.to_owned(),
            memory: MemoryMib::DEFAULT,
            status: WorkspaceStatus::Created,
            busy: None,
            created_at: 0,
            disk_size_mib: DEFAULT_DISK_MIB,
            disk_used_mib: None,
        }
    }
}

impl WorkspaceRecord {
    /// What the user calls the workspace: its display name, else its name.
    #[must_use]
    pub fn label(&self) -> &str {
        self.display_name
            .as_ref()
            .map_or(self.name.as_str(), DisplayName::as_str)
    }
}

/// A name the user chose for a workspace: free text of 1 to [`DisplayName::MAX_CHARS`]
/// characters, trimmed, with no control characters (a line break included).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DisplayName(String);

impl DisplayName {
    /// Longest display name, in characters.
    pub const MAX_CHARS: usize = 60;

    /// Checks a display name.
    ///
    /// # Errors
    ///
    /// A message for the user when the name is empty, too long or has control characters.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("the name must not be empty".into());
        }
        if text.chars().count() > Self::MAX_CHARS {
            return Err(format!(
                "the name is longer than {} characters",
                Self::MAX_CHARS
            ));
        }
        if text.chars().any(char::is_control) {
            return Err("the name must not contain line breaks or control characters".into());
        }
        Ok(Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The workspace in `records` that already goes by `label`, ignoring case and `except` itself.
/// Two workspaces never share a label, so the list, the dialogs and the toasts stay unambiguous.
pub fn label_taken<'a>(
    records: impl IntoIterator<Item = &'a WorkspaceRecord>,
    label: &str,
    except: Option<&WorkspaceId>,
) -> Option<&'a WorkspaceRecord> {
    let wanted = label.to_lowercase();
    records
        .into_iter()
        .find(|r| Some(&r.id) != except && r.label().to_lowercase() == wanted)
}

/// Whether the workspace `id` may take `display_name` (or go back to its name for `None`) among
/// `records`. The one rule both services apply.
///
/// # Errors
///
/// [`WorkspaceError::NotFound`] for an unknown id; [`WorkspaceError::Conflict`] while the
/// workspace is being created or deleted (there is nothing settled to rename), or when another
/// workspace already goes by that name.
pub fn check_rename<'a>(
    records: impl IntoIterator<Item = &'a WorkspaceRecord> + Clone,
    id: &WorkspaceId,
    display_name: Option<&DisplayName>,
) -> Result<(), WorkspaceError> {
    let record = records
        .clone()
        .into_iter()
        .find(|r| &r.id == id)
        .ok_or_else(|| WorkspaceError::NotFound(format!("no workspace {id}")))?;
    if let Some(busy @ (Operation::Creating | Operation::Deleting)) = record.busy {
        return Err(WorkspaceError::Conflict(format!(
            "{} is {busy}; rename it when that is done",
            record.label()
        )));
    }
    let label = display_name.map_or(record.name.as_str(), DisplayName::as_str);
    match label_taken(records, label, Some(id)) {
        Some(other) => Err(WorkspaceError::Conflict(format!(
            "another workspace is already called {}; choose a different name",
            other.label()
        ))),
        None => Ok(()),
    }
}

/// The image a workspace gets when the request names none.
pub const DEFAULT_IMAGE: &str = "mcr.microsoft.com/devcontainers/base:debian";

/// The volume size a new workspace gets (32 GiB, sparse on the host apart from the 64 MiB journal
/// written when the volume is made).
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
                "remove the user name and password from the URL; Puddle supplies credentials itself"
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

impl fmt::Display for RepoUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One repository Puddle manages for a workspace (storage ST-40): the address it is cloned from
/// and the checkout directly under the volume root it is cloned into. Its identity and its Pull
/// and Push toggles are not part of it: they are the workspace's Git settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// Where it is cloned from.
    pub url: RepoUrl,
    /// The checkout it is cloned into.
    pub directory: CheckoutDir,
}

impl Repository {
    /// The entry for `url` in the directory `git clone` would pick (storage ST-9).
    #[must_use]
    pub fn at_default_directory(url: RepoUrl) -> Self {
        let directory = CheckoutDir::from_url(url.as_str());
        Self { url, directory }
    }
}

/// Most repositories one workspace holds (where the delete check stops counting checkouts).
pub const MAX_REPOSITORIES: usize = 100;

/// A repository a create asks for: the entry, and the Git settings it starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRepository {
    /// The entry on the workspace's list.
    pub repository: Repository,
    /// The identity the user picked for it; `None` lets Puddle choose (storage ST-44).
    pub identity: Option<IdentityId>,
    /// Pull on its new repository table row.
    pub pull: bool,
    /// Push on its new repository table row.
    pub push: bool,
}

/// A repository as a request names it, before [`check_repositories`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryDraft {
    /// The address as typed.
    pub url: String,
    /// The checkout's directory as typed; `None` takes the one the address gives.
    pub directory: Option<String>,
    /// The identity picked for it.
    pub identity: Option<IdentityId>,
    /// Pull; `None` is on.
    pub pull: Option<bool>,
    /// Push; `None` is on.
    pub push: Option<bool>,
}

/// Checks a create's repository list as a whole (storage ST-43), before anything exists. Each
/// refusal names the entry by its place in the list and its address: an address the create
/// checks refuse, a bad directory, two entries with one directory (with a free name to use
/// instead), the same repository twice in the repository table's spelling, an identity
/// `identity_exists` does not know, or more than [`MAX_REPOSITORIES`].
///
/// # Errors
///
/// The message for the user.
pub fn check_repositories(
    drafts: &[RepositoryDraft],
    identity_exists: impl Fn(IdentityId) -> bool,
) -> Result<Vec<NewRepository>, String> {
    if drafts.len() > MAX_REPOSITORIES {
        return Err(format!(
            "a workspace holds at most {MAX_REPOSITORIES} repositories; this list has {}",
            drafts.len()
        ));
    }
    let mut checked: Vec<NewRepository> = Vec::with_capacity(drafts.len());
    for (n, draft) in (1..).zip(drafts) {
        let named = |reason: &str| format!("repository {n} ({}): {reason}", shown(&draft.url));
        let url = RepoUrl::parse(&draft.url).map_err(|e| named(&e))?;
        let directory = match &draft.directory {
            Some(dir) => CheckoutDir::new(dir).map_err(|e| named(e.reason()))?,
            None => CheckoutDir::from_url(url.as_str()),
        };
        if let Some(id) = draft.identity
            && !identity_exists(id)
        {
            return Err(named(&format!("there is no identity {}", id.0)));
        }
        checked.push(NewRepository {
            repository: Repository { url, directory },
            identity: draft.identity,
            pull: draft.pull.unwrap_or(true),
            push: draft.push.unwrap_or(true),
        });
    }
    for (i, a) in checked.iter().enumerate() {
        for (j, b) in checked.iter().enumerate().skip(i + 1) {
            let (an, bn) = (i + 1, j + 1);
            if a.repository.directory == b.repository.directory {
                let dir = &a.repository.directory;
                return Err(format!(
                    "repositories {an} ({}) and {bn} ({}) both go into {dir}; give one of them \
                     another directory, such as {}",
                    a.repository.url,
                    b.repository.url,
                    free_directory(dir, &checked)
                ));
            }
            if let (Ok(ra), Ok(rb)) = (table_spelling(a), table_spelling(b))
                && ra == rb
            {
                return Err(format!(
                    "repositories {an} ({}) and {bn} ({}) are the same repository, {ra}; list it once",
                    a.repository.url, b.repository.url
                ));
            }
        }
    }
    Ok(checked)
}

/// `url` as an error message may quote it: trimmed, cut to a readable length, and with any user
/// name or password replaced by `***`, so a refusal never echoes a credential.
fn shown(url: &str) -> String {
    const MAX_SHOWN: usize = 200;
    let url = url.trim();
    let shown = match url.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            match rest.get(..end).and_then(|authority| authority.rfind('@')) {
                Some(at) => format!("{scheme}://***{}", rest.get(at..).unwrap_or_default()),
                None => url.to_owned(),
            }
        }
        None => url.to_owned(),
    };
    if shown.chars().count() > MAX_SHOWN {
        let cut: String = shown.chars().take(MAX_SHOWN).collect();
        format!("{cut}…")
    } else {
        shown
    }
}

/// How the repository table spells an entry's repository, when its address names one.
pub(crate) fn table_spelling(
    repository: &NewRepository,
) -> Result<RepoRef, puddle_store::StoreError> {
    RepoRef::from_https_url(repository.repository.url.as_str())
}

/// `<dir>-2`, `<dir>-3`, ...: the first that no entry uses (cut so it stays a valid name).
fn free_directory(dir: &CheckoutDir, taken: &[NewRepository]) -> CheckoutDir {
    (2..)
        .find_map(|n| {
            let suffix = format!("-{n}");
            let keep = CheckoutDir::MAX_LEN - suffix.len();
            let base: String = dir.as_str().chars().take(keep).collect();
            let candidate = CheckoutDir::new(&format!("{base}{suffix}")).ok()?;
            (!taken.iter().any(|t| t.repository.directory == candidate)).then_some(candidate)
        })
        .unwrap_or_else(|| dir.clone())
}

/// A start folder (storage ST-54): a relative path under the volume root, `/` between its
/// parts, no part empty, `.` or `..`, no control character or `\`, not inside `.puddle` or
/// `lost+found`, at most [`StartFolder::MAX_BYTES`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StartFolder(String);

impl StartFolder {
    /// Longest start folder, in bytes.
    pub const MAX_BYTES: usize = 255;

    /// Checks a start folder.
    ///
    /// # Errors
    ///
    /// A message for the user that says which rule the path breaks.
    pub fn parse(path: &str) -> Result<Self, String> {
        if path.is_empty() {
            return Err("the start folder must not be empty; use null for the volume root".into());
        }
        if path.len() > Self::MAX_BYTES {
            return Err(format!(
                "the start folder is longer than {} bytes",
                Self::MAX_BYTES
            ));
        }
        if path.starts_with('/') {
            return Err("the start folder is a path under the volume, without a leading /".into());
        }
        if path.chars().any(|c| c.is_control() || c == '\\') {
            return Err("the start folder must not contain control characters or \\".into());
        }
        for part in path.split('/') {
            if matches!(part, "" | "." | "..") {
                return Err(format!(
                    "the start folder has an empty, . or .. part ({path}); name each folder"
                ));
            }
        }
        let first = path.split('/').next().unwrap_or_default();
        if first == ".puddle" || first == CheckoutDir::LOST_AND_FOUND {
            return Err(format!("the start folder must not be inside {first}"));
        }
        Ok(Self(path.to_owned()))
    }

    /// The start folder of a checkout's directory.
    #[must_use]
    pub fn of_checkout(dir: &CheckoutDir) -> Self {
        Self(dir.as_str().to_owned())
    }

    /// The path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StartFolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What `create` needs. Build it from a request with [`check_repositories`] and the typed names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewWorkspace {
    /// The workspace's name; its id is derived from it.
    pub name: WorkspaceName,
    /// What to clone, in order, with the Git settings each starts with.
    pub repositories: Vec<NewRepository>,
    /// The start folder; `None` is the volume root.
    pub start_folder: Option<StartFolder>,
    /// The image, or the default.
    pub image: Option<ImageRef>,
    /// The memory, or the default.
    pub memory: Option<MemoryMib>,
}

impl NewWorkspace {
    /// A request for a workspace with the defaults.
    #[must_use]
    pub fn new(name: WorkspaceName, repositories: Vec<NewRepository>) -> Self {
        Self {
            name,
            repositories,
            start_folder: None,
            image: None,
            memory: None,
        }
    }

    /// The entries the new workspace's list holds.
    #[must_use]
    pub fn entries(&self) -> Vec<Repository> {
        self.repositories
            .iter()
            .map(|r| r.repository.clone())
            .collect()
    }
}

/// Sets up the Git settings of a new workspace's repositories (storage ST-44). A service calls
/// it once a create is accepted (the name is reserved and the workspace list saved) and before
/// the first clone, so every clone carries its credential. It reports nothing back to the
/// service: a repository it could not set up is cloned without, and the caller tells the user.
pub trait GitSetup: Send + Sync {
    /// Sets up `repositories` of `workspace`, in order.
    fn set_up<'a>(
        &'a self,
        workspace: &'a WorkspaceName,
        repositories: &'a [NewRepository],
    ) -> BoxFuture<'a, ()>;
}

/// A [`GitSetup`] that sets nothing up, for services and tests with no store.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoGitSetup;

impl GitSetup for NoGitSetup {
    fn set_up<'a>(&'a self, _: &'a WorkspaceName, _: &'a [NewRepository]) -> BoxFuture<'a, ()> {
        Box::pin(async {})
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
    /// The stopped workspace that is removed together with the workspace.
    pub removes_sandbox: Option<SandboxName>,
    /// The workspace's volume is already gone: there was nothing to inspect, and deleting loses
    /// nothing; it only drops the workspace.
    pub volume_missing: bool,
    /// A digest of exactly this report. A delete that passes it is refused when the workspace
    /// has changed since.
    pub fingerprint: String,
}

impl DeleteCheck {
    /// A report with its fingerprint computed from the findings, so every service (the real one
    /// and the fake) digests a report the same way.
    #[must_use]
    pub fn new(
        workspace: WorkspaceId,
        repos: Vec<RepoFindings>,
        other: Listing,
        errors: Vec<String>,
        removes_sandbox: Option<SandboxName>,
    ) -> Self {
        let mut check = Self {
            workspace,
            repos,
            other,
            errors,
            removes_sandbox,
            volume_missing: false,
            fingerprint: String::new(),
        };
        check.fingerprint = fingerprint(&check);
        check
    }

    /// Marks the report as one for a workspace whose volume is gone (recomputes the fingerprint,
    /// so a delete confirmed for this report is refused if the volume comes back).
    #[must_use]
    pub fn with_volume_missing(mut self) -> Self {
        self.volume_missing = true;
        self.fingerprint = fingerprint(&self);
        self
    }

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
    /// Whether Puddle opened an editor itself (desktop mode, when it worked).
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
    /// Puddle failed; the text goes to the log, not to the client.
    #[error("{0}")]
    Internal(String),
}

/// What running a shell init in a throwaway shell in the workspace showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellInitCheck {
    /// It parsed and printed nothing.
    Passed,
    /// It was not run, for the reason given (the workspace is stopped, say).
    NotRun(String),
    /// It does not parse, or printed something, or ran too long: the text says what, for the user.
    Refused(String),
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

    /// Creates a workspace: its volume, then a clone of each repository, one at a time. Once the
    /// create is accepted and before the first clone it runs `git` for the new repositories.
    /// [`WorkspaceError::Conflict`] if the name is taken. A clone that fails fails only its
    /// repository (a background problem names it); the create still ends done.
    fn create<'a>(
        &'a self,
        new: NewWorkspace,
        git: &'a dyn GitSetup,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

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

    /// Gives the workspace a display name (`None` goes back to its name). Only the label
    /// changes: the id, the name, the volume and the sandbox stay, so this works on a running
    /// workspace and does not restart anything. [`WorkspaceError::Conflict`] when another
    /// workspace already goes by that name (ignoring case), or while this one is being created
    /// or deleted.
    fn rename<'a>(
        &'a self,
        id: &'a WorkspaceId,
        display_name: Option<DisplayName>,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>>;

    /// Opens the workspace in an editor. The workspace must be running.
    fn attach<'a>(
        &'a self,
        id: &'a WorkspaceId,
        mode: AttachMode,
    ) -> BoxFuture<'a, Result<Attached, WorkspaceError>>;

    /// Runs a shell init `script` once in a throwaway shell in the running workspace `id` and says
    /// whether it parsed and printed nothing. The default does not check: a build with no guest
    /// to run it in.
    fn check_shell_init<'a>(
        &'a self,
        _id: &'a WorkspaceId,
        _script: &'a str,
    ) -> BoxFuture<'a, Result<ShellInitCheck, WorkspaceError>> {
        Box::pin(async {
            Ok(ShellInitCheck::NotRun(
                "this Puddle has no workspace to run it in".to_owned(),
            ))
        })
    }

    /// Tells the service that settings changed, so it can apply what takes effect at once (the
    /// SSH endpoint of a running workspace opens or closes with its `direct_ssh` setting).
    /// The default does nothing.
    fn settings_changed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }
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
    fn create<'a>(
        &'a self,
        _: NewWorkspace,
        _: &'a dyn GitSetup,
    ) -> BoxFuture<'a, Result<WorkspaceRecord, WorkspaceError>> {
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
    fn rename<'a>(
        &'a self,
        _: &'a WorkspaceId,
        _: Option<DisplayName>,
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
    if check.volume_missing {
        put("volume_missing");
    }
    hash.finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
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
            volume_missing: false,
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

    #[test]
    fn a_missing_volume_changes_the_fingerprint() {
        let id = WorkspaceId::new("w").unwrap();
        let plain = DeleteCheck::new(id, vec![], Listing::default(), vec![], None);
        let gone = plain.clone().with_volume_missing();
        assert!(gone.volume_missing && gone.is_clean());
        assert_ne!(plain.fingerprint, gone.fingerprint);
    }

    #[tokio::test]
    async fn the_empty_service_says_it_is_unavailable() {
        let svc = NoWorkspaces;
        let id = WorkspaceId::new("w").unwrap();
        let name = WorkspaceName::new("w").unwrap();
        let url = RepoUrl::parse("https://example.com/a").unwrap();
        let repos = vec![NewRepository {
            repository: Repository::at_default_directory(url),
            identity: None,
            pull: true,
            push: true,
        }];
        let all = [
            svc.list().await.map(|_| ()),
            svc.get(&id).await.map(|_| ()),
            svc.create(NewWorkspace::new(name, repos), &NoGitSetup)
                .await
                .map(|_| ()),
            svc.start(&id).await.map(|_| ()),
            svc.stop(&id).await.map(|_| ()),
            svc.reclaim(&id).await.map(|_| ()),
            svc.delete_check(&id).await.map(|_| ()),
            svc.delete(&id, None).await.map(|_| ()),
            svc.rename(&id, None).await.map(|_| ()),
            svc.attach(&id, AttachMode::Browser).await.map(|_| ()),
        ];
        for result in all {
            assert!(matches!(result, Err(WorkspaceError::Unavailable(_))));
        }
    }

    #[tokio::test]
    async fn a_service_with_no_guest_does_not_check_shell_init() {
        let id = WorkspaceId::new("w").unwrap();
        let check = NoWorkspaces.check_shell_init(&id, "echo hi\n").await;
        assert!(
            matches!(check, Ok(ShellInitCheck::NotRun(ref why)) if why.contains("no workspace")),
            "{check:?}"
        );
    }

    #[test]
    fn display_names_are_trimmed_and_bounded() {
        assert_eq!(
            DisplayName::parse("  Web shop ").unwrap().as_str(),
            "Web shop"
        );
        assert_eq!(
            DisplayName::parse("Café 日本").unwrap().as_str(),
            "Café 日本"
        );
        assert!(DisplayName::parse("a".repeat(60).as_str()).is_ok());
        for (bad, wants) in [
            ("", "empty"),
            ("   ", "empty"),
            (&"a".repeat(61), "longer than 60"),
            ("two\nlines", "line breaks"),
            ("tab\there", "control"),
        ] {
            let err = DisplayName::parse(bad).unwrap_err();
            assert!(err.contains(wants), "{bad:?}: {err}");
        }
        // Sixty multi-byte characters are within the limit: it counts characters, not bytes.
        assert!(DisplayName::parse(&"é".repeat(60)).is_ok());
    }

    #[test]
    fn a_label_is_taken_ignoring_case_and_the_workspace_itself() {
        let mk = |id: &str, shown: Option<&str>| {
            let mut r = WorkspaceRecord::new(
                WorkspaceId::new(id).unwrap(),
                WorkspaceName::new(id).unwrap(),
                Vec::new(),
            );
            r.display_name = shown.map(|s| DisplayName::parse(s).unwrap());
            r
        };
        let all = [mk("alpha", None), mk("beta", Some("Web Shop"))];
        assert_eq!(all[1].label(), "Web Shop");
        assert_eq!(all[0].label(), "alpha");
        let beta = WorkspaceId::new("beta").unwrap();
        assert_eq!(label_taken(&all, "web shop", None).unwrap().id, beta);
        assert_eq!(
            label_taken(&all, "ALPHA", None).unwrap().name.as_str(),
            "alpha"
        );
        assert!(label_taken(&all, "web shop", Some(&beta)).is_none());
        // A workspace that was renamed no longer goes by its old name.
        assert!(label_taken(&all, "beta", None).is_none());
    }

    #[test]
    fn a_rename_is_refused_while_creating_or_deleting_and_on_a_clash() {
        let mk = |id: &str| {
            WorkspaceRecord::new(
                WorkspaceId::new(id).unwrap(),
                WorkspaceName::new(id).unwrap(),
                Vec::new(),
            )
        };
        let (mut a, b) = (mk("alpha"), mk("beta"));
        let name = |s: &str| Some(DisplayName::parse(s).unwrap());
        let ida = a.id.clone();
        let check = |a: &WorkspaceRecord, to: Option<&DisplayName>| check_rename([a, &b], &ida, to);
        assert!(check(&a, name("Web").as_ref()).is_ok());
        assert!(
            check(&a, name("alpha").as_ref()).is_ok(),
            "its own name is not a clash"
        );
        assert!(matches!(
            check(&a, name("BETA").as_ref()),
            Err(WorkspaceError::Conflict(m)) if m.contains("already called beta")
        ));
        a.busy = Some(Operation::Creating);
        assert!(
            matches!(check(&a, None), Err(WorkspaceError::Conflict(m)) if m.contains("creating"))
        );
        a.busy = Some(Operation::Deleting);
        assert!(matches!(check(&a, None), Err(WorkspaceError::Conflict(_))));
        for busy in [
            Operation::Starting,
            Operation::Stopping,
            Operation::Reclaiming,
        ] {
            a.busy = Some(busy);
            assert!(check(&a, name("Web").as_ref()).is_ok(), "{busy}");
        }
        let missing = WorkspaceId::new("nope").unwrap();
        assert!(matches!(
            check_rename([&a, &b], &missing, None),
            Err(WorkspaceError::NotFound(_))
        ));
    }

    fn draft(url: &str) -> RepositoryDraft {
        RepositoryDraft {
            url: url.to_owned(),
            ..RepositoryDraft::default()
        }
    }

    #[test]
    fn a_repository_list_takes_defaults_and_keeps_its_order() {
        let checked = check_repositories(
            &[
                draft("https://github.com/acme/api.git"),
                RepositoryDraft {
                    directory: Some("site".into()),
                    identity: Some(IdentityId(4)),
                    pull: Some(false),
                    ..draft("https://github.com/acme/web")
                },
            ],
            |id| id == IdentityId(4),
        )
        .unwrap();
        let shape: Vec<_> = checked
            .iter()
            .map(|r| {
                (
                    r.repository.url.as_str(),
                    r.repository.directory.as_str(),
                    r.identity,
                    r.pull,
                    r.push,
                )
            })
            .collect();
        assert_eq!(
            shape,
            [
                ("https://github.com/acme/api.git", "api", None, true, true),
                (
                    "https://github.com/acme/web",
                    "site",
                    Some(IdentityId(4)),
                    false,
                    true
                ),
            ]
        );
        assert_eq!(check_repositories(&[], |_| false).unwrap(), []);
    }

    #[test]
    fn a_repository_list_is_refused_naming_the_entry() {
        let refused =
            |drafts: &[RepositoryDraft]| check_repositories(drafts, |_| false).unwrap_err();
        let clash = refused(&[
            draft("https://github.com/acme/api"),
            draft("https://github.com/acme/web"),
            draft("https://gitlab.com/other/api.git"),
        ]);
        assert_eq!(
            clash,
            "repositories 1 (https://github.com/acme/api) and 3 (https://gitlab.com/other/api.git) \
             both go into api; give one of them another directory, such as api-2"
        );
        let taken = refused(&[
            draft("https://github.com/acme/api"),
            RepositoryDraft {
                directory: Some("api-2".into()),
                ..draft("https://github.com/acme/web")
            },
            draft("https://gitlab.com/other/api.git"),
        ]);
        assert!(taken.ends_with("such as api-3"), "{taken}");
        let twice = refused(&[
            draft("https://github.com/Acme/API.git"),
            RepositoryDraft {
                directory: Some("again".into()),
                ..draft("https://github.com/acme/api/")
            },
        ]);
        assert_eq!(
            twice,
            "repositories 1 (https://github.com/Acme/API.git) and 2 (https://github.com/acme/api/) \
             are the same repository, github.com/acme/api; list it once"
        );
        let ghost = refused(&[
            draft("https://github.com/acme/api"),
            RepositoryDraft {
                identity: Some(IdentityId(9)),
                ..draft("https://github.com/acme/web")
            },
        ]);
        assert_eq!(
            ghost,
            "repository 2 (https://github.com/acme/web): there is no identity 9"
        );
        let ssh = refused(&[draft("git@github.com:acme/api.git")]);
        assert!(
            ssh.starts_with("repository 1 (git@github.com:acme/api.git): SSH remotes"),
            "{ssh}"
        );
        let bad_dir = refused(&[RepositoryDraft {
            directory: Some("../up".into()),
            ..draft("https://github.com/acme/api")
        }]);
        assert!(bad_dir.contains("must not start with"), "{bad_dir}");
        let many: Vec<_> = (0..=MAX_REPOSITORIES)
            .map(|n| draft(&format!("https://github.com/acme/r{n}")))
            .collect();
        assert_eq!(
            refused(&many),
            "a workspace holds at most 100 repositories; this list has 101"
        );
        assert!(check_repositories(&many[..MAX_REPOSITORIES], |_| false).is_ok());
    }

    #[test]
    fn a_refused_address_is_named_without_its_credentials() {
        let err = check_repositories(&[draft("  https://me:tok@github.com/a/b  ")], |_| false)
            .unwrap_err();
        assert!(
            err.starts_with("repository 1 (https://***@github.com/a/b): remove the user name"),
            "{err}"
        );
        assert!(!err.contains("tok"), "{err}");
        let long = format!("https://github.com/{}", "a".repeat(3000));
        let err = check_repositories(&[draft(&long)], |_| false).unwrap_err();
        assert!(err.len() < 400, "{}", err.len());
    }

    #[test]
    fn a_long_directory_still_gets_a_free_name_that_fits() {
        let long = "a".repeat(CheckoutDir::MAX_LEN);
        let refused = check_repositories(
            &[
                RepositoryDraft {
                    directory: Some(long.clone()),
                    ..draft("https://github.com/acme/one")
                },
                RepositoryDraft {
                    directory: Some(long.clone()),
                    ..draft("https://github.com/acme/two")
                },
            ],
            |_| false,
        )
        .unwrap_err();
        let suggested = refused.rsplit(' ').next().unwrap();
        assert_eq!(suggested, format!("{}-2", "a".repeat(98)));
    }

    #[test]
    fn a_start_folder_is_a_plain_path_under_the_volume() {
        for ok in ["api", "api/src", "web site/app", "a.b/c_d"] {
            assert_eq!(StartFolder::parse(ok).unwrap().as_str(), ok);
        }
        assert!(StartFolder::parse(&"a".repeat(255)).is_ok());
        for (bad, why) in [
            ("", "empty"),
            ("/api", "leading /"),
            ("api/", "empty, . or .."),
            ("a//b", "empty, . or .."),
            ("./api", "empty, . or .."),
            ("api/../..", "empty, . or .."),
            ("..", "empty, . or .."),
            ("a\\b", "control characters"),
            ("a\nb", "control characters"),
            (".puddle", "inside .puddle"),
            (".puddle/editor", "inside .puddle"),
            ("lost+found/x", "inside lost+found"),
            (&"a".repeat(256), "255 bytes"),
        ] {
            let err = StartFolder::parse(bad).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
        assert_eq!(
            StartFolder::of_checkout(&CheckoutDir::new("src").unwrap()).as_str(),
            "src"
        );
    }

    #[test]
    fn operations_have_wire_names() {
        assert_eq!(Operation::Reclaiming.to_string(), "reclaiming");
        assert_eq!(Operation::Deleting.to_string(), "deleting");
    }
}
