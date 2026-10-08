// SPDX-License-Identifier: GPL-3.0-or-later
//! The injector for one workspace: what happens to each request on a decrypted Git host.
//!
//! In order, for a request that reads as a Git request (anything else passes through untouched):
//!
//! 1. A path that names a repository in more than one way is refused (`400`).
//! 2. The workspace's repository table is applied: a push to a repository without Push, or, when
//!    the workspace asks for it, a fetch from one without Pull, is refused (`403`) with a one-line
//!    message and an event the UI turns into an "add it" notice. This holds whoever supplies the
//!    credential.
//! 3. A request that carries its own `Authorization` goes out as it is: never replaced, never
//!    dropped, and a `401` to it is the server's answer.
//! 4. Otherwise the identity that covers the repository's owner supplies the credential. No
//!    covering identity: the request goes out without one and the server's `401` is its answer. A
//!    source that cannot supply the secret: `502` and a sign-in notice. A `401` to the credential
//!    puddle added becomes a `403`: the workspace holds no credential to answer it with.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use puddle_proxy::{
    BoxFuture, InjectContext, InjectDecision, InjectRefusal, InjectedHeader, Injection, Injector,
    RequestView, Unauthorized,
};
use puddle_secrets::SourceSpec;
use puddle_store::{CredentialBinding, CredentialChoice, Identity, WorkspaceGit};
use puddle_types::{Event, EventSink, GitAccess, WorkspaceName};
use tokio::time::Instant;

use crate::git_path::{Access, Classified, GitPath, classify};
use crate::header::authorization;
use crate::source::{CredentialSource, GitSettings};

/// The most request body read to tell an LFS download from an upload. A batch of a hundred
/// objects is about 10 KiB.
const MAX_LFS_BATCH: usize = 256 * 1024;

/// What the guest reads when the store offers a way to choose that this reading does not know.
const UNCHOOSABLE: &str = "puddle could not choose a credential for this request";

/// A notice about the same thing is raised at most once in this long, however many requests
/// meet it (a Git client retries).
const NOTICE_EVERY: Duration = Duration::from_secs(10);

/// Most notices remembered.
const MAX_NOTICES: usize = 256;

/// The injector of one workspace.
pub struct GitInjector {
    workspace: WorkspaceName,
    settings: Arc<dyn GitSettings>,
    credentials: Arc<dyn CredentialSource>,
    events: Arc<dyn EventSink>,
    notices: Arc<Notices>,
}

impl fmt::Debug for GitInjector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitInjector")
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

impl GitInjector {
    /// The injector of `workspace`, reading its Git `settings` and the secrets its identities name
    /// from `credentials`, and raising notices on `events`.
    #[must_use]
    pub fn new(
        workspace: WorkspaceName,
        settings: Arc<dyn GitSettings>,
        credentials: Arc<dyn CredentialSource>,
        events: Arc<dyn EventSink>,
    ) -> Self {
        Self {
            workspace,
            settings,
            credentials,
            events,
            notices: Arc::new(Notices::default()),
        }
    }

    async fn decide_git(
        &self,
        context: &InjectContext<'_>,
        request: &RequestView<'_>,
    ) -> InjectDecision {
        let host = context.host.to_string();
        let path = match classify(&host, request.method(), request.path(), request.query()) {
            Classified::NotGit => return InjectDecision::PassThrough,
            Classified::Ambiguous(why) => {
                return refuse(
                    400,
                    "bad_git_path",
                    format!(
                        "this request names a Git repository in a way puddle cannot read safely ({why}); nothing was sent to {host}. Use the repository's plain address"
                    ),
                );
            }
            Classified::Git(path) => path,
        };
        let git = match self.settings.current().await {
            Ok(git) => git,
            Err(err) => {
                tracing::warn!(workspace = %self.workspace, error = %err, "the Git settings could not be read");
                return refuse(
                    502,
                    "git_settings_unavailable",
                    format!(
                        "puddle could not read this workspace's Git settings ({err}); nothing was sent to {host}"
                    ),
                );
            }
        };
        let access = match path.access {
            Access::Pull => GitAccess::Pull,
            Access::Push => GitAccess::Push,
            Access::Batch => batch_access(request.body()),
        };
        if let Some(refusal) = self.check_table(&git, &path, access) {
            return InjectDecision::Refuse(refusal);
        }
        if request.header("authorization").is_some() {
            return InjectDecision::PassThrough;
        }
        match covering(&git, &path) {
            CredentialChoice::Covered {
                identity, binding, ..
            } => self.inject(identity, binding, &path).await,
            // No identity covers it: it goes out as the workspace sent it, so a token the workspace
            // supplies after the server's `401` (a credential helper, `.netrc`, the address's user
            // name and password) is used as it would be without puddle.
            CredentialChoice::Uncovered => {
                tracing::info!(
                    workspace = %self.workspace,
                    owner = %format!("{}/{}", path.host, path.owner),
                    "no identity covers this owner; the request goes out without a credential"
                );
                InjectDecision::PassThrough
            }
            CredentialChoice::Ambiguous(ids) => {
                let labels = git
                    .identities
                    .iter()
                    .filter(|identity| ids.contains(&identity.id))
                    .map(|identity| identity.label.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ");
                refuse(
                    409,
                    "credential_ambiguous",
                    format!(
                        "{labels} both cover {}/{}; narrow one in puddle",
                        path.host, path.owner
                    ),
                )
            }
            // A choice a later puddle adds: nothing it says is trusted.
            _ => refuse(502, "credential_unavailable", UNCHOOSABLE),
        }
    }

    /// The refusal for a push or fetch the workspace's table does not allow, with the event that
    /// lets the user add the repository.
    fn check_table(
        &self,
        git: &WorkspaceGit,
        path: &GitPath,
        access: GitAccess,
    ) -> Option<InjectRefusal> {
        let repo = path.repo_ref();
        let allowed = match (access, &repo) {
            (GitAccess::Push, Some(repo)) => git.allows_push(repo),
            (GitAccess::Pull, Some(repo)) => git.allows_pull(repo),
            (GitAccess::Push, None) => !git.only_push_listed,
            (GitAccess::Pull, None) => !git.only_pull_listed,
        };
        if allowed {
            return None;
        }
        let (code, verb, list, switch) = match access {
            GitAccess::Push => (
                "push_denied",
                "push to",
                "push",
                "Only push to listed repos",
            ),
            GitAccess::Pull => (
                "pull_denied",
                "pull from",
                "pull",
                "Only pull from listed repos",
            ),
        };
        let what = path.describe();
        let message = match &repo {
            Some(repo) => {
                if self.notices.first(format!("{code}:{repo}")) {
                    self.events.emit(Event::GitAccessDenied {
                        workspace: self.workspace.clone(),
                        host: repo.host.to_string(),
                        owner: repo.owner.to_string(),
                        repo: repo.repo.clone(),
                        access,
                    });
                }
                format!(
                    "{verb} {what} is not on this workspace's {list} list; add it, or turn off \"{switch}\" on the workspace's Git tab"
                )
            }
            None => format!(
                "{verb} {what} is not allowed: the repository list cannot hold this name, so turn off \"{switch}\" on the workspace's Git tab"
            ),
        };
        tracing::info!(workspace = %self.workspace, code, repo = %what, "refused by the repository list");
        Some(InjectRefusal::new(403, code, message))
    }

    /// Adds `identity`'s credential for `path`.
    async fn inject(
        &self,
        identity: &Identity,
        binding: &CredentialBinding,
        path: &GitPath,
    ) -> InjectDecision {
        let source = &binding.source;
        let named = format!("{}/{}", path.host, path.owner);
        // The token is checked against where it is about to go, as its source asks.
        let scope = source.scope();
        let right_place = scope
            .host
            .as_str()
            .eq_ignore_ascii_case(binding.host.as_str())
            && scope
                .org
                .as_ref()
                .is_none_or(|org| org.as_str().eq_ignore_ascii_case(&path.owner));
        if !right_place {
            tracing::warn!(workspace = %self.workspace, identity = %identity.label, "a stored credential is not for the place it covers");
            return refuse(
                502,
                "credential_unavailable",
                format!(
                    "the credential of identity {} is not for {named}; fix the identity in puddle",
                    identity.label
                ),
            );
        }
        let credential = match self.credentials.credential(source).await {
            Ok(credential) => credential,
            Err(err) => {
                tracing::info!(workspace = %self.workspace, source = %source.describe(), "the credential could not be read: {err}");
                let advice = if err.needs_sign_in() {
                    if self.notices.first(format!("sign_in:{}", source.describe())) {
                        self.events.emit(Event::CredentialSignInNeeded {
                            host: path.credential_host.clone(),
                            source: source.describe(),
                        });
                    }
                    "sign in to it in puddle"
                } else {
                    "check it in puddle"
                };
                return refuse(
                    502,
                    "credential_unavailable",
                    format!(
                        "the credential of identity {} for {named} ({}) is not available: {err}; {advice}",
                        identity.label,
                        source.describe()
                    ),
                );
            }
        };
        let value = authorization(&path.credential_host, credential.secret.expose());
        let Ok(header) = InjectedHeader::new("authorization", value) else {
            return refuse(
                502,
                "credential_unavailable",
                format!(
                    "the credential of identity {} for {named} is not a usable header value; replace it in puddle",
                    identity.label
                ),
            );
        };
        let injection = Injection::new(
            format!("identity:{}:{}", identity.id, binding.host),
            vec![header],
        );
        InjectDecision::Inject(injection.on_unauthorized(self.rejected(identity, source, path)))
    }

    /// What a `401` to the credential puddle added becomes.
    fn rejected(&self, identity: &Identity, source: &SourceSpec, path: &GitPath) -> Unauthorized {
        let credentials = Arc::clone(&self.credentials);
        let events = Arc::clone(&self.events);
        let notices = Arc::clone(&self.notices);
        let (source, label) = (source.clone(), identity.label.clone());
        let (host, named) = (
            path.credential_host.clone(),
            format!("{}/{}", path.host, path.owner),
        );
        Unauthorized::new(move || {
            // The user may have signed in again since the token was read.
            credentials.forget(&source);
            if notices.first(format!("sign_in:{}", source.describe())) {
                events.emit(Event::CredentialSignInNeeded {
                    host: host.clone(),
                    source: source.describe(),
                });
            }
            InjectRefusal::new(
                403,
                "credential_rejected",
                format!(
                    "{host} did not accept the credential of identity {label} ({}) for {named}; sign in again or check that the token can reach it, in puddle",
                    source.describe()
                ),
            )
        })
    }
}

impl Injector for GitInjector {
    fn decide<'a>(
        &'a self,
        context: &'a InjectContext<'a>,
        request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision> {
        Box::pin(self.decide_git(context, request))
    }

    fn body_wanted(&self, context: &InjectContext<'_>, request: &RequestView<'_>) -> Option<usize> {
        let host = context.host.to_string();
        match classify(&host, request.method(), request.path(), request.query()) {
            Classified::Git(GitPath {
                access: Access::Batch,
                ..
            }) => Some(MAX_LFS_BATCH),
            _ => None,
        }
    }
}

fn refuse(status: u16, code: &'static str, message: impl Into<String>) -> InjectDecision {
    InjectDecision::Refuse(InjectRefusal::new(status, code, message))
}

/// What an LFS batch request asks for: a download is a read, every other `operation` (and a body
/// that cannot be read) is a write.
fn batch_access(body: Option<&[u8]>) -> GitAccess {
    let operation = body
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .and_then(|json| {
            json.get("operation")
                .and_then(|o| o.as_str().map(str::to_owned))
        });
    if operation.as_deref() == Some("download") {
        GitAccess::Pull
    } else {
        GitAccess::Push
    }
}

/// The credential that covers `path`: by the host the credential is for (`dev.azure.com` for every
/// Azure DevOps name), and, failing that, by the host asked for.
fn covering<'a>(git: &'a WorkspaceGit, path: &GitPath) -> CredentialChoice<'a> {
    let choice = git.credential_for(&path.credential_host, &path.owner);
    if matches!(choice, CredentialChoice::Uncovered) && path.host != path.credential_host {
        return git.credential_for(&path.host, &path.owner);
    }
    choice
}

/// Which notices were raised lately.
#[derive(Debug, Default)]
struct Notices {
    last: Mutex<HashMap<String, Instant>>,
}

impl Notices {
    /// Whether `key` has not been raised in the last [`NOTICE_EVERY`]; counts it as raised.
    fn first(&self, key: String) -> bool {
        let now = Instant::now();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.len() >= MAX_NOTICES {
            last.retain(|_, at| now.duration_since(*at) < NOTICE_EVERY);
            if last.len() >= MAX_NOTICES {
                // A flood of different notices is not a flood of events.
                return false;
            }
        }
        match last.get(&key) {
            Some(at) if now.duration_since(*at) < NOTICE_EVERY => false,
            _ => {
                last.insert(key, now);
                true
            }
        }
    }
}
