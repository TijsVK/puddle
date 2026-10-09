// SPDX-License-Identifier: GPL-3.0-or-later
//! What a listing is made of: repositories, why a list could not be read, and notes about what a
//! list leaves out. Names and URLs only; nothing here holds a secret.

use std::sync::Arc;

use puddle_secrets::SourceError;
use puddle_store::IdentityId;

/// Who can see a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Visibility {
    /// Anyone.
    Public,
    /// Only people it is shared with.
    Private,
    /// Everyone in the organisation (GitHub Enterprise).
    Internal,
    /// The host did not say.
    Unknown,
}

/// What the account that listed a repository can do in it, as the host reports it. A fine-grained
/// token can hold less than the account's role; the host does not say, so this is "your role".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// Full control.
    Admin,
    /// Manages the repository without the destructive settings.
    Maintain,
    /// Can push.
    Write,
    /// Can manage issues and pull requests.
    Triage,
    /// Can read.
    Read,
    /// The host did not say (Azure DevOps does not).
    Unknown,
}

/// One repository a credential can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// The Git host (`github.com`, `dev.azure.com`).
    pub host: String,
    /// The user or organisation that owns it; for Azure DevOps, the organisation.
    pub owner: String,
    /// The Azure DevOps project; `None` elsewhere.
    pub project: Option<String>,
    /// The repository's own name.
    pub name: String,
    /// `owner/name`, or `organisation/project/name` on Azure DevOps. What a search matches.
    pub full_name: String,
    /// The HTTPS address to clone, without a user name.
    pub url: String,
    /// Who can see it.
    pub visibility: Visibility,
    /// What the account can do in it.
    pub role: Role,
    /// Whether it is archived (read-only).
    pub archived: bool,
    /// Whether it is a fork.
    pub fork: bool,
}

impl Repository {
    /// The spelling two lists agree on: the address, lower case.
    #[must_use]
    pub fn key(&self) -> String {
        self.url.to_ascii_lowercase()
    }
}

/// Why a list could not be read, or could not be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    /// The source has no login: sign in.
    NotSignedIn,
    /// The source could not be run (tool missing, credential store unavailable, answer unusable).
    SourceUnavailable,
    /// The host refused the token (expired, revoked or wrong).
    TokenRejected,
    /// The host knows the token and says it may not do this.
    Forbidden,
    /// There is no such organisation or listing, or the token cannot see it.
    NotFound,
    /// The host's rate limit: nothing is asked before `retry_at`.
    RateLimited,
    /// The host could not be reached.
    Unreachable,
    /// The host answered something this version does not understand.
    BadAnswer,
    /// puddle lists repositories for GitHub and Azure DevOps only.
    Unsupported,
    /// An Azure DevOps credential that names no organisation.
    OrganisationNeeded,
    /// The credential is for another host or organisation than the one asked.
    WrongTarget,
}

/// A reason in words, with what the user can do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The class of the problem, for a client to switch on.
    pub kind: ProblemKind,
    /// The reason, for the user: what happened and the way out. Never a secret.
    pub message: String,
    /// When asking again is allowed (epoch milliseconds), for a rate limit.
    pub retry_at: Option<u64>,
    /// Whether signing in again is the way out.
    pub needs_sign_in: bool,
}

impl Problem {
    pub(crate) fn new(kind: ProblemKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            retry_at: None,
            needs_sign_in: matches!(kind, ProblemKind::NotSignedIn),
        }
    }

    pub(crate) fn from_source(err: &SourceError) -> Self {
        let message = match err {
            SourceError::NotSignedIn => "not signed in, or the sign-in has expired".to_owned(),
            SourceError::Timeout(tool) => format!(
                "{} did not answer in time; it may be waiting for a sign-in",
                tool.name()
            ),
            other => other.to_string(),
        };
        let kind = if err.needs_sign_in() {
            ProblemKind::NotSignedIn
        } else {
            ProblemKind::SourceUnavailable
        };
        Self::new(kind, message)
    }

    pub(crate) fn unreachable(why: impl std::fmt::Display) -> Self {
        Self::new(
            ProblemKind::Unreachable,
            format!("the host could not be reached: {why}"),
        )
    }

    pub(crate) fn bad_answer(what: impl std::fmt::Display) -> Self {
        Self::new(
            ProblemKind::BadAnswer,
            format!("the host answered something puddle does not understand: {what}"),
        )
    }
}

/// What a list leaves out or how to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoteKind {
    /// GitHub says organisations that require SAML single sign-on are missing from this list.
    SsoPartial,
    /// A sign-in through an app (`gh`, Git Credential Manager) cannot see organisations that
    /// restrict third-party apps or require single sign-on until the user approves it there.
    OrganisationsMayBeHidden,
    /// A fine-grained token lists only the repositories it was granted.
    FineGrainedToken,
    /// More repositories exist than puddle reads.
    Truncated,
    /// The account's author cannot be read from this host.
    AuthorUnavailable,
    /// The account's organisations could not be listed.
    OrganisationsUnavailable,
}

/// A fact about a list or a profile, in words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The class of the note.
    pub kind: NoteKind,
    /// The note, for the user.
    pub message: String,
}

impl Note {
    pub(crate) fn new(kind: NoteKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// What one read of a credential's list found.
#[derive(Debug)]
pub(crate) struct Listed {
    pub(crate) repos: Vec<Repository>,
    pub(crate) notes: Vec<Note>,
    /// Set when the answer used up the hour's budget: nothing more is asked until then.
    pub(crate) spent_until: Option<u64>,
}

/// How current a list is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListState {
    /// Read, and the newest read worked.
    Ok,
    /// An earlier read is shown; the newest could not be done and `problem` says why.
    Stale,
    /// Nothing was read yet and the attempt failed; `problem` says why.
    Failed,
    /// This credential cannot be listed by design; `problem` says why.
    Unavailable,
}

/// One credential's list (for an Azure DevOps credential, one organisation's), with how current
/// it is. A screen shows `refreshed_at` and the problem; an empty `repos` with no problem means
/// the account reaches no repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceList {
    /// The identity that holds the credential.
    pub identity: IdentityId,
    /// The credential's place in that identity's list.
    pub credential: usize,
    /// The credential's host.
    pub host: String,
    /// The Azure DevOps organisation this list is for.
    pub organisation: Option<String>,
    /// How current it is.
    pub state: ListState,
    /// When it was read (epoch milliseconds); `None` when it never was.
    pub refreshed_at: Option<u64>,
    /// When the host lets puddle ask again (epoch milliseconds), when it said to wait.
    pub retry_at: Option<u64>,
    /// Why the newest read is missing or failed.
    pub problem: Option<Problem>,
    /// What the list leaves out.
    pub notes: Vec<Note>,
    /// The repositories, in the host's name order.
    pub repos: Arc<[Repository]>,
}

/// What a credential's account is, to prefill an identity: the commit author and the
/// organisations to offer as coverage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    /// The account name on the host.
    pub account: Option<String>,
    /// The display name, the author's name.
    pub name: Option<String>,
    /// The address commits use (the host's private no-reply address on GitHub).
    pub email: Option<String>,
    /// The organisations the account belongs to, in the host's order.
    pub organisations: Vec<String>,
    /// What is missing or limited.
    pub notes: Vec<Note>,
}
