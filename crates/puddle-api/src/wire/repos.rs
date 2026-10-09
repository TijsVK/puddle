// SPDX-License-Identifier: GPL-3.0-or-later
//! The repositories an identity's credentials reach, and who a credential's account is
//! (credentials spec §8). One list serves the Identities tab and the create form. Names, URLs and
//! reasons only: nothing here carries a secret.

use puddle_repos::{
    ListState, Note, NoteKind, Problem, ProblemKind, Profile, ProfileRead, Repository, Role,
    SourceList, Visibility, listing::Found,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::identities::CredentialSource;

/// How current one credential's list is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoListState {
    /// Read, and the newest read worked.
    Ok,
    /// An earlier read is shown; the newest could not be done and `problem` says why.
    Stale,
    /// Nothing was read and the attempt failed; `problem` says why.
    Failed,
    /// This credential cannot be listed by design; `problem` says why (an empty list is never
    /// the answer to that).
    Unavailable,
}

impl From<ListState> for RepoListState {
    fn from(state: ListState) -> Self {
        match state {
            ListState::Ok => Self::Ok,
            ListState::Stale => Self::Stale,
            ListState::Failed => Self::Failed,
            ListState::Unavailable => Self::Unavailable,
        }
    }
}

/// Why a list or a profile could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoProblemCode {
    /// The source has no login: sign in.
    NotSignedIn,
    /// The source could not be run (a tool is missing, the credential store is unavailable).
    SourceUnavailable,
    /// The host did not accept the token (expired, revoked or wrong).
    TokenRejected,
    /// The host knows the token and refuses this.
    Forbidden,
    /// There is no such organisation or listing, or the token cannot see it.
    NotFound,
    /// The host limits requests; nothing is asked before `retry_at`.
    RateLimited,
    /// The host could not be reached.
    Unreachable,
    /// The host answered something this version does not understand.
    BadAnswer,
    /// puddle lists repositories on GitHub and Azure DevOps only.
    Unsupported,
    /// An Azure DevOps credential that names no organisation.
    OrganisationNeeded,
    /// The credential is for another host or organisation than the one asked.
    WrongTarget,
}

impl From<ProblemKind> for RepoProblemCode {
    fn from(kind: ProblemKind) -> Self {
        match kind {
            ProblemKind::NotSignedIn => Self::NotSignedIn,
            ProblemKind::SourceUnavailable => Self::SourceUnavailable,
            ProblemKind::TokenRejected => Self::TokenRejected,
            ProblemKind::Forbidden => Self::Forbidden,
            ProblemKind::NotFound => Self::NotFound,
            ProblemKind::RateLimited => Self::RateLimited,
            ProblemKind::Unreachable => Self::Unreachable,
            ProblemKind::BadAnswer => Self::BadAnswer,
            ProblemKind::Unsupported => Self::Unsupported,
            ProblemKind::OrganisationNeeded => Self::OrganisationNeeded,
            ProblemKind::WrongTarget => Self::WrongTarget,
        }
    }
}

/// A reason in words, with what to do about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoProblem {
    /// The class of the problem.
    pub code: RepoProblemCode,
    /// What happened and the way out. Never a secret.
    pub message: String,
    /// Whether signing in again is the way out.
    pub needs_sign_in: bool,
}

impl From<&Problem> for RepoProblem {
    fn from(problem: &Problem) -> Self {
        Self {
            code: problem.kind.into(),
            message: problem.message.clone(),
            needs_sign_in: problem.needs_sign_in,
        }
    }
}

/// What a list or a profile leaves out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoNoteCode {
    /// GitHub says organisations that require single sign-on are missing from this list.
    SsoPartial,
    /// A sign-in through an app can miss organisations that restrict third-party apps or require
    /// single sign-on.
    OrganisationsMayBeHidden,
    /// A fine-grained token lists only the repositories it was granted.
    FineGrainedToken,
    /// More repositories exist than puddle reads.
    Truncated,
    /// The account's author cannot be read from this host: enter it yourself.
    AuthorUnavailable,
    /// The account's organisations could not be listed.
    OrganisationsUnavailable,
    /// The host's request limit for this hour is used up: a refresh waits until `retry_at`.
    HostLimitReached,
}

impl From<NoteKind> for RepoNoteCode {
    fn from(kind: NoteKind) -> Self {
        match kind {
            NoteKind::SsoPartial => Self::SsoPartial,
            NoteKind::OrganisationsMayBeHidden => Self::OrganisationsMayBeHidden,
            NoteKind::FineGrainedToken => Self::FineGrainedToken,
            NoteKind::Truncated => Self::Truncated,
            NoteKind::AuthorUnavailable => Self::AuthorUnavailable,
            NoteKind::OrganisationsUnavailable => Self::OrganisationsUnavailable,
            NoteKind::HostLimitReached => Self::HostLimitReached,
        }
    }
}

/// A fact about a list or a profile, in words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoNote {
    /// The class of the note.
    pub code: RepoNoteCode,
    /// The note for the user.
    pub message: String,
}

impl From<&Note> for RepoNote {
    fn from(note: &Note) -> Self {
        Self {
            code: note.kind.into(),
            message: note.message.clone(),
        }
    }
}

/// One credential's list (for an Azure DevOps credential, one organisation's) and how current it
/// is. An empty list with no problem means the account reaches no repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoSource {
    /// The identity that holds the credential.
    pub identity_id: i64,
    /// The credential's place in that identity's list (from 0).
    pub credential: u32,
    /// The credential's host.
    pub host: String,
    /// The Azure DevOps organisation this list is for; `null` elsewhere.
    #[schema(required = true)]
    pub organisation: Option<String>,
    /// How current the list is.
    pub state: RepoListState,
    /// Epoch ms the list was read; `null` when it never was.
    #[schema(required = true)]
    pub refreshed_at: Option<u64>,
    /// Epoch ms the host lets puddle ask again, when it said to wait.
    #[schema(required = true)]
    pub retry_at: Option<u64>,
    /// Why the newest read is missing or failed; `null` when it worked.
    #[schema(required = true)]
    pub problem: Option<RepoProblem>,
    /// What the list leaves out.
    pub notes: Vec<RepoNote>,
    /// How many repositories the list holds.
    pub repo_count: u32,
}

impl RepoSource {
    pub(crate) fn from_list(list: &SourceList) -> Self {
        Self {
            identity_id: list.identity.0,
            credential: u32::try_from(list.credential).unwrap_or(u32::MAX),
            host: list.host.clone(),
            organisation: list.organisation.clone(),
            state: list.state.into(),
            refreshed_at: list.refreshed_at,
            retry_at: list.retry_at,
            problem: list.problem.as_ref().map(RepoProblem::from),
            notes: list.notes.iter().map(RepoNote::from).collect(),
            repo_count: u32::try_from(list.repos.len()).unwrap_or(u32::MAX),
        }
    }
}

/// Who can see a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoVisibility {
    /// Anyone.
    Public,
    /// Only people it is shared with.
    Private,
    /// Everyone in the organisation (GitHub Enterprise).
    Internal,
    /// The host did not say.
    Unknown,
}

impl From<Visibility> for RepoVisibility {
    fn from(visibility: Visibility) -> Self {
        match visibility {
            Visibility::Public => Self::Public,
            Visibility::Private => Self::Private,
            Visibility::Internal => Self::Internal,
            Visibility::Unknown => Self::Unknown,
        }
    }
}

/// What the account that lists a repository can do in it, as the host says. A fine-grained token
/// can hold less than the account's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoRole {
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

impl From<Role> for RepoRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Admin => Self::Admin,
            Role::Maintain => Self::Maintain,
            Role::Write => Self::Write,
            Role::Triage => Self::Triage,
            Role::Read => Self::Read,
            Role::Unknown => Self::Unknown,
        }
    }
}

/// A repository an identity can reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoView {
    /// The Git host (`github.com`, `dev.azure.com`).
    pub host: String,
    /// The user or organisation that owns it; the organisation on Azure DevOps.
    pub owner: String,
    /// The Azure DevOps project; `null` elsewhere.
    #[schema(required = true)]
    pub project: Option<String>,
    /// The repository's own name.
    pub name: String,
    /// `owner/name`, or `organisation/project/name` on Azure DevOps: what a search matches.
    pub full_name: String,
    /// The HTTPS address to clone, with no user name: what the create form takes.
    pub url: String,
    /// Who can see it.
    pub visibility: RepoVisibility,
    /// What the account can do in it.
    pub role: RepoRole,
    /// Whether it is archived (read-only).
    pub archived: bool,
    /// Whether it is a fork.
    pub fork: bool,
    /// The identities whose credentials list it; the first listed it first. Offer these to
    /// "create a workspace for this".
    pub identities: Vec<i64>,
}

impl RepoView {
    pub(crate) fn from_found(found: &Found) -> Self {
        let Repository {
            host,
            owner,
            project,
            name,
            full_name,
            url,
            visibility,
            role,
            archived,
            fork,
        } = found.repository.clone();
        Self {
            host,
            owner,
            project,
            name,
            full_name,
            url,
            visibility: visibility.into(),
            role: role.into(),
            archived,
            fork,
            identities: found.identities.iter().map(|id| id.0).collect(),
        }
    }
}

/// The repositories of the identities, one entry each, by name, and how current each credential's
/// list is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoListing {
    /// One entry per credential (per organisation on Azure DevOps) of the identities asked for,
    /// in the identities' order. Read these before trusting an empty `repos`.
    pub sources: Vec<RepoSource>,
    /// The matching repositories, a page of them.
    pub repos: Vec<RepoView>,
    /// How many repositories match, before the page is cut.
    pub total: u32,
    /// Where the page starts.
    pub offset: u32,
    /// The page size that was applied.
    pub limit: u32,
}

/// Which lists to read again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RepoRefreshRequest {
    /// Only this identity's credentials; leave out (or `null`) for every identity's.
    #[serde(default)]
    #[schema(required = false)]
    pub identity_id: Option<i64>,
}

/// How current each list is after a refresh. Read the repositories with `GET /api/repos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RepoSources {
    /// One entry per credential (per organisation on Azure DevOps) asked for.
    pub sources: Vec<RepoSource>,
}

/// A credential whose account to describe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountProfileRequest {
    /// Where its value comes from.
    pub source: CredentialSource,
}

/// Who a credential's account is, to prefill an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AccountProfile {
    /// The account name on the host; `null` when it could not be read.
    #[schema(required = true)]
    pub account: Option<String>,
    /// The display name, for the commit author's name; `null` when it could not be read.
    #[schema(required = true)]
    pub name: Option<String>,
    /// The address commits use (GitHub's private no-reply address); `null` when the host cannot
    /// say.
    #[schema(required = true)]
    pub email: Option<String>,
    /// The organisations the account belongs to (GitHub), or the one the credential names (Azure
    /// DevOps): suggestions for what the credential covers.
    pub organisations: Vec<String>,
    /// What is missing or limited.
    pub notes: Vec<RepoNote>,
    /// Why the profile could not be read; `null` when it could (possibly with notes).
    #[schema(required = true)]
    pub problem: Option<RepoProblem>,
}

impl From<ProfileRead> for AccountProfile {
    fn from(read: ProfileRead) -> Self {
        let Profile {
            account,
            name,
            email,
            organisations,
            notes,
        } = read.profile;
        Self {
            account,
            name,
            email,
            organisations,
            notes: notes.iter().map(RepoNote::from).collect(),
            problem: read.problem.as_ref().map(RepoProblem::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use puddle_store::IdentityId;

    use super::*;

    fn name<T: Serialize>(value: &T) -> String {
        serde_json::to_value(value)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn every_kind_of_list_state_problem_note_visibility_and_role_has_its_own_wire_name() {
        let states = [
            (ListState::Ok, "ok"),
            (ListState::Stale, "stale"),
            (ListState::Failed, "failed"),
            (ListState::Unavailable, "unavailable"),
        ];
        for (state, wire) in states {
            assert_eq!(name(&RepoListState::from(state)), wire);
        }
        let problems = [
            (ProblemKind::NotSignedIn, "not_signed_in"),
            (ProblemKind::SourceUnavailable, "source_unavailable"),
            (ProblemKind::TokenRejected, "token_rejected"),
            (ProblemKind::Forbidden, "forbidden"),
            (ProblemKind::NotFound, "not_found"),
            (ProblemKind::RateLimited, "rate_limited"),
            (ProblemKind::Unreachable, "unreachable"),
            (ProblemKind::BadAnswer, "bad_answer"),
            (ProblemKind::Unsupported, "unsupported"),
            (ProblemKind::OrganisationNeeded, "organisation_needed"),
            (ProblemKind::WrongTarget, "wrong_target"),
        ];
        for (kind, wire) in problems {
            assert_eq!(name(&RepoProblemCode::from(kind)), wire);
        }
        let notes = [
            (NoteKind::SsoPartial, "sso_partial"),
            (
                NoteKind::OrganisationsMayBeHidden,
                "organisations_may_be_hidden",
            ),
            (NoteKind::FineGrainedToken, "fine_grained_token"),
            (NoteKind::Truncated, "truncated"),
            (NoteKind::AuthorUnavailable, "author_unavailable"),
            (
                NoteKind::OrganisationsUnavailable,
                "organisations_unavailable",
            ),
            (NoteKind::HostLimitReached, "host_limit_reached"),
        ];
        for (kind, wire) in notes {
            assert_eq!(name(&RepoNoteCode::from(kind)), wire);
        }
        let visibilities = [
            (Visibility::Public, "public"),
            (Visibility::Private, "private"),
            (Visibility::Internal, "internal"),
            (Visibility::Unknown, "unknown"),
        ];
        for (visibility, wire) in visibilities {
            assert_eq!(name(&RepoVisibility::from(visibility)), wire);
        }
        let roles = [
            (Role::Admin, "admin"),
            (Role::Maintain, "maintain"),
            (Role::Write, "write"),
            (Role::Triage, "triage"),
            (Role::Read, "read"),
            (Role::Unknown, "unknown"),
        ];
        for (role, wire) in roles {
            assert_eq!(name(&RepoRole::from(role)), wire);
        }
    }

    #[test]
    fn a_count_past_what_the_wire_holds_saturates() {
        let list = SourceList {
            identity: IdentityId(3),
            credential: usize::MAX,
            host: "github.com".to_owned(),
            organisation: None,
            state: ListState::Ok,
            refreshed_at: None,
            retry_at: None,
            problem: None,
            notes: Vec::new(),
            repos: Arc::from([]),
        };
        let source = RepoSource::from_list(&list);
        assert_eq!(source.credential, u32::MAX);
        assert_eq!(source.repo_count, 0);
    }
}
