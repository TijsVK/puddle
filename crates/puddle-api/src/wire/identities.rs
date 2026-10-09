// SPDX-License-Identifier: GPL-3.0-or-later
//! Git identities and a workspace's Git settings on the wire (credentials spec §7, §8). A
//! credential names a source; no request or response carries a secret value.

use std::collections::BTreeSet;

use puddle_secrets::{AccountName, HostName, OrgName, SourceSpec, StoredId, TokenScope, UrlPath};
use puddle_store as store;
use puddle_types::WorkspaceName;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ApiError;

fn bad(what: &str) -> ApiError {
    ApiError::invalid(format!("not a valid {what}"))
}

/// Where the host reads a credential's value. A closed list; there is no command-line source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialSource {
    /// The token of a named, signed-in GitHub CLI account.
    Gh {
        /// The GitHub host.
        host: String,
        /// The account.
        account: String,
    },
    /// Git Credential Manager (or the configured credential helper) asked for one URL.
    GitCredential {
        /// The host.
        host: String,
        /// The URL path that selects the credential (`org`, `org/project`).
        path: String,
        /// A GitHub account name, when the host has several.
        #[serde(default)]
        #[schema(required = true)]
        username: Option<String>,
    },
    /// A token the user pasted, kept in the OS credential store under puddle's own name.
    Stored {
        /// The entry's id.
        id: String,
        /// The host the token is for.
        host: String,
        /// The organisation, for tokens that belong to one (Azure DevOps).
        #[serde(default)]
        #[schema(required = true)]
        org: Option<String>,
    },
}

impl CredentialSource {
    pub(crate) fn from_store(spec: &SourceSpec) -> Option<Self> {
        Some(match spec {
            SourceSpec::Gh { host, account } => Self::Gh {
                host: host.to_string(),
                account: account.to_string(),
            },
            SourceSpec::GitCredential {
                host,
                path,
                username,
            } => Self::GitCredential {
                host: host.to_string(),
                path: path.to_string(),
                username: username.as_ref().map(ToString::to_string),
            },
            SourceSpec::Stored { id, scope } => Self::Stored {
                id: id.to_string(),
                host: scope.host.to_string(),
                org: scope.org.as_ref().map(ToString::to_string),
            },
            _ => return None,
        })
    }

    /// The source as `puddle-secrets` has it, or why it is refused. For tools that seed a store
    /// from a description (the UI fixture).
    ///
    /// # Errors
    /// The refusal in words: a host, account, path, id or organisation that is not valid.
    pub fn into_spec(self) -> Result<SourceSpec, String> {
        self.into_store().map_err(|err| err.message().to_owned())
    }

    pub(crate) fn into_store(self) -> Result<SourceSpec, ApiError> {
        let host = |h: &str| HostName::new(h).map_err(|_| bad("host"));
        let account = |a: &str| AccountName::new(a).map_err(|_| bad("account name"));
        Ok(match self {
            Self::Gh {
                host: h,
                account: a,
            } => SourceSpec::Gh {
                host: host(&h)?,
                account: account(&a)?,
            },
            Self::GitCredential {
                host: h,
                path,
                username,
            } => SourceSpec::GitCredential {
                host: host(&h)?,
                path: UrlPath::new(path).map_err(|_| bad("URL path"))?,
                username: username.as_deref().map(account).transpose()?,
            },
            Self::Stored { id, host: h, org } => SourceSpec::Stored {
                id: StoredId::new(id).map_err(|_| bad("stored credential id"))?,
                scope: TokenScope {
                    host: host(&h)?,
                    org: org
                        .map(OrgName::new)
                        .transpose()
                        .map_err(|_| bad("organisation"))?,
                },
            },
        })
    }
}

/// What a credential covers on its host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CredentialCoverage {
    /// Named owners and organisations (case does not matter; stored lower-case).
    pub owners: Vec<String>,
    /// Every other owner on the host. At least one of the two must be set.
    pub rest_of_host: bool,
}

/// One credential of an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityCredential {
    /// The Git host (`github.com`, `dev.azure.com`).
    pub host: String,
    /// Where its value comes from.
    pub source: CredentialSource,
    /// What it covers.
    pub covers: CredentialCoverage,
}

impl IdentityCredential {
    fn from_store(binding: &store::CredentialBinding) -> Option<Self> {
        Some(Self {
            host: binding.host.to_string(),
            source: CredentialSource::from_store(&binding.source)?,
            covers: CredentialCoverage {
                owners: binding
                    .covers
                    .owners
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                rest_of_host: binding.covers.rest_of_host,
            },
        })
    }

    fn into_store(self) -> Result<store::CredentialBinding, ApiError> {
        let host = HostName::new(self.host).map_err(|_| bad("host"))?;
        let owners = self
            .covers
            .owners
            .iter()
            .map(|o| store::Owner::new(o))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let covers = store::Coverage::new(owners, self.covers.rest_of_host)?;
        Ok(store::CredentialBinding::new(
            &host,
            self.source.into_store()?,
            covers,
        )?)
    }
}

/// The name and email git writes into a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityAuthor {
    /// `user.name`.
    pub name: String,
    /// `user.email`.
    pub email: String,
}

/// How an identity signs commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySigning {
    /// Not signed (the only choice for now).
    None,
}

/// An identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityView {
    /// Its number.
    pub id: i64,
    /// The name you see.
    pub label: String,
    /// The commit author.
    pub author: IdentityAuthor,
    /// Its credentials, as references.
    pub credentials: Vec<IdentityCredential>,
    /// How it signs.
    pub signing: IdentitySigning,
    /// Whether it is the default: what a new workspace gets when no identity covers its URL.
    pub is_default: bool,
    /// The workspaces it is on.
    pub workspaces: Vec<WorkspaceName>,
    /// Epoch ms it was made.
    pub created_at: u64,
    /// Epoch ms it last changed.
    pub changed_at: u64,
}

impl IdentityView {
    pub(crate) fn from_store(identity: store::Identity, workspaces: Vec<WorkspaceName>) -> Self {
        Self {
            id: identity.id.0,
            label: identity.label,
            author: IdentityAuthor {
                name: identity.author.name,
                email: identity.author.email,
            },
            credentials: identity
                .credentials
                .iter()
                .filter_map(IdentityCredential::from_store)
                .collect(),
            signing: IdentitySigning::None,
            is_default: identity.is_default,
            workspaces,
            created_at: identity.created_at,
            changed_at: identity.changed_at,
        }
    }
}

/// Every identity, in your order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityList {
    /// The identities.
    pub identities: Vec<IdentityView>,
}

/// Makes or replaces an identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityRequest {
    /// The name you see; unique whatever the case.
    pub label: String,
    /// The commit author.
    pub author: IdentityAuthor,
    /// Its credentials. No two of one identity may cover the same place.
    pub credentials: Vec<IdentityCredential>,
}

impl IdentityRequest {
    /// The store's draft of this request, or why it is refused. For tools that seed a store from
    /// a description (the UI fixture).
    ///
    /// # Errors
    /// The refusal in words.
    pub fn into_store_draft(self) -> Result<store::IdentityDraft, String> {
        self.into_draft().map_err(|err| err.message().to_owned())
    }

    pub(crate) fn into_draft(self) -> Result<store::IdentityDraft, ApiError> {
        Ok(store::IdentityDraft {
            label: self.label,
            author: store::Author::new(&self.author.name, &self.author.email)?,
            credentials: self
                .credentials
                .into_iter()
                .map(IdentityCredential::into_store)
                .collect::<Result<_, _>>()?,
        })
    }
}

/// The order of the identities: every id once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityOrderRequest {
    /// The ids, first to last.
    pub ids: Vec<i64>,
}

/// What deleting an identity changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct IdentityDeleted {
    /// The workspaces it was taken off.
    pub detached_from: Vec<WorkspaceName>,
}

/// One row of a workspace's repository table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitRepoView {
    /// The row's number.
    pub id: i64,
    /// The host, lower-case.
    pub host: String,
    /// The user or organisation, lower-case.
    pub owner: String,
    /// `repo`, or `project/repo` on Azure DevOps; lower-case, no `.git`.
    pub repo: String,
    /// A fetch from it may go out.
    pub pull: bool,
    /// A push to it may go out.
    pub push: bool,
    /// Epoch ms it was added.
    pub created_at: u64,
}

impl GitRepoView {
    pub(crate) fn from_store(entry: store::RepoEntry) -> Self {
        Self {
            id: entry.id,
            host: entry.repo.host.to_string(),
            owner: entry.repo.owner.to_string(),
            repo: entry.repo.repo,
            pull: entry.pull,
            push: entry.push,
            created_at: entry.created_at,
        }
    }
}

/// A workspace's Git settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceGitView {
    /// The workspace.
    pub workspace: WorkspaceName,
    /// Its identities in order (the order breaks author ties; coverage picks the credential).
    pub identities: Vec<IdentityView>,
    /// The repository table.
    pub repos: Vec<GitRepoView>,
    /// Refuse a push to a repository not listed with Push on (default on).
    pub only_push_listed: bool,
    /// Refuse a fetch from a repository not listed with Pull on (default off).
    pub only_pull_listed: bool,
}

/// The identities a workspace has, replacing its list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct WorkspaceIdentitiesRequest {
    /// The ids in order.
    pub ids: Vec<i64>,
}

/// Adds one identity to a workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AttachIdentityRequest {
    /// The identity.
    pub identity: i64,
    /// Where in the order; omitted means last.
    #[serde(default)]
    #[schema(required = false)]
    pub position: Option<u32>,
}

/// Sets either switch; a switch left out stays as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitSwitchesRequest {
    /// "Only push to listed repos".
    #[serde(default)]
    #[schema(required = false)]
    pub only_push_listed: Option<bool>,
    /// "Only pull from listed repos".
    #[serde(default)]
    #[schema(required = false)]
    pub only_pull_listed: Option<bool>,
}

/// Adds a repository to the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitRepoRequest {
    /// The host (`github.com`).
    pub host: String,
    /// The user or organisation.
    pub owner: String,
    /// `repo`, or `project/repo` on Azure DevOps; `.git` is dropped.
    pub repo: String,
    /// A fetch from it may go out.
    pub pull: bool,
    /// A push to it may go out.
    pub push: bool,
}

impl GitRepoRequest {
    pub(crate) fn repo_ref(&self) -> Result<store::RepoRef, ApiError> {
        Ok(store::RepoRef::new(&self.host, &self.owner, &self.repo)?)
    }
}

/// A repository row's toggles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitRepoToggles {
    /// A fetch from it may go out.
    pub pull: bool,
    /// A push to it may go out.
    pub push: bool,
}

/// The default of the two switches, for every workspace that has not set its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GitDefaultsView {
    /// Refuse a push to a repository not listed with Push on (built in: on).
    pub only_push_listed: bool,
    /// Refuse a fetch from a repository not listed with Pull on (built in: off).
    pub only_pull_listed: bool,
}

impl From<store::GitDefaults> for GitDefaultsView {
    fn from(d: store::GitDefaults) -> Self {
        Self {
            only_push_listed: d.only_push_listed,
            only_pull_listed: d.only_pull_listed,
        }
    }
}

/// Why a new workspace got the identity it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NewWorkspaceIdentityBasis {
    /// An identity covers the repository.
    Covers,
    /// None does: it got the default identity, which has no credential for the repository.
    Default,
    /// None does and there is no default identity.
    None,
}

/// What a new workspace's Git settings started with. Only the answer to creating a workspace
/// carries it; the Git tab shows the same thing afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct NewWorkspaceIdentity {
    /// The label of the identity it got; `null` for none.
    #[schema(required = true)]
    pub identity: Option<String>,
    /// Why.
    pub basis: NewWorkspaceIdentityBasis,
    /// What to tell you when no identity covers the repository (which one it got and what that
    /// means); `null` when one does.
    #[schema(required = true)]
    pub warning: Option<String>,
}

impl NewWorkspaceIdentity {
    pub(crate) fn from_store(start: &store::GitStart, repo: &store::RepoRef) -> Self {
        let place = format!("{}/{}", repo.host, repo.owner);
        let (basis, warning) = match (start.basis, &start.identity) {
            (store::StartBasis::Default, Some((_, label))) => (
                NewWorkspaceIdentityBasis::Default,
                Some(format!(
                    "No identity covers {place}, so this workspace got your default identity, {label}. \
                     {label} has no credential for {place}: commits use its author, but requests to \
                     {place} go out without a credential until an identity covers it (Identities tab)."
                )),
            ),
            (store::StartBasis::Covers, _) => (NewWorkspaceIdentityBasis::Covers, None),
            _ => (
                NewWorkspaceIdentityBasis::None,
                Some(format!(
                    "No identity covers {place} and you have no default identity, so this workspace \
                     has no commit author and no credential. Add an identity on the Identities tab."
                )),
            ),
        };
        Self {
            identity: start.identity.as_ref().map(|(_, label)| label.clone()),
            basis,
            warning,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> store::RepoRef {
        store::RepoRef::new("github.com", "acme", "shop").unwrap()
    }

    #[test]
    fn only_a_repository_nobody_covers_has_a_warning_naming_the_identity_and_the_place() {
        let start = |basis, label: Option<&str>| store::GitStart {
            identity: label.map(|l| (store::IdentityId(1), l.to_owned())),
            basis,
        };
        let covered = NewWorkspaceIdentity::from_store(
            &start(store::StartBasis::Covers, Some("Work")),
            &repo(),
        );
        assert_eq!(covered.warning, None);
        assert_eq!(covered.identity.as_deref(), Some("Work"));

        let default = NewWorkspaceIdentity::from_store(
            &start(store::StartBasis::Default, Some("Personal")),
            &repo(),
        );
        assert_eq!(default.basis, NewWorkspaceIdentityBasis::Default);
        let text = default.warning.unwrap();
        assert!(
            text.contains("Personal") && text.contains("github.com/acme"),
            "{text}"
        );

        let none =
            NewWorkspaceIdentity::from_store(&start(store::StartBasis::NoIdentity, None), &repo());
        assert_eq!(
            (none.identity, none.basis),
            (None, NewWorkspaceIdentityBasis::None)
        );
        assert!(none.warning.unwrap().contains("no default identity"));
    }
}
