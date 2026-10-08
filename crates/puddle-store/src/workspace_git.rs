// SPDX-License-Identifier: GPL-3.0-or-later
//! What a workspace's Git settings hold: its ordered identities, the repository table with a
//! Pull and a Push toggle per repository, and the two "only listed" switches
//! (`docs/arch/spec/credentials.md` §7).

use puddle_secrets::HostName;

use crate::error::StoreError;
use crate::identity::{CredentialChoice, Identity, Owner, resolve};

const MAX_SEGMENT: usize = 100;

/// A repository on a Git host in the one spelling the table and the proxy compare: host and
/// every name lower-case, no `.git`, Azure DevOps without `_git` (`org`, `project/repo`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RepoRef {
    /// The host, lower-case.
    pub host: HostName,
    /// The user, organisation or Azure DevOps organisation.
    pub owner: Owner,
    /// `repo`, or `project/repo` on Azure DevOps.
    pub repo: String,
}

impl RepoRef {
    /// Checks and canonicalises a repository.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] for a name the Git hosts don't have: empty or dot
    /// segments, more than two segments, a character outside letters, digits and `-_.`.
    pub fn new(host: &str, owner: &str, repo: &str) -> Result<Self, StoreError> {
        let bad =
            |what: &str| StoreError::IdentityInvalid(format!("not a valid repository: {what}"));
        let host = HostName::new(host.trim().to_ascii_lowercase()).map_err(|_| bad("host"))?;
        let owner = Owner::new(owner).map_err(|_| bad("owner"))?;
        let repo = repo.trim().to_ascii_lowercase();
        let repo = repo.strip_suffix(".git").unwrap_or(&repo).to_owned();
        let segments: Vec<&str> = repo.split('/').collect();
        let ok = (1..=2).contains(&segments.len())
            && segments.iter().all(|s| {
                !s.is_empty()
                    && s.len() <= MAX_SEGMENT
                    && *s != "."
                    && *s != ".."
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            });
        if !ok {
            return Err(bad("name"));
        }
        Ok(Self { host, owner, repo })
    }
}

impl RepoRef {
    /// The repository an HTTPS clone address names: `https://github.com/acme/web.git`,
    /// `https://dev.azure.com/org/project/_git/repo` (or `org/_git/repo`, whose project has the
    /// repository's name) and `https://org.visualstudio.com/project/_git/repo` (optionally with a
    /// `DefaultCollection` segment first). A query or fragment is ignored.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] for another scheme, a user name or port in the address, or
    /// a path that is not one of those shapes.
    pub fn from_https_url(url: &str) -> Result<Self, StoreError> {
        let bad = || StoreError::IdentityInvalid("not an HTTPS repository address".into());
        let url = url.trim();
        let rest = url
            .get(..8)
            .filter(|scheme| scheme.eq_ignore_ascii_case("https://"))
            .and_then(|_| url.get(8..))
            .ok_or_else(bad)?;
        let rest = rest.split(['?', '#']).next().unwrap_or_default();
        let (host, path) = rest.split_once('/').ok_or_else(bad)?;
        if host.contains(['@', ':']) {
            return Err(bad());
        }
        let host = host.to_ascii_lowercase();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let git = |s: &&str| s.eq_ignore_ascii_case("_git");
        let (owner, repo) = if host == "dev.azure.com" {
            match segments.as_slice() {
                [org, mid, repo] if git(mid) => ((*org).to_owned(), format!("{repo}/{repo}")),
                [org, project, mid, repo] if git(mid) => {
                    ((*org).to_owned(), format!("{project}/{repo}"))
                }
                _ => return Err(bad()),
            }
        } else if let Some(org) = host.strip_suffix(".visualstudio.com") {
            match segments.as_slice() {
                [project, mid, repo] | [_, project, mid, repo] if git(mid) => {
                    (org.to_owned(), format!("{project}/{repo}"))
                }
                _ => return Err(bad()),
            }
        } else {
            match segments.as_slice() {
                [owner, repo] => ((*owner).to_owned(), (*repo).to_owned()),
                _ => return Err(bad()),
            }
        };
        Self::new(&host, &owner, &repo)
    }
}

impl std::fmt::Display for RepoRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.host, self.owner, self.repo)
    }
}

/// One row of the repository table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoEntry {
    /// The row's number.
    pub id: i64,
    /// The repository.
    pub repo: RepoRef,
    /// A fetch from it may go out (when "only pull from listed repos" is on).
    pub pull: bool,
    /// A push to it may go out (when "only push to listed repos" is on).
    pub push: bool,
    /// Epoch ms it was added.
    pub created_at: u64,
}

/// A workspace's Git settings as the store holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceGit {
    /// The attached identities, in the workspace's order (the order breaks author ties only).
    pub identities: Vec<Identity>,
    /// The repository table.
    pub repos: Vec<RepoEntry>,
    /// Refuse a push to a repository not listed with Push on (default on).
    pub only_push_listed: bool,
    /// Refuse a fetch from a repository not listed with Pull on (default off: a fetch reaches
    /// every repository the token can read).
    pub only_pull_listed: bool,
}

impl WorkspaceGit {
    /// The settings of a workspace nobody configured: nothing attached or listed, push list on,
    /// pull list off.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            identities: Vec::new(),
            repos: Vec::new(),
            only_push_listed: true,
            only_pull_listed: false,
        }
    }

    fn listed(&self, repo: &RepoRef) -> Option<&RepoEntry> {
        self.repos.iter().find(|entry| entry.repo == *repo)
    }

    /// Whether a push to `repo` may go out.
    #[must_use]
    pub fn allows_push(&self, repo: &RepoRef) -> bool {
        !self.only_push_listed || self.listed(repo).is_some_and(|entry| entry.push)
    }

    /// Whether a fetch from `repo` may go out.
    #[must_use]
    pub fn allows_pull(&self, repo: &RepoRef) -> bool {
        !self.only_pull_listed || self.listed(repo).is_some_and(|entry| entry.pull)
    }

    /// The credential for a request about `owner` on `host`.
    #[must_use]
    pub fn credential_for(&self, host: &str, owner: &str) -> CredentialChoice<'_> {
        resolve(&self.identities, host, owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(text: &str) -> RepoRef {
        let (host, rest) = text.split_once('/').unwrap();
        let (owner, name) = rest.split_once('/').unwrap();
        RepoRef::new(host, owner, name).unwrap()
    }

    fn entry(text: &str, pull: bool, push: bool) -> RepoEntry {
        RepoEntry {
            id: 1,
            repo: repo(text),
            pull,
            push,
            created_at: 0,
        }
    }

    #[test]
    fn clone_addresses_name_the_repository_the_ui_also_reads() {
        // The same file drives the UI's parser (`ui/src/lib/identities/repo.ts`).
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/repo-urls.json")).unwrap();
        for case in vectors["cases"].as_array().unwrap() {
            let url = case["url"].as_str().unwrap();
            let got = RepoRef::from_https_url(url);
            match case["repo"].as_array() {
                Some(want) => {
                    let want: Vec<&str> = want.iter().map(|v| v.as_str().unwrap()).collect();
                    let got = got.unwrap_or_else(|e| panic!("{url:?}: {e}"));
                    assert_eq!(
                        [got.host.as_str(), got.owner.as_str(), got.repo.as_str()],
                        [want[0], want[1], want[2]],
                        "{url:?}"
                    );
                }
                None => assert!(got.is_err(), "{url:?} must be refused, got {got:?}"),
            }
        }
    }

    #[test]
    fn repos_are_canonical() {
        assert_eq!(repo("GitHub.com/Acme/Web.GIT"), repo("github.com/acme/web"));
        assert_eq!(repo("dev.azure.com/Org/Proj/Repo").repo, "proj/repo");
        assert_eq!(
            repo("github.com/acme/web").to_string(),
            "github.com/acme/web"
        );
        for bad in [
            "", ".", "..", "a//b", "a/b/c", "a b", "a%2Fb", "a\\b", "/a", "a/", ".git",
        ] {
            assert!(RepoRef::new("github.com", "acme", bad).is_err(), "{bad:?}");
        }
        assert!(RepoRef::new("github.com", "ac me", "x").is_err());
        assert!(RepoRef::new("git hub", "acme", "x").is_err());
        assert!(RepoRef::new("github.com", "acme", &"a".repeat(MAX_SEGMENT + 1)).is_err());
    }

    #[test]
    fn the_switches_decide_what_the_toggles_mean() {
        let mut git = WorkspaceGit::unconfigured();
        git.repos = vec![
            entry("github.com/a/b", true, false),
            entry("github.com/a/c", false, true),
        ];
        let (b, c, d) = (
            repo("github.com/a/b"),
            repo("github.com/a/c"),
            repo("github.com/a/d"),
        );
        // Defaults: push only to listed repos with Push on; pull anywhere.
        assert!(!git.allows_push(&b) && git.allows_push(&c) && !git.allows_push(&d));
        assert!(git.allows_pull(&b) && git.allows_pull(&c) && git.allows_pull(&d));
        git.only_pull_listed = true;
        assert!(git.allows_pull(&b) && !git.allows_pull(&c) && !git.allows_pull(&d));
        git.only_push_listed = false;
        assert!(git.allows_push(&b) && git.allows_push(&d));
    }
}
