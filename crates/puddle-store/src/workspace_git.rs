// SPDX-License-Identifier: GPL-3.0-or-later
//! What a workspace's Git settings hold: its ordered identities, the repository table with a
//! Pull and a Push toggle per repository, and the two "only listed" switches
//! (`docs/arch/spec/credentials.md` §7).

use puddle_secrets::HostName;

use crate::error::StoreError;
use crate::identity::{CredentialChoice, Identity, Owner, resolve};

const MAX_SEGMENT: usize = 100;

/// The most names in a repository's path on a host with subgroups (GitLab allows twenty groups
/// and then the project).
const MAX_NESTED: usize = 21;

/// A repository on a Git host in the one spelling the table and the proxy compare: host and
/// every name lower-case, no `.git`, Azure DevOps without `_git` (`org`, `project/repo`).
///
/// Names are held as people write them, not as an address escapes them: an Azure DevOps project
/// `My Project` is `my project` here and `my%20project` only on the wire. The proxy decodes a
/// request's path (and refuses one that is not in its one canonical escaping) before it looks a
/// repository up, and an address typed by the user is decoded the same way, so one repository has
/// one spelling here however it is reached.
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

/// Whether `host` is an Azure DevOps name, whose project and repository names may hold a space
/// and any letter.
fn azure_devops(host: &str) -> bool {
    host == "dev.azure.com" || host.ends_with(".visualstudio.com")
}

/// Whether one name segment of a repository is one the host `azure` or not can have. A segment
/// never holds what an address uses to separate or end a path segment, so it cannot be read as
/// two names or as another one after decoding.
fn valid_segment(segment: &str, azure: bool) -> bool {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let wide = |c: char| !c.is_control() && !matches!(c, '/' | '\\' | '%' | '?' | '#' | ';');
    !segment.is_empty()
        && (azure || segment != "-")
        && segment.chars().count() <= MAX_SEGMENT
        && segment != "."
        && segment != ".."
        && if azure {
            segment == segment.trim() && segment.chars().all(wide)
        } else {
            segment.chars().all(plain)
        }
}

impl RepoRef {
    /// How many names a repository's path holds at most on `host`: `project/repo` on Azure DevOps,
    /// one on github.com, and any depth of groups on another host (GitLab's subgroups).
    #[must_use]
    pub fn max_segments(host: &str) -> usize {
        if azure_devops(host) {
            2
        } else if host == "github.com" {
            1
        } else {
            MAX_NESTED
        }
    }

    /// Checks and canonicalises a repository.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] for a name the Git hosts don't have: empty or dot
    /// segments, more names than the host nests ([`Self::max_segments`]), a `-` name (GitLab's
    /// separator of its pages), a character outside letters, digits and `-_.` (on Azure
    /// DevOps: a space or any other letter is fine, but not a control character, `/`, `\`, `%`,
    /// `?`, `#` or `;`).
    pub fn new(host: &str, owner: &str, repo: &str) -> Result<Self, StoreError> {
        let bad =
            |what: &str| StoreError::IdentityInvalid(format!("not a valid repository: {what}"));
        let host = HostName::new(host.trim().to_ascii_lowercase()).map_err(|_| bad("host"))?;
        let owner = Owner::new(owner).map_err(|_| bad("owner"))?;
        // ASCII only, as the proxy folds a request's path: `K` (the Kelvin sign) is not `k` to every host.
        let repo = repo.trim().to_ascii_lowercase();
        let repo = repo.strip_suffix(".git").unwrap_or(&repo).to_owned();
        let azure = azure_devops(host.as_str());
        let segments: Vec<&str> = repo.split('/').collect();
        let ok = (1..=Self::max_segments(host.as_str())).contains(&segments.len())
            && segments.iter().all(|s| valid_segment(s, azure));
        if !ok {
            return Err(bad("name"));
        }
        Ok(Self { host, owner, repo })
    }
}

impl RepoRef {
    /// The repository an HTTPS clone address names: `https://github.com/acme/web.git`,
    /// `https://gitlab.com/group/subgroup/project` (the subgroups are part of the name; github.com
    /// has none), `https://dev.azure.com/org/project/_git/repo` (or `org/_git/repo`, whose project has the
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
        let decoded: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| decode_address_segment(s).ok_or_else(bad))
            .collect::<Result<_, _>>()?;
        let segments: Vec<&str> = decoded.iter().map(String::as_str).collect();
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
                [owner, repo @ ..] if !repo.is_empty() => ((*owner).to_owned(), repo.join("/")),
                _ => return Err(bad()),
            }
        };
        Self::new(&host, &owner, &repo)
    }
}

/// One segment of a typed clone address with its `%XX` escapes decoded, or `None` for a segment
/// that is not one an address can have: a raw space or control character, a bad escape, bytes
/// that are not UTF-8, or an escape for what separates segments (`/`, `\`, `%`, `?`, `#`, `;`)
/// or is a control character.
fn decode_address_segment(segment: &str) -> Option<String> {
    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                let decoded = u8::try_from(high << 4 | low).ok()?;
                if decoded < 0x20
                    || decoded == 0x7f
                    || matches!(decoded, b'/' | b'\\' | b'%' | b'?' | b'#' | b';')
                {
                    return None;
                }
                out.push(decoded);
            }
            0..=0x20 | 0x7f => return None,
            other => out.push(other),
        }
    }
    String::from_utf8(out)
        .ok()
        .filter(|name| name == name.trim())
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

/// The default of the two switches, for every workspace that has not set its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GitDefaults {
    /// Refuse a push to a repository not listed with Push on.
    pub only_push_listed: bool,
    /// Refuse a fetch from a repository not listed with Pull on.
    pub only_pull_listed: bool,
}

impl Default for GitDefaults {
    /// Push list on, pull list off: a fetch reaches every repository the token can read.
    fn default() -> Self {
        Self {
            only_push_listed: true,
            only_pull_listed: false,
        }
    }
}

/// Why a repository got the identity it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartBasis {
    /// The user picked it for this repository. It may cover the repository or not.
    Chosen,
    /// An identity covers the repository's owner (or its host).
    Covers,
    /// None does, so it got the default identity, which has no credential for the repository.
    Default,
    /// None does and there is no default identity: the workspace has no identity.
    NoIdentity,
}

/// What one repository of a workspace asks of its Git settings
/// ([`crate::Store::start_repository_git`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoGitRequest {
    /// The repository, in the table's spelling.
    pub repo: RepoRef,
    /// The identity the user picked for it; `None` lets Puddle choose.
    pub identity: Option<crate::IdentityId>,
    /// Pull on its table row, when the row is new.
    pub pull: bool,
    /// Push on its table row, when the row is new.
    pub push: bool,
}

/// What [`crate::Store::start_repository_git`] set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStart {
    /// The identity attached (id and label), if any.
    pub identity: Option<(crate::IdentityId, String)>,
    /// Why.
    pub basis: StartBasis,
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
    fn an_azure_devops_name_can_hold_a_space_and_a_letter_a_git_host_has_not() {
        let spaced = RepoRef::new("dev.azure.com", "Contoso", "My Project/The Api").unwrap();
        assert_eq!(spaced.repo, "my project/the api");
        assert_eq!(
            spaced.to_string(),
            "dev.azure.com/contoso/my project/the api"
        );
        assert_eq!(
            RepoRef::new("contoso.visualstudio.com", "contoso", "Été/Api")
                .unwrap()
                .repo,
            "Été/api"
        );
        // Not at the ends of a name, and never what ends or splits a path segment.
        for bad in [
            "a /b", "a/ b", "a\u{0}/b", "a%/b", "a?/b", "a#/b", "a;/b", "a\\/b",
        ] {
            assert!(
                RepoRef::new("dev.azure.com", "contoso", bad).is_err(),
                "{bad:?}"
            );
        }
        // Another host keeps the plain alphabet.
        for bad in ["my project", "\u{e9}t\u{e9}", "a:b"] {
            assert!(RepoRef::new("github.com", "acme", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_ascii_letters_fold_so_a_look_alike_is_another_name() {
        let kelvin = RepoRef::new("dev.azure.com", "org", "proj\u{212a}/x").unwrap();
        assert_ne!(
            kelvin,
            RepoRef::new("dev.azure.com", "org", "projk/x").unwrap()
        );
        assert_eq!(
            RepoRef::new("dev.azure.com", "org", "\u{c9}T\u{c9}/X")
                .unwrap()
                .repo,
            "\u{c9}t\u{c9}/x"
        );
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
