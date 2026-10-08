// SPDX-License-Identifier: GPL-3.0-or-later
//! Finding the accounts the user is already signed in with, from a closed list of listing commands.
//!
//! Every command prints names only. Each answer is parsed into the few fields kept below
//! (host, account, organisation, signed-in state); the rest of the output is dropped unread, so a
//! token in it cannot reach a caller, a log or the store.

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;

use crate::error::{SourceError, Tool};
use crate::name::{AccountName, HostName, OrgName};
use crate::run::{TOOL_TIMEOUT, ToolPaths, run};

/// The listing commands puddle may run. A closed list: `az account list` joins it with the `az` source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Listing {
    /// `gh auth status --json hosts`.
    GhAuthStatus,
    /// `git credential-manager github list`.
    GcmGithub,
    /// `git credential-manager azure-repos list`.
    GcmAzureRepos,
}

impl Listing {
    /// Every listing command.
    pub const ALL: [Self; 3] = [Self::GhAuthStatus, Self::GcmGithub, Self::GcmAzureRepos];

    fn tool(self) -> Tool {
        match self {
            Self::GhAuthStatus => Tool::Gh,
            Self::GcmGithub | Self::GcmAzureRepos => Tool::Git,
        }
    }

    fn args(self) -> &'static [&'static str] {
        match self {
            Self::GhAuthStatus => &["auth", "status", "--json", "hosts"],
            Self::GcmGithub => &["credential-manager", "github", "list"],
            Self::GcmAzureRepos => &["credential-manager", "azure-repos", "list"],
        }
    }
}

/// An account found on the host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveredAccount {
    /// Which listing found it.
    pub via: Listing,
    /// The Git host.
    pub host: HostName,
    /// The account.
    pub account: AccountName,
    /// The Azure DevOps organisation the account is bound to, when the listing says.
    pub org: Option<OrgName>,
    /// False when `gh` lists the account but its token no longer works.
    pub signed_in: bool,
}

/// What the listings found, and which of them could not run.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Accounts, de-duplicated and sorted.
    pub accounts: Vec<DiscoveredAccount>,
    /// Listings that failed (tool missing, nothing signed in, timeout).
    pub problems: Vec<(Listing, SourceError)>,
}

/// Runs every listing, none of them interactive. Meant for "Add identity" and first run, not for a
/// request.
pub async fn discover(tools: &ToolPaths) -> Discovery {
    let mut found = BTreeSet::new();
    let mut problems = Vec::new();
    for listing in Listing::ALL {
        match run_listing(tools, listing).await {
            Ok(accounts) => found.extend(accounts),
            Err(err) => problems.push((listing, err)),
        }
    }
    Discovery {
        accounts: found.into_iter().collect(),
        problems,
    }
}

async fn run_listing(
    tools: &ToolPaths,
    listing: Listing,
) -> Result<Vec<DiscoveredAccount>, SourceError> {
    let program = tools.get(listing.tool())?;
    let out = run(listing.tool(), program, listing.args(), None, TOOL_TIMEOUT).await?;
    let text = String::from_utf8_lossy(&out.stdout);
    // `gh auth status` exits non-zero when any account is broken but still prints the JSON.
    let accounts = match listing {
        Listing::GhAuthStatus => parse_gh(&text),
        Listing::GcmGithub => parse_gcm_github(&text),
        Listing::GcmAzureRepos => parse_gcm_azure(&text),
    };
    if accounts.is_empty() && !out.success {
        return Err(SourceError::NotSignedIn);
    }
    Ok(accounts)
}

#[derive(Deserialize)]
struct GhStatus {
    #[serde(default)]
    hosts: HashMap<String, Vec<GhLogin>>,
}

#[derive(Deserialize)]
struct GhLogin {
    login: String,
    #[serde(default)]
    state: Option<String>,
}

fn parse_gh(text: &str) -> Vec<DiscoveredAccount> {
    let Ok(status) = serde_json::from_str::<GhStatus>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (host, logins) in status.hosts {
        let Ok(host) = HostName::new(host) else {
            continue;
        };
        for login in logins {
            let Ok(account) = AccountName::new(login.login) else {
                continue;
            };
            out.push(DiscoveredAccount {
                via: Listing::GhAuthStatus,
                host: host.clone(),
                account,
                org: None,
                signed_in: login.state.as_deref().is_none_or(|s| s == "success"),
            });
        }
    }
    out
}

fn github_host() -> Option<HostName> {
    HostName::new("github.com").ok()
}

/// One account name per line; a line that is not a plain name is dropped.
fn parse_gcm_github(text: &str) -> Vec<DiscoveredAccount> {
    let Some(host) = github_host() else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| AccountName::new(line.trim()).ok())
        .map(|account| DiscoveredAccount {
            via: Listing::GcmGithub,
            host: host.clone(),
            account,
            org: None,
            signed_in: true,
        })
        .collect()
}

/// `org:` at the start of a line, then `  (global) -> user` or `  (local)  -> user` below it.
fn parse_gcm_azure(text: &str) -> Vec<DiscoveredAccount> {
    let Ok(host) = HostName::new("dev.azure.com") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut org: Option<OrgName> = None;
    for line in text.lines() {
        if line.starts_with(char::is_whitespace) {
            let Some(current) = org.as_ref() else {
                continue;
            };
            let Some((binding, user)) = line.trim().split_once("->") else {
                continue;
            };
            if !(binding.starts_with("(global)") || binding.starts_with("(local)")) {
                continue;
            }
            if let Ok(account) = AccountName::new(user.trim()) {
                out.push(DiscoveredAccount {
                    via: Listing::GcmAzureRepos,
                    host: host.clone(),
                    account,
                    org: Some(current.clone()),
                    signed_in: true,
                });
            }
        } else {
            org = line
                .trim()
                .strip_suffix(':')
                .and_then(|name| OrgName::new(name).ok());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gh_json_keeps_names_and_state_only() {
        let json = r#"{"hosts":{"github.com":[
            {"login":"me","active":true,"state":"success","token":"CANARY-x","scopes":"repo"},
            {"login":"old","active":false,"state":"error"},
            {"login":"-bad"}],
          "bad host":[{"login":"x"}]}}"#;
        let mut got = parse_gh(json);
        got.sort();
        assert_eq!(got.len(), 2);
        assert!(
            got.iter()
                .any(|a| a.account.as_str() == "me" && a.signed_in)
        );
        assert!(
            got.iter()
                .any(|a| a.account.as_str() == "old" && !a.signed_in)
        );
        assert!(!format!("{got:?}").contains("CANARY"));
        assert_eq!(parse_gh("not json").len(), 0);
    }

    #[test]
    fn gcm_github_lines() {
        let got = parse_gcm_github("me\n  other  \npassword CANARY-y\n\n");
        let names: Vec<_> = got.iter().map(|a| a.account.as_str()).collect();
        assert_eq!(names, ["me", "other"]);
    }

    #[test]
    fn gcm_azure_bindings() {
        let text = "acme:\n  (global) -> me@example.com\n  (local)  -> you@example.com\nother:\n  \
                    (global) -> x\n  token=CANARY-z\nstray: junk\n  (global) -> orphan\n";
        let got = parse_gcm_azure(text);
        let pairs: Vec<_> = got
            .iter()
            .map(|a| (a.org.as_ref().unwrap().as_str(), a.account.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("acme", "me@example.com"),
                ("acme", "you@example.com"),
                ("other", "x")
            ]
        );
    }
}
