// SPDX-License-Identifier: GPL-3.0-or-later
//! The closed list of places a secret can come from.

use serde::{Deserialize, Serialize};

use crate::name::{AccountName, HostName, OrgName, StoredId, UrlPath};

/// Which host (and, for a token that belongs to one organisation, which organisation) a secret is
/// for. Sources do not enforce it: whoever uses the token (the proxy's injector, a host-side API
/// call) checks it against where the token is about to go.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenScope {
    /// The Git host.
    pub host: HostName,
    /// The organisation, for tokens that are per organisation (Azure DevOps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgName>,
}

/// One secret source. A closed enum: there is no variant that carries a command line, so no
/// configuration or API input can make puddle run anything but the fixed invocations in this crate.
/// An identity owns one of these per credential; a source never assumes it is the only one for a
/// workspace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceSpec {
    /// The token of a named, signed-in GitHub CLI account (`gh auth token --user`), never "whichever
    /// account is active".
    Gh {
        /// The GitHub host.
        host: HostName,
        /// The account.
        account: AccountName,
    },
    /// Git Credential Manager (or any configured Git credential helper), asked for one HTTPS URL
    /// with its path. The path is always sent.
    GitCredential {
        /// The host.
        host: HostName,
        /// The URL path that selects the credential.
        path: UrlPath,
        /// A GitHub account name, when the host has several.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<AccountName>,
    },
    /// A token the user pasted, kept in the OS credential store under puddle's own name.
    Stored {
        /// The id of the entry.
        id: StoredId,
        /// What the token is for.
        scope: TokenScope,
    },
}

impl SourceSpec {
    /// What the credential is for, when the source knows.
    #[must_use]
    pub fn scope(&self) -> TokenScope {
        match self {
            Self::Gh { host, .. } | Self::GitCredential { host, .. } => TokenScope {
                host: host.clone(),
                org: None,
            },
            Self::Stored { scope, .. } => scope.clone(),
        }
    }

    /// A line for logs, events and errors. Names only, never a value.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Gh { host, account } => format!("gh account {account} on {host}"),
            Self::GitCredential {
                host,
                path,
                username: None,
            } => {
                format!("Git credential for https://{host}/{path}")
            }
            Self::GitCredential {
                host,
                path,
                username: Some(user),
            } => {
                format!("Git credential for https://{host}/{path} (account {user})")
            }
            Self::Stored { id, scope } => format!("stored token {id} for {}", scope.host),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> HostName {
        HostName::new(s).unwrap()
    }

    #[test]
    fn round_trips_through_json() {
        let spec = SourceSpec::GitCredential {
            host: host("dev.azure.com"),
            path: UrlPath::new("org").unwrap(),
            username: None,
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"git_credential","host":"dev.azure.com","path":"org"}"#
        );
        assert_eq!(serde_json::from_str::<SourceSpec>(&json).unwrap(), spec);
    }

    #[test]
    fn there_is_no_command_line_variant() {
        for bad in [
            r#"{"kind":"command","command":"curl evil"}"#,
            r#"{"kind":"gh","host":"github.com","account":"a b"}"#,
            r#"{"kind":"git_credential","host":"github.com","path":"../x"}"#,
        ] {
            assert!(serde_json::from_str::<SourceSpec>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn describe_and_scope_name_the_target() {
        let gh = SourceSpec::Gh {
            host: host("github.com"),
            account: AccountName::new("me").unwrap(),
        };
        assert_eq!(gh.describe(), "gh account me on github.com");
        assert_eq!(gh.scope().org, None);
        let gc = SourceSpec::GitCredential {
            host: host("github.com"),
            path: UrlPath::new("o/r").unwrap(),
            username: Some(AccountName::new("me").unwrap()),
        };
        assert_eq!(
            gc.describe(),
            "Git credential for https://github.com/o/r (account me)"
        );
        let st = SourceSpec::Stored {
            id: StoredId::new("x1").unwrap(),
            scope: TokenScope {
                host: host("dev.azure.com"),
                org: Some(OrgName::new("acme").unwrap()),
            },
        };
        assert_eq!(st.describe(), "stored token x1 for dev.azure.com");
        assert_eq!(st.scope().org.unwrap().as_str(), "acme");
        let plain = SourceSpec::GitCredential {
            host: host("h.io"),
            path: UrlPath::new("o").unwrap(),
            username: None,
        };
        assert_eq!(plain.describe(), "Git credential for https://h.io/o");
    }
}
