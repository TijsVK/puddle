// SPDX-License-Identifier: GPL-3.0-or-later
//! What puddle knows about a service's login: where the token comes back, which fields of the
//! answer are tokens, and which hosts the tokens are for.
//!
//! A profile is data. Adding a service is a new entry in [`builtin`], not new code: the token
//! endpoints and the hosts that take the tokens, and for each token field what it looks like.

use puddle_proxy::TerminationSet;

/// What a captured token is used for. A workspace has at most one stand-in for each role of a
/// profile, so a refresh gives the tool the same stand-in with a new real token behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Role {
    /// The short-lived token the service's API takes.
    Access,
    /// The token that is only ever shown to the token endpoint, to get a new access token.
    Refresh,
    /// A long-lived API key that the login produces next to the tokens.
    ApiKey,
}

impl Role {
    /// The role as it appears in names: `access`, `refresh`, `api-key`.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Refresh => "refresh",
            Self::ApiKey => "api-key",
        }
    }
}

/// Which hosts a stand-in is swapped toward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// The profile's API hosts and its token endpoints.
    Api,
    /// Only the token endpoints: a refresh token has no business anywhere else.
    TokenEndpoint,
}

/// One field of a token answer that holds a token.
#[derive(Debug, Clone, Copy)]
pub struct Field {
    /// The field's name in the answer.
    pub name: &'static str,
    /// What the token is for.
    pub role: Role,
    /// The prefixes the service's tokens of this kind start with (`gho_`); the stand-in keeps the
    /// one the real token has. A token with none of them gets a stand-in with no prefix.
    pub prefixes: &'static [&'static str],
    /// How many of the token's last characters the stand-in keeps. A client may record the end
    /// of a key it was given and compare with it later; no profile needs more than 20.
    pub keep_last: usize,
    /// Where the stand-in is swapped for the real token.
    pub scope: Scope,
}

/// A request to one path of one host whose answer holds tokens and whose request may hold the
/// refresh token the tool sends back.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    /// The host, exactly.
    pub host: &'static str,
    /// The path, exactly, for a `POST`.
    pub path: &'static str,
    /// The request field that holds the refresh token, where the stand-in is swapped back.
    pub refresh_field: Option<&'static str>,
    /// The answer's token fields.
    pub fields: &'static [Field],
}

/// A service whose login puddle captures.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    /// A short name for identifiers: `claude`, `github`.
    pub id: &'static str,
    /// What the user calls the service.
    pub name: &'static str,
    /// Where tokens come back.
    pub endpoints: &'static [Endpoint],
    /// The hosts, besides the token endpoints, that take the tokens (exact names or `*.suffix`).
    pub api_hosts: &'static [&'static str],
}

impl Profile {
    /// The name of the stand-in for `role` in logs and the audit: `claude-access`.
    #[must_use]
    pub fn slot_name(&self, role: Role) -> String {
        format!("{}-{}", self.id, role.key())
    }

    /// Every host this profile decrypts, for the workspace's decrypted set: the token endpoints
    /// and the API hosts.
    #[must_use]
    pub fn hosts(&self) -> TerminationSet {
        self.hosts_for(Scope::Api)
    }

    /// The hosts a stand-in with `scope` is swapped toward: for [`Scope::Api`] the API hosts and
    /// every token endpoint's host, for [`Scope::TokenEndpoint`] only the hosts of the endpoints
    /// that take a refresh token.
    #[must_use]
    pub fn hosts_for(&self, scope: Scope) -> TerminationSet {
        let mut set = TerminationSet::new();
        let (endpoints, api): (Vec<&Endpoint>, &[&str]) = match scope {
            Scope::Api => (self.endpoints.iter().collect(), self.api_hosts),
            Scope::TokenEndpoint => (
                self.endpoints
                    .iter()
                    .filter(|e| e.refresh_field.is_some())
                    .collect(),
                &[],
            ),
        };
        for host in endpoints.iter().map(|e| e.host).chain(api.iter().copied()) {
            // The patterns are literals in this file, and a test checks that each one is accepted.
            let _ = set.insert(host);
        }
        set
    }

    /// Every field of every endpoint, with its endpoint.
    pub fn fields(&self) -> impl Iterator<Item = (&Endpoint, &Field)> + '_ {
        self.endpoints
            .iter()
            .flat_map(|endpoint| endpoint.fields.iter().map(move |field| (endpoint, field)))
    }

    /// The slots this profile has stand-ins for: each role with the scope of its stand-in.
    #[must_use]
    pub fn slots(&self) -> Vec<(Role, Scope)> {
        let mut slots: Vec<(Role, Scope)> = self
            .fields()
            .map(|(_, field)| (field.role, field.scope))
            .collect();
        slots.sort_by_key(|(role, _)| *role);
        slots.dedup_by_key(|(role, _)| *role);
        slots
    }

    /// The roles this profile has stand-ins for.
    #[must_use]
    pub fn roles(&self) -> Vec<Role> {
        self.slots().into_iter().map(|(role, _)| role).collect()
    }
}

/// Claude Code (`claude auth login`, `/login`): the OAuth code exchange and refresh at
/// `platform.claude.com`, JSON both ways, and the API key the login creates.
pub const CLAUDE: Profile = Profile {
    id: "claude",
    name: "Claude Code",
    endpoints: &[
        Endpoint {
            host: "platform.claude.com",
            path: "/v1/oauth/token",
            refresh_field: Some("refresh_token"),
            fields: &[
                Field {
                    name: "access_token",
                    role: Role::Access,
                    prefixes: &["sk-ant-oat01-"],
                    keep_last: 0,
                    scope: Scope::Api,
                },
                Field {
                    name: "refresh_token",
                    role: Role::Refresh,
                    prefixes: &["sk-ant-ort01-"],
                    keep_last: 0,
                    scope: Scope::TokenEndpoint,
                },
            ],
        },
        Endpoint {
            host: "api.anthropic.com",
            path: "/api/oauth/claude_cli/create_api_key",
            refresh_field: None,
            fields: &[Field {
                name: "raw_key",
                role: Role::ApiKey,
                prefixes: &["sk-ant-api03-"],
                // The CLI keeps the last 20 characters of the key it was given.
                keep_last: 20,
                scope: Scope::Api,
            }],
        },
    ],
    api_hosts: &[
        "api.anthropic.com",
        "claude.ai",
        "console.anthropic.com",
        "mcp-proxy.anthropic.com",
    ],
};

/// GitHub (`gh auth login`, `copilot login`): the OAuth device flow and the web flow end at
/// `github.com/login/oauth/access_token`, answered as a form or as JSON by the request's `Accept`.
/// The tokens go to GitHub's API, to Git over HTTPS and to the host `copilot_internal/user` names
/// for the Copilot service.
pub const GITHUB: Profile = Profile {
    id: "github",
    name: "GitHub",
    endpoints: &[Endpoint {
        host: "github.com",
        path: "/login/oauth/access_token",
        refresh_field: Some("refresh_token"),
        fields: &[
            Field {
                name: "access_token",
                role: Role::Access,
                prefixes: &["gho_", "ghu_"],
                keep_last: 0,
                scope: Scope::Api,
            },
            Field {
                name: "refresh_token",
                role: Role::Refresh,
                prefixes: &["ghr_"],
                keep_last: 0,
                scope: Scope::TokenEndpoint,
            },
        ],
    }],
    api_hosts: &[
        "github.com",
        "api.github.com",
        "uploads.github.com",
        "*.githubcopilot.com",
    ],
};

/// The profiles puddle ships.
#[must_use]
pub fn builtin() -> &'static [Profile] {
    &[CLAUDE, GITHUB]
}

#[cfg(test)]
mod tests {
    use puddle_types::Host;

    use super::*;

    fn host(name: &str) -> Host {
        Host::parse_normalised(name).unwrap()
    }

    #[test]
    fn every_built_in_host_is_a_name_the_proxy_accepts() {
        for profile in builtin() {
            for scope in [Scope::Api, Scope::TokenEndpoint] {
                let set = profile.hosts_for(scope);
                let wanted: Vec<&str> = profile
                    .endpoints
                    .iter()
                    .filter(|e| scope == Scope::Api || e.refresh_field.is_some())
                    .map(|e| e.host)
                    .chain(match scope {
                        Scope::Api => profile.api_hosts.iter().copied(),
                        Scope::TokenEndpoint => [].iter().copied(),
                    })
                    .collect();
                for name in wanted {
                    let probe = name
                        .strip_prefix("*.")
                        .map_or_else(|| name.to_owned(), |base| format!("anything.{base}"));
                    assert!(set.contains(&host(&probe)), "{}: {name}", profile.id);
                }
            }
        }
    }

    #[test]
    fn a_refresh_token_is_swapped_toward_the_token_endpoint_only() {
        let claude = CLAUDE.hosts_for(Scope::TokenEndpoint);
        assert!(claude.contains(&host("platform.claude.com")));
        assert!(
            !claude.contains(&host("api.anthropic.com")),
            "the endpoint that creates a key takes no refresh token"
        );
        assert!(!claude.contains(&host("claude.ai")));
        let github = GITHUB.hosts_for(Scope::TokenEndpoint);
        assert!(github.contains(&host("github.com")));
        assert!(!github.contains(&host("api.github.com")));
    }

    #[test]
    fn the_github_profile_covers_copilot_hosts_and_not_the_whole_domain() {
        let set = GITHUB.hosts();
        assert!(set.contains(&host("api.individual.githubcopilot.com")));
        assert!(set.contains(&host("api.github.com")));
        assert!(!set.contains(&host("githubcopilot.com")));
        assert!(!set.contains(&host("gist.github.com")));
        assert!(!set.contains(&host("evilgithub.com")));
    }

    #[test]
    fn slots_are_named_by_profile_and_role_and_each_role_is_listed_once() {
        assert_eq!(CLAUDE.slot_name(Role::ApiKey), "claude-api-key");
        assert_eq!(GITHUB.slot_name(Role::Access), "github-access");
        assert_eq!(CLAUDE.roles(), [Role::Access, Role::Refresh, Role::ApiKey]);
        assert_eq!(GITHUB.roles(), [Role::Access, Role::Refresh]);
        assert_eq!(CLAUDE.fields().count(), 3);
    }

    #[test]
    fn profile_ids_and_paths_are_unique_and_well_formed() {
        let profiles = builtin();
        for (i, a) in profiles.iter().enumerate() {
            for b in &profiles[i + 1..] {
                assert_ne!(a.id, b.id);
            }
            assert!(a.id.bytes().all(|c| c.is_ascii_lowercase()));
            for e in a.endpoints {
                assert!(e.path.starts_with('/'));
                assert!(!e.fields.is_empty());
            }
        }
    }
}
