// SPDX-License-Identifier: GPL-3.0-or-later
//! What the Git hosts are called in URLs: the names puddle decrypts for a credential, and the
//! remote URLs that belong to an owner (which choose the commit author).
//!
//! Azure DevOps has two names for one thing, `dev.azure.com/{org}` and `{org}.visualstudio.com`,
//! so a credential on `dev.azure.com` covers both.

use puddle_boot::{GitAuthorRule, GitIdentity, MAX_GIT_AUTHOR_GLOBS, MAX_GIT_AUTHOR_RULES};
use puddle_proxy::TerminationSet;
use puddle_store::{Identity, WorkspaceGit};

/// Azure DevOps's own host; its organisations also answer on `{org}.visualstudio.com`.
const AZURE_DEVOPS: &str = "dev.azure.com";
const AZURE_DEVOPS_LEGACY: &str = "visualstudio.com";

/// The only port puddle decrypts.
const HTTPS_PORT: &str = "443";

/// The names puddle decrypts for a credential on `host` (a name, with a port only when the host
/// is not on 443): the host itself, and for Azure DevOps its `*.visualstudio.com` names. A host
/// on another port gets none, because only port 443 is terminated.
pub(crate) fn decrypt_patterns(host: &str) -> Vec<String> {
    let host = host.to_ascii_lowercase();
    let name = match host.split_once(':') {
        None => host.as_str(),
        Some((name, HTTPS_PORT)) => name,
        Some(_) => return Vec::new(),
    };
    let mut patterns = vec![name.to_owned()];
    if name == AZURE_DEVOPS {
        patterns.push(format!("*.{AZURE_DEVOPS_LEGACY}"));
    }
    patterns
}

/// The hosts a workspace decrypts for its attached identities' credentials.
pub(crate) fn decrypt_set(git: &WorkspaceGit) -> TerminationSet {
    let mut set = TerminationSet::new();
    for identity in &git.identities {
        for credential in &identity.credentials {
            for pattern in decrypt_patterns(credential.host.as_str()) {
                if let Err(err) = set.insert(&pattern) {
                    tracing::warn!(host = %credential.host, %err, "this credential's host is never decrypted");
                }
            }
        }
    }
    set
}

/// Every letter as a two-letter class (`a` as `[aA]`): git matches remote globs case-sensitively
/// and a host or an owner is one name whatever its case.
fn fold(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Git globs for the remote URLs of `owner` on `host`, or of every owner on it (`None`): `https`
/// URLs with and without a `user@` in them, and for Azure DevOps the `visualstudio.com` names.
/// Matching is on the URL as git stores it in `remote.<name>.url`.
pub(crate) fn remote_globs(host: &str, owner: Option<&str>) -> Vec<String> {
    let host = host.to_ascii_lowercase();
    let mut authorities = vec![(host.clone(), owner.map(str::to_owned))];
    if host == AZURE_DEVOPS {
        // `{org}.visualstudio.com/{project}/_git/{repo}`: the organisation is in the host name.
        let legacy = owner.map_or_else(
            || format!("*.{AZURE_DEVOPS_LEGACY}"),
            |org| format!("{org}.{AZURE_DEVOPS_LEGACY}"),
        );
        authorities.push((legacy, None));
    }
    let mut globs = Vec::new();
    for (authority, owner) in authorities {
        let authority = if authority.starts_with("*.") {
            // Keep the leading `*.` as the glob it is; fold the rest.
            format!("*.{}", fold(&authority[2..]))
        } else {
            fold(&authority)
        };
        let path = owner.map_or_else(
            || "/**".to_owned(),
            |owner| format!("/{}/**", fold(&owner.to_ascii_lowercase())),
        );
        globs.push(format!("https://{authority}{path}"));
        globs.push(format!("https://*@{authority}{path}"));
    }
    globs
}

/// The commit authors of a workspace: the fallback and the rules by remote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Authors {
    /// The author of a repository no rule matches: the first identity's.
    pub(crate) fallback: Option<GitIdentity>,
    /// Rules in git's order, lowest priority first: the last matching one wins.
    pub(crate) rules: Vec<GitAuthorRule>,
}

/// The author an identity gives its commits, if the store's text is something git can keep.
fn author_of(identity: &Identity) -> Option<GitIdentity> {
    match GitIdentity::new(&identity.author.name, &identity.author.email) {
        Ok(author) => Some(author),
        Err(err) => {
            tracing::warn!(identity = %identity.label, %err, "this identity's author is not used");
            None
        }
    }
}

/// The authors of `git`'s identities.
///
/// The first identity's author is the fallback. A remote on an owner an identity names gets that
/// identity's author, and beats one on the rest of a host, because the credential follows the same
/// rule; among identities that match equally, the first in the workspace's order wins. Git lets
/// the last matching rule win, so the rules are written in the opposite order: the rest of a host
/// first, then named owners, the last identity first in each.
pub(crate) fn authors(git: &WorkspaceGit) -> Authors {
    let fallback = git.identities.first().and_then(author_of);
    let mut rules = Vec::new();
    for named in [false, true] {
        for identity in git.identities.iter().rev() {
            let Some(author) = author_of(identity) else {
                continue;
            };
            let mut globs = Vec::new();
            for credential in &identity.credentials {
                let host = credential.host.as_str();
                if named {
                    for owner in &credential.covers.owners {
                        globs.extend(remote_globs(host, Some(owner.as_str())));
                    }
                } else if credential.covers.rest_of_host {
                    globs.extend(remote_globs(host, None));
                }
            }
            for chunk in globs.chunks(MAX_GIT_AUTHOR_GLOBS) {
                if let Ok(rule) = GitAuthorRule::new(chunk.to_vec(), author.clone()) {
                    rules.push(rule);
                }
            }
        }
    }
    if rules.len() > MAX_GIT_AUTHOR_RULES {
        tracing::warn!(
            rules = rules.len(),
            "more author rules than a workspace holds: the lowest priority ones are left out"
        );
        rules.drain(..rules.len() - MAX_GIT_AUTHOR_RULES);
    }
    Authors { fallback, rules }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use puddle_secrets::{AccountName, HostName, SourceSpec};
    use puddle_store::{
        Author, Coverage, CredentialBinding, IdentityDraft, Limits, ManualClock, Owner, Store,
    };
    use puddle_types::WorkspaceName;

    use super::*;

    fn credential(host: &str, owners: &[&str], rest: bool) -> CredentialBinding {
        let host = HostName::new(host).unwrap();
        CredentialBinding::new(
            &host,
            SourceSpec::Gh {
                host: host.clone(),
                account: AccountName::new("me").unwrap(),
            },
            Coverage::new(
                owners
                    .iter()
                    .map(|o| Owner::new(o).unwrap())
                    .collect::<BTreeSet<_>>(),
                rest,
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// A workspace with these identities attached in this order, through a real store: what the
    /// host reads.
    fn git(identities: Vec<(&str, Vec<CredentialBinding>)>) -> WorkspaceGit {
        let store =
            Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap();
        let ws = WorkspaceName::new("alpha").unwrap();
        for (name, credentials) in identities {
            let identity = store
                .create_identity(IdentityDraft {
                    label: name.to_owned(),
                    author: Author::new(name, &format!("{}@example.org", name.to_lowercase()))
                        .unwrap(),
                    credentials,
                })
                .unwrap();
            store.attach_identity(&ws, identity.id, None).unwrap();
        }
        store.workspace_git(&ws).unwrap()
    }

    #[test]
    fn a_credential_decrypts_its_host_and_azure_devops_its_legacy_names_too() {
        assert_eq!(decrypt_patterns("GitHub.com"), ["github.com"]);
        assert_eq!(decrypt_patterns("github.com:443"), ["github.com"]);
        assert_eq!(
            decrypt_patterns("dev.azure.com"),
            ["dev.azure.com", "*.visualstudio.com"]
        );
        // Only port 443 is terminated.
        assert!(decrypt_patterns("ghe.example:8443").is_empty());
    }

    #[test]
    fn the_decrypt_set_is_the_credentials_hosts_of_the_attached_identities() {
        let set = decrypt_set(&git(vec![
            ("Ada", vec![credential("github.com", &[], true)]),
            (
                "Bob",
                vec![
                    credential("dev.azure.com", &["contoso"], false),
                    // On another port, an address: never decrypted, and not a failure.
                    credential("ghe.example:8443", &[], true),
                    credential("10.0.0.5", &[], true),
                ],
            ),
        ]));
        let host = |h: &str| puddle_types::Host::parse_normalised(h).unwrap();
        for yes in ["github.com", "dev.azure.com", "contoso.visualstudio.com"] {
            assert!(set.contains(&host(yes)), "{yes}");
        }
        for no in ["api.github.com", "gitlab.com", "ghe.example", "10.0.0.5"] {
            assert!(!set.contains(&host(no)), "{no}");
        }
        assert!(decrypt_set(&git(vec![])).is_empty());
    }

    #[test]
    fn globs_cover_the_url_forms_of_a_host_and_an_owner_in_any_case() {
        assert_eq!(
            remote_globs("github.com", Some("Acme")),
            [
                "https://[gG][iI][tT][hH][uU][bB].[cC][oO][mM]/[aA][cC][mM][eE]/**",
                "https://*@[gG][iI][tT][hH][uU][bB].[cC][oO][mM]/[aA][cC][mM][eE]/**",
            ]
        );
        assert_eq!(
            remote_globs("gitlab.com", None),
            [
                "https://[gG][iI][tT][lL][aA][bB].[cC][oO][mM]/**",
                "https://*@[gG][iI][tT][lL][aA][bB].[cC][oO][mM]/**",
            ]
        );
        let ado = remote_globs("dev.azure.com", Some("contoso"));
        assert_eq!(ado.len(), 4);
        assert!(
            ado[2].contains("[cC][oO][nN][tT][oO][sS][oO].[vV][iI]"),
            "{ado:?}"
        );
        let ado_rest = remote_globs("dev.azure.com", None);
        assert!(
            ado_rest[2].starts_with("https://*.[vV][iI][sS]"),
            "{ado_rest:?}"
        );
        assert!(
            ado_rest[3].starts_with("https://*@*.[vV][iI][sS]"),
            "{ado_rest:?}"
        );
    }

    #[test]
    fn the_first_identity_is_the_fallback_and_a_named_owner_beats_the_rest_of_a_host() {
        // Personal is first and covers the rest of github.com; Work names acme.
        let a = authors(&git(vec![
            ("Personal", vec![credential("github.com", &[], true)]),
            ("Work", vec![credential("github.com", &["acme"], false)]),
        ]));
        assert_eq!(a.fallback.as_ref().unwrap().name(), "Personal");
        // The rest-of-host rule is written first, so the named owner's wins on acme's remotes.
        let names: Vec<&str> = a.rules.iter().map(|r| r.author().name()).collect();
        assert_eq!(names, ["Personal", "Work"]);
        assert!(a.rules[0].globs()[0].ends_with("/**") && !a.rules[0].globs()[0].contains("[aA]"));
        assert!(a.rules[1].globs()[0].contains("[aA][cC][mM][eE]"));
    }

    #[test]
    fn among_identities_that_match_equally_the_first_in_the_list_is_written_last() {
        let a = authors(&git(vec![
            ("First", vec![credential("github.com", &["a"], false)]),
            ("Second", vec![credential("gitlab.com", &["a"], false)]),
        ]));
        let names: Vec<&str> = a.rules.iter().map(|r| r.author().name()).collect();
        assert_eq!(names, ["Second", "First"]);
    }

    #[test]
    fn an_identity_without_credentials_is_only_a_fallback_and_nobody_is_none() {
        let a = authors(&git(vec![("Solo", vec![])]));
        assert_eq!(a.fallback.as_ref().unwrap().email(), "solo@example.org");
        assert!(a.rules.is_empty());
        assert_eq!(authors(&git(vec![])), Authors::default());
    }

    #[test]
    fn an_author_git_cannot_keep_is_left_out_not_fatal() {
        let mut with_bad = git(vec![
            ("Good", vec![credential("github.com", &["a"], false)]),
            ("Bad", vec![credential("gitlab.com", &["a"], false)]),
        ]);
        with_bad.identities[1].author.name = "two\nlines".to_owned();
        let a = authors(&with_bad);
        let names: Vec<&str> = a.rules.iter().map(|r| r.author().name()).collect();
        assert_eq!(names, ["Good"]);
        with_bad.identities[0].author.email = String::new();
        assert_eq!(authors(&with_bad), Authors::default());
    }

    #[test]
    fn many_owners_are_split_into_rules_and_too_many_rules_drop_the_lowest_priority() {
        let owners: Vec<String> = (0..20).map(|i| format!("org{i}")).collect();
        let refs: Vec<&str> = owners.iter().map(String::as_str).collect();
        // 20 owners x 2 globs = 40 globs: two rules, neither over the limit.
        let a = authors(&git(vec![(
            "Many",
            vec![credential("github.com", &refs, false)],
        )]));
        assert_eq!(a.rules.len(), 2);
        assert!(
            a.rules
                .iter()
                .all(|r| r.globs().len() <= MAX_GIT_AUTHOR_GLOBS)
        );

        // A hundred identities on a hundred hosts: more rules than a plan holds.
        let names: Vec<String> = (0..100).map(|i| format!("Id{i}")).collect();
        let many: Vec<(&str, Vec<CredentialBinding>)> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    n.as_str(),
                    vec![credential(&format!("host{i}.example"), &["x"], false)],
                )
            })
            .collect();
        let a = authors(&git(many));
        assert_eq!(a.rules.len(), MAX_GIT_AUTHOR_RULES);
        // The first identity (highest priority, written last) is kept.
        assert_eq!(a.rules.last().unwrap().author().name(), "Id0");
    }
}
