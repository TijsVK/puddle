// SPDX-License-Identifier: GPL-3.0-or-later
//! Git identities: who commits (the author) and which credential puddle adds on the way out,
//! per host and per owner or organisation (`docs/arch/spec/credentials.md` §7 and §8).
//!
//! An [`Identity`] never holds a secret: a [`CredentialBinding`] names a [`SourceSpec`], the place
//! the host reads the value from. What a binding [`Coverage`] covers decides which credential a
//! request gets; attaching two identities whose coverage meets on one workspace is refused
//! ([`check_attachable`]), so a request never has two candidates and [`resolve`] never has to
//! guess.

use std::collections::BTreeSet;
use std::fmt;

use puddle_secrets::{HostName, OrgName, SourceSpec};
use serde::{Deserialize, Serialize};

use crate::error::StoreError;

/// The most credentials one identity holds.
pub const MAX_CREDENTIALS: usize = 16;
const MAX_LABEL: usize = 64;
const MAX_AUTHOR_NAME: usize = 100;
const MAX_EMAIL: usize = 254;

/// An identity's number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(pub i64);

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn invalid(what: impl Into<String>) -> StoreError {
    StoreError::IdentityInvalid(what.into())
}

fn plain(text: &str, max: usize, what: &str) -> Result<String, StoreError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(invalid(format!("{what} can't be empty")));
    }
    if text.chars().count() > max {
        return Err(invalid(format!("{what} is longer than {max} characters")));
    }
    if text.chars().any(|c| c.is_control() || c == '<' || c == '>') {
        return Err(invalid(format!("{what} has a character git does not keep")));
    }
    Ok(text.to_owned())
}

/// The name and email git writes into a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Author {
    /// `user.name`.
    pub name: String,
    /// `user.email`.
    pub email: String,
}

impl Author {
    /// Checks and wraps an author.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] for an empty, long or odd name, or an email that is not
    /// `local@domain` without spaces.
    pub fn new(name: &str, email: &str) -> Result<Self, StoreError> {
        let name = plain(name, MAX_AUTHOR_NAME, "the author name")?;
        let email = plain(email, MAX_EMAIL, "the author email")?;
        let ok = email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        }) && !email.chars().any(char::is_whitespace);
        if !ok {
            return Err(invalid("the author email must look like name@example.com"));
        }
        Ok(Self { name, email })
    }
}

/// How an identity signs commits. Only "none" exists; a key comes later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Signing {
    /// Commits are not signed.
    None,
}

/// A user, organisation or Azure DevOps organisation on a host, lower-cased (Git hosts treat the
/// case of an owner as one name).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Owner(String);

impl Owner {
    /// Checks and lower-cases an owner name.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] for an empty name or one with a character no owner has.
    pub fn new(name: &str) -> Result<Self, StoreError> {
        let org =
            OrgName::new(name.trim()).map_err(|_| invalid("not a valid owner or organisation"))?;
        Ok(Self(org.as_str().to_ascii_lowercase()))
    }

    /// The lower-case text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Owner {
    type Error = StoreError;
    fn try_from(value: String) -> Result<Self, StoreError> {
        Self::new(&value)
    }
}

impl From<Owner> for String {
    fn from(owner: Owner) -> String {
        owner.0
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a credential covers on its host: named owners or organisations, the rest of the host
/// (every owner no other identity names), or both. Never empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CoverageRaw")]
#[non_exhaustive]
pub struct Coverage {
    /// The owners and organisations named.
    pub owners: BTreeSet<Owner>,
    /// Every other owner on the host.
    pub rest_of_host: bool,
}

#[derive(Deserialize)]
struct CoverageRaw {
    owners: BTreeSet<Owner>,
    rest_of_host: bool,
}

impl TryFrom<CoverageRaw> for Coverage {
    type Error = StoreError;
    fn try_from(raw: CoverageRaw) -> Result<Self, StoreError> {
        Self::new(raw.owners, raw.rest_of_host)
    }
}

impl Coverage {
    /// A coverage.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] when it names no owner and not the rest of the host.
    pub fn new(owners: BTreeSet<Owner>, rest_of_host: bool) -> Result<Self, StoreError> {
        if owners.is_empty() && !rest_of_host {
            return Err(invalid(
                "a credential must cover at least one owner or the rest of its host",
            ));
        }
        Ok(Self {
            owners,
            rest_of_host,
        })
    }

    /// Whether `owner` is named.
    #[must_use]
    pub fn names(&self, owner: &Owner) -> bool {
        self.owners.contains(owner)
    }
}

/// One credential of an identity: the host it is for, where its value comes from and what it
/// covers there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CredentialBinding {
    /// The Git host, lower-case.
    pub host: HostName,
    /// Where the host reads the value. A reference; the value is never stored.
    pub source: SourceSpec,
    /// Which owners on the host it covers.
    pub covers: Coverage,
}

fn same_host(a: &HostName, b: &HostName) -> bool {
    a.as_str().eq_ignore_ascii_case(b.as_str())
}

impl CredentialBinding {
    /// Checks a binding: the source is for the same host, and a token that belongs to one
    /// organisation covers only that organisation.
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`] naming what does not fit.
    pub fn new(host: &HostName, source: SourceSpec, covers: Coverage) -> Result<Self, StoreError> {
        let host = HostName::new(host.as_str().to_ascii_lowercase())
            .map_err(|_| invalid("not a valid host"))?;
        let scope = source.scope();
        if !same_host(&scope.host, &host) {
            return Err(invalid(format!(
                "the credential source is for {} but the binding is for {host}",
                scope.host
            )));
        }
        if let Some(org) = scope.org {
            let only = Owner::new(org.as_str())?;
            if covers.rest_of_host || covers.owners.iter().any(|o| *o != only) {
                return Err(invalid(format!(
                    "a token for the organisation {org} can only cover {org}"
                )));
            }
        }
        Ok(Self {
            host,
            source,
            covers,
        })
    }

    fn collides_with(&self, other: &Self) -> Option<CollisionWhat> {
        if !same_host(&self.host, &other.host) {
            return None;
        }
        if let Some(owner) = self.covers.owners.intersection(&other.covers.owners).next() {
            return Some(CollisionWhat::Owner(owner.clone()));
        }
        (self.covers.rest_of_host && other.covers.rest_of_host).then_some(CollisionWhat::RestOfHost)
    }
}

/// What a client sends to make or replace an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDraft {
    /// The name the user sees.
    pub label: String,
    /// The commit author.
    pub author: Author,
    /// The credentials, in the order the user keeps them.
    pub credentials: Vec<CredentialBinding>,
}

impl IdentityDraft {
    /// Checks a draft: a label, and credentials that do not collide with each other (one
    /// identity can't cover the same owner twice).
    ///
    /// # Errors
    /// [`StoreError::IdentityInvalid`].
    pub fn checked(self) -> Result<Self, StoreError> {
        let label = plain(&self.label, MAX_LABEL, "the label")?;
        if self.credentials.len() > MAX_CREDENTIALS {
            return Err(invalid(format!(
                "an identity holds at most {MAX_CREDENTIALS} credentials"
            )));
        }
        for (i, a) in self.credentials.iter().enumerate() {
            for b in self.credentials.iter().skip(i + 1) {
                if let Some(what) = a.collides_with(b) {
                    return Err(invalid(format!(
                        "two credentials of one identity both cover {}",
                        what.describe(&a.host)
                    )));
                }
            }
        }
        Ok(Self { label, ..self })
    }
}

/// An identity: an author and the credentials it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Identity {
    /// Its number.
    pub id: IdentityId,
    /// The name the user sees.
    pub label: String,
    /// The commit author.
    pub author: Author,
    /// The credentials, as references to their sources.
    pub credentials: Vec<CredentialBinding>,
    /// How it signs commits.
    pub signing: Signing,
    /// Whether it is the default (the one a new workspace gets when none covers its URL).
    pub is_default: bool,
    /// Epoch ms it was made.
    pub created_at: u64,
    /// Epoch ms it last changed.
    pub changed_at: u64,
}

/// What two identities both cover.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CollisionWhat {
    /// The same owner or organisation.
    Owner(Owner),
    /// Both cover the rest of the host.
    RestOfHost,
}

impl CollisionWhat {
    fn describe(&self, host: &HostName) -> String {
        match self {
            Self::Owner(owner) => format!("{host}/{owner}"),
            Self::RestOfHost => format!("the rest of {host}"),
        }
    }
}

/// Two identities whose coverage meets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Collision {
    /// The label of the identity already there.
    pub first: String,
    /// The label of the one that can't join.
    pub second: String,
    /// The host.
    pub host: HostName,
    /// What both cover.
    pub what: CollisionWhat,
}

impl fmt::Display for Collision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} and {} both cover {}; narrow one",
            self.first,
            self.second,
            self.what.describe(&self.host)
        )
    }
}

/// The first place `a` and `b` both cover, if any.
#[must_use]
pub fn collision(a: &Identity, b: &Identity) -> Option<Collision> {
    for x in &a.credentials {
        for y in &b.credentials {
            if let Some(what) = x.collides_with(y) {
                return Some(Collision {
                    first: a.label.clone(),
                    second: b.label.clone(),
                    host: x.host.clone(),
                    what,
                });
            }
        }
    }
    None
}

/// Whether `candidate` can join the identities already on a workspace.
///
/// # Errors
/// The [`Collision`] with the first identity in the list that it meets.
pub fn check_attachable(attached: &[Identity], candidate: &Identity) -> Result<(), Collision> {
    attached
        .iter()
        .filter(|other| other.id != candidate.id)
        .find_map(|other| collision(other, candidate))
        .map_or(Ok(()), Err)
}

/// Which credential a request gets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialChoice<'a> {
    /// One identity covers it. `exact` is true when it names the owner, false for "rest of host".
    Covered {
        /// The identity.
        identity: &'a Identity,
        /// Its credential.
        binding: &'a CredentialBinding,
        /// Whether the owner is named.
        exact: bool,
    },
    /// No attached identity covers it: the request goes out without a credential.
    Uncovered,
    /// More than one identity covers it at the same level. Attaching refuses this, so seeing it
    /// means a bug or a hand-edited store; the caller refuses the request and never guesses.
    Ambiguous(Vec<IdentityId>),
}

/// The credential for a request to `host` about `owner` (the owner or organisation in the path).
/// An identity that names the owner beats one that covers the rest of the host.
#[must_use]
pub fn resolve<'a>(attached: &'a [Identity], host: &str, owner: &str) -> CredentialChoice<'a> {
    let owner = owner.to_ascii_lowercase();
    for exact in [true, false] {
        let mut hits: Vec<(&Identity, &CredentialBinding)> = Vec::new();
        for identity in attached {
            for binding in &identity.credentials {
                if !binding.host.as_str().eq_ignore_ascii_case(host) {
                    continue;
                }
                let hit = if exact {
                    binding.covers.owners.iter().any(|o| o.as_str() == owner)
                } else {
                    binding.covers.rest_of_host
                };
                if hit {
                    hits.push((identity, binding));
                }
            }
        }
        let Some(&(identity, binding)) = hits.first() else {
            continue;
        };
        let mut ids: Vec<IdentityId> = hits.iter().map(|(i, _)| i.id).collect();
        ids.sort();
        ids.dedup();
        // Two bindings of one identity can't both match (checked on save); if a hand-edited row
        // does, the first one wins and the request is still safe.
        return if ids.len() == 1 {
            CredentialChoice::Covered {
                identity,
                binding,
                exact,
            }
        } else {
            CredentialChoice::Ambiguous(ids)
        };
    }
    CredentialChoice::Uncovered
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use puddle_secrets::{AccountName, StoredId, TokenScope};

    const HOSTS: [&str; 2] = ["github.com", "dev.azure.com"];
    const OWNERS: [&str; 4] = ["acme", "acme-labs", "me", "other"];

    fn binding(host: &str, owners: &[&str], rest: bool) -> CredentialBinding {
        let owners = owners.iter().map(|o| Owner::new(o).unwrap()).collect();
        CredentialBinding::new(
            &HostName::new(host).unwrap(),
            SourceSpec::Gh {
                host: HostName::new(host).unwrap(),
                account: AccountName::new("me").unwrap(),
            },
            Coverage::new(owners, rest).unwrap(),
        )
        .unwrap()
    }

    fn identity(id: i64, label: &str, credentials: Vec<CredentialBinding>) -> Identity {
        Identity {
            id: IdentityId(id),
            label: label.to_owned(),
            author: Author::new("Me", "me@example.com").unwrap(),
            credentials,
            signing: Signing::None,
            is_default: false,
            created_at: 0,
            changed_at: 0,
        }
    }

    #[test]
    fn exact_owner_beats_rest_of_host() {
        let work = identity(
            1,
            "Work",
            vec![binding("github.com", &["acme", "acme-labs"], false)],
        );
        let personal = identity(2, "Personal", vec![binding("github.com", &[], true)]);
        let both = [work, personal];
        for (owner, who, exact) in [("acme", 1, true), ("ACME-Labs", 1, true), ("me", 2, false)] {
            match resolve(&both, "GitHub.com", owner) {
                CredentialChoice::Covered {
                    identity, exact: e, ..
                } => {
                    assert_eq!((identity.id, e), (IdentityId(who), exact), "{owner}");
                }
                other => panic!("{owner}: {other:?}"),
            }
        }
        assert_eq!(
            resolve(&both, "dev.azure.com", "acme"),
            CredentialChoice::Uncovered
        );
    }

    #[test]
    fn a_collision_names_both_and_the_place() {
        let work = identity(1, "Work", vec![binding("github.com", &["acme"], false)]);
        let personal = identity(
            2,
            "Personal",
            vec![binding("github.com", &["Acme", "me"], false)],
        );
        let c = check_attachable(std::slice::from_ref(&work), &personal).unwrap_err();
        assert_eq!(
            c.to_string(),
            "Work and Personal both cover github.com/acme; narrow one"
        );
        let rest = identity(3, "Rest", vec![binding("github.com", &[], true)]);
        let rest2 = identity(4, "Other rest", vec![binding("github.com", &["x"], true)]);
        let c = check_attachable(&[rest], &rest2).unwrap_err();
        assert_eq!(
            c.to_string(),
            "Rest and Other rest both cover the rest of github.com; narrow one"
        );
        // Another host, or an exact owner against the rest of the host, is no collision.
        let azure = identity(5, "Azure", vec![binding("dev.azure.com", &["acme"], true)]);
        assert!(check_attachable(std::slice::from_ref(&work), &azure).is_ok());
        let rest = identity(6, "Rest", vec![binding("github.com", &[], true)]);
        assert!(check_attachable(std::slice::from_ref(&work), &rest).is_ok());
    }

    #[test]
    fn an_identity_does_not_collide_with_itself() {
        let work = identity(1, "Work", vec![binding("github.com", &["acme"], false)]);
        assert!(check_attachable(std::slice::from_ref(&work), &work).is_ok());
    }

    #[test]
    fn a_hand_edited_overlap_is_ambiguous_never_a_guess() {
        let a = identity(1, "A", vec![binding("github.com", &["acme"], false)]);
        let b = identity(2, "B", vec![binding("github.com", &["acme"], false)]);
        assert_eq!(
            resolve(&[a, b], "github.com", "acme"),
            CredentialChoice::Ambiguous(vec![IdentityId(1), IdentityId(2)])
        );
    }

    #[test]
    fn bindings_are_checked() {
        let host = HostName::new("dev.azure.com").unwrap();
        let stored = SourceSpec::Stored {
            id: StoredId::new("t1").unwrap(),
            scope: TokenScope {
                host: host.clone(),
                org: Some(OrgName::new("Contoso").unwrap()),
            },
        };
        let own = Coverage::new([Owner::new("contoso").unwrap()].into(), false).unwrap();
        assert!(CredentialBinding::new(&host, stored.clone(), own).is_ok());
        let other = Coverage::new([Owner::new("acme").unwrap()].into(), false).unwrap();
        assert!(CredentialBinding::new(&host, stored.clone(), other).is_err());
        let rest = Coverage::new(BTreeSet::new(), true).unwrap();
        assert!(CredentialBinding::new(&host, stored, rest.clone()).is_err());
        let gh = SourceSpec::Gh {
            host: HostName::new("github.com").unwrap(),
            account: AccountName::new("me").unwrap(),
        };
        assert!(CredentialBinding::new(&host, gh, rest).is_err());
        assert!(Coverage::new(BTreeSet::new(), false).is_err());
    }

    #[test]
    fn author_and_label_are_checked() {
        assert!(Author::new("Me", "me@example.com").is_ok());
        for (name, email) in [
            ("", "a@b"),
            ("Me", "nobody"),
            ("Me", "a b@c"),
            ("Me", "@c"),
            ("M\ne", "a@b"),
            ("Me", "a@b@c"),
        ] {
            assert!(Author::new(name, email).is_err(), "{name:?} {email:?}");
        }
        let draft = |label: &str, credentials| IdentityDraft {
            label: label.into(),
            author: Author::new("Me", "me@example.com").unwrap(),
            credentials,
        };
        assert!(draft(" ", vec![]).checked().is_err());
        assert_eq!(draft(" Work ", vec![]).checked().unwrap().label, "Work");
        let twice = vec![
            binding("github.com", &["acme"], false),
            binding("github.com", &["acme"], false),
        ];
        assert!(draft("x", twice).checked().is_err());
        let many = vec![binding("github.com", &["a"], false); MAX_CREDENTIALS + 1];
        assert!(draft("x", many).checked().is_err());
    }

    #[test]
    fn coverage_survives_json_and_rejects_nonsense() {
        let c = binding("github.com", &["Acme"], true);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""owners":["acme"]"#), "{json}");
        assert_eq!(serde_json::from_str::<CredentialBinding>(&json).unwrap(), c);
        let empty = json.replace(
            r#""owners":["acme"],"rest_of_host":true"#,
            r#""owners":[],"rest_of_host":false"#,
        );
        assert!(serde_json::from_str::<CredentialBinding>(&empty).is_err());
    }

    fn arb_binding() -> impl Strategy<Value = CredentialBinding> {
        (
            0..HOSTS.len(),
            proptest::collection::vec(0..OWNERS.len(), 0..3),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_filter_map("empty coverage", |(h, owners, rest, upper)| {
                let names: Vec<String> = owners
                    .iter()
                    .map(|&i| {
                        if upper {
                            OWNERS[i].to_ascii_uppercase()
                        } else {
                            OWNERS[i].to_owned()
                        }
                    })
                    .collect();
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                (!refs.is_empty() || rest).then(|| binding(HOSTS[h], &refs, rest))
            })
    }

    fn arb_identities() -> impl Strategy<Value = Vec<Identity>> {
        proptest::collection::vec(proptest::collection::vec(arb_binding(), 1..3), 1..6).prop_map(
            |all| {
                all.into_iter()
                    .enumerate()
                    .map(|(i, creds)| {
                        identity(i64::try_from(i).unwrap() + 1, &format!("I{i}"), creds)
                    })
                    .collect()
            },
        )
    }

    proptest! {
        /// Attach greedily the way the store does; then no request has two candidates, and the
        /// winner is the identity that names the owner, else the one that covers the rest.
        #[test]
        fn no_two_attached_identities_match_one_request(candidates in arb_identities()) {
            let mut attached: Vec<Identity> = Vec::new();
            for candidate in candidates {
                if candidate.credentials.iter().enumerate().any(|(i, a)| {
                    candidate.credentials.iter().skip(i + 1).any(|b| a.collides_with(b).is_some())
                }) {
                    continue;
                }
                if check_attachable(&attached, &candidate).is_ok() {
                    attached.push(candidate);
                }
            }
            for host in HOSTS {
                for owner in OWNERS.iter().map(|o| o.to_ascii_uppercase()).chain(["nobody".to_owned()]) {
                    let low = owner.to_ascii_lowercase();
                    let names: Vec<_> = attached.iter().filter(|i| i.credentials.iter().any(|b|
                        b.host.as_str() == host && b.covers.owners.iter().any(|o| o.as_str() == low))).collect();
                    let rests: Vec<_> = attached.iter().filter(|i| i.credentials.iter().any(|b|
                        b.host.as_str() == host && b.covers.rest_of_host)).collect();
                    prop_assert!(names.len() <= 1 && rests.len() <= 1);
                    match resolve(&attached, host, &owner) {
                        CredentialChoice::Covered { identity, exact, binding } => {
                            prop_assert_eq!(exact, !names.is_empty());
                            let expected = if exact { names[0] } else { rests[0] };
                            prop_assert_eq!(identity.id, expected.id);
                            prop_assert_eq!(binding.host.as_str(), host);
                        }
                        CredentialChoice::Uncovered => prop_assert!(names.is_empty() && rests.is_empty()),
                        other => prop_assert!(false, "ambiguous: {other:?}"),
                    }
                }
            }
        }

        #[test]
        fn collisions_are_symmetric(identities in arb_identities()) {
            for a in &identities {
                for b in &identities {
                    prop_assert_eq!(collision(a, b).is_some(), collision(b, a).is_some());
                }
            }
        }
    }
}
