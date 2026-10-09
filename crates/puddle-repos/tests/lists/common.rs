// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared test parts: scripted tokens, identities from a real in-memory store, a rig.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::future::BoxFuture;
use puddle_repos::{FakeApi, Freshness, Read, Repos, Secrets, SourceList};
use puddle_secrets::{
    AccountName, Credential, HostName, OrgName, Secret, SourceError, SourceSpec, StoredId,
    TokenScope, UrlPath,
};
use puddle_store::{
    Author, Coverage, CredentialBinding, Identity, IdentityDraft, IdentityId, Limits, ManualClock,
    Owner, Store,
};

/// Where the test clock starts (epoch milliseconds).
pub(crate) const T0: u64 = 1_700_000_000_000;

pub(crate) fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

pub(crate) fn ok_json(name: &str) -> puddle_repos::ApiReply {
    puddle_repos::ApiReply::new(200, data(name))
}

/// The first page of a GitHub list, as the crate asks for it.
pub(crate) const REPOS_PATH: &str = "/user/repos?per_page=100&sort=full_name&direction=asc";

pub(crate) fn host(name: &str) -> HostName {
    HostName::new(name).unwrap()
}

pub(crate) fn gh(host_name: &str, account: &str) -> SourceSpec {
    SourceSpec::Gh {
        host: host(host_name),
        account: AccountName::new(account).unwrap(),
    }
}

pub(crate) fn gcm(host_name: &str, path: &str) -> SourceSpec {
    SourceSpec::GitCredential {
        host: host(host_name),
        path: UrlPath::new(path).unwrap(),
        username: None,
    }
}

pub(crate) fn stored(id: &str, host_name: &str, org: Option<&str>) -> SourceSpec {
    SourceSpec::Stored {
        id: StoredId::new(id).unwrap(),
        scope: TokenScope {
            host: host(host_name),
            org: org.map(|o| OrgName::new(o).unwrap()),
        },
    }
}

pub(crate) fn binding(
    host_name: &str,
    source: SourceSpec,
    owners: &[&str],
    rest_of_host: bool,
) -> CredentialBinding {
    let owners: BTreeSet<Owner> = owners.iter().map(|o| Owner::new(o).unwrap()).collect();
    CredentialBinding::new(
        &host(host_name),
        source,
        Coverage::new(owners, rest_of_host).unwrap(),
    )
    .unwrap()
}

/// Identities as a real store makes them, in this order (ids 1, 2, ...).
pub(crate) fn identities(specs: Vec<(&str, Vec<CredentialBinding>)>) -> Vec<Identity> {
    let store = Store::open_in_memory(Arc::new(ManualClock::new(T0)), Limits::default()).unwrap();
    specs
        .into_iter()
        .map(|(label, credentials)| {
            store
                .create_identity(IdentityDraft {
                    label: label.to_owned(),
                    author: Author::new(label, "me@example.org").unwrap(),
                    credentials,
                })
                .unwrap()
        })
        .collect()
}

/// Tokens by source; a source with none is "not signed in".
#[derive(Default)]
pub(crate) struct Tokens {
    by_source: Mutex<HashMap<SourceSpec, Result<String, SourceError>>>,
    invalidated: Mutex<Vec<SourceSpec>>,
}

impl Tokens {
    pub(crate) fn set(&self, source: &SourceSpec, token: &str) {
        self.put(source, Ok(token.to_owned()));
    }

    pub(crate) fn fail(&self, source: &SourceSpec, err: SourceError) {
        self.put(source, Err(err));
    }

    fn put(&self, source: &SourceSpec, answer: Result<String, SourceError>) {
        self.by_source
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(source.clone(), answer);
    }

    pub(crate) fn invalidated(&self) -> Vec<SourceSpec> {
        self.invalidated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Secrets for Tokens {
    fn get<'a>(&'a self, spec: &'a SourceSpec) -> BoxFuture<'a, Result<Credential, SourceError>> {
        Box::pin(async move {
            let found = self
                .by_source
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(spec)
                .cloned();
            match found {
                Some(Ok(token)) => Ok(Credential {
                    username: None,
                    secret: Arc::new(Secret::new(token)),
                }),
                Some(Err(err)) => Err(err),
                None => Err(SourceError::NotSignedIn),
            }
        })
    }

    fn invalidate(&self, spec: &SourceSpec) {
        self.invalidated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(spec.clone());
    }
}

/// Everything a test needs: the scripted host, the tokens, the clock and the lists.
pub(crate) struct Rig {
    pub(crate) api: Arc<FakeApi>,
    pub(crate) tokens: Arc<Tokens>,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) repos: Repos,
}

impl Rig {
    pub(crate) fn new() -> Self {
        let api = Arc::new(FakeApi::new());
        let tokens = Arc::new(Tokens::default());
        let clock = Arc::new(ManualClock::new(T0));
        let repos = Repos::new(api.clone(), tokens.clone(), clock.clone());
        Self {
            api,
            tokens,
            clock,
            repos,
        }
    }

    pub(crate) async fn lists(&self, ids: &[Identity], freshness: Freshness) -> Vec<SourceList> {
        self.repos
            .lists(
                ids,
                Read {
                    only: None,
                    freshness,
                },
            )
            .await
    }

    pub(crate) async fn lists_of(
        &self,
        ids: &[Identity],
        only: IdentityId,
        freshness: Freshness,
    ) -> Vec<SourceList> {
        self.repos
            .lists(
                ids,
                Read {
                    only: Some(only),
                    freshness,
                },
            )
            .await
    }
}
