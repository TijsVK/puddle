// SPDX-License-Identifier: GPL-3.0-or-later
//! In-memory settings and credential sources for tests, and a [`World`]: a workspace in a real
//! in-memory store with identities, a repository table and an injector over them. Never in
//! product code (feature `testing`).
#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers fail the test by panicking"
)]

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use puddle_proxy::BoxFuture;
use puddle_secrets::{
    Credential, HostName, OrgName, Secret, SourceError, SourceSpec, StoredId, TokenScope,
};
use puddle_store::{
    Author, Coverage, CredentialBinding, IdentityDraft, IdentityId, Limits, ManualClock, Owner,
    RepoRef, Store, WorkspaceGit,
};
use puddle_types::{CollectingSink, WorkspaceName};

use crate::injector::GitInjector;
use crate::source::{CredentialSource, GitSettings, SettingsError, StoreSettings};

/// Settings a test changes by hand.
#[derive(Debug)]
pub struct StaticSettings {
    git: Mutex<Result<WorkspaceGit, SettingsError>>,
}

impl StaticSettings {
    /// Settings that answer `git`.
    #[must_use]
    pub fn new(git: WorkspaceGit) -> Arc<Self> {
        Arc::new(Self {
            git: Mutex::new(Ok(git)),
        })
    }

    /// Changes the answer, as an edit in the UI would.
    pub fn set(&self, git: WorkspaceGit) {
        *self.git.lock().unwrap_or_else(PoisonError::into_inner) = Ok(git);
    }

    /// Makes every read fail with `reason`.
    pub fn fail(&self, reason: &str) {
        *self.git.lock().unwrap_or_else(PoisonError::into_inner) = Err(SettingsError::new(reason));
    }
}

impl GitSettings for StaticSettings {
    fn current(&self) -> BoxFuture<'_, Result<WorkspaceGit, SettingsError>> {
        let answer = self
            .git
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Box::pin(std::future::ready(answer))
    }
}

/// Secrets by source, read and forgotten as counted.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    answers: Mutex<HashMap<SourceSpec, Result<String, SourceError>>>,
    reads: AtomicUsize,
    forgotten: Mutex<Vec<SourceSpec>>,
}

impl StaticCredentials {
    /// No source answers yet.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// `source` answers `token`.
    pub fn give(&self, source: &SourceSpec, token: &str) {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(source.clone(), Ok(token.to_owned()));
    }

    /// `source` fails with `error`.
    pub fn fail(&self, source: &SourceSpec, error: SourceError) {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(source.clone(), Err(error));
    }

    /// How many reads were asked.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// The sources that were forgotten, in order.
    #[must_use]
    pub fn forgotten(&self) -> Vec<SourceSpec> {
        self.forgotten
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl CredentialSource for StaticCredentials {
    fn credential<'a>(
        &'a self,
        source: &'a SourceSpec,
    ) -> BoxFuture<'a, Result<Credential, SourceError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let answer = self
            .answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(source)
            .cloned()
            .unwrap_or(Err(SourceError::NotSignedIn));
        Box::pin(std::future::ready(answer.map(|token| Credential {
            username: None,
            secret: Arc::new(Secret::new(token)),
        })))
    }

    fn forget(&self, source: &SourceSpec) {
        self.forgotten
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(source.clone());
    }
}

/// A workspace `box` in a real in-memory store with an injector over it.
pub struct World {
    /// The store.
    pub store: Arc<Store>,
    /// The workspace.
    pub workspace: WorkspaceName,
    /// The secrets the identities' sources give.
    pub credentials: Arc<StaticCredentials>,
    /// The events the injector raised.
    pub events: Arc<CollectingSink>,
    /// The injector of the workspace, reading its settings from the store.
    pub injector: Arc<GitInjector>,
}

/// An identity made in a [`World`].
pub struct Made {
    /// Its number.
    pub id: IdentityId,
    /// The source of its token.
    pub source: SourceSpec,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    /// A workspace with no identity and an empty table.
    #[must_use]
    pub fn new() -> Self {
        let store = Arc::new(
            Store::open_in_memory(
                Arc::new(ManualClock::new(1_800_000_000_000)),
                Limits::default(),
            )
            .unwrap(),
        );
        let workspace = WorkspaceName::new("box").unwrap();
        let credentials = StaticCredentials::new();
        let events = Arc::new(CollectingSink::default());
        let injector = Arc::new(GitInjector::new(
            workspace.clone(),
            Arc::new(StoreSettings::new(Arc::clone(&store), workspace.clone())),
            credentials.clone(),
            events.clone(),
        ));
        Self {
            store,
            workspace,
            credentials,
            events,
            injector,
        }
    }

    /// An identity with one credential for `host` covering `owners` and, when `rest`, the rest of
    /// the host; its token is `token`. Attached to the workspace.
    #[expect(
        clippy::must_use_candidate,
        reason = "a caller that needs no more than the identity's presence ignores it"
    )]
    pub fn identity(
        &self,
        label: &str,
        host: &str,
        owners: &[&str],
        rest: bool,
        token: &str,
    ) -> Made {
        let made = self.identity_in_store(label, host, owners, rest, token, None);
        self.store
            .attach_identity(&self.workspace, made.id, None)
            .unwrap();
        made
    }

    /// As [`Self::identity`] but not attached, and with a token that belongs to the organisation
    /// `org` when one is named (Azure DevOps).
    #[must_use]
    pub fn identity_in_store(
        &self,
        label: &str,
        host: &str,
        owners: &[&str],
        rest: bool,
        token: &str,
        org: Option<&str>,
    ) -> Made {
        let host = HostName::new(host).unwrap();
        let source = SourceSpec::Stored {
            id: StoredId::new(format!("t-{}", label.to_lowercase())).unwrap(),
            scope: TokenScope {
                host: host.clone(),
                org: org.map(|org| OrgName::new(org).unwrap()),
            },
        };
        self.credentials.give(&source, token);
        let owners: BTreeSet<Owner> = owners.iter().map(|o| Owner::new(o).unwrap()).collect();
        let draft = IdentityDraft {
            label: label.to_owned(),
            author: Author::new(label, &format!("{}@example.com", label.to_lowercase())).unwrap(),
            credentials: vec![
                CredentialBinding::new(&host, source.clone(), Coverage::new(owners, rest).unwrap())
                    .unwrap(),
            ],
        };
        let id = self.store.create_identity(draft).unwrap().id;
        Made { id, source }
    }

    /// Lists `repo` (`host/owner/name`) in the table.
    pub fn list(&self, repo: &str, pull: bool, push: bool) {
        self.store
            .add_repo(&self.workspace, &repo_ref(repo), pull, push)
            .unwrap();
    }

    /// Sets "Only push to listed repos" and "Only pull from listed repos".
    pub fn switches(&self, only_push_listed: bool, only_pull_listed: bool) {
        self.store
            .set_git_switches(
                &self.workspace,
                Some(only_push_listed),
                Some(only_pull_listed),
            )
            .unwrap();
    }
}

/// The repository `host/owner/name` as the table spells it.
#[must_use]
pub fn repo_ref(text: &str) -> RepoRef {
    let (host, rest) = text.split_once('/').unwrap();
    let (owner, name) = rest.split_once('/').unwrap();
    RepoRef::new(host, owner, name).unwrap()
}
