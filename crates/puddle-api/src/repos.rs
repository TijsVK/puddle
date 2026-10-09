// SPDX-License-Identifier: GPL-3.0-or-later
//! The host side of the repository lists and the account profile ([`RepoService`]): which
//! repositories each identity's credentials reach, and who a credential's account is, to prefill
//! an identity. [`Repos`] reads them from the Git hosts over puddle's own route; [`FakeRepos`]
//! answers from what a test or the UI fixture put in it.
//!
//! No method returns a secret, and nothing here reaches a workspace: the lists are read on the
//! host with the credential's own token and kept in memory.

use std::sync::{Mutex, PoisonError};

use futures_util::future::BoxFuture;
use puddle_repos::{Problem, ProblemKind, Profile, ProfileRead, Read, Repos, SourceList};
use puddle_secrets::SourceSpec;
use puddle_store::Identity;

/// Why a call could not be answered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReposError {
    /// Not wired in this build or state (503).
    #[error("{0}")]
    Unavailable(String),
}

/// What the Identities tab and the create form ask of the host about repositories.
pub trait RepoService: Send + Sync {
    /// One list for each credential of `identities` (for an Azure DevOps credential, one for each
    /// organisation it names), from the cache or read now as `read` says. Pass every identity:
    /// `read.only` narrows what is read and returned, and the rest decides what is forgotten.
    fn lists<'a>(
        &'a self,
        identities: &'a [Identity],
        read: Read,
    ) -> BoxFuture<'a, Result<Vec<SourceList>, ReposError>>;

    /// Who `source`'s account is: the author and organisations to offer an identity. A host that
    /// cannot say answers with the reason inside the [`ProfileRead`], not as an error.
    fn profile(&self, source: SourceSpec) -> BoxFuture<'_, Result<ProfileRead, ReposError>>;
}

/// The service when none is wired in: every call says so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRepos;

fn not_wired() -> ReposError {
    ReposError::Unavailable("repository lists are not available in this build yet".into())
}

impl RepoService for NoRepos {
    fn lists<'a>(
        &'a self,
        _identities: &'a [Identity],
        _read: Read,
    ) -> BoxFuture<'a, Result<Vec<SourceList>, ReposError>> {
        Box::pin(async { Err(not_wired()) })
    }

    fn profile(&self, _source: SourceSpec) -> BoxFuture<'_, Result<ProfileRead, ReposError>> {
        Box::pin(async { Err(not_wired()) })
    }
}

impl RepoService for Repos {
    fn lists<'a>(
        &'a self,
        identities: &'a [Identity],
        read: Read,
    ) -> BoxFuture<'a, Result<Vec<SourceList>, ReposError>> {
        Box::pin(async move { Ok(Repos::lists(self, identities, read).await) })
    }

    fn profile(&self, source: SourceSpec) -> BoxFuture<'_, Result<ProfileRead, ReposError>> {
        Box::pin(async move { Ok(Repos::profile(self, &source).await) })
    }
}

/// Answers from what a test or the UI fixture put in it: the lists to show (those of the
/// identities asked for) and the profile of each source. Records what was asked.
#[derive(Default)]
pub struct FakeRepos {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    lists: Vec<SourceList>,
    profiles: Vec<(SourceSpec, ProfileRead)>,
    reads: Vec<Read>,
}

impl std::fmt::Debug for FakeRepos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeRepos").finish_non_exhaustive()
    }
}

impl FakeRepos {
    /// Nothing listed; every profile says the host could not be asked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The lists `lists` answers with from now on (each for the identity it names).
    pub fn set_lists(&self, lists: Vec<SourceList>) {
        self.state().lists = lists;
    }

    /// What `profile` answers for `source`.
    pub fn set_profile(&self, source: SourceSpec, read: ProfileRead) {
        let mut state = self.state();
        state.profiles.retain(|(known, _)| *known != source);
        state.profiles.push((source, read));
    }

    /// The reads asked for so far, in order.
    #[must_use]
    pub fn reads(&self) -> Vec<Read> {
        self.state().reads.clone()
    }
}

impl RepoService for FakeRepos {
    fn lists<'a>(
        &'a self,
        identities: &'a [Identity],
        read: Read,
    ) -> BoxFuture<'a, Result<Vec<SourceList>, ReposError>> {
        Box::pin(async move {
            let mut state = self.state();
            state.reads.push(read);
            Ok(state
                .lists
                .iter()
                .filter(|list| {
                    identities.iter().any(|i| i.id == list.identity)
                        && read.only.is_none_or(|id| id == list.identity)
                })
                .cloned()
                .collect())
        })
    }

    fn profile(&self, source: SourceSpec) -> BoxFuture<'_, Result<ProfileRead, ReposError>> {
        Box::pin(async move {
            let found = self
                .state()
                .profiles
                .iter()
                .find(|(known, _)| *known == source)
                .map(|(_, read)| read.clone());
            Ok(found.unwrap_or_else(|| ProfileRead {
                profile: Profile::default(),
                problem: Some(Problem {
                    kind: ProblemKind::Unreachable,
                    message: "the fake host has no profile for this credential".to_owned(),
                    retry_at: None,
                    needs_sign_in: false,
                }),
            }))
        })
    }
}
