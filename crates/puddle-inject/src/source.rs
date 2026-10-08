// SPDX-License-Identifier: GPL-3.0-or-later
//! What the injector asks of the rest of puddle: the workspace's Git settings, and the secret a
//! source holds. Two small traits, so the injector is tested without a store or a `gh`.

use std::fmt;
use std::sync::Arc;

use puddle_proxy::BoxFuture;
use puddle_secrets::{Credential, Fetch, SecretCache, SourceError, SourceSpec};
use puddle_store::{Store, WorkspaceGit};
use puddle_types::WorkspaceName;

/// The settings could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SettingsError(String);

impl SettingsError {
    /// An error with `reason`, one clause with no secret in it.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// A workspace's identities, repository table and switches, read for each request so a change
/// applies at once to a workspace that is running.
pub trait GitSettings: Send + Sync + fmt::Debug {
    /// The settings as they are now.
    fn current(&self) -> BoxFuture<'_, Result<WorkspaceGit, SettingsError>>;
}

/// The settings of one workspace in puddle's store.
#[derive(Debug, Clone)]
pub struct StoreSettings {
    store: Arc<Store>,
    workspace: WorkspaceName,
}

impl StoreSettings {
    /// The settings `workspace` has in `store`.
    #[must_use]
    pub fn new(store: Arc<Store>, workspace: WorkspaceName) -> Self {
        Self { store, workspace }
    }
}

impl GitSettings for StoreSettings {
    fn current(&self) -> BoxFuture<'_, Result<WorkspaceGit, SettingsError>> {
        // One small read of a local database, as the proxy's rule check is.
        let read = self
            .store
            .workspace_git(&self.workspace)
            .map_err(|err| SettingsError::new(err.to_string()));
        Box::pin(std::future::ready(read))
    }
}

/// Where the injector gets the secret a source names.
pub trait CredentialSource: Send + Sync {
    /// The credential `source` names: from memory while fresh, else read again.
    fn credential<'a>(
        &'a self,
        source: &'a SourceSpec,
    ) -> BoxFuture<'a, Result<Credential, SourceError>>;

    /// Drops what is held for `source`, so the next request reads it again: the host said the
    /// token was not accepted, and the user may have signed in again since.
    fn forget(&self, source: &SourceSpec);
}

impl<F: Fetch + 'static> CredentialSource for SecretCache<F> {
    fn credential<'a>(
        &'a self,
        source: &'a SourceSpec,
    ) -> BoxFuture<'a, Result<Credential, SourceError>> {
        Box::pin(self.get(source))
    }

    fn forget(&self, source: &SourceSpec) {
        self.invalidate(source);
    }
}
