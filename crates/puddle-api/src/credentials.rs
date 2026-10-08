// SPDX-License-Identifier: GPL-3.0-or-later
//! The host side of the identities screens: which accounts are already signed in on this computer,
//! whether puddle can read a credential now, a pasted token's entry in the OS credential store, and
//! signing in on a click ([`CredentialService`]). [`HostCredentials`] runs the real sources;
//! [`FakeCredentials`] answers from what a test or the UI fixture put in it.
//!
//! No method returns a secret value. A pasted token goes in and is never read back through here;
//! the injector and the host-side API calls read it through `puddle-secrets` directly.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use futures_util::future::BoxFuture;
use puddle_secrets::{
    Discovery, Fetch, KeyringStore, SecretStore, SignInError, SignInStart, SignIns, SourceError,
    SourceSpec, Sources, StoredId, TokenScope, ToolPaths, discover, pasted_token,
};

/// Why a call could not be answered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialsError {
    /// Not wired in this build or state (503).
    #[error("{0}")]
    Unavailable(String),
    /// A value is refused (422).
    #[error("{0}")]
    Invalid(String),
    /// Something broke; the detail is for the log (500).
    #[error("{0}")]
    Internal(String),
}

/// What reading a credential came to. Never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Check {
    /// The source gave a value.
    Readable,
    /// It did not, and why.
    Problem(SourceError),
}

/// What the identities screens need from the host.
pub trait CredentialService: Send + Sync {
    /// The accounts already signed in on this computer, from the fixed listing commands.
    fn found(&self) -> BoxFuture<'_, Result<Discovery, CredentialsError>>;

    /// Reads the credential once and says whether that worked. Never interactive.
    fn check(&self, source: SourceSpec) -> BoxFuture<'_, Result<Check, CredentialsError>>;

    /// Keeps a pasted token in the OS credential store and returns the source that names it.
    fn store_token(
        &self,
        scope: TokenScope,
        token: String,
    ) -> BoxFuture<'_, Result<SourceSpec, CredentialsError>>;

    /// Removes a pasted token; one that is already gone counts as removed.
    fn forget_token(&self, id: StoredId) -> BoxFuture<'_, Result<(), CredentialsError>>;

    /// Starts a sign-in the user finishes outside puddle. Only ever from a click.
    fn sign_in(&self, source: SourceSpec) -> BoxFuture<'_, Result<SignInStart, CredentialsError>>;
}

/// The service when none is wired in: every call says so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCredentials;

fn not_wired() -> CredentialsError {
    CredentialsError::Unavailable("credentials are not available in this build yet".into())
}

impl CredentialService for NoCredentials {
    fn found(&self) -> BoxFuture<'_, Result<Discovery, CredentialsError>> {
        Box::pin(async { Err(not_wired()) })
    }
    fn check(&self, _source: SourceSpec) -> BoxFuture<'_, Result<Check, CredentialsError>> {
        Box::pin(async { Err(not_wired()) })
    }
    fn store_token(
        &self,
        _scope: TokenScope,
        _token: String,
    ) -> BoxFuture<'_, Result<SourceSpec, CredentialsError>> {
        Box::pin(async { Err(not_wired()) })
    }
    fn forget_token(&self, _id: StoredId) -> BoxFuture<'_, Result<(), CredentialsError>> {
        Box::pin(async { Err(not_wired()) })
    }
    fn sign_in(&self, _source: SourceSpec) -> BoxFuture<'_, Result<SignInStart, CredentialsError>> {
        Box::pin(async { Err(not_wired()) })
    }
}

fn sign_in_error(err: SignInError) -> CredentialsError {
    let said = err.to_string();
    match err {
        SignInError::NothingToSignIn => CredentialsError::Invalid(
            "a pasted token has nothing to sign in to; paste a new one".into(),
        ),
        SignInError::NoPrompt(..) => {
            CredentialsError::Unavailable(format!("{said}; try again, or sign in from a terminal"))
        }
        SignInError::Ended(..) => CredentialsError::Unavailable(format!(
            "{said}; Git Credential Manager is what signs in here, so check that Git can run it"
        )),
        SignInError::Source(err) => {
            CredentialsError::Unavailable(crate::wire::source_problem(&err))
        }
        // `SignInError` grows with the Azure CLI.
        _ => CredentialsError::Unavailable(said),
    }
}

/// A fresh id for a pasted token: `tok-` and 128 random bits.
fn new_stored_id() -> Result<StoredId, CredentialsError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| CredentialsError::Internal(err.to_string()))?;
    let id = bytes
        .iter()
        .fold(String::from("tok-"), |id, byte| format!("{id}{byte:02x}"));
    StoredId::new(id).map_err(|err| CredentialsError::Internal(err.to_string()))
}

/// The real thing, over `puddle-secrets`. Cheap to share.
pub struct HostCredentials {
    tools: ToolPaths,
    sources: Sources,
    store: Arc<dyn SecretStore>,
    sign_ins: SignIns,
}

impl std::fmt::Debug for HostCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostCredentials").finish_non_exhaustive()
    }
}

impl HostCredentials {
    /// Sources that run the tools at `tools` and keep pasted tokens in `store`.
    #[must_use]
    pub fn new(tools: ToolPaths, store: Arc<dyn SecretStore>) -> Self {
        Self {
            sources: Sources::new(tools.clone(), Arc::clone(&store)),
            sign_ins: SignIns::new(tools.clone()),
            tools,
            store,
        }
    }

    /// The sources of this computer: `gh` and `git` found on `PATH`, pasted tokens in the
    /// operating system's credential store.
    #[must_use]
    pub fn on_this_computer() -> Self {
        Self::new(ToolPaths::resolve(), Arc::new(KeyringStore))
    }

    /// The same with these sign-ins (to change how long one stays open).
    #[must_use]
    pub fn with_sign_ins(mut self, sign_ins: SignIns) -> Self {
        self.sign_ins = sign_ins;
        self
    }
}

impl CredentialService for HostCredentials {
    fn found(&self) -> BoxFuture<'_, Result<Discovery, CredentialsError>> {
        Box::pin(async move { Ok(discover(&self.tools).await) })
    }

    fn check(&self, source: SourceSpec) -> BoxFuture<'_, Result<Check, CredentialsError>> {
        Box::pin(async move {
            Ok(match self.sources.fetch(&source).await {
                Ok(_) => Check::Readable,
                Err(err) => Check::Problem(err),
            })
        })
    }

    fn store_token(
        &self,
        scope: TokenScope,
        token: String,
    ) -> BoxFuture<'_, Result<SourceSpec, CredentialsError>> {
        Box::pin(async move {
            let secret = pasted_token(&token).map_err(|_| {
                CredentialsError::Invalid(
                    "that is not a usable token: it is empty or has spaces or control characters"
                        .into(),
                )
            })?;
            drop(token);
            let id = new_stored_id()?;
            let (store, key) = (Arc::clone(&self.store), id.clone());
            tokio::task::spawn_blocking(move || store.set(&key, &secret))
                .await
                .map_err(|err| CredentialsError::Internal(err.to_string()))?
                .map_err(|_| {
                    CredentialsError::Unavailable(
                        "the operating system's credential store is not available".into(),
                    )
                })?;
            Ok(SourceSpec::Stored { id, scope })
        })
    }

    fn forget_token(&self, id: StoredId) -> BoxFuture<'_, Result<(), CredentialsError>> {
        Box::pin(async move {
            let store = Arc::clone(&self.store);
            tokio::task::spawn_blocking(move || store.delete(&id))
                .await
                .map_err(|err| CredentialsError::Internal(err.to_string()))?
                .map_err(|_| {
                    CredentialsError::Unavailable(
                        "the operating system's credential store is not available".into(),
                    )
                })
        })
    }

    fn sign_in(&self, source: SourceSpec) -> BoxFuture<'_, Result<SignInStart, CredentialsError>> {
        Box::pin(async move { self.sign_ins.begin(&source).await.map_err(sign_in_error) })
    }
}

/// Answers from what a test or the UI fixture put in it: the accounts "found", which credentials
/// are readable, the code a sign-in shows. A sign-in makes the credential readable, as a finished
/// one would. Pasted tokens are kept by id only so a test can see that one was stored or removed.
#[derive(Default)]
pub struct FakeCredentials {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    found: Option<Discovery>,
    unreadable: HashMap<SourceSpec, SourceError>,
    sign_in: SignInStart,
    tokens: HashSet<String>,
    next_token: u64,
    sign_ins: Vec<SourceSpec>,
}

impl std::fmt::Debug for FakeCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeCredentials").finish_non_exhaustive()
    }
}

impl FakeCredentials {
    /// Nothing found, everything readable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What `found` answers from now on.
    pub fn set_found(&self, found: Discovery) {
        self.state().found = Some(found);
    }

    /// Makes `source` unreadable with this reason (`None` makes it readable again).
    pub fn set_unreadable(&self, source: SourceSpec, why: Option<SourceError>) {
        let mut state = self.state();
        match why {
            Some(why) => state.unreadable.insert(source, why),
            None => state.unreadable.remove(&source),
        };
    }

    /// What a sign-in shows the user.
    pub fn set_sign_in(&self, start: SignInStart) {
        self.state().sign_in = start;
    }

    /// The ids of the tokens kept, in no order.
    #[must_use]
    pub fn tokens(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.state().tokens.iter().cloned().collect();
        ids.sort();
        ids
    }

    /// The sources a sign-in was started for, in order.
    #[must_use]
    pub fn sign_ins(&self) -> Vec<SourceSpec> {
        self.state().sign_ins.clone()
    }
}

impl CredentialService for FakeCredentials {
    fn found(&self) -> BoxFuture<'_, Result<Discovery, CredentialsError>> {
        Box::pin(async move { Ok(self.state().found.clone().unwrap_or_default()) })
    }

    fn check(&self, source: SourceSpec) -> BoxFuture<'_, Result<Check, CredentialsError>> {
        Box::pin(async move {
            Ok(match self.state().unreadable.get(&source) {
                Some(why) => Check::Problem(why.clone()),
                None => Check::Readable,
            })
        })
    }

    fn store_token(
        &self,
        scope: TokenScope,
        token: String,
    ) -> BoxFuture<'_, Result<SourceSpec, CredentialsError>> {
        Box::pin(async move {
            pasted_token(&token)
                .map_err(|_| CredentialsError::Invalid("that is not a usable token".into()))?;
            let mut state = self.state();
            state.next_token += 1;
            let id = format!("tok-fake-{}", state.next_token);
            state.tokens.insert(id.clone());
            let id =
                StoredId::new(id).map_err(|err| CredentialsError::Internal(err.to_string()))?;
            Ok(SourceSpec::Stored { id, scope })
        })
    }

    fn forget_token(&self, id: StoredId) -> BoxFuture<'_, Result<(), CredentialsError>> {
        Box::pin(async move {
            self.state().tokens.remove(id.as_str());
            Ok(())
        })
    }

    fn sign_in(&self, source: SourceSpec) -> BoxFuture<'_, Result<SignInStart, CredentialsError>> {
        Box::pin(async move {
            if matches!(source, SourceSpec::Stored { .. }) {
                return Err(sign_in_error(SignInError::NothingToSignIn));
            }
            let mut state = self.state();
            state.unreadable.remove(&source);
            state.sign_ins.push(source);
            Ok(state.sign_in.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use puddle_secrets::Tool;

    use super::*;

    #[test]
    fn a_sign_in_that_could_not_start_says_what_happened_and_what_to_try() {
        let said = |err| match sign_in_error(err) {
            CredentialsError::Unavailable(m) | CredentialsError::Invalid(m) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            said(SignInError::NoPrompt(
                Tool::Gh,
                "x509: unknown authority".into()
            )),
            "gh did not show a sign-in code: x509: unknown authority; try again, or sign in from a terminal"
        );
        assert_eq!(
            said(SignInError::Ended(Tool::Git, String::new())),
            "git ended without signing in; Git Credential Manager is what signs in here, so check that Git can run it"
        );
        assert_eq!(
            said(SignInError::Source(SourceError::ToolMissing(Tool::Gh))),
            "gh is not installed or not on PATH"
        );
        assert!(said(SignInError::NothingToSignIn).starts_with("a pasted token has nothing"));
    }
}
