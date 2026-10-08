// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's side of credential injection: one CA for each running sandbox, the registry that
//! tells the proxy which hosts each workspace decrypts, the injector all workspaces share and the
//! cache of secrets behind it.
//!
//! A sandbox's CA is made when the sandbox starts and dropped when it stops: it lives in this
//! process's memory only, and its certificate goes into the guest's trust at boot. The CA has no
//! name constraint, so the hosts a workspace decrypts are only what its [`Termination`] says, and
//! that is recomputed from the workspace's identities whenever they change: a credential for a
//! host the workspace has not used yet applies to the next connection, with no restart.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use puddle_ca::{CaBuilder, CaCertificate, WorkspaceCa};
use puddle_proxy::{Injector, Termination, TerminationSource, Terminations};
use puddle_secrets::{Fetch, SecretCache, Sources};
use puddle_store::{Store, WorkspaceGit};
use puddle_types::{Event, EventSink, WorkspaceName};
use tokio::task::JoinHandle;

use crate::git_hosts::decrypt_set;

/// What an injector is built from when the host starts.
#[derive(Clone)]
#[non_exhaustive]
pub struct InjectorInputs {
    /// The database: identities, and each workspace's Git settings.
    pub store: Arc<Store>,
    /// The host's one cache of secrets read from the user's own sign-ins (`gh`, Git, the operating
    /// system's store). Every workspace shares it, so one source is read once at a time.
    pub secrets: Arc<SecretCache<Sources>>,
}

impl std::fmt::Debug for InjectorInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectorInputs").finish_non_exhaustive()
    }
}

/// Builds the injector every terminated request is decided by (one for the host: the request
/// names its workspace).
pub type InjectorFactory = Arc<dyn Fn(&InjectorInputs) -> Arc<dyn Injector> + Send + Sync>;

/// What a sandbox needs from [`Injection::begin`].
pub(crate) struct Began {
    /// The CA's public certificate, for the guest's trust.
    pub(crate) certificate: CaCertificate,
    /// The workspace's Git settings as they were when its CA was made.
    pub(crate) git: WorkspaceGit,
}

pub(crate) struct Injection {
    terminations: Arc<Terminations>,
    injector: Arc<dyn Injector>,
    store: Arc<Store>,
    running: Mutex<BTreeMap<WorkspaceName, Arc<WorkspaceCa>>>,
}

impl Injection {
    pub(crate) fn new(
        terminations: Arc<Terminations>,
        injector: Arc<dyn Injector>,
        store: Arc<Store>,
    ) -> Self {
        Self {
            terminations,
            injector,
            store,
            running: Mutex::new(BTreeMap::new()),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, BTreeMap<WorkspaceName, Arc<WorkspaceCa>>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The workspace's Git settings, from the database.
    pub(crate) fn git(&self, workspace: &WorkspaceName) -> Result<WorkspaceGit, String> {
        self.store
            .workspace_git(workspace)
            .map_err(|e| format!("cannot read {workspace}'s Git settings: {e}"))
    }

    /// Makes `workspace`'s CA for this start and registers what it decrypts. A CA from an earlier
    /// start is replaced.
    pub(crate) fn begin(&self, workspace: &WorkspaceName) -> Result<Began, String> {
        let git = self.git(workspace)?;
        // The common name shows in the guest's trust store and in a tool's error message.
        let name: String = format!("puddle CA for {workspace}")
            .chars()
            .take(64)
            .collect();
        let ca = Arc::new(
            CaBuilder::new(&name)
                .build()
                .map_err(|e| format!("cannot make {workspace}'s certificate authority: {e}"))?,
        );
        let certificate = ca.certificate().clone();
        self.terminations.insert(
            workspace.clone(),
            Termination::new(decrypt_set(&git), Arc::clone(&ca), self.injector.clone()),
        );
        self.running().insert(workspace.clone(), ca);
        Ok(Began { certificate, git })
    }

    /// Recomputes what the running `workspace` decrypts from `git`; false when it has no CA (it is
    /// not running, so the next start reads the settings itself).
    pub(crate) fn refresh(&self, workspace: &WorkspaceName, git: &WorkspaceGit) -> bool {
        let Some(ca) = self.running().get(workspace).cloned() else {
            return false;
        };
        self.terminations.insert(
            workspace.clone(),
            Termination::new(decrypt_set(git), ca, self.injector.clone()),
        );
        true
    }

    /// Drops `workspace`'s CA and what it decrypts. Connections already open keep what they have;
    /// the key is gone with the last of them.
    pub(crate) fn end(&self, workspace: &WorkspaceName) {
        self.terminations.remove(workspace);
        self.running().remove(workspace);
    }

    /// What `workspace` decrypts and the CA that certifies it, while it runs.
    pub(crate) fn termination(&self, workspace: &WorkspaceName) -> Option<Arc<Termination>> {
        self.terminations.termination(workspace)
    }

    /// The workspaces that have a CA now.
    pub(crate) fn running_workspaces(&self) -> Vec<WorkspaceName> {
        self.running().keys().cloned().collect()
    }
}

/// Sends [`Event::CredentialSignInNeeded`] for each read of a source that needs the user to sign
/// in, until the returned task is aborted. The sign-in itself starts only on the user's click.
pub(crate) fn forward_sign_in_needed<F: Fetch + 'static>(
    secrets: &Arc<SecretCache<F>>,
    sink: Arc<dyn EventSink>,
) -> JoinHandle<()> {
    let mut notices = secrets.subscribe();
    tokio::spawn(async move {
        loop {
            match notices.recv().await {
                Ok(notice) => sink.emit(Event::CredentialSignInNeeded {
                    host: notice.source.scope().host.to_string(),
                    source: notice.source.describe(),
                }),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use std::time::Duration;

    use puddle_proxy::NoInjection;
    use puddle_secrets::{AccountName, Fetched, HostName, SourceError, SourceSpec};
    use puddle_store::{
        Author, Clock, Coverage, CredentialBinding, IdentityDraft, Limits, ManualClock, Owner,
    };
    use puddle_types::Host;

    use super::*;

    fn store() -> Arc<Store> {
        let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(1_000));
        Arc::new(Store::open_in_memory(clock, Limits::default()).unwrap())
    }

    fn workspace(name: &str) -> WorkspaceName {
        WorkspaceName::new(name).unwrap()
    }

    fn injection(store: &Arc<Store>) -> (Injection, Arc<Terminations>) {
        let terminations = Arc::new(Terminations::new());
        let injection = Injection::new(
            Arc::clone(&terminations),
            Arc::new(NoInjection),
            Arc::clone(store),
        );
        (injection, terminations)
    }

    fn attach(store: &Store, ws: &WorkspaceName, label: &str, host: &str) {
        let host = HostName::new(host).unwrap();
        let credential = CredentialBinding::new(
            &host,
            SourceSpec::Gh {
                host: host.clone(),
                account: AccountName::new("me").unwrap(),
            },
            Coverage::new(BTreeSet::<Owner>::new(), true).unwrap(),
        )
        .unwrap();
        let identity = store
            .create_identity(IdentityDraft {
                label: label.to_owned(),
                author: Author::new(label, &format!("{label}@example.org")).unwrap(),
                credentials: vec![credential],
            })
            .unwrap();
        store.attach_identity(ws, identity.id, None).unwrap();
    }

    fn decrypts(terminations: &Terminations, ws: &WorkspaceName, host: &str) -> bool {
        terminations
            .termination(ws)
            .is_some_and(|t| t.set().contains(&Host::parse_normalised(host).unwrap()))
    }

    #[test]
    fn a_sandbox_gets_its_own_ca_and_decrypts_what_its_identities_name() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let (a, b) = (workspace("alpha"), workspace("beta"));
        attach(&store, &a, "ada", "github.com");

        let began_a = injection.begin(&a).unwrap();
        let began_b = injection.begin(&b).unwrap();
        assert_ne!(began_a.certificate, began_b.certificate);
        assert!(decrypts(&terminations, &a, "github.com"));
        assert!(!decrypts(&terminations, &a, "gitlab.com"));
        // beta has no identity: a CA (the guest trusts it from boot) and nothing decrypted.
        assert!(!decrypts(&terminations, &b, "github.com"));
        assert_eq!(injection.running_workspaces(), [a.clone(), b]);
        assert_eq!(began_a.git.identities.len(), 1);
    }

    #[test]
    fn refresh_applies_a_new_host_to_the_running_workspace_with_the_same_ca() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        injection.begin(&ws).unwrap();
        let ca_before = terminations
            .termination(&ws)
            .unwrap()
            .ca()
            .certificate()
            .clone();
        assert!(!decrypts(&terminations, &ws, "gitlab.com"));

        attach(&store, &ws, "ada", "gitlab.com");
        assert!(injection.refresh(&ws, &injection.git(&ws).unwrap()));
        assert!(decrypts(&terminations, &ws, "gitlab.com"));
        // The CA the guest was given at boot is the one that still signs.
        let ca_after = terminations
            .termination(&ws)
            .unwrap()
            .ca()
            .certificate()
            .clone();
        assert_eq!(ca_before, ca_after);
    }

    #[test]
    fn a_stopped_sandbox_has_no_ca_and_decrypts_nothing() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        attach(&store, &ws, "ada", "github.com");
        injection.begin(&ws).unwrap();
        injection.end(&ws);
        assert!(terminations.termination(&ws).is_none());
        assert_eq!(injection.running_workspaces(), []);
        // A change to a workspace that is not running touches nothing.
        assert!(!injection.refresh(&ws, &injection.git(&ws).unwrap()));
        assert!(terminations.termination(&ws).is_none());
        injection.end(&ws);
    }

    #[test]
    fn a_new_start_replaces_the_ca_of_the_earlier_one() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        let first = injection.begin(&ws).unwrap().certificate;
        let second = injection.begin(&ws).unwrap().certificate;
        assert_ne!(first, second);
        assert_eq!(
            terminations.termination(&ws).unwrap().ca().certificate(),
            &second
        );
    }

    #[test]
    fn a_long_workspace_name_still_gives_a_valid_ca_name() {
        let store = store();
        let (injection, _) = injection(&store);
        let ws = workspace(&"a".repeat(63));
        assert!(injection.begin(&ws).is_ok());
    }

    /// A source that always needs the user to sign in.
    struct NotSignedIn(Mutex<usize>);

    impl Fetch for NotSignedIn {
        fn fetch(
            &self,
            _: &SourceSpec,
        ) -> impl Future<Output = Result<Fetched, SourceError>> + Send {
            *self.0.lock().unwrap() += 1;
            std::future::ready(Err(SourceError::NotSignedIn))
        }
    }

    #[derive(Default)]
    struct Events(Mutex<Vec<Event>>);

    impl EventSink for Events {
        fn emit(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[tokio::test]
    async fn a_source_that_needs_a_sign_in_becomes_one_notice_naming_it() {
        let secrets = Arc::new(SecretCache::new(NotSignedIn(Mutex::new(0))));
        let events = Arc::new(Events::default());
        let task = forward_sign_in_needed(&secrets, events.clone());
        let host = HostName::new("github.com").unwrap();
        let spec = SourceSpec::Gh {
            host,
            account: AccountName::new("me").unwrap(),
        };
        assert!(secrets.get(&spec).await.is_err());
        for _ in 0..200 {
            if !events.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *events.0.lock().unwrap(),
            [Event::CredentialSignInNeeded {
                host: "github.com".into(),
                source: "gh account me on github.com".into(),
            }]
        );
        task.abort();
    }
}
