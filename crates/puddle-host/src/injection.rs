// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's side of credential injection: one CA for each running sandbox, the registry that
//! tells the proxy which hosts each workspace decrypts, the injector of each start and the cache of
//! secrets behind it.
//!
//! A sandbox's CA is made when the sandbox starts and dropped when it stops: it lives in this
//! process's memory only, and its certificate goes into the guest's trust at boot. The CA has no
//! name constraint, so the hosts a workspace decrypts are only what its [`Termination`] says, and
//! that is recomputed from the workspace's identities whenever they change: a credential for a
//! host the workspace has not used yet applies to the next connection, with no restart.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use puddle_ca::{CaBuilder, CaCertificate, WorkspaceCa};
use puddle_inject::{CredentialSource, GitInjector, StoreSettings};
use puddle_proxy::{Injector, Termination, TerminationSource, Terminations};
use puddle_secrets::{Fetch, SecretCache, Sources};
use puddle_store::{Store, WorkspaceGit};
use puddle_types::{Event, EventSink, WorkspaceName};
use tokio::task::JoinHandle;

use crate::git_hosts::decrypt_set;

/// What an injector is built from.
#[derive(Clone)]
#[non_exhaustive]
pub struct InjectorInputs {
    /// The database: identities, and each workspace's Git settings.
    pub store: Arc<Store>,
    /// The host's one cache of secrets read from the user's own sign-ins (`gh`, Git, the operating
    /// system's store). Every workspace shares it, so one source is read once at a time.
    pub secrets: Arc<SecretCache<Sources>>,
    /// Where a notice for the user goes (a sign-in that is needed, a push that was refused).
    pub events: Arc<dyn EventSink>,
}

impl std::fmt::Debug for InjectorInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectorInputs").finish_non_exhaustive()
    }
}

/// Builds the injector that decides, for each request on a host a workspace decrypts, which
/// credential is added. Called once for each start of a workspace's sandbox, with that workspace.
pub type InjectorFactory =
    Arc<dyn Fn(&InjectorInputs, &WorkspaceName) -> Arc<dyn Injector> + Send + Sync>;

/// The injector a workspace gets when the host was given no factory: puddle's own, for Git hosts.
/// It reads the workspace's identities and lists from the store for each request, and the secret
/// of an identity from the cache at the moment it is needed.
fn git_injector(inputs: &InjectorInputs, workspace: &WorkspaceName) -> Arc<dyn Injector> {
    let settings = StoreSettings::new(Arc::clone(&inputs.store), workspace.clone());
    let credentials: Arc<dyn CredentialSource> = inputs.secrets.clone();
    Arc::new(GitInjector::new(
        workspace.clone(),
        Arc::new(settings),
        credentials,
        Arc::clone(&inputs.events),
    ))
}

/// What a sandbox needs from [`Injection::begin`].
pub(crate) struct Began {
    /// The CA's public certificate, for the guest's trust.
    pub(crate) certificate: CaCertificate,
    /// The workspace's Git settings as they were when its CA was made.
    pub(crate) git: WorkspaceGit,
}

/// What a running sandbox holds in memory: its CA and the injector made for this start.
#[derive(Clone)]
struct Running {
    ca: Arc<WorkspaceCa>,
    injector: Arc<dyn Injector>,
}

pub(crate) struct Injection {
    terminations: Arc<Terminations>,
    inputs: InjectorInputs,
    /// Without one, each workspace gets [`git_injector`].
    factory: Option<InjectorFactory>,
    running: Mutex<BTreeMap<WorkspaceName, Running>>,
    /// Held while a workspace's settings are read and what it decrypts is changed to match, so
    /// the last change to run is the last one to read: a slow reader never puts back an old set.
    syncing: Mutex<()>,
}

impl Injection {
    pub(crate) fn new(
        terminations: Arc<Terminations>,
        inputs: InjectorInputs,
        factory: Option<InjectorFactory>,
    ) -> Self {
        Self {
            terminations,
            inputs,
            factory,
            running: Mutex::new(BTreeMap::new()),
            syncing: Mutex::new(()),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, BTreeMap<WorkspaceName, Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The workspace's Git settings, from the database.
    pub(crate) fn git(&self, workspace: &WorkspaceName) -> Result<WorkspaceGit, String> {
        self.inputs
            .store
            .workspace_git(workspace)
            .map_err(|e| format!("cannot read {workspace}'s Git settings: {e}"))
    }

    /// Makes `workspace`'s CA for this start and registers what it decrypts. A CA from an earlier
    /// start is replaced.
    pub(crate) fn begin(&self, workspace: &WorkspaceName) -> Result<Began, String> {
        let _one_at_a_time = self.syncing.lock().unwrap_or_else(PoisonError::into_inner);
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
        let injector = self.factory.as_ref().map_or_else(
            || git_injector(&self.inputs, workspace),
            |make| make(&self.inputs, workspace),
        );
        // The registry and the list of running CAs change together, under the list's lock, so a
        // `resync` or an `end` never sees one without the other.
        let mut running = self.running();
        self.terminations.insert(
            workspace.clone(),
            Termination::new(decrypt_set(&git), Arc::clone(&ca), Arc::clone(&injector)),
        );
        running.insert(workspace.clone(), Running { ca, injector });
        drop(running);
        Ok(Began { certificate, git })
    }

    /// Reads the running `workspace`'s settings again and changes what it decrypts to match, with
    /// the CA it has. `Ok(None)` when it has no CA (it is not running, so the next start reads the
    /// settings itself); the settings otherwise.
    pub(crate) fn resync(&self, workspace: &WorkspaceName) -> Result<Option<WorkspaceGit>, String> {
        let _one_at_a_time = self.syncing.lock().unwrap_or_else(PoisonError::into_inner);
        let git = self.git(workspace)?;
        // Held until the registry is changed: an `end` in between would otherwise leave a CA
        // registered for a sandbox that is gone.
        let running = self.running();
        let Some(Running { ca, injector }) = running.get(workspace).cloned() else {
            return Ok(None);
        };
        self.terminations.insert(
            workspace.clone(),
            Termination::new(decrypt_set(&git), ca, injector),
        );
        drop(running);
        Ok(Some(git))
    }

    /// Drops `workspace`'s CA and what it decrypts. Connections already open keep what they have;
    /// the key is gone with the last of them.
    pub(crate) fn end(&self, workspace: &WorkspaceName) {
        let mut running = self.running();
        self.terminations.remove(workspace);
        running.remove(workspace);
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

    use puddle_proxy::{InjectContext, InjectDecision, NoInjection, RequestView};
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

    fn inputs(store: &Arc<Store>) -> InjectorInputs {
        InjectorInputs {
            store: Arc::clone(store),
            secrets: Arc::new(SecretCache::new(Sources::new(
                puddle_secrets::ToolPaths::resolve(),
                Arc::new(puddle_secrets::MemoryStore::new()),
            ))),
            events: Arc::new(Events::default()),
        }
    }

    fn injection(store: &Arc<Store>) -> (Injection, Arc<Terminations>) {
        let terminations = Arc::new(Terminations::new());
        let injection = Injection::new(Arc::clone(&terminations), inputs(store), None);
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
        assert!(injection.resync(&ws).unwrap().is_some());
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
        assert!(injection.resync(&ws).unwrap().is_none());
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
        // The forwarder ends with the cache it listens to.
        drop(secrets);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn notices_over_the_buffer_lose_the_oldest_and_the_rest_still_arrive() {
        let secrets = Arc::new(SecretCache::new(NotSignedIn(Mutex::new(0))));
        let events = Arc::new(Events::default());
        // The forwarder cannot run until this test awaits something that is not ready, so the
        // notices pile up past the cache's buffer (16) and it must skip what was lost.
        let task = forward_sign_in_needed(&secrets, events.clone());
        for i in 0..40 {
            let host = HostName::new(format!("host{i}.example")).unwrap();
            let spec = SourceSpec::Gh {
                host,
                account: AccountName::new("me").unwrap(),
            };
            assert!(secrets.get(&spec).await.is_err());
        }
        for _ in 0..200 {
            if events.0.lock().unwrap().len() >= 16 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let seen = events.0.lock().unwrap().len();
        assert!((1..40).contains(&seen), "{seen} notices");
        task.abort();
    }

    #[test]
    fn the_inputs_print_without_what_they_hold() {
        let text = format!("{:?}", inputs(&store()));
        assert_eq!(text, "InjectorInputs { .. }");
    }

    #[tokio::test]
    async fn a_git_request_whose_source_needs_a_sign_in_is_a_502_and_the_user_gets_one_notice() {
        // The shape of the default injector, over a cache whose source is never signed in: the
        // request is refused with the way out, and the one notice is the cache's, forwarded.
        let store = store();
        let ws = workspace("alpha");
        attach(&store, &ws, "ada", "github.com");
        let secrets = Arc::new(SecretCache::new(NotSignedIn(Mutex::new(0))));
        let events = Arc::new(Events::default());
        let task = forward_sign_in_needed(&secrets, events.clone());
        let credentials: Arc<dyn CredentialSource> = secrets.clone();
        let injector = GitInjector::new(
            ws.clone(),
            Arc::new(StoreSettings::new(store, ws.clone())),
            credentials,
            events.clone(),
        );
        let host = Host::parse_normalised("github.com").unwrap();
        let context = InjectContext {
            workspace: &ws,
            host: &host,
        };
        let lines = ["host: github.com".to_owned()];
        let view = RequestView::new(
            "GET",
            "/acme/web.git/info/refs?service=git-upload-pack",
            &lines,
        );
        let decision = injector.decide(&context, &view).await;
        assert!(matches!(&decision, InjectDecision::Refuse(refusal)
                if refusal.code() == "credential_unavailable"
                    && refusal.message().contains("sign in to it in puddle")));
        for _ in 0..200 {
            if !events.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *events.0.lock().unwrap(),
            [Event::CredentialSignInNeeded {
                host: "github.com".into(),
                source: "gh account me on github.com".into(),
            }]
        );
        drop(secrets);
        drop(injector);
        task.abort();
    }

    #[tokio::test]
    async fn without_a_factory_a_workspace_gets_puddles_git_injector_which_reads_the_store() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        injection.begin(&ws).unwrap();
        let termination = terminations.termination(&ws).unwrap();
        assert!(format!("{termination:?}").contains("GitInjector"));
        // A push to a repository that is not on the workspace's list is refused, so the injector
        // read the workspace's settings from the store.
        let host = Host::parse_normalised("github.com").unwrap();
        let context = InjectContext {
            workspace: &ws,
            host: &host,
        };
        let lines = ["host: github.com".to_owned()];
        let view = RequestView::new(
            "GET",
            "/acme/web.git/info/refs?service=git-receive-pack",
            &lines,
        );
        let injector = Arc::clone(&injection.running().get(&ws).unwrap().injector);
        let decision = injector.decide(&context, &view).await;
        assert!(
            matches!(&decision, InjectDecision::Refuse(refusal) if refusal.code() == "push_denied")
        );
    }

    #[test]
    fn each_start_gets_an_injector_made_for_its_workspace_and_it_stays_across_changes() {
        let store = store();
        let made = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&made);
        let factory: InjectorFactory = Arc::new(move |_, workspace| {
            record.lock().unwrap().push(workspace.clone());
            Arc::new(NoInjection)
        });
        let terminations = Arc::new(Terminations::new());
        let injection = Injection::new(Arc::clone(&terminations), inputs(&store), Some(factory));
        let (a, b) = (workspace("alpha"), workspace("beta"));
        injection.begin(&a).unwrap();
        injection.begin(&b).unwrap();
        assert_eq!(*made.lock().unwrap(), [a.clone(), b]);
        // A change to a running workspace keeps its injector (it may hold state of its own).
        let before = format!("{:?}", terminations.termination(&a).unwrap());
        attach(&store, &a, "ada", "github.com");
        assert!(injection.resync(&a).unwrap().is_some());
        assert_eq!(made.lock().unwrap().len(), 2);
        assert!(format!("{:?}", terminations.termination(&a).unwrap()).contains("NoInjection"));
        assert!(before.contains("NoInjection"));
        // A restart makes a new one.
        injection.begin(&a).unwrap();
        assert_eq!(made.lock().unwrap().len(), 3);
    }
}
