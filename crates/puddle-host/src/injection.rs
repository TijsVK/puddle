// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's side of credential injection: one CA for each running sandbox, the registry that
//! tells the proxy which hosts each workspace decrypts, the injector of each start, the cache of
//! secrets behind it, and the stand-ins of the workspace's environment secrets.
//!
//! A sandbox's CA is made when the sandbox starts and dropped when it stops: it lives in this
//! process's memory only, and its certificate goes into the guest's trust at boot. The CA has no
//! name constraint, so the hosts a workspace decrypts are only what its [`Termination`] says, and
//! that is recomputed whenever the workspace's identities or secrets change: a credential or a
//! secret for a host the workspace has not used yet applies to the next connection, with no
//! restart.
//!
//! The registry of a workspace's stand-ins is built from the store when it starts and kept for as
//! long as it runs; a change to its environment brings the registry and the decrypted hosts up to
//! date, while the guest's own environment is read at its next start.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use puddle_ca::{CaBuilder, CaCertificate, WorkspaceCa};
use puddle_inject::{CredentialSource, GitInjector, StoreSettings};
use puddle_proxy::{
    Injector, StandInOrigin, StandIns, Termination, TerminationSet, TerminationSource, Terminations,
};
use puddle_secrets::{Fetch, SecretCache, SecretStore, Sources};
use puddle_store::{Store, WorkspaceGit};
use puddle_types::{Event, EventSink, GuestEnv, WorkspaceName};
use tokio::task::JoinHandle;

use crate::environment::{Resolved, resolve};
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
    /// The variables the guest starts with: the workspace's own and the global ones, each secret
    /// as its stand-in.
    pub(crate) env: GuestEnv,
}

/// What a running sandbox holds in memory: its CA, the injector made for this start and the
/// registry of its stand-ins.
#[derive(Clone)]
struct Running {
    ca: Arc<WorkspaceCa>,
    injector: Arc<dyn Injector>,
    stand_ins: Arc<StandIns>,
}

/// What the workspace decrypts: its identities' credential hosts and the hosts of its secrets.
fn decrypted(git: &WorkspaceGit, stand_ins: &StandIns) -> TerminationSet {
    let mut set = decrypt_set(git);
    set.extend(&stand_ins.hosts());
    set
}

/// How long a workspace's secrets may take to read from the credential store. A locked keyring
/// waits for the user to unlock it; past this the start fails and says so, instead of hanging.
const VAULT_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) struct Injection {
    terminations: Arc<Terminations>,
    inputs: InjectorInputs,
    /// Without one, each workspace gets [`git_injector`].
    factory: Option<InjectorFactory>,
    /// Where the real values of environment secrets are kept.
    vault: Arc<dyn SecretStore>,
    running: Mutex<BTreeMap<WorkspaceName, Running>>,
    /// Held while a workspace's settings are read and what it decrypts is changed to match, so
    /// the last change to run is the last one to read: a slow reader never puts back an old set.
    syncing: Mutex<()>,
    /// One lock for each workspace, held while its environment is read (the credential store can
    /// take a while) and applied or registered, so a start and a change to the environment never
    /// cross: whichever comes second reads what the first left. Per workspace, so a credential
    /// store that is slow for one workspace's secrets holds up no other workspace.
    environment: Mutex<BTreeMap<WorkspaceName, Arc<tokio::sync::Mutex<()>>>>,
    vault_timeout: Duration,
}

impl Injection {
    pub(crate) fn new(
        terminations: Arc<Terminations>,
        inputs: InjectorInputs,
        factory: Option<InjectorFactory>,
        vault: Arc<dyn SecretStore>,
    ) -> Self {
        Self {
            terminations,
            inputs,
            factory,
            vault,
            running: Mutex::new(BTreeMap::new()),
            syncing: Mutex::new(()),
            environment: Mutex::new(BTreeMap::new()),
            vault_timeout: VAULT_TIMEOUT,
        }
    }

    /// The same with another limit on how long the credential store may take (tests).
    #[cfg(test)]
    fn with_vault_timeout(mut self, timeout: Duration) -> Self {
        self.vault_timeout = timeout;
        self
    }

    /// `workspace`'s environment lock.
    fn environment_lock(&self, workspace: &WorkspaceName) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .environment
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(locks.entry(workspace.clone()).or_default())
    }

    /// Reads `workspace`'s environment off the async threads, giving up when the credential store
    /// does not answer in time.
    async fn environment_of(&self, workspace: &WorkspaceName) -> Result<Resolved, String> {
        let (store, vault, name) = (
            Arc::clone(&self.inputs.store),
            Arc::clone(&self.vault),
            workspace.clone(),
        );
        let read = tokio::task::spawn_blocking(move || resolve(&store, vault.as_ref(), &name));
        match tokio::time::timeout(self.vault_timeout, read).await {
            Ok(done) => done.map_err(|e| format!("cannot read {workspace}'s environment: {e}"))?,
            Err(_) => Err(format!(
                "the operating system's credential store did not answer within {} seconds while \
                 reading {workspace}'s secrets; unlock it or check that it is running, then try again",
                self.vault_timeout.as_secs().max(1)
            )),
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

    /// Makes `workspace`'s CA for this start, reads its environment and registers what it
    /// decrypts. A CA from an earlier start is replaced.
    ///
    /// # Errors
    /// A message for the user: the settings or the environment cannot be read (a secret's value
    /// is missing from the credential store, say), or the CA cannot be made.
    pub(crate) async fn begin(&self, workspace: &WorkspaceName) -> Result<Began, String> {
        // Held until the workspace is registered: a change to its environment in the meantime
        // waits for that and then finds it running.
        let lock = self.environment_lock(workspace);
        let _environment = lock.lock().await;
        let resolved = self.environment_of(workspace).await?;
        self.register(workspace, resolved)
    }

    fn register(&self, workspace: &WorkspaceName, resolved: Resolved) -> Result<Began, String> {
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
        let Resolved { guest, entries } = resolved;
        let stand_ins = Arc::new(StandIns::new());
        stand_ins
            .replace_origin(StandInOrigin::Secret, entries)
            .map_err(|e| format!("the secrets of {workspace} cannot be registered: {e}"))?;
        // The registry and the list of running CAs change together, under the list's lock, so a
        // `resync` or an `end` never sees one without the other.
        let mut running = self.running();
        self.terminations.insert(
            workspace.clone(),
            Termination::new(
                decrypted(&git, &stand_ins),
                Arc::clone(&ca),
                Arc::clone(&injector),
            )
            .with_stand_ins(Arc::clone(&stand_ins)),
        );
        running.insert(
            workspace.clone(),
            Running {
                ca,
                injector,
                stand_ins,
            },
        );
        drop(running);
        Ok(Began {
            certificate,
            git,
            env: guest,
        })
    }

    /// Brings the running `workspace`'s secrets up to date with the store: a new secret's stand-in
    /// is registered and its hosts join what the workspace decrypts, a changed value or host list
    /// replaces the old, a removed secret's stand-in stops being swapped. All of it applies from
    /// the next request, with no restart. The guest's own environment is read at its next start.
    ///
    /// A workspace that does not run reads its environment at its next start. A failure leaves
    /// what the workspace had and is logged: the next change tries again.
    pub(crate) async fn environment_changed(&self, workspace: &WorkspaceName) {
        let lock = self.environment_lock(workspace);
        let _environment = lock.lock().await;
        if !self.running().contains_key(workspace) {
            return;
        }
        let applied = match self.environment_of(workspace).await {
            Ok(resolved) => self.apply_environment(workspace, resolved),
            Err(reason) => Err(reason),
        };
        if let Err(reason) = applied {
            tracing::warn!(workspace = %workspace, %reason, "the workspace's secrets are not updated");
        }
    }

    /// Makes the registry of the running `workspace` hold `resolved`'s entries, then makes what it
    /// decrypts follow the registry. Not an error when the workspace stopped meanwhile: its next
    /// start reads its secrets itself.
    fn apply_environment(
        &self,
        workspace: &WorkspaceName,
        resolved: Resolved,
    ) -> Result<(), String> {
        let Some(stand_ins) = self
            .running()
            .get(workspace)
            .map(|r| Arc::clone(&r.stand_ins))
        else {
            return Ok(());
        };
        stand_ins
            .replace_origin(StandInOrigin::Secret, resolved.entries)
            .map_err(|e| format!("the secrets of {workspace} cannot be registered: {e}"))?;
        self.resync(workspace).map(|_| ())
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
        let Some(Running {
            ca,
            injector,
            stand_ins,
        }) = running.get(workspace).cloned()
        else {
            return Ok(None);
        };
        self.terminations.insert(
            workspace.clone(),
            Termination::new(decrypted(&git, &stand_ins), ca, injector).with_stand_ins(stand_ins),
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

    /// Removes what a deleted `workspace` held: its own variables and stand-ins in the store and
    /// its own secrets' values in the credential store. Failures are logged: the workspace is gone
    /// either way, and a value that stays behind is unreachable (nothing names it any more).
    pub(crate) async fn forget(&self, workspace: &WorkspaceName) {
        let (store, vault, name) = (
            Arc::clone(&self.inputs.store),
            Arc::clone(&self.vault),
            workspace.clone(),
        );
        let outcome = tokio::task::spawn_blocking(move || {
            let deletion = store
                .delete_workspace(&name)
                .map_err(|e| format!("cannot remove {name}'s rules and environment: {e}"))?;
            for id in &deletion.secret_ids {
                if vault.delete(id).is_err() {
                    tracing::warn!(workspace = %name, secret = %id, "a deleted workspace's secret could not be removed from the credential store");
                }
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|removed| removed);
        if let Err(reason) = outcome {
            tracing::warn!(workspace = %workspace, %reason, "a deleted workspace's settings are not removed");
        }
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
    use puddle_secrets::{
        AccountName, Fetched, HostName, MemoryStore, Secret, SourceError, SourceSpec, StoredId,
    };
    use puddle_store::{
        Author, Clock, Coverage, CredentialBinding, EnvDraft, EnvName, EnvScope, IdentityDraft,
        Limits, ManualClock, Owner, SecretHost,
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
                Arc::new(MemoryStore::new()),
            ))),
            events: Arc::new(Events::default()),
        }
    }

    fn injection(store: &Arc<Store>) -> (Injection, Arc<Terminations>) {
        let (injection, terminations, _) = injection_with_vault(store);
        (injection, terminations)
    }

    fn injection_with_vault(
        store: &Arc<Store>,
    ) -> (Injection, Arc<Terminations>, Arc<MemoryStore>) {
        let terminations = Arc::new(Terminations::new());
        let vault = Arc::new(MemoryStore::new());
        let injection = Injection::new(
            Arc::clone(&terminations),
            inputs(store),
            None,
            vault.clone(),
        );
        (injection, terminations, vault)
    }

    const REAL: &str = "real-value-CANARY-4711";

    /// A secret for `hosts` in the workspace's own scope, its value in `vault`.
    fn add_secret(
        store: &Store,
        vault: &MemoryStore,
        ws: &WorkspaceName,
        var: &str,
        hosts: &[&str],
    ) {
        let id = StoredId::new(format!("env-{var}")).unwrap();
        vault.set(&id, &Secret::new(REAL.to_owned())).unwrap();
        let hosts = hosts.iter().map(|h| SecretHost::new(h).unwrap()).collect();
        store
            .set_env(
                &EnvScope::Workspace(ws.clone()),
                &EnvName::new(var).unwrap(),
                EnvDraft::secret(id, hosts).unwrap(),
            )
            .unwrap();
    }

    fn stand_ins(terminations: &Terminations, ws: &WorkspaceName) -> Vec<String> {
        terminations.termination(ws).unwrap().stand_ins().ids()
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

    #[tokio::test]
    async fn a_sandbox_gets_its_own_ca_and_decrypts_what_its_identities_name() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let (a, b) = (workspace("alpha"), workspace("beta"));
        attach(&store, &a, "ada", "github.com");

        let began_a = injection.begin(&a).await.unwrap();
        let began_b = injection.begin(&b).await.unwrap();
        assert_ne!(began_a.certificate, began_b.certificate);
        assert!(decrypts(&terminations, &a, "github.com"));
        assert!(!decrypts(&terminations, &a, "gitlab.com"));
        // beta has no identity: a CA (the guest trusts it from boot) and nothing decrypted.
        assert!(!decrypts(&terminations, &b, "github.com"));
        assert_eq!(injection.running_workspaces(), [a.clone(), b]);
        assert_eq!(began_a.git.identities.len(), 1);
    }

    #[tokio::test]
    async fn refresh_applies_a_new_host_to_the_running_workspace_with_the_same_ca() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        injection.begin(&ws).await.unwrap();
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

    #[tokio::test]
    async fn a_stopped_sandbox_has_no_ca_and_decrypts_nothing() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        attach(&store, &ws, "ada", "github.com");
        injection.begin(&ws).await.unwrap();
        injection.end(&ws);
        assert!(terminations.termination(&ws).is_none());
        assert_eq!(injection.running_workspaces(), []);
        // A change to a workspace that is not running touches nothing.
        assert!(injection.resync(&ws).unwrap().is_none());
        assert!(terminations.termination(&ws).is_none());
        injection.end(&ws);
    }

    #[tokio::test]
    async fn a_new_start_replaces_the_ca_of_the_earlier_one() {
        let store = store();
        let (injection, terminations) = injection(&store);
        let ws = workspace("alpha");
        let first = injection.begin(&ws).await.unwrap().certificate;
        let second = injection.begin(&ws).await.unwrap().certificate;
        assert_ne!(first, second);
        assert_eq!(
            terminations.termination(&ws).unwrap().ca().certificate(),
            &second
        );
    }

    #[tokio::test]
    async fn a_long_workspace_name_still_gives_a_valid_ca_name() {
        let store = store();
        let (injection, _) = injection(&store);
        let ws = workspace(&"a".repeat(63));
        assert!(injection.begin(&ws).await.is_ok());
    }

    #[tokio::test]
    async fn a_start_registers_the_stand_ins_of_its_secrets_and_decrypts_their_hosts() {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let ws = workspace("alpha");
        add_secret(
            &store,
            &vault,
            &ws,
            "NPM_TOKEN",
            &["registry.npmjs.org", "*.example.com"],
        );
        store
            .set_env(
                &EnvScope::Workspace(ws.clone()),
                &EnvName::new("EDITOR").unwrap(),
                EnvDraft::plain("vim").unwrap(),
            )
            .unwrap();

        let began = injection.begin(&ws).await.unwrap();
        assert_eq!(began.env.get("EDITOR"), Some("vim"));
        let stand_in = began.env.get("NPM_TOKEN").unwrap();
        assert!(stand_in.starts_with("puddle-secret-NPM_TOKEN-"));
        assert!(began.env.iter().all(|(_, v)| !v.contains("CANARY")));
        assert_eq!(stand_ins(&terminations, &ws), ["stand-in:secret:NPM_TOKEN"]);
        assert!(decrypts(&terminations, &ws, "registry.npmjs.org"));
        assert!(decrypts(&terminations, &ws, "api.example.com"));
        assert!(!decrypts(&terminations, &ws, "github.com"));
    }

    #[tokio::test]
    async fn a_secret_added_to_a_running_workspace_is_decrypted_from_the_next_connection_with_no_restart()
     {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let ws = workspace("alpha");
        let first = injection.begin(&ws).await.unwrap();
        let before = terminations.termination(&ws).unwrap();
        assert_eq!(stand_ins(&terminations, &ws), Vec::<String>::new());
        assert!(!decrypts(&terminations, &ws, "api.example.org"));

        add_secret(&store, &vault, &ws, "API_KEY", &["api.example.org"]);
        injection.environment_changed(&ws).await;

        assert!(decrypts(&terminations, &ws, "api.example.org"));
        assert_eq!(stand_ins(&terminations, &ws), ["stand-in:secret:API_KEY"]);
        let after = terminations.termination(&ws).unwrap();
        // The same CA (the guest's trust is unchanged), the same registry (open connections see
        // the new stand-in too), a new set for the next connection.
        assert_eq!(before.ca().certificate(), after.ca().certificate());
        assert!(Arc::ptr_eq(before.stand_ins(), after.stand_ins()));
        assert_eq!(first.certificate, *after.ca().certificate());
        // Nothing was started again: the start made one CA.
        assert_eq!(injection.running_workspaces(), std::slice::from_ref(&ws));

        // A change of the hosts moves the decrypted host; removing the secret drops it.
        add_secret(&store, &vault, &ws, "API_KEY", &["other.example.org"]);
        injection.environment_changed(&ws).await;
        assert!(decrypts(&terminations, &ws, "other.example.org"));
        assert!(!decrypts(&terminations, &ws, "api.example.org"));
        store
            .delete_env(
                &EnvScope::Workspace(ws.clone()),
                &EnvName::new("API_KEY").unwrap(),
            )
            .unwrap();
        injection.environment_changed(&ws).await;
        assert_eq!(stand_ins(&terminations, &ws), Vec::<String>::new());
        assert!(!decrypts(&terminations, &ws, "other.example.org"));
    }

    #[tokio::test]
    async fn a_global_secret_changes_what_every_running_workspace_decrypts_and_a_git_change_keeps_it()
     {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let (a, b) = (workspace("alpha"), workspace("beta"));
        injection.begin(&a).await.unwrap();
        injection.begin(&b).await.unwrap();
        let id = StoredId::new("env-G").unwrap();
        vault.set(&id, &Secret::new(REAL.to_owned())).unwrap();
        store
            .set_env(
                &EnvScope::Global,
                &EnvName::new("G").unwrap(),
                EnvDraft::secret(id, vec![SecretHost::new("g.example.org").unwrap()]).unwrap(),
            )
            .unwrap();
        for ws in [&a, &b] {
            injection.environment_changed(ws).await;
            assert!(decrypts(&terminations, ws, "g.example.org"), "{ws}");
        }
        // Another workspace's own stand-in differs: each holds its own.
        let held = |ws: &WorkspaceName| {
            store
                .env_for_start(ws, &mut |_| Err("already made".into()))
                .unwrap()
        };
        assert_ne!(held(&a), held(&b));

        // An identity attached later keeps the secret's host in the set.
        attach(&store, &a, "ada", "gitlab.com");
        injection.resync(&a).unwrap();
        assert!(decrypts(&terminations, &a, "gitlab.com"));
        assert!(decrypts(&terminations, &a, "g.example.org"));
        assert_eq!(stand_ins(&terminations, &a), ["stand-in:secret:G"]);
    }

    #[tokio::test]
    async fn a_workspace_that_does_not_run_is_left_alone_and_a_failed_read_keeps_what_it_had() {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let (stopped, running) = (workspace("stopped"), workspace("running"));
        add_secret(&store, &vault, &stopped, "T", &["x.example.org"]);
        vault.break_it();
        // Not running: nothing is read, nothing registered.
        injection.environment_changed(&stopped).await;
        assert!(terminations.termination(&stopped).is_none());

        vault.heal();
        injection.begin(&running).await.unwrap();
        add_secret(&store, &vault, &running, "T", &["x.example.org"]);
        injection.environment_changed(&running).await;
        assert!(decrypts(&terminations, &running, "x.example.org"));
        // The credential store fails while a second secret is added: the first stays as it was.
        add_secret(&store, &vault, &running, "U", &["y.example.org"]);
        vault.break_it();
        injection.environment_changed(&running).await;
        assert_eq!(stand_ins(&terminations, &running), ["stand-in:secret:T"]);
        assert!(!decrypts(&terminations, &running, "y.example.org"));
        vault.heal();
        injection.environment_changed(&running).await;
        assert_eq!(
            stand_ins(&terminations, &running),
            ["stand-in:secret:T", "stand-in:secret:U"]
        );
    }

    #[tokio::test]
    async fn a_start_whose_secret_cannot_be_read_fails_with_the_reason_and_registers_nothing() {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let ws = workspace("alpha");
        add_secret(&store, &vault, &ws, "T", &["x.example.org"]);
        vault.break_it();
        let err = injection.begin(&ws).await.err().unwrap();
        assert!(
            err.contains('T') && err.contains("credential store"),
            "{err}"
        );
        assert!(terminations.termination(&ws).is_none());
        assert_eq!(injection.running_workspaces(), []);
    }

    #[tokio::test]
    async fn a_deleted_workspace_loses_its_variables_and_the_values_of_its_own_secrets() {
        let store = store();
        let (injection, _, vault) = injection_with_vault(&store);
        let (gone, other) = (workspace("gone"), workspace("other"));
        add_secret(&store, &vault, &gone, "MINE", &["x.example.org"]);
        add_secret(&store, &vault, &other, "THEIRS", &["x.example.org"]);
        let id = StoredId::new("env-GLOBAL").unwrap();
        vault.set(&id, &Secret::new(REAL.to_owned())).unwrap();
        store
            .set_env(
                &EnvScope::Global,
                &EnvName::new("GLOBAL").unwrap(),
                EnvDraft::secret(id, vec![SecretHost::new("g.example.org").unwrap()]).unwrap(),
            )
            .unwrap();

        injection.forget(&gone).await;
        assert_eq!(vault.ids(), ["env-GLOBAL", "env-THEIRS"]);
        assert_eq!(store.env_entries(&EnvScope::Workspace(gone)).unwrap(), []);
        assert_eq!(
            store
                .env_entries(&EnvScope::Workspace(other))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.env_entries(&EnvScope::Global).unwrap().len(), 1);

        // A credential store that fails leaves the value but never stops the deletion.
        vault.break_it();
        injection.forget(&workspace("other")).await;
        assert_eq!(
            store
                .env_entries(&EnvScope::Workspace(workspace("other")))
                .unwrap(),
            []
        );
    }

    /// A credential store that does not answer for a while (a keyring waiting for the user to
    /// unlock it), and says when it was asked.
    struct SlowStore {
        inner: MemoryStore,
        delay: Duration,
        asked: Mutex<Vec<String>>,
    }

    impl SecretStore for SlowStore {
        fn get(&self, id: &StoredId) -> Result<Option<Secret>, puddle_secrets::StoreError> {
            self.asked.lock().unwrap().push(id.to_string());
            std::thread::sleep(self.delay);
            self.inner.get(id)
        }

        fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), puddle_secrets::StoreError> {
            self.inner.set(id, secret)
        }

        fn delete(&self, id: &StoredId) -> Result<(), puddle_secrets::StoreError> {
            self.inner.delete(id)
        }
    }

    #[tokio::test]
    async fn a_credential_store_that_does_not_answer_fails_that_workspace_in_time_and_holds_up_no_other()
     {
        let store = store();
        let vault = Arc::new(SlowStore {
            inner: MemoryStore::new(),
            delay: Duration::from_millis(1500),
            asked: Mutex::new(Vec::new()),
        });
        let injection = Injection::new(
            Arc::new(Terminations::new()),
            inputs(&store),
            None,
            vault.clone(),
        )
        .with_vault_timeout(Duration::from_millis(200));
        let (stuck, free) = (workspace("stuck"), workspace("free"));
        add_secret(&store, &vault.inner, &stuck, "T", &["x.example.org"]);

        let waiting = injection.begin(&stuck);
        let others = async {
            // A workspace without secrets never asks the store, so it is not held up.
            let began = injection.begin(&free).await;
            assert!(began.is_ok());
        };
        let (stuck_result, ()) = tokio::join!(waiting, others);
        let err = stuck_result.err().unwrap();
        assert!(err.contains("did not answer within"), "{err}");
        assert!(err.contains("stuck") && err.contains("unlock"), "{err}");
        assert_eq!(vault.asked.lock().unwrap().len(), 1);
        assert_eq!(injection.running_workspaces(), [free]);
    }

    /// Two stand-ins of which one contains the other: the proxy cannot tell which to swap, so it
    /// refuses to hold both. Puddle makes none like that; a hand-edited database can.
    fn overlapping_stand_ins(store: &Store, ws: &WorkspaceName) {
        store
            .env_for_start(ws, &mut |name| {
                let first = "puddle-secret-A-0123456789abcdef0123456789abcdef";
                Ok(if name.as_str() == "A" {
                    first.to_owned()
                } else {
                    format!("{first}-{name}")
                })
            })
            .unwrap();
    }

    #[tokio::test]
    async fn stand_ins_that_overlap_stop_a_start_and_leave_a_running_workspace_as_it_was() {
        let store = store();
        let (injection, terminations, vault) = injection_with_vault(&store);
        let ws = workspace("alpha");
        add_secret(&store, &vault, &ws, "A", &["a.example.org"]);
        add_secret(&store, &vault, &ws, "B", &["b.example.org"]);
        overlapping_stand_ins(&store, &ws);
        let err = injection.begin(&ws).await.err().unwrap();
        assert!(err.contains("cannot be registered"), "{err}");
        assert!(terminations.termination(&ws).is_none());

        // The same while it runs: it keeps the secret it had.
        let other = workspace("beta");
        add_secret(&store, &vault, &other, "A", &["a.example.org"]);
        overlapping_stand_ins(&store, &other);
        injection.begin(&other).await.unwrap();
        add_secret(&store, &vault, &other, "B", &["b.example.org"]);
        overlapping_stand_ins(&store, &other);
        injection.environment_changed(&other).await;
        assert_eq!(stand_ins(&terminations, &other), ["stand-in:secret:A"]);
        assert!(!decrypts(&terminations, &other, "b.example.org"));
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
        injection.begin(&ws).await.unwrap();
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

    #[tokio::test]
    async fn each_start_gets_an_injector_made_for_its_workspace_and_it_stays_across_changes() {
        let store = store();
        let made = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&made);
        let factory: InjectorFactory = Arc::new(move |_, workspace| {
            record.lock().unwrap().push(workspace.clone());
            Arc::new(NoInjection)
        });
        let terminations = Arc::new(Terminations::new());
        let injection = Injection::new(
            Arc::clone(&terminations),
            inputs(&store),
            Some(factory),
            Arc::new(MemoryStore::new()),
        );
        let (a, b) = (workspace("alpha"), workspace("beta"));
        injection.begin(&a).await.unwrap();
        injection.begin(&b).await.unwrap();
        assert_eq!(*made.lock().unwrap(), [a.clone(), b]);
        // A change to a running workspace keeps its injector (it may hold state of its own).
        let before = format!("{:?}", terminations.termination(&a).unwrap());
        attach(&store, &a, "ada", "github.com");
        assert!(injection.resync(&a).unwrap().is_some());
        assert_eq!(made.lock().unwrap().len(), 2);
        assert!(format!("{:?}", terminations.termination(&a).unwrap()).contains("NoInjection"));
        assert!(before.contains("NoInjection"));
        // A restart makes a new one.
        injection.begin(&a).await.unwrap();
        assert_eq!(made.lock().unwrap().len(), 3);
    }
}
