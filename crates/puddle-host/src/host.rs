// SPDX-License-Identifier: GPL-3.0-or-later
//! The host: one start-up sequence and one shutdown sequence for the whole process.
//!
//! Starting has two phases because one step has to run before the process has any other thread:
//!
//! 1. [`prepare`] (synchronous): bind the image-pull proxy, pin the process environment, check
//!    the bundled runtime, read the corporate roots.
//! 2. [`Host::start`] (asynchronous): open the store, build the egress chain, open the runtime,
//!    reconcile with what an earlier run left, start the proxies and background tasks, build the
//!    workspace service and serve the API last, so nothing can call a half-built host.
//!
//! Every step is recorded as a [`Step`], in order, so tests (and a log reader) can see the
//! sequence that ran.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, HostNetworkHealth, Launcher, RunningApi, Services,
    SettingsRepo, forward_network_changes,
};
use puddle_certs::CorporateRoots;
use puddle_compute::{Runtime, SandboxInfo};
use puddle_lifecycle::{Inventory, Lifecycle, ShutdownReport, adopt_workspaces, reconcile};
use puddle_netpolicy::{LocalAccess, NetPolicy, PuddleEndpoints};
use puddle_proxy::{Proxy, ProxyUrl, PullProxy, PullRoute, Upstream};
use puddle_settings::{GlobalSettings, WorkspaceSettings, resolve};
use puddle_store::{DEFAULT_SWEEP_PERIOD, Limits, Store, Sweeper, SystemClock};
use puddle_types::{EventSink, WorkspaceName, WorkspaceStatus};
use puddle_upstream::{AuthList, BasicAuth, Chain, Discovery, Watching, system_auth};
use puddle_workspace::Workspaces;
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
use url::Url;

use crate::boot::BootKit;
use crate::files::{FileSettings, WorkspaceBook};
use crate::workspaces::{NoLauncher, Parts, known_ids};
use crate::{HostConfig, HostError, HostWorkspaces, Platform};

/// One step of starting or stopping the host, in the order they ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Step {
    /// The image-pull proxy is bound (not serving yet).
    PullProxyBound,
    /// The process environment is pinned to puddle's runtime.
    EnvironmentPinned,
    /// The bundled runtime is present and of the exact version.
    RuntimeChecked,
    /// The corporate root certificates are read.
    RootsRead,
    /// The database is open and the event hub is wired to it.
    StoreOpened,
    /// The way out through the company network is built: discovery, sign-in, the chain.
    UpstreamBuilt,
    /// The files and the egress proxy sandboxes are built from are ready.
    GuestFilesReady,
    /// The sandbox runtime is open (its image pulls go through the pull proxy).
    RuntimeOpened,
    /// What an earlier run left behind is cleaned up.
    Reconciled,
    /// The workspaces' holders are rebuilt from what exists.
    WorkspacesAdopted,
    /// The image-pull proxy serves.
    PullProxyServing,
    /// The sweeper and the network-change watcher run.
    BackgroundStarted,
    /// The workspace service is built over the runtime.
    WorkspacesReady,
    /// The API serves.
    ApiServing,
    /// New workspace operations are refused.
    WorkspacesClosed,
    /// Running workspace operations have finished (or were ended after the grace period).
    OperationsFinished,
    /// Every sandbox is trimmed and stopped.
    WorkspacesStopped,
    /// The SSH endpoints and egress routes are closed.
    RoutesClosed,
    /// The API stopped serving.
    ApiStopped,
    /// The sweeper, the watcher and the pull proxy are stopped.
    BackgroundStopped,
}

/// The steps [`prepare`] runs, in order.
pub const PREPARE_STEPS: [Step; 4] = [
    Step::PullProxyBound,
    Step::EnvironmentPinned,
    Step::RuntimeChecked,
    Step::RootsRead,
];

/// The steps of a start with the default options, in order, [`prepare`]'s included.
pub const START_STEPS: [Step; 14] = [
    Step::PullProxyBound,
    Step::EnvironmentPinned,
    Step::RuntimeChecked,
    Step::RootsRead,
    Step::StoreOpened,
    Step::UpstreamBuilt,
    Step::GuestFilesReady,
    Step::RuntimeOpened,
    Step::Reconciled,
    Step::WorkspacesAdopted,
    Step::PullProxyServing,
    Step::BackgroundStarted,
    Step::WorkspacesReady,
    Step::ApiServing,
];

/// The steps of a shutdown, in order.
pub const SHUTDOWN_STEPS: [Step; 6] = [
    Step::WorkspacesClosed,
    Step::OperationsFinished,
    Step::WorkspacesStopped,
    Step::RoutesClosed,
    Step::ApiStopped,
    Step::BackgroundStopped,
];

/// The result of [`prepare`]: everything the asynchronous start needs from the synchronous phase.
pub struct Prepared {
    config: HostConfig,
    pull: PullProxy,
    endpoints: PuddleEndpoints,
    roots: CorporateRoots,
    steps: Vec<Step>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("pull", &self.pull)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    /// The steps run so far.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
}

/// The synchronous phase of starting. Call it from `main` before building the async runtime or
/// starting any thread (the desktop shell: before the UI toolkit starts its own).
///
/// The order is the dependency order. The pull proxy is bound first because the runtime's image
/// pulls need its address; the environment is pinned before the runtime is looked at; the
/// corporate roots are read last and handed to the runtime when it opens, because msb fixes them
/// then.
///
/// # Errors
///
/// [`HostError`] from the step that failed; nothing is left running.
pub fn prepare(config: HostConfig, platform: &dyn Platform) -> Result<Prepared, HostError> {
    let mut steps = Vec::new();
    let endpoints = PuddleEndpoints::new();
    let pull = PullProxy::bind(&endpoints).map_err(HostError::PullProxy)?;
    steps.push(Step::PullProxyBound);
    platform.pin_environment(&config.layout)?;
    steps.push(Step::EnvironmentPinned);
    platform.check_runtime(&config.layout, &config.expected_runtime)?;
    steps.push(Step::RuntimeChecked);
    let roots = platform.corporate_roots()?;
    steps.push(Step::RootsRead);
    tracing::info!(
        roots = roots.certificates().len(),
        "corporate root certificates read"
    );
    Ok(Prepared {
        config,
        pull,
        endpoints,
        roots,
        steps,
    })
}

/// What a [`RuntimeFactory`] opens the runtime with.
#[derive(Debug)]
#[non_exhaustive]
pub struct RuntimeInputs<'a> {
    /// The runtime folder and msb home.
    pub layout: &'a puddle_runtime::RuntimeLayout,
    /// The root every mount source must be inside.
    pub guest_share: PathBuf,
    /// The pull proxy, which the runtime's image pulls go through.
    pub pull_proxy: ProxyUrl,
    /// The corporate roots (PEM) the registry client must trust besides the system's.
    pub registry_roots: Vec<String>,
    /// msb's log level for sandbox runtimes.
    pub log_level: Option<String>,
}

/// Opens the sandbox runtime. The real one opens msb; tests open a fake.
pub trait RuntimeFactory: Send + Sync {
    /// The runtime type.
    type Runtime: Runtime + Clone;

    /// Opens the runtime.
    ///
    /// # Errors
    ///
    /// [`HostError::Compute`] when it cannot be opened.
    fn open(
        &self,
        inputs: RuntimeInputs<'_>,
    ) -> impl Future<Output = Result<Self::Runtime, HostError>> + Send;
}

/// Opens msb in puddle's private home.
#[derive(Debug, Default, Clone, Copy)]
pub struct MsbFactory;

impl RuntimeFactory for MsbFactory {
    type Runtime = puddle_compute_msb::MsbRuntime;

    async fn open(&self, inputs: RuntimeInputs<'_>) -> Result<Self::Runtime, HostError> {
        let config = puddle_compute_msb::MsbConfig::new(
            inputs.layout.home(),
            inputs.layout.msb_path(),
            inputs.layout.libkrunfw_path(),
            inputs.guest_share,
        )
        .with_registry_proxy(inputs.pull_proxy.expose())
        .with_registry_roots(inputs.registry_roots)
        .with_runtime_log_level(inputs.log_level);
        Ok(puddle_compute_msb::MsbRuntime::open(config).await?)
    }
}

/// What a host takes besides its configuration.
#[derive(Clone)]
#[non_exhaustive]
pub struct HostOptions {
    /// Opens editors for the workspaces (the desktop shell supplies it).
    pub launcher: Arc<dyn Launcher>,
    /// The proxy discovery to use instead of the system's (tests).
    pub discovery: Option<Arc<Discovery>>,
}

impl Default for HostOptions {
    fn default() -> Self {
        Self {
            launcher: Arc::new(NoLauncher),
            discovery: None,
        }
    }
}

impl std::fmt::Debug for HostOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostOptions").finish_non_exhaustive()
    }
}

/// What a shutdown did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostShutdown {
    /// The trim and stop of every sandbox.
    pub sandboxes: ShutdownReport,
    /// How many workspace operations were still running after the grace period and were ended.
    pub operations_ended: usize,
    /// The steps that ran.
    pub steps: Vec<Step>,
}

struct Background {
    sweeper: Sweeper,
    pull: PullRoute,
    // Dropped (stopped) with the rest; `None` where the OS cannot watch.
    _watching: Option<Watching>,
    // Tells the API's event stream about each new network epoch; ended with the rest.
    _network_events: AbortOnDrop,
}

/// Aborts its task when dropped, so a forwarder never outlives the host.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    /// Announces each new network epoch of `discovery` on `events`.
    fn forwarding(discovery: &Discovery, events: &Arc<EventHub>) -> Self {
        Self(forward_network_changes(
            discovery,
            events.clone() as Arc<dyn EventSink>,
        ))
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The running host. Its API URL and token are what a window or the CLI connects with.
pub struct Host<R: Runtime + Clone> {
    info: puddle_api::ConnectionInfo,
    url: Url,
    events: Arc<EventHub>,
    store: Arc<Store>,
    endpoints: PuddleEndpoints,
    workspaces: HostWorkspaces<R>,
    lifecycle: Arc<Lifecycle<R>>,
    grace: std::time::Duration,
    api: AsyncMutex<Option<RunningApi>>,
    background: AsyncMutex<Option<Background>>,
    steps: Mutex<Vec<Step>>,
    reconcile: puddle_lifecycle::ReconcileReport,
    stopped: OnceCell<HostShutdown>,
}

impl<R: Runtime + Clone> std::fmt::Debug for Host<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// The local-destination settings of `sandbox`, read from the settings at each connection so a
/// change applies to the next one. A document that cannot be read leaves the defaults (all
/// local destinations blocked): the guard fails closed.
fn local_access(settings: &dyn SettingsRepo, workspace: &WorkspaceName) -> LocalAccess {
    let global = settings
        .load_global()
        .ok()
        .flatten()
        .and_then(|doc| GlobalSettings::from_document(doc).ok())
        .map(|loaded| loaded.settings)
        .unwrap_or_default();
    let own = settings
        .load_workspace(workspace)
        .ok()
        .flatten()
        .and_then(|doc| WorkspaceSettings::from_document(doc).ok())
        .map(|loaded| loaded.settings);
    LocalAccess::from_effective(&resolve(&global, own.as_ref()))
}

impl<R: Runtime + Clone> Host<R> {
    /// Starts the host: the asynchronous phase, after [`prepare`].
    ///
    /// # Errors
    ///
    /// [`HostError`] from the step that failed. Whatever started is stopped again by drop, and
    /// no sandbox is left running: reconcile only runs after everything that can refuse to start
    /// has been built.
    pub async fn start<F>(
        prepared: Prepared,
        factory: &F,
        options: HostOptions,
    ) -> Result<Self, HostError>
    where
        F: RuntimeFactory<Runtime = R>,
    {
        let Prepared {
            config,
            pull,
            endpoints,
            roots,
            mut steps,
        } = prepared;
        let paths = config.paths.clone();

        // Store, settings and the event hub.
        let events = Arc::new(EventHub::default());
        let clock = Arc::new(SystemClock);
        let State {
            store,
            settings,
            book,
            stored,
        } = open_state(&paths, &events, &clock)?;
        steps.push(Step::StoreOpened);

        // The way out: the company network (discovery, sign-in as the user, then Basic) for the
        // sandbox proxy and the pull proxy alike.
        let egress = Egress::build(&config, &options, &settings, &endpoints, &store, &events);
        let (proxy, upstream, discovery) = (egress.proxy, egress.upstream, egress.discovery);
        let network_health = network_health_of(&egress.chain, &discovery, &clock, &roots);
        let pull_url = pull.proxy_url();
        // Image pulls are puddle's own traffic: audited with origin `puddle`, like sandbox traffic.
        let pull = pull
            .with_upstream(upstream)
            .with_connection_log(store.clone());
        steps.push(Step::UpstreamBuilt);

        let kit = BootKit::new(&paths.guest_share(), &config.guest, proxy, &roots)?;
        steps.push(Step::GuestFilesReady);

        // The runtime, with image pulls through the pull proxy and the corporate roots trusted.
        let runtime = factory
            .open(RuntimeInputs {
                layout: &config.layout,
                guest_share: paths.guest_share(),
                pull_proxy: pull_url,
                registry_roots: pem_of(&roots),
                log_level: config.runtime_log_level.clone(),
            })
            .await?;
        steps.push(Step::RuntimeOpened);

        // Clean up after an earlier run, then rebuild what only lives in memory.
        let (report, status) = reconcile_with(&runtime, &config, &stored).await?;
        steps.push(Step::Reconciled);
        let workspaces = Workspaces::new(config.workspaces.clone());
        let inventory = inventory_of(&runtime, &stored).await?;
        let adopted = adopt_workspaces(&workspaces, &inventory);
        tracing::info!(adopted = adopted.len(), "workspace holders rebuilt");
        steps.push(Step::WorkspacesAdopted);

        // From here the host serves. The pull proxy first: the first create pulls an image.
        let pull = pull.serve().map_err(HostError::PullProxy)?;
        // Image pulls leave through the company proxy chain, like the sandboxes' traffic.
        network_health.set_pull_proxy(true, true);
        steps.push(Step::PullProxyServing);
        let sweeper = Sweeper::spawn(store.clone(), DEFAULT_SWEEP_PERIOD);
        let watching = discovery.watch();
        let network_events = AbortOnDrop::forwarding(&discovery, &events);
        steps.push(Step::BackgroundStarted);

        let lifecycle = Arc::new(Lifecycle::new(runtime.clone(), config.shutdown.clone()));
        let service = HostWorkspaces::new(
            Parts {
                runtime,
                workspaces,
                lifecycle: lifecycle.clone(),
                kit,
                events: events.clone() as Arc<dyn EventSink>,
                clock: clock.clone(),
                settings: settings.clone(),
                launcher: options.launcher,
                book,
            },
            stored,
            &status,
        )?;
        steps.push(Step::WorkspacesReady);

        let services = Services::new(store.clone(), settings, events.clone(), clock)
            .with_workspaces(Arc::new(service.clone()))
            .with_network_health(network_health)
            .with_endpoints(endpoints.clone());
        let served = serve_api(&config, services).await?;
        let (info, url, api) = (served.info, served.url, served.api);
        steps.push(Step::ApiServing);
        tracing::info!(%url, "puddle is up");

        Ok(Self {
            info,
            url,
            events,
            store,
            endpoints,
            workspaces: service,
            lifecycle,
            grace: config.operations_grace,
            api: AsyncMutex::new(Some(api)),
            background: AsyncMutex::new(Some(Background {
                sweeper,
                pull,
                _watching: watching,
                _network_events: network_events,
            })),
            steps: Mutex::new(steps),
            reconcile: report,
            stopped: OnceCell::new(),
        })
    }

    /// The API's origin, `http://127.0.0.1:<port>/`.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The API token. Never log it.
    #[must_use]
    pub fn token(&self) -> &str {
        self.info.token.expose()
    }

    /// The connection (URL and token), for writing a connection file.
    #[must_use]
    pub fn connection(&self) -> &puddle_api::ConnectionInfo {
        &self.info
    }

    /// The event hub the API streams from; the tray and notifications subscribe through it.
    #[must_use]
    pub fn events(&self) -> &Arc<EventHub> {
        &self.events
    }

    /// The database.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Every address puddle itself listens on, which the destination guard keeps guests away
    /// from. Components that open their own listener (the forwarder) register it here.
    #[must_use]
    pub fn endpoints(&self) -> &PuddleEndpoints {
        &self.endpoints
    }

    /// The workspace service the API serves.
    #[must_use]
    pub fn workspaces(&self) -> &HostWorkspaces<R> {
        &self.workspaces
    }

    /// What reconcile found and did at start.
    #[must_use]
    pub fn reconcile_report(&self) -> &puddle_lifecycle::ReconcileReport {
        &self.reconcile
    }

    /// The steps run so far, in order.
    #[must_use]
    pub fn steps(&self) -> Vec<Step> {
        self.steps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn step(&self, step: Step) {
        self.steps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(step);
    }

    /// Stops the host: refuse new operations, let running ones finish (up to the grace period),
    /// trim and stop every sandbox, close the routes, stop the API, stop the background tasks.
    /// Calling it again returns the first result.
    pub async fn shutdown(&self) -> HostShutdown {
        self.stopped
            .get_or_init(|| async {
                self.workspaces.close();
                self.step(Step::WorkspacesClosed);
                let operations_ended = self.workspaces.finish_operations(self.grace).await;
                self.step(Step::OperationsFinished);
                let sandboxes = self.lifecycle.shutdown().await;
                self.step(Step::WorkspacesStopped);
                self.workspaces.release_all().await;
                self.step(Step::RoutesClosed);
                if let Some(api) = self.api.lock().await.take() {
                    api.shutdown().await;
                }
                self.step(Step::ApiStopped);
                if let Some(background) = self.background.lock().await.take() {
                    background.sweeper.shutdown().await;
                    background.pull.shutdown().await;
                }
                self.step(Step::BackgroundStopped);
                let steps = self
                    .steps()
                    .into_iter()
                    .skip_while(|s| !matches!(s, Step::WorkspacesClosed))
                    .collect();
                HostShutdown {
                    sandboxes,
                    operations_ended,
                    steps,
                }
            })
            .await
            .clone()
    }
}

/// What `open_state` opened.
struct State {
    store: Arc<Store>,
    settings: Arc<dyn SettingsRepo>,
    book: WorkspaceBook,
    stored: Vec<crate::files::Stored>,
}

/// Opens the database, the settings files and the workspace list.
fn open_state(
    paths: &crate::HostPaths,
    events: &Arc<EventHub>,
    clock: &Arc<SystemClock>,
) -> Result<State, HostError> {
    if let Some(dir) = paths.store().parent() {
        std::fs::create_dir_all(dir).map_err(|e| HostError::State {
            what: "the data folder",
            reason: format!("cannot create {}: {e}", dir.display()),
        })?;
    }
    let store = Arc::new(
        Store::open(&paths.store(), clock.clone(), Limits::default())?
            .with_events(events.clone() as Arc<dyn EventSink>),
    );
    let settings: Arc<dyn SettingsRepo> = Arc::new(FileSettings::new(paths.settings()));
    let book = WorkspaceBook::new(paths.workspace_book());
    let stored = book.load()?;
    Ok(State {
        store,
        settings,
        book,
        stored,
    })
}

/// The company roots as PEM, for the runtime's registry client.
fn pem_of(roots: &CorporateRoots) -> Vec<String> {
    roots
        .certificates()
        .iter()
        .map(puddle_certs::SyncedCert::pem)
        .collect()
}

/// What the network-health screen reads: what discovery, the sign-in log of `chain` and the
/// company roots know. The pull proxy reports itself once it serves.
fn network_health_of(
    chain: &Arc<Chain>,
    discovery: &Arc<Discovery>,
    clock: &Arc<SystemClock>,
    roots: &CorporateRoots,
) -> Arc<HostNetworkHealth> {
    let health = Arc::new(
        HostNetworkHealth::new(discovery.clone(), clock.clone()).with_chain(chain.clone()),
    );
    health.set_roots(Arc::new(roots.clone()));
    health
}

/// The way out through the company network, shared by the sandbox proxy and the pull proxy.
struct Egress {
    proxy: Arc<Proxy>,
    upstream: Upstream,
    chain: Arc<Chain>,
    discovery: Arc<Discovery>,
}

impl Egress {
    fn build(
        config: &HostConfig,
        options: &HostOptions,
        settings: &Arc<dyn SettingsRepo>,
        endpoints: &PuddleEndpoints,
        store: &Arc<Store>,
        events: &Arc<EventHub>,
    ) -> Self {
        let discovery = options.discovery.clone().unwrap_or_else(|| {
            Discovery::new(
                puddle_upstream::system_os(),
                config.upstream.discovery.clone(),
            )
        });
        let mut auth = AuthList::new().with(system_auth());
        if let Some(credentials) = config.upstream.basic.clone() {
            auth = auth.with(Arc::new(BasicAuth::new().with_default(credentials)));
        }
        let chain = Chain::new(discovery.clone(), Arc::new(auth));
        let upstream = Upstream::new(chain.clone());
        let access_settings = settings.clone();
        let guard = NetPolicy::new(Arc::new(move |workspace: &WorkspaceName| {
            local_access(access_settings.as_ref(), workspace)
        }))
        .with_endpoints(endpoints.clone());
        let proxy = Arc::new(
            Proxy::new(store.clone(), events.clone() as Arc<dyn EventSink>)
                .with_connection_log(store.clone())
                .with_address_check(Arc::new(guard))
                .with_upstream(upstream.clone()),
        );
        Self {
            proxy,
            upstream,
            chain,
            discovery,
        }
    }
}

/// The API, bound and serving. It registers its own address in the services' endpoint registry
/// (the guard's) and drops that entry when it stops.
struct ServedApi {
    info: puddle_api::ConnectionInfo,
    url: Url,
    api: RunningApi,
}

async fn serve_api(config: &HostConfig, services: Services) -> Result<ServedApi, HostError> {
    let mut api_config = ApiConfig::with_port(config.api.port);
    api_config
        .extra_origins
        .clone_from(&config.api.extra_origins);
    if let Some(ui) = &config.api.ui {
        api_config.ui = Some(ui.clone());
    }
    let server = ApiServer::bind(api_config, ApiToken::generate()?, services).await?;
    let info = server.connection_info();
    if let Some(file) = &config.api.connection_file {
        info.write(file)?;
    }
    let url = Url::parse(&info.url).map_err(|e| HostError::State {
        what: "the API address",
        reason: e.to_string(),
    })?;
    let api = server.spawn();
    Ok(ServedApi { info, url, api })
}

/// What reconcile works from: the workspaces puddle knows, the sandboxes they own and which of
/// those exist.
async fn inventory_of<R: Runtime>(
    runtime: &R,
    stored: &[crate::files::Stored],
) -> Result<Inventory, HostError> {
    let existing: BTreeSet<String> = runtime
        .list()
        .await?
        .into_iter()
        .map(|SandboxInfo { name, .. }| name)
        .collect();
    let workspaces = known_ids(stored);
    let mut inventory = Inventory::default();
    for stored in stored.iter().filter(|s| !s.creating) {
        let (Ok(id), Ok(name)) = (
            puddle_types::WorkspaceId::new(&stored.id),
            WorkspaceName::new(&stored.name),
        ) else {
            continue;
        };
        if existing.contains(name.as_str()) {
            inventory.attached.insert(id, name.sandbox_name());
        }
        inventory.sandboxes.insert(name.sandbox_name());
    }
    inventory.workspaces = workspaces;
    inventory.interrupted = stored
        .iter()
        .filter(|s| s.creating)
        .filter_map(|s| puddle_types::WorkspaceId::new(&s.id).ok())
        .collect();
    Ok(inventory)
}

/// Runs reconcile and returns its report with the state each known sandbox was left in.
async fn reconcile_with<R: Runtime>(
    runtime: &R,
    config: &HostConfig,
    stored: &[crate::files::Stored],
) -> Result<
    (
        puddle_lifecycle::ReconcileReport,
        BTreeMap<WorkspaceName, WorkspaceStatus>,
    ),
    HostError,
> {
    let inventory = inventory_of(runtime, stored).await?;
    let report = reconcile(runtime, &inventory, &config.shutdown)
        .await
        .map_err(|e| HostError::Reconcile(e.to_string()))?;
    if !report.unknown_volumes.is_empty() {
        // Kept, never removed: the list may be the thing that is missing or out of date.
        tracing::warn!(
            volumes = ?report.unknown_volumes,
            "workspace volumes that no workspace in the list claims were kept"
        );
    }
    if !report.removed.is_empty() {
        // Only the sandbox's own disk goes (its workspace volume is never touched), and a restart
        // rebuilds a sandbox from the volume anyway; say so rather than remove silently.
        tracing::warn!(
            sandboxes = ?report.removed,
            "sandbox records that no workspace in the list claims were removed (their root disks are discarded; workspace volumes are untouched)"
        );
    }
    for failure in &report.failures {
        tracing::warn!(item = %failure.item, action = failure.action, error = %failure.error, "reconcile did not finish this");
    }
    let status = report
        .crashed
        .iter()
        .filter_map(|name| Some((name.workspace_name()?, WorkspaceStatus::Crashed)))
        .collect();
    Ok((report, status))
}
