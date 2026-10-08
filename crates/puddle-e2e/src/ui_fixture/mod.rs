// SPDX-License-Identifier: GPL-3.0-or-later
//! The UI fixture backend: the real `puddle-api` router on an in-memory store, a manual
//! clock and in-memory settings, seeded from a [`Scenario`] and driven by scripted [`Step`]s.
//!
//! A UI test therefore exercises the real Host/Origin/token guard, error bodies, SSE framing and
//! wire types; only what sits behind the API is fake. When a later task puts a new service behind
//! the API, its fake is built in `Fixture::build_state`, and a field in [`Scenario`] seeds it
//! (workspaces are the first: [`WorkspaceSeed`]); new events need nothing here (an
//! [`Event`] in JSON
//! is a step).
//!
//! The fixture is for tests and development only. It listens on `127.0.0.1`, keeps nothing on
//! disk but the connection files, and is never a dependency of a product crate.
//!
//! Besides the API, a small control server (see [`control`]) lets a test or a developer emit
//! events, move the clock, run a script, restart the API (open event streams end) or reset the
//! data.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, ConnectionInfo, EventHub, FakeLauncher, FakeNetworkHealth,
    FakeWorkspaces, Launcher, Listing, MemorySettings, NetworkHealthService, Operation,
    RepoFindings, RepoUrl, RunningApi, Services, SettingsRepo, Unsaved, WorkspaceRecord,
};
use puddle_store::{Actor, Clock, Limits, ManualClock, NewRule, Pattern, Scope, Store};
use puddle_types::{
    BlockReason, ConnectionDecision, ConnectionEvent, ConnectionReason, EgressRequest, Event,
    EventSink, Host, ImageRef, MemoryMib, SuffixAllows, WorkspaceId, WorkspaceName,
    WorkspaceStatus,
};
use tokio::sync::Mutex;

pub mod cli;
pub mod control;
pub mod scenario;

pub use scenario::{
    ConnectionSeed, DecisionSeed, EffectSeed, RepoSeed, RequestSeed, RuleSeed, Scenario,
    SettingsSeed, StatusSeed, Step, UnsavedSeed, WorkspaceOperationSeed, WorkspaceSeed,
};

/// The built-in scenarios (`ui/e2e/fixtures/*.json`), by name.
const BUILT_IN: [(&str, &str); 6] = [
    (
        "default",
        include_str!("../../../../ui/e2e/fixtures/default.json"),
    ),
    (
        "empty",
        include_str!("../../../../ui/e2e/fixtures/empty.json"),
    ),
    (
        "lived-in",
        include_str!("../../../../ui/e2e/fixtures/lived-in.json"),
    ),
    (
        "corporate-network",
        include_str!("../../../../ui/e2e/fixtures/corporate-network.json"),
    ),
    (
        "network-trouble",
        include_str!("../../../../ui/e2e/fixtures/network-trouble.json"),
    ),
    (
        "volume-missing",
        include_str!("../../../../ui/e2e/fixtures/volume-missing.json"),
    ),
];

/// Names of the built-in scenarios.
#[must_use]
pub fn built_in_names() -> Vec<&'static str> {
    BUILT_IN.iter().map(|(name, _)| *name).collect()
}

/// Reads a scenario: a built-in name, or the path of a JSON file.
///
/// # Errors
///
/// A readable message if the file can't be read or isn't a valid scenario.
pub fn load_scenario(name_or_path: &str) -> Result<Scenario, String> {
    let (label, text) = match BUILT_IN.iter().find(|(name, _)| *name == name_or_path) {
        Some((name, text)) => ((*name).to_owned(), (*text).to_owned()),
        None => (
            name_or_path.to_owned(),
            std::fs::read_to_string(name_or_path).map_err(|err| {
                format!(
                    "scenario {name_or_path:?} is neither a built-in ({}) nor a readable file: {err}",
                    built_in_names().join(", ")
                )
            })?,
        ),
    };
    let mut scenario: Scenario = serde_json::from_str(&text)
        .map_err(|err| format!("scenario {label:?} is not valid: {err}"))?;
    if scenario.name.is_empty() {
        scenario.name = label;
    }
    Ok(scenario)
}

/// How to start a fixture.
#[derive(Debug, Clone)]
pub struct FixtureOptions {
    /// Port of the API on `127.0.0.1`; 0 lets the OS pick.
    pub port: u16,
    /// Where to write the connection file (`{version, url, token}`, what `npm run dev` and the
    /// Playwright setup read). The control server's address goes to `<file>.control`.
    pub connection_file: Option<PathBuf>,
    /// What to start with.
    pub scenario: Scenario,
}

/// What the API runs on. Replaced as a whole by [`Fixture::reset`].
struct State {
    store: Arc<Store>,
    clock: Arc<ManualClock>,
    events: Arc<EventHub>,
    settings: Arc<MemorySettings>,
    workspaces: FakeWorkspaces,
    network: Arc<FakeNetworkHealth>,
    api: Option<RunningApi>,
}

/// A running fixture: the API, its fakes and the scenario that seeded them.
pub struct Fixture {
    state: Mutex<State>,
    scenario: Mutex<Scenario>,
    token: ApiToken,
    /// The requested port, then the bound one, so a restart comes back on the same port.
    port: AtomicU16,
    connection_file: Option<PathBuf>,
}

impl Fixture {
    /// Seeds the fakes from the scenario, binds the API and writes the connection file.
    ///
    /// # Errors
    ///
    /// A readable message if the port can't be bound, the scenario can't be applied or the
    /// connection file can't be written.
    pub async fn start(options: FixtureOptions) -> Result<Arc<Self>, String> {
        let token = ApiToken::generate().map_err(|err| err.to_string())?;
        let state = Self::build_state(&options.scenario)?;
        let fixture = Arc::new(Self {
            state: Mutex::new(state),
            scenario: Mutex::new(options.scenario),
            token,
            port: AtomicU16::new(options.port),
            connection_file: options.connection_file,
        });
        fixture.bind().await?;
        Ok(fixture)
    }

    /// The fakes behind the API, seeded. The store emits its events into the same hub the API's
    /// streams read, so a scenario's decisions and rule changes reach the page as they would live.
    fn build_state(scenario: &Scenario) -> Result<State, String> {
        let start = scenario.start_ms();
        let clock = Arc::new(ManualClock::new(start));
        let events = Arc::new(EventHub::default());
        let store = Arc::new(
            Store::open_in_memory(clock.clone() as Arc<dyn Clock>, Limits::default())
                .map_err(|err| err.to_string())?
                .with_events(events.clone()),
        );
        let settings = Arc::new(MemorySettings::default());
        let workspaces = FakeWorkspaces::with_options(
            events.clone(),
            clock.clone() as Arc<dyn Clock>,
            Arc::new(FakeLauncher::new()) as Arc<dyn Launcher>,
            Duration::from_millis(scenario.workspace_step_delay_ms),
        );
        let network = Arc::new(FakeNetworkHealth::new(clock.clone() as Arc<dyn Clock>));
        let state = State {
            store,
            clock,
            events,
            settings,
            workspaces,
            network,
            api: None,
        };
        state.seed(scenario)?;
        Ok(state)
    }

    /// Binds the API on the fixed port (retrying briefly: a restart rebinds the port just
    /// released) and writes the connection file.
    async fn bind(&self) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let mut last = String::new();
        for _ in 0..100 {
            let services = Services::new(
                state.store.clone(),
                state.settings.clone() as Arc<dyn SettingsRepo>,
                state.events.clone(),
                state.clock.clone() as Arc<dyn Clock>,
            )
            .with_workspaces(Arc::new(state.workspaces.clone()))
            .with_network_health(state.network.clone() as Arc<dyn NetworkHealthService>);
            match ApiServer::bind(
                ApiConfig::with_port(self.port.load(Ordering::SeqCst)),
                self.token.clone(),
                services,
            )
            .await
            {
                Ok(server) => {
                    self.port
                        .store(server.local_addr().port(), Ordering::SeqCst);
                    if let Some(file) = &self.connection_file {
                        server
                            .connection_info()
                            .write(file)
                            .map_err(|err| err.to_string())?;
                    }
                    state.api = Some(server.spawn());
                    return Ok(());
                }
                Err(err) => {
                    last = err.to_string();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Err(last)
    }

    /// The API's address.
    pub async fn addr(&self) -> Option<SocketAddr> {
        self.state
            .lock()
            .await
            .api
            .as_ref()
            .map(RunningApi::local_addr)
    }

    /// What a client needs to reach the API.
    pub async fn connection_info(&self) -> Option<ConnectionInfo> {
        let addr = self.addr().await?;
        Some(ConnectionInfo {
            url: format!("http://{addr}"),
            token: self.token.clone(),
        })
    }

    /// Where events go: the hub the API's SSE streams read from.
    pub async fn event_sink(&self) -> Arc<dyn EventSink> {
        self.state.lock().await.events.clone()
    }

    /// The bearer token (the control server takes the same one).
    #[must_use]
    pub fn token(&self) -> &ApiToken {
        &self.token
    }

    /// The fixture clock, epoch ms.
    pub async fn now_ms(&self) -> u64 {
        self.state.lock().await.clock.now_ms()
    }

    /// The name of the running scenario.
    pub async fn scenario_name(&self) -> String {
        self.scenario.lock().await.name.clone()
    }

    /// The names of the scripts the running scenario has.
    pub async fn script_names(&self) -> Vec<String> {
        self.scenario.lock().await.scripts.keys().cloned().collect()
    }

    /// How many requests wait for a decision.
    pub async fn pending_count(&self) -> usize {
        let state = self.state.lock().await;
        state
            .store
            .inbox()
            .map(|groups| groups.iter().map(|g| g.rows.len()).sum())
            .unwrap_or_default()
    }

    /// Does one step.
    ///
    /// # Errors
    ///
    /// A readable message if the step names something invalid (a host, a pattern, a time in the
    /// past for an expiry).
    pub async fn apply(&self, step: &Step) -> Result<(), String> {
        if let Step::Wait { ms } = step {
            tokio::time::sleep(Duration::from_millis(*ms)).await;
            return Ok(());
        }
        self.state.lock().await.apply(step)
    }

    /// Runs the steps of a script in order.
    ///
    /// # Errors
    ///
    /// `Ok(false)` if the scenario has no such script; an error if a step fails (the earlier
    /// steps stay done).
    pub async fn run_script(&self, name: &str) -> Result<bool, String> {
        let steps = self.scenario.lock().await.scripts.get(name).cloned();
        let Some(steps) = steps else {
            return Ok(false);
        };
        for step in &steps {
            self.apply(step).await?;
        }
        Ok(true)
    }

    /// Drops every open connection (event streams end, so clients reconnect and refetch) and
    /// serves again on the same port with the same data.
    ///
    /// # Errors
    ///
    /// A readable message if the port can't be bound again.
    pub async fn restart(&self) -> Result<(), String> {
        let api = self.state.lock().await.api.take();
        if let Some(api) = api {
            api.shutdown().await;
        }
        self.bind().await
    }

    /// Starts over from a scenario (the running one when `None`): new store, clock and settings,
    /// the API restarted on the same port with the same token.
    ///
    /// # Errors
    ///
    /// A readable message if the scenario can't be applied or the port can't be bound again.
    pub async fn reset(&self, scenario: Option<Scenario>) -> Result<(), String> {
        let scenario = match scenario {
            Some(new) => new,
            None => self.scenario.lock().await.clone(),
        };
        let fresh = Self::build_state(&scenario)?;
        let old = std::mem::replace(&mut *self.state.lock().await, fresh).api;
        if let Some(api) = old {
            api.shutdown().await;
        }
        *self.scenario.lock().await = scenario;
        self.bind().await
    }

    /// Stops the API.
    pub async fn shutdown(&self) {
        let api = self.state.lock().await.api.take();
        if let Some(api) = api {
            api.shutdown().await;
        }
    }
}

/// Reads control files dropped into `dir` (one JSON object or an array per file; each is taken
/// once and deleted). An object without `do` is read as a `request` (it has `host`) or a `bulk`
/// (it has `count`): the format the earlier `serve_ui` example took.
pub fn watch_drop_dir(fixture: Arc<Fixture>, dir: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = tokio::fs::create_dir_all(&dir).await;
        loop {
            drain_drop_dir(&fixture, &dir).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

#[expect(
    clippy::print_stderr,
    reason = "a dev tool: a bad control file is reported on stderr, there is nobody else to tell"
)]
async fn drain_drop_dir(fixture: &Fixture, dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        // Writers rename a finished file into place; a file that doesn't read or parse yet is
        // left for the next round.
        let Ok(text) = tokio::fs::read_to_string(&path).await else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let _ = tokio::fs::remove_file(&path).await;
        let items = match value {
            serde_json::Value::Array(items) => items,
            item => vec![item],
        };
        for item in items {
            match step_from_drop(item) {
                Ok(step) => {
                    if let Err(err) = fixture.apply(&step).await {
                        eprintln!("fixture: control file {}: {err}", path.display());
                    }
                }
                Err(err) => eprintln!("fixture: control file {}: {err}", path.display()),
            }
        }
    }
}

/// An object from a control file as a [`Step`].
///
/// # Errors
///
/// A readable message if it is not a step.
pub fn step_from_drop(mut item: serde_json::Value) -> Result<Step, String> {
    if let Some(object) = item.as_object_mut()
        && !object.contains_key("do")
    {
        let kind = if object.contains_key("count") {
            "bulk"
        } else {
            "request"
        };
        object.insert("do".to_owned(), kind.into());
    }
    serde_json::from_value(item).map_err(|err| err.to_string())
}

impl State {
    fn seed(&self, scenario: &Scenario) -> Result<(), String> {
        let start = scenario.start_ms();
        for rule in &scenario.rules {
            self.add_rule(rule, start)?;
        }
        for request in &scenario.requests {
            self.request(request, start)?;
        }
        for connection in &scenario.connections {
            self.connection(connection, start)?;
        }
        for workspace in &scenario.workspaces {
            self.workspace(workspace, start)?;
        }
        if let Some(global) = &scenario.settings.global {
            self.settings
                .save_global(global.clone())
                .map_err(|err| err.to_string())?;
        }
        for (name, document) in &scenario.settings.workspaces {
            self.settings
                .save_workspace(&workspace(name)?, document.clone())
                .map_err(|err| err.to_string())?;
        }
        if let Some(report) = &scenario.network_health {
            self.network.set(report.clone());
        }
        self.clock.set(start);
        Ok(())
    }

    fn apply(&self, step: &Step) -> Result<(), String> {
        let now = self.clock.now_ms();
        match step {
            Step::Emit { event } => self.events.emit(event.clone()),
            Step::Advance { ms } => {
                self.clock.advance(*ms);
                self.store.sweep().map_err(|err| err.to_string())?;
            }
            // Handled by the caller: it must not hold the state while it sleeps.
            Step::Wait { .. } => {}
            Step::Request(request) => self.request(request, now)?,
            Step::Bulk {
                workspace,
                count,
                domain,
            } => {
                let domain = domain.as_deref().unwrap_or("bulk.example.org");
                for i in 0..*count {
                    self.request(
                        &RequestSeed {
                            workspace: workspace.clone(),
                            host: format!("n{i}.{domain}"),
                            port: 443,
                            repeat: 1,
                            ago_ms: 0,
                        },
                        now,
                    )?;
                }
            }
            Step::Spread { count } => {
                for i in 0..*count {
                    self.request(
                        &RequestSeed {
                            workspace: format!("bulk-{}", i % 10),
                            host: format!("h{i}.d{}.example.org", i % 50),
                            port: 443,
                            repeat: 1,
                            ago_ms: 0,
                        },
                        now,
                    )?;
                }
            }
            Step::History { count } => {
                const WEEK_MS: u64 = 7 * 24 * 3_600_000;
                let count = *count;
                for i in 0..count {
                    let decision = match i % 4 {
                        0 => DecisionSeed::Allow,
                        1 => DecisionSeed::Deny,
                        2 => DecisionSeed::Pending,
                        _ => DecisionSeed::Blocked,
                    };
                    self.connection(
                        &ConnectionSeed {
                            workspace: format!("bulk-{}", i % 10),
                            host: format!("h{}.d{}.example.org", i % 200, i % 50),
                            port: 443,
                            decision,
                            reason: None,
                            bytes_up: i % 5000,
                            bytes_down: (i % 700) * 1024,
                            ago_ms: (count - 1 - i) * WEEK_MS / count,
                        },
                        now,
                    )?;
                }
            }
            Step::NetworkHealth(report) => {
                let epoch = report.proxy.epoch;
                self.network.set((**report).clone());
                self.events.emit(Event::NetworkChanged { epoch });
            }
            Step::Rule(rule) => self.add_rule(rule, now)?,
            Step::Connection(connection) => self.connection(connection, now)?,
            Step::HoldWorkspaces => self.workspaces.hold(),
            Step::ReleaseWorkspaces => self.workspaces.release(),
            Step::FailWorkspace { operation, reason } => self.workspaces.fail_next(
                match operation {
                    WorkspaceOperationSeed::Create => Operation::Creating,
                    WorkspaceOperationSeed::Start => Operation::Starting,
                    WorkspaceOperationSeed::Stop => Operation::Stopping,
                    WorkspaceOperationSeed::Reclaim => Operation::Reclaiming,
                    WorkspaceOperationSeed::Delete => Operation::Deleting,
                },
                reason.clone(),
            ),
        }
        Ok(())
    }

    fn workspace(&self, seed: &WorkspaceSeed, now: u64) -> Result<(), String> {
        let name = workspace(&seed.name)?;
        let id = WorkspaceId::new(&seed.name)
            .map_err(|err| format!("workspace name {:?}: {err}", seed.name))?;
        let repo_url = RepoUrl::parse(&seed.repo_url)
            .map_err(|err| format!("workspace {:?}: {err}", seed.name))?;
        let mut record = WorkspaceRecord::new(id, name, repo_url.as_str());
        if let Some(image) = &seed.image {
            ImageRef::new(image)
                .map_err(|err| format!("workspace {:?}: {err}", seed.name))?
                .as_str()
                .clone_into(&mut record.image);
        }
        if let Some(mib) = seed.memory_mib {
            record.memory =
                MemoryMib::new(mib).map_err(|err| format!("workspace {:?}: {err}", seed.name))?;
        }
        record.status = match seed.status {
            StatusSeed::Created => WorkspaceStatus::Created,
            StatusSeed::Running => WorkspaceStatus::Running,
            StatusSeed::Stopped => WorkspaceStatus::Stopped,
            StatusSeed::Crashed => WorkspaceStatus::Crashed,
            StatusSeed::VolumeMissing => WorkspaceStatus::VolumeMissing,
        };
        record.created_at = now.saturating_sub(seed.ago_ms);
        record.disk_used_mib = seed.disk_used_mib;
        let list = |items: &[String]| Listing {
            items: items.to_vec(),
            more: 0,
        };
        self.workspaces.seed(
            record,
            Unsaved {
                repos: seed
                    .unsaved
                    .repos
                    .iter()
                    .map(|r| RepoFindings {
                        dir: r.dir.clone(),
                        uncommitted: list(&r.uncommitted),
                        unpushed: list(&r.unpushed),
                        stashes: list(&r.stashes),
                    })
                    .collect(),
                other: list(&seed.unsaved.other),
                errors: seed.unsaved.errors.clone(),
            },
        );
        Ok(())
    }

    /// Runs `work` with the clock `ago_ms` before `now`, then puts the clock back.
    fn at<T>(&self, now: u64, ago_ms: u64, work: impl FnOnce() -> T) -> T {
        self.clock.set(now.saturating_sub(ago_ms));
        let out = work();
        self.clock.set(now);
        out
    }

    fn add_rule(&self, seed: &RuleSeed, now: u64) -> Result<(), String> {
        let created = now.saturating_sub(seed.ago_ms);
        let new = NewRule {
            scope: match &seed.workspace {
                Some(name) => Scope::Workspace(workspace(name)?),
                None => Scope::Global,
            },
            pattern: Pattern::parse(&seed.pattern).map_err(|err| err.to_string())?,
            effect: match seed.effect {
                EffectSeed::Allow => puddle_store::Effect::Allow,
                EffectSeed::Deny => puddle_store::Effect::Deny,
            },
            expires_at: seed.expires_in_ms.map(|ms| created + ms),
            created_by: Actor::Ui,
        };
        self.at(now, seed.ago_ms, || self.store.add_rule(&new))
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn request(&self, seed: &RequestSeed, now: u64) -> Result<(), String> {
        let request = EgressRequest::new(workspace(&seed.workspace)?, host(&seed.host)?, seed.port);
        self.at(now, seed.ago_ms, || {
            for _ in 0..seed.repeat {
                let decision = self
                    .store
                    .decide(&request, SuffixAllows::Count)
                    .map_err(|err| err.to_string())?;
                self.store
                    .record_connection(&ConnectionEvent::decided(&request, &decision))
                    .map_err(|err| err.to_string())?;
            }
            Ok(())
        })
    }

    fn connection(&self, seed: &ConnectionSeed, now: u64) -> Result<(), String> {
        let request = EgressRequest::new(workspace(&seed.workspace)?, host(&seed.host)?, seed.port);
        let (decision, default_reason) = match seed.decision {
            DecisionSeed::Allow => (ConnectionDecision::Allow, "rule"),
            DecisionSeed::Deny => (ConnectionDecision::Deny, "rule"),
            DecisionSeed::Pending => (ConnectionDecision::Pending, "no_rule"),
            DecisionSeed::Blocked => (ConnectionDecision::Blocked, "local_address"),
        };
        let reason = match seed.reason.as_deref().unwrap_or(default_reason) {
            "rule" => ConnectionReason::Rule,
            "no_rule" => ConnectionReason::NoRule,
            "puddle_endpoint" => ConnectionReason::Blocked(BlockReason::PuddleEndpoint),
            "ssh_unsupported" => ConnectionReason::Blocked(BlockReason::SshUnsupported),
            "local_address" => ConnectionReason::Blocked(BlockReason::LocalAddress),
            other => return Err(format!("unknown connection reason {other:?}")),
        };
        let mut event = ConnectionEvent::new(&request, decision, reason);
        event.bytes_up = seed.bytes_up;
        event.bytes_down = seed.bytes_down;
        self.at(now, seed.ago_ms, || self.store.record_connection(&event))
            .map_err(|err| err.to_string())
    }
}

fn workspace(name: &str) -> Result<WorkspaceName, String> {
    WorkspaceName::new(name).map_err(|err| format!("workspace name {name:?}: {err}"))
}

fn host(name: &str) -> Result<Host, String> {
    Host::parse_normalised(name).map_err(|err| format!("host {name:?}: {err}"))
}
