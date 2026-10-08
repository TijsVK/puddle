// SPDX-License-Identifier: GPL-3.0-or-later
//! The whole host on fakes: the sandbox runtime is `FakeRuntime` with a scripted guest, the
//! machine is a fake that records what it was asked, and everything else (store, proxies, the
//! workspace service, the API, the UI route, the event stream) is the real code.
#![expect(
    clippy::assert_is_empty,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "a failed step fails the test; emptiness reads best as a plain assert"
)]

mod support;

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puddle_api::{LaunchError, Launcher, UiAssets, UiFile, WorkspaceRecord};
use puddle_certs::{CorporateRoots, SOURCES, StoreSnapshot};
use puddle_compute::fake::{ExecContext, FakeRuntime};
use puddle_compute::{ExecOutput, ExecRequest, ImageConfig, Runtime};
use puddle_host::{
    GuestSettings, Host, HostConfig, HostError, HostOptions, HostPaths, PREPARE_STEPS, Platform,
    RuntimeFactory, RuntimeInputs, SHUTDOWN_STEPS, START_STEPS, Step, prepare,
};
use puddle_netpolicy::EndpointKind;
use puddle_runtime::{RuntimeLayout, RuntimeVersion};
use puddle_types::{Event, EventSink, ImageRef, SandboxName, WorkspaceId, WorkspaceName};
use puddle_upstream::{Discovery, FakeOs, Mode, ProxyConfig};
use puddle_workspace::{CLEAR_LOCKS_SH, DELETE_CHECK_SH};
use rustls::pki_types::pem::PemObject;
use serde_json::json;
use support::{Api, ended};

type Log = Arc<Mutex<Vec<String>>>;

/// A machine that records every call and can refuse one.
struct FakePlatform {
    log: Log,
    refuse: Option<&'static str>,
    roots: CorporateRoots,
}

impl FakePlatform {
    fn new(log: &Log) -> Self {
        Self {
            log: log.clone(),
            refuse: None,
            roots: CorporateRoots::default(),
        }
    }

    fn call(&self, what: &'static str) -> Result<(), HostError> {
        self.log.lock().unwrap().push(what.to_owned());
        if self.refuse == Some(what) {
            return Err(HostError::Roots(format!("{what} refused")));
        }
        Ok(())
    }
}

impl Platform for FakePlatform {
    fn pin_environment(&self, _: &RuntimeLayout) -> Result<(), HostError> {
        self.call("pin_environment")
    }

    fn check_runtime(&self, _: &RuntimeLayout, expected: &RuntimeVersion) -> Result<(), HostError> {
        assert_eq!(expected, &RuntimeVersion::built_for());
        self.call("check_runtime")
    }

    fn corporate_roots(&self) -> Result<CorporateRoots, HostError> {
        self.call("corporate_roots")?;
        Ok(self.roots.clone())
    }
}

/// The company roots of a machine that has one: a single self-signed root.
fn company_roots() -> CorporateRoots {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Corp Root CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_after = rcgen::date_time_ymd(2090, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let mut snapshot = StoreSnapshot::new();
    snapshot.add(SOURCES[0], cert.der().to_vec());
    CorporateRoots::select(&snapshot, std::time::SystemTime::now())
}

/// Opens the shared `FakeRuntime` and records what it was given.
struct FakeFactory {
    runtime: FakeRuntime,
    log: Log,
    pull_proxy: Mutex<Option<String>>,
    pull_url: Mutex<Option<String>>,
    roots: Mutex<Option<usize>>,
}

impl FakeFactory {
    fn new(runtime: &FakeRuntime, log: &Log) -> Self {
        Self {
            runtime: runtime.clone(),
            log: log.clone(),
            pull_proxy: Mutex::new(None),
            pull_url: Mutex::new(None),
            roots: Mutex::new(None),
        }
    }
}

impl RuntimeFactory for FakeFactory {
    type Runtime = FakeRuntime;

    fn open(
        &self,
        inputs: RuntimeInputs<'_>,
    ) -> impl Future<Output = Result<FakeRuntime, HostError>> + Send {
        self.log.lock().unwrap().push("open_runtime".to_owned());
        *self.pull_proxy.lock().unwrap() = Some(inputs.pull_proxy.addr().to_string());
        *self.pull_url.lock().unwrap() = Some(inputs.pull_proxy.expose().to_owned());
        *self.roots.lock().unwrap() = Some(inputs.registry_roots.len());
        assert!(inputs.guest_share.ends_with("guest-share"));
        std::future::ready(Ok(self.runtime.clone()))
    }
}

/// The scripted guest: answers every command puddle runs in a sandbox.
#[derive(Default)]
struct Guest {
    commands: Mutex<Vec<String>>,
    /// The boot plan (stdin) of every run of the boot hook, with the sandbox it ran in.
    plans: Mutex<Vec<(String, Vec<u8>)>>,
    dirty: AtomicBool,
    fail_clone: AtomicBool,
    fail_boot: AtomicBool,
    /// Runs once, inside the next run of the boot hook: a change made while the guest boots.
    during_boot: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// When set, the clone turns this path into a folder, so the next save of the workspace
    /// list fails (a stand-in for a full disk or a locked file).
    break_list_on_clone: Mutex<Option<PathBuf>>,
}

impl Guest {
    fn install(self: &Arc<Self>, runtime: &FakeRuntime) {
        let guest = self.clone();
        runtime.on_exec(move |ctx: &mut ExecContext<'_>, r: &ExecRequest| guest.answer(ctx, r));
    }

    fn answer(&self, ctx: &ExecContext<'_>, r: &ExecRequest) -> Option<ExecOutput> {
        let second = r.args.get(1).map(String::as_str);
        let kind = match (r.program.as_str(), r.args.first().map(String::as_str)) {
            ("/bin/sh", Some("/puddle/boot.sh")) => "boot",
            ("mkdir", _) => "layout",
            ("sh", _) if second == Some(CLEAR_LOCKS_SH) => "locks",
            ("sh", _) if second == Some(DELETE_CHECK_SH) => "check",
            ("sh", _) if second.is_some_and(|s| s.contains("fstrim")) => "shutdown-trim",
            ("fstrim", _) => "trim",
            ("git", _) => "clone",
            ("sync", _) => "sync",
            _ => return None,
        };
        self.commands
            .lock()
            .unwrap()
            .push(format!("{} {kind}", ctx.sandbox()));
        if kind == "boot" {
            self.plans
                .lock()
                .unwrap()
                .push((ctx.sandbox().to_string(), r.stdin.clone()));
        }
        Some(match kind {
            "boot" if self.fail_boot.load(Ordering::SeqCst) => {
                ExecOutput::new(5, "", "boot.sh: no disk")
            }
            "boot" if self.during_boot.lock().unwrap().is_some() => {
                let change = self.during_boot.lock().unwrap().take().unwrap();
                change();
                ExecOutput::new(0, "puddle-boot: ready\n", "")
            }
            "boot" => ExecOutput::new(0, "puddle-boot: ready\n", ""),
            "locks" => ExecOutput::new(0, "D\n", ""),
            "check" if self.dirty.load(Ordering::SeqCst) => {
                ExecOutput::new(0, "R\tapi\nU\t?? notes.txt\nD\n", "")
            }
            "check" => ExecOutput::new(0, "R\tapi\nD\n", ""),
            "trim" | "shutdown-trim" => {
                ExecOutput::new(0, "/workspaces/x: 4096 bytes trimmed\n", "")
            }
            "clone" => {
                if let Some(list) = self.break_list_on_clone.lock().unwrap().take() {
                    make_unwritable(&list);
                }
                if self.fail_clone.load(Ordering::SeqCst) {
                    ExecOutput::new(128, "", "fatal: repository not found")
                } else {
                    ExecOutput::new(0, "", "")
                }
            }
            _ => ExecOutput::new(0, "", ""),
        })
    }

    fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }

    /// The files the boot plan number `n` (from 0) wrote, by guest path.
    fn plan_files(&self, n: usize) -> std::collections::BTreeMap<String, Vec<u8>> {
        plan_files(&self.plans.lock().unwrap()[n].1)
    }

    fn boots(&self) -> usize {
        self.plans.lock().unwrap().len()
    }

    /// Waits until the hook has run `n` times in all.
    async fn boots_reach(&self, n: usize) {
        for _ in 0..500 {
            if self.boots() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            self.boots() >= n,
            "the boot hook ran {} times, not {n}",
            self.boots()
        );
    }
}

/// The files a rendered boot plan writes: each `puddle_file '<path>' <mode> '<printf format>'`
/// line, with the format decoded the way `printf` reads it (`\NNN` is an octal byte).
fn plan_files(plan: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
    let text = String::from_utf8(plan.to_vec()).unwrap();
    let mut files = std::collections::BTreeMap::new();
    for line in text.split("\npuddle_") {
        let Some(rest) = line.strip_prefix("file ") else {
            continue;
        };
        let rest = rest.strip_prefix('\'').unwrap();
        let (path, rest) = rest.split_once("' ").unwrap();
        let (_mode, rest) = rest.split_once(' ').unwrap();
        let format = rest.strip_prefix('\'').unwrap();
        let format = &format[..format.rfind('\'').unwrap()];
        let mut bytes = Vec::new();
        let mut chars = format.bytes().peekable();
        while let Some(b) = chars.next() {
            if b == b'\\' {
                let octal: String = (0..3).map(|_| char::from(chars.next().unwrap())).collect();
                bytes.push(u8::from_str_radix(&octal, 8).unwrap());
            } else {
                bytes.push(b);
            }
        }
        files.insert(path.to_owned(), bytes);
    }
    files
}

#[derive(Debug)]
struct TestUi;

impl UiAssets for TestUi {
    fn get(&self, path: &str) -> Option<UiFile> {
        (path.is_empty() || path == "index.html")
            .then(|| UiFile::new(&b"<html>puddle test ui</html>"[..], "text/html"))
    }
}

#[derive(Debug, Default)]
struct RecordingLauncher {
    opened: Mutex<Vec<String>>,
}

impl Launcher for RecordingLauncher {
    fn open_desktop<'a>(
        &'a self,
        workspace: &'a WorkspaceRecord,
    ) -> futures_util::future::BoxFuture<'a, Result<(), LaunchError>> {
        Box::pin(async move {
            self.opened.lock().unwrap().push(workspace.name.to_string());
            Ok(())
        })
    }
}

struct Rig {
    dir: tempfile::TempDir,
    log: Log,
    runtime: FakeRuntime,
    guest: Arc<Guest>,
    launcher: Arc<RecordingLauncher>,
}

impl Rig {
    fn new() -> Self {
        let runtime = FakeRuntime::new();
        let guest = Arc::new(Guest::default());
        guest.install(&runtime);
        Self {
            dir: tempfile::tempdir().unwrap(),
            log: Log::default(),
            runtime,
            guest,
            launcher: Arc::new(RecordingLauncher::default()),
        }
    }

    fn config(&self) -> HostConfig {
        let root = self.dir.path();
        let agent = root.join("puddle-agent");
        std::fs::write(&agent, b"#!agent\n").unwrap();
        let layout =
            RuntimeLayout::new(root.join("runtime"), root.join("data").join("msb")).unwrap();
        let mut config = HostConfig::new(
            HostPaths::new(root.join("data")),
            layout,
            GuestSettings::new(agent),
        );
        // Never the machine's own proxy settings.
        config.upstream.discovery.mode = Mode::Direct;
        config.api.ui = Some(Arc::new(TestUi));
        config.operations_grace = Duration::from_secs(5);
        config
    }

    async fn start(&self) -> Host<FakeRuntime> {
        self.start_with(self.config()).await
    }

    async fn start_with(&self, config: HostConfig) -> Host<FakeRuntime> {
        let prepared = prepare(config, &FakePlatform::new(&self.log)).unwrap();
        let mut options = HostOptions::default();
        options.launcher = self.launcher.clone();
        Host::start(
            prepared,
            &FakeFactory::new(&self.runtime, &self.log),
            options,
        )
        .await
        .unwrap()
    }

    fn calls(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

fn api(host: &Host<FakeRuntime>) -> Api {
    Api::new(host.url(), host.token())
}

const REPO: &str = "https://example.org/acme/api.git";

fn new_workspace(name: &str) -> String {
    json!({"name": name, "repo_url": REPO}).to_string()
}

async fn create(api: &Api, events: &mut support::Events, name: &'static str) {
    let reply = api.post("/api/workspaces", &new_workspace(name)).await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    events.until(ended(name), Duration::from_secs(20)).await;
}

/// Turns the file at `path` into a non-empty folder: replacing it then fails on every OS.
fn make_unwritable(path: &std::path::Path) {
    if path.is_file() {
        std::fs::remove_file(path).unwrap();
    }
    std::fs::create_dir_all(path).unwrap();
    std::fs::write(path.join("keep"), b"x").unwrap();
}

fn status_of(reply: &support::Reply) -> String {
    reply.json()["status"].as_str().unwrap().to_owned()
}

// ---- the start-up order -------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn start_runs_the_steps_in_the_documented_order() {
    let rig = Rig::new();
    let platform = FakePlatform::new(&rig.log);
    let prepared = prepare(rig.config(), &platform).unwrap();
    assert_eq!(prepared.steps(), PREPARE_STEPS);
    let factory = FakeFactory::new(&rig.runtime, &rig.log);
    let host = Host::start(prepared, &factory, HostOptions::default())
        .await
        .unwrap();
    assert_eq!(host.steps(), START_STEPS);
    // The machine was asked in dependency order and the runtime opened last of those.
    assert_eq!(
        rig.calls(),
        [
            "pin_environment",
            "check_runtime",
            "corporate_roots",
            "open_runtime"
        ]
    );
    // The runtime got the address of the pull proxy bound in the first step, loopback only,
    // and no roots (this machine has none).
    let proxy = factory.pull_proxy.lock().unwrap().clone().unwrap();
    assert!(proxy.starts_with("127.0.0.1:"), "{proxy}");
    assert_eq!(*factory.roots.lock().unwrap(), Some(0));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_step_stops_the_start_before_the_runtime_is_touched() {
    for refused in ["pin_environment", "check_runtime", "corporate_roots"] {
        let rig = Rig::new();
        let mut platform = FakePlatform::new(&rig.log);
        platform.refuse = Some(refused);
        let err = prepare(rig.config(), &platform).unwrap_err();
        assert!(err.to_string().contains(refused), "{err}");
        assert!(!rig.calls().contains(&"open_runtime".to_owned()));
        // Nothing was asked of the runtime.
        assert!(rig.runtime.calls().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_agent_stops_the_start_before_anything_is_reconciled() {
    let rig = Rig::new();
    let mut config = rig.config();
    config.guest = GuestSettings::new(rig.dir.path().join("no-agent"));
    let prepared = prepare(config, &FakePlatform::new(&rig.log)).unwrap();
    let err = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, HostError::AgentMissing { .. }), "{err}");
    assert!(!rig.calls().contains(&"open_runtime".to_owned()));
    assert!(rig.runtime.calls().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_taken_api_port_is_reported_and_nothing_was_stopped_or_removed() {
    let rig = Rig::new();
    let first = rig.start().await;
    // Another data folder, so only the port is shared.
    let mut config = rig.config();
    config.paths = HostPaths::new(rig.dir.path().join("other-data"));
    config.api.port = first.url().port().unwrap();
    let prepared = prepare(config, &FakePlatform::new(&rig.log)).unwrap();
    let err = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, HostError::Api(_)), "{err}");
    first.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_host_on_the_same_data_folder_is_refused_and_the_first_is_untouched() {
    let rig = Rig::new();
    let first = rig.start().await;
    let api = api(&first);
    let mut events = api.events().await;
    create(&api, &mut events, "keep").await;
    let running = rig
        .runtime
        .list()
        .await
        .unwrap()
        .iter()
        .filter(|s| !s.status.is_down())
        .count();
    assert_eq!(running, 1);
    let calls_before = rig.runtime.calls();
    let log_before = rig.calls();

    let err = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap_err();
    assert!(matches!(err, HostError::DataFolder(_)), "{err}");
    let message = err.to_string();
    assert!(
        message.contains(&format!("process ID {}", std::process::id())),
        "{message}"
    );
    assert!(message.contains("data folder"), "{message}");

    // The refused start asked the machine nothing and the runtime nothing: the first host's
    // sandbox was neither trimmed nor stopped.
    assert_eq!(rig.calls(), log_before);
    assert_eq!(rig.runtime.calls(), calls_before);
    let still = rig.runtime.list().await.unwrap();
    assert_eq!(still.iter().filter(|s| !s.status.is_down()).count(), 1);
    assert_eq!(api.get("/api/health").await.status, 200);

    // Once the first host is gone the folder is free again.
    first.shutdown().await;
    drop(first);
    drop(prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap());
}

// ---- the daemon end to end ----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_serves_the_api_the_ui_and_the_event_stream() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);

    // The API wants the token; the UI is served from the same origin without one.
    assert_eq!(
        api.request("GET", "/api/health", None, false).await.status,
        401
    );
    assert_eq!(api.get("/api/health").await.status, 200);
    let ui = api.request("GET", "/", None, false).await;
    assert_eq!(ui.status, 200);
    assert!(ui.body.contains("puddle test ui"), "{}", ui.body);

    // The connection file names this host.
    let info =
        puddle_api::ConnectionInfo::read(&rig.dir.path().join("data").join("api.json")).unwrap();
    assert_eq!(info.token.expose(), host.token());

    // Create: events flow, in order, from the real service.
    let mut events = api.events().await;
    let reply = api.post("/api/workspaces", &new_workspace("acme")).await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(reply.json()["busy"], "creating");
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert_eq!(
        events.steps("acme"),
        [
            "preparing_volume",
            "pulling_image",
            "starting",
            "syncing",
            "cloning",
            "done"
        ]
    );
    assert!(
        events
            .seen
            .iter()
            .any(|e| e["type"] == "status_changed" && e["status"] == "running")
    );

    let list = api.get("/api/workspaces").await.json();
    assert_eq!(list["workspaces"][0]["name"], "acme");
    assert_eq!(list["workspaces"][0]["status"], "running");
    assert!(list["workspaces"][0]["busy"].is_null());

    // The guest saw the whole boot sequence, in order.
    let commands = rig.guest.commands();
    let kinds: Vec<&str> = commands
        .iter()
        .map(|c| c.split(' ').nth(1).unwrap())
        .collect();
    assert_eq!(kinds, ["boot", "layout", "locks", "clone", "sync"]);

    // Stop trims then stops; start boots it again in the same sandbox.
    let stop = api.post("/api/workspaces/acme/stop", "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(status_of(&api.get("/api/workspaces/acme").await), "stopped");
    let start = api.post("/api/workspaces/acme/start", "").await;
    assert_eq!(start.status, 202, "{}", start.body);
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(status_of(&api.get("/api/workspaces/acme").await), "running");
    let calls: Vec<String> = rig
        .runtime
        .calls()
        .iter()
        .map(|c| format!("{:?}", c.op))
        .collect();
    assert_eq!(
        calls.iter().filter(|c| *c == "Create").count(),
        1,
        "{calls:?}"
    );
    assert_eq!(
        calls.iter().filter(|c| *c == "Start").count(),
        1,
        "{calls:?}"
    );

    // Stop, then delete a clean workspace without a fingerprint.
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    let gone = api
        .delete(
            "/api/workspaces/acme",
            Some(&json!({"confirm": true}).to_string()),
        )
        .await;
    assert_eq!(gone.status, 202, "{}", gone.body);
    events.until(ended("acme"), Duration::from_secs(20)).await;
    let list = api.get("/api/workspaces").await.json();
    assert!(list["workspaces"].as_array().unwrap().is_empty());
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(rig.runtime.list_volumes().await.unwrap().is_empty());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_apis_address_is_registered_so_no_guest_can_ask_the_proxy_for_it() {
    let rig = Rig::new();
    let host = rig.start().await;
    let addr = std::net::SocketAddr::new(
        host.url().host_str().unwrap().parse().unwrap(),
        host.url().port().unwrap(),
    );
    let kinds: Vec<_> = host
        .endpoints()
        .list()
        .into_iter()
        .map(|(a, kind)| (a == addr, kind))
        .collect();
    assert!(kinds.contains(&(true, EndpointKind::Api)), "{kinds:?}");
    // The pull proxy is registered too (the other loopback entry).
    assert!(
        kinds.iter().any(|(_, k)| *k == EndpointKind::PullProxy),
        "{kinds:?}"
    );
    host.shutdown().await;
    assert!(
        host.endpoints().list().is_empty(),
        "{:?}",
        host.endpoints().list()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_api_and_the_pull_proxy_are_each_registered_once_in_the_one_registry() {
    let rig = Rig::new();
    let host = rig.start().await;
    let kinds: Vec<_> = host
        .endpoints()
        .list()
        .into_iter()
        .map(|(_, kind)| kind)
        .collect();
    assert_eq!(
        kinds.iter().filter(|k| **k == EndpointKind::Api).count(),
        1,
        "{kinds:?}"
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == EndpointKind::PullProxy)
            .count(),
        1,
        "{kinds:?}"
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_network_health_report_is_the_hosts_own_and_follows_a_network_change() {
    let rig = Rig::new();
    let os = FakeOs::new(ProxyConfig::default());
    let mut platform = FakePlatform::new(&rig.log);
    platform.roots = company_roots();
    let prepared = prepare(rig.config(), &platform).unwrap();
    let mut options = HostOptions::default();
    options.discovery = Some(Discovery::new(
        os.clone(),
        puddle_upstream::Config::default(),
    ));
    let host = Host::start(prepared, &FakeFactory::new(&rig.runtime, &rig.log), options)
        .await
        .unwrap();
    let api = api(&host);

    assert_eq!(
        api.request("GET", "/api/network-health", None, false)
            .await
            .status,
        401
    );
    let reply = api.get("/api/network-health").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let report = reply.json();
    assert_eq!(report["roots"]["synced"], true, "{report}");
    assert_eq!(report["roots"]["roots"], 1, "{report}");
    assert_eq!(
        report["roots"]["certificates"][0]["subject"],
        "Corp Root CA"
    );
    assert_eq!(
        report["pull_proxy"],
        json!({"active": true, "via_upstream": true})
    );
    assert_eq!(report["proxy"]["epoch"], 0);
    assert_eq!(report["proxy"]["last_change_at"], serde_json::Value::Null);

    // A network change: the event, then a report that shows the new epoch.
    let mut events = api.events().await;
    assert!(os.fire_change());
    let event = events
        .until(|e| e["type"] == "network_changed", Duration::from_secs(20))
        .await;
    assert_eq!(event["epoch"], 1, "{event}");
    let after = api.get("/api/network-health").await.json();
    assert_eq!(after["proxy"]["epoch"], 1, "{after}");
    assert!(after["proxy"]["last_change_at"].as_u64().unwrap() > 0);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_system_check_looks_at_the_runtime_folder_the_host_was_started_with() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);

    assert_eq!(
        api.request("GET", "/api/doctor?boot=false", None, false)
            .await
            .status,
        401
    );
    // The rig's runtime folder holds no msb: the check says so, names the folder, and skips what
    // needs a runtime. (The machine's own hypervisor check can come out either way.)
    let reply = api.get("/api/doctor?boot=false").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let report = reply.json();
    assert_eq!(report["schema_version"], 1, "{report}");
    assert_eq!(report["ok"], false, "{report}");
    let check = |id: &str| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no {id} check in {report}"))
            .clone()
    };
    let runtime = check("runtime");
    assert_eq!(runtime["status"], "fail", "{runtime}");
    assert_eq!(runtime["finding"], "runtime_missing", "{runtime}");
    assert!(
        runtime["summary"]
            .as_str()
            .unwrap()
            .contains(&rig.dir.path().join("runtime").display().to_string()),
        "{runtime}"
    );
    assert_eq!(check("launch")["status"], "skipped");
    assert_eq!(check("test_boot")["status"], "skipped");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_clone_leaves_nothing_behind() {
    let rig = Rig::new();
    rig.guest.fail_clone.store(true, Ordering::SeqCst);
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    api.post("/api/workspaces", &new_workspace("acme")).await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed");
    assert!(
        end["detail"]
            .as_str()
            .unwrap()
            .contains("repository not found"),
        "{end}"
    );
    assert_eq!(
        events.steps("acme"),
        [
            "preparing_volume",
            "pulling_image",
            "starting",
            "syncing",
            "cloning",
            "failed"
        ]
    );
    // No record, no sandbox, no volume, no VM.
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(rig.runtime.list_volumes().await.unwrap().is_empty());
    // The name is free again.
    rig.guest.fail_clone.store(false, Ordering::SeqCst);
    create(&api, &mut events, "acme").await;
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_boot_leaves_nothing_behind_and_a_failed_start_says_crashed() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    rig.guest.fail_boot.store(true, Ordering::SeqCst);
    api.post("/api/workspaces", &new_workspace("acme")).await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert!(
        end["detail"].as_str().unwrap().contains("boot hook"),
        "{end}"
    );
    assert!(rig.runtime.list_volumes().await.unwrap().is_empty());
    assert!(rig.runtime.list().await.unwrap().is_empty());

    rig.guest.fail_boot.store(false, Ordering::SeqCst);
    create(&api, &mut events, "acme").await;
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    rig.guest.fail_boot.store(true, Ordering::SeqCst);
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert_eq!(status_of(&api.get("/api/workspaces/acme").await), "crashed");
    // The volume and the workspace survive a failed start.
    assert_eq!(rig.runtime.list_volumes().await.unwrap().len(), 1);
    rig.guest.fail_boot.store(false, Ordering::SeqCst);
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dirty_workspace_is_deleted_only_with_the_fingerprint_the_user_saw() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;

    rig.guest.dirty.store(true, Ordering::SeqCst);
    let check = api.get("/api/workspaces/acme/delete-check").await.json();
    assert_eq!(check["clean"], false);
    let fingerprint = check["fingerprint"].as_str().unwrap().to_owned();

    let bare = json!({"confirm": true}).to_string();
    let refused = api.delete("/api/workspaces/acme", Some(&bare)).await;
    assert_eq!(refused.status, 409, "{}", refused.body);
    let stale = json!({"confirm": true, "fingerprint": "0".repeat(64)}).to_string();
    assert_eq!(
        api.delete("/api/workspaces/acme", Some(&stale))
            .await
            .status,
        409
    );
    assert_eq!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let seen = json!({"confirm": true, "fingerprint": fingerprint}).to_string();
    let accepted = api.delete("/api/workspaces/acme", Some(&seen)).await;
    assert_eq!(accepted.status, 202, "{}", accepted.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_workspace_cannot_be_deleted_and_busy_ones_refuse_a_second_operation() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let delete = api
        .delete(
            "/api/workspaces/acme",
            Some(&json!({"confirm": true}).to_string()),
        )
        .await;
    assert_eq!(delete.status, 409, "{}", delete.body);
    assert_eq!(api.post("/api/workspaces/acme/start", "").await.status, 409);
    assert_eq!(
        api.post("/api/workspaces", &new_workspace("acme"))
            .await
            .status,
        409
    );
    assert_eq!(api.get("/api/workspaces/nope").await.status, 404);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reclaim_trims_the_running_workspace() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let reply = api.post("/api/workspaces/acme/reclaim", "").await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done");
    assert!(rig.guest.commands().iter().any(|c| c.ends_with(" trim")));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_opens_the_desktop_editor_through_the_launcher() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    let before = api
        .post(
            "/api/workspaces/acme/attach",
            &json!({"mode": "desktop"}).to_string(),
        )
        .await;
    assert_eq!(before.status, 404);
    create(&api, &mut events, "acme").await;
    let refused = api
        .post(
            "/api/workspaces/acme/attach",
            &json!({"mode": "desktop"}).to_string(),
        )
        .await;
    assert_eq!(refused.status, 409, "direct SSH is off: {}", refused.body);
    assert!(rig.launcher.opened.lock().unwrap().is_empty());
    allow_direct_ssh(&api, "acme", true).await;
    let reply = api
        .post(
            "/api/workspaces/acme/attach",
            &json!({"mode": "desktop"}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json()["opened"], true);
    assert_eq!(*rig.launcher.opened.lock().unwrap(), ["acme"]);
    let browser = api
        .post(
            "/api/workspaces/acme/attach",
            &json!({"mode": "browser"}).to_string(),
        )
        .await;
    assert_eq!(browser.json()["opened"], false);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_workspace_gets_the_memory_the_settings_name() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    let put = api
        .request(
            "PUT",
            "/api/settings",
            Some(&json!({"workspace_defaults": {"memory": 2048}}).to_string()),
            true,
        )
        .await;
    assert_eq!(put.status, 200, "{}", put.body);
    create(&api, &mut events, "acme").await;
    let spec_memory = api.get("/api/workspaces/acme").await.json()["memory_mib"].clone();
    assert_eq!(spec_memory, 2048);
    host.shutdown().await;
    // The next start is a new process: the first one's hold on the data folder ends.
    drop(host);
    // The settings are files: a second host over the same folder sees them.
    let again = rig.start().await;
    let reply = api_for(&again).get("/api/settings").await;
    assert!(reply.body.contains("2048"), "{}", reply.body);
    again.shutdown().await;
}

/// Puts a damaged global settings file where the host reads it, before the host starts.
fn damage_global_settings(rig: &Rig) -> PathBuf {
    let dir = rig.dir.path().join("data").join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("global.json");
    std::fs::write(&file, b"{ not json").unwrap();
    file
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_that_needs_the_default_memory_is_refused_while_the_settings_are_unreadable() {
    let rig = Rig::new();
    let file = damage_global_settings(&rig);
    let host = rig.start().await;
    let api = api(&host);
    let reply = api.post("/api/workspaces", &new_workspace("acme")).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    let message = reply.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("global.json"), "{message}");
    assert!(message.contains("choose a memory size"), "{message}");
    assert_eq!(
        api.get("/api/workspaces").await.json()["workspaces"],
        json!([])
    );

    // Naming the memory needs no settings, so that way out works.
    let mut events = api.events().await;
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": "acme", "repo_url": REPO, "memory_mib": 4096}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    events.until(ended("acme"), Duration::from_secs(20)).await;
    let view = api.get("/api/workspaces/acme").await.json();
    assert_eq!(view["memory_mib"], 4096);
    // The same damage is on the workspace, and direct SSH stays off.
    assert_eq!(view["direct_ssh"], false);
    assert!(view["settings_error"].as_str().is_some(), "{view}");
    assert!(
        !host
            .workspaces()
            .direct_ssh_allowed(&WorkspaceName::new("acme").unwrap())
    );
    assert!(file.is_file(), "the damaged file is left for the user");
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_memory_size_that_is_not_valid_stops_the_start_and_names_the_way_out() {
    let rig = Rig::new();
    let data = rig.dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(
        data.join("workspaces.json"),
        json!({"version": 1, "workspaces": [{
            "id": "acme", "name": "acme", "repo_url": REPO, "image": "img",
            "memory_mib": 1, "created_at": 0, "disk_size_mib": 64
        }]})
        .to_string(),
    )
    .unwrap();
    let prepared = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap();
    let err = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("workspace acme"), "{message}");
    assert!(message.contains("workspaces.json"), "{message}");
}

fn api_for(host: &Host<FakeRuntime>) -> Api {
    api(host)
}

// ---- the shutdown order -------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_runs_the_steps_in_order_and_trims_then_stops_every_sandbox() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    create(&api, &mut events, "beta").await;

    let down = host.shutdown().await;
    assert_eq!(down.steps, SHUTDOWN_STEPS);
    assert_eq!(down.operations_ended, 0);
    assert!(down.sandboxes.all_stopped(), "{down:?}");
    assert_eq!(down.sandboxes.sandboxes.len(), 2);
    assert!(
        down.sandboxes
            .sandboxes
            .iter()
            .all(|s| s.trim == puddle_lifecycle::TrimOutcome::Trimmed),
        "{down:?}"
    );
    // Each sandbox: the trim command ran before its stop.
    let commands = rig.guest.commands();
    for name in ["acme", "beta"] {
        let trim = commands
            .iter()
            .position(|c| c == &format!("{name} shutdown-trim"))
            .unwrap();
        let stop = rig
            .runtime
            .calls()
            .iter()
            .position(|c| format!("{:?}", c.op) == "Stop" && c.target.as_deref() == Some(name))
            .unwrap();
        assert!(trim < commands.len() && stop > 0);
    }
    for info in rig.runtime.list().await.unwrap() {
        assert!(info.status.is_down(), "{info:?}");
    }
    // The API is gone, and a second shutdown returns the first result.
    assert!(
        tokio::net::TcpStream::connect((
            host.url().host_str().unwrap(),
            host.url().port().unwrap()
        ))
        .await
        .is_err()
    );
    assert_eq!(host.shutdown().await, down);
    assert_eq!(
        host.steps()
            .iter()
            .filter(|s| **s == Step::ApiStopped)
            .count(),
        1
    );
}

/// A runtime whose image pull takes a while, so an operation is in flight at an await point.
#[derive(Clone)]
struct SlowPull(FakeRuntime, Duration);

impl Runtime for SlowPull {
    type Sandbox = <FakeRuntime as Runtime>::Sandbox;

    fn probe(
        &self,
    ) -> impl Future<Output = Result<puddle_compute::Capabilities, puddle_compute::ComputeError>> + Send
    {
        self.0.probe()
    }

    async fn pull_image(
        &self,
        image: &ImageRef,
    ) -> Result<ImageConfig, puddle_compute::ComputeError> {
        tokio::time::sleep(self.1).await;
        self.0.pull_image(image).await
    }

    fn create(
        &self,
        spec: puddle_compute::SandboxSpec,
    ) -> impl Future<Output = Result<Self::Sandbox, puddle_compute::ComputeError>> + Send {
        self.0.create(spec)
    }

    fn start(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<Self::Sandbox, puddle_compute::ComputeError>> + Send {
        self.0.start(name)
    }

    fn get(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<Self::Sandbox, puddle_compute::ComputeError>> + Send {
        self.0.get(name)
    }

    fn set_memory(
        &self,
        name: &SandboxName,
        memory: puddle_types::MemoryMib,
    ) -> impl Future<Output = Result<(), puddle_compute::ComputeError>> + Send {
        self.0.set_memory(name, memory)
    }

    fn list(
        &self,
    ) -> impl Future<Output = Result<Vec<puddle_compute::SandboxInfo>, puddle_compute::ComputeError>>
    + Send {
        self.0.list()
    }

    fn remove(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<(), puddle_compute::ComputeError>> + Send {
        self.0.remove(name)
    }

    fn stale_dirs(
        &self,
    ) -> impl Future<Output = Result<Vec<String>, puddle_compute::ComputeError>> + Send {
        self.0.stale_dirs()
    }

    fn remove_stale_dir(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<(), puddle_compute::ComputeError>> + Send {
        self.0.remove_stale_dir(name)
    }

    fn create_volume(
        &self,
        spec: puddle_compute::VolumeSpec,
    ) -> impl Future<Output = Result<puddle_compute::VolumeInfo, puddle_compute::ComputeError>> + Send
    {
        self.0.create_volume(spec)
    }

    fn volume(
        &self,
        name: &puddle_types::VolumeName,
    ) -> impl Future<
        Output = Result<Option<puddle_compute::VolumeInfo>, puddle_compute::ComputeError>,
    > + Send {
        self.0.volume(name)
    }

    fn list_volumes(
        &self,
    ) -> impl Future<Output = Result<Vec<puddle_compute::VolumeInfo>, puddle_compute::ComputeError>> + Send
    {
        self.0.list_volumes()
    }

    fn remove_volume(
        &self,
        name: &puddle_types::VolumeName,
    ) -> impl Future<Output = Result<(), puddle_compute::ComputeError>> + Send {
        self.0.remove_volume(name)
    }
}

struct SlowFactory(SlowPull);

impl RuntimeFactory for SlowFactory {
    type Runtime = SlowPull;

    fn open(
        &self,
        _: RuntimeInputs<'_>,
    ) -> impl Future<Output = Result<SlowPull, HostError>> + Send {
        std::future::ready(Ok(self.0.clone()))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_ends_an_operation_that_outlasts_the_grace_period() {
    let rig = Rig::new();
    let mut config = rig.config();
    config.operations_grace = Duration::from_millis(50);
    let prepared = prepare(config, &FakePlatform::new(&rig.log)).unwrap();
    let slow = SlowPull(rig.runtime.clone(), Duration::from_secs(30));
    let host = Host::start(prepared, &SlowFactory(slow), HostOptions::default())
        .await
        .unwrap();
    let api = api_slow(&host);
    let mut events = api.events().await;
    api.post("/api/workspaces", &new_workspace("acme")).await;
    events
        .until(
            |e| e["type"] == "workspace_progress" && e["step"] == "pulling_image",
            Duration::from_secs(20),
        )
        .await;
    let started = std::time::Instant::now();
    let down = host.shutdown().await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(down.operations_ended, 1, "{down:?}");
    assert_eq!(down.steps, SHUTDOWN_STEPS);
    // The ended create left its half-made volume for the next start's reconcile.
    assert!(!rig.runtime.list_volumes().await.unwrap().is_empty());
}

fn api_slow(host: &Host<SlowPull>) -> Api {
    Api::new(host.url(), host.token())
}

#[tokio::test(flavor = "multi_thread")]
async fn operations_are_refused_once_shutdown_has_begun() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    host.workspaces().close();
    let refused = api.post("/api/workspaces", &new_workspace("late")).await;
    assert_eq!(refused.status, 503, "{}", refused.body);
    assert!(refused.body.contains("shutting down"), "{}", refused.body);
    host.shutdown().await;
}

// ---- after a restart ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_restart_keeps_the_workspaces_and_rebuilds_the_sandbox_on_the_same_volume() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    let created_at = api1.get("/api/workspaces/acme").await.json()["created_at"].clone();
    host.shutdown().await;
    // The next start is a new process: the first one's hold on the data folder ends.
    drop(host);
    drop(events);

    let again = rig.start().await;
    let api2 = api(&again);
    let list = api2.get("/api/workspaces").await.json();
    assert_eq!(list["workspaces"][0]["name"], "acme");
    assert_eq!(list["workspaces"][0]["status"], "stopped");
    assert_eq!(list["workspaces"][0]["created_at"], created_at);
    // Reconcile kept the sandbox and the volume (the workspace is known).
    assert!(
        again.reconcile_report().removed.is_empty(),
        "{:?}",
        again.reconcile_report()
    );
    assert!(again.reconcile_report().volumes_removed.is_empty());

    // This process does not serve the old sandbox's route, so starting rebuilds the sandbox.
    let mut events = api2.events().await;
    api2.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert_eq!(
        status_of(&api2.get("/api/workspaces/acme").await),
        "running"
    );
    let creates = rig
        .runtime
        .calls()
        .iter()
        .filter(|c| format!("{:?}", c.op) == "Create")
        .count();
    assert_eq!(creates, 2);
    assert_eq!(rig.runtime.list_volumes().await.unwrap().len(), 1);
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_crashed_sandbox_is_reported_crashed_and_start_recovers_it() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    assert!(rig.runtime.crash(&SandboxName::new("acme").unwrap()));
    host.shutdown().await;
    // The next start is a new process: the first one's hold on the data folder ends.
    drop(host);

    let again = rig.start().await;
    let api2 = api(&again);
    assert_eq!(
        status_of(&api2.get("/api/workspaces/acme").await),
        "crashed"
    );
    assert_eq!(again.reconcile_report().crashed.len(), 1);
    let mut events = api2.events().await;
    api2.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vm_left_running_by_a_dead_puddle_is_stopped_at_the_next_start() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    // The first host never shuts down (it died): its VM still runs.
    let running = rig.runtime.list().await.unwrap();
    assert!(!running[0].status.is_down());

    // It died: its hold on the data folder ended with it, and the VM kept running.
    drop(host);
    // Let whatever the drop ends finish before the VM is made to outlive it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rig.runtime
            .outlive_owner(&SandboxName::new("acme").unwrap())
    );
    assert!(
        !rig.runtime
            .outlive_owner(&SandboxName::new("nobody").unwrap())
    );
    let again = rig.start().await;
    assert_eq!(
        again.reconcile_report().stopped.len(),
        1,
        "{:?}",
        again.reconcile_report()
    );
    assert!(rig.runtime.list().await.unwrap()[0].status.is_down());
    assert_eq!(
        status_of(&api(&again).get("/api/workspaces/acme").await),
        "stopped"
    );
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_interrupted_create_is_dropped_and_its_volume_removed() {
    let rig = Rig::new();
    let data = rig.dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let book = json!({"version": 1, "workspaces": [{
        "id": "half", "name": "half", "repo_url": REPO, "image": FakeRuntime::DEBIAN,
        "memory_mib": 1024, "created_at": 1, "disk_size_mib": 1024,
        "first_connect_notice_due": true, "creating": true
    }]});
    std::fs::write(data.join("workspaces.json"), book.to_string()).unwrap();
    rig.runtime
        .create_volume(puddle_compute::VolumeSpec {
            name: WorkspaceId::new("half").unwrap().volume_name(),
            size: puddle_compute::DiskSize::mib(1024),
        })
        .await
        .unwrap();

    let host = rig.start().await;
    assert!(
        api(&host).get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(host.reconcile_report().volumes_removed.len(), 1);
    assert!(rig.runtime.list_volumes().await.unwrap().is_empty());
    // The book no longer lists it.
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(data.join("workspaces.json")).unwrap()).unwrap();
    assert!(
        saved["workspaces"].as_array().unwrap().is_empty(),
        "{saved}"
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_workspace_list_stops_the_start_instead_of_looking_empty() {
    let rig = Rig::new();
    let data = rig.dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("workspaces.json"), b"{ not json").unwrap();
    let prepared = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap();
    let err = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, HostError::State { .. }), "{err}");
    // Nothing was reconciled: a volume of the workspace that could not be listed is safe.
    assert!(rig.runtime.calls().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_data_folder_is_made_owner_only_at_start_and_one_that_cannot_be_refuses() {
    let rig = Rig::new();
    let data = rig.dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("puddle.db"), b"").unwrap();
    let prepared = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap();
    let host = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap();
    let db = std::fs::File::open(data.join("puddle.db")).unwrap();
    puddle_fs::private::check(&db).unwrap();
    host.shutdown().await;

    // A folder in the database's place can't be made owner-only: the start is refused before
    // anything is reconciled.
    let rig = Rig::new();
    let data = rig.dir.path().join("data");
    std::fs::create_dir_all(data.join("puddle.db")).unwrap();
    let prepared = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap();
    let err = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("will not run with wider permissions"),
        "{err}"
    );
    assert!(rig.runtime.calls().is_empty());
}

// ---- the workspace list never costs a workspace its volume ------------------------------

async fn volume_names(rig: &Rig) -> Vec<String> {
    rig.runtime
        .list_volumes()
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect()
}

fn list_path(rig: &Rig) -> PathBuf {
    rig.dir.path().join("data").join("workspaces.json")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_workspace_list_keeps_every_workspace_volume() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    host.shutdown().await;
    // The next start is a new process: the first one's hold on the data folder ends.
    drop(host);
    drop(events);
    // The list is gone (deleted by hand, restored from an old backup, a broken disk).
    std::fs::remove_file(list_path(&rig)).unwrap();

    let again = rig.start().await;
    assert_eq!(volume_names(&rig).await, ["ws-acme"]);
    assert!(
        again.reconcile_report().volumes_removed.is_empty(),
        "{:?}",
        again.reconcile_report()
    );
    // Reported, so the user can be told, and still usable: the volume is never taken.
    assert_eq!(
        again.reconcile_report().unknown_volumes,
        [WorkspaceId::new("acme").unwrap().volume_name()]
    );
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_volume_no_listed_workspace_claims_is_kept() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    host.shutdown().await;
    // The next start is a new process: the first one's hold on the data folder ends.
    drop(host);
    drop(events);
    // A volume with work on it that the list doesn't name (an older or partial list).
    rig.runtime
        .create_volume(puddle_compute::VolumeSpec {
            name: WorkspaceId::new("lost").unwrap().volume_name(),
            size: puddle_compute::DiskSize::mib(1024),
        })
        .await
        .unwrap();

    let again = rig.start().await;
    assert_eq!(volume_names(&rig).await, ["ws-acme", "ws-lost"]);
    assert_eq!(
        again.reconcile_report().unknown_volumes,
        [WorkspaceId::new("lost").unwrap().volume_name()]
    );
    // The listed workspace is unaffected.
    assert_eq!(
        status_of(&api(&again).get("/api/workspaces/acme").await),
        "stopped"
    );
    again.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_is_refused_when_the_workspace_list_cannot_be_saved() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    make_unwritable(&list_path(&rig));

    let reply = api.post("/api/workspaces", &new_workspace("acme")).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    let message = reply.json()["message"].as_str().unwrap().to_owned();
    // What failed, the file, and what to do about it.
    assert!(message.contains("workspace list"), "{message}");
    assert!(message.contains("workspaces.json"), "{message}");
    assert!(message.contains("try again"), "{message}");
    // Nothing was made, and the name is still free.
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(volume_names(&rig).await.is_empty());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_whose_last_save_fails_is_undone_and_says_why() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    *rig.guest.break_list_on_clone.lock().unwrap() = Some(list_path(&rig));

    api1.post("/api/workspaces", &new_workspace("acme")).await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    // The list still says "being created", so a restart would take the volume as a leftover:
    // the create fails now, before anyone works in it.
    assert_eq!(end["step"], "failed", "{end}");
    assert!(
        end["detail"].as_str().unwrap().contains("workspace list"),
        "{end}"
    );
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(volume_names(&rig).await.is_empty());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delete_is_refused_when_the_workspace_list_cannot_be_saved() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    make_unwritable(&list_path(&rig));

    let confirm = json!({"confirm": true}).to_string();
    let refused = api.delete("/api/workspaces/acme", Some(&confirm)).await;
    assert_eq!(refused.status, 503, "{}", refused.body);
    let message = refused.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("workspace list"), "{message}");
    // Nothing was deleted: the workspace and its volume are still there.
    assert_eq!(status_of(&api.get("/api/workspaces/acme").await), "stopped");
    assert_eq!(volume_names(&rig).await, ["ws-acme"]);
    // Not busy any more: once the list can be saved again, the delete goes through.
    std::fs::remove_file(list_path(&rig).join("keep")).unwrap();
    std::fs::remove_dir(list_path(&rig)).unwrap();
    let accepted = api.delete("/api/workspaces/acme", Some(&confirm)).await;
    assert_eq!(accepted.status, 202, "{}", accepted.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(volume_names(&rig).await.is_empty());
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(list_path(&rig)).unwrap()).unwrap();
    assert!(
        saved["workspaces"].as_array().unwrap().is_empty(),
        "{saved}"
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ssh_endpoint_exists_while_the_workspace_runs_with_direct_ssh_on() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    allow_direct_ssh(&api, "acme", true).await;
    create(&api, &mut events, "acme").await;
    let name = WorkspaceName::new("acme").unwrap();
    let endpoint: PathBuf = host.workspaces().ssh_endpoint(&name).await.unwrap();
    assert_ne!(endpoint.as_os_str(), "");
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert!(host.workspaces().ssh_endpoint(&name).await.is_none());
    host.shutdown().await;
}

async fn allow_direct_ssh(api: &Api, name: &str, on: bool) {
    let reply = api
        .put(
            &format!("/api/settings/workspaces/{name}"),
            &json!({"overrides": {"direct_ssh": on}}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_direct_ssh_off_there_is_no_ssh_endpoint_and_the_gate_says_no() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let name = WorkspaceName::new("acme").unwrap();
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["status"],
        "running"
    );
    assert!(
        host.workspaces().ssh_endpoint(&name).await.is_none(),
        "no endpoint while the switch is off"
    );
    assert!(
        !host.workspaces().direct_ssh_allowed(&name),
        "the gate says no, so nothing else may open a way in"
    );
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["direct_ssh"],
        false
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn turning_direct_ssh_on_and_off_opens_and_closes_the_endpoint_at_once() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let name = WorkspaceName::new("acme").unwrap();

    allow_direct_ssh(&api, "acme", true).await;
    assert!(host.workspaces().direct_ssh_allowed(&name));
    host.workspaces()
        .ssh_endpoint(&name)
        .await
        .expect("endpoint opens live");
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["direct_ssh"],
        true
    );

    allow_direct_ssh(&api, "acme", false).await;
    assert!(
        host.workspaces().ssh_endpoint(&name).await.is_none(),
        "endpoint closes live"
    );
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["direct_ssh"],
        false
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_global_default_decides_for_workspaces_without_their_own_switch() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    let reply = api
        .put(
            "/api/settings",
            &json!({"workspace_defaults": {"direct_ssh": true}}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    create(&api, &mut events, "acme").await;
    let name = WorkspaceName::new("acme").unwrap();
    assert!(host.workspaces().ssh_endpoint(&name).await.is_some());
    // Its own switch wins over the default.
    allow_direct_ssh(&api, "acme", false).await;
    assert!(host.workspaces().ssh_endpoint(&name).await.is_none());
    host.shutdown().await;
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn an_image_pull_is_audited_as_puddles_own_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rig = Rig::new();
    let platform = FakePlatform::new(&rig.log);
    let prepared = prepare(rig.config(), &platform).unwrap();
    let factory = FakeFactory::new(&rig.runtime, &rig.log);
    let host = Host::start(prepared, &factory, HostOptions::default())
        .await
        .unwrap();

    let target = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = target.accept().await;
    });
    let url = factory.pull_url.lock().unwrap().clone().unwrap();
    let rest = url.strip_prefix("http://").unwrap();
    let (credentials, addr) = rest.split_once('@').unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        base64(credentials.as_bytes())
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head).await.unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    drop(stream);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let records: Vec<serde_json::Value> = host
            .store()
            .audit_lines(0, 1000)
            .unwrap()
            .into_iter()
            .filter_map(|(_, line)| serde_json::from_str(&line).ok())
            .filter(|v: &serde_json::Value| v["type"] == "connection")
            .collect();
        if let Some(record) = records.first() {
            assert!(record["workspace"].is_null(), "{record}");
            assert_eq!(record["origin"], "puddle", "{record}");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no audit record for the pull"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    host.shutdown().await;
}

/// Seeds a workspace the list names whose volume is gone, then returns the rig and its host.
async fn host_with_listed_workspace_whose_volume_is_gone() -> (Rig, Host<FakeRuntime>) {
    let rig = Rig::new();
    let host = rig.start().await;
    let api1 = api(&host);
    let mut events = api1.events().await;
    create(&api1, &mut events, "acme").await;
    host.shutdown().await;
    drop(host);
    drop(events);
    rig.runtime
        .remove_volume(&WorkspaceId::new("acme").unwrap().volume_name())
        .await
        .unwrap();
    let again = rig.start().await;
    (rig, again)
}

#[tokio::test(flavor = "multi_thread")]
async fn starting_a_workspace_whose_volume_is_gone_refuses_and_makes_no_empty_volume() {
    let (rig, host) = host_with_listed_workspace_whose_volume_is_gone().await;
    let api = api(&host);
    let mut events = api.events().await;
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    let detail = end["detail"].as_str().unwrap();
    assert!(detail.contains("has no volume"), "{detail}");
    assert!(detail.contains("ws-acme"), "{detail}");
    assert!(detail.contains("no new empty volume"), "{detail}");
    // Nothing was made in its place.
    assert!(volume_names(&rig).await.is_empty());
    assert!(rig.runtime.list().await.unwrap().is_empty());
    // The entry stays in the list (nothing else was lost).
    assert_eq!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_start_for_a_missing_volume_shows_the_volume_missing_state() {
    let (_rig, host) = host_with_listed_workspace_whose_volume_is_gone().await;
    let api = api(&host);
    let mut events = api.events().await;
    api.post("/api/workspaces/acme/start", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["status"],
        "volume_missing"
    );
    // The state is a way to delete, and a start that finds the volume again leaves it.
    let check = api.get("/api/workspaces/acme/delete-check").await.json();
    assert_eq!(check["volume_missing"], true);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workspace_whose_volume_is_gone_can_be_deleted_without_a_check_in_a_sandbox() {
    let (rig, host) = host_with_listed_workspace_whose_volume_is_gone().await;
    let api = api(&host);
    let mut events = api.events().await;
    let check = api.get("/api/workspaces/acme/delete-check").await.json();
    assert_eq!(check["volume_missing"], true, "{check}");
    assert_eq!(check["clean"], true, "{check}");
    let seen =
        json!({"confirm": true, "fingerprint": check["fingerprint"].as_str().unwrap()}).to_string();
    let accepted = api.delete("/api/workspaces/acme", Some(&seen)).await;
    assert_eq!(accepted.status, 202, "{}", accepted.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(volume_names(&rig).await.is_empty());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_workspace_with_no_volume_also_removes_the_sandbox_the_restart_kept() {
    let (rig, host) = host_with_listed_workspace_whose_volume_is_gone().await;
    // The restart kept the stopped sandbox record.
    assert_eq!(rig.runtime.list().await.unwrap().len(), 1);
    let api = api(&host);
    let mut events = api.events().await;
    let check = api.get("/api/workspaces/acme/delete-check").await.json();
    let seen = json!({"confirm": true, "fingerprint": check["fingerprint"]}).to_string();
    let accepted = api.delete("/api/workspaces/acme", Some(&seen)).await;
    assert_eq!(accepted.status, 202, "{}", accepted.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(rig.runtime.list().await.unwrap().is_empty());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restored_volume_lets_a_volume_missing_workspace_start() {
    let (rig, host) = host_with_listed_workspace_whose_volume_is_gone().await;
    let api = api(&host);
    let mut events = api.events().await;
    api.post("/api/workspaces/acme/start", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    rig.runtime
        .create_volume(puddle_compute::VolumeSpec {
            name: WorkspaceId::new("acme").unwrap().volume_name(),
            size: puddle_compute::DiskSize::mib(1024),
        })
        .await
        .unwrap();
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert_eq!(
        api.get("/api/workspaces/acme").await.json()["status"],
        "running"
    );
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_a_workspace_named_like_a_kept_volume_is_refused_and_leaves_it_alone() {
    let rig = Rig::new();
    rig.runtime
        .create_volume(puddle_compute::VolumeSpec {
            name: WorkspaceId::new("lost").unwrap().volume_name(),
            size: puddle_compute::DiskSize::mib(1024),
        })
        .await
        .unwrap();
    let host = rig.start().await;
    let api = api(&host);

    let reply = api.post("/api/workspaces", &new_workspace("lost")).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    let message = reply.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("ws-lost"), "{message}");
    assert!(message.contains("may hold"), "{message}");
    assert!(message.contains("another name"), "{message}");
    // Nothing was made or removed, and no list entry exists.
    assert_eq!(volume_names(&rig).await, ["ws-lost"]);
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // Another name still works.
    let mut events = api.events().await;
    create(&api, &mut events, "other").await;
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_record_the_list_does_not_name_is_removed_and_reported_but_its_volume_stays() {
    let rig = Rig::new();
    rig.runtime
        .create_volume(puddle_compute::VolumeSpec {
            name: WorkspaceId::new("lost").unwrap().volume_name(),
            size: puddle_compute::DiskSize::mib(1024),
        })
        .await
        .unwrap();
    let ghost = SandboxName::new("ghost").unwrap();
    rig.runtime
        .create(puddle_compute::SandboxSpec::new(
            ghost.clone(),
            ImageRef::new(FakeRuntime::DEBIAN).unwrap(),
        ))
        .await
        .unwrap();

    let host = rig.start().await;
    assert_eq!(host.reconcile_report().removed, [ghost]);
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert_eq!(volume_names(&rig).await, ["ws-lost"]);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_is_refused_when_the_runtime_cannot_say_whether_the_volume_exists() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    rig.runtime.inject(
        puddle_compute::fake::Op::Volume,
        puddle_compute::fake::Fault::once(puddle_compute::ComputeError::Runtime {
            op: "volume",
            message: "volume lookup broke".into(),
        }),
    );

    let reply = api.post("/api/workspaces", &new_workspace("acme")).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    let message = reply.json()["message"].as_str().unwrap().to_owned();
    assert!(message.contains("ws-acme"), "{message}");
    assert!(message.contains("volume lookup broke"), "{message}");
    assert!(
        api.get("/api/workspaces").await.json()["workspaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    host.shutdown().await;
}

// ---- credential injection: the CA, what is decrypted, the authors ---------------------------------

const KEY_MARKER: &[u8] = b"PRIVATE KEY";

fn pem_of(files: &std::collections::BTreeMap<String, Vec<u8>>, path: &str) -> String {
    String::from_utf8(files[path].clone()).unwrap()
}

/// `POST /api/identities`: a `gh` credential on `host` covering the rest of it (or `owners`).
async fn make_identity(api: &Api, label: &str, host: &str, owners: &[&str]) -> i64 {
    let body = json!({
        "label": label,
        "author": {"name": label, "email": format!("{}@example.org", label.to_lowercase())},
        "credentials": [{
            "host": host,
            "source": {"kind": "gh", "host": host, "account": "me"},
            "covers": {"owners": owners, "rest_of_host": owners.is_empty()}
        }]
    });
    let reply = api.post("/api/identities", &body.to_string()).await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    reply.json()["id"].as_i64().unwrap()
}

async fn attach(api: &Api, workspace: &str, identity: i64) {
    let reply = api
        .post(
            &format!("/api/workspaces/{workspace}/identities"),
            &json!({"identity": identity}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

fn name(workspace: &str) -> WorkspaceName {
    WorkspaceName::new(workspace).unwrap()
}

fn decrypts(host: &Host<FakeRuntime>, workspace: &str, site: &str) -> bool {
    host.workspaces()
        .termination(&name(workspace))
        .is_some_and(|t| {
            t.set()
                .contains(&puddle_types::Host::parse_normalised(site).unwrap())
        })
}

/// Waits for `condition` to hold (a change applies when the host has handled its event).
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(condition(), "never became true: {what}");
}

fn calls_of(rig: &Rig, op: &str) -> usize {
    rig.runtime
        .calls()
        .iter()
        .filter(|c| format!("{:?}", c.op) == op)
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_workspace_trusts_its_own_ca_from_the_first_boot_and_decrypts_nothing_yet() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    create(&api, &mut events, "beta").await;

    // The CA the guest was given is the one the proxy signs with, and each workspace has its own.
    let ca_of = |workspace: &str| {
        host.workspaces()
            .termination(&name(workspace))
            .unwrap()
            .ca()
            .certificate()
            .clone()
    };
    let (acme, beta) = (ca_of("acme"), ca_of("beta"));
    assert_ne!(acme, beta);
    let files = rig.guest.plan_files(0);
    for path in [
        "/etc/puddle/extra-cas.pem",
        "/usr/local/share/ca-certificates/puddle/puddle-ca-1.crt",
    ] {
        assert_eq!(pem_of(&files, path), acme.pem(), "{path}");
    }
    let guest_der =
        rustls::pki_types::CertificateDer::from_pem_slice(&files["/etc/puddle/extra-cas.pem"])
            .unwrap();
    assert_eq!(guest_der.as_ref(), acme.der().as_ref());
    assert_ne!(
        pem_of(
            &rig.guest.plan_files(rig.guest.boots() - 1),
            "/etc/puddle/extra-cas.pem"
        ),
        acme.pem()
    );
    // Tools are pointed at the bundle, though nothing is decrypted yet.
    let env = pem_of(&files, "/etc/profile.d/01-puddle-env.sh");
    assert!(
        env.contains("export SSL_CERT_FILE='/etc/puddle/ca-bundle.pem'"),
        "{env}"
    );
    assert!(
        env.contains("export NODE_EXTRA_CA_CERTS='/etc/puddle/extra-cas.pem'"),
        "{env}"
    );
    assert!(!decrypts(&host, "acme", "github.com"));
    assert!(
        host.workspaces()
            .termination(&name("acme"))
            .unwrap()
            .set()
            .is_empty()
    );
    // No key anywhere in what the guest was sent.
    for (_, plan) in rig.guest.plans.lock().unwrap().iter() {
        assert!(!plan.windows(KEY_MARKER.len()).any(|w| w == KEY_MARKER));
        assert!(!String::from_utf8_lossy(plan).contains("PRIVATE"));
    }
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_for_any_host_applies_to_the_running_workspace_with_no_restart() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let ca_before = host
        .workspaces()
        .termination(&name("acme"))
        .unwrap()
        .ca()
        .certificate()
        .clone();
    let (creates, starts, stops) = (
        calls_of(&rig, "Create"),
        calls_of(&rig, "Start"),
        calls_of(&rig, "Stop"),
    );

    // A host the workspace has never used, on a host puddle's default list does not have.
    let gitlab = make_identity(&api, "Ada", "gitlab.com", &[]).await;
    attach(&api, "acme", gitlab).await;
    eventually("gitlab.com decrypted", || {
        decrypts(&host, "acme", "gitlab.com")
    })
    .await;
    // A second one, on Azure DevOps: both of its names.
    let azure = make_identity(&api, "Bob", "dev.azure.com", &["contoso"]).await;
    attach(&api, "acme", azure).await;
    eventually("azure decrypted", || {
        decrypts(&host, "acme", "contoso.visualstudio.com")
    })
    .await;
    assert!(decrypts(&host, "acme", "dev.azure.com"));
    // Nothing else is: a host nobody gave a credential is still spliced.
    assert!(!decrypts(&host, "acme", "github.com"));
    assert!(!decrypts(&host, "acme", "api.gitlab.com"));
    // The CA is the one the guest booted with, and the sandbox was not touched.
    let after = host.workspaces().termination(&name("acme")).unwrap();
    assert_eq!(after.ca().certificate(), &ca_before);
    assert_eq!(
        (
            calls_of(&rig, "Create"),
            calls_of(&rig, "Start"),
            calls_of(&rig, "Stop")
        ),
        (creates, starts, stops)
    );

    // Taking an identity off takes its hosts out of the set on the next connection.
    let gone = api
        .delete(&format!("/api/workspaces/acme/identities/{gitlab}"), None)
        .await;
    assert_eq!(gone.status, 200, "{}", gone.body);
    eventually("gitlab.com no longer decrypted", || {
        !decrypts(&host, "acme", "gitlab.com")
    })
    .await;
    assert!(decrypts(&host, "acme", "dev.azure.com"));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_commit_authors_in_the_running_guest_follow_the_identities() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let booted = rig.guest.boots();
    // No identity yet: no author file, and the workspace's git settings name nobody.
    let files = rig.guest.plan_files(booted - 1);
    assert!(!pem_of(&files, "/etc/puddle/gitconfig").contains("[user]"));

    // Work names acme on github.com; Personal covers the rest of it and is first in the list.
    let personal = make_identity(&api, "Personal", "github.com", &[]).await;
    let work = make_identity(&api, "Work", "github.com", &["Acme"]).await;
    attach(&api, "acme", personal).await;
    rig.guest.boots_reach(booted + 1).await;
    attach(&api, "acme", work).await;
    rig.guest.boots_reach(booted + 2).await;
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    let config = pem_of(&files, "/etc/puddle/gitconfig");
    // The fallback is the first identity's; the rest-of-host rule comes before the named owner's,
    // so git, which lets the last match win, gives acme's remotes to Work.
    assert!(config.contains("[user]\n\tname = \"Personal\""), "{config}");
    let personal_at = config.find("path = git-author-1.gitconfig").unwrap();
    let work_at = config.find("path = git-author-2.gitconfig").unwrap();
    assert!(personal_at < work_at, "{config}");
    assert!(config.contains("[aA][cC][mM][eE]"), "{config}");
    assert!(pem_of(&files, "/etc/puddle/git-author-2.gitconfig").contains("name = \"Work\""));
    // The guest's trust is what it booted with: the same CA in every run.
    let ca = host
        .workspaces()
        .termination(&name("acme"))
        .unwrap()
        .ca()
        .certificate()
        .clone();
    assert_eq!(pem_of(&files, "/etc/puddle/extra-cas.pem"), ca.pem());

    // A change that moves no author does not touch the guest again.
    let reply = api
        .request(
            "PUT",
            "/api/workspaces/acme/git/switches",
            Some(&json!({"only_push_listed": false}).to_string()),
            true,
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rig.guest.boots(), booted + 2);

    // Taking both off removes the authors again.
    for id in [personal, work] {
        api.delete(&format!("/api/workspaces/acme/identities/{id}"), None)
            .await;
    }
    rig.guest.boots_reach(booted + 4).await;
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    assert!(!pem_of(&files, "/etc/puddle/gitconfig").contains("[user]"));
    assert!(!files.contains_key("/etc/puddle/git-author-1.gitconfig"));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_workspace_has_no_ca_and_each_start_makes_a_new_one() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let first = host
        .workspaces()
        .termination(&name("acme"))
        .unwrap()
        .ca()
        .certificate()
        .clone();

    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert!(host.workspaces().termination(&name("acme")).is_none());
    // A change to a workspace that does not run reaches nothing now: its next start reads it.
    let identity = make_identity(&api, "Ada", "github.com", &[]).await;
    attach(&api, "acme", identity).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(host.workspaces().termination(&name("acme")).is_none());

    api.post("/api/workspaces/acme/start", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    let second = host.workspaces().termination(&name("acme")).unwrap();
    assert_ne!(second.ca().certificate(), &first);
    assert!(decrypts(&host, "acme", "github.com"));
    // The second boot got the second CA, and not the first.
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    assert_eq!(
        pem_of(&files, "/etc/puddle/extra-cas.pem"),
        second.ca().certificate().pem()
    );
    assert!(!pem_of(&files, "/etc/puddle/extra-cas.pem").contains(first.pem()));
    // The author came from the identity at the start, with no rewrite after it.
    assert!(pem_of(&files, "/etc/puddle/gitconfig").contains("name = \"Ada\""));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_file_in_the_data_folder_holds_a_key_or_the_ca_whether_the_workspace_runs_or_not() {
    fn files_under(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files_under(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let identity = make_identity(&api, "Ada", "github.com", &[]).await;
    attach(&api, "acme", identity).await;
    eventually("decrypted", || decrypts(&host, "acme", "github.com")).await;
    let ca = host
        .workspaces()
        .termination(&name("acme"))
        .unwrap()
        .ca()
        .certificate()
        .clone();
    let body = ca.pem().lines().nth(1).unwrap().to_owned();

    let check = |when: &str| {
        let mut files = Vec::new();
        files_under(&rig.dir.path().join("data"), &mut files);
        files_under(&rig.dir.path().join("runtime"), &mut files);
        assert!(!files.is_empty());
        for file in files {
            // A file the database or a save is replacing may be gone by now.
            let Ok(bytes) = std::fs::read(&file) else {
                continue;
            };
            assert!(
                !bytes.windows(KEY_MARKER.len()).any(|w| w == KEY_MARKER),
                "{when}: {} holds a key",
                file.display()
            );
            assert!(
                !bytes.windows(body.len()).any(|w| w == body.as_bytes()),
                "{when}: {} holds the CA",
                file.display()
            );
            assert!(
                !bytes
                    .windows(ca.der().len())
                    .any(|w| w == ca.der().as_ref()),
                "{when}: {} holds the CA",
                file.display()
            );
        }
    };
    check("running");
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    check("stopped");
    // A workspace still running at shutdown loses its CA with the host's routes.
    api.post(&format!("/api/workspaces/{}/start", "acme"), "")
        .await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert!(host.workspaces().termination(&name("acme")).is_some());
    host.shutdown().await;
    assert!(host.workspaces().termination(&name("acme")).is_none());
    check("after shutdown");
}

#[derive(Debug)]
struct MarkedInjector;

impl puddle_proxy::Injector for MarkedInjector {
    fn decide<'a>(
        &'a self,
        _: &'a puddle_proxy::InjectContext<'a>,
        _: &'a puddle_proxy::RequestView<'a>,
    ) -> futures_util::future::BoxFuture<'a, puddle_proxy::InjectDecision> {
        Box::pin(async { puddle_proxy::InjectDecision::PassThrough })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_start_gets_an_injector_built_for_its_workspace_from_the_hosts_store() {
    let rig = Rig::new();
    let built = Arc::new(Mutex::new(Vec::new()));
    let prepared = prepare(rig.config(), &FakePlatform::new(&rig.log)).unwrap();
    let mut options = HostOptions::default();
    let record = built.clone();
    options.injector = Some(Arc::new(
        move |inputs: &puddle_host::InjectorInputs, workspace: &WorkspaceName| {
            record
                .lock()
                .unwrap()
                .push((workspace.clone(), inputs.store.clone()));
            Arc::new(MarkedInjector)
        },
    ));
    let host = Host::start(prepared, &FakeFactory::new(&rig.runtime, &rig.log), options)
        .await
        .unwrap();
    // Nothing is made before a workspace starts.
    assert!(built.lock().unwrap().is_empty());
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    create(&api, &mut events, "beta").await;
    for workspace in ["acme", "beta"] {
        let termination = host.workspaces().termination(&name(workspace)).unwrap();
        assert!(
            format!("{termination:?}").contains("MarkedInjector"),
            "{termination:?}"
        );
    }
    let made = built.lock().unwrap().clone();
    let workspaces: Vec<&WorkspaceName> = made.iter().map(|(w, _)| w).collect();
    assert_eq!(workspaces, [&name("acme"), &name("beta")]);
    assert!(
        made.iter()
            .all(|(_, store)| Arc::ptr_eq(store, host.store()))
    );
    // A start in place makes a new one.
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    api.post("/api/workspaces/acme/start", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(built.lock().unwrap().len(), 3);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_that_fails_after_the_ca_was_made_leaves_no_ca_behind() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    // A create whose boot fails.
    rig.guest.fail_boot.store(true, Ordering::SeqCst);
    let reply = api.post("/api/workspaces", &new_workspace("acme")).await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert!(host.workspaces().termination(&name("acme")).is_none());

    // A start in place whose boot fails.
    rig.guest.fail_boot.store(false, Ordering::SeqCst);
    create(&api, &mut events, "beta").await;
    api.post("/api/workspaces/beta/stop", "").await;
    events.until(ended("beta"), Duration::from_secs(20)).await;
    rig.guest.fail_boot.store(true, Ordering::SeqCst);
    api.post("/api/workspaces/beta/start", "").await;
    let end = events.until(ended("beta"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert!(host.workspaces().termination(&name("beta")).is_none());
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_company_roots_go_into_the_clients_that_verify_decrypted_hosts() {
    // A host with company roots starts: the TLS client for decrypted hosts is built with them.
    let rig = Rig::new();
    let mut platform = FakePlatform::new(&rig.log);
    platform.roots = company_roots();
    let prepared = prepare(rig.config(), &platform).unwrap();
    let host = Host::start(
        prepared,
        &FakeFactory::new(&rig.runtime, &rig.log),
        HostOptions::default(),
    )
    .await
    .unwrap();
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    // The host's own TLS client took the company root: nothing is reported as left out.
    let report = api.get("/api/network-health").await.json();
    assert_eq!(report["roots"]["left_out_of_tls"], json!([]));
    // The guest got the company root and the CA in one extra-CAs file.
    let files = rig.guest.plan_files(0);
    let extra = pem_of(&files, "/etc/puddle/extra-cas.pem");
    assert_eq!(extra.matches("BEGIN CERTIFICATE").count(), 2, "{extra}");
    host.shutdown().await;
}

/// Opens the host's database next to it and runs `sql` (a row the store would never write).
fn damage_database(rig: &Rig, sql: &str) {
    let db = rusqlite::Connection::open(rig.dir.path().join("data").join("puddle.db")).unwrap();
    db.execute_batch(sql).unwrap();
}

const UNREADABLE_GIT_ROW: &str = "INSERT INTO workspace_repos \
    (workspace_id, host, owner, repo, pull, push, created_at) \
    VALUES ('{}', 'github.com', 'acme', 'not a repo', 1, 1, 0)";

#[tokio::test(flavor = "multi_thread")]
async fn git_settings_the_host_cannot_read_stop_a_start_and_change_nothing_while_running() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    create(&api, &mut events, "beta").await;
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;

    // acme's settings are damaged: its start says why and leaves no CA.
    damage_database(&rig, &UNREADABLE_GIT_ROW.replace("{}", "acme"));
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert!(
        end["detail"]
            .as_str()
            .unwrap()
            .contains("cannot read acme's Git settings"),
        "{end}"
    );
    assert!(host.workspaces().termination(&name("acme")).is_none());

    // beta runs; its settings are damaged after the start: what it decrypts stays as it was.
    let identity = make_identity(&api, "Ada", "github.com", &[]).await;
    attach(&api, "beta", identity).await;
    eventually("github.com decrypted", || {
        decrypts(&host, "beta", "github.com")
    })
    .await;
    damage_database(&rig, &UNREADABLE_GIT_ROW.replace("{}", "beta"));
    host.events().emit(Event::WorkspaceGitChanged {
        workspace: name("beta"),
    });
    // The next change is applied after the damaged one was looked at (events are handled in
    // order), and beta's set did not lose what it had.
    host.events().emit(Event::WorkspaceGitChanged {
        workspace: name("beta"),
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(decrypts(&host, "beta", "github.com"));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_image_the_boot_plan_cannot_take_fails_the_start_and_leaves_nothing_behind() {
    let rig = Rig::new();
    let odd = ImageRef::new("example.org/odd:1").unwrap();
    rig.runtime.add_image(
        &odd,
        ImageConfig {
            // A newline cannot be written into the guest's environment file.
            env: vec![("PATH".to_owned(), "/bin\n/usr/bin".to_owned())],
            ..ImageConfig::default()
        },
    );
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": "acme", "repo_url": REPO, "image": "example.org/odd:1"}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "failed", "{end}");
    assert!(host.workspaces().termination(&name("acme")).is_none());
    assert!(rig.runtime.list().await.unwrap().is_empty());
    assert!(rig.runtime.list_volumes().await.unwrap().is_empty());
    host.shutdown().await;
}

/// Makes the next run of the boot hook attach a new identity to `workspace`, as a user clicking
/// while the guest boots would.
fn attach_during_the_next_boot(rig: &Rig, host: &Host<FakeRuntime>, workspace: &str) {
    let store = host.store().clone();
    let workspace = name(workspace);
    *rig.guest.during_boot.lock().unwrap() = Some(Box::new(move || {
        let host = puddle_secrets::HostName::new("github.com").unwrap();
        let credential = puddle_store::CredentialBinding::new(
            &host,
            puddle_secrets::SourceSpec::Gh {
                host: host.clone(),
                account: puddle_secrets::AccountName::new("me").unwrap(),
            },
            puddle_store::Coverage::new(std::collections::BTreeSet::new(), true).unwrap(),
        )
        .unwrap();
        let identity = store
            .create_identity(puddle_store::IdentityDraft {
                label: "Ada".to_owned(),
                author: puddle_store::Author::new("Ada", "ada@example.org").unwrap(),
                credentials: vec![credential],
            })
            .unwrap();
        // The first identity becomes the default, which a new workspace gets at its create; attach
        // is idempotent for this test's purpose.
        let _ = store.attach_identity(&workspace, identity.id, None);
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_made_while_the_guest_boots_reaches_it_once_it_is_up() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    // No identity exists when the workspace is created, so its plan names no author.
    attach_during_the_next_boot(&rig, &host, "acme");
    create(&api, &mut events, "acme").await;

    // The set followed while the guest was booting, and once it was up the guest was brought in
    // line with a second run of the hook.
    assert!(decrypts(&host, "acme", "github.com"));
    rig.guest.boots_reach(2).await;
    let first = rig.guest.plan_files(0);
    assert!(!pem_of(&first, "/etc/puddle/gitconfig").contains("[user]"));
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    assert!(pem_of(&files, "/etc/puddle/gitconfig").contains("name = \"Ada\""));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_made_while_a_stopped_workspace_starts_again_reaches_it_once_it_is_up() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    api.post("/api/workspaces/acme/stop", "").await;
    events.until(ended("acme"), Duration::from_secs(20)).await;
    let booted = rig.guest.boots();

    attach_during_the_next_boot(&rig, &host, "acme");
    api.post("/api/workspaces/acme/start", "").await;
    let end = events.until(ended("acme"), Duration::from_secs(20)).await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(decrypts(&host, "acme", "github.com"));
    rig.guest.boots_reach(booted + 2).await;
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    assert!(pem_of(&files, "/etc/puddle/gitconfig").contains("name = \"Ada\""));
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_that_turn_unreadable_during_a_boot_do_not_fail_the_boot() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    let db = rig.dir.path().join("data").join("puddle.db");
    *rig.guest.during_boot.lock().unwrap() = Some(Box::new(move || {
        let db = rusqlite::Connection::open(db).unwrap();
        db.execute_batch(&UNREADABLE_GIT_ROW.replace("{}", "acme"))
            .unwrap();
    }));
    // The boot had what it needed; the workspace comes up with the settings it started with.
    create(&api, &mut events, "acme").await;
    assert!(host.workspaces().termination(&name("acme")).is_some());
    assert_eq!(rig.guest.boots(), 1);
    host.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guest_that_cannot_take_new_authors_keeps_the_old_ones_and_the_next_change_retries() {
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let booted = rig.guest.boots();
    let ada = make_identity(&api, "Ada", "github.com", &[]).await;
    let bob = make_identity(&api, "Bob", "gitlab.com", &[]).await;

    rig.guest.fail_boot.store(true, Ordering::SeqCst);
    attach(&api, "acme", ada).await;
    rig.guest.boots_reach(booted + 1).await;
    // What is decrypted followed anyway: only the guest's files could not be written.
    eventually("github.com decrypted", || {
        decrypts(&host, "acme", "github.com")
    })
    .await;

    rig.guest.fail_boot.store(false, Ordering::SeqCst);
    attach(&api, "acme", bob).await;
    rig.guest.boots_reach(booted + 2).await;
    let files = rig.guest.plan_files(rig.guest.boots() - 1);
    let config = pem_of(&files, "/etc/puddle/gitconfig");
    // Both identities are in the retry: the first change was never written.
    assert!(config.contains("name = \"Ada\""), "{config}");
    assert!(pem_of(&files, "/etc/puddle/git-author-1.gitconfig").contains("Bob"));
    host.shutdown().await;
}

#[tokio::test]
async fn missed_events_are_made_up_for_by_looking_at_every_running_workspace_again() {
    // One thread: the host's tasks cannot run while this test emits, so the follower falls
    // behind the event buffer.
    let rig = Rig::new();
    let host = rig.start().await;
    let api = api(&host);
    let mut events = api.events().await;
    create(&api, &mut events, "acme").await;
    let identity = make_identity(&api, "Ada", "github.com", &[]).await;
    let before = rig.guest.boots();

    let attached =
        host.store()
            .attach_identity(&name("acme"), puddle_store::IdentityId(identity), None);
    attached.unwrap();
    for _ in 0..4096 {
        host.events().emit(Event::RulesChanged {});
    }
    eventually("the set follows", || decrypts(&host, "acme", "github.com")).await;
    rig.guest.boots_reach(before + 1).await;
    host.shutdown().await;
}
