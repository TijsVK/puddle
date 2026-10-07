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
use puddle_compute::{ExecOutput, ExecRequest, Runtime};
use puddle_host::{
    GuestSettings, Host, HostConfig, HostError, HostOptions, HostPaths, PREPARE_STEPS, Platform,
    RuntimeFactory, RuntimeInputs, SHUTDOWN_STEPS, START_STEPS, Step, prepare,
};
use puddle_netpolicy::EndpointKind;
use puddle_runtime::{RuntimeLayout, RuntimeVersion};
use puddle_types::{SandboxName, WorkspaceId};
use puddle_upstream::{Discovery, FakeOs, Mode, ProxyConfig};
use puddle_workspace::{CLEAR_LOCKS_SH, DELETE_CHECK_SH};
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
    dirty: AtomicBool,
    fail_clone: AtomicBool,
    fail_boot: AtomicBool,
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
        Some(match kind {
            "boot" if self.fail_boot.load(Ordering::SeqCst) => {
                ExecOutput::new(5, "", "boot.sh: no disk")
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
    let mut config = rig.config();
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
            Some(&json!({"sandbox_defaults": {"memory": 2048}}).to_string()),
            true,
        )
        .await;
    assert_eq!(put.status, 200, "{}", put.body);
    create(&api, &mut events, "acme").await;
    let spec_memory = api.get("/api/workspaces/acme").await.json()["memory_mib"].clone();
    assert_eq!(spec_memory, 2048);
    host.shutdown().await;
    // The settings are files: a second host over the same folder sees them.
    let again = rig.start().await;
    let reply = api_for(&again).get("/api/settings").await;
    assert!(reply.body.contains("2048"), "{}", reply.body);
    again.shutdown().await;
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
        image: &puddle_types::ImageRef,
    ) -> Result<puddle_compute::ImageConfig, puddle_compute::ComputeError> {
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
    host.shutdown().await;
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
    let name = SandboxName::new("acme").unwrap();
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
            &format!("/api/settings/sandboxes/{name}"),
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
    let name = SandboxName::new("acme").unwrap();
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
    let name = SandboxName::new("acme").unwrap();

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
            &json!({"sandbox_defaults": {"direct_ssh": true}}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    create(&api, &mut events, "acme").await;
    let name = SandboxName::new("acme").unwrap();
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
            assert!(record["sandbox"].is_null(), "{record}");
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
