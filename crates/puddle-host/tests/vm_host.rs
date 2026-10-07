// SPDX-License-Identifier: GPL-3.0-or-later
//! The whole host on a real microVM (K on Linux KVM, W on Windows WHP): start the host with the
//! msb runtime, create a workspace through the API, watch its `workspace_progress` events, run
//! a command in it, stop it through the API, and shut the host down: the sandbox must end
//! `Stopped`, not `Crashed`.
//!
//! The clone goes out through the host's own egress proxy (guest git, guest agent, the sandbox's
//! route, the rules engine, the internet), so this also shows that a sandbox booted by the host
//! reaches only what a rule allows.
#![expect(
    clippy::unwrap_used,
    reason = "VM test: a failed step fails the test; measurements go to stderr"
)]

mod support;

use std::time::Duration;

use puddle_certs::CorporateRoots;
use puddle_compute::{ExecRequest, Runtime, Sandbox};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_host::{
    GuestSettings, Host, HostConfig, HostError, HostOptions, HostPaths, Platform, RuntimeFactory,
    RuntimeInputs, SHUTDOWN_STEPS, START_STEPS, prepare,
};
use puddle_runtime::{RuntimeLayout, RuntimeVersion};
use puddle_store::{Actor, Effect, NewRule, Pattern, Scope};
use puddle_types::{SandboxName, SandboxStatus};
use puddle_upstream::Mode;
use puddle_vm_tests::Settings;
use serde_json::json;
use support::{Api, ended};

/// A small public repository on a host the test allows.
const REPO_HOST: &str = "github.com";
const REPO: &str = "https://github.com/octocat/Hello-World.git";

/// The harness has set the environment and checked the runtime pair already.
struct HarnessPlatform;

impl Platform for HarnessPlatform {
    fn pin_environment(&self, _: &RuntimeLayout) -> Result<(), HostError> {
        Ok(())
    }

    fn check_runtime(&self, _: &RuntimeLayout, _: &RuntimeVersion) -> Result<(), HostError> {
        Ok(())
    }

    fn corporate_roots(&self) -> Result<CorporateRoots, HostError> {
        Ok(CorporateRoots::default())
    }
}

/// Opens msb over the harness's private home and runtime pair.
struct HarnessFactory {
    settings: Settings,
    msb: std::path::PathBuf,
    libkrunfw: std::path::PathBuf,
    opened: std::sync::Mutex<Option<MsbRuntime>>,
}

impl RuntimeFactory for HarnessFactory {
    type Runtime = MsbRuntime;

    async fn open(&self, inputs: RuntimeInputs<'_>) -> Result<MsbRuntime, HostError> {
        let config = MsbConfig::new(
            self.settings.home(),
            &self.msb,
            &self.libkrunfw,
            inputs.guest_share,
        )
        .with_registry_proxy(inputs.pull_proxy.expose())
        .with_registry_roots(inputs.registry_roots)
        .with_runtime_log_level(self.settings.msb_log_level.clone())
        .with_keep_logs_dir(self.settings.kept_logs());
        let runtime = MsbRuntime::open(config).await?;
        *self.opened.lock().unwrap() = Some(runtime.clone());
        Ok(runtime)
    }
}

#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_creates_a_workspace_with_progress_and_stops_cleanly() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings");
    let pair = settings.prepare().expect("msb runtime pair");
    let root = settings.scratch_home("host");
    std::fs::create_dir_all(&root).unwrap();
    let agent = std::path::PathBuf::from(
        std::env::var_os("PUDDLE_AGENT_BIN")
            .expect("PUDDLE_AGENT_BIN: the static puddle-agent (ci/build-agent.sh)"),
    );
    let layout =
        RuntimeLayout::new(pair.msb.parent().unwrap().to_path_buf(), settings.home()).unwrap();
    let mut config = HostConfig::new(HostPaths::new(&root), layout, GuestSettings::new(agent));
    config.upstream.discovery.mode = Mode::Direct;
    config.runtime_log_level = settings.msb_log_level.clone();
    let factory = HarnessFactory {
        settings: settings.clone(),
        msb: pair.msb.clone(),
        libkrunfw: pair.libkrunfw.clone(),
        opened: std::sync::Mutex::new(None),
    };
    let prepared = prepare(config, &HarnessPlatform).unwrap();
    let host = Host::start(prepared, &factory, HostOptions::default())
        .await
        .expect("the host starts");
    assert_eq!(host.steps(), START_STEPS);
    let runtime = factory.opened.lock().unwrap().clone().unwrap();

    // The workspace's sandbox may reach the repository host, and nothing else.
    let name = format!("{}-host", settings.prefix.as_str());
    let sandbox = SandboxName::new(&name).unwrap();
    host.store()
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sandbox.clone()),
            pattern: Pattern::parse(REPO_HOST).unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();

    let api = Api::new(host.url(), host.token());
    let mut events = api.events().await;
    let started = std::time::Instant::now();
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repo_url": REPO, "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    eprintln!("create took {:?}", started.elapsed());
    assert_eq!(
        events.steps(&name),
        [
            "preparing_volume",
            "pulling_image",
            "starting",
            "syncing",
            "cloning",
            "done"
        ]
    );
    let workspace = api.get(&format!("/api/workspaces/{name}")).await.json();
    assert_eq!(workspace["status"], "running", "{workspace}");

    // The clone is on the volume, in the guest.
    let handle = runtime.get(&sandbox).await.unwrap();
    let out = handle
        .exec(
            ExecRequest::sh(format!(
                "git -C /workspaces/{name}/Hello-World log --oneline | head -1"
            ))
            .as_user("root")
            .with_timeout(Duration::from_secs(60)),
        )
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}{}",
        out.stdout_text(),
        out.stderr_text()
    );
    assert_ne!(out.stdout_text().trim(), "");

    // Stop through the API: trimmed, then stopped.
    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    assert_eq!(
        api.get(&format!("/api/workspaces/{name}")).await.json()["status"],
        "stopped"
    );
    let record = runtime
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap();
    assert_eq!(record.status, SandboxStatus::Stopped);

    // Start again, then shut the host down with the workspace running: the shutdown trims and
    // stops it, and msb records it Stopped, not Crashed.
    api.post(&format!("/api/workspaces/{name}/start"), "").await;
    let end = events
        .until(ended(name_static), Duration::from_secs(300))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert_eq!(down.steps, SHUTDOWN_STEPS);
    assert!(down.sandboxes.all_stopped(), "{down:?}");
    let record = runtime
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.name == name)
        .unwrap();
    assert_eq!(record.status, SandboxStatus::Stopped);
}
