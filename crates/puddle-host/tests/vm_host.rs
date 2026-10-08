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
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "VM test: a failed step fails the test; measurements go to stderr"
)]

mod support;

use std::collections::BTreeSet;
use std::time::Duration;

use puddle_certs::CorporateRoots;
use puddle_compute::{ExecRequest, Runtime, Sandbox};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_host::{
    GuestSettings, Host, HostConfig, HostError, HostOptions, HostPaths, Platform, RuntimeFactory,
    RuntimeInputs, SHUTDOWN_STEPS, START_STEPS, prepare,
};
use puddle_runtime::{RuntimeLayout, RuntimeVersion};
use puddle_secrets::{AccountName, HostName, SourceSpec};
use puddle_store::{
    Actor, Author, Coverage, CredentialBinding, Effect, IdentityDraft, NewRule, Pattern, Scope,
};
use puddle_types::{WorkspaceName, WorkspaceStatus};
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

/// A host on a real msb runtime in the test's own scratch home.
struct VmHost {
    host: Host<MsbRuntime>,
    runtime: MsbRuntime,
    settings: Settings,
}

async fn start_vm_host() -> VmHost {
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
    VmHost {
        host,
        runtime,
        settings,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_creates_a_workspace_with_progress_and_stops_cleanly() {
    let VmHost {
        host,
        runtime,
        settings,
    } = start_vm_host().await;

    // The workspace's sandbox may reach the repository host, and nothing else.
    let name = format!("{}-host", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    host.store()
        .add_rule(&NewRule {
            scope: Scope::Workspace(sandbox.clone()),
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
    let handle = runtime.get(&sandbox.sandbox_name()).await.unwrap();
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
    assert_eq!(record.status, WorkspaceStatus::Stopped);

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
    assert_eq!(record.status, WorkspaceStatus::Stopped);
}

/// Runs `script` as root in the guest and returns what it printed; fails the test if it fails.
async fn guest(runtime: &MsbRuntime, sandbox: &WorkspaceName, script: &str) -> String {
    let handle = runtime.get(&sandbox.sandbox_name()).await.unwrap();
    let out = handle
        .exec(
            ExecRequest::sh(script)
                .as_user("root")
                .with_timeout(Duration::from_secs(120)),
        )
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{script}\n{}{}",
        out.stdout_text(),
        out.stderr_text()
    );
    format!("{}{}", out.stdout_text(), out.stderr_text())
}

/// The issuer curl saw on `https://<host>/`, which also proves the connection worked.
fn issuer_script(host: &str) -> String {
    format!("curl -sv -o /dev/null --max-time 60 https://{host}/ 2>&1 | grep -i 'issuer:'")
}

fn identity(label: &str, host: &str) -> IdentityDraft {
    let name = HostName::new(host).unwrap();
    IdentityDraft {
        label: label.to_owned(),
        author: Author::new(label, &format!("{}@example.org", label.to_lowercase())).unwrap(),
        credentials: vec![
            CredentialBinding::new(
                &name,
                SourceSpec::Gh {
                    host: name.clone(),
                    account: AccountName::new("nobody").unwrap(),
                },
                Coverage::new(BTreeSet::new(), true).unwrap(),
            )
            .unwrap(),
        ],
    }
}

/// The guest trusts the workspace's CA from its first boot; only the hosts an identity names are
/// decrypted (a clone through one of them works); an identity attached to the running workspace
/// takes effect on the next connection with no restart; the author of a commit follows the
/// remote, also after a change in the running guest; and no key is in the guest.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_decrypts_only_what_an_identity_names_and_the_guest_trusts_the_ca() {
    let VmHost {
        host,
        runtime,
        settings,
    } = start_vm_host().await;
    let name = format!("{}-ca", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in ["github.com", "gitlab.com", "example.com"] {
        host.store()
            .add_rule(&NewRule {
                scope: Scope::Workspace(sandbox.clone()),
                pattern: Pattern::parse(site).unwrap(),
                effect: Effect::Allow,
                expires_at: None,
                created_by: Actor::Cli,
            })
            .unwrap();
    }
    // The first identity is the default: the new workspace gets it, and decrypts github.com.
    let work = host
        .store()
        .create_identity(identity("Work", REPO_HOST))
        .unwrap();
    let api = Api::new(host.url(), host.token());
    let mut events = api.events().await;
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repo_url": REPO, "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    // The clone went through puddle's own certificate for github.com: git trusted it.
    assert_eq!(end["step"], "done", "{end}");
    let termination = host
        .workspaces()
        .termination(&sandbox)
        .expect("a CA while it runs");
    let ca_name = format!("puddle CA for {name}");

    // github.com is decrypted and the guest trusts its certificate; example.com is spliced and
    // shows its real issuer; gitlab.com has no identity yet, so it is spliced too.
    let github = guest(&runtime, &sandbox, &issuer_script("github.com")).await;
    assert!(github.contains(&ca_name), "{github}");
    for site in ["example.com", "gitlab.com"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(!issuer.contains("puddle"), "{site}: {issuer}");
    }

    // The guest holds the CA certificate and no key anywhere puddle writes.
    let files = guest(
        &runtime,
        &sandbox,
        "ls /usr/local/share/ca-certificates/puddle /etc/puddle; \
         grep -rl 'PRIVATE KEY' /etc/puddle /usr/local/share/ca-certificates /run/puddle /var/lib/puddle || true",
    )
    .await;
    assert!(files.contains("puddle-ca-1.crt"), "{files}");
    assert!(!files.contains("PRIVATE"), "{files}");
    // One CA in the extra CAs file: the one of this start.
    let extra = guest(
        &runtime,
        &sandbox,
        "grep -c 'BEGIN CERTIFICATE' /etc/puddle/extra-cas.pem",
    )
    .await;
    assert_eq!(extra.trim(), "1");

    // The author of a commit is the identity's, by remote.
    let email = |remote: &str| {
        format!(
            "rm -rf /tmp/author && git init -q /tmp/author && git -C /tmp/author remote add origin {remote} \
             && git -C /tmp/author config user.email"
        )
    };
    assert_eq!(
        guest(
            &runtime,
            &sandbox,
            &email("https://github.com/octocat/Hello-World")
        )
        .await
        .trim(),
        "work@example.org"
    );

    // A second identity attached to the running workspace: gitlab.com is decrypted on the next
    // connection with the CA the guest already had, and its remotes get its author.
    let lab = host
        .store()
        .create_identity(identity("Lab", "gitlab.com"))
        .unwrap();
    let ca_before = termination.ca().certificate().clone();
    host.store()
        .attach_identity(&sandbox, lab.id, None)
        .unwrap();
    let mut decrypted = false;
    for _ in 0..100 {
        let now = host.workspaces().termination(&sandbox).unwrap();
        if now
            .set()
            .contains(&puddle_types::Host::parse_normalised("gitlab.com").unwrap())
        {
            decrypted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(decrypted, "gitlab.com never joined the decrypt set");
    assert_eq!(
        host.workspaces()
            .termination(&sandbox)
            .unwrap()
            .ca()
            .certificate(),
        &ca_before
    );
    let gitlab = guest(&runtime, &sandbox, &issuer_script("gitlab.com")).await;
    assert!(gitlab.contains(&ca_name), "{gitlab}");
    let mut author = String::new();
    for _ in 0..60 {
        author = guest(
            &runtime,
            &sandbox,
            &email("https://gitlab.com/gitlab-org/gitlab"),
        )
        .await;
        if author.trim() == "lab@example.org" {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(author.trim(), "lab@example.org");
    // Work's remotes keep Work's author; example.com is still spliced.
    assert_eq!(
        guest(
            &runtime,
            &sandbox,
            &email("https://github.com/octocat/Hello-World")
        )
        .await
        .trim(),
        "work@example.org"
    );
    let issuer = guest(&runtime, &sandbox, &issuer_script("example.com")).await;
    assert!(!issuer.contains("puddle"), "{issuer}");
    let _ = work;

    // Stopping drops the CA: nothing is decrypted for a stopped workspace.
    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(host.workspaces().termination(&sandbox).is_none());
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}
