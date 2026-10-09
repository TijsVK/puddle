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
use puddle_secrets::{AccountName, HostName, MemoryStore, SourceSpec};
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
    /// Where the host keeps the values of secrets: never the machine's own credential store.
    secrets: std::sync::Arc<MemoryStore>,
}

/// Starts a host over its own store and workspace folder, named by `tag` (a few characters), so
/// what one test creates (an identity, a rule, a workspace) is never in another's host. Tests of
/// one binary share the run's prefix, and a host over a shared folder reads the identities an
/// earlier test left.
async fn start_vm_host(tag: &str) -> VmHost {
    start_vm_host_with(tag, HostOptions::default()).await
}

async fn start_vm_host_with(tag: &str, options: HostOptions) -> VmHost {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings");
    let pair = settings.prepare().expect("msb runtime pair");
    let root = settings.scratch_home(tag);
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
    let secrets = std::sync::Arc::new(MemoryStore::new());
    let mut options = options;
    options.secret_store = Some(secrets.clone());
    let host = Host::start(prepared, &factory, options)
        .await
        .expect("the host starts");
    assert_eq!(host.steps(), START_STEPS);
    let runtime = factory.opened.lock().unwrap().clone().unwrap();
    VmHost {
        host,
        runtime,
        settings,
        secrets,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_creates_a_workspace_with_progress_and_stops_cleanly() {
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host("life").await;

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

/// Options for a test of what the host decrypts, trusts and writes: its identities name a `gh`
/// account that is not signed in on the machine that runs the test, and the Git injector (the
/// default) answers a request on a host such an identity covers with a `502` naming the missing
/// sign-in. This injector adds nothing, so the clone of a public repository goes through the
/// decrypting proxy with no credential. What the Git injector does with a credential is tested
/// in `puddle-inject` and the proxy's terminate tests.
fn options_without_injection() -> HostOptions {
    let mut options = HostOptions::default();
    options.injector = Some(std::sync::Arc::new(|_, _| {
        std::sync::Arc::new(puddle_proxy::NoInjection)
    }));
    options
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
        ..
    } = start_vm_host_with("ca", options_without_injection()).await;
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

/// A public host that serves HTTP/3 (it answers `alt-svc: h3=":443"`) next to HTTP/2 over TCP.
const H3_HOST: &str = "example.com";

/// Sends one datagram to port 443 of four addresses from bash (a connected socket) and of two
/// from perl (an unconnected `sendto`), each timed inside the guest: one line per attempt,
/// `udp <tool> <target> sent|failed <ms> <message>`.
const UDP_443_SCRIPT: &str = r#"
for target in 1.1.1.1 142.250.74.46 198.18.0.5 10.0.0.1; do
  start=${EPOCHREALTIME/[.,]/}
  if err=$({ echo x > /dev/udp/$target/443; } 2>&1); then result=sent; else result=failed; fi
  end=${EPOCHREALTIME/[.,]/}
  echo "udp bash $target $result $(( (end - start) / 1000 )) ${err//$'\n'/ | }"
done
perl -MSocket -MTime::HiRes=time -e '
  socket(my $s, PF_INET, SOCK_DGRAM, 0) or die "socket: $!";
  for my $ip ("1.1.1.1", "8.8.8.8") {
    my $t = time;
    my $sent = send($s, "x", 0, sockaddr_in(443, inet_aton($ip)));
    printf "udp perl %s %s %d %s\n", $ip, ($sent ? "sent" : "failed"), (time - $t) * 1000, $!;
  }' </dev/null
"#;

/// A client that insists on HTTP/3 and ignores the proxy settings: its QUIC attempt must end at
/// once with an error, not wait for a timeout. 192.0.2.1 is reserved for documentation, so
/// nothing here depends on a name or on the internet.
const DIRECT_HTTP3_SCRIPT: &str = r#"
start=${EPOCHREALTIME/[.,]/}
curl --noproxy '*' --http3-only --resolve example.com:443:192.0.2.1 -sS -o /dev/null \
  --max-time 20 https://example.com/ </dev/null 2>&1
echo "exit=$?"
end=${EPOCHREALTIME/[.,]/}
echo "direct-http3 $(( (end - start) / 1000 )) ms"
"#;

/// A workspace cannot send UDP, so a client that tries QUIC fails at once and uses TCP: a UDP
/// send to port 443 fails in under 100 ms (in the guest, whatever the tool), and `curl --http3`
/// against a host that serves HTTP/3 still gets its answer, over HTTP/2 through the proxy.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_refuses_udp_443_at_once_and_curl_http3_falls_back_to_tcp() {
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host("quic").await;
    let name = format!("{}-quic", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in [REPO_HOST, H3_HOST] {
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
    assert_eq!(end["step"], "done", "{end}");

    // The image's curl speaks HTTP/3, so the fallback below is curl's own.
    let version = guest(&runtime, &sandbox, "curl --version").await;
    assert!(
        version.contains("HTTP3"),
        "no HTTP/3 in the image's curl: {version}"
    );

    // UDP to port 443 fails in under 100 ms, from a connected and from an unconnected socket.
    let udp = guest(
        &runtime,
        &sandbox,
        &format!("bash -s <<'PUDDLE_EOF'\n{UDP_443_SCRIPT}\nPUDDLE_EOF"),
    )
    .await;
    eprintln!("{udp}");
    let attempts: Vec<Vec<&str>> = udp
        .lines()
        .filter(|line| line.starts_with("udp "))
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(attempts.len(), 6, "{udp}");
    for attempt in &attempts {
        let [_, tool, target, result, millis, ..] = attempt.as_slice() else {
            panic!("unreadable line: {attempt:?}");
        };
        assert_eq!(*result, "failed", "{tool} to {target} was sent: {udp}");
        let millis: u64 = millis.parse().unwrap();
        assert!(millis < 100, "{tool} to {target} took {millis} ms: {udp}");
    }

    // curl asked for HTTP/3 gets its answer over TCP: the workspace's proxy settings make it
    // tunnel through `CONNECT`, and curl does not use HTTP/3 over an HTTP proxy.
    let answer = guest(
        &runtime,
        &sandbox,
        &format!(
            "curl --http3 -sS -v -o /dev/null --max-time 60 \
             -w 'answer http_version=%{{http_version}} http_code=%{{http_code}}\\n' \
             https://{H3_HOST}/ 2>&1 | grep -i -E 'HTTP/3 is not|alt-svc|^answer'"
        ),
    )
    .await;
    eprintln!("{answer}");
    assert!(
        answer.contains("answer http_version=2 http_code=200"),
        "{answer}"
    );
    // The server does offer HTTP/3 (the connection is spliced, so its header reaches the guest):
    // the answer came over TCP although HTTP/3 was on offer.
    assert!(
        answer.to_ascii_lowercase().contains("alt-svc: h3="),
        "{answer}"
    );

    // The tunnel is a connection the host saw and allowed.
    let mut recorded = false;
    for _ in 0..50 {
        let lines = host.store().audit_lines(0, 10_000).unwrap();
        recorded = lines.iter().any(|(_, line)| {
            let record: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
            record["type"] == "connection"
                && record["host"] == H3_HOST
                && record["port"] == 443
                && record["decision"] == "allow"
        });
        if recorded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recorded,
        "no allowed connection to {H3_HOST}:443 in the audit"
    );

    // A client that tries QUIC and ignores the proxy fails at once instead of waiting.
    let direct = guest(
        &runtime,
        &sandbox,
        &format!("bash -s <<'PUDDLE_EOF'\n{DIRECT_HTTP3_SCRIPT}\nPUDDLE_EOF"),
    )
    .await;
    eprintln!("{direct}");
    assert!(direct.contains("exit=7"), "{direct}");
    let millis: u64 = direct
        .lines()
        .find_map(|line| line.strip_prefix("direct-http3 "))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("the timing line");
    assert!(millis < 1000, "the QUIC attempt took {millis} ms: {direct}");

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// The values the real secrets hold in the credential store. Written in the guest scripts as two
/// quoted halves, so the script's own text is not what a search for the value finds.
const SECRET_A: &str = "puddle-vm-real-a-7f3c9d21e0b44a58";
const SECRET_B: &str = "puddle-vm-real-b-51c0aa9e3d7742f1";
const SECRET_C: &str = "puddle-vm-real-c-0be4d86a92c7135e";

/// `"first""second"`: the shell joins them, the script text never holds the value.
fn split(value: &str) -> String {
    let (head, tail) = value.split_at(value.len() / 2);
    format!("\"{head}\"\"{tail}\"")
}

/// The stand-in the store keeps for the secret `var` of the workspace.
fn stand_in_of(host: &Host<MsbRuntime>, workspace: &WorkspaceName, var: &str) -> String {
    let found = host
        .store()
        .env_for_start(workspace, &mut |_| Err("already made".into()))
        .unwrap()
        .into_iter()
        .find(|v| v.name.as_str() == var)
        .and_then(|v| match v.value {
            puddle_store::StartValue::Secret { stand_in, .. } => Some(stand_in),
            puddle_store::StartValue::Plain(_) => None,
        });
    assert!(found.is_some(), "no secret {var}");
    found.unwrap()
}

/// Waits for a connection record of `workspace` to `host` that `wanted` accepts (a record is
/// written when the connection ends, a moment after the tool is done) and returns it.
async fn record_where(
    api: &Api,
    workspace: &str,
    host: &str,
    wanted: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    let mut seen = Vec::new();
    for _ in 0..60 {
        seen = connections(api, workspace, host).await;
        if let Some(found) = seen.iter().find(|r| wanted(r)) {
            return found.clone();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    unreachable!("no matching connection record for {host}: {seen:#?}")
}

/// The connection records of `workspace` to `host`, newest first.
async fn connections(api: &Api, workspace: &str, host: &str) -> Vec<serde_json::Value> {
    let page = api
        .get(&format!(
            "/api/audit?workspace={workspace}&type=connection&host_contains={host}&limit=50"
        ))
        .await
        .json();
    page.get("entries")
        .and_then(serde_json::Value::as_array)
        .unwrap()
        .iter()
        .filter_map(|e| e.get("record").cloned())
        .filter(|r| r.get("host").is_some_and(|h| h == host))
        .collect()
}

/// A workspace's secrets: the guest holds a stand-in under the secret's name and never the real
/// value (not in its environment, not in a file anywhere, not in a process's environment); the
/// proxy swaps the real value in toward the secret's own hosts only; a stand-in toward another
/// decrypted host is flagged; and a secret added to the running workspace makes its host
/// decrypted from the next connection with no restart.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_gives_the_guest_stand_ins_only_and_swaps_them_for_a_secrets_own_hosts() {
    let VmHost {
        host,
        runtime,
        settings,
        secrets,
    } = start_vm_host("env").await;
    let name = format!("{}-env", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in ["github.com", "example.com", "example.org", "example.net"] {
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
    let api = Api::new(host.url(), host.token());
    let put = |path: &str, body: serde_json::Value| {
        let (api, path) = (&api, path.to_owned());
        async move {
            let reply = api.put(&path, &body.to_string()).await;
            assert_eq!(reply.status, 200, "{path}: {}", reply.body);
        }
    };
    put(
        "/api/env/PROBE_PLAIN",
        json!({"kind": "plain", "value": "plain value 'quoted' $HOME"}),
    )
    .await;
    put(
        "/api/env/PROBE_A",
        json!({"kind": "secret", "value": SECRET_A, "hosts": ["example.com"]}),
    )
    .await;
    put(
        "/api/env/PROBE_B",
        json!({"kind": "secret", "value": SECRET_B, "hosts": ["example.org"]}),
    )
    .await;
    assert_eq!(secrets.ids().len(), 2);

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
    assert_eq!(end["step"], "done", "{end}");

    // The guest has the plain variable as it was written and a stand-in under each secret's name,
    // for a process started directly and for a login shell.
    let stand_a = stand_in_of(&host, &sandbox, "PROBE_A");
    let stand_b = stand_in_of(&host, &sandbox, "PROBE_B");
    assert!(stand_a.starts_with("puddle-secret-PROBE_A-"), "{stand_a}");
    assert_eq!(
        guest(&runtime, &sandbox, "printenv PROBE_PLAIN")
            .await
            .trim(),
        "plain value 'quoted' $HOME"
    );
    assert_eq!(
        guest(&runtime, &sandbox, "printenv PROBE_A").await.trim(),
        stand_a
    );
    assert_eq!(
        guest(&runtime, &sandbox, "printenv PROBE_B").await.trim(),
        stand_b
    );
    assert_eq!(
        guest(&runtime, &sandbox, "sh -lc 'printenv PROBE_A'")
            .await
            .trim(),
        stand_a
    );

    // The real values are nowhere in the guest: no file on the disk, no running process's
    // environment.
    let (a, b) = (split(SECRET_A), split(SECRET_B));
    let search = guest(
        &runtime,
        &sandbox,
        &format!(
            "files=$(grep -rla -e {a} -e {b} / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev 2>/dev/null); \
             live=$(cat /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n' | grep -c -e {a} -e {b}); \
             echo \"files=[$files] processes=[$live]\""
        ),
    )
    .await;
    assert_eq!(search.trim(), "files=[] processes=[0]", "{search}");

    // Only the hosts the secrets name are decrypted; the rest keep their real certificate.
    let ca_name = format!("puddle CA for {name}");
    for site in ["example.com", "example.org"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(issuer.contains(&ca_name), "{site}: {issuer}");
    }
    let net = guest(&runtime, &sandbox, &issuer_script("example.net")).await;
    assert!(!net.contains("puddle"), "{net}");

    // A request toward a secret's own host with its stand-in: the proxy swaps the real value in
    // (the record says a credential was added, by name), and the guest still sees only the stand-in.
    let curl = |site: &str, header: &str, value: &str| {
        format!(
            "curl -s -o /dev/null -w '%{{http_code}}' --max-time 60 -H \"{header}: {value}\" https://{site}/"
        )
    };
    let code = guest(
        &runtime,
        &sandbox,
        &curl("example.com", "Authorization", "Bearer $PROBE_A"),
    )
    .await;
    assert!(
        code.trim().starts_with('2') || code.trim().starts_with('4'),
        "{code}"
    );
    let swapped = record_where(&api, &name, "example.com", |r| r["injected"] == true).await;
    assert_eq!(swapped["binding_id"], "stand-in:secret:PROBE_A");
    assert_eq!(swapped["placeholder_unbound"], false);

    // The same stand-in toward another decrypted host goes out unchanged and is flagged.
    guest(
        &runtime,
        &sandbox,
        &curl("example.org", "X-Probe", "$PROBE_A"),
    )
    .await;
    let flagged = record_where(&api, &name, "example.org", |r| {
        r["placeholder_unbound"] == true
    })
    .await;
    assert_eq!(flagged["injected"], false);

    // A secret added to the running workspace: its host is decrypted from the next connection,
    // with the same CA and no restart.
    let ca_before = host
        .workspaces()
        .termination(&sandbox)
        .unwrap()
        .ca()
        .certificate()
        .clone();
    put(
        "/api/env/PROBE_C",
        json!({"kind": "secret", "value": SECRET_C, "hosts": ["example.net"]}),
    )
    .await;
    let mut decrypted = false;
    for _ in 0..100 {
        let now = host.workspaces().termination(&sandbox).unwrap();
        if now
            .set()
            .contains(&puddle_types::Host::parse_normalised("example.net").unwrap())
        {
            decrypted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(decrypted, "example.net never joined the decrypt set");
    assert_eq!(
        host.workspaces()
            .termination(&sandbox)
            .unwrap()
            .ca()
            .certificate(),
        &ca_before
    );
    let net = guest(&runtime, &sandbox, &issuer_script("example.net")).await;
    assert!(net.contains(&ca_name), "{net}");
    // Its stand-in is not in the running guest's environment (that is read at the next start),
    // but the proxy already knows it: a request that carries it is swapped.
    let stand_c = stand_in_of(&host, &sandbox, "PROBE_C");
    guest(
        &runtime,
        &sandbox,
        &curl("example.net", "X-Probe", &stand_c),
    )
    .await;
    let swapped = record_where(&api, &name, "example.net", |r| r["injected"] == true).await;
    assert_eq!(swapped["binding_id"], "stand-in:secret:PROBE_C");

    // Removing it takes the host out again, and its value out of the credential store.
    assert_eq!(api.delete("/api/env/PROBE_C", None).await.status, 204);
    let mut spliced = false;
    for _ in 0..100 {
        let now = host.workspaces().termination(&sandbox).unwrap();
        if !now
            .set()
            .contains(&puddle_types::Host::parse_normalised("example.net").unwrap())
        {
            spliced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(spliced, "example.net stayed in the decrypt set");
    assert_eq!(secrets.ids().len(), 2);
    let net = guest(&runtime, &sandbox, &issuer_script("example.net")).await;
    assert!(!net.contains("puddle"), "{net}");

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}
