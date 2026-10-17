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
mod vm_support;

use std::collections::BTreeSet;
use std::time::Duration;

use puddle_compute::{ExecRequest, Runtime, Sandbox};
use puddle_compute_msb::MsbRuntime;
use puddle_host::{Host, HostOptions, SHUTDOWN_STEPS, prepare};
use puddle_secrets::{AccountName, HostName, SourceSpec};
use puddle_store::{
    Actor, Author, Coverage, CredentialBinding, Effect, IdentityDraft, NewRule, Pattern, Scope,
};
use puddle_types::{WorkspaceName, WorkspaceStatus};
use puddle_vm_tests::{RuntimePair, Settings};
use serde_json::json;
use support::{Api, TestDevCert, ended, hermetic_options};
#[cfg(not(windows))]
use vm_support::start_vm_host_config;
use vm_support::{
    HarnessPlatform, VmHost, guest, guest_within, harness_config, kill_vm, start_vm_host,
    start_vm_host_with,
};

/// A small public repository on a host the test allows.
const REPO_HOST: &str = "github.com";
const REPO: &str = "https://github.com/octocat/Hello-World.git";

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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
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

/// A second small public repository on the same host.
const SECOND_REPO: &str = "https://github.com/octocat/Spoon-Knife.git";
/// A host the rules allow that resolves nowhere, so a clone from it fails like an unreachable
/// server's.
const UNREACHABLE_HOST: &str = "unreachable.invalid";

/// A create with three repositories, the middle one unreachable: the other two are cloned, the
/// create ends done, a problem names the one that failed and git left no folder for it. A VMM
/// kill right after the create keeps both checkouts whole: `git fsck --full` passes in each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_clones_each_repository_and_one_that_cannot_be_reached_fails_alone() {
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host("repos").await;
    let name = format!("{}-repos", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for allowed in [REPO_HOST, UNREACHABLE_HOST] {
        host.store()
            .add_rule(&NewRule {
                scope: Scope::Workspace(sandbox.clone()),
                pattern: Pattern::parse(allowed).unwrap(),
                effect: Effect::Allow,
                expires_at: None,
                created_by: Actor::Cli,
            })
            .unwrap();
    }
    let unreachable = format!("https://{UNREACHABLE_HOST}/acme/missing.git");
    let api = Api::new(host.url(), host.token());
    let mut events = api.events().await;
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "memory_mib": 1024, "repositories": [
                {"url": REPO}, {"url": unreachable}, {"url": SECOND_REPO}
            ]})
            .to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let end = events
        .until(ended(name_static), Duration::from_mins(15))
        .await;
    assert_eq!(
        end["step"], "done",
        "one failed clone does not fail the create: {end}"
    );
    assert_eq!(
        events.steps(&name),
        [
            "preparing_volume",
            "pulling_image",
            "starting",
            "syncing",
            "cloning",
            "cloning",
            "cloning",
            "done"
        ]
    );
    let problems = api.get("/api/problems").await.json();
    let failed: Vec<_> = problems["problems"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["workspace"] == name)
        .collect();
    assert_eq!(failed.len(), 1, "{problems}");
    assert_eq!(failed[0]["key"], format!("clone:{name}:missing"));
    assert!(
        failed[0]["title"].as_str().unwrap().contains(&unreachable),
        "{problems}"
    );
    assert!(
        failed[0]["detail"]
            .as_str()
            .unwrap()
            .starts_with("git exited "),
        "{problems}"
    );
    let listing = guest(&runtime, &sandbox, &format!("ls -1A /workspaces/{name}")).await;
    let listed: Vec<&str> = listing.lines().filter(|l| *l != ".puddle").collect();
    assert_eq!(
        listed,
        ["Hello-World", "Spoon-Knife"],
        "git left nothing of the failed clone"
    );

    // The one sync after the last clone has put both on the disk: a hard kill now loses neither.
    kill_vm(&runtime, &settings, &sandbox).await;
    checkouts_are_whole(&runtime, &sandbox, &["Hello-World", "Spoon-Knife"]).await;
    host.shutdown().await;
}

/// Boots the killed `sandbox` straight from the runtime and checks that each checkout passes
/// `git fsck --full` and has a HEAD, then stops it again.
async fn checkouts_are_whole(runtime: &MsbRuntime, sandbox: &WorkspaceName, dirs: &[&str]) {
    let restarted = runtime.start(&sandbox.sandbox_name()).await.unwrap();
    for dir in dirs {
        let repo = format!("/workspaces/{sandbox}/{dir}");
        let out = restarted
            .exec(
                ExecRequest::sh(format!(
                    "git -c safe.directory='*' -C {repo} fsck --full && \
                     git -c safe.directory='*' -C {repo} rev-parse HEAD"
                ))
                .as_user("root")
                .with_timeout(Duration::from_mins(5)),
            )
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{dir} after the kill: {}{}",
            out.stdout_text(),
            out.stderr_text()
        );
    }
    restarted.stop().await.unwrap();
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
    let mut options = hermetic_options();
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    // The clone went through Puddle's own certificate for github.com: git trusted it.
    assert_eq!(end["step"], "done", "{end}");
    let termination = host
        .workspaces()
        .termination(&sandbox)
        .expect("a CA while it runs");
    let ca_name = format!("Puddle CA for {name}");

    // github.com is decrypted and the guest trusts its certificate; example.com is spliced and
    // shows its real issuer; gitlab.com has no identity yet, so it is spliced too.
    let github = guest(&runtime, &sandbox, &issuer_script("github.com")).await;
    assert!(github.contains(&ca_name), "{github}");
    for site in ["example.com", "gitlab.com"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(
            !issuer.to_lowercase().contains("puddle"),
            "{site}: {issuer}"
        );
    }

    // The guest holds the CA certificate and no key anywhere Puddle writes.
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
    assert!(!issuer.to_lowercase().contains("puddle"), "{issuer}");
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
/// against a host that serves HTTP/3 still gets its answer, over HTTP/2 through the proxy. With
/// capture on, the same holds for a curl that ignores the proxy settings: its QUIC attempt is
/// refused at once, and its TCP fallback is redirected to the proxy by name.
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
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
    let allowed_to_h3_host = || {
        host.store()
            .audit_lines(0, 10_000)
            .unwrap()
            .iter()
            .filter(|(_, line)| {
                let record: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
                record["type"] == "connection"
                    && record["host"] == H3_HOST
                    && record["port"] == 443
                    && record["decision"] == "allow"
            })
            .count()
    };
    let mut recorded = 0;
    for _ in 0..50 {
        recorded = allowed_to_h3_host();
        if recorded > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recorded > 0,
        "no allowed connection to {H3_HOST}:443 in the audit"
    );

    // The same curl with no proxy at all: its name resolves to a stand-in through the stub, the
    // QUIC attempt to it is refused at once, and the TCP fallback is redirected to the proxy and
    // sent as `CONNECT example.com:443`, which the host allows: a second connection record.
    let captured = guest(
        &runtime,
        &sandbox,
        &format!(
            "curl --noproxy '*' --http3 -sS -v -o /dev/null --max-time 60 \
             -w 'answer http_version=%{{http_version}} http_code=%{{http_code}}\n' \
             https://{H3_HOST}/ 2>&1 | grep -i -E 'alt-svc|^answer|Connected to'"
        ),
    )
    .await;
    eprintln!("{captured}");
    assert!(
        captured.contains("answer http_version=2 http_code=200"),
        "{captured}"
    );
    assert!(
        captured.to_ascii_lowercase().contains("alt-svc: h3="),
        "{captured}"
    );
    // The guest connected to a stand-in address, not a real one: its answer came from the stub.
    assert!(
        captured.contains("Connected to example.com (198.1"),
        "{captured}"
    );
    let mut after = recorded;
    for _ in 0..50 {
        after = allowed_to_h3_host();
        if after > recorded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        after > recorded,
        "the captured fallback left no connection record ({recorded} before, {after} after)"
    );

    // A client that tries QUIC and ignores the proxy fails at once instead of waiting.
    let direct = guest(
        &runtime,
        &sandbox,
        &format!("bash -s <<'PUDDLE_EOF'\n{DIRECT_HTTP3_SCRIPT}\nPUDDLE_EOF"),
    )
    .await;
    eprintln!("{direct}");
    // curl's exit status for a refused send is not the "no route" 7 it was with no capture; the
    // bar is that it failed at once and was not a timeout (28).
    assert!(
        !direct.contains("exit=0") && !direct.contains("exit=28"),
        "{direct}"
    );
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
        root: _,
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
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
    let ca_name = format!("Puddle CA for {name}");
    for site in ["example.com", "example.org"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(issuer.contains(&ca_name), "{site}: {issuer}");
    }
    let net = guest(&runtime, &sandbox, &issuer_script("example.net")).await;
    assert!(!net.to_lowercase().contains("puddle"), "{net}");

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
    assert!(!net.to_lowercase().contains("puddle"), "{net}");

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// Login capture on a real guest. With capture on (the default) the hosts of the Claude Code and
/// GitHub logins are decrypted from the workspace's start: the guest trusts Puddle's certificate
/// there, a request works over HTTP/2 where the real server speaks it, and a request to a token
/// endpoint reaches the real server and the server's own error answer comes back untouched, with
/// no notice (an answer with no token in it is nothing to capture). A workspace that turns capture
/// off sees the real certificates from its next start.
///
/// No account is used: the real services refuse an unauthenticated request, which is the answer
/// that proves the exchange path is transparent.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_decrypts_the_login_hosts_while_capture_is_on_and_leaves_them_alone_when_it_is_off()
{
    let VmHost {
        host,
        runtime,
        settings,
        secrets: _,
        root: _,
    } = start_vm_host("login").await;
    let name = format!("{}-login", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in [
        "github.com",
        "api.github.com",
        "platform.claude.com",
        "api.anthropic.com",
        "example.com",
    ] {
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");

    // On by default: the login hosts show Puddle's certificate, every other host its own.
    let ca_name = format!("Puddle CA for {name}");
    for site in ["platform.claude.com", "api.anthropic.com", "api.github.com"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(issuer.contains(&ca_name), "{site}: {issuer}");
    }
    let example = guest(&runtime, &sandbox, &issuer_script("example.com")).await;
    assert!(!example.to_lowercase().contains("puddle"), "{example}");

    // An ordinary request on a decrypted login host works, over HTTP/2 where the server speaks it.
    // `/rate_limit` and not `/zen`: an unauthenticated address gets 60 API calls an hour and a
    // hosted runner shares its address with other jobs, so `/zen` answers 403 once they used it
    // up. GitHub does not count `/rate_limit` against that allowance and answers it while the
    // allowance is spent. The whole answer is in the assert message, so a refusal says why.
    let rate = guest(
        &runtime,
        &sandbox,
        "curl -si -w '\\n%{http_code} %{http_version}' --max-time 60 https://api.github.com/rate_limit",
    )
    .await;
    assert!(
        rate.trim()
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("200 ")),
        "{rate}"
    );
    eprintln!(
        "api.github.com through the proxy: {}",
        rate.trim().lines().last().unwrap_or_default()
    );

    // A token endpoint: the real server refuses an unknown refresh token with its own error; the
    // request body went through the exchange path and the answer is not touched.
    let refused = guest(
        &runtime,
        &sandbox,
        "curl -s -X POST -H 'content-type: application/json' --max-time 60 \
         -d '{\"grant_type\":\"refresh_token\",\"refresh_token\":\"not-a-real-token\",\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\"}' \
         -w '\\n%{http_code}' https://platform.claude.com/v1/oauth/token",
    )
    .await;
    let status: u16 = refused
        .trim()
        .rsplit('\n')
        .next()
        .and_then(|code| code.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        (400..500).contains(&status),
        "the real token endpoint should refuse it: {refused}"
    );
    // GitHub's device-code request: a form POST that is not a token answer either.
    let device = guest(
        &runtime,
        &sandbox,
        "curl -s -X POST -H 'accept: application/json' --max-time 60 \
         -d 'client_id=178c6fc778ccc68e1d6a&scope=repo' -w '\\n%{http_code}' \
         https://github.com/login/device/code",
    )
    .await;
    assert!(device.trim().ends_with("200"), "{device}");
    assert!(device.contains("user_code"), "{device}");
    // Nothing was reported: no answer here held a token.
    assert!(
        !events.seen.iter().any(|e| e["type"] == "login_problem"),
        "{:#?}",
        events.seen
    );

    // Turning capture off applies at the next start.
    let reply = api
        .put(
            &format!("/api/settings/workspaces/{name}"),
            &json!({"overrides": {"capture_logins": false}}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    api.post(&format!("/api/workspaces/{name}/start"), "").await;
    let end = events
        .until(ended(name_static), Duration::from_secs(300))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    for site in ["platform.claude.com", "api.anthropic.com", "api.github.com"] {
        let issuer = guest(&runtime, &sandbox, &issuer_script(site)).await;
        assert!(
            !issuer.to_lowercase().contains("puddle"),
            "{site}: {issuer}"
        );
    }
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// How many connections the guest holds open at once in the test below: more than a browser or a
/// parallel `npm install` opens, below the proxy's per-workspace cap.
const HELD_CONNECTIONS: usize = 2000;

/// Opens `HELD` connections to the agent's proxy port as `CONNECT 127.0.0.1:<port>` (the host's
/// own loopback, which the test allows for this workspace), holds all of them open, then sends a
/// line on each and reads it back, and prints the counts and the agent's own limits.
///
/// No `read -t`: bash waits with `select`, which breaks on descriptors from 1024 up. A stuck
/// connection is caught by the guest command's own time limit.
const HELD_CONNECTIONS_SCRIPT: &str = r#"
set -u
ulimit -n $((HELD * 2 + 256)) 2>/dev/null || ulimit -n "$(ulimit -Hn)"
echo "guest shell limit: $(ulimit -n)"
echo "agent started: $(grep -h 'open-file limit' /run/puddle/agent.log 2>&1 | tail -1)"
echo "agent limits: $(grep -i 'open files' /proc/$(pidof puddle-agent | cut -d' ' -f1)/limits)"
opened=0; refused=0; fds=()
for ((i = 0; i < HELD; i++)); do
  if exec {fd}<>/dev/tcp/127.0.0.1/3128 2>/dev/null; then
    printf 'CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n' "$PORT" "$PORT" >&"$fd"
    IFS= read -r -u "$fd" status; IFS= read -r -u "$fd" _blank
    case "$status" in
      "HTTP/1.1 200"*) opened=$((opened + 1)); fds+=("$fd") ;;
      *) refused=$((refused + 1)); echo "refused $i: $status"; exec {fd}>&- ;;
    esac
  else
    refused=$((refused + 1)); echo "no socket for $i"
  fi
done
echo "held=$opened refused=$refused"
echoed=0
for ((i = 0; i < ${#fds[@]}; i++)); do
  fd=${fds[$i]}
  printf 'line %s\n' "$i" >&"$fd"
  IFS= read -r -u "$fd" back
  if [ "$back" = "line $i" ]; then echoed=$((echoed + 1)); fi
done
echo "echoed=$echoed"
for fd in "${fds[@]}"; do exec {fd}>&-; done
"#;

/// The bar from the tools that open the most connections: 2 000 connections from the guest,
/// through the agent, the vsock route and the proxy, to a server on the host, all open at the
/// same moment, none refused, each echoing a line back. The host process (this one) holds a
/// socket per connection on each side, so it also proves the host's raised open-file limit.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_carries_2000_concurrent_guest_connections_through_agent_and_proxy() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host("held").await;
    let limit = puddle_fd_limit::raise_open_file_limit(puddle_fd_limit::Reach::Soft);
    eprintln!("host process: {limit}");
    assert!(
        limit.allows(4 * HELD_CONNECTIONS as u64),
        "the host process cannot hold {HELD_CONNECTIONS} connections: {limit}"
    );

    // The server on the host: echoes each line, and counts the most connections open at once.
    let server = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = server.local_addr().unwrap().port();
    let now = std::sync::Arc::new(AtomicUsize::new(0));
    let peak = std::sync::Arc::new(AtomicUsize::new(0));
    {
        let (now, peak) = (now.clone(), peak.clone());
        tokio::spawn(async move {
            loop {
                let Ok((conn, _)) = server.accept().await else {
                    return;
                };
                let (now, peak) = (now.clone(), peak.clone());
                tokio::spawn(async move {
                    peak.fetch_max(now.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    let (read, mut write) = conn.into_split();
                    let mut lines = BufReader::new(read);
                    let mut line = String::new();
                    while lines.read_line(&mut line).await.is_ok_and(|n| n > 0) {
                        if write.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                        line.clear();
                    }
                    now.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }

    let name = format!("{}-held", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    // The repository host for the clone, and the host's own address for the connections.
    for site in [REPO_HOST, "127.0.0.1"] {
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    // The host's loopback is a local destination: off by default, one toggle per workspace.
    let toggle = api
        .put(
            &format!("/api/settings/workspaces/{name}"),
            &json!({"overrides": {"local_toggles": {"loopback": true}}}).to_string(),
        )
        .await;
    assert_eq!(toggle.status, 200, "{}", toggle.body);

    let started = std::time::Instant::now();
    let out = guest(
        &runtime,
        &sandbox,
        &format!(
            "HELD={HELD_CONNECTIONS} PORT={port} bash -s <<'PUDDLE_EOF'\n{HELD_CONNECTIONS_SCRIPT}\nPUDDLE_EOF"
        ),
    )
    .await;
    eprintln!("{out}took {:?}", started.elapsed());
    let peak_seen = peak.load(Ordering::SeqCst);
    eprintln!("the server saw {peak_seen} connections open at once");
    assert!(
        out.contains(&format!("held={HELD_CONNECTIONS} refused=0")),
        "{out}"
    );
    assert!(out.contains(&format!("echoed={HELD_CONNECTIONS}")), "{out}");
    assert!(
        peak_seen >= HELD_CONNECTIONS,
        "only {peak_seen} were open together"
    );

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// A small HTTP/1.1 server on the host for the transparency bar (keep-alive):
/// `GET /ping` answers `pong`; `GET /bytes/<n>` sends `n` bytes; `PUT /sink` with a
/// `Content-Length` reads that many bytes and answers `received=<n>`.
#[expect(
    clippy::too_many_lines,
    reason = "one connection loop, read top to bottom"
)]
async fn transparency_fixture() -> u16 {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let server = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = server.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut conn = BufReader::new(conn);
                loop {
                    let mut line = String::new();
                    if conn.read_line(&mut line).await.is_ok_and(|n| n == 0) || line.is_empty() {
                        return;
                    }
                    let request = line.trim_end().to_owned();
                    let mut length = 0u64;
                    let mut close = false;
                    loop {
                        let mut header = String::new();
                        if conn.read_line(&mut header).await.is_ok_and(|n| n == 0) {
                            return;
                        }
                        if header == "\r\n" {
                            break;
                        }
                        let header = header.to_ascii_lowercase();
                        if let Some(value) = header.strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                        close |= header.trim_end() == "connection: close";
                    }
                    let mut parts = request.split(' ');
                    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                    let path = path.split('?').next().unwrap_or("");
                    let mut buf = vec![0u8; 1 << 20];
                    let ok = if method == "PUT" {
                        let mut left = length;
                        while left > 0 {
                            let want = usize::try_from(left.min(buf.len() as u64)).unwrap();
                            match conn
                                .read(buf.get_mut(..want).expect("within the buffer"))
                                .await
                            {
                                Ok(0) | Err(_) => return,
                                Ok(n) => left -= n as u64,
                            }
                        }
                        let body = format!("received={length}");
                        conn.get_mut()
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await
                            .is_ok()
                    } else if let Some(n) = path.strip_prefix("/bytes/") {
                        let total: u64 = n.parse().unwrap_or(0);
                        if conn
                            .get_mut()
                            .write_all(
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\r\n")
                                    .as_bytes(),
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let mut left = total;
                        let mut ok = true;
                        while left > 0 && ok {
                            let n = usize::try_from(left.min(buf.len() as u64)).unwrap();
                            ok = conn
                                .get_mut()
                                .write_all(buf.get(..n).expect("within the buffer"))
                                .await
                                .is_ok();
                            left -= n as u64;
                        }
                        ok
                    } else {
                        conn.get_mut()
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                            .await
                            .is_ok()
                    };
                    if !ok || close {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// What every part of [`TRANSPARENCY_PARTS`] starts with.
const TRANSPARENCY_PRELUDE: &str = r#"
set -u
ulimit -n 8192 2>/dev/null || ulimit -n "$(ulimit -Hn)"
PROXY=(-p -x http://127.0.0.1:3128 --noproxy '')
U="http://127.0.0.1:$PORT"
cd /tmp
t0=$(date +%s%N)
wall() { echo "$1_wall=$(( ($(date +%s%N) - t0) / 1000000 ))ms"; }
"#;

/// What the guest runs for the transparency bar, as curl at its widest: `curl` is the one tool the
/// image is sure to have, and it does what the package managers do (parallel transfers, one
/// connection reused for many requests, big bodies each way, plain HTTP as apt sends it, a reader
/// that is slow). Each part is its own exec with a time limit above its curl limits, so a slow part
/// fails on its own numbers and the parts before it are already printed; one limit for all of them
/// once timed out the whole script on a hosted Windows runner whose parts were each within their
/// bars. A gibibyte gets 120 s each way, about three times the slowest seen (35 s up on that runner,
/// one vCPU).
/// Each part prints `key=value` words; the test asserts them.
const TRANSPARENCY_PARTS: &[(&str, u64, &str)] = &[
    (
        "parallel",
        150,
        r#"
# 1024 connections at once (four times pnpm's peak), curl's own parallel mode.
: > par.cfg
for i in $(seq 1 1024); do printf 'url = "%s/ping?i=%s"\noutput = "/dev/null"\n' "$U" "$i" >> par.cfg; done
curl -s "${PROXY[@]}" --parallel --parallel-immediate --parallel-max 1024 -K par.cfg --max-time 120 \
  -w '%{http_code} %{time_total}\n' > par.out 2> par.err
echo "parallel_ok=$(grep -c '^200 ' par.out) parallel_total=1024 parallel_slowest=$(sort -k2 -n par.out | tail -1 | cut -d' ' -f2)"
[ -s par.err ] && echo "parallel_stderr=$(head -c 300 par.err | tr '\n' ' ')"
wall parallel
"#,
    ),
    (
        "keepalive",
        150,
        r#"
# 1000 requests in a row on one reused connection.
: > seq.cfg
for i in $(seq 1 1000); do printf 'url = "%s/ping?i=%s"\noutput = "/dev/null"\n' "$U" "$i" >> seq.cfg; done
curl -s "${PROXY[@]}" -K seq.cfg --max-time 120 -w '%{http_code} %{time_total} %{num_connects}\n' > seq.out 2> seq.err
echo "keepalive_ok=$(grep -c '^200 ' seq.out) keepalive_slowest=$(sort -k2 -n seq.out | tail -1 | cut -d' ' -f2) keepalive_mean=$(awk '{t+=$2} END {printf "%.6f", t/NR}' seq.out) keepalive_connects=$(awk '{n+=$3} END {print n}' seq.out)"
wall keepalive
"#,
    ),
    (
        "download",
        150,
        r#"
curl -s "${PROXY[@]}" -o /dev/null --max-time 120 -w 'download_bytes=%{size_download} download_s=%{time_total} download_code=%{http_code}\n' "$U/bytes/1073741824"
"#,
    ),
    (
        "plain_download",
        150,
        r#"
# apt's way: a plain `GET http://` that the proxy forwards, no tunnel.
curl -s -x http://127.0.0.1:3128 --noproxy '' -o /dev/null --max-time 120 -w 'plain_download_bytes=%{size_download} plain_download_s=%{time_total} plain_download_code=%{http_code}\n' "$U/bytes/1073741824"
"#,
    ),
    (
        "upload",
        150,
        r#"
head -c 1073741824 /dev/zero | curl -s "${PROXY[@]}" -T - -H 'Transfer-Encoding:' -H 'Content-Length: 1073741824' \
  --max-time 120 -w ' upload_s=%{time_total} upload_code=%{http_code}\n' "$U/sink"
"#,
    ),
    (
        "slow",
        180,
        r#"
# A reader at 1 KiB/s for 60 s, with 20 other transfers started meanwhile, one every 2 s.
curl -s "${PROXY[@]}" --limit-rate 1k -o /dev/null --max-time 60 -w 'slow_bytes=%{size_download} slow_exit_time=%{time_total}\n' "$U/bytes/1073741824" &
slow=$!
sleep 3
others=0
for i in $(seq 1 20); do
  if curl -s "${PROXY[@]}" -o /dev/null --max-time 5 "$U/bytes/1048576"; then others=$((others + 1)); fi
  sleep 2
done
echo "slow_others_ok=$others slow_others_total=20"
wait "$slow"
echo "slow_curl_exit=$?"
wall slow
"#,
    ),
];

/// The transparency bar from inside a real VM: what the heaviest package managers do (see
/// [`TRANSPARENCY_PARTS`]) goes from the guest through the agent, the vsock route, the proxy and
/// the rules engine to a server on the host. No failure, and no connection slower than 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_transparency_bar_curl_at_its_widest_through_agent_and_proxy() {
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host("transp").await;
    let limit = puddle_fd_limit::raise_open_file_limit(puddle_fd_limit::Reach::Soft);
    assert!(
        limit.allows(4 * 1100),
        "the host process cannot hold 1024 connections: {limit}"
    );
    let port = transparency_fixture().await;
    let name = format!("{}-transp", settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in [REPO_HOST, "127.0.0.1"] {
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
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let toggle = api
        .put(
            &format!("/api/settings/workspaces/{name}"),
            &json!({"overrides": {"local_toggles": {"loopback": true}}}).to_string(),
        )
        .await;
    assert_eq!(toggle.status, 200, "{}", toggle.body);

    let mut out = String::new();
    for (part, limit, script) in TRANSPARENCY_PARTS {
        eprintln!("{part} starts, limit {limit} s");
        let started = std::time::Instant::now();
        let said = guest_within(
            &runtime,
            &sandbox,
            &format!(
                "PORT={port} bash -s <<'PUDDLE_EOF'\n{TRANSPARENCY_PRELUDE}{script}\nPUDDLE_EOF"
            ),
            Duration::from_secs(*limit),
        )
        .await;
        eprintln!("{said}{part} took {:?}", started.elapsed());
        out.push_str(&said);
    }

    let value = |key: &str| -> String {
        out.split_whitespace()
            .find_map(|word| word.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("no {key} in the guest's output:\n{out}"))
            .to_owned()
    };
    let seconds = |key: &str| -> f64 { value(key).parse().unwrap() };
    assert_eq!(value("parallel_ok"), "1024", "{out}");
    assert!(seconds("parallel_slowest") < 5.0, "{out}");
    assert_eq!(value("keepalive_ok"), "1000", "{out}");
    assert_eq!(value("keepalive_connects"), "1", "{out}");
    assert!(seconds("keepalive_slowest") < 5.0, "{out}");
    assert_eq!(value("download_bytes"), "1073741824", "{out}");
    assert_eq!(value("download_code"), "200", "{out}");
    assert_eq!(value("plain_download_bytes"), "1073741824", "{out}");
    assert_eq!(value("plain_download_code"), "200", "{out}");
    assert_eq!(value("upload_code"), "200", "{out}");
    assert_eq!(value("slow_others_ok"), "20", "{out}");
    // 28 is curl's "operation timed out": the slow reader was still reading at --max-time.
    assert_eq!(value("slow_curl_exit"), "28", "{out}");
    let slow_bytes: u64 = value("slow_bytes").parse().unwrap();
    assert!(
        (30 * 1024..=120 * 1024).contains(&slow_bytes),
        "the slow reader read {slow_bytes} bytes in a minute: {out}"
    );

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

/// Hosts the radar's package managers talk to. With termination on, an identity names each, so
/// Puddle decrypts and re-encrypts every connection to them; with it off they are only allowed.
const RADAR_HOSTS: &[&str] = &[
    "deb.debian.org",
    "security.debian.org",
    "registry.npmjs.org",
    "index.crates.io",
    "static.crates.io",
    "crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "storage.googleapis.com",
];

/// Hosts served over TLS among [`RADAR_HOSTS`] (apt uses plain HTTP).
fn radar_tls_hosts() -> impl Iterator<Item = &'static &'static str> {
    RADAR_HOSTS.iter().filter(|h| !h.ends_with("debian.org"))
}

/// An identity with one credential binding per host, so every one of them is decrypted.
fn identity_for(label: &str, hosts: impl Iterator<Item = &'static &'static str>) -> IdentityDraft {
    let credentials = hosts
        .map(|host| {
            let name = HostName::new(*host).unwrap();
            CredentialBinding::new(
                &name,
                SourceSpec::Gh {
                    host: name.clone(),
                    account: AccountName::new("nobody").unwrap(),
                },
                Coverage::new(BTreeSet::new(), true).unwrap(),
            )
            .unwrap()
        })
        .collect();
    IdentityDraft {
        label: label.to_owned(),
        author: Author::new(label, "radar@example.org").unwrap(),
        credentials,
    }
}

/// A workspace for a radar: the hosts allowed, the identity attached when `terminate` is set (a
/// host with no injection, so nothing is added to a request), and the workspace created and
/// running.
async fn radar_workspace(tag: &str, terminate: bool) -> (VmHost, WorkspaceName, Api) {
    let vm = start_vm_host_with(tag, options_without_injection()).await;
    let name = format!("{}-{tag}", vm.settings.prefix.as_str());
    let sandbox = WorkspaceName::new(&name).unwrap();
    for site in RADAR_HOSTS.iter().chain(&[REPO_HOST]) {
        vm.host
            .store()
            .add_rule(&NewRule {
                scope: Scope::Workspace(sandbox.clone()),
                pattern: Pattern::parse(site).unwrap(),
                effect: Effect::Allow,
                expires_at: None,
                created_by: Actor::Cli,
            })
            .unwrap();
    }
    if terminate {
        vm.host
            .store()
            .create_identity(identity_for("Radar", radar_tls_hosts()))
            .unwrap();
    }
    let api = Api::new(vm.host.url(), vm.host.token());
    let mut events = api.events().await;
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 2048}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(
        end.get("step").and_then(serde_json::Value::as_str),
        Some("done"),
        "{end}"
    );
    (vm, sandbox, api)
}

/// The connection records of the audit so far.
fn audit_connections(host: &Host<MsbRuntime>) -> Vec<serde_json::Value> {
    host.store()
        .audit_lines(0, 200_000)
        .unwrap()
        .into_iter()
        .filter_map(|(_, line)| serde_json::from_str::<serde_json::Value>(&line).ok())
        .filter(|r| r["type"] == "connection")
        .collect()
}

/// A summary of the connection records: how many per host, how many decrypted (they carry a
/// method), and every one the proxy did not simply allow by rule.
fn audit_summary(records: &[serde_json::Value]) -> String {
    let mut per_host: std::collections::BTreeMap<String, (u32, u32)> =
        std::collections::BTreeMap::new();
    let mut odd = Vec::new();
    for r in records {
        let host = r["host"].as_str().unwrap_or("?").to_owned();
        let entry = per_host.entry(host).or_default();
        entry.0 += 1;
        entry.1 += u32::from(!r["method"].is_null());
        if r["reason"] != "rule" || r["decision"] != "allow" {
            odd.push(format!(
                "  {} {} {} {}",
                r["host"], r["decision"], r["reason"], r["detail"]
            ));
        }
    }
    let mut lines = vec!["connection records by host (all, decrypted):".to_owned()];
    lines.extend(
        per_host
            .into_iter()
            .map(|(host, (all, decrypted))| format!("  {host}: {all}, {decrypted}")),
    );
    lines.push(format!("not allowed by rule: {}", odd.len()));
    lines.extend(odd.into_iter().take(20));
    lines.join("\n")
}

/// What the radar installs and fetches, as one guest script: each step is timed, its own output
/// kept, and the lines that show a tool retrying or failing are counted (a retry is a failure the
/// tool hid). The package sets are pinned at the top level only, so the full trees drift with the
/// registries: that is what a radar is for.
const RADAR_SCRIPT: &str = r#"
set -u
export DEBIAN_FRONTEND=noninteractive
env | grep -i -E '^(https?|no|all)_proxy=' | sed 's/^/RADAR env /'
df -PmT | awk 'NR > 1 && $2 != "devtmpfs" {print "RADAR mount=" $7 " type=" $2 " size_mib=" $3 " free_mib=" $5}'
step() {
  name=$1; shift
  t0=$(date +%s.%N)
  timeout 1500 bash -c "$*" > "/tmp/radar-$name.log" 2>&1
  rc=$?
  t1=$(date +%s.%N)
  bad=$(grep -c -i -E 'Err:|W: Failed|^E: |retrying|will retry|timed out|ETIMEDOUT|ECONNRESET|EPIPE|reset by peer|connection refused|EAI_AGAIN|unexpected eof|\bstalled|handshake fail|handshake_failure|handshake (timeout|error)|handshakeexception|certificate verify|SSL_ERROR|SSL certificate problem|x509: |PKIX|spurious network error|i/o timeout|dial tcp|could not transfer|transfer failed|but failed' "/tmp/radar-$name.log")
  echo "RADAR step=$name rc=$rc secs=$(awk "BEGIN {printf \"%.1f\", $t1 - $t0}") suspicious_lines=$bad disk_free_mib=$(df -Pm / | awk 'NR==2 {print $4}')"
  if [ "$rc" != 0 ] || [ "$bad" != 0 ]; then
    grep -i -E 'Err:|W: Failed|^E: |retrying|will retry|timed out|ETIMEDOUT|ECONNRESET|EPIPE|reset by peer|connection refused|EAI_AGAIN|unexpected eof|\bstalled|handshake fail|handshake_failure|handshake (timeout|error)|handshakeexception|certificate verify|SSL_ERROR|SSL certificate problem|x509: |PKIX|spurious network error|i/o timeout|dial tcp|could not transfer|transfer failed|but failed' "/tmp/radar-$name.log" | head -8 | sed 's/^/  | /'
    tail -5 "/tmp/radar-$name.log" | sed 's/^/  > /'
  fi
}

step apt_update 'apt-get update'
PKGS='nodejs npm golang-go default-jdk-headless ca-certificates-java maven cargo curl'
step apt_download "apt-get install -y -d --no-install-recommends $PKGS"
echo "RADAR apt_downloaded_mib=$(du -sm /var/cache/apt/archives | cut -f1)"
step apt_install "apt-get install -y --no-install-recommends $PKGS"
apt-get clean

mkdir -p /tmp/np && cd /tmp/np
cat > package.json <<'JSON'
{"name":"radar","version":"1.0.0","dependencies":{
 "next":"14.2.15","react":"18.3.1","react-dom":"18.3.1","typescript":"5.6.3","eslint":"8.57.1",
 "eslint-config-next":"14.2.15","jest":"29.7.0","webpack":"5.95.0","@babel/core":"7.25.8",
 "@babel/preset-env":"7.25.8","tailwindcss":"3.4.14","postcss":"8.4.47","rollup":"4.24.0","vite":"5.4.9",
 "@angular/cli":"18.2.9","@nestjs/core":"10.4.5","@nestjs/cli":"10.4.5","express":"4.21.1","lodash":"4.17.21"}}
JSON
step npm_cold_install 'cd /tmp/np && npm install --no-audit --no-fund --ignore-scripts --loglevel=http'
echo "RADAR npm_packages=$(find /tmp/np/node_modules -name package.json -not -path '*/test/*' | wc -l)"
rm -rf /tmp/np/node_modules /root/.npm

step pnpm_cold_install 'npm install -g pnpm@10.12.1 && mkdir -p /tmp/pn && cp /tmp/np/package.json /tmp/pn/ && cd /tmp/pn && pnpm install --ignore-scripts --reporter=append-only'
echo "RADAR pnpm_packages=$(ls /tmp/pn/node_modules/.pnpm 2>/dev/null | wc -l)"
rm -rf /tmp/pn /root/.local/share/pnpm /root/.cache/pnpm

mkdir -p /tmp/cg/src && cd /tmp/cg
cat > Cargo.toml <<'TOML'
[package]
name = "radar"
version = "0.1.0"
edition = "2021"
[dependencies]
tokio = { version = "1", features = ["full"] }
axum = "0.7"
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
sqlx = { version = "0.8", features = ["sqlite", "runtime-tokio"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
tracing-subscriber = "0.3"
rayon = "1"
regex = "1"
hyper = "1"
tonic = "0.12"
prost = "0.13"
aws-sdk-s3 = "1"
polars = "0.43"
bevy = "0.14"
TOML
echo 'fn main() {}' > src/main.rs
step cargo_fetch 'cd /tmp/cg && cargo fetch'
echo "RADAR cargo_crates=$(ls ~/.cargo/registry/cache/*/ 2>/dev/null | wc -l)"
rm -rf /root/.cargo/registry

mkdir -p /tmp/go && cd /tmp/go
step go_mod_download 'cd /tmp/go && go mod init radar && go get k8s.io/client-go@v0.31.2 github.com/aws/aws-sdk-go-v2/service/s3@v1.66.3 github.com/prometheus/client_golang@v1.20.5 google.golang.org/grpc@v1.67.1 github.com/gin-gonic/gin@v1.10.0 && go mod download'
echo "RADAR go_modules=$(find $(go env GOMODCACHE)/cache/download -name '*.zip' 2>/dev/null | wc -l)"
chmod -R u+w "$(go env GOMODCACHE)" 2>/dev/null; rm -rf "$(go env GOMODCACHE)" /root/.cache/go-build

mkdir -p /tmp/mv && cd /tmp/mv
cat > pom.xml <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>x</groupId><artifactId>radar</artifactId><version>1</version>
<properties><maven.compiler.source>21</maven.compiler.source><maven.compiler.target>21</maven.compiler.target></properties>
<dependencies>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId><version>3.3.5</version></dependency>
<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId><version>3.3.5</version></dependency>
<dependency><groupId>org.apache.kafka</groupId><artifactId>kafka-clients</artifactId><version>3.8.0</version></dependency>
<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.18.0</version></dependency>
</dependencies></project>
XML
step maven_resolve 'cd /tmp/mv && mvn -B dependency:resolve dependency:resolve-plugins'
echo "RADAR maven_jars=$(find ~/.m2/repository -name '*.jar' | wc -l)"
"#;

/// Tools whose refusal of the workspace's certificate the proxy cannot see today: they finish the
/// TLS handshake (their trust check runs after it) or close without a certificate alert, so the
/// audit shows an ordinary connection. Listed so the test fails when a tool outside the list goes
/// silent and when a listed one starts to be seen.
const SILENT_REFUSALS: &[&str] = &["node", "java"];

/// One probe per tool. Each is given a trust list without the workspace's CA (an unrelated root),
/// goes through the proxy like the tool would, and asks the decrypted registry for its front page.
fn refusal_probes() -> Vec<(&'static str, String)> {
    let host = "registry.npmjs.org";
    let probe_js = r"
const net = require('net'), tls = require('tls'), fs = require('fs');
const s = net.connect(3128, '127.0.0.1');
s.write('CONNECT HOST:443 HTTP/1.1\r\nHost: HOST:443\r\n\r\n');
s.once('data', () => {
  const t = tls.connect({ socket: s, servername: 'HOST', ca: fs.readFileSync('/tmp/other.pem') }, () => {
    console.log(t.authorized ? 'trusted' : 'refused after the handshake: ' + t.authorizationError);
    t.destroy(); process.exit(t.authorized ? 0 : 1);
  });
  t.on('error', (e) => { console.log('error: ' + e.message); process.exit(1); });
});
".replace("HOST", host);
    let probe_go = r#"
package main
import ("fmt"; "net/http"; "os")
func main() {
	r, err := http.Get(os.Args[1])
	if err != nil { fmt.Println("error:", err); os.Exit(1) }
	fmt.Println("status:", r.Status)
}
"#;
    let probe_java = r#"
import java.net.URI;
import java.net.http.*;
public class Probe {
  public static void main(String[] a) throws Exception {
    try {
      var r = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(a[0])).build(), HttpResponse.BodyHandlers.ofString());
      System.out.println("status: " + r.statusCode());
    } catch (Exception e) { System.out.println("error: " + e); System.exit(1); }
  }
}
"#;
    let setup = format!(
        "set -u; mkdir -p /tmp/no-roots; cp /usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt /tmp/other.pem; \
         rm -f /tmp/other.jks; keytool -importcert -noprompt -alias isrg -file /tmp/other.pem \
         -keystore /tmp/other.jks -storepass changeit >/dev/null 2>&1; \
         cat > /tmp/probe.js <<'EOF'\n{probe_js}\nEOF\n\
         cat > /tmp/probe.go <<'EOF'\n{probe_go}\nEOF\n\
         cat > /tmp/Probe.java <<'EOF'\n{probe_java}\nEOF\n"
    );
    let url = format!("https://{host}/");
    vec![
        ("setup", setup),
        (
            "curl",
            format!("curl -sS --max-time 30 --cacert /tmp/other.pem --capath /tmp/no-roots {url}"),
        ),
        ("node", "node /tmp/probe.js".to_owned()),
        (
            "go",
            format!(
                "cd /tmp && SSL_CERT_FILE=/tmp/other.pem SSL_CERT_DIR=/nonexistent go run /tmp/probe.go {url}"
            ),
        ),
        (
            "java",
            format!(
                "cd /tmp && java -Djavax.net.ssl.trustStore=/tmp/other.jks -Djavax.net.ssl.trustStorePassword=changeit \
                 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=3128 /tmp/Probe.java {url}"
            ),
        ),
    ]
}

/// Runs each probe as root and reads the audit record the connection left: the exit code, what the
/// tool said, and the audit reason (`guest_tls_rejected` when the proxy saw the certificate alert).
/// Returns one line per tool, the tools whose refusal the audit did not show, and the tools that
/// trusted the certificate or left no connection record (none should: the caller fails on them once
/// everything is printed).
async fn refusal_matrix(
    vm: &VmHost,
    sandbox: &WorkspaceName,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let handle = vm.runtime.get(&sandbox.sandbox_name()).await.unwrap();
    let (mut lines, mut silent, mut trusted) = (Vec::new(), Vec::new(), Vec::new());
    for (tool, script) in refusal_probes() {
        let count = |records: &[serde_json::Value]| {
            records
                .iter()
                .filter(|r| r["host"] == "registry.npmjs.org")
                .count()
        };
        let before = count(&audit_connections(&vm.host));
        let out = handle
            .exec(
                ExecRequest::sh(script)
                    .as_user("root")
                    .with_timeout(Duration::from_secs(300)),
            )
            .await
            .unwrap();
        let said = format!("{}{}", out.stdout_text(), out.stderr_text());
        if tool == "setup" {
            assert!(out.status.success(), "the probes' setup failed: {said}");
            continue;
        }
        let mut reason = "no connection record".to_owned();
        for _ in 0..40 {
            let records = audit_connections(&vm.host);
            if count(&records) > before {
                let newest = records
                    .iter()
                    .rev()
                    .find(|r| r["host"] == "registry.npmjs.org")
                    .unwrap();
                reason = newest["reason"].as_str().unwrap_or("?").to_owned();
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let first_line = said
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(150)
            .collect::<String>();
        lines.push(format!(
            "{tool}: exit={} audit_reason={reason} tool said: {first_line}",
            out.status.code
        ));
        if out.status.success() {
            trusted.push(format!("{tool}: {said}"));
        } else if reason == "no connection record" {
            trusted.push(format!(
                "{tool}: no connection record, so its refusal is unknown"
            ));
        } else if reason != "guest_tls_rejected" {
            silent.push(tool.to_owned());
        }
    }
    (lines, silent, trusted)
}

/// The real tools at their widest, cold, through the real proxy and the real agent (the discovery
/// radar of the transparency bar): apt, npm, pnpm, cargo, go and maven fetch a few hundred to a few
/// thousand packages from the real registries. Nothing may fail or be retried. With `terminate`
/// set the registries' connections are decrypted and re-encrypted by Puddle; without it they are
/// spliced. Never run by the per-pull-request gate (the name starts `vm_radar_`).
#[expect(clippy::print_stderr, reason = "the radar's table goes to stderr")]
async fn radar(tag: &str, terminate: bool) {
    let (vm, sandbox, api) = radar_workspace(tag, terminate).await;
    // The run means nothing if the registries are not decrypted when they should be (or are when
    // they should not be): the issuer the guest sees says which.
    let issuer = guest(&vm.runtime, &sandbox, &issuer_script("registry.npmjs.org")).await;
    eprintln!("RADAR issuer {}", issuer.trim());
    assert_eq!(
        issuer.contains(&format!("Puddle CA for {}", sandbox.as_str())),
        terminate,
        "registry.npmjs.org decrypted is not {terminate}: {issuer}"
    );
    let out = {
        let handle = vm.runtime.get(&sandbox.sandbox_name()).await.unwrap();
        let out = handle
            .exec(
                ExecRequest::sh(format!(
                    "bash -s <<'PUDDLE_EOF'\n{RADAR_SCRIPT}\nPUDDLE_EOF"
                ))
                .as_user("root")
                .with_timeout(Duration::from_hours(3)),
            )
            .await
            .unwrap();
        format!("{}{}", out.stdout_text(), out.stderr_text())
    };
    eprintln!("{out}");
    let refusals = if terminate {
        let (lines, silent, trusted) = refusal_matrix(&vm, &sandbox).await;
        eprintln!("refused certificate, by tool:\n{}", lines.join("\n"));
        Some((silent, trusted))
    } else {
        None
    };
    let records = audit_connections(&vm.host);
    eprintln!("terminate={terminate}\n{}", audit_summary(&records));
    let steps = out.lines().filter(|l| l.starts_with("RADAR step=")).count();
    assert_eq!(steps, 8, "the radar script stopped early:\n{out}");
    let failing: Vec<&str> = out
        .lines()
        .filter(|l| {
            let mut words = l.split_whitespace();
            l.starts_with("RADAR step=")
                && !(words.clone().any(|w| w == "rc=0") && words.any(|w| w == "suspicious_lines=0"))
        })
        .collect();
    assert!(
        failing.is_empty(),
        "steps that failed or retried: {failing:#?}"
    );
    if let Some((silent, trusted)) = refusals {
        assert!(
            trusted.is_empty(),
            "tools that trusted a certificate they should have refused, or left no connection record: {trusted:#?}"
        );
        assert_eq!(
            silent, SILENT_REFUSALS,
            "the tools whose refused certificate the audit did not show changed"
        );
    }
    let stop = api
        .post(&format!("/api/workspaces/{}/stop", sandbox.as_str()), "")
        .await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let down = vm.host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_radar_package_managers_cold_with_the_registries_decrypted() {
    radar("radt", true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_radar_package_managers_cold_with_the_registries_spliced() {
    radar("rads", false).await;
}

/// The variable that turns [`vm_host_second_process_probe`] from a no-op into the second
/// `puddle serve`: it names the data folder the first process holds.
const SECOND_PROCESS_FOLDER_VAR: &str = "PUDDLE_VM_SECOND_PROCESS_FOLDER";

/// The second process of the refusal test (a copy of this test binary): does what
/// `puddle serve` does first, `prepare` on the data folder, and reports the refusal. It starts
/// no runtime and opens no store, so it can only fail the first process by taking its lock
/// (and the test below checks that it doesn't).
#[test]
fn vm_host_second_process_probe() {
    // skip-ok: the refusal test starts this binary again with the folder variable set; started on its own it is not a test.
    let Some(folder) = std::env::var_os(SECOND_PROCESS_FOLDER_VAR) else {
        return;
    };
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM test settings");
    // Not `settings.prepare()`: that rewrites the msb home's config while the first process
    // runs on it.
    let pair = RuntimePair::find_in(&settings.runtime_dir).expect("msb runtime pair");
    let agent = std::path::PathBuf::from(std::env::var_os("PUDDLE_AGENT_BIN").expect("agent"));
    let config = harness_config(&settings, &pair, std::path::Path::new(&folder), agent);
    match prepare(config, &HarnessPlatform::default()) {
        Ok(_) => panic!("the second process took the first one's data folder"),
        Err(error) => println!("refused: {error}"),
    }
}

/// A second host process on a data folder a running host holds is refused, and the first one's
/// sandbox keeps running: same boot, same API, and it still stops cleanly at the end. The
/// second process is a copy of this test binary that calls `prepare`, `puddle serve`'s first
/// step; the real executable's own argument handling is not part of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_a_second_process_on_the_same_data_folder_is_refused_and_the_vm_keeps_running() {
    let VmHost {
        host,
        runtime,
        settings,
        root,
        ..
    } = start_vm_host("twice").await;
    let name = format!("{}-twice", settings.prefix.as_str());
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
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");

    // What identifies this boot of this guest: its boot id, and an uptime that only grows.
    let probe = "cat /proc/sys/kernel/random/boot_id; cut -d' ' -f1 /proc/uptime";
    let before = guest(&runtime, &sandbox, probe).await;

    let started = std::time::Instant::now();
    let second = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            "--exact",
            "vm_host_second_process_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SECOND_PROCESS_FOLDER_VAR, &root)
        .output()
        .expect("start the second process");
    let stdout = String::from_utf8_lossy(&second.stdout);
    let stderr = String::from_utf8_lossy(&second.stderr);
    eprintln!(
        "second process took {:?}\n{stdout}{stderr}",
        started.elapsed()
    );
    assert!(second.status.success(), "{stdout}{stderr}");
    // libtest prints "test <name> ... " before the test's own output, so the refusal starts
    // mid-line, not at a line start.
    let refusal = stdout
        .lines()
        .find_map(|line| line.split_once("refused: ").map(|(_, refusal)| refusal))
        .unwrap_or_else(|| panic!("the second process did not report a refusal: {stdout}{stderr}"));
    assert!(
        refusal.contains(&format!("process ID {}", std::process::id())),
        "{refusal}"
    );
    assert!(refusal.contains("data folder"), "{refusal}");

    // The first host did not notice: the workspace still runs the same boot, the API answers,
    // and the sandbox is the one it created.
    let after = guest(&runtime, &sandbox, probe).await;
    let (boot_before, up_before) = before.split_once('\n').expect("boot id and uptime");
    let (boot_after, up_after) = after.split_once('\n').expect("boot id and uptime");
    assert_eq!(boot_before, boot_after, "the guest rebooted");
    let (up_before, up_after): (f64, f64) = (
        up_before.trim().parse().expect("uptime"),
        up_after.trim().parse().expect("uptime"),
    );
    assert!(up_after > up_before, "{up_before} then {up_after}");
    let workspace = api.get(&format!("/api/workspaces/{name}")).await.json();
    assert_eq!(workspace["status"], "running", "{workspace}");
    let running = runtime
        .list()
        .await
        .unwrap()
        .iter()
        .filter(|s| !s.status.is_down())
        .count();
    assert_eq!(running, 1);

    // It still stops cleanly, and once it is gone the folder is free for the next process.
    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
    drop(host);
    let agent = std::path::PathBuf::from(std::env::var_os("PUDDLE_AGENT_BIN").expect("agent"));
    let pair = RuntimePair::find_in(&settings.runtime_dir).expect("msb runtime pair");
    drop(
        prepare(
            harness_config(&settings, &pair, &root, agent),
            &HarnessPlatform::default(),
        )
        .unwrap(),
    );
}

/// Waits until the editor server in the guest answers its health check.
#[cfg(not(windows))]
async fn editor_up(runtime: &MsbRuntime, sandbox: &WorkspaceName) {
    guest(
        runtime,
        sandbox,
        "for i in $(seq 1 120); do \
             [ \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:41337/healthz)\" = 200 ] && exit 0; \
             sleep 1; \
         done; \
         echo \"no editor server; agent log:\"; tail -n 20 /run/puddle/agent.log; exit 1",
    )
    .await;
}

/// What a client sees of the editor server in a fresh sandbox: the release is read-only, the
/// password is the owner's alone, a client signs in with it, and it is on no command line.
/// Returns the password.
#[cfg(not(windows))]
async fn check_editor_session(runtime: &MsbRuntime, sandbox: &WorkspaceName, name: &str) -> String {
    // The release is read-only in the guest, and the password is the owner's alone.
    let mount = guest(
        runtime,
        sandbox,
        "touch /puddle/code-server/x 2>&1; test -x /puddle/code-server/lib/node && echo node-runs",
    )
    .await;
    assert!(
        mount.contains("Read-only file system") && mount.contains("node-runs"),
        "{mount}"
    );
    let first_password = guest(
        runtime,
        sandbox,
        "stat -c %a /run/puddle/editor-password; cat /run/puddle/editor-password",
    )
    .await;
    let (mode, password) = first_password.split_once('\n').unwrap();
    assert_eq!(mode, "600");
    assert_eq!(password.len(), 64, "{password}");
    let password = password.to_owned();
    // A client without the password is sent to the login page, with it gets in, and the password
    // is on no command line (the pattern's first character is bracketed so grep does not match itself).
    let signed_in = guest(
        runtime,
        sandbox,
        "pw=$(cat /run/puddle/editor-password); pat=$(printf %s \"$pw\" | sed 's/^./[&]/'); \
         curl -s -o /dev/null -w 'anonymous %{http_code} %{redirect_url}\\n' http://127.0.0.1:41337/; \
         curl -s -c /tmp/jar -o /dev/null -w 'login %{http_code}\\n' -d \"password=$pw\" http://127.0.0.1:41337/login; \
         curl -s -b /tmp/jar -o /dev/null -w 'signed-in %{http_code} %{redirect_url}\\n' http://127.0.0.1:41337/; \
         cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' >/tmp/cmdlines; \
         grep -c \"$pat\" /tmp/cmdlines | sed 's/^/on-command-lines /'; \
         grep -q '[-]-reconnection-grace-time 300' /tmp/cmdlines && echo grace-300",
    )
    .await;
    for expected in [
        "anonymous 302 http://127.0.0.1:41337/login",
        "login 302",
        // Signed in, the client is sent to the folder the editor opens.
        format!("signed-in 302 http://127.0.0.1:41337/?folder=/workspaces/{name}").as_str(),
        "on-command-lines 0",
        "grace-300",
    ] {
        assert!(
            signed_in.contains(expected),
            "{expected} missing in {signed_in}"
        );
    }
    password
}

/// K tier. The bundled code-server runs in the guest, started by the agent from the read-only
/// mount: it listens on loopback with a password only its owner can read, signs a client in, and
/// keeps its data on the workspace volume, so a rebuilt sandbox finds it again. (The Windows tier
/// needs the bundle's executable bits to survive the host's file system; that run is a follow-up.)
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_runs_the_editor_server_and_its_data_survives_a_rebuilt_sandbox() {
    let release = std::path::PathBuf::from(std::env::var_os("PUDDLE_CODE_SERVER_DIR").expect(
        "PUDDLE_CODE_SERVER_DIR: the unpacked code-server release (ci/fetch-code-server.sh)",
    ));
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host_config("edit", hermetic_options(), |config| {
        config.guest.code_server = Some(release);
    })
    .await;

    let name = format!("{}-edit", settings.prefix.as_str());
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
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 2048}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");

    editor_up(&runtime, &sandbox).await;
    let data = format!("/workspaces/{name}/.puddle/code-server");
    let password = check_editor_session(&runtime, &sandbox, &name).await;
    // Data on the volume: the server made its folders there, and a marker we add stays.
    guest(
        &runtime,
        &sandbox,
        &format!(
            "test -d {data}/user-data && test -d {data}/extensions \
             && mkdir -p {data}/extensions/puddle-marker && echo kept >{data}/extensions/puddle-marker/marker \
             && echo old-sandbox >/tmp/old-sandbox"
        ),
    )
    .await;

    // Rebuild the sandbox: a changed variable makes the next start create a new sandbox on the
    // same volume.
    let changed = api
        .put(
            &format!("/api/workspaces/{name}/env/REBUILD"),
            &json!({"kind": "plain", "value": "1"}).to_string(),
        )
        .await;
    assert_eq!(changed.status, 200, "{}", changed.body);
    for step in ["stop", "start"] {
        let reply = api
            .post(&format!("/api/workspaces/{name}/{step}"), "")
            .await;
        assert_eq!(reply.status, 202, "{}", reply.body);
        let end = events
            .until(ended(name_static), Duration::from_secs(300))
            .await;
        assert_eq!(end["step"], "done", "{end}");
    }
    editor_up(&runtime, &sandbox).await;
    let after = guest(
        &runtime,
        &sandbox,
        &format!(
            "test -e /tmp/old-sandbox && echo same-sandbox; cat {data}/extensions/puddle-marker/marker; \
             test -d {data}/user-data && echo user-data-kept; cat /run/puddle/editor-password"
        ),
    )
    .await;
    assert!(
        !after.contains("same-sandbox"),
        "the sandbox was not rebuilt: {after}"
    );
    assert!(
        after.contains("kept\n") && after.contains("user-data-kept"),
        "{after}"
    );
    assert!(
        !after.contains(&password),
        "the password is new for every start: {after}"
    );

    host.shutdown().await;
}

/// A workspace's shell init on a real guest: the script is checked in a throwaway shell before it
/// is saved, a login shell sources it from a read-only mount, the guest cannot change it, and a
/// start that finds the file that loads it replaced says so and puts it back.
///
/// The second half tries what a root process in the guest can try against the mount itself
/// (remounting it writable, writing a file in it). Whatever the VM allows, the host's folder is
/// back to the saved text at the next start, and the user is told when the guest changed it.
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_shell_init_is_checked_read_only_sourced_by_login_shells_and_restored_after_tampering()
 {
    let VmHost {
        host,
        runtime,
        settings,
        root,
        secrets: _,
    } = start_vm_host("shi").await;
    let name = format!("{}-shi", settings.prefix.as_str());
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
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");

    let path = format!("/api/workspaces/{name}/shell-init");
    let save = |content: &str| {
        let (api, path, content) = (&api, path.clone(), content.to_owned());
        async move {
            api.put(&path, &json!({ "content": content }).to_string())
                .await
        }
    };

    // What a login shell prints with no shell init (an image may print its own banner).
    let quiet_before = guest(&runtime, &sandbox, "bash -lc true 2>&1; echo end").await;

    // A script that prints, and one that does not parse, are refused by the guest's own shell and
    // nothing is saved.
    let loud = save("echo hello from my init\n").await;
    assert_eq!(loud.status, 422, "{}", loud.body);
    assert!(
        loud.body.contains("It printed: hello from my init"),
        "{}",
        loud.body
    );
    let broken = save("if then\n").await;
    assert_eq!(broken.status, 422, "{}", broken.body);
    assert!(broken.body.contains("does not parse"), "{}", broken.body);
    assert_eq!(api.get(&path).await.json()["saved"], false);

    // A quiet one is saved, and a login shell sources it, for a variable and for a function.
    let saved = save("export PUDDLE_SHELL_INIT_PROBE='from the shell init'\nshell_init_probe() { echo probed; }\n").await;
    assert_eq!(saved.status, 200, "{}", saved.body);
    assert_eq!(saved.json()["checked"], true, "{}", saved.body);
    let mut seen = String::new();
    for _ in 0..100 {
        seen = guest(
            &runtime,
            &sandbox,
            "bash -lc 'printenv PUDDLE_SHELL_INIT_PROBE; shell_init_probe' 2>&1 || true",
        )
        .await;
        if seen.contains("from the shell init") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        seen.contains("from the shell init") && seen.contains("probed"),
        "a login shell did not source the saved script: {seen}"
    );
    // The shell's output stays clean, which is what the check protects.
    let clean = guest(&runtime, &sandbox, "bash -lc true 2>&1; echo end").await;
    assert_eq!(
        clean, quiet_before,
        "the image's login shell said something new"
    );

    // A variable added while the workspace runs reaches the login shells opened from then on, with
    // no restart (the login-shell file is rewritten); one removed leaves them again.
    let reply = api
        .put(
            &format!("/api/workspaces/{name}/env/SHELL_INIT_LIVE_PROBE"),
            &json!({"kind": "plain", "value": "added while running"}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let live = |wanted: &'static str| {
        let (runtime, sandbox) = (&runtime, &sandbox);
        async move {
            let mut now = String::new();
            for _ in 0..100 {
                now = guest(
                    runtime,
                    sandbox,
                    "bash -lc 'echo \"[${SHELL_INIT_LIVE_PROBE-unset}]\"'",
                )
                .await;
                if now.trim() == wanted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!("a new login shell sees {now:?}, wanted {wanted}");
        }
    };
    live("[added while running]").await;
    assert_eq!(
        api.delete(
            &format!("/api/workspaces/{name}/env/SHELL_INIT_LIVE_PROBE"),
            None
        )
        .await
        .status,
        204
    );
    live("[unset]").await;

    // The guest cannot change it: not the file, not a new file beside it.
    let attempt = guest(
        &runtime,
        &sandbox,
        "echo evil >/puddle/shell-init/init.sh 2>/dev/null; echo \"write=$?\"; \
         touch /puddle/shell-init/new.sh 2>/dev/null; echo \"create=$?\"",
    )
    .await;
    assert!(
        !attempt.contains("write=0") && !attempt.contains("create=0"),
        "the guest changed the read-only folder: {attempt}"
    );
    assert!(
        !root
            .join("guest-share")
            .join("shell-init")
            .join(&name)
            .join("new.sh")
            .exists()
    );
    let folder = root.join("guest-share").join("shell-init").join(&name);
    assert_eq!(
        std::fs::read_to_string(folder.join("init.sh")).unwrap(),
        "export PUDDLE_SHELL_INIT_PROBE='from the shell init'\nshell_init_probe() { echo probed; }\n"
    );

    // The file that loads it is replaced from inside, and the next start says so and puts it back.
    // The variable change above runs the boot plan again in the guest, and that run is still
    // writing Puddle's files when the new value is first visible: it would put the loader back
    // over the replacement. The hook writes `boot.done` last, so wait for it.
    let mut settled = String::new();
    for _ in 0..100 {
        settled = guest(
            &runtime,
            &sandbox,
            "if [ -f /run/puddle/boot.done ]; then echo settled; else echo running; fi",
        )
        .await;
        if settled.trim() == "settled" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(settled.trim(), "settled", "the boot plan did not finish");
    guest(
        &runtime,
        &sandbox,
        "echo '# nothing to see' >/etc/profile.d/02-puddle-shell-init.sh",
    )
    .await;
    let replaced = guest(
        &runtime,
        &sandbox,
        "cat /etc/profile.d/02-puddle-shell-init.sh",
    )
    .await;
    assert_eq!(
        replaced.trim(),
        "# nothing to see",
        "the replacement did not stay"
    );
    let before_start = events.seen.len();
    api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    api.post(&format!("/api/workspaces/{name}/start"), "").await;
    // Wait for the end of the start, not for the notice: a notice that never comes must fail here
    // with what the hook said, not after the wait for a second event that it swallowed.
    let end = events
        .until(ended(name_static), Duration::from_secs(300))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    let boot_log = guest(&runtime, &sandbox, "cat /run/puddle/boot.log").await;
    assert!(
        events.seen[before_start..]
            .iter()
            .any(|e| e["type"] == "workspace_shell_init_restored" && e["workspace"] == name_static),
        "no notice that the guest replaced the file that loads the shell init; the hook said:\n{boot_log}"
    );
    let loader = guest(
        &runtime,
        &sandbox,
        "cat /etc/profile.d/02-puddle-shell-init.sh",
    )
    .await;
    assert!(loader.contains(". /puddle/shell-init/init.sh"), "{loader}");
    assert!(
        guest(
            &runtime,
            &sandbox,
            "bash -lc 'printenv PUDDLE_SHELL_INIT_PROBE'"
        )
        .await
        .contains("from the shell init")
    );

    // What a root process can try against the mount itself. Not an assertion about the VM: the
    // host's folder is what counts, and it is put right at the next start whatever happened.
    let tried = guest(
        &runtime,
        &sandbox,
        "(mount -o remount,rw /puddle/shell-init) 2>&1; (echo evil >/puddle/shell-init/evil.sh) 2>&1; echo end",
    )
    .await;
    let wrote = folder.join("evil.sh").exists();
    eprintln!("remount and write inside the guest: wrote to the host folder = {wrote}: {tried}");
    let from = events.seen.len();
    api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    api.post(&format!("/api/workspaces/{name}/start"), "").await;
    let end = events
        .until(ended(name_static), Duration::from_secs(300))
        .await;
    assert_eq!(end["step"], "done", "{end}");
    assert!(!folder.join("evil.sh").exists());
    assert_eq!(
        std::fs::read_to_string(folder.join("init.sh")).unwrap(),
        "export PUDDLE_SHELL_INIT_PROBE='from the shell init'\nshell_init_probe() { echo probed; }\n"
    );
    let told = events.seen[from..]
        .iter()
        .any(|e| e["type"] == "workspace_shell_init_restored");
    assert_eq!(
        told, wrote,
        "the user is told exactly when the guest changed the folder"
    );

    let stop = api.post(&format!("/api/workspaces/{name}/stop"), "").await;
    assert_eq!(stop.status, 202, "{}", stop.body);
    events
        .until(ended(name_static), Duration::from_secs(120))
        .await;
    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vm_host_boots_the_guest_with_the_development_certificate_and_its_key_stays_root_only() {
    let dev_cert = std::sync::Arc::new(TestDevCert::new());
    dev_cert.give();
    let mut options = options_without_injection();
    options.dev_cert = Some(dev_cert.clone());
    let VmHost {
        host,
        runtime,
        settings,
        ..
    } = start_vm_host_with("devc", options).await;

    let name = format!("{}-devc", settings.prefix.as_str());
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
    let reply = api
        .post(
            "/api/workspaces",
            &json!({"name": name, "repositories": [{"url": REPO}], "memory_mib": 1024}).to_string(),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    let name_static: &'static str = Box::leak(name.clone().into_boxed_str());
    let end = events
        .until(ended(name_static), Duration::from_secs(600))
        .await;
    assert_eq!(end["step"], "done", "{end}");

    // The real boot hook put the files in place: the key is root's alone, the certificate is in
    // the system store (a self-signed certificate verifies against a bundle that holds it), in
    // Node's extra roots and in the profile's variables.
    let out = guest(
        &runtime,
        &sandbox,
        "set -e
stat -c 'key %a %U' /etc/puddle/dev-cert/localhost.key
stat -c 'crt %a' /etc/puddle/dev-cert/localhost.crt
cmp /etc/puddle/dev-cert/localhost.crt /usr/local/share/ca-certificates/puddle-dev/localhost.crt && echo same-in-store
grep -c -F \"$(sed -n 2p /etc/puddle/dev-cert/localhost.crt)\" /etc/ssl/certs/ca-certificates.crt | sed 's/^/in-bundle /'
grep -c -F \"$(sed -n 2p /etc/puddle/dev-cert/localhost.crt)\" /etc/puddle/extra-cas.pem | sed 's/^/in-extra /'
grep -o 'DEV_CERT_PEM=[^ ]*' /etc/profile.d/01-puddle-env.sh
if command -v openssl >/dev/null; then openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/puddle/dev-cert/localhost.crt; fi",
    )
    .await;
    eprintln!("{out}");
    for line in [
        "key 600 root",
        "crt 644",
        "same-in-store",
        "in-bundle 1",
        "in-extra 1",
    ] {
        assert!(
            out.lines().any(|l| l == line),
            "missing {line:?} in:\n{out}"
        );
    }
    assert!(
        out.contains("DEV_CERT_PEM='/etc/puddle/dev-cert/localhost.crt'"),
        "{out}"
    );
    if out.contains("localhost.crt: ") {
        assert!(out.contains("localhost.crt: OK"), "{out}");
    }

    let down = host.shutdown().await;
    assert!(down.sandboxes.all_stopped(), "{down:?}");
}
