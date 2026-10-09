// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests with real clients: OpenSSH `ssh` and `git` in a guest-like setup, through the
//! `puddle-agent connect` binary as `ProxyCommand` (the drop-in `puddle-guest-env` writes), the
//! agent's listener, a Unix socket route and the real proxy. Every SSH connection is refused with
//! "SSH is not supported yet" on the client's own stderr; nothing reaches the rules, the inbox or
//! the resolver; what is inside the workspace stays direct.
//!
//! Needs `ssh` and `git` on `PATH`. Without them the tests say so and pass locally; with `CI` set
//! they fail instead.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_guest_env::{ProxySettings, SSH_CONFIG_GUEST, guest_proxy_config};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, CollectingConnectionLog, StaticPolicy, StaticResolver};
use puddle_proxy::{Proxy, Route};
use puddle_types::{
    BlockReason, ConnectionDecision, ConnectionReason, GuestPath, Host, NullSink, WorkspaceName,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const AGENT: &str = env!("CARGO_BIN_EXE_puddle-agent");

#[expect(
    clippy::print_stderr,
    reason = "a local run without ssh or git says that it skipped"
)]
fn clients_available() -> bool {
    let missing: Vec<&str> = ["ssh", "git"]
        .into_iter()
        .filter(|tool| {
            let flag = if *tool == "ssh" { "-V" } else { "--version" };
            Command::new(tool)
                .arg(flag)
                .output()
                .map_or(true, |o| !o.status.success())
        })
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI needs {missing:?} on PATH for this test"
    );
    eprintln!("skipped: {missing:?} not on PATH");
    false
}

fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

struct Rig {
    agent: Agent,
    policy: Arc<StaticPolicy>,
    resolver: Arc<StaticResolver>,
    log: Arc<CollectingConnectionLog>,
    dir: tempfile::TempDir,
    _route: Route,
    _root: IpcRoot,
}

impl Rig {
    async fn new(names: &[&str]) -> Self {
        let policy = Arc::new(StaticPolicy::new());
        let log = Arc::new(CollectingConnectionLog::new());
        let resolver = Arc::new(
            names
                .iter()
                .fold(StaticResolver::new(), |r, n| r.with(n, &[LOCAL])),
        );
        let proxy = Arc::new(
            Proxy::new(policy.clone(), Arc::new(NullSink))
                .with_connection_log(log.clone())
                .with_resolver(resolver.clone())
                .with_address_check(Arc::new(AnyAddress)),
        );
        let root = IpcRoot::new().unwrap();
        let route = proxy.serve_route(root.listen().unwrap(), WorkspaceName::new("box").unwrap());
        let agent = Agent::start(Config {
            listen: SocketAddr::new(LOCAL, 0),
            target: Target::Unix(route.endpoint().path().to_path_buf()),
            oom: None,
            bridge: None,
            ..Config::default()
        })
        .await
        .unwrap();
        Self {
            agent,
            policy,
            resolver,
            log,
            dir: tempfile::tempdir().unwrap(),
            _route: route,
            _root: root,
        }
    }

    /// The guest's `ssh_config` as the boot hook lays it out: puddle's drop-in, included first.
    /// `before` is what the user's own config says before the include (it wins).
    fn ssh_config(&self, before: &str) -> PathBuf {
        let settings = ProxySettings {
            agent: GuestPath::new(AGENT).unwrap(),
            ..ProxySettings::default()
        };
        let files = guest_proxy_config(&settings, &[]).unwrap().files;
        let drop_in = files
            .iter()
            .find(|f| f.path().as_str() == SSH_CONFIG_GUEST)
            .unwrap();
        let d = self.dir.path().join("ssh_config.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("00-puddle.conf"), drop_in.contents()).unwrap();
        let main = self.dir.path().join("ssh_config");
        std::fs::write(
            &main,
            format!(
                "{before}\nMatch all\nInclude {}/*.conf\nHost *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  BatchMode yes\n  ConnectTimeout 10\n",
                d.display()
            ),
        )
        .unwrap();
        main
    }

    /// Runs `program args` the way a guest process runs: the agent's address in the environment,
    /// no user config.
    async fn run(&self, program: &str, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let listen = self.agent.local_addr().to_string();
        let home = self.dir.path().display().to_string();
        let (program, args) = (
            program.to_owned(),
            args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(),
        );
        let envs: Vec<(String, String)> = envs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        tokio::task::spawn_blocking(move || {
            Command::new(program)
                .args(args)
                .env("PUDDLE_AGENT_LISTEN", listen)
                .env("HOME", home)
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .envs(envs)
                .stdin(Stdio::null())
                .output()
                .unwrap()
        })
        .await
        .unwrap()
    }

    async fn ssh(&self, config: &Path, args: &[&str]) -> Output {
        let config = config.display().to_string();
        let mut all = vec!["-T", "-F", config.as_str()];
        all.extend_from_slice(args);
        self.run("ssh", &all, &[]).await
    }

    /// Nothing of SSH reached the rules, the inbox or the resolver, and every connection that was
    /// recorded is an `ssh_unsupported` refusal.
    async fn assert_only_refusals(&self, expected: usize) {
        assert_eq!(self.policy.decisions(), 0, "the rules were never asked");
        assert!(self.policy.pending().is_empty(), "nothing in the inbox");
        assert_eq!(self.resolver.lookups(), 0, "nothing was resolved");
        let events = self.log.wait_for(expected, Duration::from_secs(5)).await;
        assert_eq!(events.len(), expected, "{events:?}");
        for event in events {
            assert_eq!(event.decision, ConnectionDecision::Blocked, "{event:?}");
            assert_eq!(
                event.reason,
                ConnectionReason::Blocked(BlockReason::SshUnsupported),
                "{event:?}"
            );
        }
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[tokio::test]
async fn ssh_to_a_git_host_is_refused_with_the_https_form_of_the_remote() {
    if !clients_available() {
        return;
    }
    let rig = Rig::new(&[]).await;
    let config = rig.ssh_config("");
    let out = rig
        .ssh(&config, &["git@github.com", "git-upload-pack 'o/r.git'"])
        .await;
    assert_eq!(out.status.code(), Some(255), "{}", stderr(&out));
    assert_eq!(out.stdout, b"");
    assert!(
        stderr(&out).contains(
            "puddle: SSH is not supported yet, use HTTPS: the remote becomes https://github.com/OWNER/REPO.git\n"
        ),
        "{}",
        stderr(&out)
    );
    // The same host over port 443, and the others on the list.
    for (args, https) in [
        (
            vec!["-p", "443", "git@ssh.github.com"],
            "https://github.com/OWNER/REPO.git",
        ),
        (
            vec!["git@gitlab.com"],
            "https://gitlab.com/GROUP/PROJECT.git",
        ),
        (
            vec!["git@bitbucket.org"],
            "https://bitbucket.org/WORKSPACE/REPO.git",
        ),
        (
            vec!["git@ssh.dev.azure.com"],
            "https://dev.azure.com/ORGANIZATION/PROJECT/_git/REPO",
        ),
        (
            vec!["org@vs-ssh.visualstudio.com"],
            "https://dev.azure.com/ORGANIZATION/PROJECT/_git/REPO",
        ),
    ] {
        let out = rig.ssh(&config, &args).await;
        assert!(
            stderr(&out).contains(&format!("the remote becomes {https}\n")),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    rig.assert_only_refusals(6).await;
}

#[tokio::test]
async fn ssh_to_any_other_host_and_port_gets_the_plain_message() {
    if !clients_available() {
        return;
    }
    let rig = Rig::new(&[]).await;
    let config = rig.ssh_config("");
    for args in [
        vec!["-p", "2222", "me@nas.example.test"],
        vec!["me@203.0.113.7"],
        vec!["me@[2001:db8::1]"],
        vec!["me@2001:db8::1"],
    ] {
        let out = rig.ssh(&config, &args).await;
        assert_eq!(out.status.code(), Some(255), "{args:?}");
        // The refusal comes first; ssh adds its own line about the connection closing.
        assert_eq!(
            stderr(&out).lines().next(),
            Some("puddle: SSH is not supported yet; no rule or setting allows it"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(!stderr(&out).contains("HTTPS"), "{args:?}");
    }
    rig.assert_only_refusals(4).await;
}

#[tokio::test]
async fn a_rule_that_allows_the_host_does_not_let_ssh_through() {
    if !clients_available() {
        return;
    }
    let rig = Rig::new(&[]).await;
    rig.policy.allow(&host("github.com"));
    let config = rig.ssh_config("");
    let out = rig.ssh(&config, &["git@github.com"]).await;
    assert!(
        stderr(&out).contains("SSH is not supported yet"),
        "{}",
        stderr(&out)
    );
    rig.assert_only_refusals(1).await;
}

#[tokio::test]
async fn git_over_ssh_shows_the_refusal_and_gets_nothing() {
    if !clients_available() {
        return;
    }
    let rig = Rig::new(&[]).await;
    let config = rig.ssh_config("");
    let ssh = format!("ssh -F {}", config.display());
    let clone_dir = rig.dir.path().join("clone");
    let clone = clone_dir.display().to_string();
    let out = rig
        .run(
            "git",
            &["clone", "git@github.com:owner/repo.git", &clone],
            &[("GIT_SSH_COMMAND", &ssh)],
        )
        .await;
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("puddle: SSH is not supported yet, use HTTPS: the remote becomes https://github.com/OWNER/REPO.git"),
        "{}",
        stderr(&out)
    );
    assert!(!clone_dir.exists(), "nothing was cloned");
    // The `ssh://` form on the port GitHub offers for networks that block 22.
    let out = rig
        .run(
            "git",
            &["ls-remote", "ssh://git@ssh.github.com:443/owner/repo.git"],
            &[("GIT_SSH_COMMAND", &ssh)],
        )
        .await;
    assert_eq!(out.status.code(), Some(128), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("puddle: SSH is not supported yet, use HTTPS"),
        "{}",
        stderr(&out)
    );
    rig.assert_only_refusals(2).await;
}

#[tokio::test]
async fn what_is_inside_the_workspace_stays_direct_and_the_users_own_proxy_command_wins() {
    if !clients_available() {
        return;
    }
    let rig = Rig::new(&[]).await;
    let config = rig.ssh_config(
        "Host user-proxy.test\n  ProxyCommand sh -c 'echo user-proxy-ran >&2; exit 255'\n",
    );
    let drop_in = format!("'{AGENT}' connect");
    for (target, through_agent) in [
        ("github.com", true),
        ("nas.example.test", true),
        ("localhost", false),
        ("127.0.0.1", false),
        ("::1", false),
        ("172.17.0.5", false),
        ("user-proxy.test", false),
    ] {
        let out = rig.ssh(&config, &["-G", target]).await;
        let dump = String::from_utf8_lossy(&out.stdout).into_owned();
        let proxy_command = dump.lines().find(|l| l.starts_with("proxycommand "));
        assert_eq!(
            proxy_command.is_some_and(|l| l.contains(&drop_in)),
            through_agent,
            "{target}: {proxy_command:?}"
        );
    }
    // A connection to loopback is ssh's own, not the agent's: a closed port is refused by the
    // kernel and said so by ssh, and the proxy never heard of it.
    let closed = {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        listener.local_addr().unwrap().port().to_string()
    };
    let out = rig.ssh(&config, &["-p", &closed, "me@localhost"]).await;
    assert!(
        stderr(&out).contains("Connection refused"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("puddle"), "{}", stderr(&out));
    let out = rig.ssh(&config, &["me@user-proxy.test"]).await;
    assert!(stderr(&out).contains("user-proxy-ran"), "{}", stderr(&out));
    assert!(rig.log.events().is_empty(), "the proxy was never asked");
}

#[tokio::test]
async fn the_connect_command_carries_what_is_not_ssh() {
    let rig = Rig::new(&["echo.test"]).await;
    rig.policy.allow(&host("echo.test"));
    let echo = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let listen = rig.agent.local_addr().to_string();
    let mut child = tokio::process::Command::new(AGENT)
        .args(["connect", "echo.test", &port.to_string(), "alias"])
        .env("PUDDLE_AGENT_LISTEN", listen)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"hello, not ssh\n").await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    let out = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .expect("the command ends when the echo does")
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(out.stdout, b"hello, not ssh\n");
    assert!(out.stderr.is_empty(), "{}", stderr(&out));
    // The destination was an ordinary one: decided by the rules, recorded as allowed.
    let events = rig.log.wait_for(1, Duration::from_secs(5)).await;
    assert_eq!(events.first().unwrap().decision, ConnectionDecision::Allow);
}

#[test]
fn the_connect_command_without_a_destination_is_a_usage_error() {
    let out = Command::new(AGENT).arg("connect").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("usage: puddle-agent connect <host> <port> [<name>]"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_connect_command_with_a_bad_environment_says_so() {
    let out = Command::new(AGENT)
        .args(["connect", "github.com", "22"])
        .env("PUDDLE_AGENT_LISTEN", "not an address")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr(&out).contains("PUDDLE_AGENT_LISTEN"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_connect_command_with_no_agent_listening_says_so() {
    let closed = {
        let listener = std::net::TcpListener::bind((LOCAL, 0)).unwrap();
        listener.local_addr().unwrap()
    };
    let out = Command::new(AGENT)
        .args(["connect", "github.com", "22"])
        .env("PUDDLE_AGENT_LISTEN", closed.to_string())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr(&out).contains(&format!("github.com:22 through {closed}")),
        "{}",
        stderr(&out)
    );
}
