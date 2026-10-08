// SPDX-License-Identifier: GPL-3.0-or-later
//! Regression test, L2 with a real client: Node `fetch` with `NODE_USE_ENV_PROXY=1` (what
//! `puddle-guest-env` sets in the guest) sends a plain `http://` URL as a `CONNECT host:port`
//! tunnel, not as an absolute-form request. Through the real agent, proxy and SQLite store, such a
//! tunnel must be decided like any request (pending until allowed), work once allowed, and be
//! audited with its method and path.
//!
//! Needs `node` 24 or newer on `PATH` (CI installs it for the openapi gate). Without it the tests
//! say so and pass locally; with `CI` set they fail instead.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticResolver};
use puddle_proxy::{Proxy, Route};
use puddle_store::{Actor, Effect, Limits, NewRule, Pattern, Scope, Store, SystemClock};
use puddle_types::{NullSink, WorkspaceName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const CANARY: &str = "CANARY-node-9c1e";

fn workspace() -> WorkspaceName {
    WorkspaceName::new("node").unwrap()
}

struct Rig {
    store: Arc<Store>,
    agent: Agent,
    _route: Route,
    _root: IpcRoot,
}

async fn rig() -> Rig {
    let store = Arc::new(Store::open_in_memory(Arc::new(SystemClock), Limits::default()).unwrap());
    let resolver = StaticResolver::new()
        .with("node.test", &[LOCAL])
        .with("new.test", &[LOCAL]);
    let proxy = Arc::new(
        Proxy::new(store.clone(), Arc::new(NullSink))
            .with_connection_log(store.clone())
            .with_resolver(Arc::new(resolver))
            .with_address_check(Arc::new(AnyAddress)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), workspace());
    let config = Config {
        listen: SocketAddr::new(LOCAL, 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        ..Config::default()
    };
    let agent = Agent::start(config).await.unwrap();
    Rig {
        store,
        agent,
        _route: route,
        _root: root,
    }
}

/// Whether a `node` that honours `NODE_USE_ENV_PROXY` (24+) is on `PATH`. Panics in CI when not.
#[expect(
    clippy::print_stderr,
    reason = "a local run without node says that it skipped"
)]
fn node_available() -> bool {
    let version = Command::new("node")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
    let major = version
        .as_deref()
        .and_then(|v| v.strip_prefix('v')?.split('.').next()?.parse::<u32>().ok());
    if major.is_some_and(|m| m >= 24) {
        return true;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI needs node 24+ on PATH for this test (found {version:?})"
    );
    eprintln!("skipped: node 24+ not on PATH (found {version:?})");
    false
}

/// Runs Node `fetch(url)` through the agent at `proxy` with the guest's proxy env; returns
/// whether it succeeded and what it printed (`<status> <body>` or `error <cause>`).
async fn node_fetch(proxy: SocketAddr, url: String) -> (bool, String) {
    const SCRIPT: &str = "fetch(process.argv[1]).then(async r => console.log(r.status + ' ' + await r.text())).catch(e => { console.log('error ' + ((e.cause && e.cause.message) || e.message)); process.exitCode = 1; })";
    tokio::task::spawn_blocking(move || {
        let proxy = format!("http://{proxy}");
        let out = Command::new("node")
            .args(["-e", SCRIPT, &url])
            .env("NODE_USE_ENV_PROXY", "1")
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        )
    })
    .await
    .unwrap()
}

/// An HTTP server that answers every request with `hello` and sends each request head to the
/// test.
async fn http_server() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(conn);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let _ = tx.send(head);
                let response =
                    "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello";
                let _ = reader.get_mut().write_all(response.as_bytes()).await;
                let _ = reader.get_mut().shutdown().await;
            });
        }
    });
    (addr, rx)
}

/// The `connection` audit records, waiting up to 5 s for at least `count`.
async fn connection_records(store: &Store, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let records: Vec<Value> = store
            .audit_lines(0, 100_000)
            .unwrap()
            .into_iter()
            .map(|(_, line)| {
                assert!(!line.contains(CANARY), "query string in the audit: {line}");
                serde_json::from_str::<Value>(&line).unwrap()
            })
            .filter(|v| v["type"] == "connection")
            .collect();
        if records.len() >= count || Instant::now() >= deadline {
            assert!(
                records.len() >= count,
                "{count} records expected: {records:?}"
            );
            return records;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn node_fetch_of_plain_http_is_pending_then_allowed_and_audited_with_method_and_path() {
    if !node_available() {
        return;
    }
    let rig = rig().await;
    let (server, mut heads) = http_server().await;
    let agent = rig.agent.local_addr();
    let url = format!("http://node.test:{}/some/path?q={CANARY}", server.port());

    // Unknown name: Node's CONNECT is refused and the name is waiting in the inbox.
    let (ok, out) = node_fetch(agent, url.clone()).await;
    assert!(!ok, "fetch passed before any rule: {out}");
    let pending = rig.store.open_pending(Some(&workspace())).unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let records = connection_records(&rig.store, 1).await;
    assert_eq!(
        (
            &records[0]["decision"],
            &records[0]["host"],
            &records[0]["port"]
        ),
        (
            &Value::from("pending"),
            &Value::from("node.test"),
            &Value::from(server.port())
        ),
        "{records:?}"
    );
    assert!(heads.try_recv().is_err(), "the server was reached");

    // Allowed: the request reaches the server unchanged and is audited with method and path.
    rig.store
        .add_rule(&NewRule {
            scope: Scope::Workspace(workspace()),
            pattern: Pattern::parse("node.test").unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
    let (ok, out) = node_fetch(agent, url).await;
    assert!(ok, "fetch failed once allowed: {out}");
    assert_eq!(out, "200 hello");
    let head = heads.recv().await.unwrap();
    assert!(
        head.starts_with(&format!("GET /some/path?q={CANARY} HTTP/1.1\r\n")),
        "{head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains(&format!("\r\nhost: node.test:{}\r\n", server.port())),
        "{head}"
    );
    let records = connection_records(&rig.store, 2).await;
    let allowed = &records[1];
    assert_eq!(
        (
            &allowed["decision"],
            &allowed["method"],
            &allowed["path"],
            &allowed["resolved_ip"]
        ),
        (
            &Value::from("allow"),
            &Value::from("GET"),
            &Value::from("/some/path"),
            &Value::from("127.0.0.1")
        ),
        "{allowed}"
    );
}
