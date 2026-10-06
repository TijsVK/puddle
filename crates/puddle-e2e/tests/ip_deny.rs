// SPDX-License-Identifier: GPL-3.0-or-later
//! R-27 end to end, no VM: an exact deny of an address wins over every rule for a name, with the
//! real agent, proxy and SQLite rules engine. A guest TCP client → the real guest agent → the
//! real proxy → servers on `127.0.0.1` (allowed) and `127.0.0.2` (denied by an IP rule).
//!
//! Linux only: it needs all of `127.0.0.0/8` on loopback. The doubles are the resolver (`*.test`
//! names) and the address check (loopback is where the test servers are).
#![cfg(target_os = "linux")]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticResolver};
use puddle_proxy::{Proxy, Route};
use puddle_store::{
    Actor, Effect, Limits, ManualClock, NewRule, Pattern, Resolution, Rule, Scope, Store,
};
use puddle_types::{NullSink, SandboxName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const ALLOWED: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DENIED: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const NOW: u64 = 1_800_000_000_000;

fn sandbox() -> SandboxName {
    SandboxName::new("e2e-r27").unwrap()
}

struct Rig {
    store: Arc<Store>,
    clock: Arc<ManualClock>,
    agent: Agent,
    _route: Route,
    _root: IpcRoot,
}

async fn rig() -> Rig {
    let clock = Arc::new(ManualClock::new(NOW));
    let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
    let resolver = StaticResolver::new()
        .with("named.test", &[DENIED])
        .with("a.wild.test", &[DENIED])
        .with("mixed.test", &[DENIED, ALLOWED])
        .with("new.test", &[DENIED]);
    let proxy = Arc::new(
        Proxy::new(store.clone(), Arc::new(NullSink))
            .with_connection_log(store.clone())
            .with_resolver(Arc::new(resolver))
            .with_address_check(Arc::new(AnyAddress)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), sandbox());
    let config = Config {
        listen: SocketAddr::new(ALLOWED, 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        ..Config::default()
    };
    let agent = Agent::start(config).await.unwrap();
    Rig {
        store,
        clock,
        agent,
        _route: route,
        _root: root,
    }
}

fn rule(
    store: &Store,
    scope: Scope,
    pattern: &str,
    effect: Effect,
    expires_at: Option<u64>,
) -> Rule {
    store
        .add_rule(&NewRule {
            scope,
            pattern: Pattern::parse(pattern).unwrap(),
            effect,
            expires_at,
            created_by: Actor::Cli,
        })
        .unwrap()
}

/// Servers on the same port at both addresses: an echo on [`ALLOWED`], and on [`DENIED`] one
/// that counts the connections it accepts (any is a failure unless the test expects it).
async fn servers() -> (u16, Arc<AtomicUsize>) {
    let trap = TcpListener::bind((DENIED, 0)).await.unwrap();
    let port = trap.local_addr().unwrap().port();
    let echo = TcpListener::bind((ALLOWED, port)).await.unwrap();
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = reached.clone();
    tokio::spawn(async move {
        loop {
            let (conn, _) = trap.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            drop(conn);
        }
    });
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
    (port, reached)
}

/// The answer to `CONNECT authority` through the agent: status code, header lines, connection.
async fn connect_via(
    agent: SocketAddr,
    authority: &str,
) -> io::Result<(u16, Vec<String>, BufReader<TcpStream>)> {
    let mut conn = TcpStream::connect(agent).await?;
    conn.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let code = line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other(format!("bad status line {line:?}")))?;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await?;
        if h == "\r\n" || h.is_empty() {
            return Ok((code, headers, reader));
        }
        headers.push(h.trim_end().to_owned());
    }
}

/// Asserts `CONNECT name:port` is a deny by `rule`, with no pending row.
async fn assert_denied_by(rig: &Rig, name: &str, port: u16, rule: &Rule) {
    let (code, headers, _) = connect_via(rig.agent.local_addr(), &format!("{name}:{port}"))
        .await
        .unwrap();
    assert_eq!(code, 403, "{name}");
    assert!(
        headers.contains(&"x-puddle-decision: deny".to_owned()),
        "{name}: {headers:?}"
    );
    assert!(
        headers.contains(&format!("x-puddle-rule: {}", rule.id)),
        "{name}: {headers:?}"
    );
    assert_eq!(rig.store.open_pending(None).unwrap().len(), 0, "{name}");
}

/// Echoes `ping` over an open tunnel.
async fn ping(conn: &mut BufReader<TcpStream>) {
    conn.get_mut().write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
}

/// The `connection` audit records so far, after waiting up to 5 s for at least `count`.
async fn connection_records(store: &Store, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let records: Vec<Value> = store
            .audit_lines(0, 10_000)
            .unwrap()
            .into_iter()
            .map(|(_, line)| serde_json::from_str::<Value>(&line).unwrap())
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
async fn r27_an_ip_deny_wins_over_exact_wildcard_and_approved_name_allows() {
    let rig = rig().await;
    let (port, reached) = servers().await;
    let deny = rule(&rig.store, Scope::Global, "127.0.0.2", Effect::Deny, None);
    let in_sandbox = || Scope::Sandbox(sandbox());
    rule(&rig.store, in_sandbox(), "named.test", Effect::Allow, None);
    rule(&rig.store, in_sandbox(), "mixed.test", Effect::Allow, None);
    rule(&rig.store, in_sandbox(), "*.wild.test", Effect::Allow, None);

    // An exact name allow and a wildcard allow: denied by the IP rule, nothing pending.
    assert_denied_by(&rig, "named.test", port, &deny).await;
    assert_denied_by(&rig, "a.wild.test", port, &deny).await;

    // A mixed answer: only the address no rule denies is used.
    let (code, _, mut conn) = connect_via(rig.agent.local_addr(), &format!("mixed.test:{port}"))
        .await
        .unwrap();
    assert_eq!(code, 200);
    ping(&mut conn).await;
    drop(conn);

    // An unknown name goes pending (it is never resolved before a rule allows it, R-10); once
    // approved, the IP rule still denies it.
    let (code, _, _) = connect_via(rig.agent.local_addr(), &format!("new.test:{port}"))
        .await
        .unwrap();
    assert_eq!(code, 403);
    let row = rig.store.open_pending(None).unwrap()[0].id;
    rig.store
        .resolve_pending(row, &Resolution::allow(), Actor::Cli)
        .unwrap();
    assert_denied_by(&rig, "new.test", port, &deny).await;

    assert_eq!(
        reached.load(Ordering::SeqCst),
        0,
        "a denied address was reached"
    );
    let records = connection_records(&rig.store, 5).await;
    let denials: Vec<&Value> = records.iter().filter(|r| r["decision"] == "deny").collect();
    assert_eq!(denials.len(), 3, "{records:?}");
    for record in denials {
        assert_eq!(
            (
                &record["reason"],
                &record["rule_id"],
                &record["resolved_ip"]
            ),
            (
                &Value::from("rule"),
                &Value::from(deny.id.0),
                &Value::from("127.0.0.2")
            ),
            "{record}"
        );
    }
    let mixed = records.iter().find(|r| r["host"] == "mixed.test").unwrap();
    assert_eq!(
        (&mixed["decision"], &mixed["resolved_ip"]),
        (&Value::from("allow"), &Value::from("127.0.0.1"))
    );
}

#[tokio::test]
async fn r27_a_sandbox_ip_deny_counts_until_it_expires() {
    let rig = rig().await;
    let (port, reached) = servers().await;
    let deny = rule(
        &rig.store,
        Scope::Sandbox(sandbox()),
        "127.0.0.2",
        Effect::Deny,
        Some(NOW + 60_000),
    );
    rule(&rig.store, Scope::Global, "named.test", Effect::Allow, None);
    assert_denied_by(&rig, "named.test", port, &deny).await;
    assert_eq!(reached.load(Ordering::SeqCst), 0);

    // Expired (R-7): the address is reachable again through the name's allow.
    rig.clock.advance(60_000);
    let (code, _, _) = connect_via(rig.agent.local_addr(), &format!("named.test:{port}"))
        .await
        .unwrap();
    assert_eq!(code, 200);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

/// The IP's own rules decide with R-6 precedence: a sandbox allow of the address beats a global
/// deny of it, as it would for a request to the literal (T-095 default).
#[tokio::test]
async fn r27_a_sandbox_ip_allow_overrides_a_global_ip_deny_as_for_the_literal() {
    let rig = rig().await;
    let (port, reached) = servers().await;
    rule(&rig.store, Scope::Global, "127.0.0.2", Effect::Deny, None);
    rule(
        &rig.store,
        Scope::Sandbox(sandbox()),
        "127.0.0.2",
        Effect::Allow,
        None,
    );
    rule(&rig.store, Scope::Global, "named.test", Effect::Allow, None);
    let agent = rig.agent.local_addr();
    for authority in [format!("127.0.0.2:{port}"), format!("named.test:{port}")] {
        let (code, _, _) = connect_via(agent, &authority).await.unwrap();
        assert_eq!(code, 200, "{authority}");
    }
    assert_eq!(reached.load(Ordering::SeqCst), 2);
}
