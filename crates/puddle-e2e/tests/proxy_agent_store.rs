// SPDX-License-Identifier: GPL-3.0-or-later
//! L2 end to end, no VM: a guest TCP client → the real guest agent → yamux over the sandbox's
//! real endpoint (`puddle-ipc`, a Unix socket) → the real proxy → local servers, with the real
//! SQLite rules engine (`puddle-store`) as the policy and as the proxy's connection log, so every
//! connection ends as a `connection` audit record (R-24).
//!
//! The only doubles are the resolver (`*.test` names point at loopback) and the address check
//! (loopback is where the test servers are).
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticResolver};
use puddle_proxy::{Proxy, Route};
use puddle_store::{
    Actor, Effect, Limits, NewRule, Pattern, PendingState, Resolution, Scope, Store, SystemClock,
};
use puddle_types::{NullSink, SandboxName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn sandbox() -> SandboxName {
    SandboxName::new("e2e").unwrap()
}

struct Rig {
    store: Arc<Store>,
    agent: Agent,
    route: Route,
    _root: IpcRoot,
}

async fn rig() -> Rig {
    let store = Arc::new(Store::open_in_memory(Arc::new(SystemClock), Limits::default()).unwrap());
    let resolver = StaticResolver::new()
        .with("echo.test", &[LOCAL])
        .with("sink.test", &[LOCAL])
        .with("new.test", &[LOCAL]);
    let proxy = Arc::new(
        Proxy::new(store.clone(), Arc::new(NullSink))
            .with_connection_log(store.clone())
            .with_resolver(Arc::new(resolver))
            .with_address_check(Arc::new(AnyAddress)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), sandbox());
    let config = Config {
        listen: SocketAddr::new(LOCAL, 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        // Never the machine's real docker0.
        bridge: None,
        ..Config::default()
    };
    let agent = Agent::start(config).await.unwrap();
    Rig {
        store,
        agent,
        route,
        _root: root,
    }
}

fn allow(store: &Store, host: &str) {
    store
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sandbox()),
            pattern: Pattern::parse(host).unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
}

/// The `connection` audit records so far, oldest first.
fn connection_records(store: &Store) -> Vec<Value> {
    store
        .audit_lines(0, 100_000)
        .unwrap()
        .into_iter()
        .map(|(_, line)| serde_json::from_str::<Value>(&line).unwrap())
        .filter(|v| v["type"] == "connection")
        .collect()
}

/// Waits up to 5 s for at least `count` `connection` records (one is written when its
/// connection ends, after the guest has its answer).
async fn wait_for_records(store: &Store, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let records = connection_records(store);
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

/// An echo server: sends back everything, then closes after the client's FIN.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// Sends `CONNECT authority` through the agent; returns the status code and the connection.
async fn connect_via(
    agent: SocketAddr,
    authority: &str,
) -> io::Result<(u16, BufReader<TcpStream>)> {
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
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await?;
        if h == "\r\n" || h.is_empty() {
            return Ok((code, reader));
        }
    }
}

async fn round_trip(agent: SocketAddr, authority: &str, i: usize) -> io::Result<Duration> {
    let started = Instant::now();
    let (code, mut conn) = connect_via(agent, authority).await?;
    if code != 200 {
        return Err(io::Error::other(format!("connection {i}: status {code}")));
    }
    let payload: Vec<u8> = (0..64 * 1024usize)
        .map(|n| u8::try_from((n + i) % 251).unwrap())
        .collect();
    let (mut rd, mut wr) = tokio::io::split(&mut conn);
    let upload = async {
        wr.write_all(&payload).await?;
        wr.shutdown().await
    };
    let mut back = Vec::new();
    let download = rd.read_to_end(&mut back);
    let (up, down) = tokio::join!(upload, download);
    up?;
    down?;
    if back != payload {
        return Err(io::Error::other(format!("connection {i}: echo mismatch")));
    }
    Ok(started.elapsed())
}

/// The load bar through the real agent and the real rules engine: 256 parallel `CONNECT`s,
/// 0 failures, none slower than 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_connects_256_through_agent_proxy_and_store() {
    let rig = rig().await;
    allow(&rig.store, "echo.test");
    let echo = echo_server().await;
    let authority = format!("echo.test:{}", echo.port());
    let agent = rig.agent.local_addr();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..256 {
        let authority = authority.clone();
        set.spawn(async move { round_trip(agent, &authority, i).await });
    }
    let results = tokio::time::timeout(Duration::from_secs(60), async {
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.unwrap());
        }
        out
    })
    .await
    .expect("256 connections did not finish within 60 s");
    let failures: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert!(
        failures.is_empty(),
        "{} of 256 failed: {:?}",
        failures.len(),
        failures.first()
    );
    let slowest = results
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .max()
        .unwrap();
    assert!(
        *slowest < Duration::from_secs(5),
        "slowest connection took {slowest:?}"
    );
    assert_eq!(rig.store.open_pending(None).unwrap().len(), 0);

    // Every connection is in the audit: written, or counted in a `suppressed` summary once its
    // second is over (200 records per sandbox per second, R-26).
    let deadline = Instant::now() + Duration::from_secs(10);
    let accounted = loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        rig.store.sweep().unwrap();
        let records = connection_records(&rig.store);
        let written = records.iter().filter(|r| r["reason"] == "rule").count() as u64;
        let summarised: u64 = records.iter().filter_map(|r| r["count"].as_u64()).sum();
        if written + summarised >= 256 || Instant::now() >= deadline {
            break written + summarised;
        }
    };
    assert_eq!(accounted, 256);
}

/// R-24/R-25 end to end: the proxy's connection events land in the store's audit with decision,
/// rule or pending row, address and bytes, and no query string.
#[tokio::test]
async fn connections_land_in_the_store_audit() {
    const CANARY: &str = "CANARY-e2e-5b7d";
    let rig = rig().await;
    let echo = echo_server().await;
    let agent = rig.agent.local_addr();

    let pending = format!("new.test:{}", echo.port());
    let (code, _) = connect_via(agent, &pending).await.unwrap();
    assert_eq!(code, 403);
    let row = rig.store.open_pending(Some(&sandbox())).unwrap()[0].id;
    wait_for_records(&rig.store, 1).await;

    let mut conn = TcpStream::connect(agent).await.unwrap();
    conn.write_all(
        format!(
            "GET http://{pending}/p/q?token={CANARY}#{CANARY} HTTP/1.1\r\nHost: new.test\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut answer = String::new();
    conn.read_to_string(&mut answer).await.unwrap();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    wait_for_records(&rig.store, 2).await;

    allow(&rig.store, "echo.test");
    let authority = format!("echo.test:{}", echo.port());
    let (code, mut conn) = connect_via(agent, &authority).await.unwrap();
    assert_eq!(code, 200);
    conn.get_mut().write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    conn.read_exact(&mut back).await.unwrap();
    conn.get_mut().shutdown().await.unwrap();
    let mut rest = Vec::new();
    conn.read_to_end(&mut rest).await.unwrap();
    let records = wait_for_records(&rig.store, 3).await;

    let fields = |r: &Value| {
        (
            r["sandbox_id"].clone(),
            r["host"].clone(),
            r["decision"].clone(),
            r["reason"].clone(),
            r["pending_id"].clone(),
        )
    };
    let pending_record = |r: &Value| {
        (
            Value::from("e2e"),
            Value::from("new.test"),
            Value::from("pending"),
            Value::from("no_rule"),
            Value::from(row.0),
        ) == fields(r)
    };
    assert!(pending_record(&records[0]), "{}", records[0]);
    assert!(pending_record(&records[1]), "{}", records[1]);
    assert!(records[0]["method"].is_null());
    assert_eq!(
        (&records[1]["method"], &records[1]["path"]),
        (&Value::from("GET"), &Value::from("/p/q"))
    );

    let allowed = &records[2];
    assert_eq!(
        (
            &allowed["host"],
            &allowed["decision"],
            &allowed["reason"],
            &allowed["resolved_ip"]
        ),
        (
            &Value::from("echo.test"),
            &Value::from("allow"),
            &Value::from("rule"),
            &Value::from("127.0.0.1")
        )
    );
    assert!(allowed["rule_id"].is_i64());
    let head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    let established = "HTTP/1.1 200 Connection Established\r\n\r\n";
    assert_eq!(allowed["bytes_up"], head.len() + 4);
    assert_eq!(allowed["bytes_down"], established.len() + 4);

    for (_, line) in rig.store.audit_lines(0, 1000).unwrap() {
        assert!(!line.contains(CANARY), "{line}");
    }
}

/// Deny ⇒ 403 and a pending row in the store; approving the row ⇒ the next attempt passes
/// without restarting anything (R-8, R-10, R-15).
#[tokio::test]
async fn an_unknown_host_is_pending_in_the_store_and_passes_after_approval() {
    let rig = rig().await;
    let echo = echo_server().await;
    let authority = format!("new.test:{}", echo.port());
    let agent = rig.agent.local_addr();

    let (code, mut conn) = connect_via(agent, &authority).await.unwrap();
    assert_eq!(code, 403);
    let mut body = String::new();
    conn.read_to_string(&mut body).await.unwrap();
    assert!(body.contains("approve it in puddle"), "{body}");

    let open = rig.store.open_pending(Some(&sandbox())).unwrap();
    assert_eq!(open.len(), 1);
    let row = &open[0];
    assert_eq!(
        (row.host.to_string(), row.port, row.state),
        ("new.test".to_owned(), echo.port(), PendingState::Requested)
    );

    // A second attempt before approval is a repeat of the same row (R-11).
    let (code, _) = connect_via(agent, &authority).await.unwrap();
    assert_eq!(code, 403);
    assert_eq!(rig.store.pending(row.id).unwrap().attempts, 2);

    rig.store
        .resolve_pending(row.id, &Resolution::allow(), Actor::Cli)
        .unwrap();
    let (code, mut conn) = connect_via(agent, &authority).await.unwrap();
    assert_eq!(code, 200);
    conn.get_mut().write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    assert_eq!(rig.store.open_pending(None).unwrap().len(), 0);
}

/// How a server-side connection ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Eof(usize),
    Reset(usize),
    Other(String),
}

/// A sink server: reads to the end and reports how it ended; signals after the first bytes.
async fn sink_server() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<End>,
    mpsc::UnboundedReceiver<()>,
) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (end_tx, ends) = mpsc::unbounded_channel();
    let (first_tx, firsts) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            let (end_tx, first_tx) = (end_tx.clone(), first_tx.clone());
            tokio::spawn(async move {
                let mut total = 0;
                let mut buf = vec![0u8; 16 * 1024];
                let end = loop {
                    match conn.read(&mut buf).await {
                        Ok(0) => break End::Eof(total),
                        Ok(n) => {
                            if total == 0 {
                                let _ = first_tx.send(());
                            }
                            total += n;
                        }
                        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                            break End::Reset(total);
                        }
                        Err(e) => break End::Other(e.to_string()),
                    }
                };
                let _ = end_tx.send(end);
            });
        }
    });
    (addr, ends, firsts)
}

/// Through the product proxy: an aborted upload reaches the server as a reset, not as a
/// complete-looking EOF.
#[tokio::test]
async fn an_aborted_guest_upload_reaches_the_server_as_a_reset() {
    let rig = rig().await;
    allow(&rig.store, "sink.test");
    let (sink, mut ends, mut firsts) = sink_server().await;
    let authority = format!("sink.test:{}", sink.port());
    let (code, mut conn) = connect_via(rig.agent.local_addr(), &authority)
        .await
        .unwrap();
    assert_eq!(code, 200);
    conn.get_mut()
        .write_all(&vec![7u8; 32 * 1024])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), firsts.recv())
        .await
        .unwrap();
    conn.get_ref().set_zero_linger().unwrap();
    drop(conn);
    let end = tokio::time::timeout(Duration::from_secs(5), ends.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(end, End::Reset(_)),
        "server saw {end:?}, not a reset"
    );
}

#[tokio::test]
async fn a_graceful_upload_reaches_the_server_complete() {
    let rig = rig().await;
    allow(&rig.store, "sink.test");
    let (sink, mut ends, _firsts) = sink_server().await;
    let authority = format!("sink.test:{}", sink.port());
    let (code, mut conn) = connect_via(rig.agent.local_addr(), &authority)
        .await
        .unwrap();
    assert_eq!(code, 200);
    conn.get_mut().write_all(&vec![7u8; 1 << 20]).await.unwrap();
    conn.get_mut().shutdown().await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(10), ends.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, End::Eof(1 << 20));
}

#[tokio::test]
async fn a_server_reset_reaches_the_guest_client_as_a_reset() {
    let rig = rig().await;
    allow(&rig.store, "echo.test");
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go_tx, go_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        conn.write_all(b"partial").await.unwrap();
        let _ = go_rx.await;
        conn.set_zero_linger().unwrap();
        drop(conn);
    });
    let (code, mut conn) = connect_via(rig.agent.local_addr(), &format!("echo.test:{port}"))
        .await
        .unwrap();
    assert_eq!(code, 200);
    let mut first = [0u8; 7];
    conn.read_exact(&mut first).await.unwrap();
    go_tx.send(()).unwrap();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
        .await
        .unwrap();
    assert_eq!(
        read.map_err(|e| e.kind()).err(),
        Some(io::ErrorKind::ConnectionReset),
        "the guest client must see the reset, not a clean end"
    );
}

/// A probe that always finds a bridge at index 1: the kernel's docker0, faked.
struct BridgeUp;

impl puddle_agent::bridge::Probe for BridgeUp {
    fn find(&self, _: Ipv4Addr) -> Option<u32> {
        Some(1)
    }
}

/// A request that arrives on the Docker bridge listener meets the same policy and lands
/// in the same audit as one on the loopback listener: same sandbox, same pending row (the
/// repeat bumps `attempts`), same rule once approved, same record shape.
#[tokio::test]
async fn the_bridge_listener_gets_the_same_policy_and_audit_as_loopback() {
    let rig = rig().await;
    // A second agent on the same route, listening on the faked bridge address (127.0.0.2).
    let config = Config {
        listen: SocketAddr::new(LOCAL, 0),
        target: Target::Unix(rig.route.endpoint().path().to_path_buf()),
        oom: None,
        bridge: Some(puddle_agent::config::BridgeConfig {
            addr: std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
            poll: Duration::from_millis(10),
        }),
        ..Config::default()
    };
    let agent = Agent::start_with_probe(config, Arc::new(BridgeUp))
        .await
        .unwrap();
    let mut state = agent.bridge_state();
    let bridge = tokio::time::timeout(
        Duration::from_secs(10),
        state.wait_for(|s| s.addr.is_some()),
    )
    .await
    .unwrap()
    .unwrap()
    .addr
    .unwrap();
    let echo = echo_server().await;
    let authority = format!("new.test:{}", echo.port());

    // Unknown host: refused and pending, on both listeners.
    let (code, _) = connect_via(rig.agent.local_addr(), &authority)
        .await
        .unwrap();
    assert_eq!(code, 403);
    let (code, _) = connect_via(bridge, &authority).await.unwrap();
    assert_eq!(code, 403);
    let pending = rig.store.open_pending(Some(&sandbox())).unwrap();
    assert_eq!(pending.len(), 1, "one pending item for both listeners");
    assert_eq!(pending[0].attempts, 2);
    let records = wait_for_records(&rig.store, 2).await;
    let shape = |r: &Value| {
        (
            r["sandbox_id"].clone(),
            r["host"].clone(),
            r["decision"].clone(),
            r["reason"].clone(),
            r["pending_id"].clone(),
        )
    };
    assert_eq!(shape(&records[0]), shape(&records[1]));

    // One approval covers both; the bridge then tunnels.
    allow(&rig.store, "new.test");
    let (code, mut conn) = connect_via(bridge, &authority).await.unwrap();
    assert_eq!(code, 200);
    conn.get_mut().write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    drop(conn);
    let records = wait_for_records(&rig.store, 3).await;
    assert_eq!(records[2]["decision"], "allow");
    assert_eq!(records[2]["sandbox_id"], "e2e");
}
