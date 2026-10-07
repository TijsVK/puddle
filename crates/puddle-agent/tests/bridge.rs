// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests for the Docker bridge listener: the bridge appears after the agent started,
//! disappears, and comes back as a different interface, with a fake probe standing in for the
//! kernel and `127.0.0.2` standing in for the bridge address.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    unreachable_pub,
    reason = "helpers outside #[test] fns, and the shared harness module, run only in tests"
)]

#[expect(dead_code, reason = "shared harness; this test uses part of it")]
mod common;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use puddle_agent::bridge::{BridgeState, Probe};
use puddle_agent::config::BridgeConfig;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const BRIDGE_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const POLL: Duration = Duration::from_millis(10);
const WAIT: Duration = Duration::from_secs(10);

/// The kernel's view of the bridge: 0 = no bridge, anything else = the interface's index.
#[derive(Default)]
struct FakeBridge(AtomicU32);

impl FakeBridge {
    fn set(&self, index: u32) {
        self.0.store(index, Ordering::SeqCst);
    }
}

impl Probe for FakeBridge {
    fn find(&self, addr: Ipv4Addr) -> Option<u32> {
        assert_eq!(
            addr, BRIDGE_IP,
            "the watcher asks about the configured address"
        );
        Some(self.0.load(Ordering::SeqCst)).filter(|&i| i != 0)
    }
}

struct Setup {
    rig: common::Rig,
    kernel: Arc<FakeBridge>,
}

async fn setup(tag: &str, port: u16) -> Setup {
    let kernel = Arc::new(FakeBridge::default());
    let rig = common::rig_with(
        tag,
        |_| None,
        |config| {
            config.bridge = Some(BridgeConfig {
                addr: SocketAddrV4::new(BRIDGE_IP, port),
                poll: POLL,
            });
        },
        kernel.clone(),
    )
    .await;
    Setup { rig, kernel }
}

async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

/// Waits until the state satisfies `ok`.
async fn state_where(
    rx: &mut watch::Receiver<BridgeState>,
    ok: impl Fn(&BridgeState) -> bool,
) -> BridgeState {
    tokio::time::timeout(WAIT, rx.wait_for(|s| ok(s)))
        .await
        .expect("the bridge state did not change in time")
        .unwrap()
        .to_owned()
}

/// `CONNECT target` through `proxy`, then an echo round trip of `payload`.
async fn echo_through(proxy: SocketAddr, target: SocketAddr, payload: &[u8]) {
    let mut conn = TcpStream::connect(proxy).await.unwrap();
    conn.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(conn);
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    assert!(status.starts_with("HTTP/1.1 200"), "{status:?}");
    reader.read_line(&mut String::new()).await.unwrap();
    reader.get_mut().write_all(payload).await.unwrap();
    reader.get_mut().shutdown().await.unwrap();
    let mut back = Vec::new();
    reader.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, payload);
}

#[tokio::test]
async fn nothing_listens_on_the_bridge_address_before_the_bridge_exists() {
    let s = setup("nobridge", 0).await;
    // Several polls with no bridge.
    tokio::time::sleep(POLL * 10).await;
    assert_eq!(s.rig.agent.bridge_addr(), None);
    assert_eq!(s.rig.agent.bridge_state().borrow().binds, 0);
}

#[tokio::test]
async fn the_bridge_appearing_after_start_gets_a_listener_that_relays() {
    let s = setup("appears", 0).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    assert_eq!(s.rig.agent.bridge_addr(), None);

    s.kernel.set(7);
    let bound = state_where(&mut state, |s| s.addr.is_some()).await;
    let addr = bound.addr.unwrap();
    assert_eq!(addr.ip(), std::net::IpAddr::V4(BRIDGE_IP));
    echo_through(addr, echo, b"through the bridge").await;
    // The sandbox's own listener keeps working next to it.
    echo_through(s.rig.agent.local_addr(), echo, b"through loopback").await;
}

#[tokio::test]
async fn the_listener_stops_when_the_bridge_goes_away() {
    let s = setup("goes", 0).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    s.kernel.set(7);
    let addr = state_where(&mut state, |s| s.addr.is_some())
        .await
        .addr
        .unwrap();

    // A connection through the bridge, open while it goes away, is dropped with it.
    let mut open = TcpStream::connect(addr).await.unwrap();
    open.write_all(format!("CONNECT {echo} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 12];
    open.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200");

    s.kernel.set(0);
    state_where(&mut state, |s| s.addr.is_none()).await;
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "the closed bridge address still accepts"
    );
    let mut rest = Vec::new();
    let ended = tokio::time::timeout(WAIT, open.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "the connection survived its bridge");
    // The loopback listener is untouched.
    echo_through(s.rig.agent.local_addr(), echo, b"still up").await;
}

#[tokio::test]
async fn a_recreated_bridge_is_rebound_even_between_two_polls() {
    let s = setup("recreated", 0).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    s.kernel.set(7);
    let first = state_where(&mut state, |s| s.binds == 1).await;

    // Same address, different interface index, never seen as absent.
    s.kernel.set(9);
    let second = state_where(&mut state, |s| s.binds == 2 && s.addr.is_some()).await;
    assert_ne!(first.binds, second.binds);
    echo_through(second.addr.unwrap(), echo, b"after the rebind").await;
}

#[tokio::test]
async fn a_bridge_that_comes_goes_and_comes_again_works_each_time() {
    let s = setup("flap", 0).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    for round in 1..=3u64 {
        s.kernel.set(10 + u32::try_from(round).unwrap());
        let up = state_where(&mut state, |s| s.binds == round && s.addr.is_some()).await;
        echo_through(up.addr.unwrap(), echo, b"round").await;
        s.kernel.set(0);
        state_where(&mut state, |s| s.addr.is_none()).await;
    }
}

#[tokio::test]
async fn a_busy_bridge_port_is_retried_until_it_is_free() {
    // Hold a port on the bridge address, as a published container port would.
    let held = TcpListener::bind((BRIDGE_IP, 0)).await.unwrap();
    let port = held.local_addr().unwrap().port();
    let s = setup("busy", port).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    s.kernel.set(7);
    tokio::time::sleep(POLL * 10).await;
    assert_eq!(s.rig.agent.bridge_addr(), None, "bound over a busy port");

    drop(held);
    let up = state_where(&mut state, |s| s.addr.is_some()).await;
    assert_eq!(up.addr.unwrap().port(), port);
    echo_through(up.addr.unwrap(), echo, b"free now").await;
}

/// The transparency bar: what `docker build`/`pull`/`npm install` in a container do is many
/// parallel tunnels with real payloads, through the bridge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_connects_256_all_succeed_through_the_bridge() {
    let s = setup("par", 0).await;
    let echo = echo_server().await;
    let mut state = s.rig.agent.bridge_state();
    s.kernel.set(7);
    let addr = state_where(&mut state, |s| s.addr.is_some())
        .await
        .addr
        .unwrap();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..256usize {
        set.spawn(async move {
            let payload: Vec<u8> = (0..64 * 1024usize)
                .map(|n| u8::try_from((n + i) % 251).unwrap())
                .collect();
            echo_through(addr, echo, &payload).await;
        });
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(done) = set.join_next().await {
            done.unwrap();
        }
    })
    .await
    .expect("256 connections through the bridge did not finish in 60 s");
}

#[tokio::test]
async fn a_bridge_listener_is_off_when_the_config_says_so() {
    let kernel = Arc::new(FakeBridge::default());
    let rig = common::rig_with("off", |_| None, |c| c.bridge = None, kernel.clone()).await;
    kernel.set(7);
    tokio::time::sleep(POLL * 10).await;
    assert_eq!(rig.agent.bridge_addr(), None);
}

#[tokio::test]
async fn a_wildcard_proxy_listener_already_covers_the_bridge() {
    // The old way to reach containers (listen on 0.0.0.0): no second listener is started.
    let kernel = Arc::new(FakeBridge::default());
    let probe: Arc<dyn Probe> = kernel.clone();
    let rig = common::rig_with(
        "wild",
        |_| None,
        |c| {
            c.listen = "0.0.0.0:0".parse().unwrap();
            c.bridge = Some(BridgeConfig {
                addr: SocketAddrV4::new(BRIDGE_IP, 0),
                poll: POLL,
            });
        },
        probe,
    )
    .await;
    kernel.set(7);
    tokio::time::sleep(POLL * 10).await;
    assert_eq!(rig.agent.bridge_addr(), None);
}
