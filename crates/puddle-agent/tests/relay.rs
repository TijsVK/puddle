// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests: guest client → agent → yamux over a Unix socket → host allow-all endpoint → server.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    unreachable_pub,
    reason = "helpers outside #[test] fns, and the shared harness module, run only in tests"
)]

mod common;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// An echo server: sends back everything, then closes after the client's FIN.
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

/// Connects through the agent with `CONNECT` and reads the `200` response.
async fn connect_via(agent: SocketAddr, target: SocketAddr) -> io::Result<BufReader<TcpStream>> {
    let mut conn = TcpStream::connect(agent).await?;
    conn.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(conn);
    let mut status = String::new();
    reader.read_line(&mut status).await?;
    if !status.starts_with("HTTP/1.1 200") {
        return Err(io::Error::other(format!("status {status:?}")));
    }
    let mut blank = String::new();
    reader.read_line(&mut blank).await?;
    Ok(reader)
}

async fn round_trip(agent: SocketAddr, target: SocketAddr, i: usize) -> io::Result<()> {
    let mut conn = connect_via(agent, target).await?;
    let payload: Vec<u8> = (0..64 * 1024usize)
        .map(|n| u8::try_from((n + i) % 251).unwrap())
        .collect();
    let (mut rd, mut wr) = tokio::io::split(&mut conn);
    let send = async {
        wr.write_all(&payload).await?;
        wr.shutdown().await
    };
    let mut back = Vec::new();
    let recv = rd.read_to_end(&mut back);
    let (upload, download) = tokio::join!(send, recv);
    upload?;
    download?;
    if back != payload {
        return Err(io::Error::other(format!("connection {i}: echo mismatch")));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_connects_256_all_succeed() {
    let rig = common::rig("par", |_| None).await;
    let echo = echo_server().await;
    let agent = rig.agent.local_addr();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..256 {
        set.spawn(async move { round_trip(agent, echo, i).await });
    }
    let all = tokio::time::timeout(Duration::from_secs(60), async {
        let mut failures = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Err(e) = r.unwrap() {
                failures.push(e.to_string());
            }
        }
        failures
    })
    .await
    .expect("256 connections did not finish within 60 s");
    assert!(
        all.is_empty(),
        "{} of 256 failed: {:?}",
        all.len(),
        all.first()
    );
    let mut rig = rig;
    assert_eq!(
        common::next_event(&mut rig.events, Duration::from_millis(100)).await,
        None
    );
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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

#[tokio::test]
async fn an_aborted_guest_upload_reaches_the_server_as_a_reset() {
    let rig = common::rig("abort", |_| None).await;
    let (sink, mut ends, mut firsts) = sink_server().await;
    let mut conn = connect_via(rig.agent.local_addr(), sink).await.unwrap();
    conn.get_mut()
        .write_all(&vec![7u8; 32 * 1024])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), firsts.recv())
        .await
        .unwrap();
    // Abort: zero linger makes the close an RST, like a killed upload.
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
async fn a_graceful_upload_reaches_the_server_complete_with_a_clean_eof() {
    let rig = common::rig("graceful", |_| None).await;
    let (sink, mut ends, _firsts) = sink_server().await;
    let mut conn = connect_via(rig.agent.local_addr(), sink).await.unwrap();
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
    let rig = common::rig("srvreset", |_| None).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (go_tx, go_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        conn.write_all(b"partial").await.unwrap();
        go_rx.await.ok();
        conn.set_zero_linger().unwrap();
        drop(conn);
    });
    let mut conn = connect_via(rig.agent.local_addr(), addr).await.unwrap();
    let mut first = [0u8; 7];
    conn.read_exact(&mut first).await.unwrap();
    go_tx.send(()).unwrap();
    let mut rest = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
        .await
        .unwrap();
    assert_eq!(
        r.map_err(|e| e.kind()).err(),
        Some(io::ErrorKind::ConnectionReset)
    );
}

#[tokio::test]
async fn with_the_host_down_a_guest_connection_is_reset_not_hung() {
    let mut rig = common::rig("down", |_| None).await;
    rig.host.abort();
    let _ = (&mut rig.host).await;
    std::fs::remove_file(rig.socket()).unwrap();
    let mut conn = TcpStream::connect(rig.agent.local_addr()).await.unwrap();
    conn.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut buf))
        .await
        .unwrap();
    assert!(r.is_err() || buf.is_empty(), "{r:?}");
}

#[tokio::test]
async fn non_connect_requests_and_unreachable_targets_get_errors_from_the_endpoint() {
    let rig = common::rig("errs", |_| None).await;
    let mut conn = TcpStream::connect(rig.agent.local_addr()).await.unwrap();
    conn.write_all(b"GET http://x/ HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await.unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 405"));

    // A port nothing listens on: bind, note it, close.
    let gone = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let err = connect_via(rig.agent.local_addr(), gone).await.unwrap_err();
    assert!(err.to_string().contains("502"), "{err}");
}

#[tokio::test]
async fn after_a_host_restart_new_connections_redial_and_work() {
    let mut rig = common::rig("restart", |_| None).await;
    let echo = echo_server().await;
    let agent = rig.agent.local_addr();
    // Use every session slot once, so each holds a session to the old host.
    for i in 0..8 {
        round_trip(agent, echo, i).await.unwrap();
    }
    rig.restart_host().await;
    for i in 0..8 {
        round_trip(agent, echo, i).await.unwrap();
    }
}
