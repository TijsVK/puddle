// SPDX-License-Identifier: GPL-3.0-or-later
//! Throughput of a terminated connection against a spliced one: a 256 MiB upload and a 256 MiB
//! download of the same server, once decrypted by the proxy and once passed through.
//!
//! Slow and only meaningful in a release build, so it is ignored by default:
//!
//! ```text
//! cargo nextest run --release -p puddle-proxy --test terminate_perf --run-ignored only --no-capture
//! ```
//!
//! It reports the ratio and asserts only that both finish and the bytes arrive intact. The goal
//! (decrypting costs at most ten percent more than splicing) is for a quiet machine, not for a
//! shared runner.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "tests fail by panicking, and report by printing"
)]
mod terminate_support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use terminate_support::{Client, Flaw, Pki, RigBuilder, host, read_response};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const MIB: usize = 1024 * 1024;

/// A server that drains `Content-Length` bytes of a POST and answers with that many bytes of
/// `x`: the same work for both paths, with no per-request allocation of the body.
async fn bulk_server(pki: &Pki, name: &str) -> std::net::SocketAddr {
    let acceptor = TlsAcceptor::from(pki.server_config(name, Flaw::None));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut reader = BufReader::new(tls);
                loop {
                    let mut length = 0_usize;
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut h = String::new();
                        reader.read_line(&mut h).await.unwrap();
                        if h == "\r\n" {
                            break;
                        }
                        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                            length = v.trim().parse().unwrap();
                        }
                    }
                    let mut left = length;
                    let mut buf = vec![0_u8; 256 * 1024];
                    while left > 0 {
                        let take = left.min(buf.len());
                        let n = reader.read(&mut buf[..take]).await.unwrap();
                        assert_ne!(n, 0);
                        left -= n;
                    }
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {length}\r\n\r\n");
                    reader.get_mut().write_all(head.as_bytes()).await.unwrap();
                    let chunk = vec![b'x'; 256 * 1024];
                    let mut left = length;
                    while left > 0 {
                        let n = left.min(chunk.len());
                        reader.get_mut().write_all(&chunk[..n]).await.unwrap();
                        left -= n;
                    }
                    reader.get_mut().flush().await.unwrap();
                }
            });
        }
    });
    addr
}

async fn transfer(client: &mut Client, host: &str, mib: usize) -> Duration {
    let started = Instant::now();
    // Upload and read at once: a yamux stream whose reader is idle does not get its window back.
    let (read, mut write) = tokio::io::split(&mut client.stream);
    let mut read = BufReader::new(read);
    let upload = async {
        write
            .write_all(
                format!(
                    "POST /bulk HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
                    mib * MIB
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let chunk = vec![b'u'; 64 * 1024];
        let mut left = mib * MIB;
        while left > 0 {
            let n = left.min(chunk.len());
            write.write_all(&chunk[..n]).await.unwrap();
            if left % (16 * MIB) == 0 {
                eprintln!("  left {} MiB", left / MIB);
            }
            left -= n;
        }
        write.flush().await.unwrap();
        eprintln!("  upload done {:?}", started.elapsed());
    };
    let (response, ()) = tokio::join!(read_response(&mut read, "POST"), upload);
    let response = response.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body.len(), mib * MIB);
    assert!(response.body.iter().all(|b| *b == b'x'));
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a 256 MiB transfer, meaningful only in a release build; run it by hand"]
async fn terminating_costs_little_next_to_splicing() {
    let pki = Pki::new();
    let bound = bulk_server(&pki, "bound.test").await;
    let spliced = bulk_server(&pki, "unbound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", bound)
        .name("unbound.test", spliced)
        .allow(vec!["bound.test", "unbound.test"])
        .build();
    let _ = host("bound.test");
    let mut guest = rig.guest().await;
    let mut decrypted = guest.tls("bound.test:443", None).await.unwrap();
    let mut passed = guest
        .tls_trusting("unbound.test:443", &[pki.root.clone()])
        .await
        .unwrap();
    // Warm both paths, then measure each twice and keep the faster run.
    transfer(&mut decrypted, "bound.test", 16).await;
    transfer(&mut passed, "unbound.test", 16).await;
    for mib in [32, 64, 128] {
        let t = transfer(&mut decrypted, "bound.test", mib).await;
        eprintln!("T {mib} {t:?}");
    }
    let mut best_terminated = Duration::MAX;
    let mut best_spliced = Duration::MAX;
    for _ in 0..2 {
        best_spliced = best_spliced.min(transfer(&mut passed, "unbound.test", 256).await);
        best_terminated = best_terminated.min(transfer(&mut decrypted, "bound.test", 256).await);
    }
    let ratio = best_terminated.as_secs_f64() / best_spliced.as_secs_f64();
    eprintln!(
        "256 MiB up and 256 MiB down: terminated {best_terminated:.2?}, spliced {best_spliced:.2?}, ratio {ratio:.2}"
    );
    let _ = Arc::strong_count(&rig.ca);
}
