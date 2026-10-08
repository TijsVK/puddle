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
#![expect(clippy::unwrap_used, reason = "tests fail by panicking")]
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
                        let n = reader.read(buf.split_at_mut(take).0).await.unwrap();
                        assert_ne!(n, 0);
                        left -= n;
                    }
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {length}\r\n\r\n");
                    reader.get_mut().write_all(head.as_bytes()).await.unwrap();
                    let chunk = vec![b'x'; 256 * 1024];
                    let mut left = length;
                    while left > 0 {
                        let n = left.min(chunk.len());
                        reader
                            .get_mut()
                            .write_all(chunk.split_at(n).0)
                            .await
                            .unwrap();
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
            write.write_all(chunk.split_at(n).0).await.unwrap();
            left -= n;
        }
        write.flush().await.unwrap();
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
        .tls_trusting("unbound.test:443", std::slice::from_ref(&pki.root))
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

/// A response bigger than a yamux stream window has to arrive although the guest sends nothing
/// while it waits: the proxy's writer stalled on a full window until its guest side was read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_download_larger_than_the_stream_window_arrives() {
    let pki = Pki::new();
    let bound = bulk_server(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki).name("bound.test", bound).build();
    let mut guest = rig.guest().await;
    for _ in 0..8 {
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        let took = tokio::time::timeout(
            Duration::from_secs(20),
            transfer(&mut client, "bound.test", 40),
        )
        .await;
        assert!(took.is_ok(), "40 MiB up and down stalled");
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP/2: throughput next to HTTP/1.1, and memory per idle connection.

mod h2_perf {
    use super::*;
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    use terminate_support::h2_rig::{H2Guest, H2Server, Handler, ReqBody};

    /// An HTTP/2 server with the bulk server's behaviour: drain the request body, answer with as
    /// many bytes of `x` as it had.
    pub(super) async fn bulk_h2_server(pki: &Pki, name: &str) -> H2Server {
        let chunk = Bytes::from(vec![b'x'; 256 * 1024]);
        let handler: Handler = Arc::new(move |request, _| {
            let chunk = chunk.clone();
            Box::pin(async move {
                let mut body = request.into_body();
                let mut total = 0_usize;
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.unwrap().into_data() {
                        total += data.len();
                    }
                }
                let stream = futures_util::stream::unfold(total, move |left| {
                    let chunk = chunk.clone();
                    async move {
                        if left == 0 {
                            return None;
                        }
                        let n = left.min(chunk.len());
                        Some((
                            Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                                chunk.slice(..n),
                            )),
                            left - n,
                        ))
                    }
                });
                http::Response::new(http_body_util::StreamBody::new(stream).boxed_unsync())
            })
        });
        H2Server::bulk(pki, name, handler).await
    }

    pub(super) async fn transfer_h2(client: &mut H2Guest, host: &str, mib: usize) -> Duration {
        let started = Instant::now();
        let chunk = Bytes::from(vec![b'u'; 64 * 1024]);
        let total = mib * MIB;
        let body: ReqBody =
            http_body_util::StreamBody::new(futures_util::stream::unfold(total, move |left| {
                let chunk = chunk.clone();
                async move {
                    if left == 0 {
                        return None;
                    }
                    let n = left.min(chunk.len());
                    Some((
                        Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                            chunk.slice(..n),
                        )),
                        left - n,
                    ))
                }
            }))
            .boxed_unsync();
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://{host}/bulk"))
            .header("content-length", total.to_string())
            .body(body)
            .unwrap();
        let response = client.sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut got = 0_usize;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.unwrap().into_data() {
                assert!(data.iter().all(|b| *b == b'x'));
                got += data.len();
            }
        }
        assert_eq!(got, total);
        started.elapsed()
    }

    pub(super) fn rss_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a 256 MiB transfer, meaningful only in a release build; run it by hand"]
async fn http2_costs_little_next_to_http11() {
    use h2_perf::{bulk_h2_server, transfer_h2};
    let pki = Pki::new();
    let h1 = bulk_server(&pki, "bound.test").await;
    let h2 = bulk_h2_server(&pki, "bound.test").await;
    let h2_spliced = bulk_h2_server(&pki, "unbound.test").await;
    let rig_h1 = RigBuilder::new(&pki).name("bound.test", h1).build();
    let rig_h2 = RigBuilder::new(&pki)
        .name("bound.test", h2.addr)
        .name("unbound.test", h2_spliced.addr)
        .allow(vec!["bound.test", "unbound.test"])
        .build();
    let rig_translated = RigBuilder::new(&pki).name("bound.test", h1).build();
    let mut g1 = rig_h1.guest().await;
    let mut g2 = rig_h2.guest().await;
    let mut g3 = rig_translated.guest().await;
    let mut g4 = rig_h2.guest().await;
    let mut http11 = g1.tls("bound.test:443", None).await.unwrap();
    let mut http2 = g2.h2_bulk("bound.test:443").await;
    let mut translated = g3.h2_bulk("bound.test:443").await;
    // The same two endpoints with nothing decrypted in between: what HTTP/2 costs by itself.
    let mut passed = {
        let (code, reader) = g4.connect_to("unbound.test:443").await;
        assert_eq!(code, 200);
        let config =
            terminate_support::Guest::client_config(std::slice::from_ref(&pki.root), &[b"h2"]);
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("unbound.test".to_owned()).unwrap(),
                reader,
            )
            .await
            .unwrap();
        terminate_support::Guest::h2_over_bulk(Client {
            alpn: Some(b"h2".to_vec()),
            stream: BufReader::new(tls),
        })
        .await
    };
    transfer(&mut http11, "bound.test", 16).await;
    transfer_h2(&mut http2, "bound.test", 16).await;
    transfer_h2(&mut translated, "bound.test", 16).await;
    transfer_h2(&mut passed, "unbound.test", 16).await;
    let mut best = [Duration::MAX; 4];
    for _ in 0..3 {
        best[0] = best[0].min(transfer(&mut http11, "bound.test", 256).await);
        best[1] = best[1].min(transfer_h2(&mut http2, "bound.test", 256).await);
        best[2] = best[2].min(transfer_h2(&mut translated, "bound.test", 256).await);
        best[3] = best[3].min(transfer_h2(&mut passed, "unbound.test", 256).await);
    }
    eprintln!(
        "256 MiB up and 256 MiB down: HTTP/1.1 terminated {:.2?}; HTTP/2 spliced {:.2?}, terminated {:.2?} (ratio {:.2}), terminated to an HTTP/1.1 server {:.2?}",
        best[0],
        best[3],
        best[1],
        best[1].as_secs_f64() / best[3].as_secs_f64(),
        best[2],
    );
}

/// An HTTP/2 connection to `unbound.test`, which is spliced: the guest and the server talk TLS
/// to each other.
async fn spliced_h2(
    guest: &mut terminate_support::Guest,
    pki: &Pki,
) -> terminate_support::h2_rig::H2Guest {
    let (code, reader) = guest.connect_to("unbound.test:443").await;
    assert_eq!(code, 200);
    let config = terminate_support::Guest::client_config(std::slice::from_ref(&pki.root), &[b"h2"]);
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("unbound.test".to_owned()).unwrap(),
            reader,
        )
        .await
        .unwrap();
    terminate_support::Guest::h2_over(Client {
        alpn: Some(b"h2".to_vec()),
        stream: BufReader::new(tls),
    })
    .await
}

/// Resident memory the process gains per idle connection, measured in a process of its own per
/// kind of connection (a heap that an earlier kind grew and freed would flatter the next).
async fn idle_memory(kind: &str) {
    use h2_perf::{bulk_h2_server, rss_kib};
    const N: usize = 400;
    let pki = Pki::new();
    let h1 = bulk_server(&pki, "bound.test").await;
    let spliced = bulk_server(&pki, "unbound.test").await;
    let h2 = bulk_h2_server(&pki, "bound.test").await;
    let h2_spliced = bulk_h2_server(&pki, "unbound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", if kind == "h2" { h2.addr } else { h1 })
        .name(
            "unbound.test",
            if kind == "spliced-h2" {
                h2_spliced.addr
            } else {
                spliced
            },
        )
        .allow(vec!["bound.test", "unbound.test"])
        .build();
    let mut guest = rig.guest().await;
    // Warm up the allocator, the TLS tables and the runtime, then take the baseline.
    for _ in 0..16 {
        match kind {
            "h2" => {
                let mut c = guest.h2("bound.test:443", &[b"h2"]).await;
                c.get("bound.test", "/").await;
            }
            "spliced-h2" => {
                let mut c = spliced_h2(&mut guest, &pki).await;
                c.get("unbound.test", "/").await;
            }
            "spliced" => {
                let mut c = guest
                    .tls_trusting("unbound.test:443", std::slice::from_ref(&pki.root))
                    .await
                    .unwrap();
                c.get("unbound.test", "/").await;
            }
            _ => {
                let mut c = guest.tls("bound.test:443", None).await.unwrap();
                c.get("bound.test", "/").await;
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = rss_kib();
    let mut held_h1 = Vec::new();
    let mut held_h2 = Vec::new();
    for _ in 0..N {
        match kind {
            "h2" => {
                let mut c = guest.h2("bound.test:443", &[b"h2"]).await;
                assert_eq!(c.get("bound.test", "/").await.status, 200);
                held_h2.push(c);
            }
            "spliced-h2" => {
                let mut c = spliced_h2(&mut guest, &pki).await;
                c.get("unbound.test", "/").await;
                held_h2.push(c);
            }
            "spliced" => {
                let mut c = guest
                    .tls_trusting("unbound.test:443", std::slice::from_ref(&pki.root))
                    .await
                    .unwrap();
                c.get("unbound.test", "/").await;
                held_h1.push(c);
            }
            _ => {
                let mut c = guest.tls("bound.test:443", None).await.unwrap();
                c.get("bound.test", "/").await;
                held_h1.push(c);
            }
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let grown = rss_kib().saturating_sub(before);
    eprintln!(
        "{kind}: {} KiB per idle connection ({N} connections, whole test process: proxy, guest and server)",
        grown / N
    );
    drop((held_h1, held_h2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures resident memory of the whole test process; run it by hand in a release build"]
async fn memory_of_an_idle_spliced_connection() {
    idle_memory("spliced").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures resident memory of the whole test process; run it by hand in a release build"]
async fn memory_of_an_idle_spliced_http2_connection() {
    idle_memory("spliced-h2").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures resident memory of the whole test process; run it by hand in a release build"]
async fn memory_of_an_idle_terminated_http11_connection() {
    idle_memory("h1").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measures resident memory of the whole test process; run it by hand in a release build"]
async fn memory_of_an_idle_terminated_http2_connection() {
    idle_memory("h2").await;
}
