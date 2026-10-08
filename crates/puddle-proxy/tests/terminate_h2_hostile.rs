// SPDX-License-Identifier: GPL-3.0-or-later
//! A hostile guest on an HTTP/2 terminated connection: floods, resets, smuggling by translation,
//! malformed headers. Each test says what must not happen at the real server, and that the
//! connection (or stream) ends instead of the proxy giving way.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use puddle_proxy::ProxyConfig;
use terminate_support::h2_rig::{H2Server, Handler, Script, reply};
use terminate_support::{FakeServer, Flaw, Pki, Reply, RigBuilder, TestInjector, TlsStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let [_, a, b, c] = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut out = vec![a, b, c, kind, flags];
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// An HPACK literal without indexing (RFC 7541 §6.2.2), no Huffman coding.
fn literal(name: &str, value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, u8::try_from(name.len()).unwrap()];
    out.extend_from_slice(name.as_bytes());
    out.push(u8::try_from(value.len()).unwrap());
    out.extend_from_slice(value);
    out
}

/// `GET <path> https bound.test`, as an HPACK block.
fn get_block(path: &[u8]) -> Vec<u8> {
    let mut block = vec![0x82, 0x87];
    block.extend(literal(":path", path));
    block.extend(literal(":authority", b"bound.test"));
    block
}

fn ok() -> Script {
    Arc::new(|_| reply(200, "fine"))
}

/// A connection to the proxy that has sent the HTTP/2 preface and nothing else.
async fn raw(guest: &mut terminate_support::Guest) -> TlsStream {
    let client = guest
        .tls_with("bound.test:443", None, &[b"h2"], true)
        .await
        .unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"h2"[..]));
    let mut tls = client.stream.into_inner();
    tls.write_all(PREFACE).await.unwrap();
    tls.write_all(&frame(4, 0, 0, &[])).await.unwrap();
    tls
}

/// Reads frames until the connection ends or `limit` passes; the (type, stream, payload) of each.
async fn frames_until_end(tls: &mut TlsStream, limit: Duration) -> (Vec<(u8, u32, Vec<u8>)>, bool) {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let mut head = [0_u8; 9];
        match tokio::time::timeout_at(deadline, tls.read_exact(&mut head)).await {
            Err(_) => return (seen, false),
            Ok(Err(_)) => return (seen, true),
            Ok(Ok(_)) => {}
        }
        let len = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let stream = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);
        let mut payload = vec![0_u8; len];
        match tokio::time::timeout_at(deadline, tls.read_exact(&mut payload)).await {
            Err(_) => return (seen, false),
            Ok(Err(_)) => return (seen, true),
            Ok(Ok(_)) => {}
        }
        if head[3] == 4 && head[4] & 1 == 0 {
            let _ = tls.write_all(&frame(4, 1, 0, &[])).await;
        }
        seen.push((head[3], stream, payload));
    }
}

fn rig_with(
    pki: &Pki,
    server: std::net::SocketAddr,
    config: ProxyConfig,
    injector: Arc<TestInjector>,
) -> terminate_support::Rig {
    RigBuilder::new(pki)
        .name("bound.test", server)
        .config(config)
        .injector(injector)
        .build()
}

#[tokio::test]
async fn a_rapid_reset_flood_is_ended_and_most_of_it_never_reaches_the_server() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let injector = TestInjector::always();
    let rig = rig_with(&pki, server.addr, ProxyConfig::default(), injector.clone());
    let mut guest = rig.guest().await;
    let mut tls = raw(&mut guest).await;
    let block = get_block(b"/n");
    let mut ended = false;
    for i in 0..5000_u32 {
        let id = 2 * i + 1;
        let mut burst = frame(1, 0x4 | 0x1, id, &block);
        burst.extend(frame(3, 0, id, &8_u32.to_be_bytes()));
        if tls.write_all(&burst).await.is_err() {
            ended = true;
            break;
        }
    }
    let (_, closed) = frames_until_end(&mut tls, Duration::from_secs(5)).await;
    assert!(ended || closed, "the connection was ended");
    assert!(
        injector.calls() <= 1500,
        "{} requests got as far as the injector",
        injector.calls()
    );
}

#[tokio::test]
async fn a_continuation_flood_ends_the_connection_and_nothing_is_sent_upstream() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let mut guest = rig.guest().await;
    let mut tls = raw(&mut guest).await;
    tls.write_all(&frame(1, 0x1, 1, &get_block(b"/")))
        .await
        .unwrap();
    // 4 MiB of CONTINUATION frames with no END_HEADERS: far more than any header list the proxy
    // accepts. The write may fail once the proxy has hung up; that is the point.
    let junk = vec![0x41_u8; 16 * 1024];
    for _ in 0..256 {
        let written = tokio::time::timeout(
            Duration::from_secs(5),
            tls.write_all(&frame(9, 0, 1, &junk)),
        )
        .await;
        if !matches!(written, Ok(Ok(()))) {
            break;
        }
    }
    let (_, closed) = frames_until_end(&mut tls, Duration::from_secs(5)).await;
    assert!(closed, "the connection ended");
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn a_header_block_left_open_is_cut_off_after_the_head_timeout() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let config = ProxyConfig::default().with_head_timeout(Duration::from_secs(1));
    let rig = rig_with(&pki, server.addr, config, TestInjector::always());
    let mut guest = rig.guest().await;
    let mut tls = raw(&mut guest).await;
    // HEADERS without END_HEADERS, then silence.
    tls.write_all(&frame(1, 0x1, 1, &get_block(b"/")[..4]))
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let (_, closed) = frames_until_end(&mut tls, Duration::from_secs(10)).await;
    assert!(closed);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn a_header_list_over_the_limit_never_reaches_the_server() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let mut guest = rig.guest().await;
    let client = guest
        .tls_with("bound.test:443", None, &[b"h2"], true)
        .await
        .unwrap();
    let (mut send, connection) = h2::client::handshake(client.stream.into_inner())
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut request = Request::builder().uri("https://bound.test/");
    for i in 0..12 {
        request = request.header(format!("x-big-{i}"), "a".repeat(8 * 1024));
    }
    let (response, _) = send.send_request(request.body(()).unwrap(), true).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap();
    // Either a 431, or the stream or the connection was reset.
    if let Ok(response) = outcome {
        assert_eq!(response.status(), 431);
    }
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn streams_over_the_limit_are_refused_and_the_server_never_sees_more_than_the_limit() {
    let pki = Pki::new();
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let handler: Handler = {
        let in_flight = Arc::clone(&in_flight);
        let peak = Arc::clone(&peak);
        Arc::new(move |_request, _| {
            let in_flight = Arc::clone(&in_flight);
            let peak = Arc::clone(&peak);
            Box::pin(async move {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(3)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                reply(200, "slow")
            })
        })
    };
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let mut guest = rig.guest().await;
    let mut tls = raw(&mut guest).await;
    let block = get_block(b"/slow");
    let mut burst = Vec::new();
    for i in 0..400_u32 {
        burst.extend(frame(1, 0x4 | 0x1, 2 * i + 1, &block));
    }
    tls.write_all(&burst).await.unwrap();
    let (seen, _) = frames_until_end(&mut tls, Duration::from_secs(2)).await;
    let refused = seen
        .iter()
        .filter(|(kind, _, payload)| *kind == 3 && payload == &7_u32.to_be_bytes())
        .count();
    assert!(refused >= 100, "{refused} streams refused");
    assert!(
        peak.load(Ordering::SeqCst) <= 256,
        "peak {}",
        peak.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn a_content_length_that_the_body_does_not_match_is_never_forwarded_as_a_complete_request() {
    let pki = Pki::new();
    let mut config = Arc::into_inner(pki.server_config("bound.test", Flaw::None)).unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let h1 = FakeServer::tls(Arc::new(config), Arc::new(|_| Reply::ok("never"))).await;
    let rig = rig_with(
        &pki,
        h1.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let mut guest = rig.guest().await;
    let client = guest
        .tls_with("bound.test:443", None, &[b"h2"], true)
        .await
        .unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"h2"[..]));
    let (mut send, connection) = h2::client::handshake(client.stream.into_inner())
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = Request::builder()
        .method("POST")
        .uri("https://bound.test/up")
        .header("content-length", "10")
        .body(())
        .unwrap();
    let (response, mut body) = send.send_request(request, false).unwrap();
    body.send_data(Bytes::from_static(b"12345"), true).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap();
    assert!(
        outcome.as_ref().map_or(true, |r| r.status() != 200),
        "a short body is not a success: {outcome:?}"
    );
    assert!(h1.recorded().is_empty(), "{:?}", h1.recorded());
}

#[tokio::test]
async fn headers_that_only_exist_to_smuggle_are_refused_before_the_server_sees_anything() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    for (name, value) in [
        ("transfer-encoding", "chunked"),
        ("connection", "keep-alive, x-evil"),
        ("keep-alive", "timeout=5"),
        ("upgrade", "h2c"),
        ("te", "gzip"),
        ("proxy-connection", "keep-alive"),
    ] {
        let mut guest = rig.guest().await;
        let client = guest
            .tls_with("bound.test:443", None, &[b"h2"], true)
            .await
            .unwrap();
        let (mut send, connection) = h2::client::handshake(client.stream.into_inner())
            .await
            .unwrap();
        tokio::spawn(connection);
        let request = Request::builder()
            .uri("https://bound.test/")
            .header(name, value)
            .body(())
            .unwrap();
        let outcome = match send.send_request(request, true) {
            Ok((response, _)) => tokio::time::timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .map(|r| r.status().as_u16())
                .map_err(|e| e.to_string()),
            Err(err) => Err(err.to_string()),
        };
        // Either a 400, or the stream was reset.
        if let Ok(status) = outcome {
            assert_eq!(status, 400, "{name}");
        }
    }
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn control_characters_in_a_header_or_the_path_are_refused() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("crlf in a value", {
            let mut block = get_block(b"/");
            block.extend(literal("x-evil", b"a\r\nx-injected: 1"));
            block
        }),
        ("nul in a value", {
            let mut block = get_block(b"/");
            block.extend(literal("x-evil", b"a\0b"));
            block
        }),
        ("space in a name", {
            let mut block = get_block(b"/");
            block.extend(literal("x evil", b"1"));
            block
        }),
        ("crlf in the path", get_block(b"/a\r\nx-injected: 1")),
        ("a space in the path", get_block(b"/a b")),
        ("an uppercase name", {
            let mut block = get_block(b"/");
            block.extend(literal("X-Upper", b"1"));
            block
        }),
    ];
    for (what, block) in cases {
        let mut guest = rig.guest().await;
        let mut tls = raw(&mut guest).await;
        tls.write_all(&frame(1, 0x4 | 0x1, 1, &block))
            .await
            .unwrap();
        let (seen, closed) = frames_until_end(&mut tls, Duration::from_secs(2)).await;
        let answered_ok = seen.iter().any(|(kind, stream, payload)| {
            *kind == 1 && *stream == 1 && payload.first() == Some(&0x88)
        });
        assert!(!answered_ok, "{what}: answered 200");
        let _ = closed;
    }
    assert!(
        server
            .recorded()
            .iter()
            .all(|r| r.header("x-injected").is_none() && r.header("x-evil").is_none()),
        "{:?}",
        server.recorded()
    );
}

#[tokio::test]
async fn a_stream_the_guest_resets_is_cancelled_upstream() {
    let pki = Pki::new();
    let cancelled = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let handler: Handler = {
        let cancelled = Arc::clone(&cancelled);
        let started = Arc::clone(&started);
        Arc::new(move |_request, _| {
            let cancelled = Arc::clone(&cancelled);
            let started = Arc::clone(&started);
            Box::pin(async move {
                struct OnDrop(Arc<AtomicBool>);
                impl Drop for OnDrop {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::SeqCst);
                    }
                }
                let _guard = OnDrop(cancelled);
                started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(60)).await;
                reply(200, "late")
            })
        })
    };
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let rig = rig_with(
        &pki,
        server.addr,
        ProxyConfig::default(),
        TestInjector::always(),
    );
    let mut guest = rig.guest().await;
    let mut tls = raw(&mut guest).await;
    tls.write_all(&frame(1, 0x4 | 0x1, 1, &get_block(b"/hang")))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the request reached the server");
    tls.write_all(&frame(3, 0, 1, &8_u32.to_be_bytes()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !cancelled.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the server saw the stream cancelled");
}

#[tokio::test]
async fn a_stream_that_is_idle_by_design_is_not_cut_by_the_body_stall_timeout() {
    let pki = Pki::new();
    let handler: Handler = Arc::new(|_request, _| {
        Box::pin(async move {
            use http_body_util::BodyExt as _;
            let stream = futures_util::stream::unfold(0_u8, |n| async move {
                if n == 2 {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(2500)).await;
                Some((
                    Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                        Bytes::from_static(b"tick "),
                    )),
                    n + 1,
                ))
            });
            http::Response::new(http_body_util::StreamBody::new(stream).boxed_unsync())
        })
    });
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let config = ProxyConfig::default().with_terminate_timeouts(
        Duration::from_secs(10),
        Duration::from_secs(60),
        Duration::from_secs(10),
        Duration::from_secs(1),
    );
    let rig = rig_with(&pki, server.addr, config, TestInjector::always());
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client.get("bound.test", "/watch").await;
    assert_eq!(got.text(), "tick tick ");
}
