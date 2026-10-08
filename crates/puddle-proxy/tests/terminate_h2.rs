// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests of HTTP/2 on terminated connections: protocol agreement with the real server, requests
//! decided and injected like HTTP/1.1, translation to an HTTP/1.1 server, trailers.
mod terminate_support;

use std::sync::Arc;

use http_body_util::BodyExt as _;
use puddle_proxy::ProxyConfig;
use terminate_support::h2_rig::{H2Server, Script, full, reply};
use terminate_support::{CANARY, FakeServer, Flaw, Pki, Reply, RigBuilder, TestInjector, refuse};

fn ok(text: &'static str) -> Script {
    Arc::new(move |_| reply(200, text))
}

#[tokio::test]
async fn an_h2_guest_talking_to_an_h2_server_is_served_h2_end_to_end() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("hello over h2")).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2", b"http/1.1"]).await;
    let got = client
        .request(
            "GET",
            "bound.test",
            "/org/repo?x=1",
            &[
                ("authorization", "Bearer guest-token"),
                ("user-agent", "tool/1"),
                ("proxy-authorization", "Basic zzz"),
            ],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.text(), "hello over h2");
    let seen = server.recorded();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.version, http::Version::HTTP_2);
    assert_eq!(request.authority.as_deref(), Some("bound.test"));
    assert_eq!(request.path, "/org/repo?x=1");
    assert_eq!(
        request.headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    assert_eq!(request.header("proxy-authorization"), None);
    assert_eq!(request.header("user-agent"), Some("tool/1"));
    client.close().await;
    let events = rig.events(1).await;
    assert!(events[0].injected);
    assert_eq!(events[0].http.as_ref().unwrap().path(), "/org/repo");
}

#[tokio::test]
async fn many_streams_share_the_one_upstream_connection() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("x")).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let mut tasks = Vec::new();
    for i in 0..64 {
        let mut sender = client.sender.clone();
        tasks.push(tokio::spawn(async move {
            let request = http::Request::builder()
                .uri(format!("https://bound.test/n/{i}"))
                .body(full(bytes::Bytes::new()))
                .unwrap();
            terminate_support::h2_rig::collect(sender.send_request(request).await.unwrap()).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().status, 200);
    }
    assert_eq!(server.recorded().len(), 64);
    assert_eq!(server.accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_http11_server_keeps_an_http11_guest_even_when_the_guest_offers_h2() {
    let pki = Pki::new();
    let mut config = Arc::into_inner(pki.server_config("bound.test", Flaw::None)).unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server = FakeServer::tls(Arc::new(config), Arc::new(|_| Reply::ok("h1 body"))).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest
        .tls_with("bound.test:443", None, &[b"h2", b"http/1.1"], true)
        .await
        .unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"http/1.1"[..]));
    assert_eq!(client.get("bound.test", "/").await.text(), "h1 body");
}

#[tokio::test]
async fn an_h2_only_guest_is_translated_to_an_http11_server() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|request| {
            Reply::ok(&format!(
                "{} {} body={}",
                request.method,
                request.target,
                request.body.len()
            ))
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "POST",
            "bound.test",
            "/up",
            &[
                ("cookie", "a=1"),
                ("cookie", "b=2"),
                ("authorization", "Bearer guest"),
            ],
            full(vec![7_u8; 1000]),
        )
        .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.text(), "POST /up body=1000");
    let seen = server.recorded();
    assert_eq!(seen[0].header("host"), Some("bound.test"));
    assert_eq!(seen[0].headers_named("cookie"), ["a=1; b=2"]);
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
}

#[tokio::test]
async fn a_refusal_of_the_injector_is_a_response_on_that_stream_only() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("fine")).await;
    let injector = TestInjector::new(|view| {
        if view.path() == "/denied" {
            refuse(403, "not-on-the-list")
        } else {
            terminate_support::inject("x")
        }
    });
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let denied = client.get("bound.test", "/denied").await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.header("x-puddle-blocked"), Some("not-on-the-list"));
    assert!(denied.text().contains("puddle:"));
    assert_eq!(client.get("bound.test", "/fine").await.status, 200);
    assert_eq!(
        server.recorded().len(),
        1,
        "the refused request went nowhere"
    );
}

#[tokio::test]
async fn trailers_and_te_trailers_pass_both_ways() {
    let pki = Pki::new();
    let handler: terminate_support::h2_rig::Handler = Arc::new(|request, _| {
        Box::pin(async move {
            use http_body_util::BodyExt as _;
            let te = request
                .headers()
                .get("te")
                .map(|v| v.to_str().unwrap().to_owned());
            let collected = request.into_body().collect().await.unwrap();
            let sent_trailer = collected
                .trailers()
                .and_then(|t| t.get("x-sent"))
                .map(|v| v.to_str().unwrap().to_owned());
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", "0".parse().unwrap());
            trailers.insert(
                "x-echo",
                format!("te={te:?} trailer={sent_trailer:?}")
                    .parse()
                    .unwrap(),
            );
            let body = http_body_util::StreamBody::new(futures_util::stream::iter([
                Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                    bytes::Bytes::from_static(b"payload"),
                )),
                Ok(http_body::Frame::trailers(trailers)),
            ]));
            http::Response::new(body.boxed_unsync())
        })
    });
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let mut sender = client.sender.clone();
    let mut request_trailers = http::HeaderMap::new();
    request_trailers.insert("x-sent", "yes".parse().unwrap());
    let body = {
        use http_body_util::BodyExt as _;
        http_body_util::StreamBody::new(futures_util::stream::iter([
            Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                bytes::Bytes::from_static(b"in"),
            )),
            Ok(http_body::Frame::trailers(request_trailers)),
        ]))
        .boxed_unsync()
    };
    let request = http::Request::builder()
        .method("POST")
        .uri("https://bound.test/svc/Method")
        .header("te", "trailers")
        .header("content-type", "application/grpc")
        .body(body)
        .unwrap();
    let got = terminate_support::h2_rig::collect(sender.send_request(request).await.unwrap()).await;
    assert_eq!(got.status, 200);
    assert_eq!(got.text(), "payload");
    assert_eq!(got.trailer("grpc-status"), Some("0"));
    assert_eq!(
        got.trailer("x-echo"),
        Some("te=Some(\"trailers\") trailer=Some(\"yes\")")
    );
}

#[tokio::test]
async fn request_trailers_cannot_carry_credentials_or_framing() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", Arc::new(|_| reply(200, "ok"))).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let mut sender = client.sender.clone();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-kept", "yes".parse().unwrap());
    trailers.insert("authorization", "Bearer guest".parse().unwrap());
    trailers.insert("cookie", "a=b".parse().unwrap());
    trailers.insert("content-length", "5".parse().unwrap());
    trailers.insert("host", "evil.test".parse().unwrap());
    let body = {
        use http_body_util::BodyExt as _;
        http_body_util::StreamBody::new(futures_util::stream::iter([
            Ok::<_, terminate_support::h2_rig::BoxError>(http_body::Frame::data(
                bytes::Bytes::from_static(b"in"),
            )),
            Ok(http_body::Frame::trailers(trailers)),
        ]))
        .boxed_unsync()
    };
    let request = http::Request::builder()
        .method("POST")
        .uri("https://bound.test/x")
        .body(body)
        .unwrap();
    let got = terminate_support::h2_rig::collect(sender.send_request(request).await.unwrap()).await;
    assert_eq!(got.status, 200);
    let seen = server.recorded();
    let trailers = seen[0].trailers.clone().unwrap();
    assert_eq!(trailers, vec![("x-kept".to_owned(), "yes".to_owned())]);
}

#[tokio::test]
async fn a_request_that_is_not_for_the_connection_host_or_not_valid_h2_is_refused() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("fine")).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let other = client.get("other.test", "/").await;
    assert_eq!(other.status, 421);
    let mixed = client
        .request(
            "GET",
            "bound.test",
            "/",
            &[("host", "other.test")],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(mixed.status, 421);
    assert!(server.recorded().is_empty());
    assert_eq!(client.get("bound.test", "/ok").await.status, 200);
}

#[tokio::test]
async fn a_server_with_a_bad_certificate_is_a_502_on_the_first_stream_and_nothing_is_sent() {
    let pki = Pki::new();
    let mut config = Arc::into_inner(pki.server_config("bound.test", Flaw::WrongName)).unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let server = FakeServer::tls(Arc::new(config), Arc::new(|_| Reply::ok("never"))).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client.get("bound.test", "/").await;
    assert_eq!(got.status, 502);
    assert_eq!(got.header("x-puddle-blocked-by"), Some("upstream-tls"));
    assert_eq!(injector.calls(), 0);
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn an_idle_h2_connection_is_closed_after_the_keepalive_timeout() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("x")).await;
    let config = ProxyConfig::default().with_terminate_timeouts(
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(10),
    );
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(config)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.get("bound.test", "/").await.status, 200);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !client.sender.is_closed() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the idle connection is closed");
}

// ---------------------------------------------------------------------------------------------
// WebSocket

use terminate_support::h2_rig::{WsServer, accept_for};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn handshake(host: &str, extra: &str) -> String {
    format!(
        "GET /chat HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

#[tokio::test]
async fn a_websocket_upgrade_over_http11_is_injected_and_piped() {
    let pki = Pki::new();
    let server = WsServer::start(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            handshake(
                "bound.test",
                "Authorization: Bearer guest\r\nSec-WebSocket-Protocol: chat, superchat\r\n",
            )
            .as_bytes(),
        )
        .await;
    let mut head = String::new();
    loop {
        let mut line = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut client.stream, &mut line)
            .await
            .unwrap();
        if line == "\r\n" {
            break;
        }
        head.push_str(&line.to_ascii_lowercase());
    }
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert!(head.contains(&format!(
        "sec-websocket-accept: {}",
        accept_for(KEY).to_ascii_lowercase()
    )));
    assert!(head.contains("sec-websocket-protocol: chat"));
    // Bytes now go both ways untouched.
    client
        .stream
        .write_all(b"\x81\x85mask!hello")
        .await
        .unwrap();
    let mut echo = [0_u8; 12];
    client.stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"\x81\x85mask!hello");
    let seen = server.handshakes();
    let find = |name: &str| {
        seen[0]
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(find("authorization"), Some(&*format!("Basic {CANARY}")));
    assert_eq!(find("sec-websocket-key"), Some(KEY));
    assert_eq!(find("host"), Some("bound.test"));
    assert_eq!(find("upgrade"), Some("websocket"));
    // The guest hangs up: the pipe ends and the connection is recorded.
    client.close().await;
    assert_eq!(rig.events(1).await.len(), 1);
}

#[tokio::test]
async fn a_refused_upgrade_is_an_ordinary_answer_and_the_connection_goes_on() {
    let pki = Pki::new();
    let server = WsServer::start(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    // No key: the server answers 404 and closes.
    client
        .send(b"GET /chat HTTP/1.1\r\nHost: bound.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 404);
}

#[tokio::test]
async fn a_websocket_over_http2_extended_connect_reaches_an_http11_server_as_an_upgrade() {
    let pki = Pki::new();
    let server = WsServer::start(&pki, "bound.test").await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/chat")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-protocol", "chat")
        .header("authorization", "Bearer guest")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let mut response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        "chat"
    );
    let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);
    io.write_all(b"ping bytes").await.unwrap();
    let mut echo = [0_u8; 10];
    io.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping bytes");
    let seen = server.handshakes();
    let find = |name: &str| {
        seen[0]
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(find("authorization"), Some(&*format!("Basic {CANARY}")));
    assert_eq!(find("upgrade"), Some("websocket"));
    assert!(find("sec-websocket-key").is_some_and(|k| k != KEY));
    // The rules judged the `GET` the server was sent, not the guest's extended `CONNECT`.
    let asked = injector.seen.lock().unwrap().clone();
    assert_eq!(asked, vec![("GET".to_owned(), "/chat".to_owned())]);
    // The guest hangs up: the pipe ends and the connection is recorded.
    drop(io);
    client.close().await;
    assert_eq!(rig.events(1).await.len(), 1);
}

#[tokio::test]
async fn a_websocket_over_http2_to_an_http2_server_is_passed_as_extended_connect() {
    let pki = Pki::new();
    let handler: terminate_support::h2_rig::Handler = Arc::new(|mut request, _| {
        Box::pin(async move {
            assert_eq!(request.method(), http::Method::CONNECT);
            assert_eq!(
                request
                    .extensions()
                    .get::<hyper::ext::Protocol>()
                    .map(hyper::ext::Protocol::as_str),
                Some("websocket")
            );
            assert_eq!(
                request
                    .headers()
                    .get("authorization")
                    .map(|v| v.to_str().unwrap().to_owned()),
                Some(format!("Basic {CANARY}"))
            );
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let Ok(upgraded) = upgrade.await else { return };
                let mut io = hyper_util::rt::TokioIo::new(upgraded);
                let mut buf = [0_u8; 64];
                while let Ok(n) = io.read(&mut buf).await {
                    if n == 0 || io.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
            reply(200, "")
        })
    });
    let server = H2Server::streaming_with_connect(&pki, "bound.test", handler).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/chat")
        .header("authorization", "Bearer guest")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let mut response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let upgraded = hyper::upgrade::on(&mut response).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);
    io.write_all(b"through h2").await.unwrap();
    let mut echo = [0_u8; 10];
    io.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"through h2");
    // The guest hangs up: the pipe ends and the connection is recorded.
    drop(io);
    drop(response);
    client.close().await;
    assert_eq!(rig.events(1).await.len(), 1);
}

#[tokio::test]
async fn an_injected_credential_is_sent_never_indexed() {
    let pki = Pki::new();
    let (addr, block, _task) =
        terminate_support::h2_rig::capture_first_headers_block(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki).name("bound.test", addr).build();
    let mut guest = rig.guest().await;
    let client = guest.h2("bound.test:443", &[b"h2"]).await;
    let mut sender = client.sender.clone();
    tokio::spawn(async move {
        let request = http::Request::builder()
            .uri("https://bound.test/")
            .body(full(bytes::Bytes::new()))
            .unwrap();
        let _ = sender.send_request(request).await;
    });
    let block = tokio::time::timeout(std::time::Duration::from_secs(5), block)
        .await
        .expect("the request reached the server")
        .unwrap();
    // RFC 7541 §6.2.3: a literal never indexed, name from the static table (`authorization` is
    // entry 23): 0001 1111, then 23 - 15 = 8.
    assert!(
        block.windows(2).any(|w| w == [0x1f, 0x08]),
        "authorization is a never-indexed literal: {block:02x?}"
    );
    // And not an incrementally indexed one (RFC 7541 §6.2.1: 01 + the index, 0x57).
    assert!(!block.contains(&0x57), "{block:02x?}");
}

#[tokio::test]
async fn head_204_and_304_answers_end_the_stream_cleanly() {
    let pki = Pki::new();
    let script: Script = Arc::new(|seen| match seen.path.as_str() {
        "/head" => http::Response::builder()
            .status(200)
            .header("content-length", "1234")
            .body(
                http_body_util::Empty::<bytes::Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap(),
        "/none" => reply(204, ""),
        _ => reply(304, ""),
    });
    let server = H2Server::recording(&pki, "bound.test", script).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let head = client
        .request(
            "HEAD",
            "bound.test",
            "/head",
            &[],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(head.status, 200);
    assert_eq!(head.body, Vec::<u8>::new());
    assert_eq!(client.get("bound.test", "/none").await.status, 204);
    assert_eq!(client.get("bound.test", "/other").await.status, 304);
}

#[tokio::test]
async fn a_connection_the_server_dropped_is_replaced_for_the_next_stream() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("again")).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.get("bound.test", "/1").await.text(), "again");
    server.drop_connections();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(client.get("bound.test", "/2").await.text(), "again");
    assert_eq!(server.accepted.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_http11_server_that_closes_after_every_answer_is_reconnected_for_each_stream() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("one shot").closing()),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    for i in 0..4 {
        let got = client.get("bound.test", &format!("/{i}")).await;
        assert_eq!(got.text(), "one shot", "request {i}");
    }
}
