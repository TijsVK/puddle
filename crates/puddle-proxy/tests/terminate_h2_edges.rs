// SPDX-License-Identifier: GPL-3.0-or-later
//! Less usual turns of an HTTP/2 terminated connection: a server that is down at the handshake and
//! back later, one that stalls or drops a request, a refused WebSocket, a request the rules let
//! through unchanged. Each one answers on its stream and leaves the connection usable.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use puddle_proxy::{InjectDecision, ProxyConfig};
use terminate_support::h2_rig::{H2Server, Script, WsServer, full, reply};
use terminate_support::{FakeServer, Flaw, Pki, Reply, RigBuilder, TestInjector, refuse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn ok(text: &'static str) -> Script {
    Arc::new(move |_| reply(200, text))
}

/// A TCP front for `target` that hangs up on its first connection and relays every later one: a
/// server that was down for a moment.
async fn down_for_the_first_connection(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut count = 0_usize;
        while let Ok((mut tcp, _)) = listener.accept().await {
            count += 1;
            if count == 1 {
                drop(tcp);
                continue;
            }
            tokio::spawn(async move {
                if let Ok(mut up) = tokio::net::TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut up).await;
                }
            });
        }
    });
    addr
}

fn h1_server_config(pki: &Pki) -> Arc<rustls::ServerConfig> {
    let mut config = Arc::into_inner(pki.server_config("bound.test", Flaw::None)).unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

#[tokio::test]
async fn an_http11_server_that_was_down_at_the_handshake_is_used_from_the_next_stream() {
    let pki = Pki::new();
    let server = FakeServer::tls(h1_server_config(&pki), Arc::new(|_| Reply::ok("back"))).await;
    let front = down_for_the_first_connection(server.addr).await;
    let rig = RigBuilder::new(&pki).name("bound.test", front).build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let first = client.get("bound.test", "/one").await;
    assert_eq!(first.status, 502, "the first stream has the reason");
    let second = client.get("bound.test", "/two").await;
    assert_eq!(second.status, 200);
    assert_eq!(second.text(), "back");
    client.close().await;
    let events = rig.events(1).await;
    assert!(events[0].resolved_ip.is_some(), "the audit has the address");
}

#[tokio::test]
async fn an_http2_server_that_was_down_at_the_handshake_is_used_from_the_next_stream() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("back")).await;
    let front = down_for_the_first_connection(server.addr).await;
    let rig = RigBuilder::new(&pki).name("bound.test", front).build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.get("bound.test", "/one").await.status, 502);
    assert_eq!(client.get("bound.test", "/two").await.text(), "back");
}

#[tokio::test]
async fn an_http11_guest_gets_the_reason_and_the_connection_ends() {
    let pki = Pki::new();
    let server = FakeServer::tls(h1_server_config(&pki), Arc::new(|_| Reply::ok("back"))).await;
    let front = down_for_the_first_connection(server.addr).await;
    let rig = RigBuilder::new(&pki).name("bound.test", front).build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/one").await.status, 502);
    assert!(
        client.closed().await,
        "HTTP/1.1 ends the connection after a refusal"
    );
    // A new connection is a new attempt, and the server is there.
    let mut again = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(again.get("bound.test", "/two").await.text(), "back");
}

#[tokio::test]
async fn a_request_the_rules_refuse_leaves_the_http11_connection_for_the_next_stream() {
    let pki = Pki::new();
    let server = FakeServer::tls(h1_server_config(&pki), Arc::new(|_| Reply::ok("fine"))).await;
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
    assert_eq!(client.get("bound.test", "/one").await.status, 200);
    assert_eq!(client.get("bound.test", "/denied").await.status, 403);
    assert_eq!(client.get("bound.test", "/two").await.status, 200);
    assert_eq!(
        server.accepted(),
        1,
        "the connection the refused stream held was given back, not closed"
    );
}

#[tokio::test]
async fn a_request_the_rules_let_through_keeps_the_guests_own_credentials() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("fine")).await;
    let injector = TestInjector::new(|_| InjectDecision::PassThrough);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "GET",
            "bound.test",
            "/",
            &[("authorization", "Bearer guest")],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);
    assert_eq!(
        server.recorded()[0].headers_named("authorization"),
        ["Bearer guest"]
    );
    client.close().await;
    assert!(!rig.events(1).await[0].injected);
}

#[tokio::test]
async fn a_server_that_never_finishes_the_tls_handshake_is_a_504_on_the_first_stream() {
    let pki = Pki::new();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    let defaults = ProxyConfig::default();
    let config = defaults.with_terminate_timeouts(
        Duration::from_millis(400),
        defaults.keepalive_timeout,
        defaults.upstream_head_timeout,
        defaults.body_idle_timeout,
    );
    let rig = RigBuilder::new(&pki)
        .name("bound.test", addr)
        .config(config)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client.get("bound.test", "/").await;
    assert_eq!(got.status, 504);
    assert_eq!(got.header("x-puddle-blocked-by"), Some("upstream-tls"));
    held.abort();
}

#[tokio::test]
async fn a_server_that_does_not_answer_is_a_504_and_the_connection_goes_on() {
    let pki = Pki::new();
    let handler: terminate_support::h2_rig::Handler = Arc::new(|request, _| {
        Box::pin(async move {
            if request.uri().path() == "/slow" {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            reply(200, "quick")
        })
    });
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let defaults = ProxyConfig::default();
    let config = defaults.with_terminate_timeouts(
        defaults.tls_handshake_timeout,
        defaults.keepalive_timeout,
        Duration::from_secs(1),
        defaults.body_idle_timeout,
    );
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(config)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.get("bound.test", "/slow").await.status, 504);
    assert_eq!(client.get("bound.test", "/fast").await.text(), "quick");
}

#[tokio::test]
async fn a_connection_the_server_drops_in_the_middle_of_a_request_is_a_502_with_the_cause() {
    let pki = Pki::new();
    let arrived = Arc::new(tokio::sync::Notify::new());
    let handler: terminate_support::h2_rig::Handler = {
        let arrived = Arc::clone(&arrived);
        Arc::new(move |_, _| {
            let arrived = Arc::clone(&arrived);
            Box::pin(async move {
                arrived.notify_one();
                std::future::pending::<()>().await;
                reply(200, "never")
            })
        })
    };
    let server = H2Server::streaming(&pki, "bound.test", handler).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let asking = client.get("bound.test", "/hang");
    let cutting = async {
        arrived.notified().await;
        server.drop_connections();
    };
    let (got, ()) = tokio::join!(asking, cutting);
    assert_eq!(got.status, 502);
    assert!(
        got.text().contains("the request to bound.test failed"),
        "{}",
        got.text()
    );
}

#[tokio::test]
async fn an_extended_connect_for_a_protocol_other_than_websocket_is_not_implemented() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("x")).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/tunnel")
        .extension(hyper::ext::Protocol::from_static("connect-udp"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 501);
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn a_websocket_over_http2_to_an_http11_server_needs_version_13() {
    let pki = Pki::new();
    let server = WsServer::start(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/chat")
        .header("sec-websocket-version", "8")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 400);
    assert!(server.handshakes().is_empty(), "nothing was sent upstream");
}

#[tokio::test]
async fn a_websocket_the_http11_server_answers_wrongly_is_a_502() {
    let pki = Pki::new();
    let server = WsServer::lying(&pki, "bound.test").await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/chat")
        .header("sec-websocket-version", "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 502);
}

#[tokio::test]
async fn a_websocket_the_http2_server_refuses_is_its_answer_on_that_stream() {
    let pki = Pki::new();
    let handler: terminate_support::h2_rig::Handler =
        Arc::new(|_, _| Box::pin(async { reply(403, "no sockets here") }));
    let server = H2Server::streaming_with_connect(&pki, "bound.test", handler).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let request = http::Request::builder()
        .method("CONNECT")
        .uri("https://bound.test/chat")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(terminate_support::h2_rig::open_body())
        .unwrap();
    let response = client.sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 403);
    let got = terminate_support::h2_rig::collect(response).await;
    assert_eq!(got.text(), "no sockets here");
    assert_eq!(client.get("bound.test", "/after").await.status, 403);
}

#[tokio::test]
async fn a_guest_that_stops_its_handshake_after_the_hello_is_dropped_at_the_handshake_timeout() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok("x")).await;
    let defaults = ProxyConfig::default();
    let config = defaults.with_terminate_timeouts(
        Duration::from_millis(400),
        defaults.keepalive_timeout,
        defaults.upstream_head_timeout,
        defaults.body_idle_timeout,
    );
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(config)
        .build();
    let guest = rig.guest().await;
    let (port, _bridge) = guest.bridge("bound.test:443").await;
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    // A ClientHello, and then silence: the guest never answers the server's flight.
    let config = terminate_support::Guest::client_config(std::slice::from_ref(&pki.root), &[b"h2"]);
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("bound.test").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).unwrap();
    tcp.write_all(&hello).await.unwrap();
    let mut sink = Vec::new();
    let ended = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut sink)).await;
    assert!(ended.is_ok(), "the proxy hung up");
    assert_eq!(rig.events(1).await.len(), 1);
}
