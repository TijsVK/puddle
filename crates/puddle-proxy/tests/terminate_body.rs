// SPDX-License-Identifier: GPL-3.0-or-later
//! An injector that decides on a request's body ([`Injector::body_wanted`]): the proxy reads the
//! whole body first (within the limit the injector names), the injector decides on it, and the
//! request goes upstream with the same body. Both HTTP versions. A refusal is recorded in the
//! connection record with its code.
mod terminate_support;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use puddle_proxy::{
    BoxFuture, InjectContext, InjectDecision, InjectRefusal, Injector, ProxyConfig, RequestView,
};
use puddle_types::{ConnectionDecision, ConnectionReason};
use terminate_support::h2_rig::{H2Server, full};
use terminate_support::{CANARY, FakeServer, Flaw, Pki, Reply, RigBuilder, inject};

const LIMIT: usize = 64;

/// Wants the body of every `POST /peek`; refuses it when it says `refuse`, injects otherwise.
#[derive(Debug, Default)]
struct Peek {
    bodies: Mutex<Vec<Option<Vec<u8>>>>,
}

impl Injector for Peek {
    fn body_wanted(&self, _: &InjectContext<'_>, request: &RequestView<'_>) -> Option<usize> {
        (request.method() == "POST" && request.path() == "/peek").then_some(LIMIT)
    }

    fn decide<'a>(
        &'a self,
        _: &'a InjectContext<'a>,
        request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision> {
        let body = request.body().map(<[u8]>::to_vec);
        let refused = body.as_deref() == Some(b"refuse");
        self.bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(body);
        Box::pin(std::future::ready(if refused {
            InjectDecision::Refuse(InjectRefusal::new(403, "peek_refused", "no, said the body"))
        } else {
            inject(CANARY)
        }))
    }
}

async fn h1() -> (FakeServer, terminate_support::Rig, Arc<Peek>) {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|request| Reply::ok(&String::from_utf8_lossy(&request.body))),
    )
    .await;
    let peek = Arc::new(Peek::default());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(peek.clone())
        .build();
    (server, rig, peek)
}

fn bodies(peek: &Peek) -> Vec<Option<Vec<u8>>> {
    peek.bodies
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

#[tokio::test]
async fn a_content_length_body_is_read_for_the_injector_and_forwarded_whole() {
    let (server, rig, peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 5\r\n\r\nhello")
        .await;
    let answer = client.response("POST").await;
    assert_eq!((answer.status, answer.text().as_str()), (200, "hello"));
    assert_eq!(bodies(&peek), [Some(b"hello".to_vec())]);
    let seen = &server.recorded()[0];
    assert_eq!(seen.body, b"hello");
    assert_eq!(
        seen.headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    // The connection serves the next request.
    assert_eq!(client.get("bound.test", "/other").await.status, 200);
}

#[tokio::test]
async fn a_chunked_body_and_an_empty_one_reach_the_injector_decoded() {
    let (server, rig, peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n")
        .await;
    assert_eq!(client.response("POST").await.text(), "abcde");
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 0\r\n\r\n")
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    assert_eq!(bodies(&peek), [Some(b"abcde".to_vec()), Some(Vec::new())]);
    assert_eq!(server.recorded().len(), 2);
}

#[tokio::test]
async fn other_requests_are_not_read_ahead() {
    let (_server, rig, peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /else HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 3\r\n\r\nabc")
        .await;
    assert_eq!(client.response("POST").await.text(), "abc");
    assert_eq!(bodies(&peek), [None]);
}

#[tokio::test]
async fn expect_continue_is_answered_before_the_body_is_read() {
    let (server, rig, peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
        .await;
    assert_eq!(client.try_response("POST").await.unwrap().status, 100);
    client.send(b"ok").await;
    assert_eq!(client.response("POST").await.text(), "ok");
    assert_eq!(bodies(&peek), [Some(b"ok".to_vec())]);
    assert_eq!(server.recorded()[0].header("expect"), None);
}

#[tokio::test]
async fn a_refusal_on_the_body_sends_nothing_upstream_and_is_recorded_with_its_code() {
    let (server, rig, _peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 6\r\n\r\nrefuse")
        .await;
    let answer = client.response("POST").await;
    assert_eq!(answer.status, 403);
    assert_eq!(answer.header("x-puddle-blocked"), Some("peek_refused"));
    assert!(server.recorded().is_empty());
    drop(client);
    let event = &rig.events(1).await[0];
    assert_eq!(event.decision, ConnectionDecision::Blocked);
    assert_eq!(event.reason.to_string(), "peek_refused");
    assert_eq!(event.reason, ConnectionReason::Refused("peek_refused"));
    assert!(!event.injected);
}

#[tokio::test]
async fn a_body_over_the_limit_is_413_whether_declared_or_chunked_and_nothing_goes_upstream() {
    let (server, rig, peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            format!(
                "POST /peek HTTP/1.1\r\nHost: bound.test\r\nContent-Length: {}\r\n\r\n",
                LIMIT + 1
            )
            .as_bytes(),
        )
        .await;
    let declared = client.response("POST").await;
    assert_eq!(declared.status, 413);
    assert_eq!(declared.header("x-puddle-blocked"), Some("body_too_large"));

    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let piece = "x".repeat(LIMIT);
    client
        .send(format!("POST /peek HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n{LIMIT:x}\r\n{piece}\r\n{LIMIT:x}\r\n{piece}\r\n0\r\n\r\n").as_bytes())
        .await;
    assert_eq!(client.response("POST").await.status, 413);
    assert!(
        bodies(&peek).is_empty(),
        "the injector never saw an oversized body"
    );
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn a_body_that_stops_short_or_is_badly_framed_is_a_400_and_nothing_goes_upstream() {
    let (server, rig, _peek) = h1().await;
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n")
        .await;
    assert_eq!(client.response("POST").await.status, 400);
    assert!(server.recorded().is_empty());
}

async fn h2() -> (H2Server, terminate_support::Rig, Arc<Peek>) {
    let pki = Pki::new();
    let server = H2Server::recording(
        &pki,
        "bound.test",
        Arc::new(|seen| {
            terminate_support::h2_rig::reply(200, &String::from_utf8_lossy(&seen.body))
        }),
    )
    .await;
    let peek = Arc::new(Peek::default());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(peek.clone())
        .build();
    (server, rig, peek)
}

#[tokio::test]
async fn over_http2_the_body_is_read_for_the_injector_and_forwarded_whole() {
    let (server, rig, peek) = h2().await;
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "POST",
            "bound.test",
            "/peek",
            &[],
            full(Bytes::from("hello")),
        )
        .await;
    assert_eq!((got.status, got.text().as_str()), (200, "hello"));
    assert_eq!(bodies(&peek), [Some(b"hello".to_vec())]);
    let seen = &server.recorded()[0];
    assert_eq!(seen.body, b"hello");
    assert_eq!(
        seen.headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    // An empty body, and a request nobody asked to read ahead.
    let empty = client
        .request("POST", "bound.test", "/peek", &[], full(Bytes::new()))
        .await;
    assert_eq!(empty.status, 200);
    let other = client
        .request("POST", "bound.test", "/else", &[], full(Bytes::from("abc")))
        .await;
    assert_eq!(other.text(), "abc");
    assert_eq!(
        bodies(&peek),
        [Some(b"hello".to_vec()), Some(Vec::new()), None]
    );
}

#[tokio::test]
async fn over_http2_a_refusal_on_the_body_and_an_oversized_body_send_nothing_upstream() {
    let (server, rig, peek) = h2().await;
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let refused = client
        .request(
            "POST",
            "bound.test",
            "/peek",
            &[],
            full(Bytes::from("refuse")),
        )
        .await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.header("x-puddle-blocked"), Some("peek_refused"));
    let big = client
        .request(
            "POST",
            "bound.test",
            "/peek",
            &[],
            full(Bytes::from("x".repeat(LIMIT + 1))),
        )
        .await;
    assert_eq!(big.status, 413);
    assert_eq!(big.header("x-puddle-blocked"), Some("body_too_large"));
    assert_eq!(bodies(&peek), [Some(b"refuse".to_vec())]);
    assert!(server.recorded().is_empty());
    client.close().await;
    let event = &rig.events(1).await[0];
    assert_eq!(event.reason, ConnectionReason::Refused("peek_refused"));
}

fn quick() -> ProxyConfig {
    ProxyConfig::default().with_terminate_timeouts(
        Duration::from_secs(10),
        Duration::from_secs(60),
        Duration::from_secs(30),
        Duration::from_millis(300),
    )
}

#[tokio::test]
async fn a_body_that_does_not_arrive_is_a_408_and_nothing_goes_upstream() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("never")),
    )
    .await;
    let peek = Arc::new(Peek::default());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(peek.clone())
        .config(quick())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /peek HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 5\r\n\r\nab")
        .await;
    assert_eq!(client.response("POST").await.status, 408);
    assert_eq!(bodies(&peek), []);
    assert!(server.recorded().is_empty());
}

#[tokio::test]
async fn over_http2_a_body_that_does_not_arrive_is_a_408_and_nothing_goes_upstream() {
    let pki = Pki::new();
    let server = H2Server::recording(
        &pki,
        "bound.test",
        Arc::new(|_| terminate_support::h2_rig::reply(200, "never")),
    )
    .await;
    let peek = Arc::new(Peek::default());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(peek.clone())
        .config(quick())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let stalled = client
        .request(
            "POST",
            "bound.test",
            "/peek",
            &[],
            terminate_support::h2_rig::open_body(),
        )
        .await;
    assert_eq!(stalled.status, 408);
    assert_eq!(bodies(&peek), []);
    assert!(server.recorded().is_empty());
}

/// What the injector sees (and the server never does) when the guest cuts a stream short or sends
/// more than the limit without saying so.
#[tokio::test]
async fn over_http2_a_stream_cut_short_or_longer_than_it_said_never_reaches_the_server() {
    let pki = Pki::new();
    let server = H2Server::recording(
        &pki,
        "bound.test",
        Arc::new(|_| terminate_support::h2_rig::reply(200, "never")),
    )
    .await;
    let peek = Arc::new(Peek::default());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(peek.clone())
        .build();
    let mut guest = rig.guest().await;
    let client = guest
        .tls_with("bound.test:443", None, &[b"h2"], true)
        .await
        .unwrap();
    let (mut send, connection) = h2::client::handshake(client.stream.into_inner())
        .await
        .unwrap();
    tokio::spawn(connection);
    let post = |length: Option<&str>| {
        let mut request = http::Request::builder()
            .method("POST")
            .uri("https://bound.test/peek");
        if let Some(length) = length {
            request = request.header("content-length", length);
        }
        request.body(()).unwrap()
    };
    // Ended cleanly short of its Content-Length: refused (the guest has already gone, so it never
    // reads the answer).
    let (_response, mut body) = send.send_request(post(Some("50")), false).unwrap();
    body.send_data(Bytes::from_static(b"0123456789"), false)
        .unwrap();
    body.send_reset(h2::Reason::NO_ERROR);
    // More than the limit with no length given: 413.
    let (response, mut body) = send.send_request(post(None), false).unwrap();
    body.send_data(Bytes::from("x".repeat(LIMIT + 1)), true)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), 413);
    // Cancelled mid-body: nothing goes upstream and the connection goes on.
    let (_response, mut body) = send.send_request(post(Some("50")), false).unwrap();
    body.send_data(Bytes::from_static(b"0123456789"), false)
        .unwrap();
    body.send_reset(h2::Reason::CANCEL);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A request that ends with trailers: the injector gets the data, the trailers are dropped.
    let (response, mut body) = send.send_request(post(Some("2")), false).unwrap();
    body.send_data(Bytes::from_static(b"ok"), false).unwrap();
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", http::HeaderValue::from_static("1"));
    body.send_trailers(trailers).unwrap();
    assert_eq!(response.await.unwrap().status(), 200);
    assert_eq!(bodies(&peek), [Some(b"ok".to_vec())]);
    assert_eq!(server.recorded().len(), 1);
}
