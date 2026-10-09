// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of the token-exchange seam on terminated connections: an exchange's request body has
//! its stand-ins swapped for the real values (one named field, toward the stand-in's hosts only),
//! its answer is read and may be replaced, and everything that is not an exchange streams as it
//! always did, on HTTP/1.1 and on HTTP/2.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::future::Future as _;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use puddle_proxy::{
    AnswerHead, AnswerRewriter, BoxFuture, Exchange, ExchangeRewriter, InjectContext,
    InjectDecision, Injector, RequestView, SecretValue, StandIn, StandInOrigin, StandIns,
    TerminationSet,
};
use puddle_types::Host;
use terminate_support::h2_rig::{H2Server, Reply as H2Reply, Script, full};
use terminate_support::{
    FakeServer, Flaw, Handler, Pki, Reply, RigBuilder, TestInjector, captured_logs,
};

const REAL_REFRESH: &str = "CANARY-real-refresh-5f1c9d3a7b";
const STAND_IN: &str = "puddle-stand-in-refresh-0123456789abcdef";
const HOST: &str = "login.test";
const PATH: &str = "/oauth/token";

/// What an answer's head said: status, content type, content encoding, length.
type Head = (u16, Option<String>, Option<String>, Option<u64>);

/// What the fake rewriter did, for the tests to read.
#[derive(Debug, Default)]
struct Seen {
    heads: Vec<Head>,
    bodies: Vec<Vec<u8>>,
    too_large: usize,
    begun: usize,
}

#[derive(Debug, Clone, Copy)]
enum Plan {
    /// The answer is not wanted.
    Skip,
    /// The answer is wanted and left as it is.
    Keep,
    /// The answer is wanted and replaced.
    Replace(&'static str),
}

#[derive(Debug)]
struct Rewriter {
    swap: Option<&'static str>,
    plan: Plan,
    seen: Arc<Mutex<Seen>>,
}

struct Answer {
    plan: Plan,
    seen: Arc<Mutex<Seen>>,
}

impl AnswerRewriter for Answer {
    fn wants(&mut self, head: &AnswerHead<'_>) -> bool {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .heads
            .push((
                head.status,
                head.content_type.map(str::to_owned),
                head.content_encoding.map(str::to_owned),
                head.content_length,
            ));
        !matches!(self.plan, Plan::Skip)
    }

    fn rewrite<'a>(
        &'a mut self,
        _: &'a AnswerHead<'a>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Option<Bytes>> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bodies
            .push(body.to_vec());
        let new = match self.plan {
            Plan::Replace(text) => Some(Bytes::from_static(text.as_bytes())),
            Plan::Skip | Plan::Keep => None,
        };
        Box::pin(std::future::ready(new))
    }

    fn too_large(&mut self) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .too_large += 1;
    }
}

impl ExchangeRewriter for Rewriter {
    fn begin(&self, host: &Host, method: &str, path: &str) -> Option<Exchange> {
        if host.to_string() != HOST || method != "POST" || path != PATH {
            return None;
        }
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .begun += 1;
        let mut exchange = Exchange::new().answered_by(Box::new(Answer {
            plan: self.plan,
            seen: Arc::clone(&self.seen),
        }));
        if let Some(field) = self.swap {
            exchange = exchange.swapping(field);
        }
        Some(exchange)
    }
}

fn rewriter(swap: Option<&'static str>, plan: Plan) -> (Arc<Rewriter>, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    (
        Arc::new(Rewriter {
            swap,
            plan,
            seen: Arc::clone(&seen),
        }),
        seen,
    )
}

/// A registry with the refresh stand-in, for `hosts`.
fn registry(hosts: &[&str]) -> Arc<StandIns> {
    let stand_ins = Arc::new(StandIns::new());
    stand_ins
        .insert(
            StandIn::new(
                StandInOrigin::CapturedLogin,
                "test-refresh",
                STAND_IN,
                SecretValue::new(REAL_REFRESH),
                TerminationSet::parse(hosts.iter().copied()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    stand_ins
}

fn json_reply(body: &str) -> Reply {
    Reply::raw(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn chunked_reply(body: &[u8]) -> Reply {
    let mut bytes =
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    for piece in body.chunks(1000) {
        bytes.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        bytes.extend_from_slice(piece);
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"0\r\n\r\n");
    Reply::raw(bytes)
}

async fn server(pki: &Pki, handler: Handler) -> FakeServer {
    FakeServer::tls(pki.server_config(HOST, Flaw::None), handler).await
}

fn pass_through() -> Arc<TestInjector> {
    TestInjector::new(|_| InjectDecision::PassThrough)
}

fn post(path: &str, content_type: &str, body: &str, extra: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {HOST}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn rig_for(
    pki: &Pki,
    upstream: &FakeServer,
    exchanges: Arc<Rewriter>,
    stand_ins: &Arc<StandIns>,
) -> terminate_support::Rig {
    RigBuilder::new(pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .stand_ins(stand_ins)
        .exchanges(exchanges)
        .build()
}

#[tokio::test]
async fn an_answer_is_replaced_and_the_guest_gets_it_at_its_own_length() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply(r#"{"a":"short"}"#))).await;
    let (exchanges, seen) = rewriter(None, Plan::Replace(r#"{"a":"a much longer replacement"}"#));
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    client.send(&post(PATH, "application/json", "{}", "")).await;
    let response = client.response("POST").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), r#"{"a":"a much longer replacement"}"#);
    assert_eq!(
        response.header("content-length"),
        Some("33"),
        "the guest's framing is the new body's"
    );
    assert_eq!(response.header("transfer-encoding"), None);
    assert_eq!(response.header("content-type"), Some("application/json"));
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.bodies, [br#"{"a":"short"}"#.to_vec()]);
        assert_eq!(
            seen.heads,
            [(200, Some("application/json".into()), None, Some(13))]
        );
    }
    // The same connection carries the next request.
    client.send(&post("/other", "text/plain", "x", "")).await;
    assert_eq!(client.response("POST").await.status, 200);
}

#[tokio::test]
async fn a_chunked_answer_is_read_in_full_and_sent_with_a_length() {
    let pki = Pki::new();
    let body = format!(r#"{{"padding":"{}"}}"#, "x".repeat(5000));
    let reply = chunked_reply(body.as_bytes());
    let upstream = server(&pki, Arc::new(move |_| reply.clone())).await;
    let (exchanges, seen) = rewriter(None, Plan::Replace("{}"));
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    client.send(&post(PATH, "application/json", "{}", "")).await;
    let response = client.response("POST").await;
    assert_eq!(response.text(), "{}");
    assert_eq!(response.header("content-length"), Some("2"));
    assert_eq!(response.header("transfer-encoding"), None);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.bodies[0], body.as_bytes());
    assert_eq!(seen.heads[0].3, None, "no length was announced");
}

#[tokio::test]
async fn an_answer_the_rewriter_keeps_or_does_not_want_reaches_the_guest_as_the_server_sent_it() {
    let pki = Pki::new();
    for plan in [Plan::Keep, Plan::Skip] {
        let upstream = server(&pki, Arc::new(|_| json_reply(r#"{"ok":true}"#))).await;
        let (exchanges, seen) = rewriter(None, plan);
        let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
        let mut guest = rig.guest().await;
        let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
        client.send(&post(PATH, "application/json", "{}", "")).await;
        let response = client.response("POST").await;
        assert_eq!(response.text(), r#"{"ok":true}"#, "{plan:?}");
        assert_eq!(response.header("content-length"), Some("11"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.heads.len(), 1);
        assert_eq!(seen.bodies.len(), usize::from(matches!(plan, Plan::Keep)));
    }
}

#[tokio::test]
async fn an_answer_over_the_cap_goes_through_whole_and_the_rewriter_is_told() {
    let pki = Pki::new();
    let body: Vec<u8> = (0..70_000_u32).map(|i| b'a' + (i % 26) as u8).collect();
    let reply = chunked_reply(&body);
    let upstream = server(&pki, Arc::new(move |_| reply.clone())).await;
    let (exchanges, seen) = rewriter(None, Plan::Replace("never"));
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    client.send(&post(PATH, "application/json", "{}", "")).await;
    let response = client.response("POST").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, body, "every byte, in order");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.too_large, 1);
    assert!(seen.bodies.is_empty(), "the rewriter was not handed a part");
}

#[tokio::test]
async fn the_upstream_is_asked_for_an_unencoded_answer_only_when_the_answer_is_read() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let (exchanges, _) = rewriter(None, Plan::Keep);
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    client
        .send(&post(
            PATH,
            "application/json",
            "{}",
            "Accept-Encoding: gzip\r\n",
        ))
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    client
        .send(&post(
            "/elsewhere",
            "application/json",
            "{}",
            "Accept-Encoding: gzip\r\n",
        ))
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    let recorded = upstream.recorded();
    assert_eq!(recorded[0].header("accept-encoding"), None);
    assert_eq!(recorded[1].header("accept-encoding"), Some("gzip"));
}

#[tokio::test]
async fn a_stand_in_in_the_named_field_is_swapped_for_the_real_value_toward_its_host_only() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();

    let json = format!(
        r#"{{"grant_type":"refresh_token","refresh_token":"{STAND_IN}","client_id":"abc","note":"{STAND_IN}"}}"#
    );
    client
        .send(&post(PATH, "application/json", &json, ""))
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    let form = format!("grant_type=refresh_token&refresh_token={STAND_IN}&client_id=abc");
    client
        .send(&post(
            PATH,
            "application/x-www-form-urlencoded; charset=utf-8",
            &form,
            "",
        ))
        .await;
    assert_eq!(client.response("POST").await.status, 200);

    let recorded = upstream.recorded();
    let sent: serde_json::Value = serde_json::from_slice(&recorded[0].body).unwrap();
    assert_eq!(sent["refresh_token"], REAL_REFRESH);
    assert_eq!(sent["grant_type"], "refresh_token");
    assert_eq!(sent["client_id"], "abc");
    assert_eq!(sent["note"], STAND_IN, "only the named field is swapped");
    assert_eq!(
        recorded[0].header("content-length"),
        Some(recorded[0].body.len().to_string().as_str())
    );
    assert_eq!(
        String::from_utf8(recorded[1].body.clone()).unwrap(),
        format!("grant_type=refresh_token&refresh_token={REAL_REFRESH}&client_id=abc")
    );
    assert_eq!(
        recorded[1].header("content-type"),
        Some("application/x-www-form-urlencoded; charset=utf-8")
    );
    client.close().await;
    let events = rig.events(1).await;
    assert!(events[0].injected);
    assert_eq!(
        events[0].binding_id.as_deref(),
        Some("stand-in:login:test-refresh")
    );
    assert!(!events[0].placeholder_unbound);
    assert!(!captured_logs().contains(REAL_REFRESH));
}

#[tokio::test]
async fn hostile_hg32_a_stand_in_in_the_refresh_field_goes_out_unchanged_toward_a_host_it_is_not_for()
 {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&["elsewhere.test"]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    let json = format!(r#"{{"refresh_token":"{STAND_IN}"}}"#);
    client
        .send(&post(PATH, "application/json", &json, ""))
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    client.close().await;
    assert_eq!(upstream.recorded()[0].body, json.as_bytes());
    let events = rig.events(1).await;
    assert!(events[0].placeholder_unbound);
    assert!(!events[0].injected);
}

#[tokio::test]
async fn hostile_hg32_a_body_that_is_not_a_token_message_is_never_swapped() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    for (content_type, body) in [
        ("text/plain", format!("refresh_token={STAND_IN}")),
        ("application/json", format!("[\"{STAND_IN}\"")),
        (
            "application/json",
            format!(r#"{{"refresh_token":["{STAND_IN}"]}}"#),
        ),
        (
            "application/x-www-form-urlencoded",
            format!("refresh_token={STAND_IN}&refresh_token={STAND_IN}"),
        ),
    ] {
        client.send(&post(PATH, content_type, &body, "")).await;
        assert_eq!(client.response("POST").await.status, 200);
        let recorded = upstream.recorded();
        assert_eq!(recorded.last().unwrap().body, body.as_bytes(), "{body}");
    }
    assert!(!captured_logs().contains(REAL_REFRESH));
}

#[tokio::test]
async fn hostile_hg32_a_request_body_over_the_cap_is_refused_and_nothing_goes_upstream() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    let big = format!(
        r#"{{"refresh_token":"{STAND_IN}","x":"{}"}}"#,
        "y".repeat(70_000)
    );
    client.send(&post(PATH, "application/json", &big, "")).await;
    let response = client.response("POST").await;
    assert_eq!(response.status, 413);
    assert_eq!(response.header("x-puddle-blocked"), Some("body_too_large"));
    assert!(upstream.recorded().is_empty());
}

#[tokio::test]
async fn requests_that_are_not_exchanges_stream_untouched() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply(r#"{"stays":"as is"}"#))).await;
    let (exchanges, seen) = rewriter(Some("refresh_token"), Plan::Replace("{}"));
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    let json = format!(r#"{{"refresh_token":"{STAND_IN}"}}"#);
    // Another path, and a GET of the exchange's own path.
    client
        .send(&post("/other", "application/json", &json, ""))
        .await;
    assert_eq!(client.response("POST").await.text(), r#"{"stays":"as is"}"#);
    assert_eq!(client.get(HOST, PATH).await.text(), r#"{"stays":"as is"}"#);
    let recorded = upstream.recorded();
    assert_eq!(recorded[0].body, json.as_bytes());
    assert_eq!(seen.lock().unwrap().begun, 0);
}

#[tokio::test]
async fn an_answer_that_stops_halfway_is_a_failed_request_not_a_stalled_one() {
    let pki = Pki::new();
    // Announces 100 bytes and sends 10.
    let upstream = server(
        &pki,
        Arc::new(|_| {
            Reply::raw(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{\"a\":\"bcd\"",
            )
            .closing()
        }),
    )
    .await;
    let (exchanges, seen) = rewriter(None, Plan::Replace("{}"));
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    client.send(&post(PATH, "application/json", "{}", "")).await;
    let response = client.response("POST").await;
    assert_eq!(response.status, 502);
    assert_eq!(seen.lock().unwrap().bodies.len(), 0);
}

// ------------------------------------------------------------------------------------------
// HTTP/2

fn json_h2(body: &'static str) -> H2Reply {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("content-length", body.len().to_string())
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

#[tokio::test]
async fn over_http2_the_request_swap_and_the_answer_rewrite_work_toward_an_http2_server() {
    let pki = Pki::new();
    let script: Script = Arc::new(|_| json_h2(r#"{"token":"short"}"#));
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let (exchanges, seen) = rewriter(
        Some("refresh_token"),
        Plan::Replace(r#"{"token":"a longer one"}"#),
    );
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .stand_ins(&registry(&[HOST]))
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest
        .h2(&format!("{HOST}:443"), &[b"h2", b"http/1.1"])
        .await;
    let json = format!(r#"{{"refresh_token":"{STAND_IN}","client_id":"abc"}}"#);
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[
                ("content-type", "application/json"),
                ("accept-encoding", "gzip"),
            ],
            full(Bytes::from(json)),
        )
        .await;
    assert_eq!(got.status, 200);
    assert_eq!(got.text(), r#"{"token":"a longer one"}"#);
    assert_eq!(got.header("content-length"), Some("24"));

    let recorded = upstream.recorded();
    assert_eq!(recorded[0].version, http::Version::HTTP_2);
    let sent: serde_json::Value = serde_json::from_slice(&recorded[0].body).unwrap();
    assert_eq!(sent["refresh_token"], REAL_REFRESH);
    assert_eq!(sent["client_id"], "abc");
    assert_eq!(recorded[0].header("accept-encoding"), None);
    assert_eq!(
        recorded[0].header("content-length"),
        Some(recorded[0].body.len().to_string().as_str())
    );
    assert_eq!(
        seen.lock().unwrap().bodies,
        [br#"{"token":"short"}"#.to_vec()]
    );
    // A request that is not an exchange on the same connection streams as before.
    let other = client
        .request("POST", HOST, "/other", &[], full(Bytes::from("x")))
        .await;
    assert_eq!(other.text(), r#"{"token":"short"}"#);
    client.close().await;
    let events = rig.events(1).await;
    assert!(events[0].injected);
    assert!(!captured_logs().contains(REAL_REFRESH));
}

#[tokio::test]
async fn over_http2_toward_an_http11_server_the_same_exchange_works() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply(r#"{"token":"short"}"#))).await;
    let (exchanges, _) = rewriter(
        Some("refresh_token"),
        Plan::Replace(r#"{"token":"a longer one"}"#),
    );
    let rig = rig_for(&pki, &upstream, exchanges, &registry(&[HOST]));
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let json = format!(r#"{{"refresh_token":"{STAND_IN}"}}"#);
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from(json)),
        )
        .await;
    assert_eq!(got.text(), r#"{"token":"a longer one"}"#);
    let recorded = upstream.recorded();
    let sent: serde_json::Value = serde_json::from_slice(&recorded[0].body).unwrap();
    assert_eq!(sent["refresh_token"], REAL_REFRESH);
    assert_eq!(
        recorded[0].header("content-length"),
        Some(recorded[0].body.len().to_string().as_str())
    );
}

#[tokio::test]
async fn over_http2_an_answer_over_the_cap_goes_through_whole() {
    let pki = Pki::new();
    let body: Vec<u8> = (0..70_000_u32).map(|i| b'a' + (i % 26) as u8).collect();
    let big = body.clone();
    let script: Script = Arc::new(move |_| {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(
                Full::new(Bytes::from(big.clone()))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap()
    });
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let (exchanges, seen) = rewriter(None, Plan::Replace("never"));
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from("{}")),
        )
        .await;
    assert_eq!(got.body, body);
    assert_eq!(seen.lock().unwrap().too_large, 1);
}

#[tokio::test]
async fn over_http2_a_body_over_the_cap_is_refused() {
    let pki = Pki::new();
    let script: Script = Arc::new(|_| json_h2("{}"));
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .stand_ins(&registry(&[HOST]))
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let big = format!(
        r#"{{"refresh_token":"{STAND_IN}","x":"{}"}}"#,
        "y".repeat(70_000)
    );
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from(big)),
        )
        .await;
    assert_eq!(got.status, 413);
    assert!(upstream.recorded().is_empty());
}

// ------------------------------------------------------------------------------------------
// An injector that wants the same body, and answers with trailers or breaks off.

/// Wants the body of the exchange's own request, and records what it was shown.
#[derive(Debug, Default)]
struct WantsBody {
    shown: Mutex<Vec<Vec<u8>>>,
}

impl Injector for WantsBody {
    fn body_wanted(&self, _: &InjectContext<'_>, request: &RequestView<'_>) -> Option<usize> {
        (request.method() == "POST" && request.path() == PATH).then_some(4096)
    }

    fn decide<'a>(
        &'a self,
        _: &'a InjectContext<'a>,
        request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision> {
        self.shown
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.body().unwrap_or_default().to_vec());
        Box::pin(std::future::ready(InjectDecision::PassThrough))
    }
}

#[tokio::test]
async fn a_body_the_injector_asked_for_is_read_once_and_the_exchange_swaps_in_it() {
    let pki = Pki::new();
    let upstream = server(&pki, Arc::new(|_| json_reply("{}"))).await;
    let injector = Arc::new(WantsBody::default());
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(injector.clone())
        .stand_ins(&registry(&[HOST]))
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls(&format!("{HOST}:443"), None).await.unwrap();
    let json = format!(r#"{{"refresh_token":"{STAND_IN}"}}"#);
    client
        .send(&post(PATH, "application/json", &json, ""))
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    // The injector saw what the guest sent; the server got the real value.
    assert_eq!(injector.shown.lock().unwrap()[0], json.as_bytes());
    let sent: serde_json::Value = serde_json::from_slice(&upstream.recorded()[0].body).unwrap();
    assert_eq!(sent["refresh_token"], REAL_REFRESH);
    assert!(!captured_logs().contains(REAL_REFRESH));
}

#[tokio::test]
async fn over_http2_a_body_the_injector_asked_for_is_read_once_and_the_exchange_swaps_in_it() {
    let pki = Pki::new();
    let script: Script = Arc::new(|_| json_h2("{}"));
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let injector = Arc::new(WantsBody::default());
    let (exchanges, _) = rewriter(Some("refresh_token"), Plan::Skip);
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(injector.clone())
        .stand_ins(&registry(&[HOST]))
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let json = format!(r#"{{"refresh_token":"{STAND_IN}"}}"#);
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from(json.clone())),
        )
        .await;
    assert_eq!(got.status, 200);
    assert_eq!(injector.shown.lock().unwrap()[0], json.as_bytes());
    let sent: serde_json::Value = serde_json::from_slice(&upstream.recorded()[0].body).unwrap();
    assert_eq!(sent["refresh_token"], REAL_REFRESH);
}

/// A response body that ends with trailers, or breaks off after its first piece.
struct Scripted {
    frames: std::collections::VecDeque<
        Result<http_body::Frame<Bytes>, terminate_support::h2_rig::BoxError>,
    >,
}

impl http_body::Body for Scripted {
    type Data = Bytes;
    type Error = terminate_support::h2_rig::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(self.frames.pop_front())
    }
}

/// A response body that gives one piece and then fails after a pause.
struct Breaks {
    first: Option<Bytes>,
    delay: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl http_body::Body for Breaks {
    type Data = Bytes;
    type Error = terminate_support::h2_rig::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        if let Some(piece) = self.first.take() {
            return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(piece))));
        }
        std::task::ready!(self.delay.as_mut().poll(cx));
        std::task::Poll::Ready(Some(Err("the server went away".into())))
    }
}

fn scripted(
    frames: Vec<Result<http_body::Frame<Bytes>, terminate_support::h2_rig::BoxError>>,
) -> H2Reply {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(
            Scripted {
                frames: frames.into(),
            }
            .boxed_unsync(),
        )
        .unwrap()
}

#[tokio::test]
async fn trailers_of_an_answer_that_is_read_are_not_part_of_what_the_guest_gets() {
    let pki = Pki::new();
    let script: Script = Arc::new(|_| {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-after", "1".parse().unwrap());
        scripted(vec![
            Ok(http_body::Frame::data(Bytes::from_static(b"{\"a\":1}"))),
            Ok(http_body::Frame::trailers(trailers)),
        ])
    });
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let (exchanges, seen) = rewriter(None, Plan::Keep);
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from("{}")),
        )
        .await;
    assert_eq!(got.text(), r#"{"a":1}"#);
    assert_eq!(got.trailers, None);
    assert_eq!(seen.lock().unwrap().bodies, [br#"{"a":1}"#.to_vec()]);
}

#[tokio::test]
async fn over_http2_an_answer_that_breaks_off_is_a_failed_request() {
    let pki = Pki::new();
    // The head and a first piece go out, then the server goes away a moment later.
    let script: Script = Arc::new(|_| {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(
                Breaks {
                    first: Some(Bytes::from_static(b"{\"a\"")),
                    delay: Box::pin(tokio::time::sleep(Duration::from_millis(150))),
                }
                .boxed_unsync(),
            )
            .unwrap()
    });
    let upstream = H2Server::recording(&pki, HOST, script).await;
    let (exchanges, seen) = rewriter(None, Plan::Replace("{}"));
    let rig = RigBuilder::new(&pki)
        .bound(vec![HOST])
        .allow(vec![HOST])
        .name(HOST, upstream.addr)
        .injector(pass_through())
        .exchanges(exchanges)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2(&format!("{HOST}:443"), &[b"h2"]).await;
    let got = client
        .request(
            "POST",
            HOST,
            PATH,
            &[("content-type", "application/json")],
            full(Bytes::from("{}")),
        )
        .await;
    assert_eq!(got.status, 502);
    assert!(
        got.text().contains("did not finish its answer"),
        "{}",
        got.text()
    );

    assert_eq!(seen.lock().unwrap().bodies.len(), 0);
}
