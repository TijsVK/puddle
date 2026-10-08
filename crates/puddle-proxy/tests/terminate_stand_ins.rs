// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of secret stand-ins on terminated connections: the real value reaches the real server
//! and nothing else, a stand-in toward any other host goes out unchanged and is flagged, and
//! another workspace's stand-in means nothing.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use puddle_proxy::{
    InjectDecision, SecretValue, StandIn, StandInOrigin, StandIns, TerminationSet, secret_stand_in,
};
use terminate_support::{
    FakeServer, Flaw, Handler, Pki, Reply, RigBuilder, TestInjector, captured_logs, read_response,
};
use tokio::io::AsyncWriteExt;

/// What the real server must get, and nothing else must ever see.
const REAL_KEY: &str = "sk-live-5c1d9e0a47b2";
const REAL_TOKEN: &str = "ghp_LIVE8f3b2a91c4d7e60";

fn ok_handler() -> Handler {
    Arc::new(|_| Reply::ok("hello from upstream"))
}

async fn upstream(pki: &Pki, name: &str, handler: Handler) -> FakeServer {
    FakeServer::tls(pki.server_config(name, Flaw::None), handler).await
}

fn entry(name: &str, real: &str, hosts: &[&str]) -> (String, StandIn) {
    let stand_in = secret_stand_in(name).unwrap();
    let entry = StandIn::new(
        StandInOrigin::Secret,
        name,
        &stand_in,
        SecretValue::new(real),
        TerminationSet::parse(hosts.iter().copied()).unwrap(),
    )
    .unwrap();
    (stand_in, entry)
}

/// A registry with `API_KEY` for `bound.test`; the injector never injects.
fn registry() -> (Arc<StandIns>, String) {
    let stand_ins = Arc::new(StandIns::new());
    let (stand_in, entry) = entry("API_KEY", REAL_KEY, &["bound.test"]);
    stand_ins.insert(entry).unwrap();
    (stand_ins, stand_in)
}

fn pass_through() -> Arc<TestInjector> {
    TestInjector::new(|_| InjectDecision::PassThrough)
}

#[tokio::test]
async fn a_stand_in_is_swapped_toward_its_host_and_only_the_real_server_sees_the_real_value() {
    let pki = Pki::new();
    let server = upstream(&pki, "bound.test", ok_handler()).await;
    let (stand_ins, stand_in) = registry();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            format!("GET /v1/models?key={stand_in} HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer {stand_in}\r\nX-Api-Key: {stand_in}\r\nCookie: a=1; k={stand_in}\r\nUser-Agent: tool/1\r\n\r\n")
                .as_bytes(),
        )
        .await;
    let response = client.response("GET").await;
    assert_eq!(response.status, 200);
    assert!(!format!("{response:?}").contains(REAL_KEY));

    let seen = server.recorded();
    let request = &seen[0];
    assert_eq!(
        request.headers_named("authorization"),
        [format!("Bearer {REAL_KEY}")]
    );
    assert_eq!(request.headers_named("x-api-key"), [REAL_KEY]);
    assert_eq!(
        request.headers_named("cookie"),
        [format!("a=1; k={REAL_KEY}")]
    );
    assert_eq!(request.header("user-agent"), Some("tool/1"));
    assert_eq!(
        request.target,
        format!("/v1/models?key={stand_in}"),
        "the query string is never swapped"
    );

    client.close().await;
    let event = &rig.events(1).await[0];
    assert!(event.injected);
    assert_eq!(event.binding_id.as_deref(), Some("stand-in:secret:API_KEY"));
    assert!(!event.placeholder_unbound);
    assert_eq!(event.http.as_ref().unwrap().path(), "/v1/models");
    let audit = format!("{event:?}");
    assert!(!audit.contains(REAL_KEY) && !audit.contains(&stand_in));
    assert!(
        !captured_logs().contains(REAL_KEY),
        "the real value reached a log"
    );
}

#[tokio::test]
async fn a_git_style_basic_value_is_decoded_swapped_and_encoded_again() {
    let pki = Pki::new();
    let server = upstream(&pki, "bound.test", ok_handler()).await;
    let stand_ins = Arc::new(StandIns::new());
    let (stand_in, entry) = entry("GH_TOKEN", REAL_TOKEN, &["bound.test"]);
    stand_ins.insert(entry).unwrap();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let basic = STANDARD.encode(format!("x-access-token:{stand_in}"));
    client
        .send(
            format!("GET /org/repo/info/refs HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Basic {basic}\r\n\r\n")
                .as_bytes(),
        )
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    let seen = server.recorded();
    let sent = seen[0].header("authorization").unwrap();
    let credentials = sent.strip_prefix("Basic ").unwrap();
    assert_eq!(
        String::from_utf8(STANDARD.decode(credentials).unwrap()).unwrap(),
        format!("x-access-token:{REAL_TOKEN}")
    );
    assert!(!captured_logs().contains(REAL_TOKEN));
}

#[tokio::test]
async fn a_stand_in_added_while_a_connection_is_open_applies_from_its_next_request() {
    let pki = Pki::new();
    let server = upstream(&pki, "bound.test", ok_handler()).await;
    let stand_ins = Arc::new(StandIns::new());
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let (stand_in, entry) = entry("API_KEY", REAL_KEY, &["bound.test"]);
    let ask = format!("GET /x HTTP/1.1\r\nHost: bound.test\r\nX-Api-Key: {stand_in}\r\n\r\n");
    client.send(ask.as_bytes()).await;
    assert_eq!(client.response("GET").await.status, 200);
    stand_ins.insert(entry).unwrap();
    client.send(ask.as_bytes()).await;
    assert_eq!(client.response("GET").await.status, 200);
    assert!(stand_ins.remove(&stand_in));
    client.send(ask.as_bytes()).await;
    assert_eq!(client.response("GET").await.status, 200);

    let seen = server.recorded();
    let sent: Vec<_> = seen
        .iter()
        .map(|r| r.header("x-api-key").unwrap())
        .collect();
    assert_eq!(sent, [stand_in.as_str(), REAL_KEY, stand_in.as_str()]);
    assert_eq!(server.accepted(), 1, "all on one upstream connection");
}

#[tokio::test]
async fn a_stand_in_toward_another_decrypted_host_goes_out_unchanged_and_is_flagged() {
    let pki = Pki::new();
    let home = upstream(&pki, "bound.test", ok_handler()).await;
    let elsewhere = upstream(&pki, "elsewhere.test", ok_handler()).await;
    let (stand_ins, stand_in) = registry();
    let rig = RigBuilder::new(&pki)
        .bound(vec!["bound.test", "elsewhere.test"])
        .allow(vec!["bound.test", "elsewhere.test"])
        .name("bound.test", home.addr)
        .name("elsewhere.test", elsewhere.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("elsewhere.test:443", None).await.unwrap();
    client
        .send(
            format!("GET /x HTTP/1.1\r\nHost: elsewhere.test\r\nAuthorization: Bearer {stand_in}\r\n\r\n")
                .as_bytes(),
        )
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    client.close().await;

    let seen = elsewhere.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Bearer {stand_in}")],
        "unchanged: worthless there"
    );
    assert!(home.recorded().is_empty());
    let event = &rig.events(1).await[0];
    assert!(event.placeholder_unbound);
    assert!(!event.injected, "nothing was added");
    assert_eq!(event.binding_id, None);
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn another_workspaces_stand_in_is_just_a_string() {
    let pki = Pki::new();
    let server = upstream(&pki, "bound.test", ok_handler()).await;
    let (stand_ins, stand_in) = registry();
    // The second workspace has stand-ins of its own, for the same host and the same secret name.
    let theirs = Arc::new(StandIns::new());
    let (their_stand_in, their_entry) = entry("API_KEY", "their-real-value-77aa", &["bound.test"]);
    theirs.insert(their_entry).unwrap();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .other_stand_ins(&theirs)
        .build();
    assert_ne!(stand_in, their_stand_in, "random per workspace and secret");

    // The first workspace's stand-in, sent from the second workspace.
    let mut guest = rig.other_guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            format!("GET /x HTTP/1.1\r\nHost: bound.test\r\nX-Api-Key: {stand_in}\r\n\r\n")
                .as_bytes(),
        )
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    // And the second's own is swapped for the second's value.
    client
        .send(
            format!("GET /y HTTP/1.1\r\nHost: bound.test\r\nX-Api-Key: {their_stand_in}\r\n\r\n")
                .as_bytes(),
        )
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    client.close().await;

    let seen = server.recorded();
    assert_eq!(seen[0].header("x-api-key"), Some(stand_in.as_str()));
    assert_eq!(seen[1].header("x-api-key"), Some("their-real-value-77aa"));
    assert!(!seen.iter().any(|r| r.header("x-api-key") == Some(REAL_KEY)));
    let events = rig.events(1).await;
    assert!(
        !events[0].placeholder_unbound,
        "an unknown stand-in is not one of this workspace's"
    );
}

#[tokio::test]
async fn a_stand_in_in_plain_http_is_never_swapped() {
    let pki = Pki::new();
    let plain = FakeServer::plain(ok_handler()).await;
    let (stand_ins, stand_in) = registry();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", plain.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let guest = rig.guest().await;
    let stream = guest.control.clone().open_stream().await.unwrap();
    let mut stream = tokio::io::BufReader::new(stream);
    stream
        .get_mut()
        .write_all(
            format!("GET http://bound.test/x HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer {stand_in}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_response(&mut stream, "GET").await.expect("a response");
    assert_eq!(response.status, 200);
    let seen = plain.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Bearer {stand_in}")]
    );
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn a_server_whose_certificate_is_not_accepted_never_gets_the_real_value() {
    let pki = Pki::new();
    let bad = FakeServer::tls(
        pki.server_config("bound.test", Flaw::UnknownRoot),
        Arc::new(|_| Reply::ok("never")),
    )
    .await;
    let (stand_ins, stand_in) = registry();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", bad.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            format!(
                "GET /x HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer {stand_in}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await;
    let response = client.response("GET").await;
    assert_eq!(response.status, 502);
    assert!(bad.recorded().is_empty());
    assert!(!format!("{response:?}").contains(REAL_KEY));
    let event = &rig.events(1).await[0];
    assert!(!event.injected && !event.placeholder_unbound);
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn a_stand_in_and_a_credential_binding_work_side_by_side() {
    let pki = Pki::new();
    let server = upstream(&pki, "bound.test", ok_handler()).await;
    let (stand_ins, stand_in) = registry();
    // The injector sets `Authorization`; the guest's stand-in in another header is still swapped,
    // and the injected value is not touched.
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(TestInjector::always())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            format!("GET /x HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer {stand_in}\r\nX-Api-Key: {stand_in}\r\n\r\n")
                .as_bytes(),
        )
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    client.close().await;
    let seen = server.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Basic {}", terminate_support::CANARY)]
    );
    assert_eq!(seen[0].headers_named("x-api-key"), [REAL_KEY]);
    let event = &rig.events(1).await[0];
    assert_eq!(
        event.binding_id.as_deref(),
        Some("binding-1"),
        "the credential binding is the one the audit names"
    );
    assert!(event.injected);
}
