// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of secret stand-ins on HTTP/2 requests of a terminated connection: the same swap as on
//! HTTP/1.1, whatever version the real server speaks.
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
use terminate_support::h2_rig::{H2Server, Script, full, reply};
use terminate_support::{FakeServer, Flaw, Pki, Reply, RigBuilder, TestInjector, captured_logs};

const REAL_KEY: &str = "sk-live-5c1d9e0a47b2";

fn ok() -> Script {
    Arc::new(|_| reply(200, "ok"))
}

fn registry(hosts: &[&str]) -> (Arc<StandIns>, String) {
    let stand_ins = Arc::new(StandIns::new());
    let stand_in = secret_stand_in("API_KEY").unwrap();
    stand_ins
        .insert(
            StandIn::new(
                StandInOrigin::Secret,
                "API_KEY",
                &stand_in,
                SecretValue::new(REAL_KEY),
                TerminationSet::parse(hosts.iter().copied()).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    (stand_ins, stand_in)
}

fn pass_through() -> Arc<TestInjector> {
    TestInjector::new(|_| InjectDecision::PassThrough)
}

#[tokio::test]
async fn a_stand_in_is_swapped_on_an_http2_request_to_an_http2_server() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let (stand_ins, stand_in) = registry(&["bound.test"]);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2", b"http/1.1"]).await;
    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("x-access-token:{stand_in}"))
    );
    let got = client
        .request(
            "GET",
            "bound.test",
            &format!("/v1/models?key={stand_in}"),
            &[
                ("authorization", &basic),
                ("x-api-key", &stand_in),
                ("cookie", "a=1"),
                ("cookie", &format!("k={stand_in}")),
            ],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);

    let seen = server.recorded();
    let request = &seen[0];
    assert_eq!(request.version, http::Version::HTTP_2);
    assert_eq!(request.headers_named("x-api-key"), [REAL_KEY]);
    let credentials = request
        .header("authorization")
        .unwrap()
        .strip_prefix("Basic ")
        .unwrap();
    assert_eq!(
        String::from_utf8(STANDARD.decode(credentials).unwrap()).unwrap(),
        format!("x-access-token:{REAL_KEY}")
    );
    assert!(
        request
            .headers_named("cookie")
            .iter()
            .any(|c| c.contains(REAL_KEY) && !c.contains(&stand_in)),
        "{:?}",
        request.headers_named("cookie")
    );
    assert_eq!(
        request.path,
        format!("/v1/models?key={stand_in}"),
        "the query string is never swapped"
    );
    client.close().await;
    let event = &rig.events(1).await[0];
    assert!(event.injected && !event.placeholder_unbound);
    assert_eq!(event.binding_id.as_deref(), Some("stand-in:secret:API_KEY"));
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn an_http2_guest_gets_its_stand_in_swapped_toward_an_http11_server_too() {
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("h1 body")),
    )
    .await;
    let (stand_ins, stand_in) = registry(&["bound.test"]);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "GET",
            "bound.test",
            "/x",
            &[
                ("authorization", &format!("Bearer {stand_in}")),
                ("cookie", "a=1"),
                ("cookie", &format!("k={stand_in}")),
            ],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);
    let seen = server.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Bearer {REAL_KEY}")]
    );
    assert_eq!(
        seen[0].headers_named("cookie"),
        [format!("a=1; k={REAL_KEY}")],
        "the crumbs are joined for HTTP/1.1, then swapped"
    );
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn an_http2_stand_in_toward_another_decrypted_host_goes_out_unchanged_and_is_flagged() {
    let pki = Pki::new();
    let home = H2Server::recording(&pki, "bound.test", ok()).await;
    let elsewhere = H2Server::recording(&pki, "elsewhere.test", ok()).await;
    let (stand_ins, stand_in) = registry(&["bound.test"]);
    let rig = RigBuilder::new(&pki)
        .bound(vec!["bound.test", "elsewhere.test"])
        .allow(vec!["bound.test", "elsewhere.test"])
        .name("bound.test", home.addr)
        .name("elsewhere.test", elsewhere.addr)
        .injector(pass_through())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("elsewhere.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "GET",
            "elsewhere.test",
            "/x",
            &[("authorization", &format!("Bearer {stand_in}"))],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);
    client.close().await;
    let seen = elsewhere.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Bearer {stand_in}")]
    );
    assert!(home.recorded().is_empty());
    let event = &rig.events(1).await[0];
    assert!(event.placeholder_unbound && !event.injected);
    assert!(!captured_logs().contains(REAL_KEY));
}

#[tokio::test]
async fn an_http2_stand_in_is_swapped_alongside_an_injected_credential() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", ok()).await;
    let (stand_ins, stand_in) = registry(&["bound.test"]);
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(TestInjector::always())
        .stand_ins(&stand_ins)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client
        .request(
            "GET",
            "bound.test",
            "/x",
            &[
                ("authorization", &format!("Bearer {stand_in}")),
                ("x-api-key", &stand_in),
            ],
            full(bytes::Bytes::new()),
        )
        .await;
    assert_eq!(got.status, 200);
    let seen = server.recorded();
    assert_eq!(
        seen[0].headers_named("authorization"),
        [format!("Basic {}", terminate_support::CANARY)]
    );
    assert_eq!(seen[0].headers_named("x-api-key"), [REAL_KEY]);
    client.close().await;
    let event = &rig.events(1).await[0];
    assert_eq!(event.binding_id.as_deref(), Some("binding-1"));
}
