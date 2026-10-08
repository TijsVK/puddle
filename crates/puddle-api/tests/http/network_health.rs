// SPDX-License-Identifier: GPL-3.0-or-later
//! `GET /api/network-health` over real HTTP: the fake, the real report over faked OS answers and
//! a real fake proxy, redaction, the `network_changed` event.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use puddle_api::{
    FakeNetworkHealth, HostNetworkHealth, NetworkHealthService, forward_network_changes,
};
use puddle_certs::{CorporateRoots, SOURCES, StoreSnapshot};
use puddle_store::{Clock, ManualClock};
use puddle_upstream::{
    BasicAuth, Behaviour, Chain, ChainConfig, Config, Credentials, Destination, Discovery, FakeOs,
    FakeProxy, Form, Hop, ProxyConfig, ProxyProblem, ProxyRules, Request, Scheme,
};
use serde_json::{Value, json};

use crate::common::{START_MS, start, start_with_network};
use crate::events::Stream;

#[tokio::test]
async fn without_a_service_the_report_says_it_is_unavailable() {
    let api = start().await;
    let reply = api.get("/api/network-health").await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.error(), "unavailable");
}

#[tokio::test]
async fn the_report_needs_the_token() {
    let api = start().await;
    let request = format!(
        "GET /api/network-health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        api.host()
    );
    let reply = crate::common::raw(api.addr, request.as_bytes()).await;
    assert_eq!(reply.status, 401);
}

#[tokio::test]
async fn the_fake_serves_a_direct_machine_stamped_with_the_clock_until_it_is_told_otherwise() {
    let clock = Arc::new(ManualClock::new(START_MS));
    let fake = Arc::new(FakeNetworkHealth::new(clock.clone() as Arc<dyn Clock>));
    let api = start_with_network(fake.clone()).await;
    let reply = api.get("/api/network-health").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["generated_at"], START_MS);
    assert_eq!(body["proxy"]["detected"], "direct");
    assert_eq!(body["proxy"]["pac_url"], Value::Null);
    assert_eq!(body["roots"]["synced"], false);
    assert_eq!(body["sign_in"]["methods"], json!([]));
    assert_eq!(
        body["pull_proxy"],
        json!({"active": false, "via_upstream": false})
    );

    let mut changed = serde_json::from_value(body).unwrap();
    let report: &mut puddle_api::wire::NetworkHealth = &mut changed;
    report.proxy.https_proxy = Some("proxy.corp:8080".into());
    fake.set(changed);
    clock.advance(5);
    let body = api.get("/api/network-health").await.json();
    assert_eq!(body["proxy"]["https_proxy"], "proxy.corp:8080");
    assert_eq!(body["generated_at"], START_MS + 5);
}

fn root_snapshot() -> StoreSnapshot {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Corp Root CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_after = rcgen::date_time_ymd(2090, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let mut snapshot = StoreSnapshot::new();
    snapshot.add(SOURCES[0], cert.der().to_vec());
    snapshot.add(SOURCES[0], b"not a certificate".to_vec());
    snapshot.note_unreadable(SOURCES[1], "access denied");
    snapshot
}

/// Every secret the setup below holds; none may reach the body.
const SECRETS: [&str; 5] = ["hunter2", "topsecret", "pw-rule", "pw-wrong", "pw-right"];

#[tokio::test]
async fn the_real_report_shows_the_setup_and_never_a_secret() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "svc".into(),
        password: "pw-right".into(),
    })
    .await;
    // A PAC address and static rules that carry credentials; a PAC that answers the fake proxy.
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://svc:hunter2@pac.corp/p.pac?key=topsecret#frag".into()),
        rules: ProxyRules::parse("http://svc:pw-rule@static.corp:3128"),
        auto_detect: true,
        ..ProxyConfig::default()
    });
    let hop = Hop::Proxy(proxy.proxy_addr());
    os.set_pac(move |_| Ok(vec![hop.clone(), Hop::Direct]));
    let discovery = Discovery::new(os, Config::default());
    let auth = Arc::new(BasicAuth::new().with_default(Credentials::new("svc", "pw-wrong")));
    let chain = Chain::with_config(
        discovery.clone(),
        auth,
        ChainConfig::default()
            .with_timeouts(Duration::from_millis(500), Duration::from_millis(400)),
    );
    let dest = Destination::new(Scheme::Https, "registry.corp.test", 443);
    chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    discovery.report_failure(&puddle_upstream::ProxyAddr::new("static.corp", 3128));

    let clock = Arc::new(ManualClock::new(START_MS));
    let health = Arc::new(
        HostNetworkHealth::new(discovery.clone(), clock as Arc<dyn Clock>).with_chain(chain),
    );
    health.set_roots(Arc::new(CorporateRoots::select(
        &root_snapshot(),
        SystemTime::now(),
    )));
    health.set_pull_proxy(true, true);
    let api = start_with_network(health.clone() as Arc<dyn NetworkHealthService>).await;

    let reply = api.get("/api/network-health").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for secret in SECRETS {
        assert!(
            !reply.body.contains(secret),
            "{secret} leaked: {}",
            reply.body
        );
    }
    let body = reply.json();
    let proxy_part = &body["proxy"];
    assert_eq!(proxy_part["mode"], "system");
    assert_eq!(proxy_part["detected"], "pac");
    assert_eq!(proxy_part["pac_url"], "http://pac.corp/p.pac");
    assert_eq!(proxy_part["pac_state"], "answering");
    assert_eq!(proxy_part["https_proxy"], "static.corp:3128");
    assert_eq!(proxy_part["last_change_at"], Value::Null);
    assert_eq!(proxy_part["dead_proxies"][0]["proxy"], "static.corp:3128");
    assert_eq!(body["sign_in"]["methods"], json!(["basic"]));
    let attempt = &body["sign_in"]["attempts"][0];
    assert_eq!(attempt["proxy"], proxy.proxy_addr().to_string());
    assert_eq!(attempt["scheme"], "Basic");
    assert_eq!(attempt["result"], "failed");
    let roots = &body["roots"];
    assert_eq!(
        (roots["synced"].clone(), roots["roots"].clone()),
        (json!(true), json!(1))
    );
    assert_eq!(roots["certificates"][0]["subject"], "Corp Root CA");
    assert_eq!(roots["certificates"][0]["kind"], "root");
    assert_eq!(roots["skipped"][0]["reason"], "not a readable certificate");
    assert!(
        roots["unreadable_stores"][0]
            .as_str()
            .unwrap()
            .contains("access denied")
    );
    assert_eq!(
        body["pull_proxy"],
        json!({"active": true, "via_upstream": true})
    );
    let route = &body["routes"][0];
    assert_eq!(route["host"], "registry.corp.test");
    assert_eq!(route["source"], "pac");
    assert_eq!(route["hops"][1], "DIRECT");
}

#[tokio::test]
async fn a_setup_that_does_not_work_as_set_is_listed_in_the_report_without_a_secret() {
    let os = FakeOs::failing_watch(
        ProxyConfig {
            problems: vec![ProxyProblem::unusable(
                "the HTTPS_PROXY variable (\"socks5://p:1080\"): unsupported proxy scheme \"socks5\"",
            )],
            read_error: Some(
                "the machine-wide WinHTTP proxy could not be read: access denied".into(),
            ),
            ..ProxyConfig::default()
        },
        "the registry watch stopped (error 6), Basic dXNlcjpwYXNzd29yZA==",
    );
    let discovery = Discovery::new(os, Config::default());
    assert!(discovery.watch().is_none());
    let clock = Arc::new(ManualClock::new(START_MS));
    let health = Arc::new(HostNetworkHealth::new(discovery, clock as Arc<dyn Clock>));
    let api = start_with_network(health).await;

    let reply = api.get("/api/network-health").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        !reply.body.contains("dXNlcjpwYXNzd29yZA"),
        "token leaked: {}",
        reply.body
    );
    let proxy = &reply.json()["proxy"];
    assert_eq!(proxy["problems"][0]["kind"], "unusable_setting");
    assert!(
        proxy["problems"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("HTTPS_PROXY")
    );
    assert_eq!(proxy["problems"][1]["kind"], "changes_not_noticed");
    assert!(
        proxy["problems"][1]["detail"]
            .as_str()
            .unwrap()
            .contains("registry watch stopped")
    );
    assert!(
        proxy["settings_error"]
            .as_str()
            .unwrap()
            .contains("machine-wide")
    );
    // A healthy setup lists nothing.
    let quiet = Discovery::new(FakeOs::new(ProxyConfig::default()), Config::default());
    let clock = Arc::new(ManualClock::new(START_MS));
    let api = start_with_network(Arc::new(HostNetworkHealth::new(
        quiet,
        clock as Arc<dyn Clock>,
    )))
    .await;
    assert_eq!(
        api.get("/api/network-health").await.json()["proxy"]["problems"],
        json!([])
    );
}

#[tokio::test]
async fn a_pull_proxy_that_is_off_is_never_reported_as_using_the_upstream() {
    let discovery = Discovery::new(FakeOs::new(ProxyConfig::default()), Config::default());
    let clock = Arc::new(ManualClock::new(START_MS));
    let health = Arc::new(HostNetworkHealth::new(discovery, clock as Arc<dyn Clock>));
    health.set_pull_proxy(false, true);
    let api = start_with_network(health).await;
    let body = api.get("/api/network-health").await.json();
    assert_eq!(
        body["pull_proxy"],
        json!({"active": false, "via_upstream": false})
    );
    assert_eq!(body["roots"]["synced_at"], Value::Null);
    assert_eq!(body["proxy"]["pac_state"], "not_used");
}

#[tokio::test]
async fn a_network_change_is_an_event_and_the_next_report_shows_it() {
    let os = FakeOs::new(ProxyConfig::default());
    let discovery = Discovery::new(os, Config::default());
    let clock = Arc::new(ManualClock::new(START_MS));
    let health = Arc::new(HostNetworkHealth::new(
        discovery.clone(),
        clock as Arc<dyn Clock>,
    ));
    let api = start_with_network(health).await;
    let _forwarder = forward_network_changes(&discovery, api.events.clone());
    let mut stream = Stream::open(&api, "").await;

    discovery.bump_epoch();
    stream.read_until(|b| b.contains("network_changed")).await;
    assert!(
        stream
            .data()
            .contains(&json!({"type": "network_changed", "epoch": 1}))
    );
    let body = api.get("/api/network-health").await.json();
    assert_eq!(body["proxy"]["epoch"], 1);
    assert!(body["proxy"]["last_change_at"].as_u64().unwrap() > 0);
}
