// SPDX-License-Identifier: GPL-3.0-or-later
//! The guard over real HTTP: token, `Host` and `Origin` refusals (T-029 AP-1, AP-2), loopback
//! binding, no CORS, JSON-only state changes.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use puddle_api::ApiConfig;
use serde_json::{Value, json};

use crate::common::{Api, Reply, raw, start, start_with};

fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> String {
    let mut text = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        let _ = write!(text, "{k}: {v}\r\n");
    }
    text.push_str("Connection: close\r\n\r\n");
    text
}

async fn send(api: &Api, method: &str, path: &str, headers: &[(&str, &str)]) -> Reply {
    raw(api.addr, request(method, path, headers).as_bytes()).await
}

fn bearer(api: &Api) -> String {
    format!("Bearer {}", api.token)
}

fn assert_refused(reply: &Reply, status: u16, code: &str, token: &str) {
    assert_eq!(reply.status, status, "{reply:?}");
    assert_eq!(reply.error(), code, "{reply:?}");
    assert!(
        !reply.body.contains(token),
        "the token leaked into a refusal"
    );
    assert!(
        reply.header("access-control-allow-origin").is_none(),
        "no CORS headers, ever"
    );
}

/// Every operation in the spec, with its path parameters filled in.
fn operations() -> Vec<(String, String)> {
    let spec: Value = serde_json::from_str(&puddle_api::openapi_json()).unwrap();
    let mut out = Vec::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        let path = path
            .replace("{id}", "1")
            .replace("{sandbox}", "box")
            .replace("{kind}", "telemetry");
        for method in item.as_object().unwrap().keys() {
            out.push((method.to_uppercase(), path.clone()));
        }
    }
    out.push(("GET".into(), "/api/openapi.json".into()));
    out.push(("GET".into(), "/api/no-such-route".into()));
    out
}

#[tokio::test]
async fn listener_is_bound_to_ipv4_loopback_only() {
    let api = start().await;
    assert_eq!(api.addr.ip(), IpAddr::from([127, 0, 0, 1]));
    // If this machine has a non-loopback address, the port must not answer on it.
    let probe = UdpSocket::bind("0.0.0.0:0").and_then(|s| {
        s.connect("192.0.2.1:9")?;
        s.local_addr()
    });
    if let Ok(local) = probe
        && !local.ip().is_loopback()
        && !local.ip().is_unspecified()
    {
        let other = SocketAddr::new(local.ip(), api.addr.port());
        let result =
            tokio::time::timeout(crate::common::STEP, tokio::net::TcpStream::connect(other)).await;
        assert!(!matches!(result, Ok(Ok(_))), "the API answered on {other}");
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn every_route_refuses_a_missing_token() {
    let api = start().await;
    let host = api.host();
    for (method, path) in operations() {
        let reply = send(&api, &method, &path, &[("Host", &host)]).await;
        assert_refused(&reply, 401, "unauthorized", &api.token);
        assert_eq!(
            reply.header("www-authenticate"),
            Some("Bearer realm=\"puddle\""),
            "{method} {path}"
        );
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn wrong_or_misplaced_tokens_are_refused() {
    let api = start().await;
    let host = api.host();
    let wrong = format!("Bearer {}", "0".repeat(64));
    let basic = format!("Basic {}", api.token);
    let query = format!("/api/health?token={}", api.token);
    for (path, auth) in [
        ("/api/health", Some(wrong.as_str())),
        ("/api/health", Some(basic.as_str())),
        ("/api/health", Some(api.token.as_str())),
        ("/api/health", Some("Bearer ")),
        (query.as_str(), None),
    ] {
        let mut headers = vec![("Host", host.as_str())];
        if let Some(auth) = auth {
            headers.push(("Authorization", auth));
        }
        let reply = send(&api, "GET", path, &headers).await;
        assert_refused(&reply, 401, "unauthorized", &api.token);
    }
    // A token in a cookie doesn't count either.
    let cookie = format!("token={}", api.token);
    let reply = send(
        &api,
        "GET",
        "/api/health",
        &[("Host", &host), ("Cookie", &cookie)],
    )
    .await;
    assert_refused(&reply, 401, "unauthorized", &api.token);
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_right_token_with_our_host_passes() {
    let api = start().await;
    let auth = bearer(&api);
    for host in [api.host(), format!("localhost:{}", api.addr.port())] {
        let reply = send(
            &api,
            "GET",
            "/api/health",
            &[("Host", &host), ("Authorization", &auth)],
        )
        .await;
        assert_eq!(reply.status, 200, "{reply:?}");
        assert_eq!(reply.json()["api_version"], puddle_api::API_VERSION);
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn foreign_hosts_are_refused_even_with_the_token() {
    let api = start().await;
    let auth = bearer(&api);
    let port = api.addr.port();
    // DNS rebinding sends the attacker's name; the rest are near misses.
    for host in [
        format!("evil.example:{port}"),
        format!("127.0.0.1.nip.io:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        format!("[::1]:{port}"),
        "127.0.0.1".to_owned(),
        "localhost".to_owned(),
    ] {
        let reply = send(
            &api,
            "GET",
            "/api/health",
            &[("Host", &host), ("Authorization", &auth)],
        )
        .await;
        assert_refused(&reply, 421, "misdirected_host", &api.token);
    }
    // Two Host headers.
    let own = api.host();
    let reply = send(
        &api,
        "GET",
        "/api/health",
        &[
            ("Host", &own),
            ("Host", "evil.example"),
            ("Authorization", &auth),
        ],
    )
    .await;
    assert!(matches!(reply.status, 400 | 421), "{reply:?}");
    // HTTP/1.0 without a Host header.
    let reply = raw(
        api.addr,
        format!("GET /api/health HTTP/1.0\r\nAuthorization: {auth}\r\n\r\n").as_bytes(),
    )
    .await;
    assert_refused(&reply, 421, "misdirected_host", &api.token);
    // An absolute-form target naming another host.
    let reply = raw(
        api.addr,
        format!(
            "GET http://evil.example/api/health HTTP/1.1\r\nHost: {own}\r\nAuthorization: {auth}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_refused(&reply, 421, "misdirected_host", &api.token);
    api.running.shutdown().await;
}

#[tokio::test]
async fn foreign_origins_are_refused_even_with_the_token() {
    let api = start().await;
    let auth = bearer(&api);
    let host = api.host();
    let port = api.addr.port();
    for origin in [
        "http://evil.example".to_owned(),
        "null".to_owned(),
        format!("http://127.0.0.1:{}", port.wrapping_add(1)),
        format!("https://127.0.0.1:{port}"),
        "tauri://localhost".to_owned(),
    ] {
        for (method, path) in [("GET", "/api/rules"), ("DELETE", "/api/rules/1")] {
            let reply = send(
                &api,
                method,
                path,
                &[
                    ("Host", &host),
                    ("Origin", &origin),
                    ("Authorization", &auth),
                ],
            )
            .await;
            assert_refused(&reply, 403, "forbidden_origin", &api.token);
        }
    }
    let own = format!("http://{host}");
    let reply = send(
        &api,
        "GET",
        "/api/rules",
        &[("Host", &host), ("Origin", &own), ("Authorization", &auth)],
    )
    .await;
    assert_eq!(reply.status, 200, "{reply:?}");
    api.running.shutdown().await;
}

#[tokio::test]
async fn configured_extra_origins_pass_and_still_need_the_token() {
    let mut config = ApiConfig::default();
    config.extra_origins = vec!["tauri://localhost".into()];
    let api = start_with(config).await;
    let host = api.host();
    let auth = bearer(&api);
    let ok = send(
        &api,
        "GET",
        "/api/rules",
        &[
            ("Host", &host),
            ("Origin", "tauri://localhost"),
            ("Authorization", &auth),
        ],
    )
    .await;
    assert_eq!(ok.status, 200, "{ok:?}");
    let no_token = send(
        &api,
        "GET",
        "/api/rules",
        &[("Host", &host), ("Origin", "tauri://localhost")],
    )
    .await;
    assert_refused(&no_token, 401, "unauthorized", &api.token);
    api.running.shutdown().await;
}

#[tokio::test]
async fn cors_preflights_get_no_allowance() {
    let api = start().await;
    let host = api.host();
    for origin in ["http://evil.example".to_owned(), format!("http://{host}")] {
        let reply = send(
            &api,
            "OPTIONS",
            "/api/pending/1/approve",
            &[
                ("Host", &host),
                ("Origin", &origin),
                ("Access-Control-Request-Method", "POST"),
                (
                    "Access-Control-Request-Headers",
                    "authorization, content-type",
                ),
            ],
        )
        .await;
        assert!(reply.status >= 400, "{reply:?}");
        assert!(
            !reply
                .headers
                .iter()
                .any(|(k, _)| k.to_ascii_lowercase().starts_with("access-control-")),
            "{reply:?}"
        );
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn state_changes_take_only_json_bodies() {
    let api = start().await;
    let id = api.request("box", "example.com");
    let host = api.host();
    let auth = bearer(&api);
    for content_type in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
    ] {
        let body = "{}";
        let text = format!(
            "POST /api/pending/{id}/approve HTTP/1.1\r\nHost: {host}\r\nAuthorization: {auth}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let reply = raw(api.addr, text.as_bytes()).await;
        assert_eq!(reply.status, 415, "{content_type}: {reply:?}");
        assert_eq!(reply.error(), "unsupported_media_type");
    }
    // Nothing was decided.
    let row = api.get(&format!("/api/pending/{id}")).await.json();
    assert_eq!(row["state"], "requested");
    api.running.shutdown().await;
}

#[tokio::test]
async fn bodies_over_the_limit_are_refused() {
    let api = start().await;
    let big =
        json!({ "pattern": "a".repeat(70 * 1024), "effect": "allow", "scope": {"type": "global"} });
    let reply = api.send("POST", "/api/rules", Some(&big)).await;
    assert_eq!(reply.status, 413, "{}", reply.status);
    assert_eq!(reply.error(), "payload_too_large");
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_spec_is_served_behind_the_guard() {
    let api = start().await;
    let reply = api.get("/api/openapi.json").await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(reply.body, puddle_api::openapi_json());
    let missing = api.get("/api/nothing-here").await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.error(), "not_found");
    api.running.shutdown().await;
}

#[tokio::test]
async fn connection_info_names_the_bound_address_and_the_token() {
    use std::sync::Arc;

    use puddle_api::{ApiServer, ApiToken, ConnectionInfo, EventHub, MemorySettings, Services};
    use puddle_store::{Limits, ManualClock, Store};

    let clock = Arc::new(ManualClock::new(1));
    let services = Services::new(
        Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap()),
        Arc::new(MemorySettings::default()),
        Arc::new(EventHub::default()),
        clock,
    );
    let token = ApiToken::generate().unwrap();
    let server = ApiServer::bind(ApiConfig::default(), token.clone(), services)
        .await
        .unwrap();
    let info = server.connection_info();
    assert_eq!(
        info.url,
        format!("http://127.0.0.1:{}", server.local_addr().port())
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle").join("api.json");
    info.write(&path).unwrap();
    let back = ConnectionInfo::read(&path).unwrap();
    assert_eq!(back.url, info.url);
    assert!(token.matches(back.token.expose().as_bytes()));

    // A second server can't take the same port.
    let second = ApiServer::bind(
        ApiConfig::with_port(server.local_addr().port()),
        token,
        Services::new(
            Arc::new(
                Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap(),
            ),
            Arc::new(MemorySettings::default()),
            Arc::new(EventHub::default()),
            Arc::new(ManualClock::new(1)),
        ),
    )
    .await;
    let err = second.err().expect("port already bound");
    assert!(
        err.to_string().contains("cannot listen on 127.0.0.1"),
        "{err}"
    );

    let running = server.spawn();
    assert_eq!(running.local_addr().ip(), IpAddr::from([127, 0, 0, 1]));
    running.shutdown().await;
}
