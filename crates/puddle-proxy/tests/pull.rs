// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of the image-pull proxy: a real loopback listener, raw HTTP clients and local
//! servers. The bars: only `127.0.0.1`; a missing or wrong token is a `407` and nothing is
//! connected; the right token tunnels and forwards; the guard blocks puddle's own endpoints and
//! metadata; the token never shows up in a log line
//! (`pull_logs.rs`, its own process for a global subscriber).
mod pull_support;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use puddle_netpolicy::{EndpointKind, LocalAccess, PuddleEndpoints};
use puddle_proxy::PullProxy;
use puddle_proxy::testing::StaticResolver;
use pull_support::{LOCAL, connect, echo, http_server, pull_proxy, send};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn the_listener_is_loopback_only_and_registered_while_it_serves() {
    let endpoints = PuddleEndpoints::new();
    let proxy = PullProxy::bind(&endpoints).unwrap();
    let addr = proxy.local_addr();
    assert_eq!(addr.ip(), LOCAL);
    assert_eq!(proxy.proxy_url().addr(), addr);
    assert_eq!(endpoints.list(), [(addr, EndpointKind::PullProxy)]);
    let url = proxy.proxy_url();
    assert_eq!(
        url.expose(),
        format!("http://puddle:{}@{addr}", proxy.token().expose())
    );
    let route = proxy.serve().unwrap();
    assert_eq!(route.local_addr(), addr);
    assert_eq!(endpoints.list().len(), 1);
    route.shutdown().await;
    assert!(endpoints.list().is_empty(), "unregistered on shutdown");
    // Each run has its own token.
    let a = PullProxy::bind(&endpoints).unwrap();
    let b = PullProxy::bind(&endpoints).unwrap();
    assert_ne!(a.token().expose(), b.token().expose());
}

#[tokio::test]
async fn a_missing_or_wrong_token_is_a_407_and_nothing_is_connected() {
    let endpoints = PuddleEndpoints::new();
    let server = echo().await;
    let (route, good) = pull_proxy(&endpoints, Some(LOCAL));
    let target = format!("registry.test:{}", server.addr.port());
    let wrong = BASE64.encode(format!("puddle:{}", "0".repeat(64)));
    let other_user = BASE64.encode("someone:else");
    for auth in [
        None,
        Some(format!("Basic {wrong}")),
        Some(format!("Basic {other_user}")),
        Some(format!("Bearer {good}")),
        Some("Basic".to_owned()),
    ] {
        let (head, mut s) = send(route.local_addr(), &connect(&target, auth.as_deref())).await;
        assert!(
            head.starts_with("HTTP/1.1 407 "),
            "{auth:?} must be refused: {head}"
        );
        assert!(
            head.contains("proxy-authenticate: Basic realm=\"puddle\""),
            "{head}"
        );
        let mut body = String::new();
        s.read_to_string(&mut body).await.unwrap();
        assert!(body.contains("only puddle may use it"), "{body}");
    }
    // A plain-HTTP request without credentials is refused the same way.
    let (head, _) = send(
        route.local_addr(),
        &format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    assert_eq!(
        server.accepted.load(Ordering::SeqCst),
        0,
        "nothing reached the server"
    );
}

#[tokio::test]
async fn the_right_token_tunnels_both_ways() {
    let endpoints = PuddleEndpoints::new();
    let server = echo().await;
    let (route, good) = pull_proxy(&endpoints, Some(LOCAL));
    let target = format!("registry.test:{}", server.addr.port());
    let (head, mut s) = send(
        route.local_addr(),
        &connect(&target, Some(&format!("Basic {good}"))),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let payload = vec![7u8; 256 * 1024];
    let (mut r, mut w) = s.split();
    let ((), echoed) = tokio::join!(
        async {
            w.write_all(&payload).await.unwrap();
            w.shutdown().await.unwrap();
        },
        async {
            let mut back = Vec::new();
            r.read_to_end(&mut back).await.unwrap();
            back
        }
    );
    assert_eq!(echoed, payload);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn plain_http_is_forwarded_without_the_proxy_credentials() {
    let endpoints = PuddleEndpoints::new();
    let (server, heads) = http_server().await;
    let (route, good) = pull_proxy(&endpoints, Some(LOCAL));
    let target = format!("registry.test:{}", server.port());
    let (head, mut s) = send(
        route.local_addr(),
        &format!(
            "GET http://{target}/v2/ HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {good}\r\nAccept: */*\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let mut body = String::new();
    s.read_to_string(&mut body).await.unwrap();
    assert_eq!(body, "hello");
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1);
    let upstream = &heads[0];
    assert!(upstream.starts_with("GET /v2/ HTTP/1.1\r\n"), "{upstream}");
    assert!(
        !upstream
            .to_ascii_lowercase()
            .contains("proxy-authorization"),
        "{upstream}"
    );
    assert!(!upstream.contains(&good), "{upstream}");
}

#[tokio::test]
async fn puddles_own_endpoints_and_metadata_are_blocked() {
    let endpoints = PuddleEndpoints::new();
    let api = echo().await;
    let _api = endpoints.register(api.addr, EndpointKind::Api);
    let (route, good) = pull_proxy(&endpoints, Some(LOCAL));
    let auth = format!("Basic {good}");
    let own = route.local_addr();
    for (target, code) in [
        (format!("127.0.0.1:{}", own.port()), "puddle_endpoint"),
        (format!("localhost:{}", own.port()), "puddle_endpoint"),
        (
            format!("registry.test:{}", api.addr.port()),
            "puddle_endpoint",
        ),
        (format!("127.0.0.1:{}", api.addr.port()), "puddle_endpoint"),
        ("169.254.169.254:80".to_owned(), "toggle:metadata"),
        ("meta.test:80".to_owned(), "toggle:metadata"),
        ("metadata.google.internal:80".to_owned(), "toggle:metadata"),
        ("169.254.10.10:80".to_owned(), "toggle:link_local"),
    ] {
        let (head, _) = send(own, &connect(&target, Some(&auth))).await;
        assert!(head.starts_with("HTTP/1.1 403 "), "{target}: {head}");
        assert!(
            head.contains(&format!("x-puddle-blocked: {code}")),
            "{target}: {head}"
        );
    }
    assert_eq!(api.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn loopback_can_be_turned_off() {
    let endpoints = PuddleEndpoints::new();
    let server = echo().await;
    let proxy = PullProxy::bind(&endpoints)
        .unwrap()
        .with_resolver(Arc::new(
            StaticResolver::new().with("registry.test", &[LOCAL]),
        ))
        .with_local_access(LocalAccess::NONE);
    let good = BASE64.encode(format!("puddle:{}", proxy.token().expose()));
    let route = proxy.serve().unwrap();
    let target = format!("registry.test:{}", server.addr.port());
    let (head, _) = send(
        route.local_addr(),
        &connect(&target, Some(&format!("Basic {good}"))),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    assert!(head.contains("x-puddle-blocked: toggle:loopback"), "{head}");
    let (head, _) = send(
        route.local_addr(),
        &connect("localhost:1", Some(&format!("Basic {good}"))),
    )
    .await;
    assert!(head.contains("x-puddle-blocked: toggle:loopback"), "{head}");
}

#[tokio::test]
async fn unresolvable_and_unreachable_registries_are_502() {
    let endpoints = PuddleEndpoints::new();
    let (route, good) = pull_proxy(&endpoints, None);
    let auth = format!("Basic {good}");
    let (head, _) = send(
        route.local_addr(),
        &connect("registry.test:443", Some(&auth)),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    // A loopback port nothing listens on.
    let closed = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let (head, _) = send(
        route.local_addr(),
        &connect(&format!("127.0.0.1:{port}"), Some(&auth)),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    let (head, _) = send(route.local_addr(), &connect("not a host", Some(&auth))).await;
    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
}
