// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of TLS termination for bound hosts: what is decrypted, what the real server sees,
//! what the guest sees, and what stays spliced.
mod terminate_support;

use std::sync::Arc;
use std::time::Duration;

use puddle_proxy::{InjectDecision, ProxyConfig, Upstream};
use puddle_types::ConnectionDecision;
use terminate_support::{
    CANARY, FakeServer, Flaw, Handler, Pki, Reply, RigBuilder, TestInjector, host, inject, refuse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn ok_handler() -> Handler {
    Arc::new(|_| Reply::ok("hello from upstream"))
}

async fn upstream(pki: &Pki, handler: Handler) -> FakeServer {
    FakeServer::tls(pki.server_config("bound.test", Flaw::None), handler).await
}

#[tokio::test]
async fn a_bound_host_is_terminated_and_gets_the_credential() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /org/repo/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer guest-token\r\nProxy-Authorization: Basic zzz\r\nConnection: keep-alive\r\nUser-Agent: git/2.47\r\n\r\n")
        .await;
    let response = client.response("GET").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "hello from upstream");

    let seen = server.recorded();
    assert_eq!(seen.len(), 1);
    let request = &seen[0];
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.target,
        "/org/repo/info/refs?service=git-upload-pack"
    );
    assert_eq!(request.header("host"), Some("bound.test"));
    assert_eq!(
        request.headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    assert_eq!(request.header("proxy-authorization"), None);
    assert_eq!(request.header("user-agent"), Some("git/2.47"));

    client.close().await;
    let events = rig.events(1).await;
    let event = &events[0];
    assert!(event.injected);
    assert_eq!(event.binding_id.as_deref(), Some("binding-1"));
    assert_eq!(event.http.as_ref().unwrap().path(), "/org/repo/info/refs");
    assert_eq!(event.resolved_ip.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn an_unbound_host_is_spliced_and_its_real_issuer_reaches_the_guest() {
    let pki = Pki::new();
    let bound = upstream(&pki, ok_handler()).await;
    let other = FakeServer::tls(
        pki.server_config("unbound.test", Flaw::None),
        Arc::new(|_| Reply::ok("the real thing")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", bound.addr)
        .name("unbound.test", other.addr)
        .allow(vec!["bound.test", "unbound.test"])
        .build();
    let mut guest = rig.guest().await;
    // Trusts only the fake internet's root: it works only if the real chain reaches the guest.
    let mut client = guest
        .tls_trusting("unbound.test:443", std::slice::from_ref(&pki.root))
        .await
        .expect("the real certificate reaches the guest");
    assert_eq!(
        client.get("unbound.test", "/x").await.text(),
        "the real thing"
    );
    // And the workspace CA is not what vouched for it.
    let mut other_guest = rig.guest().await;
    let refused = other_guest
        .tls_trusting("unbound.test:443", &[rig.ca.certificate().der().clone()])
        .await;
    assert!(
        refused.is_err(),
        "the workspace CA must not vouch for an unbound host"
    );
    assert_eq!(bound.accepted(), 0);
}

#[tokio::test]
async fn a_bound_name_on_another_port_or_plain_is_spliced() {
    let pki = Pki::new();
    let plain = FakeServer::plain(Arc::new(|_| Reply::ok("plain http"))).await;
    let rig = RigBuilder::new(&pki).name("bound.test", plain.addr).build();
    for authority in ["bound.test:80", "bound.test:8443"] {
        let mut guest = rig.guest().await;
        let (code, mut tunnel) = guest.connect_to(authority).await;
        assert_eq!(code, 200, "{authority}");
        // Bytes pass through untouched: the plain server answers the plain request directly.
        tunnel
            .write_all(b"GET /p HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer mine\r\n\r\n")
            .await
            .unwrap();
        let mut got = vec![0_u8; 12];
        tunnel.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HTTP/1.1 200", "{authority}");
    }
    let seen = plain.recorded();
    assert_eq!(seen.len(), 2);
    for request in seen {
        assert_eq!(
            request.header("authorization"),
            Some("Bearer mine"),
            "spliced: untouched"
        );
    }
}

#[tokio::test]
async fn only_http11_is_offered_to_the_guest() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let client = guest
        .tls_with("bound.test:443", None, &[b"h2", b"http/1.1"], true)
        .await
        .unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"http/1.1"[..]));
    let mut guest = rig.guest().await;
    let none = guest
        .tls_with("bound.test:443", None, &[], true)
        .await
        .unwrap();
    assert_eq!(none.alpn, None);
    let mut guest = rig.guest().await;
    assert!(
        guest
            .tls_with("bound.test:443", None, &[b"h2"], true)
            .await
            .is_err(),
        "a client that speaks only h2 is turned away, not served h2"
    );
}

#[tokio::test]
async fn a_wrong_or_missing_sni_gets_an_alert_and_never_reaches_the_upstream() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    for (sni, send_sni) in [(Some("other.test"), true), (Some("bound.test"), false)] {
        let mut guest = rig.guest().await;
        let result = guest
            .tls_with("bound.test:443", sni, &[b"http/1.1"], send_sni)
            .await;
        assert!(result.is_err(), "sni {sni:?} sent {send_sni}");
    }
    let events = rig.events(2).await;
    for event in events {
        assert_eq!(event.reason.to_string(), "sni_mismatch");
        assert_eq!(event.decision, ConnectionDecision::Blocked);
        assert!(!event.injected);
    }
    assert_eq!(server.accepted(), 0, "no connection to the real server");
    assert_eq!(injector.calls(), 0);
}

#[tokio::test]
async fn keep_alive_requests_share_one_upstream_connection_and_connections_never_share() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut a = guest.tls("bound.test:443", None).await.unwrap();
    for path in ["/1", "/2", "/3"] {
        assert_eq!(a.get("bound.test", path).await.status, 200);
    }
    assert_eq!(
        server.accepted(),
        1,
        "one upstream connection per guest connection"
    );
    let mut b = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(b.get("bound.test", "/4").await.status, 200);
    assert_eq!(server.accepted(), 2);
    let conns: Vec<usize> = server.recorded().iter().map(|r| r.conn).collect();
    assert_eq!(conns, [0, 0, 0, 1]);
}

#[tokio::test]
async fn two_workspaces_have_their_own_ca_and_their_own_upstream_connections() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut mine = rig.guest().await;
    let mut theirs = rig.other_guest().await;
    assert_eq!(
        mine.tls("bound.test:443", None)
            .await
            .unwrap()
            .get("bound.test", "/a")
            .await
            .status,
        200
    );
    assert_eq!(
        theirs
            .tls("bound.test:443", None)
            .await
            .unwrap()
            .get("bound.test", "/b")
            .await
            .status,
        200
    );
    assert_eq!(server.accepted(), 2);
    // The other workspace's CA does not vouch for this workspace's leaf.
    let (code, reader) = mine.connect_to("bound.test:443").await;
    assert_eq!(code, 200);
    let config =
        terminate_support::Guest::client_config(&[rig.other_ca.certificate().der().clone()], &[]);
    let refused = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("bound.test").unwrap(),
            reader,
        )
        .await;
    assert!(refused.is_err());
    // Only the first workspace's request was injected.
    let seen = server.recorded();
    let injected = seen
        .iter()
        .filter(|r| r.header("authorization").is_some())
        .count();
    assert_eq!(injected, 1);
}

#[tokio::test]
async fn bodies_are_carried_both_ways_whatever_their_framing() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| {
            let digest: u64 = r
                .body
                .iter()
                .fold(0, |acc, b| acc.wrapping_mul(31).wrapping_add(u64::from(*b)));
            Reply::ok(&format!("{} {digest}", r.body.len()))
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let body: Vec<u8> = (0..3_000_000_u32)
        .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 13) & 0xff).unwrap())
        .collect();
    let digest: u64 = body
        .iter()
        .fold(0, |acc, b| acc.wrapping_mul(31).wrapping_add(u64::from(*b)));
    // Content-Length.
    client
        .send(
            format!(
                "POST /up HTTP/1.1\r\nHost: bound.test\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await;
    client.send(&body).await;
    assert_eq!(
        client.response("POST").await.text(),
        format!("{} {digest}", body.len())
    );
    // Chunked, with an extension and a trailer that must not survive.
    client
        .send(b"POST /up HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await;
    for piece in body.chunks(100_000) {
        client
            .send(format!("{:x};ext=1\r\n", piece.len()).as_bytes())
            .await;
        client.send(piece).await;
        client.send(b"\r\n").await;
    }
    client.send(b"0\r\nx-trailer: smuggled\r\n\r\n").await;
    assert_eq!(
        client.response("POST").await.text(),
        format!("{} {digest}", body.len())
    );
    let seen = server.recorded();
    assert_eq!(seen[1].header("transfer-encoding"), Some("chunked"));
    assert_eq!(seen[1].header("x-trailer"), None);
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn expect_continue_is_answered_by_the_proxy_once_the_request_is_accepted() {
    let pki = Pki::new();
    let server = upstream(&pki, Arc::new(|r| Reply::ok(&r.body.len().to_string()))).await;
    let refusing = TestInjector::new(|view| {
        if view.path() == "/deny" {
            refuse(403, "push_denied")
        } else {
            inject(CANARY)
        }
    });
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(refusing)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /ok HTTP/1.1\r\nHost: bound.test\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
        .await;
    let interim = client.try_response("GET").await.unwrap();
    assert_eq!(interim.status, 100);
    client.send(b"hello").await;
    assert_eq!(client.response("POST").await.text(), "5");
    assert_eq!(server.recorded()[0].header("expect"), None);
    // A refused request gets its final answer without ever being asked for its body.
    client
        .send(b"POST /deny HTTP/1.1\r\nHost: bound.test\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n")
        .await;
    let answer = client.response("POST").await;
    assert_eq!(answer.status, 403);
    assert_eq!(answer.header("x-puddle-blocked"), Some("push_denied"));
    assert_eq!(server.recorded().len(), 1);
}

#[tokio::test]
async fn response_framings_are_rebuilt_for_the_guest() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| match r.target.as_str() {
            "/chunked" => Reply::raw("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Kept: yes\r\n\r\n5\r\nhello\r\n6;e=1\r\n world\r\n0\r\nTrailer-X: dropped\r\n\r\n"),
            "/204" => Reply::raw("HTTP/1.1 204 No Content\r\n\r\n"),
            "/304" => Reply::raw("HTTP/1.1 304 Not Modified\r\nContent-Length: 77\r\n\r\n"),
            "/head" => Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"),
            "/until-close" => Reply::raw("HTTP/1.1 200 OK\r\n\r\nthe whole rest").closing(),
            "/hop" => Reply::raw("HTTP/1.1 200 OK\r\nConnection: x-hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nContent-Length: 2\r\n\r\nhi"),
            _ => Reply::ok("default"),
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let r = client.get("bound.test", "/chunked").await;
    assert_eq!((r.status, r.text().as_str()), (200, "hello world"));
    assert_eq!(r.header("x-kept"), Some("yes"));
    assert_eq!(r.header("trailer-x"), None);
    assert_eq!(client.get("bound.test", "/204").await.status, 204);
    let r = client.get("bound.test", "/304").await;
    assert_eq!((r.status, r.header("content-length")), (304, Some("77")));
    client
        .send(b"HEAD /head HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    let r = client.response("HEAD").await;
    assert_eq!(
        (r.status, r.header("content-length"), r.body.len()),
        (200, Some("1234"), 0)
    );
    let r = client.get("bound.test", "/hop").await;
    assert_eq!(r.text(), "hi");
    assert!(
        r.header("x-hop").is_none()
            && r.header("keep-alive").is_none()
            && r.header("connection").is_none()
    );
    // After all that the connection still serves.
    assert_eq!(client.get("bound.test", "/x").await.text(), "default");
    // A body that runs to the end of the upstream connection is chunked for the guest, and the
    // guest's connection outlives the upstream's: the next request gets a new upstream connection.
    let r = client.get("bound.test", "/until-close").await;
    assert_eq!(r.text(), "the whole rest");
    assert_eq!(r.header("transfer-encoding"), Some("chunked"));
    assert_eq!(client.get("bound.test", "/x").await.text(), "default");
    assert_eq!(server.accepted(), 2);
}

#[tokio::test]
async fn a_redirect_is_passed_on_and_never_followed() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|_| {
            Reply::status(
                302,
                "location: https://evil.example/steal\r\nset-cookie: a=1\r\n",
                "",
            )
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let r = client.get("bound.test", "/r").await;
    assert_eq!(r.status, 302);
    assert_eq!(r.header("location"), Some("https://evil.example/steal"));
    assert_eq!(server.recorded().len(), 1);
    assert_eq!(server.accepted(), 1);
}

#[tokio::test]
async fn a_refusal_from_the_injector_is_sent_and_nothing_goes_upstream() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::new(|view| match view.path() {
        "/denied" => refuse(403, "push_denied"),
        "/signin" => refuse(401, "credential_unavailable"),
        "/pass" => InjectDecision::PassThrough,
        _ => inject(CANARY),
    });
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let r = client.get("bound.test", "/denied").await;
    assert_eq!(r.status, 403);
    assert_eq!(r.header("x-puddle-blocked"), Some("push_denied"));
    assert!(r.text().starts_with("puddle: "));
    assert!(server.recorded().is_empty());
    // A 401 would make git prompt; it becomes a 502.
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/signin").await.status, 502);
    // PassThrough sends the guest's own header untouched.
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /pass HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer mine\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    let seen = server.recorded();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("authorization"), Some("Bearer mine"));
    assert_eq!(injector.paths(), ["/denied", "/signin", "/pass"]);
}

#[tokio::test]
async fn the_request_the_injector_sees_is_the_one_that_was_checked() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    // Absolute-form for the same host becomes origin-form upstream.
    client
        .send(b"GET https://bound.test/a/b?q=1 HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    assert_eq!(server.recorded()[0].target, "/a/b?q=1");
    assert_eq!(injector.paths(), ["/a/b?q=1"]);
}

#[tokio::test]
async fn the_host_policy_still_applies_and_a_denied_bound_host_is_not_terminated() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .allow(vec![])
        .build();
    let mut guest = rig.guest().await;
    let mut stream = guest.control.open_stream().await.unwrap();
    stream
        .write_all(b"CONNECT bound.test:443 HTTP/1.1\r\nHost: bound.test:443\r\n\r\n")
        .await
        .unwrap();
    let mut got = String::new();
    stream.read_to_string(&mut got).await.unwrap();
    assert!(got.starts_with("HTTP/1.1 403"), "{got}");
    assert_eq!(server.accepted(), 0);
    let _ = (
        host("bound.test"),
        ProxyConfig::default(),
        Duration::ZERO,
        None::<Upstream>,
    );
}
