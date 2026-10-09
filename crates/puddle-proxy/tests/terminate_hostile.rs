// SPDX-License-Identifier: GPL-3.0-or-later
//! Hostile-guest and hostile-upstream cases for terminated connections (tier P): a guest that
//! lies about the host, smuggles requests, or sends malformed framing; an upstream with a bad
//! certificate, an oversized or slow response, or a response that is more than it should be.
//! In every case no credential may leave puddle for the wrong place, and no other connection may
//! notice.
mod terminate_support;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use puddle_proxy::ProxyConfig;
use rustls::pki_types::ServerName;
use std::fmt::Write as _;
use terminate_support::{
    CANARY, FakeServer, Flaw, Guest, Handler, Pki, Reply, RigBuilder, TestInjector, captured_logs,
    inject, refuse,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn ok_handler() -> Handler {
    Arc::new(|_| Reply::ok("hello"))
}

async fn upstream(pki: &Pki, handler: Handler) -> FakeServer {
    FakeServer::tls(pki.server_config("bound.test", Flaw::None), handler).await
}

fn quick() -> ProxyConfig {
    ProxyConfig::default()
        .with_head_timeout(Duration::from_millis(600))
        .with_terminate_timeouts(
            Duration::from_millis(600),
            Duration::from_millis(600),
            Duration::from_millis(600),
            Duration::from_millis(600),
        )
}

// HG-15: the wrong host ------------------------------------------------------------------------

#[tokio::test]
async fn hostile_hg15_a_request_for_another_host_is_421_and_the_injector_never_hears_of_it() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    for request in [
        "GET /x HTTP/1.1\r\nHost: evil.example\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: 140.82.112.3\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: bound.test:8443\r\n\r\n",
        "GET https://evil.example/x HTTP/1.1\r\nHost: bound.test\r\n\r\n",
        "GET https://bound.test.evil.example/x HTTP/1.1\r\nHost: bound.test\r\n\r\n",
    ] {
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        client.send(request.as_bytes()).await;
        let r = client.response("GET").await;
        assert_eq!(r.status, 421, "{request}");
        assert!(client.closed().await, "{request}");
    }
    assert_eq!(injector.calls(), 0);
    assert!(server.recorded().is_empty());
    assert!(!captured_logs().contains(CANARY));
}

#[tokio::test]
async fn hostile_hg15_ssh_to_a_bound_host_on_port_22_is_refused_and_the_injector_never_hears_of_it()
{
    // A bound host on port 22 (or 443, announced) is SSH, not a request to decrypt: nothing is
    // asked of the injector, nothing reaches the server, and the canary stays put.
    let pki = Pki::new();
    let server = FakeServer::plain(Arc::new(|_| Reply::ok("never"))).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    for authority in ["bound.test:22", "bound.test:443"] {
        let mut stream = guest.control.open_stream().await.unwrap();
        stream
            .write_all(
                format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nx-puddle-protocol: ssh\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        let answer = String::from_utf8_lossy(&answer).into_owned();
        assert!(answer.starts_with("HTTP/1.1 403"), "{authority}: {answer}");
        assert!(
            answer.contains("x-puddle-blocked: ssh_unsupported"),
            "{authority}: {answer}"
        );
    }
    // Not announced: the tunnel to port 22 opens (an ordinary destination) and ends at the
    // client's identification line.
    let (code, mut tunnel) = guest.connect_to("bound.test:22").await;
    assert_eq!(code, 200);
    tunnel
        .write_all(b"SSH-2.0-OpenSSH_10.0p2\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    tunnel.read_to_end(&mut answer).await.unwrap();
    assert_eq!(answer, b"puddle: SSH is not supported yet\r\n");
    assert_eq!(injector.calls(), 0);
    assert!(server.recorded().is_empty());
    assert!(!captured_logs().contains(CANARY));
}

#[tokio::test]
async fn hostile_hg15_the_connect_name_is_what_counts_not_what_the_guest_says_next() {
    // CONNECT to a host that is not bound, then TLS for the bound name: spliced, so the workspace
    // CA never gets to vouch for it and the bound upstream never sees a connection.
    let pki = Pki::new();
    let bound = upstream(&pki, ok_handler()).await;
    let other = FakeServer::tls(pki.server_config("unbound.test", Flaw::None), ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", bound.addr)
        .name("unbound.test", other.addr)
        .allow(vec!["bound.test", "unbound.test"])
        .build();
    let mut guest = rig.guest().await;
    let (code, reader) = guest.connect_to("unbound.test:443").await;
    assert_eq!(code, 200);
    let config = Guest::client_config(&[rig.ca.certificate().der().clone()], &[]);
    let result = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("bound.test").unwrap(), reader)
        .await;
    assert!(result.is_err());
    assert_eq!(bound.accepted(), 0);
}

#[tokio::test]
async fn early_bytes_after_the_connect_are_not_lost() {
    // A client that sends its ClientHello in the same write as the CONNECT head.
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut stream = guest.control.open_stream().await.unwrap();
    let roots = [rig.ca.certificate().der().clone()];
    let config = Guest::client_config(&roots, &[b"http/1.1"]);
    let mut conn = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("bound.test").unwrap(),
    )
    .unwrap();
    let mut first = b"CONNECT bound.test:443 HTTP/1.1\r\nHost: bound.test:443\r\n\r\n".to_vec();
    conn.write_tls(&mut first).unwrap();
    stream.write_all(&first).await.unwrap();
    let mut incoming = Vec::new();
    let mut buf = vec![0_u8; 16 * 1024];
    let mut head_done = false;
    while conn.is_handshaking() {
        let n = stream.read(&mut buf).await.unwrap();
        assert_ne!(n, 0, "closed during the handshake");
        incoming.extend_from_slice(&buf[..n]);
        if !head_done {
            let Some(end) = incoming.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            assert!(incoming.starts_with(b"HTTP/1.1 200"));
            incoming.drain(..end + 4);
            head_done = true;
        }
        let mut cursor = std::io::Cursor::new(std::mem::take(&mut incoming));
        conn.read_tls(&mut cursor).unwrap();
        conn.process_new_packets().unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        if !out.is_empty() {
            stream.write_all(&out).await.unwrap();
        }
    }
    assert_eq!(conn.alpn_protocol(), Some(&b"http/1.1"[..]));
}

// HG-16: smuggling ------------------------------------------------------------------------------

#[tokio::test]
async fn hostile_hg16_ambiguous_framing_is_refused_before_anything_goes_upstream() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let cases = [
        // Content-Length with Transfer-Encoding.
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        // Transfer-Encoding that does not end in chunked.
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: gzip\r\n\r\n",
        // Conflicting or malformed lengths.
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd",
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nContent-Length: -1\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 0x10\r\n\r\n",
        // Obsolete line folding hides a header.
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nX-A: b\r\n Transfer-Encoding: chunked\r\n\r\n",
        // A space before the colon, and a header with no colon.
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding : chunked\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nnonsense\r\n\r\n",
        // Two Host headers.
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nHost: evil.example\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: evil.example\r\nHost: bound.test\r\n\r\n",
        // NUL and other control characters.
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nX-A: a\u{0}b\r\n\r\n",
        "GET /x\u{1}y HTTP/1.1\r\nHost: bound.test\r\n\r\n",
        // CONNECT inside the tunnel, and an unsupported version.
        "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
        "GET /x HTTP/2.0\r\nHost: bound.test\r\n\r\n",
        // Bad chunk framing.
        "POST /x HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n",
    ];
    for request in cases {
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        client.send(request.as_bytes()).await;
        let r = client.try_response("POST").await;
        let status = r.as_ref().map(|r| r.status);
        // Bad chunk framing is only found while the body is read, so the injector may be asked
        // first; the upstream still never gets a complete request.
        assert!(
            matches!(status, Some(400 | 431) | None),
            "{request:?} -> {status:?}"
        );
        assert!(client.closed().await, "{request:?}");
    }
    assert!(
        server
            .recorded()
            .iter()
            .all(|r| r.body.is_empty() || r.target != "/x"),
        "{:?}",
        server.recorded()
    );
    assert!(!captured_logs().contains(CANARY));
}

#[tokio::test]
async fn hostile_hg16_a_body_is_never_parsed_as_a_second_request() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::always();
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let smuggled = "GET /forbidden HTTP/1.1\r\nHost: bound.test\r\n\r\n";
    client
        .send(
            format!(
                "POST /ok HTTP/1.1\r\nHost: bound.test\r\nContent-Length: {}\r\n\r\n{smuggled}",
                smuggled.len()
            )
            .as_bytes(),
        )
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    // The same through a chunked body whose data looks like a request.
    client
        .send(format!("POST /ok HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{smuggled}\r\n0\r\n\r\n", smuggled.len()).as_bytes())
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    assert_eq!(injector.paths(), ["/ok", "/ok"]);
    let seen = server.recorded();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|r| r.target == "/ok" && r.body == smuggled.as_bytes())
    );
}

#[tokio::test]
async fn hostile_hg16_pipelined_requests_are_each_decided_on_their_own() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let injector = TestInjector::new(|view| {
        if view.path() == "/forbidden" {
            refuse(403, "push_denied")
        } else {
            inject(CANARY)
        }
    });
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .injector(injector.clone())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    // One write, three requests; the middle one is forbidden, and a chunked body ends right
    // before the last.
    client
        .send(b"GET /ok HTTP/1.1\r\nHost: bound.test\r\n\r\nGET /forbidden HTTP/1.1\r\nHost: bound.test\r\n\r\nPOST /after HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    let denied = client.response("GET").await;
    assert_eq!(denied.status, 403);
    assert_eq!(denied.header("x-puddle-blocked"), Some("push_denied"));
    // A refusal ends the connection, so the request after it is never read.
    assert!(client.try_response("POST").await.is_none());
    assert_eq!(injector.paths(), ["/ok", "/forbidden"]);
    let seen = server.recorded();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/ok");
    // After a chunked body the next request on the wire is its own request.
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /a HTTP/1.1\r\nHost: bound.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /forbidden HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    assert_eq!(client.response("POST").await.status, 200);
    assert_eq!(client.response("GET").await.status, 403);
    assert_eq!(server.recorded().len(), 2);
}

#[tokio::test]
async fn hostile_hg16_an_oversized_head_and_a_stalled_one_are_cut_off() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(quick())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let big = format!(
        "GET /x HTTP/1.1\r\nHost: bound.test\r\nX-Big: {}\r\n\r\n",
        "a".repeat(70 * 1024)
    );
    client.send(big.as_bytes()).await;
    assert_eq!(client.response("GET").await.status, 431);
    // A head that never ends: 408, then closed.
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /x HTTP/1.1\r\nHost: bound.test\r\nX-Slow: a")
        .await;
    assert_eq!(client.response("GET").await.status, 408);
    // An idle keep-alive connection is closed quietly.
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/x").await.status, 200);
    assert!(client.closed().await);
    assert_eq!(server.recorded().len(), 1);
}

#[tokio::test]
async fn hostile_hg16_a_guest_that_stops_sending_a_body_does_not_hold_the_upstream() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(quick())
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(
            b"POST /x HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 100\r\n\r\nonly a few bytes",
        )
        .await;
    let r = client.try_response("POST").await;
    assert!(
        r.is_none_or(|r| r.status == 400),
        "the request is failed, not completed"
    );
    assert!(client.closed().await);
    // A complete request never reached the real server.
    assert!(server.recorded().iter().all(|r| r.body.len() != 100));
}

// HG-17-style: nothing of the guest's credentials competes ----------------------------------------

#[tokio::test]
async fn the_guests_own_credentials_never_travel_with_an_injected_one() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /x HTTP/1.1\r\nHost: bound.test\r\nauthorization: Bearer one\r\nAuthorization: Bearer two\r\nProxy-Authorization: Basic three\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 200);
    let seen = &server.recorded()[0];
    assert_eq!(
        seen.headers_named("authorization"),
        [format!("Basic {CANARY}")]
    );
    assert_eq!(seen.headers_named("proxy-authorization").len(), 0);
}

// HG-19: a bad upstream certificate ----------------------------------------------------------------

#[tokio::test]
async fn hostile_hg19_an_upstream_certificate_that_is_not_accepted_is_a_502_and_nothing_is_sent() {
    let pki = Pki::new();
    let cases = [
        (Flaw::Expired, "expired"),
        (Flaw::NotYetValid, "notvalidyet"),
        (Flaw::UnknownRoot, "unknownissuer"),
        (Flaw::WrongName, "notvalidforname"),
        (Flaw::SelfSigned, "unknownissuer"),
    ];
    for (flaw, reason) in cases {
        let server = FakeServer::tls(
            pki.server_config("bound.test", flaw),
            Arc::new(|_| Reply::ok("never")),
        )
        .await;
        let injector = TestInjector::always();
        let rig = RigBuilder::new(&pki)
            .name("bound.test", server.addr)
            .injector(injector.clone())
            .build();
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        client
            .send(b"GET /x HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer guest-secret\r\n\r\n")
            .await;
        let r = client.response("GET").await;
        assert_eq!(r.status, 502, "{reason}");
        let text = r.text();
        assert!(
            text.contains("certificate of bound.test was not accepted"),
            "{text}"
        );
        assert!(text.contains("nothing was sent"), "{text}");
        // rustls spells a reason as its variant name or as a sentence; the platform verifier on
        // Windows gives its own wording, so the reason is only checked where WebPKI verifies.
        #[cfg(not(windows))]
        assert!(
            text.to_ascii_lowercase()
                .replace([' ', '_'], "")
                .contains(reason),
            "{reason}: {text}"
        );
        assert_eq!(r.header("x-puddle-blocked-by"), Some("upstream-tls"));
        assert_eq!(
            server.handshakes.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert!(server.recorded().is_empty(), "{reason}");
        assert_eq!(
            injector.calls(),
            0,
            "the injector is asked only after verification"
        );
        assert!(!text.contains(CANARY) && !text.contains("guest-secret"));
        assert!(client.closed().await);
    }
    assert!(!captured_logs().contains(CANARY));
}

#[tokio::test]
async fn hostile_hg19_a_root_the_host_does_not_trust_is_not_trusted_because_the_guest_does() {
    // The workspace CA vouches for bound.test to the guest; it must not count for the upstream.
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::UnknownRoot),
        Arc::new(|_| Reply::ok("never")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/x").await.status, 502);
    assert!(server.recorded().is_empty());
}

// HG-28: the guest's clock ---------------------------------------------------------------------------

#[tokio::test]
async fn hostile_hg28_the_upstream_check_uses_the_hosts_clock_alone() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    // A verifier whose clock is the host's: accepted.
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    assert_eq!(
        guest
            .tls("bound.test:443", None)
            .await
            .unwrap()
            .get("bound.test", "/")
            .await
            .status,
        200
    );
    // The same server with the verification clock moved to 2040 or 2010: the certificate
    // (valid 2020 to 2090) is fine at 2040 and not yet valid at 2010. Whatever the guest's
    // clock says changes nothing, because nothing from the guest reaches this check.
    for (year_secs, ok) in [(2_200_000_000_u64, true), (1_262_304_000, false)] {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(year_secs);
        let tls = puddle_upstream::TlsClient::with_clock([pki.root.clone()], at).unwrap();
        let rig = RigBuilder::new(&pki)
            .name("bound.test", server.addr)
            .tls(tls)
            .build();
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        let status = client.get("bound.test", "/").await.status;
        assert_eq!(status == 200, ok, "clock at {year_secs}");
    }
}

// HG-29: a hostile bound upstream -------------------------------------------------------------------------

#[tokio::test]
async fn hostile_hg29_a_huge_response_head_is_a_502_and_other_connections_are_fine() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| match r.target.as_str() {
            "/medium" => Reply::raw(format!(
                "HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 4\r\n\r\nfine",
                "a".repeat(20 * 1024)
            )),
            "/huge" => Reply::raw(format!(
                "HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 0\r\n\r\n",
                "a".repeat(70 * 1024)
            )),
            "/many" => {
                let mut head = String::from("HTTP/1.1 200 OK\r\n");
                for i in 0..400 {
                    let _ = write!(head, "X-{i}: v\r\n");
                }
                head.push_str("Content-Length: 0\r\n\r\n");
                Reply::raw(head)
            }
            _ => Reply::ok("fine"),
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut healthy = guest.tls("bound.test:443", None).await.unwrap();
    let mut medium = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(medium.get("bound.test", "/medium").await.text(), "fine");
    for path in ["/huge", "/many"] {
        let mut hostile = guest.tls("bound.test:443", None).await.unwrap();
        assert_eq!(hostile.get("bound.test", path).await.status, 502, "{path}");
        assert_eq!(healthy.get("bound.test", "/ok").await.text(), "fine");
    }
}

#[tokio::test]
async fn hostile_hg29_a_slow_upstream_hits_its_limits_without_slowing_anyone_else() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| match r.target.as_str() {
            "/silent" => Reply::ok("late").after(Duration::from_secs(30)),
            "/drip" => Reply::ok("dripping").trickling(Duration::from_millis(300)),
            "/stall" => Reply::raw("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nabc")
                .after(Duration::ZERO),
            _ => Reply::ok("fine"),
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .config(quick())
        .build();
    let mut guest = rig.guest().await;
    let mut silent = guest.tls("bound.test:443", None).await.unwrap();
    let mut stalled = guest.tls("bound.test:443", None).await.unwrap();
    silent
        .send(b"GET /silent HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    stalled
        .send(b"GET /stall HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    // While they wait, an ordinary connection is served at once.
    let started = std::time::Instant::now();
    let mut healthy = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(healthy.get("bound.test", "/ok").await.text(), "fine");
    assert!(started.elapsed() < Duration::from_millis(500));
    // The silent upstream: 504 once the head limit passes.
    assert_eq!(silent.response("GET").await.status, 504);
    // The stalled one: the body is cut off, not completed, and the connection is dropped.
    let r = stalled.try_response("GET").await;
    assert!(
        r.is_none(),
        "a truncated Content-Length response is not delivered as complete"
    );
    // A dripping head hits the head limit too.
    let mut drip = guest.tls("bound.test:443", None).await.unwrap();
    drip.send(b"GET /drip HTTP/1.1\r\nHost: bound.test\r\n\r\n")
        .await;
    assert_eq!(drip.response("GET").await.status, 504);
}

#[tokio::test]
async fn hostile_hg29_extra_bytes_from_the_upstream_are_never_taken_for_the_next_response() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| match r.target.as_str() {
            "/split" => Reply::raw(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirstHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged",
            ),
            _ => Reply::ok("genuine"),
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/split").await.text(), "first");
    assert_eq!(client.get("bound.test", "/next").await.text(), "genuine");
}

#[tokio::test]
async fn hostile_hg29_responses_with_broken_framing_are_a_502() {
    let pki = Pki::new();
    let server = upstream(
        &pki,
        Arc::new(|r| match r.target.as_str() {
            "/fold" => {
                Reply::raw("HTTP/1.1 200 OK\r\nX-A: b\r\n c: d\r\nContent-Length: 0\r\n\r\n")
                    .closing()
            }
            "/garbage" => Reply::raw("not http at all\r\n\r\n").closing(),
            _ => Reply::ok("fine"),
        }),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    for path in ["/fold", "/garbage"] {
        let mut guest = rig.guest().await;
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        let status = client.get("bound.test", path).await.status;
        assert_eq!(status, 502, "{path}");
    }
}

// No secret in any log ----------------------------------------------------------------------------------

#[tokio::test]
async fn no_secret_reaches_a_log_or_the_guest() {
    let pki = Pki::new();
    let server = upstream(&pki, ok_handler()).await;
    let bad = FakeServer::tls(
        pki.server_config("bound.test", Flaw::WrongName),
        ok_handler(),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /x?token=query-secret HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer header-secret\r\n\r\n")
        .await;
    let r = client.response("GET").await;
    assert_eq!(r.status, 200);
    let guest_saw = format!("{r:?}");
    assert!(!guest_saw.contains(CANARY));
    client.close().await;
    // And on failures.
    let failing = RigBuilder::new(&pki).name("bound.test", bad.addr).build();
    let mut guest = failing.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"GET /x HTTP/1.1\r\nHost: bound.test\r\nAuthorization: Bearer header-secret\r\n\r\n")
        .await;
    assert_eq!(client.response("GET").await.status, 502);
    // The audit records hold no secret either.
    let audit = format!("{:?}", failing.events(1).await);
    assert!(!audit.contains(CANARY) && !audit.contains("header-secret"));
    let logs = captured_logs();
    assert!(!logs.is_empty(), "the capture works");
    for secret in [CANARY, "header-secret", "query-secret", "guest-secret"] {
        assert!(!logs.contains(secret), "{secret} reached a log");
    }
}
