// SPDX-License-Identifier: GPL-3.0-or-later
//! `Alt-Svc` on decrypted responses: the HTTP/3 entries are removed on both HTTP versions and
//! every other entry and header reaches the guest as the server sent it; a spliced connection is
//! not touched.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod terminate_support;

use std::sync::Arc;

use terminate_support::h2_rig::{H2Server, Script, reply};
use terminate_support::{FakeServer, Flaw, Pki, Reply, RigBuilder};

/// What a server that offers HTTP/3 next to HTTP/2 sends: one field with an entry of each, one
/// with `h3` only (it must disappear whole), one with a draft id and a quoted comma, and one
/// that is `clear` (not an HTTP/3 entry).
const FIELDS: [&str; 4] = [
    r#"h3=":443"; ma=86400, h2="alt.test:8443"; ma=60; persist=1"#,
    r#"h3=":443"; ma=86400"#,
    r#"h3-29=":443"; v="1,2", h2=":9443""#,
    "clear",
];

/// What the guest must be left with.
const KEPT: [&str; 3] = [
    r#"h2="alt.test:8443"; ma=60; persist=1"#,
    r#"h2=":9443""#,
    "clear",
];

fn values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

fn offering_h3() -> Script {
    Arc::new(|_| {
        let mut response = reply(200, "hello");
        for field in FIELDS {
            response
                .headers_mut()
                .append("alt-svc", field.parse().unwrap());
        }
        response
            .headers_mut()
            .insert("x-served-by", "origin".parse().unwrap());
        response
    })
}

fn raw_fields() -> String {
    use std::fmt::Write as _;

    let mut head = String::from("x-served-by: origin\r\n");
    for field in FIELDS {
        let _ = write!(head, "alt-svc: {field}\r\n");
    }
    head
}

#[tokio::test]
async fn an_http11_guest_gets_no_h3_entry_and_every_other_entry_unchanged() {
    let pki = Pki::new();
    let head = raw_fields();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(move |_| Reply::status(200, &head, "hello")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.alpn.as_deref(), Some(&b"http/1.1"[..]));
    let response = client.get("bound.test", "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.text(), "hello");
    assert_eq!(values(&response.headers, "alt-svc"), KEPT);
    assert_eq!(values(&response.headers, "x-served-by"), ["origin"]);
}

#[tokio::test]
async fn an_http2_guest_gets_no_h3_entry_from_an_http2_server() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", offering_h3()).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    assert_eq!(client.alpn.as_deref(), Some(&b"h2"[..]));
    let got = client.get("bound.test", "/").await;
    assert_eq!(got.status, 200);
    assert_eq!(values(&got.headers, "alt-svc"), KEPT);
    assert_eq!(values(&got.headers, "x-served-by"), ["origin"]);
}

#[tokio::test]
async fn an_http2_guest_gets_no_h3_entry_from_an_http11_server() {
    let pki = Pki::new();
    let head = raw_fields();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(move |_| Reply::status(200, &head, "hello")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client.get("bound.test", "/").await;
    assert_eq!(got.status, 200);
    assert_eq!(values(&got.headers, "alt-svc"), KEPT);
    assert_eq!(values(&got.headers, "x-served-by"), ["origin"]);
}

#[tokio::test]
async fn a_response_without_alt_svc_gains_none() {
    let pki = Pki::new();
    let server = H2Server::recording(&pki, "bound.test", Arc::new(|_| reply(200, "plain"))).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let got = client.get("bound.test", "/").await;
    assert_eq!(got.status, 200);
    assert_eq!(values(&got.headers, "alt-svc"), Vec::<&str>::new());
}

#[tokio::test]
async fn a_spliced_host_keeps_its_alt_svc() {
    let pki = Pki::new();
    let head = raw_fields();
    let bound = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("bound")),
    )
    .await;
    let spliced = FakeServer::tls(
        pki.server_config("spliced.test", Flaw::None),
        Arc::new(move |_| Reply::status(200, &head, "hello")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", bound.addr)
        .name("spliced.test", spliced.addr)
        .allow(vec!["bound.test", "spliced.test"])
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest
        .tls_trusting("spliced.test:443", std::slice::from_ref(&pki.root))
        .await
        .unwrap();
    let response = client.get("spliced.test", "/").await;
    assert_eq!(response.status, 200);
    assert_eq!(values(&response.headers, "alt-svc"), FIELDS);
}
