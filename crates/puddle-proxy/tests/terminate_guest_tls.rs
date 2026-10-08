// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of what the audit records when the client in the workspace does not accept the
//! certificate puddle presents for a bound host (the usual cause: a tool with its own list of
//! roots that does not include the workspace's CA).
mod terminate_support;

use std::sync::Arc;

use puddle_types::ConnectionDecision;
use rustls::pki_types::ServerName;
use terminate_support::{FakeServer, Flaw, Guest, Pki, Reply, RigBuilder};

async fn upstream(pki: &Pki) -> FakeServer {
    FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("hello")),
    )
    .await
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_workspace_ca_is_recorded_as_having_refused_the_certificate()
 {
    let pki = Pki::new();
    let server = upstream(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let guest = rig.guest().await;
    // A client over a real socket, whose roots hold some other CA only: it sends the alert and
    // then closes, as a tool in a workspace does.
    let (port, _bridge) = guest.bridge("bound.test:443").await;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let config = Guest::client_config(std::slice::from_ref(&pki.root), &[]);
    let refused = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("bound.test").unwrap(), tcp)
        .await;
    assert!(refused.is_err(), "the client cannot verify the certificate");

    let events = rig.events(1).await;
    assert_eq!(events[0].reason.to_string(), "guest_tls_rejected");
    // Puddle blocked nothing: the rule that allowed the host still stands.
    assert_eq!(events[0].decision, ConnectionDecision::Allow);
    assert!(!events[0].injected);
    assert_eq!(server.accepted(), 0, "nothing reached the real server");
}

#[tokio::test]
async fn a_client_that_goes_away_before_the_handshake_is_not_a_refused_certificate() {
    let pki = Pki::new();
    let server = upstream(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let (code, reader) = guest.connect_to("bound.test:443").await;
    assert_eq!(code, 200);
    drop(reader);

    let events = rig.events(1).await;
    assert_eq!(events[0].reason.to_string(), "rule");
    assert_eq!(events[0].decision, ConnectionDecision::Allow);
}

#[tokio::test]
async fn a_client_that_trusts_the_workspace_ca_is_served_as_before() {
    let pki = Pki::new();
    let server = upstream(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let mut guest = rig.guest().await;
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    assert_eq!(client.get("bound.test", "/").await.status, 200);
    client.close().await;
    let events = rig.events(1).await;
    assert_eq!(events[0].reason.to_string(), "rule");
}
