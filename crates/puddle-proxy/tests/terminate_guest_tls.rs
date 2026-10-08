// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of what the audit records when the client in the workspace does not accept the
//! certificate puddle presents for a bound host (the usual cause: a tool with its own list of
//! roots that does not include the workspace's CA).
//!
//! The real-tool test needs `python3` on the path; without it the test skips unless
//! `PUDDLE_TOOLS_REQUIRED` is set (CI sets it).
#![expect(clippy::print_stderr, reason = "a skipped test says so")]
mod terminate_support;

use std::process::Command;
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
    // The real server is connected to before the guest's handshake ends (its protocol decides
    // what the guest is offered), but no request, and no credential, reaches it.
    assert!(
        server.recorded().is_empty(),
        "no request reached the real server"
    );
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

const REFUSING_CLIENT: &str = r#"
import socket, ssl, sys
ca, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
try:
    ctx.wrap_socket(raw, server_hostname=host)
except ssl.SSLCertVerificationError as err:
    print("refused:", err.verify_message)
    sys.exit(0)
print("accepted")
sys.exit(1)
"#;

fn python_available() -> bool {
    if Command::new("python3").arg("--version").output().is_ok() {
        return true;
    }
    assert!(
        std::env::var_os("PUDDLE_TOOLS_REQUIRED").is_none(),
        "PUDDLE_TOOLS_REQUIRED is set but python3 is not on the path"
    );
    eprintln!("skipped: python3 not found");
    false
}

#[tokio::test]
async fn a_real_tool_that_refuses_the_certificate_is_recorded_too() {
    if !python_available() {
        return;
    }
    let pki = Pki::new();
    let server = upstream(&pki).await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let guest = rig.guest().await;
    let (port, _bridge) = guest.bridge("bound.test:443").await;
    let dir = tempfile::tempdir().unwrap();
    // The tool's own list of roots: some other CA, not the workspace's.
    let roots = dir.path().join("roots.pem");
    std::fs::write(&roots, rig.other_ca.certificate().pem()).unwrap();
    let script_dir = tempfile::tempdir().unwrap();
    let script = script_dir.path().join("refuse.py");
    std::fs::write(&script, REFUSING_CLIENT).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .arg("-I")
            .arg(script)
            .arg(roots)
            .arg(port.to_string())
            .arg("bound.test")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("refused:"), "{stdout}");

    let events = rig.events(1).await;
    assert_eq!(events[0].reason.to_string(), "guest_tls_rejected");
    assert_eq!(events[0].decision, ConnectionDecision::Allow);
}
