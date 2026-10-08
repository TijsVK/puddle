// SPDX-License-Identifier: GPL-3.0-or-later
//! A guest-side TLS client that trusts only the workspace's CA completes a handshake with a server
//! that presents the CA's leaf, the way the proxy will terminate bound hosts.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns: a failed setup fails the test"
)]

use std::io::{Read, Write};
use std::sync::Arc;

use puddle_ca::{CaBuilder, NameConstraints, WorkspaceCa};
use rustls::pki_types::ServerName;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

#[derive(Debug)]
struct Resolver(Arc<WorkspaceCa>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.leaf(hello.server_name()?).ok()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn workspace_ca() -> Arc<WorkspaceCa> {
    let constraints = NameConstraints::new().permit_dns("github.com").unwrap();
    Arc::new(
        CaBuilder::new("puddle proxy CA (workspace t)", constraints)
            .build()
            .unwrap(),
    )
}

/// Runs a handshake for `host` and sends one message through; returns what the server read.
fn handshake(
    server_ca: Arc<WorkspaceCa>,
    trusted: &WorkspaceCa,
    host: &str,
) -> Result<Vec<u8>, rustls::Error> {
    let server_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(server_ca)));
    let mut roots = RootCertStore::empty();
    roots.add(trusted.certificate().der().clone())?;
    let client_config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let name = ServerName::try_from(host.to_owned()).unwrap();
    let mut client = ClientConnection::new(Arc::new(client_config), name)?;
    let mut server = ServerConnection::new(Arc::new(server_config))?;
    client
        .writer()
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .unwrap();

    for _ in 0..10 {
        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut buf.as_slice()).unwrap();
        server.process_new_packets()?;
        let mut buf = Vec::new();
        server.write_tls(&mut buf).unwrap();
        client.read_tls(&mut buf.as_slice()).unwrap();
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            let mut buf = Vec::new();
            client.write_tls(&mut buf).unwrap();
            server.read_tls(&mut buf.as_slice()).unwrap();
            server.process_new_packets()?;
            let mut got = vec![0; 64];
            let n = server.reader().read(&mut got).unwrap();
            got.truncate(n);
            return Ok(got);
        }
    }
    panic!("handshake did not finish");
}

#[test]
fn guest_client_trusting_the_workspace_ca_accepts_the_proxy_leaf() {
    let ca = workspace_ca();
    let got = handshake(Arc::clone(&ca), &ca, "api.github.com").unwrap();
    assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
}

#[test]
fn a_client_trusting_another_workspace_ca_refuses_the_leaf() {
    let ca = workspace_ca();
    let other = workspace_ca();
    let err = handshake(ca, &other, "github.com").unwrap_err();
    assert!(
        matches!(err, rustls::Error::InvalidCertificate(_)),
        "{err:?}"
    );
}

#[test]
fn a_host_outside_the_constraints_gets_no_certificate() {
    let ca = workspace_ca();
    let err = handshake(Arc::clone(&ca), &ca, "example.com").unwrap_err();
    assert!(
        !matches!(err, rustls::Error::InvalidCertificate(_)),
        "{err:?}"
    );
}
