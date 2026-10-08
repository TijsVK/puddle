// SPDX-License-Identifier: GPL-3.0-or-later
//! The leaf certificate against programs other than rustls: Python's strict X.509 verification
//! (authority key identifier, critical basic constraints on the CA, a subject alternative name,
//! `serverAuth`), which is what `pip` and `requests` run under.
//!
//! Needs `python3` on the path; without it the test skips unless `PUDDLE_TOOLS_REQUIRED` is set
//! (CI sets it).
#![expect(clippy::print_stderr, reason = "a skipped test says so")]
mod terminate_support;

use std::process::Command;
use std::sync::Arc;

use terminate_support::{FakeServer, Flaw, Pki, Reply, RigBuilder};

const SCRIPT: &str = r#"
import socket, ssl, sys
ca, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(cafile=ca)
ctx.verify_flags |= ssl.VERIFY_X509_STRICT
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
tls = ctx.wrap_socket(raw, server_hostname=host)
print("alpn", tls.selected_alpn_protocol(), "version", tls.version())
tls.sendall(("GET /py HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
data = b""
while True:
    chunk = tls.recv(4096)
    if not chunk:
        break
    data += chunk
print(data.split(b"\r\n")[0].decode())
"#;

fn python() -> Option<String> {
    let found = Command::new("python3").arg("--version").output().is_ok();
    if !found {
        assert!(
            std::env::var_os("PUDDLE_TOOLS_REQUIRED").is_none(),
            "PUDDLE_TOOLS_REQUIRED is set but python3 is not on the path"
        );
        eprintln!("skipped: python3 not found");
        return None;
    }
    Some("python3".to_owned())
}

#[tokio::test]
async fn python_strict_x509_accepts_the_leaf_and_the_ca() {
    let Some(python) = python() else { return };
    let pki = Pki::new();
    let server = FakeServer::tls(
        pki.server_config("bound.test", Flaw::None),
        Arc::new(|_| Reply::ok("hi")),
    )
    .await;
    let rig = RigBuilder::new(&pki)
        .name("bound.test", server.addr)
        .build();
    let guest = rig.guest().await;
    let (port, _bridge) = guest.bridge("bound.test:443").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, rig.ca.certificate().pem()).unwrap();
    let script_dir = tempfile::tempdir().unwrap();
    let script = script_dir.path().join("check.py");
    std::fs::write(&script, SCRIPT).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(python)
            .arg("-I")
            .arg(script)
            .arg(ca)
            .arg(port.to_string())
            .arg("bound.test")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("alpn http/1.1") || stdout.contains("alpn None"),
        "{stdout}"
    );
    assert!(stdout.contains("HTTP/1.1 200"), "{stdout}");
    assert_eq!(server.recorded().len(), 1);
}
