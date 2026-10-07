// SPDX-License-Identifier: GPL-3.0-or-later
//! I test of the image-pull path (P1/P2 without a VM): the msb adapter's real
//! `pull_image` (the SDK's registry client) → the client's own proxy setting
//! ([`MsbConfig::with_registry_proxy`]) → puddle's [`PullProxy`] with its per-run token → a TLS registry whose certificate chains to a lab root
//! nobody trusts, standing in for a TLS-intercepting company proxy.
//!
//! - **P1**: without the lab root the pull fails on the certificate, after the proxy tunnelled
//!   it, and the registry never sees an HTTP request.
//! - **P2**: with the lab root in [`MsbConfig::with_registry_roots`] the image is pulled through
//!   the proxy and its config comes back; a second pull is served from the cache.
//! - The registry's name resolves only inside the pull proxy, so a pull that skipped the proxy
//!   could not reach it at all.
//! - No log line (every crate, `trace` level) and no error carries the token.
//! - **The token is not in any environment.** After the pulls, neither this process nor a
//!   child it spawns has a variable that holds it. The process environment carries a decoy
//!   `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` instead, which the pulls ignore: nothing connects to
//!   it, so puddle needs no scrubbing of the user's own proxy variables.
//!
//! One test in its own binary: it sets the decoy environment before any thread starts and
//! installs a global log subscriber. The child is this same binary run again with a marker
//! variable, which makes the test print its environment and stop.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use puddle_compute::{ComputeError, Runtime};
use puddle_compute_msb::{MsbConfig, MsbRuntime};
use puddle_netpolicy::PuddleEndpoints;
use puddle_proxy::{BoxFuture, PullProxy, Resolver};
use puddle_store::{AuditCursor, AuditFilter, AuditRecord, Clock, Limits, Store, SystemClock};
use puddle_types::{ConnectionDecision, ConnectionOrigin, DomainName, ImageRef};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The registry's name; only the pull proxy's resolver knows it.
const REGISTRY: &str = "registry.lab.test";
const REPO: &str = "puddle/hello";

/// Resolves [`REGISTRY`] to the local lab registry, whatever port was asked for.
struct LabResolver(SocketAddr);

impl Resolver for LabResolver {
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        _port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        let found = (name.as_str() == REGISTRY).then_some(vec![self.0]);
        Box::pin(async move {
            found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown lab name"))
        })
    }
}

/// The lab root (PEM) and the registry's server config, its leaf signed by that root.
fn lab_pki() -> (String, Arc<rustls::ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "puddle lab interceptor root");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![REGISTRY.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(ca.der().to_vec()),
        ],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    (ca.pem(), Arc::new(config))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().fold(String::from("sha256:"), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A one-file image: (manifest, blobs by digest). The layer is an uncompressed tar.
fn image() -> (Vec<u8>, BTreeMap<String, Vec<u8>>) {
    let mut layer = tar::Builder::new(Vec::new());
    let content = b"hello from the lab registry\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    layer
        .append_data(&mut header, "hello", &content[..])
        .unwrap();
    let layer = layer.into_inner().unwrap();
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "amd64",
    };
    let config = serde_json::to_vec(&serde_json::json!({
        "architecture": arch,
        "os": "linux",
        "config": { "Env": ["PATH=/usr/bin:/bin", "PUDDLE_LAB=1"], "Cmd": ["/hello"] },
        "rootfs": { "type": "layers", "diff_ids": [sha256(&layer)] },
    }))
    .unwrap();
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": sha256(&config),
            "size": config.len(),
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": sha256(&layer),
            "size": layer.len(),
        }],
    }))
    .unwrap();
    let blobs = BTreeMap::from([(sha256(&config), config), (sha256(&layer), layer)]);
    (manifest, blobs)
}

/// What the lab registry saw.
#[derive(Default)]
struct Seen {
    handshakes_failed: AtomicUsize,
    requests: Mutex<Vec<String>>,
}

impl Seen {
    fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Serves the OCI distribution API for [`image`] over TLS, one request per connection.
async fn registry(listener: TcpListener, tls: Arc<rustls::ServerConfig>, seen: Arc<Seen>) {
    let acceptor = TlsAcceptor::from(tls);
    let (manifest, blobs) = image();
    let manifest_digest = sha256(&manifest);
    let (manifest, blobs) = (Arc::new(manifest), Arc::new(blobs));
    while let Ok((tcp, _)) = listener.accept().await {
        let (acceptor, seen) = (acceptor.clone(), Arc::clone(&seen));
        let (manifest, blobs, manifest_digest) = (
            Arc::clone(&manifest),
            Arc::clone(&blobs),
            manifest_digest.clone(),
        );
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                seen.handshakes_failed.fetch_add(1, Ordering::SeqCst);
                return;
            };
            let mut reader = BufReader::new(tls);
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                return;
            }
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).await.unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
            }
            let mut parts = line.split_whitespace();
            let (method, path) = (
                parts.next().unwrap_or_default().to_owned(),
                parts.next().unwrap_or_default().to_owned(),
            );
            seen.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(format!("{method} {path}"));
            let manifests = format!("/v2/{REPO}/manifests/");
            let blob_prefix = format!("/v2/{REPO}/blobs/");
            let (status, kind, body): (&str, &str, Vec<u8>) = if path == "/v2/" {
                ("200 OK", "application/json", b"{}".to_vec())
            } else if let Some(r) = path.strip_prefix(&manifests)
                && (r == "1" || r == manifest_digest)
            {
                (
                    "200 OK",
                    "application/vnd.oci.image.manifest.v1+json",
                    manifest.to_vec(),
                )
            } else if let Some(blob) = path.strip_prefix(&blob_prefix).and_then(|d| blobs.get(d)) {
                ("200 OK", "application/octet-stream", blob.clone())
            } else {
                ("404 Not Found", "application/json", b"{}".to_vec())
            };
            let head = format!(
                "HTTP/1.1 {status}\r\ncontent-type: {kind}\r\ncontent-length: {}\r\ndocker-content-digest: {}\r\nconnection: close\r\n\r\n",
                body.len(),
                if kind.contains("manifest") {
                    manifest_digest.as_str()
                } else {
                    ""
                },
            );
            let tls = reader.get_mut();
            let _ = tls.write_all(head.as_bytes()).await;
            if method != "HEAD" {
                let _ = tls.write_all(&body).await;
            }
            let _ = tls.shutdown().await;
        });
    }
}

/// Every log line of the process.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn config(home: &std::path::Path, proxy_url: &str) -> MsbConfig {
    // Pulling needs no msb binary: the paths only go into msb's config.json.
    MsbConfig::new(
        home.join("msb-home"),
        home.join("runtime/msb"),
        home.join("runtime/libkrunfw"),
        home.join("guest-share"),
    )
    .with_registry_proxy(proxy_url)
}

/// Set on the re-run of this binary that only prints its environment.
const DUMP_ENV: &str = "PUDDLE_T144_DUMP_ENV";
const ENV_BEGIN: &str = "<<<ENV-BEGIN>>>";
const ENV_END: &str = "<<<ENV-END>>>";
const TEST_NAME: &str = "image_pulls_go_through_the_pull_proxy_and_trust_only_the_given_roots";

/// Runs this test binary as a child process, as puddle starts msb's runner processes, and returns
/// the environment it sees (`NAME=value` lines).
fn child_environment() -> String {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(DUMP_ENV, "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (_, rest) = text.split_once(ENV_BEGIN).unwrap();
    let (env, _) = rest.split_once(ENV_END).unwrap();
    env.to_owned()
}

/// The token is in no environment: not this process's, not a child's. The decoy proxy never saw
/// a connection.
fn assert_token_in_no_environment(token: &str, decoy: &std::net::TcpListener) {
    for (name, value) in std::env::vars_os() {
        assert!(
            !value.to_string_lossy().contains(token),
            "{} holds the token",
            name.display()
        );
    }
    let child = child_environment();
    assert!(
        child.contains("HTTPS_PROXY=http://decoy:decoy@"),
        "the child should see the decoy environment:\n{child}"
    );
    assert!(!child.contains(token), "a child process sees the token");
    assert!(
        matches!(decoy.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
        "the pulls used the environment's proxy"
    );
}

/// What the child prints: this process's environment between the markers.
fn print_environment() {
    let mut dump = String::from(ENV_BEGIN);
    for (name, value) in std::env::vars_os() {
        let _ = writeln!(
            dump,
            "\n{}={}",
            name.to_string_lossy(),
            value.to_string_lossy()
        );
    }
    let _ = writeln!(io::stdout(), "{dump}\n{ENV_END}");
}

/// Puts a decoy proxy into the environment and returns its listener. The pulls take the client's
/// own setting, so nothing may connect to it.
#[expect(
    unsafe_code,
    reason = "the test puts a decoy proxy into the process environment before any thread starts"
)]
fn decoy_environment() -> std::net::TcpListener {
    let decoy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    decoy.set_nonblocking(true).unwrap();
    let decoy_url = format!("http://decoy:decoy@{}", decoy.local_addr().unwrap());
    // SAFETY: called first in this binary's only test; the harness's other thread only waits for
    // it, and no runtime or other thread has started yet.
    unsafe {
        for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
            std::env::set_var(name, &decoy_url);
        }
        std::env::remove_var("NO_PROXY");
    }
    decoy
}

/// The pulls are in the audit as puddle's own connections: no sandbox, the address connected to,
/// and the bytes that went through.
async fn assert_pulls_are_audited(store: &Store, token: &str) {
    // connected to, and the bytes that went through.
    let puddle_only = AuditFilter {
        origin: Some(ConnectionOrigin::Puddle),
        ..AuditFilter::default()
    };
    let mut records = Vec::new();
    for _ in 0..100 {
        records = connection_records(store, &puddle_only);
        if records.iter().any(|r| r.bytes_down > 0) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(!records.is_empty(), "the pull proxy wrote no audit record");
    for record in &records {
        assert_eq!(record.sandbox_id, None);
        assert_eq!(record.origin, ConnectionOrigin::Puddle);
        assert_eq!(record.host.as_deref(), Some(REGISTRY));
        assert_eq!(record.port, Some(443));
        assert_eq!(record.decision, Some(ConnectionDecision::Allow));
        assert_eq!(record.reason, "puddle_request");
        assert_eq!(record.resolved_ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(record.upstream, None, "no company proxy is configured");
        assert!(!format!("{record:?}").contains(token));
    }
    assert!(
        records.iter().any(|r| r.bytes_up > 0 && r.bytes_down > 0),
        "{records:?}"
    );
    let sandbox_only = AuditFilter {
        origin: Some(ConnectionOrigin::Sandbox),
        ..AuditFilter::default()
    };
    assert_eq!(connection_records(store, &sandbox_only).len(), 0);
}

/// The `connection` records `filter` matches, oldest first.
fn connection_records(store: &Store, filter: &AuditFilter) -> Vec<puddle_store::ConnectionRecord> {
    store
        .audit_query(filter, AuditCursor::After(0), 500)
        .unwrap()
        .iter()
        .filter_map(|(_, line)| match serde_json::from_str(line).unwrap() {
            AuditRecord::Connection(record) => Some(record),
            _ => None,
        })
        .collect()
}

#[test]
fn image_pulls_go_through_the_pull_proxy_and_trust_only_the_given_roots() {
    if std::env::var_os(DUMP_ENV).is_some() {
        print_environment();
        return;
    }
    let captured = Captured::default();
    let writer = captured.clone();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish(),
    )
    .unwrap();

    let decoy = decoy_environment();
    let registry_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let registry_addr = registry_listener.local_addr().unwrap();
    let endpoints = PuddleEndpoints::new();
    let store = Arc::new(
        Store::open_in_memory(Arc::new(SystemClock) as Arc<dyn Clock>, Limits::default()).unwrap(),
    );
    let proxy = PullProxy::bind(&endpoints)
        .unwrap()
        .with_resolver(Arc::new(LabResolver(registry_addr)))
        .with_connection_log(store.clone());
    let token = proxy.token().expose().to_owned();
    let proxy_url = proxy.proxy_url().expose().to_owned();

    let (root, tls) = lab_pki();
    let home = tempfile::tempdir().unwrap();
    let seen = Arc::new(Seen::default());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        registry_listener.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(registry_listener).unwrap();
        tokio::spawn(registry(listener, tls, Arc::clone(&seen)));
        let route = proxy.serve().unwrap();
        let image = ImageRef::new(&format!("{REGISTRY}/{REPO}:1")).unwrap();

        // P1: no lab root, so the registry client refuses the "interceptor".
        let untrusting = MsbRuntime::open(config(&home.path().join("p1"), &proxy_url))
            .await
            .unwrap();
        let err = untrusting.pull_image(&image).await.unwrap_err();
        let ComputeError::ImagePull { reason, .. } = &err else {
            panic!("expected an image-pull error, got {err:?}");
        };
        let reason = reason.to_ascii_lowercase();
        assert!(
            reason.contains("certificate") || reason.contains("unknownissuer"),
            "P1 must fail on the certificate: {reason}"
        );
        assert!(!format!("{err:?}").contains(&token));
        assert!(seen.handshakes_failed.load(Ordering::SeqCst) >= 1);
        assert!(seen.requests().is_empty(), "{:?}", seen.requests());

        // P2: with the lab root, the image comes through the proxy.
        let trusting = MsbRuntime::open(
            config(&home.path().join("p2"), &proxy_url).with_registry_roots([root]),
        )
        .await
        .unwrap();
        let pulled = trusting.pull_image(&image).await.unwrap();
        assert_eq!(pulled.env_var("PUDDLE_LAB"), Some("1"));
        assert_eq!(pulled.cmd, ["/hello"]);
        let requests = seen.requests();
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with(&format!("GET /v2/{REPO}/manifests/")))
                && requests
                    .iter()
                    .filter(|r| r.contains("/blobs/sha256:"))
                    .count()
                    >= 2,
            "{requests:?}"
        );
        // The cache answers a second pull.
        let again = trusting.pull_image(&image).await.unwrap();
        assert_eq!(again, pulled);
        assert_eq!(
            seen.requests().len(),
            requests.len(),
            "served from the cache"
        );
        assert_pulls_are_audited(&store, &token).await;
        route.shutdown().await;
    });

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("image-pull connection") && logs.contains(REGISTRY),
        "the pulls went through the pull proxy:\n{logs}"
    );
    assert!(!logs.contains(&token), "a log line carries the token");

    assert_token_in_no_environment(&token, &decoy);
}
