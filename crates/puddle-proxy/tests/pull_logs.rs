// SPDX-License-Identifier: GPL-3.0-or-later
//! The image-pull proxy never logs its token (STANDARDS §7). Alone in its test binary, so
//! the global subscriber sees every thread.
mod pull_support;

use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use puddle_netpolicy::PuddleEndpoints;
use puddle_proxy::PullProxy;
use puddle_proxy::testing::StaticResolver;
use pull_support::{LOCAL, connect, echo, http_server, send};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Collects every log line the test writes.
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

/// Runs every path (refused, wrong token, tunnel, forward, blocked, bad request) at `trace`
/// level and checks that neither the token nor its Basic credentials appear in any log line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_never_appears_in_logs() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let endpoints = PuddleEndpoints::new();
    let proxy = PullProxy::bind(&endpoints).unwrap().with_resolver(Arc::new(
        StaticResolver::new().with("registry.test", &[LOCAL]),
    ));
    let token = proxy.token().expose().to_owned();
    let url = proxy.proxy_url();
    tracing::info!(proxy = %url, debug = ?proxy, "pull proxy bound");
    let good = BASE64.encode(format!("puddle:{token}"));
    let route = proxy.serve().unwrap();
    let server = echo().await;
    let (http, _) = http_server().await;
    let own = route.local_addr();
    let auth = format!("Basic {good}");
    let tunnel_to = format!("registry.test:{}", server.addr.port());
    let http_to = format!("registry.test:{}", http.port());
    let wrong = format!("Basic {}", BASE64.encode(format!("puddle:{token}x")));
    for request in [
        connect(&tunnel_to, None),
        connect(&tunnel_to, Some(&wrong)),
        connect(&tunnel_to, Some(&format!("Basic {token}"))),
        connect(&tunnel_to, Some(&auth)),
        connect(&format!("127.0.0.1:{}", own.port()), Some(&auth)),
        connect("169.254.169.254:80", Some(&auth)),
        connect("bad host:1", Some(&auth)),
        format!(
            "GET http://{http_to}/x?token={token} HTTP/1.1\r\nHost: {http_to}\r\nProxy-Authorization: {auth}\r\n\r\n"
        ),
    ] {
        let (_, mut s) = send(own, &request).await;
        let _ = s.shutdown().await;
        let mut rest = Vec::new();
        let _ = s.read_to_end(&mut rest).await;
    }
    route.shutdown().await;

    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("request without puddle's credentials refused")
            && logs.contains("image-pull connection")
            && logs.contains("image pull blocked")
            && logs.contains("pull proxy bound"),
        "the capture must see the proxy's lines:\n{logs}"
    );
    for secret in [token.as_str(), good.as_str()] {
        assert!(
            !logs.contains(secret),
            "a log line carries the token:\n{logs}"
        );
    }
}
