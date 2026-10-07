// SPDX-License-Identifier: GPL-3.0-or-later
//! Local servers and a raw HTTP client for the pull-proxy tests.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use puddle_netpolicy::PuddleEndpoints;
use puddle_proxy::testing::{CollectingConnectionLog, StaticResolver};
use puddle_proxy::{PullProxy, PullRoute};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub(crate) const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// An echo server that counts its connections.
pub(crate) struct Echo {
    pub(crate) addr: SocketAddr,
    pub(crate) accepted: Arc<AtomicUsize>,
}

pub(crate) async fn echo() -> Echo {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Echo { addr, accepted }
}

/// A plain-HTTP server that records the request heads it gets and answers `200 hello`.
pub(crate) async fn http_server() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut reader = BufReader::new(s);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                seen.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(head);
                let _ = reader
                    .get_mut()
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
                    )
                    .await;
                let _ = reader.get_mut().shutdown().await;
            });
        }
    });
    (addr, heads)
}

/// A pull proxy serving on loopback, with `registry.test` pointing at `target` (if given).
pub(crate) fn pull_proxy(
    endpoints: &PuddleEndpoints,
    target: Option<IpAddr>,
) -> (PullRoute, String) {
    let mut resolver =
        StaticResolver::new().with("meta.test", &["169.254.169.254".parse().unwrap()]);
    if let Some(ip) = target {
        resolver = resolver.with("registry.test", &[ip]);
    }
    let proxy = PullProxy::bind(endpoints)
        .unwrap()
        .with_resolver(Arc::new(resolver));
    let creds = BASE64.encode(format!("puddle:{}", proxy.token().expose()));
    (proxy.serve().unwrap(), creds)
}

/// Like [`pull_proxy`], with a connection log that keeps what the proxy records.
pub(crate) fn pull_proxy_logged(
    endpoints: &PuddleEndpoints,
    target: Option<IpAddr>,
) -> (PullRoute, String, Arc<CollectingConnectionLog>) {
    let mut resolver =
        StaticResolver::new().with("meta.test", &["169.254.169.254".parse().unwrap()]);
    if let Some(ip) = target {
        resolver = resolver.with("registry.test", &[ip]);
    }
    let log = Arc::new(CollectingConnectionLog::new());
    let proxy = PullProxy::bind(endpoints)
        .unwrap()
        .with_resolver(Arc::new(resolver))
        .with_connection_log(log.clone());
    let creds = BASE64.encode(format!("puddle:{}", proxy.token().expose()));
    (proxy.serve().unwrap(), creds, log)
}

/// Sends `request` to the proxy and reads the response head (and, on a refusal, the body).
pub(crate) async fn send(proxy: SocketAddr, request: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    (String::from_utf8(head).unwrap(), s)
}

pub(crate) fn connect(target: &str, auth: Option<&str>) -> String {
    let auth = auth.map_or(String::new(), |a| format!("Proxy-Authorization: {a}\r\n"));
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n")
}
