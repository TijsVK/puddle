// SPDX-License-Identifier: GPL-3.0-or-later
//! Helpers the host tests share: a minimal HTTP client for the API and a reader of its event
//! stream, written on raw sockets so they depend on nothing the API's own tests do not.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses some of the helpers")]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A client of one host's API.
pub(crate) struct Api {
    addr: SocketAddr,
    token: String,
}

/// One answer: the status code and the body.
pub(crate) struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
}

impl Api {
    pub(crate) fn new(url: &url::Url, token: &str) -> Self {
        let addr = SocketAddr::new(
            url.host_str().unwrap().parse().unwrap(),
            url.port().unwrap(),
        );
        Self {
            addr,
            token: token.to_owned(),
        }
    }

    pub(crate) async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        token: bool,
    ) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let auth = if token {
            format!("Authorization: Bearer {}\r\n", self.token)
        } else {
            String::new()
        };
        let body = body.unwrap_or("");
        let content = if body.is_empty() {
            String::new()
        } else {
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            )
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\n{auth}{content}Connection: close\r\n\r\n{body}",
            self.addr
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {head:?}"));
        Reply {
            status,
            body: dechunk(head, body),
        }
    }

    pub(crate) async fn get(&self, path: &str) -> Reply {
        self.request("GET", path, None, true).await
    }

    pub(crate) async fn post(&self, path: &str, body: &str) -> Reply {
        self.request("POST", path, Some(body), true).await
    }

    pub(crate) async fn put(&self, path: &str, body: &str) -> Reply {
        self.request("PUT", path, Some(body), true).await
    }

    pub(crate) async fn delete(&self, path: &str, body: Option<&str>) -> Reply {
        self.request("DELETE", path, body, true).await
    }

    /// Opens the event stream.
    pub(crate) async fn events(&self) -> Events {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let request = format!(
            "GET /api/events HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\n\r\n",
            self.addr, self.token
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut events = Events {
            stream,
            buf: String::new(),
            seen: Vec::new(),
        };
        // The response head tells the stream is open: events emitted from here on are seen.
        events
            .fill_until(|buf| buf.contains("\r\n\r\n"), Duration::from_secs(10))
            .await;
        assert!(events.buf.starts_with("HTTP/1.1 200"), "{}", events.buf);
        events.buf = events.buf.split_once("\r\n\r\n").unwrap().1.to_owned();
        events
    }
}

/// A chunked body, reassembled; other bodies unchanged.
fn dechunk(head: &str, body: &str) -> String {
    if !head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return body.to_owned();
    }
    let mut out = String::new();
    let mut rest = body;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.push_str(tail.get(..size).unwrap_or_default());
        rest = tail.get(size + 2..).unwrap_or_default();
    }
    out
}

/// The server-sent events of the API, parsed as they arrive.
pub(crate) struct Events {
    stream: TcpStream,
    buf: String,
    pub(crate) seen: Vec<Value>,
}

impl Events {
    async fn fill_until(&mut self, done: impl Fn(&str) -> bool, within: Duration) {
        let deadline = Instant::now() + within;
        let mut chunk = [0_u8; 4096];
        while !done(&self.buf) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "timed out; buffer: {:?}", self.buf);
            match tokio::time::timeout(left, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) => panic!("the event stream ended; buffer: {:?}", self.buf),
                Ok(Ok(n)) => self
                    .buf
                    .push_str(&String::from_utf8_lossy(chunk.get(..n).unwrap())),
                Ok(Err(e)) => panic!("event stream: {e}"),
                Err(_) => {}
            }
        }
    }

    /// Reads events until one satisfies `pred`; returns it. Every event read is kept in `seen`.
    pub(crate) async fn until(&mut self, pred: impl Fn(&Value) -> bool, within: Duration) -> Value {
        let deadline = Instant::now() + within;
        loop {
            while let Some((record, rest)) = self.buf.split_once("\n\n") {
                let record = record.to_owned();
                self.buf = String::from(rest);
                let data: String = record
                    .lines()
                    .filter_map(|l| l.strip_prefix("data:"))
                    .map(str::trim_start)
                    .collect();
                if let Ok(value) = serde_json::from_str::<Value>(&data) {
                    self.seen.push(value.clone());
                    if pred(&value) {
                        return value;
                    }
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "no matching event in {within:?}; saw {:#?}",
                self.seen
            );
            let before = self.buf.len();
            self.fill_until(|b| b.len() > before && b.contains("\n\n"), left)
                .await;
        }
    }

    /// The workspace-progress steps seen so far for `workspace`, in order.
    pub(crate) fn steps(&self, workspace: &str) -> Vec<String> {
        self.seen
            .iter()
            .filter(|e| e["type"] == "workspace_progress" && e["workspace"] == workspace)
            .filter_map(|e| e["step"].as_str().map(str::to_owned))
            .collect()
    }
}

/// Matches the `workspace_progress` event of `workspace` that ends an operation.
pub(crate) fn ended(workspace: &'static str) -> impl Fn(&Value) -> bool {
    move |e| {
        e["type"] == "workspace_progress"
            && e["workspace"] == workspace
            && matches!(e["step"].as_str(), Some("done" | "failed"))
    }
}
