// SPDX-License-Identifier: GPL-3.0-or-later
//! The SSE stream over real HTTP: filtering, lag notices, and ending on shutdown.

use std::time::Duration;

use puddle_types::{Event, EventSink, SandboxName, SandboxStatus};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::{Api, STEP, start};

/// An open event stream and what has been read from it so far.
struct Stream {
    tcp: TcpStream,
    buf: String,
}

impl Stream {
    async fn open(api: &Api, query: &str) -> Self {
        let mut tcp = TcpStream::connect(api.addr).await.unwrap();
        let request = format!(
            "GET /api/events{query} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\n\r\n",
            api.host(),
            api.token
        );
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut s = Self {
            tcp,
            buf: String::new(),
        };
        s.read_until(|b| b.contains("\r\n\r\n")).await;
        assert!(s.buf.starts_with("HTTP/1.1 200"), "{}", s.buf);
        assert!(
            s.buf
                .to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "{}",
            s.buf
        );
        // Wait until the handler subscribed, so no event emitted next is missed.
        tokio::time::timeout(STEP, async {
            while api.events.subscribers() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("subscribed");
        s
    }

    async fn read_until(&mut self, done: impl Fn(&str) -> bool) {
        let mut chunk = [0u8; 4096];
        tokio::time::timeout(STEP, async {
            while !done(&self.buf) {
                let n = self.tcp.read(&mut chunk).await.unwrap();
                assert!(n > 0, "stream closed early: {}", self.buf);
                self.buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out; read so far: {}", self.buf));
    }

    /// The JSON of every `data:` line read so far.
    fn data(&self) -> Vec<Value> {
        self.buf
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str(d).ok())
            .collect()
    }
}

fn name(s: &str) -> SandboxName {
    SandboxName::new(s).unwrap()
}

#[tokio::test]
async fn a_filtered_stream_gets_only_its_sandbox() {
    let api = start().await;
    let mut s = Stream::open(&api, "?sandbox=a").await;
    api.events.emit(Event::oom_kill(name("b"), 1, "other"));
    api.events.emit(Event::oom_kill(name("a"), 2, "node"));
    api.events.emit(Event::StatusChanged {
        sandbox: name("a"),
        status: SandboxStatus::Stopped,
    });
    s.read_until(|b| b.contains("status_changed")).await;
    let data = s.data();
    assert_eq!(data.len(), 2, "{}", s.buf);
    assert_eq!(data[0]["type"], "oom_kill");
    assert_eq!(data[0]["sandbox"], "a");
    assert_eq!(data[0]["process"], "node");
    assert_eq!(data[1]["status"], "stopped");
    assert!(!s.buf.contains("other"));
    api.running.shutdown().await;
}

#[tokio::test]
async fn an_unfiltered_stream_gets_every_sandbox() {
    let api = start().await;
    let mut s = Stream::open(&api, "").await;
    api.events.emit(Event::oom_kill(name("a"), 1, "x"));
    api.events.emit(Event::oom_kill(name("b"), 2, "y"));
    s.read_until(|b| b.matches("data: ").count() >= 2).await;
    let sandboxes: Vec<_> = s.data().iter().map(|d| d["sandbox"].clone()).collect();
    assert_eq!(sandboxes, ["a", "b"]);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_slow_subscriber_is_told_what_it_missed() {
    let api = start().await;
    let mut s = Stream::open(&api, "").await;
    // Far more than the per-subscriber buffer, emitted before the stream is read.
    for pid in 0..u32::try_from(puddle_api::DEFAULT_EVENT_BUFFER * 3).unwrap() {
        api.events.emit(Event::oom_kill(name("a"), pid, "x"));
    }
    s.read_until(|b| b.contains("event: lagged")).await;
    let lagged = s
        .buf
        .split("event: lagged")
        .nth(1)
        .and_then(|rest| rest.lines().find_map(|l| l.strip_prefix("data: ")))
        .map(|d| serde_json::from_str::<Value>(d).unwrap())
        .unwrap();
    assert!(lagged["missed"].as_u64().unwrap() > 0, "{lagged}");
    api.running.shutdown().await;
}

#[tokio::test]
async fn shutdown_ends_open_streams_promptly() {
    let api = start().await;
    let mut s = Stream::open(&api, "?sandbox=a").await;
    let started = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), api.running.shutdown())
        .await
        .expect("shutdown returns with a stream open");
    // The stream reaches its end (the terminating chunk, then EOF).
    let mut rest = Vec::new();
    tokio::time::timeout(STEP, s.tcp.read_to_end(&mut rest))
        .await
        .expect("stream closed")
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn an_invalid_filter_is_refused() {
    let api = start().await;
    let reply = api.get("/api/events?sandbox=NOT_VALID").await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error(), "bad_request");
    assert_eq!(api.get("/api/events?other=1").await.status, 400);
    api.running.shutdown().await;
}
