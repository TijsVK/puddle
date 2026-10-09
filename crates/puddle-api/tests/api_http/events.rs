// SPDX-License-Identifier: GPL-3.0-or-later
//! The SSE stream over real HTTP: filtering, lag notices, and ending on shutdown.

use std::time::Duration;

use puddle_types::{Event, EventSink, WorkspaceName, WorkspaceStatus};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::common::{Api, STEP, start};

/// An open event stream and what has been read from it so far.
pub(crate) struct Stream {
    tcp: TcpStream,
    pub(crate) buf: String,
}

impl Stream {
    pub(crate) async fn open(api: &Api, query: &str) -> Self {
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

    pub(crate) async fn read_until(&mut self, done: impl Fn(&str) -> bool) {
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
    pub(crate) fn data(&self) -> Vec<Value> {
        self.buf
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str(d).ok())
            .collect()
    }
}

fn name(s: &str) -> WorkspaceName {
    WorkspaceName::new(s).unwrap()
}

#[tokio::test]
async fn a_filtered_stream_gets_only_its_workspace() {
    let api = start().await;
    let mut s = Stream::open(&api, "?workspace=a").await;
    api.events.emit(Event::oom_kill(name("b"), 1, "other"));
    api.events.emit(Event::oom_kill(name("a"), 2, "node"));
    api.events.emit(Event::StatusChanged {
        workspace: name("a"),
        status: WorkspaceStatus::Stopped,
    });
    s.read_until(|b| b.contains("status_changed")).await;
    let data = s.data();
    assert_eq!(data.len(), 2, "{}", s.buf);
    assert_eq!(data[0]["type"], "oom_kill");
    assert_eq!(data[0]["workspace"], "a");
    assert_eq!(data[0]["process"], "node");
    assert_eq!(data[1]["status"], "stopped");
    assert!(!s.buf.contains("other"));
    api.running.shutdown().await;
}

#[tokio::test]
async fn an_unfiltered_stream_gets_every_workspace() {
    let api = start().await;
    let mut s = Stream::open(&api, "").await;
    api.events.emit(Event::oom_kill(name("a"), 1, "x"));
    api.events.emit(Event::oom_kill(name("b"), 2, "y"));
    s.read_until(|b| b.matches("data: ").count() >= 2).await;
    let workspaces: Vec<_> = s.data().iter().map(|d| d["workspace"].clone()).collect();
    assert_eq!(workspaces, ["a", "b"]);
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
    let mut s = Stream::open(&api, "?workspace=a").await;
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
    let reply = api.get("/api/events?workspace=NOT_VALID").await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.error(), "bad_request");
    assert_eq!(api.get("/api/events?other=1").await.status, 400);
    api.running.shutdown().await;
}

fn types(s: &Stream) -> Vec<String> {
    s.data()
        .iter()
        .map(|d| d["type"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn a_request_that_arrives_shows_up_live_and_a_decision_closes_it() {
    let api = start().await;
    let mut s = Stream::open(&api, "").await;
    let id = api.request("box", "www.example.com");
    s.read_until(|b| b.contains("audit_appended")).await;
    let data = s.data();
    assert_eq!(types(&s), ["pending_opened", "audit_appended"], "{}", s.buf);
    assert_eq!(data[0]["request"]["id"], id);
    assert_eq!(data[0]["request"]["workspace"], "box");
    assert_eq!(data[0]["request"]["host"], "www.example.com");
    assert_eq!(data[0]["request"]["registrable_domain"], "example.com");
    assert_eq!(data[0]["request"]["port"], 443);
    assert_eq!(data[0]["request"]["attempts"], 1);

    api.request("box", "www.example.com");
    s.read_until(|b| b.contains("pending_updated")).await;
    let updated = &s.data()[2];
    assert_eq!(
        (updated["id"].as_i64(), updated["attempts"].as_u64()),
        (Some(id), Some(2))
    );

    let sibling = api.request("box", "api.example.com");
    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{id}/approve"),
            Some(&serde_json::json!({"suffix": "Example.COM"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    s.read_until(|b| {
        b.matches("pending_closed").count() >= 2 && b.matches("rules_changed").count() >= 1
    })
    .await;
    let closed: Vec<_> = s
        .data()
        .into_iter()
        .filter(|d| d["type"] == "pending_closed")
        .collect();
    let rule_id = reply.json()["rule"]["id"].clone();
    assert_eq!(closed.len(), 2);
    for d in &closed {
        assert_eq!(
            (&d["state"], &d["rule_id"], &d["workspace"]),
            (&"allowed".into(), &rule_id, &"box".into())
        );
    }
    let ids: Vec<_> = closed.iter().map(|d| d["id"].as_i64().unwrap()).collect();
    assert!(ids.contains(&id) && ids.contains(&sibling), "{ids:?}");
    api.running.shutdown().await;
}

#[tokio::test]
async fn rule_changes_reach_every_stream_even_a_filtered_one() {
    let api = start().await;
    let mut filtered = Stream::open(&api, "?workspace=other").await;
    api.request("box", "example.com");
    let created = api
        .send(
            "POST",
            "/api/rules",
            Some(&serde_json::json!({"scope": {"type": "global"}, "pattern": "Example.COM", "effect": "deny"})),
        )
        .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let id = created.json()["id"].as_i64().unwrap();
    api.send(
        "PUT",
        &format!("/api/rules/{id}/expiry"),
        Some(&serde_json::json!({"expires_at": null})),
    )
    .await;
    assert_eq!(
        api.send("DELETE", &format!("/api/rules/{id}"), None)
            .await
            .status,
        200
    );
    filtered
        .read_until(|b| b.matches("rules_changed").count() >= 3)
        .await;
    // The other workspace's pending events are not for this stream; rule and audit events are.
    assert!(
        types(&filtered)
            .iter()
            .all(|t| t == "rules_changed" || t == "audit_appended"),
        "{}",
        filtered.buf
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn audit_appended_names_the_newest_record_so_a_client_can_read_on() {
    let api = start().await;
    let mut s = Stream::open(&api, "").await;
    api.request("box", "example.com");
    s.read_until(|b| b.contains("audit_appended")).await;
    let id = s.data().last().unwrap()["id"].as_i64().unwrap();
    let page = api.get("/api/audit?limit=1").await.json();
    assert_eq!(page["entries"][0]["id"], id);
    assert_eq!(page["next_after"], id);
    api.running.shutdown().await;
}
