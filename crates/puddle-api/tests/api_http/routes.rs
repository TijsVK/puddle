// SPDX-License-Identifier: GPL-3.0-or-later
//! Pending requests, rules and the audit log through the API, against a real store.

use serde_json::{Value, json};

use puddle_store::Clock;
use puddle_types::{EgressRequest, Host, WorkspaceName};

use crate::common::{START_MS, start};

#[tokio::test]
async fn health_names_the_versions() {
    let api = start().await;
    let reply = api.get("/api/health").await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({ "version": puddle_types::VERSION, "api_version": puddle_api::API_VERSION })
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_pending_request_is_listed_approved_and_then_allowed() {
    let api = start().await;
    let id = api.request("box", "api.example.com");
    let other = api.request("other", "example.org");

    let all = api.get("/api/pending").await.json();
    assert_eq!(all["requests"].as_array().unwrap().len(), 2);
    let mine = api.get("/api/pending?workspace=box").await.json();
    let rows = mine["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["id"], id);
    assert_eq!(row["workspace"], "box");
    assert_eq!(row["host"], "api.example.com");
    assert_eq!(row["port"], 443);
    assert_eq!(row["attempts"], 1);
    assert_eq!(row["state"], "requested");
    assert_eq!(row["first_seen"], START_MS);
    for key in ["decided_at", "decided_by", "rule_id"] {
        assert_eq!(row[key], Value::Null, "{key} is present and null");
    }

    let inbox = api.get("/api/inbox").await.json();
    let domains: Vec<&str> = inbox["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["registrable_domain"].as_str().unwrap())
        .collect();
    assert_eq!(domains.len(), 2);
    assert!(domains.contains(&"example.com") && domains.contains(&"example.org"));

    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{id}/approve"),
            Some(&json!({})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let outcome = reply.json();
    assert_eq!(outcome["request"]["state"], "allowed");
    assert_eq!(outcome["request"]["decided_by"], "api");
    assert_eq!(outcome["rule"]["effect"], "allow");
    assert_eq!(outcome["rule"]["pattern"], "api.example.com");
    assert_eq!(outcome["rule"]["pattern_kind"], "exact");
    assert_eq!(
        outcome["rule"]["scope"],
        json!({"type": "workspace", "workspace": "box"})
    );
    assert_eq!(outcome["rule"]["expires_at"], Value::Null);
    assert_eq!(outcome["rule"]["source_pending_id"], id);
    assert_eq!(outcome["also_closed"], json!([]));

    // The proxy's next attempt is allowed by the rule the API created.
    let decision = api
        .store
        .decide(
            &EgressRequest::new(
                WorkspaceName::new("box").unwrap(),
                Host::parse_normalised("api.example.com").unwrap(),
                443,
            ),
            puddle_types::SuffixAllows::Count,
        )
        .unwrap();
    assert!(
        matches!(decision, puddle_types::Decision::Allow { .. }),
        "{decision:?}"
    );

    // Deciding again is a conflict, an unknown id is 404, and the other row is still open.
    let again = api
        .send("POST", &format!("/api/pending/{id}/deny"), Some(&json!({})))
        .await;
    assert_eq!(again.status, 409);
    assert_eq!(again.error(), "conflict");
    let unknown = api
        .send("POST", "/api/pending/999/approve", Some(&json!({})))
        .await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.error(), "not_found");
    let still = api.get(&format!("/api/pending/{other}")).await.json();
    assert_eq!(still["state"], "requested");
    assert_eq!(api.get("/api/pending/999").await.status, 404);
    api.running.shutdown().await;
}

#[tokio::test]
async fn deny_with_wider_choices_covers_the_suffix_everywhere() {
    let api = start().await;
    let a = api.request("box", "cdn.tracker.example");
    let b = api.request("other", "img.tracker.example");
    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{a}/deny"),
            Some(
                &json!({"scope": "global", "suffix": "*.tracker.example", "expires_in_secs": 3600}),
            ),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let outcome = reply.json();
    assert_eq!(outcome["rule"]["effect"], "deny");
    assert_eq!(outcome["rule"]["scope"], json!({"type": "global"}));
    assert_eq!(outcome["rule"]["pattern"], ".tracker.example");
    assert_eq!(outcome["rule"]["pattern_kind"], "suffix");
    assert_eq!(outcome["rule"]["expires_at"], START_MS + 3_600_000);
    assert_eq!(outcome["also_closed"], json!([b]));
    api.running.shutdown().await;
}

#[tokio::test]
async fn bad_decisions_are_refused_without_changing_anything() {
    let api = start().await;
    let id = api.request("box", "api.example.com");
    let path = format!("/api/pending/{id}/approve");
    for (body, status, code) in [
        (json!({"suffix": "com"}), 422, "invalid"),
        (json!({"suffix": "other.example"}), 422, "invalid"),
        (json!({"expires_in_secs": 0}), 422, "invalid"),
        (json!({"scope": "everywhere"}), 422, "invalid"),
        (json!({"surprise": true}), 422, "invalid"),
        (json!([]), 422, "invalid"),
    ] {
        let reply = api.send("POST", &path, Some(&body)).await;
        assert_eq!(reply.status, status, "{body}: {}", reply.body);
        assert_eq!(reply.error(), code, "{body}");
    }
    // Malformed JSON and a non-numeric id are bad requests.
    let host = api.host();
    let text = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{{",
        api.token
    );
    let reply = crate::common::raw(api.addr, text.as_bytes()).await;
    assert_eq!(reply.status, 400, "{reply:?}");
    assert_eq!(reply.error(), "bad_request");
    let reply = api
        .send("POST", "/api/pending/abc/approve", Some(&json!({})))
        .await;
    assert_eq!(reply.status, 400);
    assert_eq!(
        api.get("/api/pending?workspace=Not_Valid").await.status,
        400
    );
    assert_eq!(api.get("/api/pending?unknown=1").await.status, 400);
    let row = api.get(&format!("/api/pending/{id}")).await.json();
    assert_eq!(row["state"], "requested");
    assert_eq!(api.get("/api/rules").await.json()["rules"], json!([]));
    api.running.shutdown().await;
}

#[tokio::test]
async fn rules_are_created_listed_changed_and_deleted() {
    let api = start().await;
    let open = api.request("box", "registry.npmjs.org");
    let reply = api
        .send(
            "POST",
            "/api/rules",
            Some(&json!({"scope": {"type": "workspace", "workspace": "box"}, "pattern": ".npmjs.org", "effect": "allow"})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    let rule = reply.json();
    let id = rule["id"].as_i64().unwrap();
    assert_eq!(rule["created_by"], "api");
    assert_eq!(rule["pattern_kind"], "suffix");
    assert_eq!(rule["created_at"], START_MS);
    // A direct rule closes the open request it now decides.
    assert_eq!(
        api.get(&format!("/api/pending/{open}")).await.json()["state"],
        "allowed"
    );

    let list = api.get("/api/rules").await.json();
    assert_eq!(list["rules"].as_array().unwrap().len(), 1);

    let later = START_MS + 60_000;
    let reply = api
        .send(
            "PUT",
            &format!("/api/rules/{id}/expiry"),
            Some(&json!({"expires_at": later})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json()["expires_at"], later);
    let reply = api
        .send(
            "PUT",
            &format!("/api/rules/{id}/expiry"),
            Some(&json!({"expires_at": null})),
        )
        .await;
    assert_eq!(reply.json()["expires_at"], Value::Null);
    let past = api
        .send(
            "PUT",
            &format!("/api/rules/{id}/expiry"),
            Some(&json!({"expires_at": 1})),
        )
        .await;
    assert_eq!(past.status, 422);

    let deleted = api.send("DELETE", &format!("/api/rules/{id}"), None).await;
    assert_eq!(deleted.status, 200);
    assert_eq!(deleted.json()["id"], id);
    assert_eq!(
        api.send("DELETE", &format!("/api/rules/{id}"), None)
            .await
            .status,
        404
    );
    assert_eq!(
        api.send(
            "PUT",
            "/api/rules/999/expiry",
            Some(&json!({"expires_at": null}))
        )
        .await
        .status,
        404
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn invalid_rules_are_refused() {
    let api = start().await;
    for body in [
        json!({"scope": {"type": "global"}, "pattern": "*.com", "effect": "allow"}),
        json!({"scope": {"type": "global"}, "pattern": "example.com", "effect": "maybe"}),
        json!({"scope": {"type": "everyone"}, "pattern": "example.com", "effect": "allow"}),
        json!({"scope": {"type": "workspace", "workspace": "tauri"}, "pattern": "example.com", "effect": "allow"}),
        json!({"scope": {"type": "global"}, "pattern": "example.com", "effect": "allow", "expires_at": 1}),
        json!({"scope": {"type": "global"}, "pattern": "example.com", "effect": "allow", "id": 1}),
    ] {
        let reply = api.send("POST", "/api/rules", Some(&body)).await;
        assert_eq!(reply.status, 422, "{body}: {}", reply.body);
    }
    assert_eq!(api.get("/api/rules").await.json()["rules"], json!([]));
    api.running.shutdown().await;
}

#[tokio::test]
async fn audit_pages_back_newest_first_and_follow_the_tail_oldest_first() {
    let api = start().await;
    for host in ["a.example.com", "b.example.com", "c.example.com"] {
        let id = api.request("box", host);
        let reply = api
            .send(
                "POST",
                &format!("/api/pending/{id}/approve"),
                Some(&json!({})),
            )
            .await;
        assert_eq!(reply.status, 200);
    }
    // Newest first, `before` pages back, and the last page says there is no older one.
    let first = api.get("/api/audit?limit=2").await.json();
    let entries = first["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let (newest, second) = (
        entries[0]["id"].as_i64().unwrap(),
        entries[1]["id"].as_i64().unwrap(),
    );
    assert!(newest > second);
    assert!(entries[0]["record"]["type"].is_string(), "{first}");
    assert!(entries[0]["record"]["ts"].is_u64(), "{first}");
    assert_eq!(first["next_after"], newest);
    assert_eq!(first["next_before"], second);
    let mut seen = vec![newest, second];
    let mut before = second;
    loop {
        let page = api
            .get(&format!("/api/audit?before={before}&limit=2"))
            .await
            .json();
        let ids: Vec<i64> = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_i64().unwrap())
            .collect();
        seen.extend(&ids);
        match page["next_before"].as_i64() {
            Some(next) => before = next,
            None => break,
        }
    }
    let mut oldest_first = seen.clone();
    oldest_first.sort_unstable();
    oldest_first.dedup();
    assert_eq!(oldest_first.len(), seen.len(), "no record twice: {seen:?}");
    assert_eq!(
        oldest_first.len(),
        10,
        "System managed at start, then 3 x (created, rule, decided)"
    );
    // `after` reads oldest first.
    let tail = api
        .get(&format!("/api/audit?after={}&limit=100", oldest_first[2]))
        .await
        .json();
    let tail_ids: Vec<i64> = tail["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_i64().unwrap())
        .collect();
    assert_eq!(tail_ids, oldest_first[3..]);
    assert_eq!(tail["next_before"], json!(null));
    let end = tail["next_after"].as_i64().unwrap();
    let empty = api.get(&format!("/api/audit?after={end}")).await.json();
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["next_after"], end);
    for bad in [
        "/api/audit?limit=0",
        "/api/audit?limit=501",
        "/api/audit?after=1&before=9",
        "/api/audit?workspace=Not%20A%20Name",
        "/api/audit?from=10&to=10",
        "/api/audit?type=nope",
        "/api/audit?outcome=nope",
    ] {
        let status = api.get(bad).await.status;
        assert!(status == 422 || status == 400, "{bad}: {status}");
    }
    assert_eq!(api.get("/api/audit?limit=0").await.status, 422);
    assert_eq!(api.get("/api/audit?after=x").await.status, 400);
    assert_eq!(api.get("/api/audit?workspace=a%20b").await.status, 422);
    assert_eq!(api.get("/api/audit?unknown=1").await.status, 400);
    api.running.shutdown().await;
}

#[tokio::test]
async fn audit_filters_run_on_the_server() {
    let api = start().await;
    let a = api.request("alpha", "api.github.com");
    api.request("beta", "registry.npmjs.org");
    api.clock.advance(60_000);
    api.send("POST", &format!("/api/pending/{a}/deny"), Some(&json!({})))
        .await;
    let t = api.clock.now_ms();
    let types = |reply: crate::common::Reply| -> Vec<String> {
        reply.json()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["record"]["type"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        types(api.get("/api/audit?workspace=beta").await),
        ["pending_created"]
    );
    assert_eq!(
        types(api.get("/api/audit?type=rule_created").await),
        ["rule_created"]
    );
    assert_eq!(
        types(api.get("/api/audit?outcome=deny").await),
        ["pending_decided"]
    );
    assert_eq!(
        types(
            api.get("/api/audit?host_contains=GITHUB&type=pending_created")
                .await
        ),
        ["pending_created"]
    );
    assert_eq!(
        types(api.get("/api/audit?host_contains=nothing").await),
        Vec::<String>::new()
    );
    // An empty filter value is no filter (a form that sends `host_contains=`). The fifth record is
    // System managed's, written when the API started.
    assert_eq!(
        types(api.get("/api/audit?host_contains=&workspace=").await).len(),
        5
    );
    assert_eq!(
        types(api.get(&format!("/api/audit?from={t}")).await),
        ["pending_decided", "rule_created"]
    );
    assert_eq!(
        types(api.get(&format!("/api/audit?to={t}&workspace=alpha")).await),
        ["pending_created"]
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn audit_records_are_typed_including_the_upstream_hop() {
    use puddle_types::{ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionReason};
    let api = start().await;
    let request = EgressRequest::new(
        WorkspaceName::new("box").unwrap(),
        Host::parse_normalised("example.com").unwrap(),
        443,
    );
    let mut event =
        ConnectionEvent::new(&request, ConnectionDecision::Allow, ConnectionReason::Rule);
    event.upstream = Some("PROXY corp.example:3128".into());
    api.store.record(&event);
    let page = api
        .get("/api/audit?type=connection&outcome=allow")
        .await
        .json();
    let record = &page["entries"][0]["record"];
    assert_eq!(record["upstream"], "PROXY corp.example:3128");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["host"], "example.com");
    assert_eq!(record["rule_id"], json!(null));
    api.running.shutdown().await;
}

#[tokio::test]
async fn puddles_own_connections_have_an_origin_and_the_origin_filter_finds_them() {
    use puddle_types::{ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionReason};
    let api = start().await;
    let host = || Host::parse_normalised("registry-1.docker.io").unwrap();
    let mut pull = ConnectionEvent::puddle(
        host(),
        443,
        ConnectionDecision::Allow,
        ConnectionReason::PuddleRequest,
    );
    pull.bytes_down = 1024;
    api.store.record(&pull);
    api.store.record(&ConnectionEvent::new(
        &EgressRequest::new(WorkspaceName::new("box").unwrap(), host(), 443),
        ConnectionDecision::Allow,
        ConnectionReason::Rule,
    ));
    api.request("box", "other.example.com");

    let page = api.get("/api/audit?origin=puddle").await.json();
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{page}");
    let record = &entries[0]["record"];
    assert_eq!(record["origin"], "puddle");
    assert_eq!(record["workspace_id"], json!(null));
    assert_eq!(record["reason"], "puddle_request");
    assert_eq!(record["bytes_down"], 1024);

    let page = api.get("/api/audit?origin=workspace").await.json();
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{page}");
    assert_eq!(entries[0]["record"]["origin"], "workspace");
    assert_eq!(entries[0]["record"]["workspace_id"], "box");
    // Only connection records have an origin; a workspace filter excludes puddle's own.
    let both = api
        .get("/api/audit?origin=puddle&workspace=box")
        .await
        .json();
    assert!(both["entries"].as_array().unwrap().is_empty(), "{both}");
    assert_eq!(api.get("/api/audit?origin=elsewhere").await.status, 400);
    api.running.shutdown().await;
}

#[tokio::test]
async fn local_destinations_name_the_toggle_that_blocks_their_approval() {
    let api = start().await;
    let private = api.request("box", "10.0.0.5");
    let loopback = api.request("box", "localhost");
    let public = api.request("box", "www.example.com");
    let blocked = |list: &Value| -> Vec<(i64, Value)> {
        let mut rows: Vec<_> = list["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["id"].as_i64().unwrap(), r["blocked_by"].clone()))
            .collect();
        rows.sort_by_key(|(id, _)| *id);
        rows
    };
    let list = api.get("/api/pending").await.json();
    assert_eq!(
        blocked(&list),
        [
            (private, json!("private")),
            (loopback, json!("loopback")),
            (public, json!(null))
        ]
    );
    let one = api.get(&format!("/api/pending/{private}")).await.json();
    assert_eq!(one["blocked_by"], "private");
    let inbox = api.get("/api/inbox").await.json();
    let in_inbox: usize = inbox["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["requests"].as_array().unwrap())
        .filter(|r| !r["blocked_by"].is_null())
        .count();
    assert_eq!(in_inbox, 2);

    // Switching the toggle on (here for every workspace) frees only that category.
    let put = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({"workspace_defaults": {"local_toggles": {"private": true}}})),
        )
        .await;
    assert_eq!(put.status, 200, "{}", put.body);
    let list = api.get("/api/pending").await.json();
    assert_eq!(
        blocked(&list),
        [
            (private, json!(null)),
            (loopback, json!("loopback")),
            (public, json!(null))
        ]
    );
    // A decided request is never blocked.
    let denied = api
        .send(
            "POST",
            &format!("/api/pending/{loopback}/deny"),
            Some(&json!({})),
        )
        .await;
    assert_eq!(denied.json()["request"]["blocked_by"], json!(null));
    api.running.shutdown().await;
}

#[tokio::test]
async fn rule_input_is_normalised_not_refused() {
    let api = start().await;
    let reply = api
        .send(
            "POST",
            "/api/rules",
            Some(&json!({"scope": {"type": "global"}, "pattern": " *.Bücher.EXAMPLE.org. ", "effect": "allow"})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    let rule = reply.json();
    assert_eq!(rule["pattern"], ".xn--bcher-kva.example.org");
    assert_eq!(rule["pattern_kind"], "suffix");
    for (pattern, field) in [
        ("https://example.com/", "pattern: "),
        ("example.com:8443", "pattern: "),
        ("a b", "pattern: "),
    ] {
        let reply = api
            .send(
                "POST",
                "/api/rules",
                Some(&json!({"scope": {"type": "global"}, "pattern": pattern, "effect": "allow"})),
            )
            .await;
        assert_eq!(reply.status, 422, "{pattern}");
        assert!(
            reply.json()["message"].as_str().unwrap().starts_with(field),
            "{pattern}: {}",
            reply.body
        );
    }
    let public = api
        .send(
            "POST",
            "/api/rules",
            Some(&json!({"scope": {"type": "global"}, "pattern": "*.CO.UK", "effect": "allow"})),
        )
        .await;
    assert_eq!(public.status, 422);
    // The same normaliser serves an approval's suffix.
    let id = api.request("box", "www.github.com");
    let approved = api
        .send(
            "POST",
            &format!("/api/pending/{id}/approve"),
            Some(&json!({"suffix": "*.GitHub.com"})),
        )
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.json()["rule"]["pattern"], ".github.com");
    let bad = api
        .send(
            "POST",
            &format!(
                "/api/pending/{}/approve",
                api.request("box", "x.example.org")
            ),
            Some(&json!({"suffix": "example.org:80"})),
        )
        .await;
    assert_eq!(bad.status, 422);
    assert!(
        bad.json()["message"]
            .as_str()
            .unwrap()
            .starts_with("suffix: "),
        "{}",
        bad.body
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn suppression_reports_per_workspace() {
    let api = start().await;
    let reply = api.get("/api/workspaces/box/suppression").await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({"workspace": "box", "active": false, "count": 0})
    );
    assert_eq!(
        api.get("/api/workspaces/Bad_Name/suppression").await.status,
        400
    );
    api.running.shutdown().await;
}
