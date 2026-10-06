// SPDX-License-Identifier: GPL-3.0-or-later
//! Pending requests, rules and the audit log through the API, against a real store.

use serde_json::{Value, json};

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
    let mine = api.get("/api/pending?sandbox=box").await.json();
    let rows = mine["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row["id"], id);
    assert_eq!(row["sandbox"], "box");
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
        json!({"type": "sandbox", "sandbox": "box"})
    );
    assert_eq!(outcome["rule"]["expires_at"], Value::Null);
    assert_eq!(outcome["rule"]["source_pending_id"], id);
    assert_eq!(outcome["also_closed"], json!([]));

    // The proxy's next attempt is allowed by the rule the API created.
    let decision = api
        .store
        .decide(
            &puddle_types::EgressRequest::new(
                puddle_types::SandboxName::new("box").unwrap(),
                puddle_types::Host::parse_normalised("api.example.com").unwrap(),
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
    assert_eq!(api.get("/api/pending?sandbox=Not_Valid").await.status, 400);
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
            Some(&json!({"scope": {"type": "sandbox", "sandbox": "box"}, "pattern": ".npmjs.org", "effect": "allow"})),
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
        json!({"scope": {"type": "global"}, "pattern": "Example.com", "effect": "allow"}),
        json!({"scope": {"type": "global"}, "pattern": "example.com", "effect": "maybe"}),
        json!({"scope": {"type": "everyone"}, "pattern": "example.com", "effect": "allow"}),
        json!({"scope": {"type": "sandbox", "sandbox": "tauri"}, "pattern": "example.com", "effect": "allow"}),
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
async fn audit_pages_read_on_from_the_last_id() {
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
    let first = api.get("/api/audit?limit=2").await.json();
    let entries = first["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries[0]["record"]["type"].is_string(), "{first}");
    assert!(entries[0]["record"]["ts"].is_u64(), "{first}");
    let next = first["next_after"].as_i64().unwrap();
    assert_eq!(next, entries[1]["id"].as_i64().unwrap());
    let rest = api
        .get(&format!("/api/audit?after={next}&limit=1000"))
        .await
        .json();
    let rest_entries = rest["entries"].as_array().unwrap();
    assert!(!rest_entries.is_empty(), "{rest}");
    assert!(rest_entries[0]["id"].as_i64().unwrap() > next);
    let end = rest["next_after"].as_i64().unwrap();
    let empty = api.get(&format!("/api/audit?after={end}")).await.json();
    assert_eq!(empty["entries"], json!([]));
    assert_eq!(empty["next_after"], end);
    for bad in ["/api/audit?limit=0", "/api/audit?limit=1001"] {
        assert_eq!(api.get(bad).await.status, 422, "{bad}");
    }
    assert_eq!(api.get("/api/audit?after=x").await.status, 400);
    api.running.shutdown().await;
}

#[tokio::test]
async fn suppression_reports_per_sandbox() {
    let api = start().await;
    let reply = api.get("/api/sandboxes/box/suppression").await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({"sandbox": "box", "active": false, "count": 0})
    );
    assert_eq!(
        api.get("/api/sandboxes/Bad_Name/suppression").await.status,
        400
    );
    api.running.shutdown().await;
}
