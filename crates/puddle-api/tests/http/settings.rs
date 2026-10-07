// SPDX-License-Identifier: GPL-3.0-or-later
//! Settings and consents through the API, over the versioned documents of `puddle-settings`.

use puddle_api::SettingsRepo;
use puddle_types::SandboxName;
use serde_json::{Value, json};

use crate::common::{START_MS, start};

fn null_layer() -> Value {
    json!({
        "memory": null,
        "local_toggles": {"loopback": null, "private": null, "link_local": null, "metadata": null, "special": null},
        "wildcards_reach_local": null,
        "reconnection_grace": null,
        "zoom_hotkeys": null,
        "clipboard_read": null,
        "direct_ssh": null
    })
}

#[tokio::test]
async fn fresh_settings_are_all_defaults_with_every_field_present() {
    let api = start().await;
    let reply = api.get("/api/settings").await;
    assert_eq!(reply.status, 200);
    let view = reply.json();
    assert_eq!(view["sandbox_defaults"], null_layer());
    assert_eq!(
        view["vscode_server"],
        json!({"server": null, "telemetry": null, "auto_update": null})
    );
    assert_eq!(
        view["ui"],
        json!({"theme": null, "notifications": null, "sound": null, "close_behaviour": null})
    );
    assert_eq!(view["unknown_fields"], json!([]));
    let e = &view["effective"];
    assert_eq!(e["memory"], json!({"value": 8192, "source": "default"}));
    assert_eq!(e["reconnection_grace"]["value"], 300);
    assert_eq!(e["clipboard_read"]["value"], "ask");
    assert_eq!(e["local_toggles"]["metadata"]["value"], false);
    assert_eq!(
        e["direct_ssh"],
        json!({"value": false, "source": "default"})
    );
    // Reading wrote nothing.
    assert_eq!(api.settings.load_global().unwrap(), None);
    api.running.shutdown().await;
}

#[tokio::test]
async fn global_and_sandbox_values_resolve_in_order() {
    let api = start().await;
    let reply = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({
                "sandbox_defaults": {"memory": 4096, "local_toggles": {"private": true}},
                "vscode_server": {"telemetry": true}
            })),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let view = reply.json();
    assert_eq!(view["sandbox_defaults"]["memory"], 4096);
    assert_eq!(view["effective"]["memory"]["source"], "global");
    assert_eq!(view["vscode_server"]["telemetry"], true);

    let reply = api
        .send(
            "PUT",
            "/api/settings/sandboxes/big",
            Some(&json!({"overrides": {"memory": 16384, "clipboard_read": "deny"}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let view = reply.json();
    assert_eq!(view["sandbox"], "big");
    assert_eq!(
        view["effective"]["memory"],
        json!({"value": 16384, "source": "sandbox"})
    );
    assert_eq!(view["effective"]["clipboard_read"]["source"], "sandbox");
    assert_eq!(
        view["effective"]["local_toggles"]["private"],
        json!({"value": true, "source": "global"})
    );
    assert_eq!(view["effective"]["zoom_hotkeys"]["source"], "default");

    // A sandbox without stored settings inherits; reading it doesn't create a document.
    let plain = api.get("/api/settings/sandboxes/plain").await.json();
    assert_eq!(plain["overrides"], null_layer());
    assert_eq!(plain["effective"]["memory"]["value"], 4096);
    let name = SandboxName::new("plain").unwrap();
    assert_eq!(api.settings.load_sandbox(&name).unwrap(), None);

    // Stored documents are sparse and versioned.
    assert_eq!(
        api.settings.load_global().unwrap().unwrap(),
        json!({
            "schema_version": 1,
            "sandbox_defaults": {"memory": 4096, "local_toggles": {"private": true}},
            "vscode_server": {"telemetry": true}
        })
    );

    // PUT replaces: leaving a value out clears it back to inherit.
    let reply = api.send("PUT", "/api/settings", Some(&json!({}))).await;
    assert_eq!(reply.json()["sandbox_defaults"], null_layer());
    api.running.shutdown().await;
}

#[tokio::test]
async fn out_of_range_and_unknown_settings_are_refused() {
    let api = start().await;
    for body in [
        json!({"sandbox_defaults": {"memory": 1}}),
        json!({"sandbox_defaults": {"reconnection_grace": 5}}),
        json!({"sandbox_defaults": {"clipboard_read": "sometimes"}}),
        json!({"sandbox_defaults": {"cpus": 4}}),
        json!({"consents": {}}),
    ] {
        let reply = api.send("PUT", "/api/settings", Some(&body)).await;
        assert_eq!(reply.status, 422, "{body}: {}", reply.body);
    }
    assert_eq!(api.settings.load_global().unwrap(), None);
    let reply = api
        .send("PUT", "/api/settings/sandboxes/tauri", Some(&json!({})))
        .await;
    assert_eq!(reply.status, 400, "a reserved sandbox name");
    api.running.shutdown().await;
}

#[tokio::test]
async fn unknown_stored_fields_are_listed_and_kept() {
    let api = start().await;
    api.settings
        .save_global(
            json!({"schema_version": 1, "rule_sets": ["x"], "sandbox_defaults": {"cpus": 2}}),
        )
        .unwrap();
    let name = SandboxName::new("box").unwrap();
    api.settings
        .save_sandbox(&name, json!({"overrides": {"gpu": true}}))
        .unwrap();
    let view = api.get("/api/settings").await.json();
    assert_eq!(
        view["unknown_fields"],
        json!(["rule_sets", "sandbox_defaults.cpus"])
    );
    let reply = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({"sandbox_defaults": {"zoom_hotkeys": false}})),
        )
        .await;
    assert_eq!(reply.status, 200);
    let stored = api.settings.load_global().unwrap().unwrap();
    assert_eq!(stored["rule_sets"], json!(["x"]));
    assert_eq!(stored["sandbox_defaults"]["cpus"], 2);
    assert_eq!(stored["sandbox_defaults"]["zoom_hotkeys"], false);

    let view = api.get("/api/settings/sandboxes/box").await.json();
    assert_eq!(view["unknown_fields"], json!(["overrides.gpu"]));
    api.send(
        "PUT",
        "/api/settings/sandboxes/box",
        Some(&json!({"overrides": {"memory": 2048}})),
    )
    .await;
    let stored = api.settings.load_sandbox(&name).unwrap().unwrap();
    assert_eq!(stored["overrides"], json!({"gpu": true, "memory": 2048}));
    api.running.shutdown().await;
}

#[tokio::test]
async fn settings_from_a_newer_puddle_are_a_conflict_and_left_alone() {
    let api = start().await;
    let newer = json!({"schema_version": 99, "sandbox_defaults": {"memory": 4096}});
    api.settings.save_global(newer.clone()).unwrap();
    for (method, path, body) in [
        ("GET", "/api/settings", None),
        ("PUT", "/api/settings", Some(json!({}))),
        ("GET", "/api/consents", None),
        (
            "PUT",
            "/api/consents/telemetry",
            Some(json!({"decision": "granted", "terms_version": "v1"})),
        ),
        ("GET", "/api/settings/sandboxes/box", None),
    ] {
        let reply = api.send(method, path, body.as_ref()).await;
        assert_eq!(reply.status, 409, "{method} {path}: {}", reply.body);
        assert_eq!(reply.error(), "newer_settings");
        assert!(
            reply.json()["message"]
                .as_str()
                .unwrap()
                .contains("update puddle")
        );
    }
    assert_eq!(api.settings.load_global().unwrap(), Some(newer));
    // A stored document that isn't an object is puddle's problem, not the client's.
    api.settings.save_global(json!([1, 2])).unwrap();
    let reply = api.get("/api/settings").await;
    assert_eq!(reply.status, 500);
    assert_eq!(reply.error(), "internal");
    api.running.shutdown().await;
}

#[tokio::test]
async fn consents_are_recorded_with_the_server_time() {
    let api = start().await;
    let all = api.get("/api/consents").await.json();
    assert_eq!(
        all,
        json!({
            "telemetry": {"state": "not_asked"},
            "crash_reports": {"state": "not_asked"},
            "vscode_server": {"state": "not_asked"}
        })
    );
    api.clock.set(START_MS + 5);
    let reply = api
        .send(
            "PUT",
            "/api/consents/vscode_server",
            Some(&json!({"decision": "granted", "terms_version": "https://example.test/license"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.json()["vscode_server"],
        json!({"state": "granted", "at": START_MS + 5, "terms_version": "https://example.test/license"})
    );
    let reply = api
        .send(
            "PUT",
            "/api/consents/telemetry",
            Some(&json!({"decision": "declined", "terms_version": "2026-10"})),
        )
        .await;
    assert_eq!(reply.json()["telemetry"]["state"], "declined");
    // Recorded in the global document, next to the settings.
    let stored = api.settings.load_global().unwrap().unwrap();
    assert_eq!(stored["consents"]["vscode_server"]["state"], "granted");

    for (path, body, status) in [
        (
            "/api/consents/telemetry",
            json!({"decision": "granted", "terms_version": "has space"}),
            422,
        ),
        (
            "/api/consents/telemetry",
            json!({"decision": "granted", "terms_version": ""}),
            422,
        ),
        (
            "/api/consents/telemetry",
            json!({"decision": "maybe", "terms_version": "v1"}),
            422,
        ),
        (
            "/api/consents/newsletter",
            json!({"decision": "granted", "terms_version": "v1"}),
            400,
        ),
    ] {
        let reply = api.send("PUT", path, Some(&body)).await;
        assert_eq!(reply.status, status, "{path} {body}: {}", reply.body);
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn microsoft_server_needs_consent_and_ui_prefs_are_stored() {
    let api = start().await;
    let ms = json!({"vscode_server": {"server": "microsoft"}});
    let reply = api.send("PUT", "/api/settings", Some(&ms)).await;
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert!(reply.body.contains("consent"), "{}", reply.body);
    assert_eq!(
        api.get("/api/settings").await.json()["vscode_server"]["server"],
        Value::Null
    );

    // A decline is not consent either.
    let declined = json!({"decision": "declined", "terms_version": "https://example.test/terms"});
    api.send("PUT", "/api/consents/vscode_server", Some(&declined))
        .await;
    assert_eq!(
        api.send("PUT", "/api/settings", Some(&ms)).await.status,
        422
    );

    let granted = json!({"decision": "granted", "terms_version": "https://example.test/terms"});
    api.send("PUT", "/api/consents/vscode_server", Some(&granted))
        .await;
    let body = json!({
        "vscode_server": {"server": "microsoft", "telemetry": false},
        "ui": {"theme": "dark", "notifications": false, "sound": true, "close_behaviour": "quit"}
    });
    let reply = api.send("PUT", "/api/settings", Some(&body)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let view = reply.json();
    assert_eq!(view["vscode_server"]["server"], "microsoft");
    assert_eq!(view["ui"]["theme"], "dark");
    assert_eq!(view["ui"]["close_behaviour"], "quit");
    let stored = api.settings.load_global().unwrap().unwrap();
    assert_eq!(stored["ui"]["theme"], "dark");
    assert_eq!(stored["vscode_server"]["server"], "microsoft");
    // The consent survives choosing code-server again.
    let back = json!({"vscode_server": {"server": "code_server"}});
    assert_eq!(
        api.send("PUT", "/api/settings", Some(&back)).await.status,
        200
    );
    assert_eq!(
        api.get("/api/consents").await.json()["vscode_server"]["state"],
        "granted"
    );

    let bad = json!({"ui": {"theme": "purple"}});
    assert_eq!(
        api.send("PUT", "/api/settings", Some(&bad)).await.status,
        422
    );
    api.running.shutdown().await;
}
