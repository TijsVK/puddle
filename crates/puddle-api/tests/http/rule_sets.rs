// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule sets and System managed through the API, against a real store.

use serde_json::{Value, json};

use puddle_types::{Decision, EgressRequest, Host, SandboxName, SuffixAllows};

use crate::common::{Api, start};

fn decide(api: &Api, sandbox: &str, host: &str) -> Decision {
    api.store
        .decide(
            &EgressRequest::new(
                SandboxName::new(sandbox).unwrap(),
                Host::parse_normalised(host).unwrap(),
                443,
            ),
            SuffixAllows::Count,
        )
        .unwrap()
}

fn system_hosts(list: &Value) -> Vec<(String, String)> {
    list["system_managed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["pattern"].as_str().unwrap().to_owned(),
                h["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn system_managed_follows_the_editor_server_choice() {
    let api = start().await;
    // A fresh setup runs code-server: Open VSX, with its reason in words.
    let list = api.get("/api/rule-sets").await.json();
    let hosts = system_hosts(&list);
    assert!(hosts.contains(&("open-vsx.org".into(), "code_server".into())));
    assert!(hosts.iter().all(|(_, reason)| reason == "code_server"));
    let first = &list["system_managed"][0];
    assert_eq!(first["sandbox"], Value::Null);
    assert!(
        first["reason_text"]
            .as_str()
            .unwrap()
            .contains("code-server")
    );
    assert!(decide(&api, "box", "open-vsx.org").is_allow());
    assert!(!decide(&api, "box", "marketplace.visualstudio.com").is_allow());

    // Microsoft's server, after consent: Microsoft's hosts instead of Open VSX.
    let waiting = api.request("box", "marketplace.visualstudio.com");
    let granted = json!({"decision": "granted", "terms_version": "https://example.test/terms"});
    api.send("PUT", "/api/consents/vscode_server", Some(&granted))
        .await;
    let reply = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({"vscode_server": {"server": "microsoft"}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let hosts = system_hosts(&api.get("/api/rule-sets").await.json());
    assert!(hosts.contains(&("*.gallerycdn.vsassets.io".into(), "microsoft_server".into())));
    assert!(!hosts.iter().any(|(p, _)| p == "open-vsx.org"));
    assert!(decide(&api, "box", "update.code.visualstudio.com").is_allow());
    // The waiting request was closed by the new host.
    let row = api.get(&format!("/api/pending/{waiting}")).await.json();
    assert_eq!(row["state"], "allowed");
    assert_eq!(row["decided_by"], "system");
    assert_eq!(row["rule_set"], "system");

    // Withdrawing the consent withdraws the hosts.
    let declined = json!({"decision": "declined", "terms_version": "https://example.test/terms"});
    api.send("PUT", "/api/consents/vscode_server", Some(&declined))
        .await;
    assert_eq!(
        system_hosts(&api.get("/api/rule-sets").await.json()),
        Vec::<(String, String)>::new()
    );
    let audit = api
        .get("/api/audit?type=system_managed_changed")
        .await
        .json();
    assert_eq!(audit["entries"].as_array().unwrap().len(), 3);
    api.running.shutdown().await;
}

#[tokio::test]
async fn built_in_sets_switch_per_workspace_and_stay_read_only() {
    let api = start().await;
    let list = api.get("/api/rule-sets").await.json();
    let github = list["sets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "builtin:github")
        .unwrap()
        .clone();
    assert_eq!(github["kind"], "built_in");
    assert_eq!(github["default_on"], false);
    assert_eq!(github["global"], Value::Null);
    assert_eq!(github["entries"][0]["effect"], "allow");
    assert_eq!(github["entries"][0]["rule_id"], Value::Null);

    let waiting = api.request("box", "api.github.com");
    let reply = api
        .send(
            "PUT",
            "/api/rule-sets/builtin:github/switch",
            Some(&json!({"sandbox": "box", "enabled": true})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let switched = reply.json();
    assert_eq!(switched["closed"], json!([waiting]));
    assert_eq!(
        switched["set"]["overrides"],
        json!([{"sandbox": "box", "enabled": true}])
    );
    assert!(decide(&api, "box", "github.com").is_allow());
    assert!(!decide(&api, "other", "github.com").is_allow());

    for (method, path, body, status) in [
        (
            "PUT",
            "/api/rule-sets/builtin:github",
            Some(json!({"name": "x"})),
            422,
        ),
        ("DELETE", "/api/rule-sets/builtin:github", None, 422),
        (
            "PUT",
            "/api/rule-sets/system/switch",
            Some(json!({"enabled": false})),
            422,
        ),
        (
            "PUT",
            "/api/rule-sets/builtin:nope/switch",
            Some(json!({"enabled": true})),
            404,
        ),
        (
            "PUT",
            "/api/rule-sets/user:99/switch",
            Some(json!({"enabled": true})),
            404,
        ),
        ("DELETE", "/api/rule-sets/user:99", None, 404),
        (
            "PUT",
            "/api/rule-sets/builtin:github/switch",
            Some(json!({"enabled": true, "x": 1})),
            422,
        ),
    ] {
        let reply = api.send(method, path, body.as_ref()).await;
        assert_eq!(reply.status, status, "{method} {path}: {}", reply.body);
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn your_own_sets_take_rules_and_inbox_approvals() {
    let api = start().await;
    let reply = api
        .send(
            "POST",
            "/api/rule-sets",
            Some(&json!({"name": "Client X", "description": "their Azure tenant"})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    let set = reply.json();
    assert_eq!(set["kind"], "user");
    assert_eq!(set["default_on"], true);
    let id = set["id"].as_str().unwrap().to_owned();
    let number: i64 = id.strip_prefix("user:").unwrap().parse().unwrap();
    assert_eq!(
        api.send("POST", "/api/rule-sets", Some(&json!({"name": "client x"})))
            .await
            .status,
        422
    );

    // An entry added as a rule with the set's scope.
    let reply = api
        .send(
            "POST",
            "/api/rules",
            Some(&json!({"scope": {"type": "set", "set": number}, "pattern": "*.azure.com", "effect": "allow"})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    assert_eq!(reply.json()["scope"], json!({"type": "set", "set": number}));
    assert!(matches!(
        decide(&api, "box", "portal.azure.com"),
        Decision::SetAllow { .. }
    ));

    // Approve into the set from the inbox.
    let waiting = api.request("box", "login.microsoftonline.com");
    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{waiting}/approve"),
            Some(&json!({"rule_set": number})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json()["rule"]["scope"]["type"], "set");
    // Not with scope global, and not into a set that is off for the workspace.
    let other = api.request("off", "graph.microsoft.com");
    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{other}/approve"),
            Some(&json!({"rule_set": number, "scope": "global"})),
        )
        .await;
    assert_eq!(reply.status, 422, "{}", reply.body);
    api.send(
        "PUT",
        &format!("/api/rule-sets/{id}/switch"),
        Some(&json!({"sandbox": "off", "enabled": false})),
    )
    .await;
    let reply = api
        .send(
            "POST",
            &format!("/api/pending/{other}/approve"),
            Some(&json!({"rule_set": number})),
        )
        .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("switch it on"), "{}", reply.body);

    // Renamed, listed with its entries, deleted with them.
    let reply = api
        .send(
            "PUT",
            &format!("/api/rule-sets/{id}"),
            Some(&json!({"name": "Client Y"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let set = reply.json();
    assert_eq!(set["name"], "Client Y");
    assert_eq!(set["entries"].as_array().unwrap().len(), 2);
    let reply = api
        .send("DELETE", &format!("/api/rule-sets/{id}"), None)
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let rules = api.get("/api/rules").await.json();
    assert_eq!(rules["rules"], json!([]));
    let kinds: Vec<String> = api.get("/api/audit").await.json()["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["record"]["type"].as_str().unwrap().to_owned())
        .collect();
    for kind in [
        "rule_set_created",
        "rule_set_updated",
        "rule_set_switched",
        "rule_set_deleted",
    ] {
        assert!(kinds.iter().any(|k| k == kind), "{kind} in {kinds:?}");
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn direct_ssh_gives_microsofts_hosts_to_that_workspace_only() {
    let api = start().await;
    for name in ["ssh", "other"] {
        let reply = api
            .send(
                "POST",
                "/api/workspaces",
                Some(&json!({"name": name, "repo_url": "https://github.com/acme/api.git"})),
            )
            .await;
        assert_eq!(reply.status, 202, "{}", reply.body);
    }
    assert!(!decide(&api, "ssh", "marketplace.visualstudio.com").is_allow());
    let reply = api
        .send(
            "PUT",
            "/api/settings/sandboxes/ssh",
            Some(&json!({"overrides": {"direct_ssh": true}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(decide(&api, "ssh", "marketplace.visualstudio.com").is_allow());
    assert!(!decide(&api, "other", "marketplace.visualstudio.com").is_allow());
    let list = api.get("/api/rule-sets").await.json();
    assert!(
        list["system_managed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| { h["reason"] == "direct_ssh" && h["sandbox"] == "ssh" })
    );
    // The global default on: a workspace made afterwards gets them too.
    api.send(
        "PUT",
        "/api/settings",
        Some(&json!({"sandbox_defaults": {"direct_ssh": true}})),
    )
    .await;
    assert!(decide(&api, "other", "marketplace.visualstudio.com").is_allow());
    // Off again for one: gone there.
    api.send(
        "PUT",
        "/api/settings/sandboxes/ssh",
        Some(&json!({"overrides": {"direct_ssh": false}})),
    )
    .await;
    assert!(!decide(&api, "ssh", "marketplace.visualstudio.com").is_allow());
    api.running.shutdown().await;
}
