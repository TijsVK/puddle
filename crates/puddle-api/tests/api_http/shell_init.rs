// SPDX-License-Identifier: GPL-3.0-or-later
//! A workspace's shell init over real HTTP, against a real store.

use puddle_api::ShellInitCheck;
use serde_json::{Value, json};

use crate::common::{Api, start};
use crate::events::Stream;

const REPO: &str = "https://github.com/acme/api.git";

/// A workspace that exists and is stopped.
async fn stopped(api: &Api, name: &str) {
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": name, "repositories": [{"url": REPO}]})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    api.workspaces.idle().await;
}

/// A workspace that is running.
async fn workspace(api: &Api, name: &str) {
    stopped(api, name).await;
    let reply = api
        .send("POST", &format!("/api/workspaces/{name}/start"), None)
        .await;
    assert!(reply.status == 202 || reply.status == 200, "{}", reply.body);
    api.workspaces.idle().await;
}

async fn save(api: &Api, name: &str, content: &str) -> crate::common::Reply {
    api.send(
        "PUT",
        &format!("/api/workspaces/{name}/shell-init"),
        Some(&json!({ "content": content })),
    )
    .await
}

#[tokio::test]
async fn a_shell_init_is_saved_read_back_replaced_and_removed() {
    let api = start().await;
    workspace(&api, "shop").await;
    let empty = api
        .send("GET", "/api/workspaces/shop/shell-init", None)
        .await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert_eq!(
        empty.json(),
        json!({"workspace": "shop", "content": "", "saved": false, "changed_at": null})
    );

    let saved = save(&api, "shop", "export EDITOR=vim\r\nalias ll='ls -l'").await;
    assert_eq!(saved.status, 200, "{}", saved.body);
    let body: Value = saved.json();
    assert_eq!(body["checked"], true);
    assert_eq!(body["unchecked_reason"], Value::Null);
    // Line ends are LF and the text ends in a newline, so what the guest sources is what was saved.
    assert_eq!(
        body["shell_init"]["content"],
        "export EDITOR=vim\nalias ll='ls -l'\n"
    );
    assert_eq!(body["shell_init"]["saved"], true);
    let read = api
        .send("GET", "/api/workspaces/shop/shell-init", None)
        .await;
    assert_eq!(read.json()["content"], body["shell_init"]["content"]);
    assert_eq!(read.json()["changed_at"], body["shell_init"]["changed_at"]);

    assert_eq!(save(&api, "shop", "export A=1").await.status, 200);
    assert_eq!(
        api.send("GET", "/api/workspaces/shop/shell-init", None)
            .await
            .json()["content"],
        "export A=1\n"
    );
    assert_eq!(
        api.send("DELETE", "/api/workspaces/shop/shell-init", None)
            .await
            .status,
        204
    );
    assert_eq!(
        api.send("GET", "/api/workspaces/shop/shell-init", None)
            .await
            .json()["saved"],
        false
    );
    let again = api
        .send("DELETE", "/api/workspaces/shop/shell-init", None)
        .await;
    assert_eq!(again.status, 404, "{}", again.body);
}

#[tokio::test]
async fn a_shell_init_belongs_to_its_workspace_and_an_unknown_one_is_404() {
    let api = start().await;
    workspace(&api, "shop").await;
    workspace(&api, "blog").await;
    save(&api, "shop", "export A=1").await;
    assert_eq!(
        api.send("GET", "/api/workspaces/blog/shell-init", None)
            .await
            .json()["saved"],
        false
    );
    for method in ["GET", "DELETE"] {
        let reply = api
            .send(method, "/api/workspaces/nobody/shell-init", None)
            .await;
        assert_eq!(reply.status, 404, "{method}: {}", reply.body);
    }
    assert_eq!(save(&api, "nobody", "x").await.status, 404);
}

#[tokio::test]
async fn text_that_is_empty_has_a_nul_or_is_too_long_is_refused_and_says_why() {
    let api = start().await;
    workspace(&api, "shop").await;
    for (content, why) in [
        ("", "empty"),
        ("   \n", "empty"),
        ("a\u{0}b", "NUL"),
        (&"x".repeat(48 * 1024), "at most 48 KiB"),
    ] {
        let reply = save(&api, "shop", content).await;
        assert_eq!(reply.status, 422, "{why}: {}", reply.body);
        assert!(reply.body.contains(why), "{why}: {}", reply.body);
    }
    // Nothing was saved, and none of it was run.
    assert_eq!(
        api.send("GET", "/api/workspaces/shop/shell-init", None)
            .await
            .json()["saved"],
        false
    );
    assert_eq!(api.workspaces.shell_init_checked(), Vec::<String>::new());
    // The body must be an object with the one field.
    let reply = api
        .send("PUT", "/api/workspaces/shop/shell-init", Some(&json!({})))
        .await;
    assert_eq!(reply.status, 422, "{}", reply.body);
}

#[tokio::test]
async fn a_script_the_check_refuses_is_not_saved_and_the_reply_says_what_was_seen() {
    let api = start().await;
    workspace(&api, "shop").await;
    api.workspaces.set_shell_init_check(ShellInitCheck::Refused(
        "the shell init prints output. It printed: hello".to_owned(),
    ));
    let reply = save(&api, "shop", "echo hello").await;
    assert_eq!(reply.status, 422, "{}", reply.body);
    assert!(reply.body.contains("It printed: hello"), "{}", reply.body);
    assert_eq!(api.workspaces.shell_init_checked(), ["echo hello\n"]);
    assert_eq!(
        api.send("GET", "/api/workspaces/shop/shell-init", None)
            .await
            .json()["saved"],
        false,
        "a refused script is not saved"
    );
}

#[tokio::test]
async fn a_stopped_workspace_takes_the_save_unchecked_and_says_why() {
    let api = start().await;
    stopped(&api, "shop").await;
    api.workspaces
        .set_shell_init_check(ShellInitCheck::Refused("never asked".to_owned()));
    let reply = save(&api, "shop", "echo hello").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json()["checked"], false);
    assert!(
        reply.json()["unchecked_reason"]
            .as_str()
            .unwrap()
            .contains("not running"),
        "{}",
        reply.body
    );
    assert_eq!(api.workspaces.shell_init_checked(), Vec::<String>::new());
}

#[tokio::test]
async fn a_save_and_a_removal_reach_the_event_stream_and_an_unchanged_save_does_not() {
    let api = start().await;
    workspace(&api, "shop").await;
    let mut stream = Stream::open(&api, "").await;
    save(&api, "shop", "export A=1").await;
    save(&api, "shop", "export A=1").await;
    save(&api, "shop", "export A=2").await;
    api.send("DELETE", "/api/workspaces/shop/shell-init", None)
        .await;
    stream
        .read_until(|b| b.matches("workspace_shell_init_changed").count() >= 3)
        .await;
    let seen: Vec<Value> = stream
        .data()
        .into_iter()
        .filter(|d| d["type"] == "workspace_shell_init_changed")
        .collect();
    assert_eq!(
        seen,
        vec![json!({"type": "workspace_shell_init_changed", "workspace": "shop"}); 3]
    );
}

#[tokio::test]
async fn the_published_contract_lists_the_routes_and_the_event() {
    let spec: Value = serde_json::from_str(&puddle_api::openapi_json()).unwrap();
    for method in ["get", "put", "delete"] {
        assert!(
            spec["paths"]["/api/workspaces/{id}/shell-init"][method].is_object(),
            "{method}"
        );
    }
    assert!(spec.to_string().contains("workspace_shell_init_restored"));
}
