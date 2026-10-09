// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment variables and secrets over real HTTP, against a real store: a secret's value goes
//! to the credential store and never comes back.

use std::sync::Arc;

use puddle_api::{ApiConfig, ApiServer, ApiToken, EventHub, MemorySettings, Services};
use puddle_secrets::{MemoryStore, SecretStore, StoredId};
use puddle_store::{Limits, ManualClock, Store};
use serde_json::{Value, json};

use crate::common::{Api, START_MS, raw, start};
use crate::events::Stream;

const CANARY: &str = "ghp_CANARY-real-value-0123456789";
const REPO: &str = "https://github.com/acme/api.git";

async fn workspace(api: &Api, name: &str) {
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": name, "repo_url": REPO})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    api.workspaces.idle().await;
}

fn plain(value: &str) -> Value {
    json!({"kind": "plain", "value": value})
}

fn secret(value: Option<&str>, hosts: &[&str]) -> Value {
    match value {
        Some(value) => json!({"kind": "secret", "value": value, "hosts": hosts}),
        None => json!({"kind": "secret", "hosts": hosts}),
    }
}

async fn put(api: &Api, path: &str, body: &Value) -> crate::common::Reply {
    api.send("PUT", path, Some(body)).await
}

fn names(list: &Value) -> Vec<String> {
    list["variables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn variables_are_set_listed_replaced_and_removed_globally_and_per_workspace() {
    let api = start().await;
    workspace(&api, "shop").await;

    let made = put(&api, "/api/env/EDITOR", &plain("vim")).await;
    assert_eq!(made.status, 200, "{}", made.body);
    let made = made.json();
    assert_eq!(made["name"], "EDITOR");
    assert_eq!(made["scope"], "global");
    assert_eq!(made["kind"], "plain");
    assert_eq!(made["value"], "vim");
    assert_eq!(made["hosts"], json!([]));
    assert_eq!(made["overridden"], false);
    assert_eq!(made["changed_at"], START_MS);

    put(&api, "/api/env/LANG_X", &plain("en")).await;
    // Replacing keeps one entry.
    let again = put(&api, "/api/env/EDITOR", &plain("emacs")).await;
    assert_eq!(again.json()["value"], "emacs");
    let global = api.get("/api/env").await.json();
    assert_eq!(names(&global), ["EDITOR", "LANG_X"]);

    // The workspace sees the global ones, and its own hides a global one of the same name.
    let own = put(&api, "/api/workspaces/shop/env/EDITOR", &plain("nano")).await;
    assert_eq!(own.status, 200, "{}", own.body);
    assert_eq!(own.json()["scope"], "workspace");
    let view = api.get("/api/workspaces/shop/env").await.json();
    assert_eq!(view["workspace"], "shop");
    let rows: Vec<(String, String, bool, Value)> = view["variables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            (
                v["name"].as_str().unwrap().to_owned(),
                v["scope"].as_str().unwrap().to_owned(),
                v["overridden"].as_bool().unwrap(),
                v["value"].clone(),
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            ("EDITOR".into(), "workspace".into(), false, json!("nano")),
            ("EDITOR".into(), "global".into(), true, json!("emacs")),
            ("LANG_X".into(), "global".into(), false, json!("en")),
        ]
    );
    // Another workspace does not see it.
    workspace(&api, "other").await;
    let other = api.get("/api/workspaces/other/env").await.json();
    assert_eq!(names(&other), ["EDITOR", "LANG_X"]);
    assert!(
        other["variables"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["scope"] == "global" && v["overridden"] == false)
    );

    // Removing the workspace's own makes the global one apply again; removing twice is a 404.
    let gone = api
        .send("DELETE", "/api/workspaces/shop/env/EDITOR", None)
        .await;
    assert_eq!(gone.status, 204, "{}", gone.body);
    let view = api.get("/api/workspaces/shop/env").await.json();
    assert_eq!(names(&view), ["EDITOR", "LANG_X"]);
    let missing = api
        .send("DELETE", "/api/workspaces/shop/env/EDITOR", None)
        .await;
    assert_eq!(missing.status, 404, "{}", missing.body);
    assert_eq!(missing.error(), "not_found");
    assert_eq!(
        api.send("DELETE", "/api/env/EDITOR", None).await.status,
        204
    );
    assert_eq!(
        api.send("DELETE", "/api/env/EDITOR", None).await.status,
        404
    );
    assert_eq!(names(&api.get("/api/env").await.json()), ["LANG_X"]);
}

#[tokio::test]
async fn a_secret_is_kept_in_the_credential_store_and_its_value_never_comes_back() {
    let api = start().await;
    workspace(&api, "shop").await;
    let mut stream = Stream::open(&api, "").await;

    let made = put(
        &api,
        "/api/workspaces/shop/env/NPM_TOKEN",
        &secret(Some(CANARY), &["registry.npmjs.org", "*.example.com"]),
    )
    .await;
    assert_eq!(made.status, 200, "{}", made.body);
    let made_json = made.json();
    assert_eq!(made_json["kind"], "secret");
    assert_eq!(made_json["value"], Value::Null);
    assert_eq!(
        made_json["hosts"],
        json!(["*.example.com", "registry.npmjs.org"])
    );

    // The value is in the credential store, once, and nowhere the API shows.
    let ids = api.secrets.ids();
    assert_eq!(ids.len(), 1, "{ids:?}");
    let held = api
        .secrets
        .get(&StoredId::new(&ids[0]).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(held.expose(), CANARY);

    let mut everything = made.body.clone();
    for path in [
        "/api/env",
        "/api/workspaces/shop/env",
        "/api/workspaces/shop",
        "/api/workspaces",
    ] {
        everything.push_str(&api.get(path).await.body);
    }
    // The change event names the workspace and carries nothing else.
    stream
        .read_until(|b| b.contains("workspace_env_changed"))
        .await;
    everything.push_str(&stream.buf);
    everything.push_str(&puddle_api::openapi_json());
    assert!(!everything.contains(CANARY), "the value is on the wire");
    assert!(
        !everything.contains(&ids[0]),
        "the credential store's id is on the wire"
    );
    let event = stream
        .data()
        .into_iter()
        .find(|d| d["type"] == "workspace_env_changed")
        .unwrap();
    assert_eq!(
        event,
        json!({"type": "workspace_env_changed", "workspace": "shop"})
    );

    // The stored row has the reference and the hosts, not the value.
    let entries = api
        .store
        .env_entries(&puddle_store::EnvScope::Workspace(
            puddle_types::WorkspaceName::new("shop").unwrap(),
        ))
        .unwrap();
    assert!(!format!("{entries:?}").contains(CANARY));
}

#[tokio::test]
async fn the_value_is_not_in_the_database_file_either() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle.sqlite");
    let clock = Arc::new(ManualClock::new(START_MS));
    let events = Arc::new(EventHub::default());
    let store = Arc::new(
        Store::open(&path, clock.clone(), Limits::default())
            .unwrap()
            .with_events(events.clone()),
    );
    let vault = Arc::new(MemoryStore::new());
    let services = Services::new(
        store.clone(),
        Arc::new(MemorySettings::default()),
        events,
        clock,
    )
    .with_secret_store(vault.clone());
    let token = ApiToken::generate().unwrap();
    let server = ApiServer::bind(ApiConfig::default(), token.clone(), services)
        .await
        .unwrap();
    let addr = server.local_addr();
    let running = server.spawn();

    let body = secret(Some(CANARY), &["api.example.com"]).to_string();
    let request = format!(
        "PUT /api/env/DB_PROBE HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        addr.port(),
        token.expose(),
        body.len()
    );
    let reply = raw(addr, request.as_bytes()).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(vault.ids().len(), 1);
    // Flush the write-ahead log into the main file, then read every file of the database.
    drop(store);
    running.shutdown().await;
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let content = std::fs::read(entry.unwrap().path()).unwrap();
        bytes += content.len();
        assert!(
            !content
                .windows(CANARY.len())
                .any(|w| w == CANARY.as_bytes()),
            "the value is in the database"
        );
    }
    assert!(bytes > 0);
}

#[tokio::test]
async fn a_secret_keeps_its_value_when_only_its_hosts_change_and_a_new_one_needs_a_value() {
    let api = start().await;
    let missing = put(&api, "/api/env/T", &secret(None, &["api.example.com"])).await;
    assert_eq!(missing.status, 422, "{}", missing.body);
    assert!(
        missing.json()["message"]
            .as_str()
            .unwrap()
            .contains("needs its value")
    );
    assert!(api.secrets.ids().is_empty(), "nothing was kept");
    assert_eq!(
        names(&api.get("/api/env").await.json()),
        Vec::<String>::new()
    );

    put(
        &api,
        "/api/env/T",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    let id = api.secrets.ids().remove(0);
    let moved = put(&api, "/api/env/T", &secret(None, &["b.example.com"])).await;
    assert_eq!(moved.status, 200, "{}", moved.body);
    assert_eq!(moved.json()["hosts"], json!(["b.example.com"]));
    assert_eq!(
        api.secrets.ids(),
        std::slice::from_ref(&id),
        "the same entry, not a second"
    );
    let held = api
        .secrets
        .get(&StoredId::new(&id).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(held.expose(), CANARY);

    // A new value replaces it in place.
    put(
        &api,
        "/api/env/T",
        &secret(Some("rotated-value"), &["b.example.com"]),
    )
    .await;
    assert_eq!(api.secrets.ids(), std::slice::from_ref(&id));
    let held = api
        .secrets
        .get(&StoredId::new(&id).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(held.expose(), "rotated-value");
}

#[tokio::test]
async fn removing_a_secret_or_turning_it_into_a_plain_variable_removes_its_value() {
    let api = start().await;
    put(
        &api,
        "/api/env/A",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    put(
        &api,
        "/api/env/B",
        &secret(Some(CANARY), &["b.example.com"]),
    )
    .await;
    assert_eq!(api.secrets.ids().len(), 2);

    assert_eq!(api.send("DELETE", "/api/env/A", None).await.status, 204);
    assert_eq!(api.secrets.ids().len(), 1);
    let plain_now = put(&api, "/api/env/B", &plain("not secret any more")).await;
    assert_eq!(plain_now.status, 200, "{}", plain_now.body);
    assert_eq!(plain_now.json()["value"], "not secret any more");
    assert!(api.secrets.ids().is_empty(), "no value left behind");

    // A plain variable turned into a secret gets a value of its own.
    put(
        &api,
        "/api/env/B",
        &secret(Some(CANARY), &["b.example.com"]),
    )
    .await;
    assert_eq!(api.secrets.ids().len(), 1);
}

#[tokio::test]
async fn a_credential_store_that_fails_changes_nothing_and_says_so() {
    let api = start().await;
    put(
        &api,
        "/api/env/KEPT",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    api.secrets.break_it();

    let refused = put(
        &api,
        "/api/env/NEW",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    assert_eq!(refused.status, 503, "{}", refused.body);
    assert_eq!(refused.error(), "unavailable");
    assert!(
        refused.json()["message"]
            .as_str()
            .unwrap()
            .contains("nothing was changed")
    );
    // Removing a secret needs its value removed first: the variable stays.
    let stuck = api.send("DELETE", "/api/env/KEPT", None).await;
    assert_eq!(stuck.status, 503, "{}", stuck.body);
    assert_eq!(names(&api.get("/api/env").await.json()), ["KEPT"]);
    // Plain variables do not need the credential store.
    assert_eq!(put(&api, "/api/env/PLAIN", &plain("x")).await.status, 200);
    assert_eq!(api.send("DELETE", "/api/env/PLAIN", None).await.status, 204);

    api.secrets.heal();
    assert_eq!(api.send("DELETE", "/api/env/KEPT", None).await.status, 204);
    assert_eq!(api.secrets.ids(), Vec::<String>::new());
}

#[tokio::test]
async fn without_a_credential_store_a_secret_is_refused_and_plain_variables_still_work() {
    let clock = Arc::new(ManualClock::new(START_MS));
    let events = Arc::new(EventHub::default());
    let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
    // `Services::new` has no credential store: a secret would have nowhere to be kept.
    let services = Services::new(store, Arc::new(MemorySettings::default()), events, clock);
    let token = ApiToken::generate().unwrap();
    let server = ApiServer::bind(ApiConfig::default(), token.clone(), services)
        .await
        .unwrap();
    let addr = server.local_addr();
    let running = server.spawn();
    let send = |body: Value| {
        let body = body.to_string();
        let request = format!(
            "PUT /api/env/T HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            addr.port(),
            token.expose(),
            body.len()
        );
        async move { raw(addr, request.as_bytes()).await }
    };
    assert_eq!(
        send(secret(Some(CANARY), &["a.example.com"])).await.status,
        503
    );
    assert_eq!(send(plain("x")).await.status, 200);
    running.shutdown().await;
}

#[expect(
    clippy::too_many_lines,
    reason = "one table of refusals, read top to bottom"
)]
#[tokio::test]
async fn what_is_refused_says_why_and_never_quotes_a_secret() {
    let api = start().await;
    workspace(&api, "shop").await;
    let refused = |reply: &crate::common::Reply| {
        assert_eq!(reply.status, 422, "{}", reply.body);
        assert_eq!(reply.error(), "invalid");
        reply.json()["message"].as_str().unwrap().to_owned()
    };

    // Names puddle owns, and names that are not names.
    for (name, says) in [
        ("PATH", "image"),
        ("PUDDLE_ROOT", "PUDDLE_"),
        ("HTTPS_PROXY", "proxy"),
        ("NODE_EXTRA_CA_CERTS", "certificate"),
        ("1BAD", "not a variable name"),
        ("A-B", "not a variable name"),
    ] {
        let reply = put(&api, &format!("/api/env/{name}"), &plain("x")).await;
        let message = refused(&reply);
        assert!(message.contains(says), "{name}: {message}");
    }
    // Names puddle adds to are the user's.
    for name in [
        "JAVA_TOOL_OPTIONS",
        "MAVEN_ARGS",
        "GRADLE_USER_HOME",
        "DOCKER_CONFIG",
    ] {
        assert_eq!(
            put(&api, &format!("/api/env/{name}"), &plain("-Xmx1g"))
                .await
                .status,
            200
        );
    }

    // Hosts.
    for (hosts, says) in [
        (vec![], "at least one host"),
        (vec!["*.github.io"], "anyone can register"),
        (vec!["10.0.0.1"], "host name"),
        (vec!["api.example.com:8443"], "port 443"),
        (vec!["https://api.example.com"], "not a host name"),
        (vec!["*.com"], "anyone can register"),
    ] {
        let reply = put(&api, "/api/env/T", &secret(Some(CANARY), &hosts)).await;
        let message = refused(&reply);
        assert!(message.contains(says), "{hosts:?}: {message}");
        assert!(!message.contains(CANARY));
    }
    assert!(
        api.secrets.ids().is_empty(),
        "a refused secret leaves no value behind"
    );

    // Values.
    let long = "x".repeat(9000);
    for (value, says) in [
        (Value::from(""), "can't be empty"),
        (Value::from(long.as_str()), "at most"),
        (Value::from("CANARY-line1\nline2"), "control character"),
        (Value::from(12_345_678), "must be a string"),
        (Value::from(true), "must be a string"),
        (Value::Null, "needs its value"),
        (json!(["CANARY-in-a-list"]), "must be a string"),
    ] {
        let body = json!({"kind": "secret", "value": value, "hosts": ["api.example.com"]});
        let reply = put(&api, "/api/env/T", &body).await;
        let message = refused(&reply);
        assert!(message.contains(says), "{message}");
        assert!(
            !reply.body.contains("CANARY") && !reply.body.contains("12345678"),
            "{}",
            reply.body
        );
    }
    let nul = put(&api, "/api/env/T", &plain("a\u{0}b")).await;
    assert!(refused(&nul).contains("NUL"));
    let too_big = put(&api, "/api/env/T", &plain(&"x".repeat(49 * 1024))).await;
    assert!(refused(&too_big).contains("at most"));
    assert_eq!(
        names(&api.get("/api/env").await.json()).len(),
        4,
        "only the four valid ones"
    );

    // Unknown workspace, unknown kind, unknown field.
    assert_eq!(
        put(&api, "/api/workspaces/nope/env/A", &plain("x"))
            .await
            .status,
        404
    );
    assert_eq!(api.get("/api/workspaces/nope/env").await.status, 404);
    assert_eq!(
        api.send("DELETE", "/api/workspaces/nope/env/A", None)
            .await
            .status,
        404
    );
    assert_eq!(
        put(&api, "/api/env/A", &json!({"kind": "other"}))
            .await
            .status,
        422
    );
    assert_eq!(
        put(
            &api,
            "/api/env/A",
            &json!({"kind": "plain", "value": "x", "extra": 1})
        )
        .await
        .status,
        422
    );
    assert_eq!(put(&api, "/api/env/A", &json!(["x"])).await.status, 422);
    // A malformed body that carries a secret does not quote it back.
    for body in [
        json!({"kind": "secret", "value": CANARY, "hosts": ["a.example.com"], "extra": 1}),
        json!({"kind": "secret", "value": CANARY}),
        json!({"kind": "secret", "value": CANARY, "hosts": "a.example.com"}),
        json!({"kind": "secret", "value": CANARY, "hosts": [CANARY]}),
    ] {
        let reply = put(&api, "/api/env/A", &body).await;
        assert_eq!(reply.status, 422, "{}", reply.body);
        assert!(
            !reply.body.contains("CANARY") || body["hosts"] == json!([CANARY]),
            "{}",
            reply.body
        );
    }
}

#[tokio::test]
async fn a_scope_holds_at_most_256_variables() {
    let api = start().await;
    for i in 0..256 {
        let reply = put(&api, &format!("/api/env/V{i}"), &plain("x")).await;
        assert_eq!(reply.status, 200, "{i}: {}", reply.body);
    }
    let over = put(&api, "/api/env/ONE_MORE", &plain("x")).await;
    assert_eq!(over.status, 422);
    assert!(
        over.json()["message"]
            .as_str()
            .unwrap()
            .contains("256 variables")
    );
    assert_eq!(put(&api, "/api/env/V0", &plain("y")).await.status, 200);

    // A new secret in a full scope is refused, and the value it wrote is taken back.
    let secret_over = put(
        &api,
        "/api/env/A_SECRET",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    assert_eq!(secret_over.status, 422, "{}", secret_over.body);
    assert_eq!(
        api.secrets.ids(),
        Vec::<String>::new(),
        "no value left behind"
    );
}

#[tokio::test]
async fn a_secret_made_plain_removes_its_value_first_and_is_refused_while_the_credential_store_is_down()
 {
    let api = start().await;
    put(
        &api,
        "/api/env/T",
        &secret(Some(CANARY), &["a.example.com"]),
    )
    .await;
    api.secrets.break_it();
    let refused = put(&api, "/api/env/T", &plain("open")).await;
    assert_eq!(refused.status, 503, "{}", refused.body);
    // Nothing changed: it is still a secret, and its value is still where it was.
    let listed = api.get("/api/env").await.json();
    assert_eq!(listed["variables"][0]["kind"], "secret");
    api.secrets.heal();
    assert_eq!(api.secrets.ids().len(), 1);
    // With the store back the change goes through and the value is gone.
    let now_plain = put(&api, "/api/env/T", &plain("open")).await;
    assert_eq!(now_plain.status, 200, "{}", now_plain.body);
    assert_eq!(api.secrets.ids(), Vec::<String>::new());
}

#[tokio::test]
async fn changes_reach_the_event_stream_as_names_only() {
    let api = start().await;
    workspace(&api, "shop").await;
    let mut stream = Stream::open(&api, "").await;
    put(&api, "/api/env/G", &plain("1")).await;
    put(&api, "/api/workspaces/shop/env/W", &plain("2")).await;
    api.send("DELETE", "/api/env/G", None).await;
    stream
        .read_until(|b| {
            b.matches("global_env_changed").count() >= 2 && b.contains("workspace_env_changed")
        })
        .await;
    let kinds: Vec<String> = stream
        .data()
        .iter()
        .map(|d| d["type"].as_str().unwrap().to_owned())
        .filter(|k| k.ends_with("env_changed"))
        .collect();
    assert_eq!(
        kinds,
        [
            "global_env_changed",
            "workspace_env_changed",
            "global_env_changed"
        ]
    );
    // A stream filtered to one workspace gets its own change and not another's.
    let mut shop = Stream::open(&api, "?workspace=shop").await;
    workspace(&api, "other").await;
    put(&api, "/api/workspaces/other/env/W", &plain("3")).await;
    put(&api, "/api/workspaces/shop/env/SECOND", &plain("4")).await;
    shop.read_until(|b| b.contains("workspace_env_changed"))
        .await;
    let seen: Vec<Value> = shop
        .data()
        .into_iter()
        .filter(|d| d["type"] == "workspace_env_changed")
        .collect();
    assert_eq!(
        seen,
        [json!({"type": "workspace_env_changed", "workspace": "shop"})]
    );
}

#[tokio::test]
async fn the_published_contract_marks_the_secret_value_write_only_and_lists_the_routes() {
    let spec: Value = serde_json::from_str(&puddle_api::openapi_json()).unwrap();
    for (path, methods) in [
        ("/api/env", vec!["get"]),
        ("/api/env/{name}", vec!["put", "delete"]),
        ("/api/workspaces/{id}/env", vec!["get"]),
        ("/api/workspaces/{id}/env/{name}", vec!["put", "delete"]),
    ] {
        for method in methods {
            assert!(spec["paths"][path][method].is_object(), "{method} {path}");
        }
    }
    let request = spec["components"]["schemas"]["EnvSetRequest"].to_string();
    assert!(request.contains("writeOnly"), "{request}");
    assert!(request.contains("password"), "{request}");
    let view = spec["components"]["schemas"]["EnvVariable"].to_string();
    assert!(!view.contains("password"), "{view}");
}
