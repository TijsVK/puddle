// SPDX-License-Identifier: GPL-3.0-or-later
//! Identities and a workspace's Git settings over real HTTP, against a real store.

use serde_json::{Value, json};

use crate::common::{Api, start};
use crate::events::Stream;

const REPO: &str = "https://github.com/acme/api.git";

fn body(label: &str, owners: &[&str], rest: bool) -> Value {
    json!({
        "label": label,
        "author": {"name": label, "email": format!("{}@example.com", label.to_lowercase())},
        "credentials": [{
            "host": "github.com",
            "source": {"kind": "gh", "host": "github.com", "account": "me"},
            "covers": {"owners": owners, "rest_of_host": rest}
        }]
    })
}

async fn make(api: &Api, label: &str, owners: &[&str], rest: bool) -> i64 {
    let reply = api
        .send("POST", "/api/identities", Some(&body(label, owners, rest)))
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    reply.json()["id"].as_i64().unwrap()
}

async fn workspace(api: &Api, name: &str) -> Value {
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": name, "repo_url": REPO})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    api.workspaces.idle().await;
    reply.json()
}

#[tokio::test]
async fn identities_are_made_listed_changed_ordered_and_deleted() {
    let api = start().await;
    let work = make(&api, "Work", &["acme", "Acme-Labs"], false).await;
    let personal = make(&api, "Personal", &[], true).await;

    let list = api.get("/api/identities").await.json();
    let labels: Vec<_> = list["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["label"].as_str().unwrap(),
                i["is_default"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(labels, [("Work", true), ("Personal", false)]);
    // Owners come back lower-case; the source is a reference.
    let first = &list["identities"][0];
    assert_eq!(
        first["credentials"][0]["covers"]["owners"],
        json!(["acme", "acme-labs"])
    );
    assert_eq!(first["credentials"][0]["source"]["kind"], "gh");
    assert_eq!(first["signing"], "none");

    let dup = api
        .send(
            "POST",
            "/api/identities",
            Some(&body("work", &["x"], false)),
        )
        .await;
    assert_eq!((dup.status, dup.error().as_str()), (409, "conflict"));

    let reply = api
        .send("PUT", &format!("/api/identities/{personal}/default"), None)
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["is_default"], true);
    let reply = api
        .send(
            "PUT",
            "/api/identities/order",
            Some(&json!({"ids": [personal, work]})),
        )
        .await;
    assert_eq!(reply.json()["identities"][0]["id"], personal);
    let bad = api
        .send(
            "PUT",
            "/api/identities/order",
            Some(&json!({"ids": [personal]})),
        )
        .await;
    assert_eq!(bad.status, 422);

    let renamed = api
        .send(
            "PUT",
            &format!("/api/identities/{work}"),
            Some(&body("Job", &["acme"], false)),
        )
        .await;
    assert_eq!(renamed.json()["label"], "Job");
    assert_eq!(
        api.get(&format!("/api/identities/{work}")).await.json()["label"],
        "Job"
    );

    let gone = api
        .send("DELETE", &format!("/api/identities/{work}"), None)
        .await;
    assert_eq!(gone.json()["detached_from"], json!([]));
    assert_eq!(
        api.get(&format!("/api/identities/{work}")).await.status,
        404
    );
    assert_eq!(
        api.send("DELETE", &format!("/api/identities/{work}"), None)
            .await
            .status,
        404
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_git_credential_source_comes_back_as_sent() {
    let api = start().await;
    let mut request = body("Azure", &["contoso"], false);
    request["credentials"][0]["host"] = json!("dev.azure.com");
    request["credentials"][0]["source"] = json!({
        "kind": "git_credential",
        "host": "dev.azure.com",
        "path": "contoso",
        "username": "me"
    });
    let made = api.send("POST", "/api/identities", Some(&request)).await;
    assert_eq!(made.status, 201, "{}", made.body);
    let source = &made.json()["credentials"][0]["source"];
    assert_eq!(source["kind"], "git_credential");
    assert_eq!(
        (source["path"].clone(), source["username"].clone()),
        (json!("contoso"), json!("me"))
    );
    // The optional field is `null`, never left out, when it was not sent.
    request["credentials"][0]["source"]["username"] = Value::Null;
    request["label"] = json!("Azure two");
    request["credentials"][0]["covers"] = json!({"owners": ["fabrikam"], "rest_of_host": false});
    let again = api
        .send("POST", "/api/identities", Some(&request))
        .await
        .json();
    assert_eq!(again["credentials"][0]["source"]["username"], Value::Null);
    api.running.shutdown().await;
}

#[tokio::test]
async fn bad_input_is_refused_and_no_command_source_exists() {
    let api = start().await;
    let mut cases = vec![
        body("", &["acme"], false),
        body("x", &[], false),
        body("x", &["a b"], false),
    ];
    let mut mismatch = body("x", &["acme"], false);
    mismatch["credentials"][0]["host"] = json!("gitlab.com");
    cases.push(mismatch);
    let mut email = body("x", &["acme"], false);
    email["author"]["email"] = json!("nobody");
    cases.push(email);
    let mut command = body("x", &["acme"], false);
    command["credentials"][0]["source"] = json!({"kind": "command", "command": "curl evil"});
    cases.push(command);
    let mut option = body("x", &["acme"], false);
    option["credentials"][0]["source"]["account"] = json!("-x");
    cases.push(option);
    for case in cases {
        let reply = api.send("POST", "/api/identities", Some(&case)).await;
        assert_eq!(reply.status, 422, "{case} -> {}", reply.body);
    }
    // A token for one organisation covers only that organisation.
    let mut stored = body("x", &[], true);
    stored["credentials"][0]["host"] = json!("dev.azure.com");
    stored["credentials"][0]["source"] =
        json!({"kind": "stored", "id": "t1", "host": "dev.azure.com", "org": "contoso"});
    assert_eq!(
        api.send("POST", "/api/identities", Some(&stored))
            .await
            .status,
        422
    );
    stored["credentials"][0]["covers"] = json!({"owners": ["contoso"], "rest_of_host": false});
    assert_eq!(
        api.send("POST", "/api/identities", Some(&stored))
            .await
            .status,
        201
    );
    assert_eq!(
        api.get("/api/identities").await.json()["identities"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    api.running.shutdown().await;
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
async fn attaching_colliding_identities_is_a_409_naming_both() {
    let api = start().await;
    workspace(&api, "shop").await;
    let work = make(&api, "Work", &["acme"], false).await;
    let clash = make(&api, "Clash", &["ACME"], false).await;
    let rest = make(&api, "Personal", &[], true).await;

    let attach = |id: i64| json!({"identity": id});
    let ok = api
        .send(
            "POST",
            "/api/workspaces/shop/identities",
            Some(&attach(work)),
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    let refused = api
        .send(
            "POST",
            "/api/workspaces/shop/identities",
            Some(&attach(clash)),
        )
        .await;
    assert_eq!(
        (refused.status, refused.error().as_str()),
        (409, "identity_collision")
    );
    let message = refused.json()["message"].as_str().unwrap().to_owned();
    assert_eq!(
        message,
        "Work and Clash both cover github.com/acme; narrow one"
    );
    // The exact owner and the rest of the host live together, rest first by position.
    let both = api
        .send(
            "POST",
            "/api/workspaces/shop/identities",
            Some(&json!({"identity": rest, "position": 0})),
        )
        .await
        .json();
    let ids: Vec<_> = both["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [rest, work]);
    assert_eq!(both["identities"][1]["workspaces"], json!(["shop"]));
    assert_eq!(
        api.send(
            "POST",
            "/api/workspaces/shop/identities",
            Some(&attach(rest))
        )
        .await
        .status,
        409
    );
    // A list without a clash replaces the old one; the clash list is refused below.
    let swapped = api
        .send(
            "PUT",
            "/api/workspaces/shop/identities",
            Some(&json!({"ids": [work, rest]})),
        )
        .await;
    assert_eq!(swapped.status, 200, "{}", swapped.body);
    assert_eq!(swapped.json()["identities"][0]["id"], work);
    // Replacing the list is checked as a whole.
    let put = api
        .send(
            "PUT",
            "/api/workspaces/shop/identities",
            Some(&json!({"ids": [work, clash]})),
        )
        .await;
    assert_eq!(put.error(), "identity_collision");
    assert_eq!(
        api.get("/api/workspaces/shop/git").await.json()["identities"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // Widening an identity into a collision on a workspace that has both is refused too; one that
    // is on no workspace can say anything.
    let widen = api
        .send(
            "PUT",
            &format!("/api/identities/{rest}"),
            Some(&body("Personal", &["acme"], true)),
        )
        .await;
    assert_eq!(
        (widen.status, widen.error().as_str()),
        (409, "identity_collision")
    );
    let free = api
        .send(
            "PUT",
            &format!("/api/identities/{clash}"),
            Some(&body("Clash", &["acme", "x"], false)),
        )
        .await;
    assert_eq!(free.status, 200);
    // Unknown things are 404.
    assert_eq!(
        api.send(
            "POST",
            "/api/workspaces/none/identities",
            Some(&attach(work))
        )
        .await
        .status,
        404
    );
    assert_eq!(
        api.send(
            "POST",
            "/api/workspaces/shop/identities",
            Some(&attach(999))
        )
        .await
        .status,
        404
    );
    let off = api
        .send(
            "DELETE",
            &format!("/api/workspaces/shop/identities/{rest}"),
            None,
        )
        .await;
    assert_eq!(off.json()["identities"].as_array().unwrap().len(), 1);
    assert_eq!(
        api.send(
            "DELETE",
            &format!("/api/workspaces/shop/identities/{rest}"),
            None
        )
        .await
        .status,
        404
    );
    api.running.shutdown().await;
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one story, read top to bottom")]
async fn a_workspaces_repository_table_and_switches() {
    let api = start().await;
    workspace(&api, "shop").await;
    let fresh = api.get("/api/workspaces/shop/git").await.json();
    assert_eq!(fresh["only_push_listed"], true);
    assert_eq!(fresh["only_pull_listed"], false);
    // A new workspace starts with its own repository, Pull and Push on.
    assert_eq!(fresh["repos"].as_array().unwrap().len(), 1);
    assert_eq!(fresh["repos"][0]["repo"], "api");

    let add = json!({"host": "GitHub.com", "owner": "Acme", "repo": "Docs.git", "pull": true, "push": true});
    let row = api
        .send("POST", "/api/workspaces/shop/git/repos", Some(&add))
        .await;
    assert_eq!(row.status, 201, "{}", row.body);
    let row = row.json();
    assert_eq!(
        (
            row["host"].as_str(),
            row["owner"].as_str(),
            row["repo"].as_str()
        ),
        (Some("github.com"), Some("acme"), Some("docs"))
    );
    assert_eq!(
        api.send("POST", "/api/workspaces/shop/git/repos", Some(&add))
            .await
            .status,
        409
    );
    let odd =
        json!({"host": "github.com", "owner": "acme", "repo": "../x", "pull": true, "push": true});
    assert_eq!(
        api.send("POST", "/api/workspaces/shop/git/repos", Some(&odd))
            .await
            .status,
        422
    );

    let id = row["id"].as_i64().unwrap();
    let toggled = api
        .send(
            "PUT",
            &format!("/api/workspaces/shop/git/repos/{id}"),
            Some(&json!({"pull": false, "push": true})),
        )
        .await;
    assert_eq!(
        (
            toggled.json()["pull"].clone(),
            toggled.json()["push"].clone()
        ),
        (json!(false), json!(true))
    );
    let switched = api
        .send(
            "PUT",
            "/api/workspaces/shop/git/switches",
            Some(&json!({"only_pull_listed": true})),
        )
        .await
        .json();
    assert_eq!(
        (
            switched["only_push_listed"].clone(),
            switched["only_pull_listed"].clone()
        ),
        (json!(true), json!(true))
    );
    let off = api
        .send(
            "PUT",
            "/api/workspaces/shop/git/switches",
            Some(&json!({"only_push_listed": false})),
        )
        .await
        .json();
    assert_eq!(
        (
            off["only_push_listed"].clone(),
            off["only_pull_listed"].clone()
        ),
        (json!(false), json!(true))
    );

    assert_eq!(
        api.send(
            "DELETE",
            &format!("/api/workspaces/shop/git/repos/{id}"),
            None
        )
        .await
        .status,
        204
    );
    assert_eq!(
        api.send(
            "DELETE",
            &format!("/api/workspaces/shop/git/repos/{id}"),
            None
        )
        .await
        .status,
        404
    );
    assert_eq!(api.get("/api/workspaces/other/git").await.status, 404);
    api.running.shutdown().await;
}

#[tokio::test]
async fn changes_reach_the_event_stream_and_no_secret_is_on_the_wire() {
    let api = start().await;
    workspace(&api, "shop").await;
    let mut stream = Stream::open(&api, "").await;
    let work = make(&api, "Work", &["acme"], false).await;
    api.send(
        "POST",
        "/api/workspaces/shop/identities",
        Some(&json!({"identity": work})),
    )
    .await;
    stream
        .read_until(|b| b.contains("workspace_git_changed"))
        .await;
    let kinds: Vec<_> = stream
        .data()
        .iter()
        .map(|d| d["type"].as_str().unwrap().to_owned())
        .collect();
    assert!(kinds.iter().any(|k| k == "identities_changed"), "{kinds:?}");
    let git = stream
        .data()
        .into_iter()
        .find(|d| d["type"] == "workspace_git_changed")
        .unwrap();
    assert_eq!(git["workspace"], "shop");

    let all = api.get("/api/identities").await.body;
    let spec =
        api.get("/api/identities").await.body + &api.get("/api/workspaces/shop/git").await.body;
    for text in [&all, &spec] {
        for word in ["token", "password", "secret"] {
            assert!(!text.to_lowercase().contains(word), "{word} in {text}");
        }
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_new_workspace_gets_the_identity_that_covers_its_repository_and_lists_it() {
    let api = start().await;
    let _personal = make(&api, "Personal", &[], true).await;
    let work = make(&api, "Work", &["acme"], false).await;
    workspace(&api, "shop").await;

    let git = api.get("/api/workspaces/shop/git").await.json();
    let attached: Vec<_> = git["identities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(attached, [work]);
    assert_eq!(git["repos"].as_array().unwrap().len(), 1);
    let row = &git["repos"][0];
    assert_eq!(
        (&row["host"], &row["owner"], &row["repo"]),
        (&json!("github.com"), &json!("acme"), &json!("api"))
    );
    assert_eq!((&row["pull"], &row["push"]), (&json!(true), &json!(true)));
    assert_eq!(git["only_push_listed"], true);
    assert_eq!(git["only_pull_listed"], false);
}

#[tokio::test]
async fn a_repository_address_puddle_cannot_read_still_makes_the_workspace_with_empty_git_settings()
{
    let api = start().await;
    let _work = make(&api, "Work", &["acme"], false).await;
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": "odd", "repo_url": "https://example.com/a/b/c"})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    api.workspaces.idle().await;
    let git = api.get("/api/workspaces/odd/git").await.json();
    assert_eq!(git["identities"], json!([]));
    assert_eq!(git["repos"], json!([]));
}

#[tokio::test]
async fn creating_a_workspace_says_which_identity_it_got_and_warns_only_when_none_covers_it() {
    let api = start().await;
    // Nobody: no identity, and the answer says so.
    let none = workspace(&api, "alone").await;
    assert_eq!(none["identity"]["basis"], "none");
    assert_eq!(none["identity"]["identity"], Value::Null);
    assert!(
        none["identity"]["warning"]
            .as_str()
            .unwrap()
            .contains("no default identity")
    );

    // The default covers a different owner: it is attached, with a warning naming it and the place.
    let _gitlab = make(&api, "Personal", &["me"], false).await;
    let default = workspace(&api, "fallback").await;
    assert_eq!(default["identity"]["basis"], "default");
    assert_eq!(default["identity"]["identity"], "Personal");
    let warning = default["identity"]["warning"].as_str().unwrap();
    assert!(
        warning.contains("Personal") && warning.contains("github.com/acme"),
        "{warning}"
    );
    let git = api.get("/api/workspaces/fallback/git").await.json();
    assert_eq!(git["identities"][0]["label"], "Personal");

    // One that covers acme wins and there is nothing to warn about; a plain read has no field.
    let _work = make(&api, "Work", &["acme"], false).await;
    let covered = workspace(&api, "covered").await;
    assert_eq!(covered["identity"]["basis"], "covers");
    assert_eq!(covered["identity"]["identity"], "Work");
    assert_eq!(covered["identity"]["warning"], Value::Null);
    let read = api.get("/api/workspaces/covered").await.json();
    assert_eq!(
        read["identity"],
        Value::Null,
        "only creating answers with it"
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_default_switches_are_read_changed_inherited_and_overridden_per_workspace() {
    let api = start().await;
    let defaults = api.get("/api/identities/git-defaults").await.json();
    assert_eq!(
        defaults,
        json!({"only_push_listed": true, "only_pull_listed": false})
    );

    workspace(&api, "before").await;
    let changed = api
        .send(
            "PUT",
            "/api/identities/git-defaults",
            Some(&json!({"only_pull_listed": true})),
        )
        .await;
    assert_eq!(changed.status, 200, "{}", changed.body);
    assert_eq!(
        changed.json(),
        json!({"only_push_listed": true, "only_pull_listed": true})
    );

    // An existing workspace that set nothing follows; a new one starts on it.
    workspace(&api, "after").await;
    for name in ["before", "after"] {
        let git = api.get(&format!("/api/workspaces/{name}/git")).await.json();
        assert_eq!(git["only_pull_listed"], true, "{name}");
        assert_eq!(git["only_push_listed"], true, "{name}");
    }

    // The workspace's own switch wins over later changes of the default.
    let own = api
        .send(
            "PUT",
            "/api/workspaces/after/git/switches",
            Some(&json!({"only_pull_listed": false})),
        )
        .await;
    assert_eq!(own.status, 200, "{}", own.body);
    api.send(
        "PUT",
        "/api/identities/git-defaults",
        Some(&json!({"only_push_listed": false, "only_pull_listed": true})),
    )
    .await;
    let after = api.get("/api/workspaces/after/git").await.json();
    assert_eq!(
        (&after["only_push_listed"], &after["only_pull_listed"]),
        (&json!(false), &json!(false)),
        "push follows the default, pull is the workspace's own"
    );
    let before = api.get("/api/workspaces/before/git").await.json();
    assert_eq!(before["only_pull_listed"], true);

    // A body that is not the two booleans is refused.
    let bad = api
        .send(
            "PUT",
            "/api/identities/git-defaults",
            Some(&json!({"only_push_listed": "yes"})),
        )
        .await;
    assert_eq!(bad.status, 422, "{}", bad.body);
    api.running.shutdown().await;
}
