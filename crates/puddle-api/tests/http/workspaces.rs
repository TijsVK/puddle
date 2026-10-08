// SPDX-License-Identifier: GPL-3.0-or-later
//! The workspaces resource over real HTTP, against `FakeWorkspaces`.

use puddle_api::{Listing, Operation, RepoFindings, Unsaved, WorkspaceRecord};
use puddle_types::{WorkspaceId, WorkspaceName, WorkspaceStatus};
use serde_json::{Value, json};

use crate::common::{Api, START_MS, start, start_without_workspaces};
use crate::events::Stream;

const REPO: &str = "https://github.com/acme/api.git";

async fn create(api: &Api, name: &str) -> Value {
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": name, "repo_url": REPO})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    reply.json()
}

async fn post(api: &Api, path: &str) -> crate::common::Reply {
    api.send("POST", path, Some(&json!({}))).await
}

/// Creates `name` and waits until it exists and is idle.
async fn created(api: &Api, name: &str) {
    create(api, name).await;
    api.workspaces.idle().await;
}

/// Creates and starts `name`.
async fn running(api: &Api, name: &str) {
    created(api, name).await;
    assert_eq!(
        post(api, &format!("/api/workspaces/{name}/start"))
            .await
            .status,
        202
    );
    api.workspaces.idle().await;
}

fn seed(api: &Api, name: &str, status: WorkspaceStatus, unsaved: Unsaved) {
    let mut record = WorkspaceRecord::new(
        WorkspaceId::new(name).unwrap(),
        WorkspaceName::new(name).unwrap(),
        REPO,
    );
    record.status = status;
    api.workspaces.seed(record, unsaved);
}

fn dirty() -> Unsaved {
    Unsaved {
        repos: vec![RepoFindings {
            dir: "api".into(),
            uncommitted: Listing {
                items: vec![" M src/main.rs".into(), "?? notes.txt".into()],
                more: 3,
            },
            unpushed: Listing {
                items: vec!["abc1234 wip".into()],
                more: 0,
            },
            stashes: Listing::default(),
        }],
        other: Listing {
            items: vec!["scratch".into()],
            more: 0,
        },
        errors: vec![],
    }
}

#[tokio::test]
async fn an_empty_install_lists_nothing() {
    let api = start().await;
    let reply = api.get("/api/workspaces").await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json(), json!({"workspaces": []}));
    api.running.shutdown().await;
}

#[tokio::test]
async fn create_is_accepted_busy_and_finishes_with_progress_events() {
    let api = start().await;
    let mut stream = Stream::open(&api, "?workspace=web").await;
    let ws = create(&api, "web").await;
    assert_eq!(
        ws,
        json!({
            "id": "web",
            "name": "web",
            "repo_url": REPO,
            "image": puddle_api::DEFAULT_IMAGE,
            "memory_mib": 8192,
            "status": "created",
            "busy": "creating",
            "created_at": START_MS,
            "disk_size_mib": puddle_api::DEFAULT_DISK_MIB,
            "disk_used_mib": 0,
            "direct_ssh": false,
            "first_connect_notice_due": false
        })
    );
    api.workspaces.idle().await;
    stream.read_until(|b| b.contains("\"step\":\"done\"")).await;
    let steps: Vec<String> = stream
        .data()
        .iter()
        .filter(|e| e["type"] == "workspace_progress")
        .map(|e| e["step"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        steps,
        ["preparing_volume", "pulling_image", "cloning", "done"]
    );
    let detail = api.get("/api/workspaces/web").await.json();
    assert_eq!(detail["busy"], Value::Null);
    assert_eq!(detail["status"], "created");
    assert_eq!(
        api.get("/api/workspaces").await.json()["workspaces"][0],
        detail
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn create_takes_an_image_and_memory() {
    let api = start().await;
    let reply = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({
                "name": "big", "repo_url": REPO,
                "image": "ghcr.io/acme/dev:1", "memory_mib": 16384
            })),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(reply.json()["image"], "ghcr.io/acme/dev:1");
    assert_eq!(reply.json()["memory_mib"], 16384);
    api.workspaces.idle().await;
    api.running.shutdown().await;
}

#[tokio::test]
async fn create_refuses_what_cannot_work_and_says_why() {
    let api = start().await;
    let long = "w".repeat(61);
    let cases: [(Value, &str); 13] = [
        (
            json!({"name": "a", "repo_url": "git@github.com:acme/api.git"}),
            "SSH remotes are not supported yet",
        ),
        (
            json!({"name": "a", "repo_url": "ssh://git@github.com/acme/api.git"}),
            "SSH remotes are not supported yet",
        ),
        (
            json!({"name": "a", "repo_url": "http://github.com/a/b"}),
            "https://",
        ),
        (json!({"name": "a", "repo_url": "/srv/repo"}), "https://"),
        (
            json!({"name": "a", "repo_url": "https://me:pw@github.com/a/b"}),
            "user name and password",
        ),
        (
            json!({"name": "a", "repo_url": "https://github.com/a b"}),
            "spaces",
        ),
        (json!({"name": "m--a", "repo_url": REPO}), "reserved"),
        (json!({"name": "A_b", "repo_url": REPO}), "workspace name"),
        (
            json!({"name": long, "repo_url": REPO}),
            "can't be a workspace",
        ),
        (
            json!({"name": "a", "repo_url": REPO, "memory_mib": 10}),
            "memory",
        ),
        (
            json!({"name": "a", "repo_url": REPO, "image": "no spaces allowed"}),
            "image",
        ),
        (json!({"name": "a"}), "repo_url"),
        (json!({"name": "a", "repo_url": REPO, "extra": 1}), "extra"),
    ];
    for (body, wants) in cases {
        let reply = api.send("POST", "/api/workspaces", Some(&body)).await;
        assert_eq!(reply.status, 422, "{body}: {}", reply.body);
        assert_eq!(reply.error(), "invalid");
        let message = reply.json()["message"].as_str().unwrap().to_owned();
        assert!(message.contains(wants), "{body}: {message}");
        assert!(
            !message.contains("pw@"),
            "credentials are never echoed: {message}"
        );
    }
    let array = api.send("POST", "/api/workspaces", Some(&json!([]))).await;
    assert_eq!(array.status, 422);
    assert_eq!(
        api.get("/api/workspaces").await.json(),
        json!({"workspaces": []})
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn create_refuses_a_taken_name_and_a_failed_create_leaves_nothing() {
    let api = start().await;
    created(&api, "web").await;
    let again = api
        .send(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": "web", "repo_url": REPO})),
        )
        .await;
    assert_eq!(again.status, 409);
    assert_eq!(again.error(), "conflict");

    let mut stream = Stream::open(&api, "?workspace=bad").await;
    api.workspaces
        .fail_next(Operation::Creating, "clone failed: repository not found");
    create(&api, "bad").await;
    api.workspaces.idle().await;
    stream
        .read_until(|b| b.contains("\"step\":\"failed\""))
        .await;
    assert!(stream.buf.contains("repository not found"));
    assert_eq!(api.get("/api/workspaces/bad").await.status, 404);
    api.running.shutdown().await;
}

#[tokio::test]
async fn start_and_stop_walk_the_states_and_report_them() {
    let api = start().await;
    created(&api, "web").await;
    let mut stream = Stream::open(&api, "?workspace=web").await;

    api.workspaces.hold();
    let started = post(&api, "/api/workspaces/web/start").await;
    assert_eq!(started.status, 202, "{}", started.body);
    assert_eq!(started.json()["status"], "starting");
    assert_eq!(started.json()["busy"], "starting");
    // Busy: a second request is refused, whatever it is.
    for path in ["start", "stop", "reclaim"] {
        let busy = post(&api, &format!("/api/workspaces/web/{path}")).await;
        assert_eq!(busy.status, 409, "{path}");
        assert!(busy.json()["message"].as_str().unwrap().contains("busy"));
    }
    api.workspaces.release();
    api.workspaces.idle().await;
    assert_eq!(
        api.get("/api/workspaces/web").await.json()["status"],
        "running"
    );
    assert_eq!(post(&api, "/api/workspaces/web/start").await.status, 409);

    let stopped = post(&api, "/api/workspaces/web/stop").await;
    assert_eq!(stopped.status, 202);
    assert_eq!(stopped.json()["status"], "draining");
    api.workspaces.idle().await;
    assert_eq!(
        api.get("/api/workspaces/web").await.json()["status"],
        "stopped"
    );
    assert_eq!(post(&api, "/api/workspaces/web/stop").await.status, 409);

    stream
        .read_until(|b| b.matches("\"step\":\"done\"").count() >= 2)
        .await;
    let statuses: Vec<String> = stream
        .data()
        .iter()
        .filter(|e| e["type"] == "status_changed")
        .map(|e| e["status"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(statuses, ["starting", "running", "draining", "stopped"]);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_failed_start_ends_crashed_and_can_be_started_again() {
    let api = start().await;
    created(&api, "web").await;
    api.workspaces
        .fail_next(Operation::Starting, "the VM did not boot");
    post(&api, "/api/workspaces/web/start").await;
    api.workspaces.idle().await;
    assert_eq!(
        api.get("/api/workspaces/web").await.json()["status"],
        "crashed"
    );
    assert_eq!(post(&api, "/api/workspaces/web/start").await.status, 202);
    api.workspaces.idle().await;
    assert_eq!(
        api.get("/api/workspaces/web").await.json()["status"],
        "running"
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn reclaim_shrinks_what_the_disk_holds() {
    let api = start().await;
    let mut record = WorkspaceRecord::new(
        WorkspaceId::new("web").unwrap(),
        WorkspaceName::new("web").unwrap(),
        REPO,
    );
    record.status = WorkspaceStatus::Stopped;
    record.disk_used_mib = Some(1000);
    api.workspaces.seed(record, Unsaved::default());
    let reply = post(&api, "/api/workspaces/web/reclaim").await;
    assert_eq!(reply.status, 202);
    assert_eq!(reply.json()["busy"], "reclaiming");
    api.workspaces.idle().await;
    let ws = api.get("/api/workspaces/web").await.json();
    assert_eq!(ws["disk_used_mib"], 500);
    assert_eq!(ws["busy"], Value::Null);
    api.running.shutdown().await;
}

#[tokio::test]
async fn unknown_workspaces_are_404_on_every_route() {
    let api = start().await;
    for id in ["nope", "Not_An_Id"] {
        let base = format!("/api/workspaces/{id}");
        for (method, path, body) in [
            ("GET", base.clone(), None),
            ("POST", format!("{base}/start"), Some(json!({}))),
            ("POST", format!("{base}/stop"), Some(json!({}))),
            ("POST", format!("{base}/reclaim"), Some(json!({}))),
            ("GET", format!("{base}/delete-check"), None),
            ("DELETE", base.clone(), Some(json!({"confirm": true}))),
            (
                "POST",
                format!("{base}/attach"),
                Some(json!({"mode": "browser"})),
            ),
        ] {
            let reply = api.send(method, &path, body.as_ref()).await;
            assert_eq!(reply.status, 404, "{method} {path}: {}", reply.body);
            assert_eq!(reply.error(), "not_found");
        }
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn the_delete_check_lists_what_would_be_lost() {
    let api = start().await;
    seed(&api, "web", WorkspaceStatus::Stopped, dirty());
    seed(&api, "tidy", WorkspaceStatus::Running, Unsaved::default());
    let check = api.get("/api/workspaces/web/delete-check").await;
    assert_eq!(check.status, 200);
    let c = check.json();
    assert_eq!(c["workspace"], "web");
    assert_eq!(c["clean"], false);
    assert_eq!(c["removes_sandbox"], "web");
    assert_eq!(c["errors"], json!([]));
    assert_eq!(c["other"], json!({"items": ["scratch"], "more": 0}));
    let repo = &c["repos"][0];
    assert_eq!(repo["dir"], "api");
    assert_eq!(repo["clean"], false);
    assert_eq!(repo["uncommitted"]["items"].as_array().unwrap().len(), 2);
    assert_eq!(repo["uncommitted"]["more"], 3);
    assert_eq!(repo["unpushed"]["items"][0], "abc1234 wip");
    assert_eq!(repo["stashes"], json!({"items": [], "more": 0}));
    assert_eq!(c["fingerprint"].as_str().unwrap().len(), 64);
    // The same state gives the same fingerprint.
    assert_eq!(api.get("/api/workspaces/web/delete-check").await.json(), c);

    let tidy = api.get("/api/workspaces/tidy/delete-check").await.json();
    assert_eq!(tidy["clean"], true);
    assert_eq!(
        tidy["removes_sandbox"],
        Value::Null,
        "a running one is stopped first"
    );
    assert_ne!(tidy["fingerprint"], c["fingerprint"]);
    api.running.shutdown().await;
}

#[tokio::test]
async fn delete_needs_an_explicit_confirmation() {
    let api = start().await;
    seed(&api, "web", WorkspaceStatus::Stopped, Unsaved::default());
    for body in [json!({"confirm": false}), json!({})] {
        let reply = api.send("DELETE", "/api/workspaces/web", Some(&body)).await;
        assert_eq!(reply.status, 422, "{body}: {}", reply.body);
    }
    let no_body = api.send("DELETE", "/api/workspaces/web", None).await;
    assert!(
        no_body.status == 415 || no_body.status == 422,
        "{}",
        no_body.status
    );
    assert_eq!(api.get("/api/workspaces/web").await.status, 200);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_clean_workspace_is_deleted_without_a_fingerprint() {
    let api = start().await;
    seed(&api, "web", WorkspaceStatus::Stopped, Unsaved::default());
    let mut stream = Stream::open(&api, "?workspace=web").await;
    let reply = api
        .send(
            "DELETE",
            "/api/workspaces/web",
            Some(&json!({"confirm": true})),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(reply.json()["busy"], "deleting");
    api.workspaces.idle().await;
    assert_eq!(api.get("/api/workspaces/web").await.status, 404);
    assert_eq!(
        api.get("/api/workspaces").await.json(),
        json!({"workspaces": []})
    );
    stream.read_until(|b| b.contains("\"step\":\"done\"")).await;
    assert!(stream.buf.contains("\"step\":\"removing\""));
    api.running.shutdown().await;
}

#[tokio::test]
async fn unsaved_work_is_never_deleted_unseen() {
    let api = start().await;
    seed(&api, "web", WorkspaceStatus::Stopped, dirty());
    let delete = |fingerprint: Value| {
        let api = &api;
        async move {
            api.send(
                "DELETE",
                "/api/workspaces/web",
                Some(&json!({"confirm": true, "fingerprint": fingerprint})),
            )
            .await
        }
    };
    // Without the report's fingerprint: refused, nothing deleted.
    let blind = api
        .send(
            "DELETE",
            "/api/workspaces/web",
            Some(&json!({"confirm": true})),
        )
        .await;
    assert_eq!(blind.status, 409);
    assert!(
        blind.json()["message"]
            .as_str()
            .unwrap()
            .contains("not saved")
    );
    // A fingerprint of something else.
    assert_eq!(delete(json!("0".repeat(64))).await.status, 409);
    assert_eq!(api.get("/api/workspaces/web").await.status, 200);

    // The report the user saw, then the workspace changes before they confirm.
    let seen = api.get("/api/workspaces/web/delete-check").await.json();
    let mut more = dirty();
    more.repos[0].stashes.items.push("stash@{0}: wip".into());
    assert!(
        api.workspaces
            .set_unsaved(&WorkspaceId::new("web").unwrap(), more)
    );
    let changed = delete(seen["fingerprint"].clone()).await;
    assert_eq!(changed.status, 409);
    assert!(
        changed.json()["message"]
            .as_str()
            .unwrap()
            .contains("changed")
    );
    assert_eq!(api.get("/api/workspaces/web").await.status, 200);

    // Confirming exactly the report the user saw goes through.
    let seen = api.get("/api/workspaces/web/delete-check").await.json();
    let ok = delete(seen["fingerprint"].clone()).await;
    assert_eq!(ok.status, 202, "{}", ok.body);
    api.workspaces.idle().await;
    assert_eq!(api.get("/api/workspaces/web").await.status, 404);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_running_or_busy_workspace_cannot_be_deleted() {
    let api = start().await;
    running(&api, "web").await;
    let reply = api
        .send(
            "DELETE",
            "/api/workspaces/web",
            Some(&json!({"confirm": true})),
        )
        .await;
    assert_eq!(reply.status, 409);
    assert!(
        reply.json()["message"]
            .as_str()
            .unwrap()
            .contains("stop it")
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn attach_needs_a_running_workspace() {
    let api = start().await;
    created(&api, "web").await;
    for mode in ["desktop", "browser"] {
        let reply = api
            .send(
                "POST",
                "/api/workspaces/web/attach",
                Some(&json!({"mode": mode})),
            )
            .await;
        assert_eq!(reply.status, 409, "{mode}");
        assert!(
            reply.json()["message"]
                .as_str()
                .unwrap()
                .contains("start it first")
        );
    }
    assert_eq!(api.launcher.opened().len(), 0);
    api.running.shutdown().await;
}

#[tokio::test]
async fn browser_attach_returns_the_url_and_opens_nothing() {
    let api = start().await;
    running(&api, "web").await;
    let reply = api
        .send(
            "POST",
            "/api/workspaces/web/attach",
            Some(&json!({"mode": "browser"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["opened"], false);
    assert!(
        body["url"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:")
    );
    assert!(body["url"].as_str().unwrap().contains("/web/"));
    assert_eq!(body["message"], Value::Null);
    assert_eq!(api.launcher.opened().len(), 0);
    // A browser attach needs no SSH: it works while direct SSH is off.
    assert_eq!(
        api.get("/api/workspaces/web").await.json()["direct_ssh"],
        false
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn desktop_attach_opens_the_editor_when_direct_ssh_is_on() {
    let api = start().await;
    running(&api, "web").await;
    allow_direct_ssh(&api, "web").await;
    let reply = api
        .send(
            "POST",
            "/api/workspaces/web/attach",
            Some(&json!({"mode": "desktop"})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.json(),
        json!({"opened": true, "url": null, "message": null})
    );
    assert_eq!(api.launcher.opened(), [WorkspaceId::new("web").unwrap()]);
    api.running.shutdown().await;
}

async fn allow_direct_ssh(api: &Api, workspace: &str) {
    let reply = api
        .send(
            "PUT",
            &format!("/api/settings/workspaces/{workspace}"),
            Some(&json!({"overrides": {"direct_ssh": true}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

#[tokio::test]
async fn desktop_attach_is_refused_while_direct_ssh_is_off() {
    let api = start().await;
    running(&api, "web").await;
    let reply = api
        .send(
            "POST",
            "/api/workspaces/web/attach",
            Some(&json!({"mode": "desktop"})),
        )
        .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.json()["message"]
            .as_str()
            .unwrap()
            .contains("direct SSH is off"),
        "{}",
        reply.body
    );
    assert_eq!(api.launcher.opened().len(), 0, "nothing was launched");
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_workspace_is_trusted_by_its_own_switch_or_the_global_default() {
    let api = start().await;
    running(&api, "web").await;
    running(&api, "db").await;
    let direct = |name: &'static str| {
        let api = &api;
        async move { api.get(&format!("/api/workspaces/{name}")).await.json()["direct_ssh"].clone() }
    };
    assert_eq!(
        (direct("web").await, direct("db").await),
        (json!(false), json!(false))
    );

    allow_direct_ssh(&api, "web").await;
    assert_eq!(
        (direct("web").await, direct("db").await),
        (json!(true), json!(false))
    );

    let reply = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({"workspace_defaults": {"direct_ssh": true}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        (direct("web").await, direct("db").await),
        (json!(true), json!(true))
    );

    // An override of off beats the global default.
    let reply = api
        .send(
            "PUT",
            "/api/settings/workspaces/db",
            Some(&json!({"overrides": {"direct_ssh": false}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(direct("db").await, json!(false));
    let list = api.get("/api/workspaces").await.json();
    let flags: Vec<_> = list["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["direct_ssh"].clone())
        .collect();
    assert!(
        flags.contains(&json!(true)) && flags.contains(&json!(false)),
        "{flags:?}"
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn changing_settings_tells_the_workspaces_service() {
    let api = start().await;
    assert_eq!(api.workspaces.settings_changes(), 0);
    allow_direct_ssh(&api, "web").await;
    assert_eq!(api.workspaces.settings_changes(), 1);
    let reply = api
        .send(
            "PUT",
            "/api/settings",
            Some(&json!({"workspace_defaults": {"direct_ssh": true}})),
        )
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(api.workspaces.settings_changes(), 2);
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_desktop_that_cannot_open_says_why() {
    let api = start().await;
    running(&api, "web").await;
    allow_direct_ssh(&api, "web").await;
    api.launcher.fail_next("VS Code is not installed");
    let reply = api
        .send(
            "POST",
            "/api/workspaces/web/attach",
            Some(&json!({"mode": "desktop"})),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({"opened": false, "url": null, "message": "VS Code is not installed"})
    );
    api.running.shutdown().await;
}

#[tokio::test]
async fn attach_refuses_unknown_modes_and_fields() {
    let api = start().await;
    running(&api, "web").await;
    for body in [
        json!({"mode": "emacs"}),
        json!({}),
        json!({"mode": "desktop", "x": 1}),
    ] {
        let reply = api
            .send("POST", "/api/workspaces/web/attach", Some(&body))
            .await;
        assert_eq!(reply.status, 422, "{body}");
    }
    api.running.shutdown().await;
}

#[tokio::test]
async fn without_a_workspaces_service_every_route_says_unavailable() {
    let api = start_without_workspaces().await;
    for (method, path, body) in [
        ("GET", "/api/workspaces", None),
        (
            "POST",
            "/api/workspaces",
            Some(json!({"name": "a", "repo_url": REPO})),
        ),
        ("GET", "/api/workspaces/a", None),
        ("POST", "/api/workspaces/a/start", Some(json!({}))),
        ("POST", "/api/workspaces/a/stop", Some(json!({}))),
        ("POST", "/api/workspaces/a/reclaim", Some(json!({}))),
        ("GET", "/api/workspaces/a/delete-check", None),
        (
            "DELETE",
            "/api/workspaces/a",
            Some(json!({"confirm": true})),
        ),
        (
            "POST",
            "/api/workspaces/a/attach",
            Some(json!({"mode": "browser"})),
        ),
    ] {
        let reply = api.send(method, path, body.as_ref()).await;
        assert_eq!(reply.status, 503, "{method} {path}: {}", reply.body);
        assert_eq!(reply.error(), "unavailable");
    }
    api.running.shutdown().await;
}
