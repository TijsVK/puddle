// SPDX-License-Identifier: GPL-3.0-or-later
//! The UI fixture backend over real HTTP: seeded data, the guard of the real API, the
//! control server, scripted events, restart and reset.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test: a failed step fails it by panicking"
)]

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use puddle_e2e::ui_fixture::{
    Fixture, FixtureOptions, Scenario, Step, built_in_names, control, load_scenario,
    step_from_drop, watch_drop_dir,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const STEP: Duration = Duration::from_secs(10);

struct Running {
    fixture: Arc<Fixture>,
    api: std::net::SocketAddr,
    control: std::net::SocketAddr,
    token: String,
}

async fn start_scenario(scenario: Scenario) -> Running {
    let fixture = Fixture::start(FixtureOptions {
        port: 0,
        connection_file: None,
        scenario,
    })
    .await
    .unwrap();
    let (control, _task) = control::serve(fixture.clone(), 0).await.unwrap();
    let info = fixture.connection_info().await.unwrap();
    Running {
        api: fixture.addr().await.unwrap(),
        control,
        token: info.token.expose().to_owned(),
        fixture,
    }
}

async fn start(name: &str) -> Running {
    start_scenario(load_scenario(name).unwrap()).await
}

struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {:?}", self.body))
    }
}

async fn http(
    addr: std::net::SocketAddr,
    host: &str,
    token: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Reply {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(token) = token {
        let _ = write!(head, "Authorization: Bearer {token}\r\n");
    }
    let body = body.map(Value::to_string).unwrap_or_default();
    if method != "GET" {
        let _ = write!(
            head,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    head.push_str("\r\n");
    head.push_str(&body);
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(head.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(STEP, tcp.read_to_end(&mut bytes))
        .await
        .expect("reply in time")
        .unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        body: body.to_owned(),
    }
}

impl Running {
    async fn api(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("127.0.0.1:{}", self.api.port());
        http(self.api, &host, Some(&self.token), method, path, body).await
    }

    async fn get(&self, path: &str) -> Reply {
        self.api("GET", path, None).await
    }

    async fn control(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let host = format!("127.0.0.1:{}", self.control.port());
        http(self.control, &host, Some(&self.token), method, path, body).await
    }

    async fn state(&self) -> Value {
        self.control("GET", "/control/state", None).await.json()
    }

    /// An open SSE stream on the API.
    async fn events(&self) -> TcpStream {
        let mut tcp = TcpStream::connect(self.api).await.unwrap();
        let request = format!(
            "GET /api/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nAccept: text/event-stream\r\n\r\n",
            self.api.port(),
            self.token
        );
        tcp.write_all(request.as_bytes()).await.unwrap();
        tcp
    }
}

/// Reads from `tcp` until `done` is true of what came, or fails after the step timeout.
async fn read_until(tcp: &mut TcpStream, done: impl Fn(&str) -> bool) -> String {
    let mut seen = String::new();
    let mut chunk = [0u8; 4096];
    tokio::time::timeout(STEP, async {
        while !done(&seen) {
            let n = tcp.read(&mut chunk).await.unwrap();
            assert!(n > 0, "stream closed early: {seen}");
            seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; saw {seen:?}"));
    seen
}

#[tokio::test]
async fn every_built_in_scenario_starts_with_its_seeded_data() {
    let counts = [("default", 1, 0), ("empty", 0, 0), ("lived-in", 8, 6)];
    for (name, pending, rules_min) in counts {
        let run = start(name).await;
        let state = run.state().await;
        assert_eq!(state["scenario"], name);
        assert_eq!(state["pending"], pending, "{name}");
        let rules = run.get("/api/rules").await.json();
        assert!(
            rules["rules"].as_array().unwrap().len() >= rules_min,
            "{name}: {rules}"
        );
        assert_eq!(run.get("/api/pending").await.status, 200);
        assert_eq!(run.get("/api/audit").await.status, 200);
        run.fixture.shutdown().await;
    }
    assert_eq!(built_in_names(), ["default", "empty", "lived-in"]);
}

#[tokio::test]
async fn the_default_scenario_is_the_one_pending_request_the_ui_gates_count_on() {
    let run = start("default").await;
    let pending = run.get("/api/pending").await.json();
    let rows = pending["requests"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{pending}");
    assert_eq!(rows[0]["sandbox"], "demo");
    assert_eq!(rows[0]["host"], "registry.example.org");
    assert_eq!(run.get("/api/rules").await.json()["rules"], json!([]));
}

#[tokio::test]
async fn the_same_scenario_gives_byte_identical_responses() {
    let paths = [
        "/api/pending",
        "/api/inbox",
        "/api/rules",
        "/api/audit?limit=500",
        "/api/sandboxes/web-shop/suppression",
        "/api/workspaces",
        "/api/workspaces/docs-site/delete-check",
    ];
    let a = start("lived-in").await;
    let b = start("lived-in").await;
    for path in paths {
        let (x, y) = (a.get(path).await, b.get(path).await);
        assert_eq!(x.status, 200, "{path}");
        assert_eq!(x.body, y.body, "{path}");
        assert!(x.body.len() > 20, "{path}: {}", x.body);
    }
}

#[tokio::test]
async fn the_api_keeps_its_guard() {
    let run = start("default").await;
    let host = format!("127.0.0.1:{}", run.api.port());
    let no_token = http(run.api, &host, None, "GET", "/api/pending", None).await;
    assert_eq!(no_token.status, 401);
    let wrong_host = http(
        run.api,
        "evil.example",
        Some(&run.token),
        "GET",
        "/api/pending",
        None,
    )
    .await;
    assert_eq!(wrong_host.status, 421);
    // The control server wants the token too.
    let host = format!("127.0.0.1:{}", run.control.port());
    let no_token = http(run.control, &host, None, "GET", "/control/state", None).await;
    assert_eq!(no_token.status, 401);
}

#[tokio::test]
async fn requests_made_through_the_real_routes_change_what_the_fixture_holds() {
    let run = start("default").await;
    let pending = run.get("/api/pending").await.json();
    let id = pending["requests"][0]["id"].as_i64().unwrap();
    let approve = run
        .api(
            "POST",
            &format!("/api/pending/{id}/approve"),
            Some(&json!({})),
        )
        .await;
    assert_eq!(approve.status, 200, "{}", approve.body);
    assert_eq!(run.state().await["pending"], 0);
    assert_eq!(
        run.get("/api/rules").await.json()["rules"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn emit_puts_an_event_on_the_stream_and_any_event_json_is_accepted() {
    let run = start("empty").await;
    let mut stream = run.events().await;
    read_until(&mut stream, |s| s.contains("\r\n\r\n")).await;
    // The stream is subscribed once the hub has a receiver; emit until it shows up.
    let event = json!({"type": "oom_kill", "sandbox": "web-shop", "pid": 7, "process": "node"});
    let sent = run.control("POST", "/control/emit", Some(&event)).await;
    assert_eq!(sent.status, 204);
    let seen = read_until(&mut stream, |s| s.contains("oom_kill")).await;
    assert!(seen.contains("\"pid\":7"), "{seen}");

    let bad = run
        .control("POST", "/control/emit", Some(&json!({"type": "nope"})))
        .await;
    assert!(bad.status == 422 || bad.status == 400, "{}", bad.status);
}

#[tokio::test]
async fn scripts_run_in_order_and_an_unknown_one_is_404() {
    let run = start("lived-in").await;
    let before = run.state().await["pending"].as_u64().unwrap();
    let ran = run.control("POST", "/control/script/arrivals", None).await;
    assert_eq!(ran.status, 204);
    assert_eq!(run.state().await["pending"].as_u64().unwrap(), before + 3);
    let missing = run.control("POST", "/control/script/nope", None).await;
    assert_eq!(missing.status, 404);
    // A script with a bad step reports it.
    let bad = run
        .control(
            "POST",
            "/control/step",
            Some(&json!({"do": "request", "sandbox": "Not A Name", "host": "x.example.org"})),
        )
        .await;
    assert_eq!(bad.status, 422, "{}", bad.body);
}

#[tokio::test]
async fn advancing_the_clock_expires_rules_like_the_sweeper() {
    let run = start("lived-in").await;
    let rules = |reply: Value| reply["rules"].as_array().unwrap().len();
    let before = rules(run.get("/api/rules").await.json());
    let now = run.state().await["now_ms"].as_u64().unwrap();
    let advance = run
        .control("POST", "/control/advance", Some(&json!({"ms": 18_000_000})))
        .await;
    assert_eq!(advance.status, 204);
    assert_eq!(
        run.state().await["now_ms"].as_u64().unwrap(),
        now + 18_000_000
    );
    // `api.example.com` (4 h from 1 h ago) has expired and been swept.
    assert_eq!(rules(run.get("/api/rules").await.json()), before - 1);
}

#[tokio::test]
async fn restart_ends_open_streams_and_keeps_the_data_on_the_same_port() {
    let run = start("lived-in").await;
    let mut stream = run.events().await;
    read_until(&mut stream, |s| s.contains("\r\n\r\n")).await;
    let before = run.get("/api/pending").await.body;
    let restarted = run.control("POST", "/control/restart", None).await;
    assert_eq!(restarted.status, 204);
    // The old stream ends (read returns 0 eventually).
    let mut buf = [0u8; 1024];
    tokio::time::timeout(STEP, async {
        loop {
            if stream.read(&mut buf).await.unwrap_or(0) == 0 {
                break;
            }
        }
    })
    .await
    .expect("the stream ended");
    assert_eq!(run.fixture.addr().await.unwrap(), run.api);
    assert_eq!(run.get("/api/pending").await.body, before);
}

#[tokio::test]
async fn reset_starts_over_from_the_scenario_or_another_one() {
    let run = start("default").await;
    run.control(
        "POST",
        "/control/step",
        Some(&json!({"do": "request", "sandbox": "demo", "host": "more.example.org"})),
    )
    .await;
    assert_eq!(run.state().await["pending"], 2);
    assert_eq!(
        run.control("POST", "/control/reset", None).await.status,
        204
    );
    assert_eq!(run.state().await["pending"], 1);
    let other = run
        .control(
            "POST",
            "/control/reset",
            Some(&json!({"scenario": "lived-in"})),
        )
        .await;
    assert_eq!(other.status, 204);
    assert_eq!(run.state().await["scenario"], "lived-in");
    let unknown = run
        .control(
            "POST",
            "/control/reset",
            Some(&json!({"scenario": "no-such"})),
        )
        .await;
    assert_eq!(unknown.status, 422);
    // The API answers on the same port and token throughout.
    assert_eq!(run.get("/api/pending").await.status, 200);
}

#[tokio::test]
async fn settings_in_a_scenario_are_served_with_their_unknown_fields_listed() {
    let scenario: Scenario = serde_json::from_value(json!({
        "name": "settings",
        "settings": {
            "global": {"schema_version": 1, "sandbox_defaults": {"zoom_hotkeys": false}},
            "sandboxes": {"web-shop": {"schema_version": 1}}
        }
    }))
    .unwrap();
    let run = start_scenario(scenario).await;
    let global = run.get("/api/settings").await;
    assert_eq!(global.status, 200, "{}", global.body);
    assert_eq!(global.json()["unknown_fields"], json!([]));
    assert_eq!(
        run.get("/api/settings/sandboxes/web-shop").await.status,
        200
    );
}

#[tokio::test]
async fn a_dropped_file_makes_requests_arrive_in_the_old_serve_ui_format() {
    let run = start("empty").await;
    let dir = tempfile::tempdir().unwrap();
    let _watch = watch_drop_dir(run.fixture.clone(), dir.path().to_owned());
    let file = dir.path().join("a.json");
    std::fs::write(
        dir.path().join("a.tmp"),
        json!([
            {"sandbox": "demo", "host": "one.example.org", "repeat": 2},
            {"sandbox": "demo", "count": 3, "domain": "many.example.org"}
        ])
        .to_string(),
    )
    .unwrap();
    std::fs::rename(dir.path().join("a.tmp"), &file).unwrap();
    tokio::time::timeout(STEP, async {
        while file.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the file was taken");
    assert_eq!(run.state().await["pending"], 4);
    let rows = run.get("/api/pending").await.json();
    let attempts: Vec<i64> = rows["requests"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["host"] == "one.example.org")
        .map(|r| r["attempts"].as_i64().unwrap())
        .collect();
    assert_eq!(attempts, [2]);
}

#[test]
fn drop_items_without_do_are_requests_or_bulks_and_others_are_refused() {
    assert!(matches!(
        step_from_drop(json!({"sandbox": "a", "host": "x.example.org"})),
        Ok(Step::Request(_))
    ));
    assert!(matches!(
        step_from_drop(json!({"sandbox": "a", "count": 2})),
        Ok(Step::Bulk { count: 2, .. })
    ));
    assert!(step_from_drop(json!({"sandbox": "a", "hots": "x"})).is_err());
    assert!(step_from_drop(json!(7)).is_err());
}

#[tokio::test]
async fn a_scenario_with_a_typo_or_a_bad_value_fails_to_start() {
    assert!(serde_json::from_value::<Scenario>(json!({"rulez": []})).is_err());
    let bad_host: Scenario =
        serde_json::from_value(json!({"requests": [{"sandbox": "a", "host": "bad host!"}]}))
            .unwrap();
    let err = Fixture::start(FixtureOptions {
        port: 0,
        connection_file: None,
        scenario: bad_host,
    })
    .await
    .err()
    .unwrap();
    assert!(err.contains("bad host!"), "{err}");
    let bad_reason: Scenario = serde_json::from_value(json!({"connections": [
        {"sandbox": "a", "host": "x.example.org", "decision": "blocked", "reason": "mystery"}
    ]}))
    .unwrap();
    assert!(
        Fixture::start(FixtureOptions {
            port: 0,
            connection_file: None,
            scenario: bad_reason
        })
        .await
        .err()
        .unwrap()
        .contains("mystery")
    );
    let missing = load_scenario("/no/such/scenario.json").unwrap_err();
    assert!(missing.contains("default, empty, lived-in"), "{missing}");
}

#[tokio::test]
async fn the_connection_file_is_written_for_the_dev_proxy_and_playwright() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sub").join("connection.json");
    let fixture = Fixture::start(FixtureOptions {
        port: 0,
        connection_file: Some(file.clone()),
        scenario: load_scenario("empty").unwrap(),
    })
    .await
    .unwrap();
    let written: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(written["version"], 1);
    let info = fixture.connection_info().await.unwrap();
    assert_eq!(written["url"], info.url);
    assert_eq!(written["token"], info.token.expose());
    // A restart rewrites it (same token, same port).
    fixture.restart().await.unwrap();
    let again: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(again, written);
}

#[tokio::test]
async fn seeded_workspaces_are_listed_with_what_deleting_them_would_lose() {
    let run = start("lived-in").await;
    let list = run.get("/api/workspaces").await.json();
    let rows = list["workspaces"].as_array().unwrap();
    let names: Vec<_> = rows.iter().map(|w| w["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["data-tools", "docs-site", "web-shop"]);
    let status = |name: &str| {
        rows.iter().find(|w| w["name"] == name).unwrap()["status"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(status("web-shop"), "running");
    assert_eq!(status("docs-site"), "stopped");
    assert_eq!(status("data-tools"), "created");
    let docs = rows.iter().find(|w| w["name"] == "docs-site").unwrap();
    assert_eq!(docs["memory_mib"], 4096);
    assert_eq!(docs["first_connect_notice_due"], true);

    let check = run
        .get("/api/workspaces/docs-site/delete-check")
        .await
        .json();
    assert_eq!(check["clean"], false);
    assert_eq!(
        check["repos"][0]["unpushed"]["items"][0],
        "3f2a9c1 Rewrite the intro"
    );
    assert_eq!(check["other"]["items"][0], "scratch");
    let clean = run
        .get("/api/workspaces/web-shop/delete-check")
        .await
        .json();
    assert_eq!(clean["clean"], true);

    let empty = start("empty").await;
    assert_eq!(
        empty.get("/api/workspaces").await.json(),
        json!({"workspaces": []})
    );
}

#[tokio::test]
async fn scripted_steps_hold_and_fail_workspace_operations() {
    let run = start("empty").await;
    let mut stream = run.events().await;
    read_until(&mut stream, |s| s.contains("\r\n\r\n")).await;
    let step = |body: Value| {
        let run = &run;
        async move { run.control("POST", "/control/step", Some(&body)).await }
    };
    assert_eq!(step(json!({"do": "hold_workspaces"})).await.status, 204);
    let created = run
        .api(
            "POST",
            "/api/workspaces",
            Some(&json!({"name": "demo", "repo_url": "https://github.com/acme/demo.git"})),
        )
        .await;
    assert_eq!(created.status, 202, "{}", created.body);
    assert_eq!(
        run.get("/api/workspaces/demo").await.json()["busy"],
        "creating"
    );
    assert_eq!(step(json!({"do": "release_workspaces"})).await.status, 204);
    read_until(&mut stream, |s| s.contains("\"step\":\"done\"")).await;
    assert_eq!(
        run.get("/api/workspaces/demo").await.json()["busy"],
        Value::Null
    );

    let fail =
        json!({"do": "fail_workspace", "operation": "start", "reason": "the VM did not boot"});
    assert_eq!(step(fail).await.status, 204);
    let started = run
        .api("POST", "/api/workspaces/demo/start", Some(&json!({})))
        .await;
    assert_eq!(started.status, 202);
    let seen = read_until(&mut stream, |s| s.contains("did not boot")).await;
    assert!(seen.contains("\"step\":\"failed\""), "{seen}");
    assert_eq!(
        run.get("/api/workspaces/demo").await.json()["status"],
        "crashed"
    );
    for operation in ["create", "stop", "reclaim", "delete"] {
        let body = json!({"do": "fail_workspace", "operation": operation, "reason": "x"});
        assert_eq!(step(body).await.status, 204, "{operation}");
    }
}

#[tokio::test]
async fn a_scenario_with_a_bad_workspace_fails_to_start() {
    let cases = [
        (
            json!({"name": "A_b", "repo_url": "https://x.test/a"}),
            "A_b",
        ),
        (
            json!({"name": "a", "repo_url": "git@x.test:a/b"}),
            "SSH remotes",
        ),
        (
            json!({"name": "a", "repo_url": "https://x.test/a", "memory_mib": 1}),
            "memory",
        ),
        (
            json!({"name": "a", "repo_url": "https://x.test/a", "image": "bad image"}),
            "image",
        ),
    ];
    for (workspace, wants) in cases {
        let scenario: Scenario =
            serde_json::from_value(json!({"workspaces": [workspace]})).unwrap();
        let err = Fixture::start(FixtureOptions {
            port: 0,
            connection_file: None,
            scenario,
        })
        .await
        .err()
        .unwrap();
        assert!(err.contains(wants), "{wants}: {err}");
    }
    assert!(
        serde_json::from_value::<Scenario>(
            json!({"workspaces": [{"name": "a", "repo_url": "https://x.test/a", "typo": 1}]})
        )
        .is_err()
    );
}

#[tokio::test]
async fn a_history_step_writes_connection_records_across_a_week() {
    let run = start("empty").await;
    let step = run
        .control(
            "POST",
            "/control/step",
            Some(&json!({"do": "history", "count": 600})),
        )
        .await;
    assert_eq!(step.status, 204, "{}", step.body);
    let now = run.state().await["now_ms"].as_u64().unwrap();
    let page = run.get("/api/audit?limit=500").await.json();
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 500);
    // Newest first, and the newest is just before now; ids and times fall together.
    let ts = |i: usize| entries[i]["record"]["ts"].as_u64().unwrap();
    assert!(ts(0) <= now && now - ts(0) < 7 * 24 * 3_600_000 / 600 + 1);
    assert!(ts(0) > ts(499));
    let oldest = run
        .get(&format!(
            "/api/audit?before={}&limit=500",
            page["next_before"]
        ))
        .await
        .json();
    assert_eq!(oldest["entries"].as_array().unwrap().len(), 100);
    assert_eq!(oldest["next_before"], Value::Null);
    let mut decisions: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["record"]["decision"].as_str())
        .collect();
    decisions.sort_unstable();
    decisions.dedup();
    assert_eq!(decisions, ["allow", "blocked", "deny", "pending"]);
}
