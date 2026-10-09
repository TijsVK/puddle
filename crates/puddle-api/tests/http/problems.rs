// SPDX-License-Identifier: GPL-3.0-or-later
//! `GET /api/problems`: what puddle did on its own that failed, listed until its cause goes away,
//! and announced on the event stream.

use puddle_api::SettingsRepo;
use serde_json::json;

use crate::common::start;
use crate::events::Stream;

async fn make_a_workspace(api: &crate::common::Api, name: &str) {
    let body = json!({"name": name, "repo_url": "https://github.com/acme/api.git"});
    let reply = api.send("POST", "/api/workspaces", Some(&body)).await;
    assert_eq!(reply.status, 202, "{}", reply.body);
}

#[tokio::test]
async fn a_fresh_install_has_no_problems() {
    let api = start().await;
    let reply = api.get("/api/problems").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.json(), json!({"problems": []}));
    api.running.shutdown().await;
}

#[tokio::test]
async fn a_system_managed_update_that_failed_is_listed_with_its_reason_until_one_works() {
    let api = start().await;
    let mut stream = Stream::open(&api, "").await;
    // A document from a newer puddle can't be read: the allows stay, and the user is told.
    api.settings
        .save_global(json!({"schema_version": 99}))
        .unwrap();
    make_a_workspace(&api, "late").await;
    stream.read_until(|b| b.contains("problems_changed")).await;
    let listed = api.get("/api/problems").await.json();
    let problem = &listed["problems"][0];
    assert_eq!(problem["key"], "system-managed", "{listed}");
    assert!(problem["workspace"].is_null());
    let title = problem["title"].as_str().unwrap();
    assert!(title.contains("could not update which hosts"), "{title}");
    let detail = problem["detail"].as_str().unwrap();
    assert!(detail.contains("stay as they were"), "{detail}");
    // The reason from the settings reader is in the text, not only in the log.
    assert!(
        detail.contains("99") || detail.contains("newer"),
        "{detail}"
    );

    api.settings.save_global(json!({})).unwrap();
    make_a_workspace(&api, "later").await;
    assert_eq!(
        api.get("/api/problems").await.json(),
        json!({"problems": []})
    );
    api.running.shutdown().await;
}
