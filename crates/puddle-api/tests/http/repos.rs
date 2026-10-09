// SPDX-License-Identifier: GPL-3.0-or-later
//! The repository lists and the account profile over real HTTP, against a real store and the
//! fake host: one list for the Identities tab and the create form, how current each credential's
//! list is and why one is not, refreshing, and prefilling an identity.

use std::sync::Arc;

use puddle_api::{FakeRepos, RepoService};
use puddle_repos::{
    Freshness, ListState, Note, NoteKind, Problem, ProblemKind, Profile, ProfileRead, Read,
    Repository, Role, SourceList, Visibility,
};
use puddle_secrets::{AccountName, HostName, SourceSpec};
use puddle_store::IdentityId;
use serde_json::{Value, json};

use crate::common::{Api, start, start_without_repos};

fn identity_body(label: &str) -> Value {
    json!({
        "label": label,
        "author": {"name": label, "email": format!("{}@example.com", label.to_lowercase())},
        "credentials": [{
            "host": "github.com",
            "source": {"kind": "gh", "host": "github.com", "account": label.to_lowercase()},
            "covers": {"owners": [], "rest_of_host": true}
        }]
    })
}

async fn make(api: &Api, label: &str) -> i64 {
    let reply = api
        .send("POST", "/api/identities", Some(&identity_body(label)))
        .await;
    assert_eq!(reply.status, 201, "{}", reply.body);
    reply.json()["id"].as_i64().unwrap()
}

fn repo(full_name: &str, role: Role) -> Repository {
    let (owner, name) = full_name.split_once('/').unwrap();
    Repository {
        host: "github.com".to_owned(),
        owner: owner.to_owned(),
        project: None,
        name: name.to_owned(),
        full_name: full_name.to_owned(),
        url: format!("https://github.com/{full_name}"),
        visibility: Visibility::Private,
        role,
        archived: false,
        fork: false,
    }
}

fn list(identity: i64, repos: Vec<Repository>) -> SourceList {
    SourceList {
        identity: IdentityId(identity),
        credential: 0,
        host: "github.com".to_owned(),
        organisation: None,
        state: ListState::Ok,
        refreshed_at: Some(1_700_000_000_000),
        retry_at: None,
        problem: None,
        notes: Vec::new(),
        repos: Arc::from(repos),
    }
}

fn gh_source() -> Value {
    json!({"kind": "gh", "host": "github.com", "account": "me"})
}

#[tokio::test]
async fn the_repositories_come_back_once_each_with_who_reaches_them_and_how_current_every_list_is()
{
    let api = start().await;
    let work = make(&api, "Work").await;
    let mine = make(&api, "Mine").await;
    let mut stale = list(
        work,
        vec![repo("acme/web", Role::Admin), repo("acme/api", Role::Read)],
    );
    stale.state = ListState::Stale;
    stale.problem = Some(Problem {
        kind: ProblemKind::RateLimited,
        message: "GitHub is limiting how fast puddle may ask; puddle waits before it asks again"
            .to_owned(),
        retry_at: Some(1_700_000_300_000),
        needs_sign_in: false,
    });
    stale.retry_at = Some(1_700_000_300_000);
    stale.notes = vec![Note {
        kind: NoteKind::OrganisationsMayBeHidden,
        message: "some organisations may be hidden".to_owned(),
    }];
    api.repos.set_lists(vec![
        stale,
        list(
            mine,
            vec![repo("Acme/Web", Role::Write), repo("me/notes", Role::Admin)],
        ),
    ]);

    let reply = api.get("/api/repos").await;

    assert_eq!(reply.status, 200, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["total"], 3);
    assert_eq!(
        (body["offset"].clone(), body["limit"].clone()),
        (json!(0), json!(100))
    );
    let names: Vec<_> = body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["full_name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["acme/api", "acme/web", "me/notes"]);
    assert_eq!(
        body["repos"][1],
        json!({
            "host": "github.com", "owner": "acme", "project": null, "name": "web",
            "full_name": "acme/web", "url": "https://github.com/acme/web",
            "visibility": "private", "role": "admin", "archived": false, "fork": false,
            "identities": [work, mine]
        })
    );
    assert_eq!(
        body["sources"],
        json!([
            {
                "identity_id": work, "credential": 0, "host": "github.com", "organisation": null,
                "state": "stale", "refreshed_at": 1_700_000_000_000_u64, "retry_at": 1_700_000_300_000_u64,
                "problem": {
                    "code": "rate_limited",
                    "message": "GitHub is limiting how fast puddle may ask; puddle waits before it asks again",
                    "needs_sign_in": false
                },
                "notes": [{"code": "organisations_may_be_hidden", "message": "some organisations may be hidden"}],
                "repo_count": 2
            },
            {
                "identity_id": mine, "credential": 0, "host": "github.com", "organisation": null,
                "state": "ok", "refreshed_at": 1_700_000_000_000_u64, "retry_at": null,
                "problem": null, "notes": [], "repo_count": 2
            }
        ])
    );
    // Read from the cache for every identity.
    assert_eq!(
        api.repos.reads(),
        [Read {
            only: None,
            freshness: Freshness::Cached
        }]
    );
}

#[tokio::test]
async fn the_create_form_searches_by_words_and_pages() {
    let api = start().await;
    let work = make(&api, "Work").await;
    api.repos.set_lists(vec![list(
        work,
        vec![
            repo("acme/web", Role::Write),
            repo("acme/web-api", Role::Write),
            repo("acme/docs", Role::Read),
            repo("me/web", Role::Admin),
        ],
    )]);

    let found = api.get("/api/repos?query=ACME%20web").await.json();
    assert_eq!(found["total"], 2);
    assert_eq!(found["repos"][0]["full_name"], "acme/web");
    assert_eq!(found["repos"][1]["full_name"], "acme/web-api");

    let second = api.get("/api/repos?limit=1&offset=1").await.json();
    assert_eq!(
        (
            second["total"].clone(),
            second["limit"].clone(),
            second["offset"].clone()
        ),
        (json!(4), json!(1), json!(1))
    );
    assert_eq!(second["repos"].as_array().unwrap().len(), 1);
    assert_eq!(second["repos"][0]["full_name"], "acme/web");

    let none = api.get("/api/repos?query=nothing").await.json();
    assert_eq!(
        (none["total"].clone(), none["repos"].clone()),
        (json!(0), json!([]))
    );
    // The sources still say how current the lists are, so an empty page is never unexplained.
    assert_eq!(none["sources"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn one_identitys_page_reads_and_shows_only_its_lists() {
    let api = start().await;
    let work = make(&api, "Work").await;
    let mine = make(&api, "Mine").await;
    api.repos.set_lists(vec![
        list(work, vec![repo("acme/web", Role::Write)]),
        list(
            mine,
            vec![repo("me/notes", Role::Admin), repo("acme/web", Role::Read)],
        ),
    ]);

    let body = api.get(&format!("/api/repos?identity={mine}")).await.json();

    let sources: Vec<_> = body["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["identity_id"].as_i64().unwrap())
        .collect();
    assert_eq!(sources, [mine]);
    assert_eq!(body["total"], 2);
    assert_eq!(
        api.repos.reads(),
        [Read {
            only: Some(IdentityId(mine)),
            freshness: Freshness::Cached
        }]
    );

    let unknown = api.get("/api/repos?identity=999").await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.json()["error"], "not_found");
}

#[tokio::test]
async fn a_credential_that_cannot_be_listed_says_why_instead_of_showing_an_empty_list() {
    let api = start().await;
    let work = make(&api, "Work").await;
    api.repos.set_lists(vec![SourceList {
        identity: IdentityId(work),
        credential: 0,
        host: "dev.azure.com".to_owned(),
        organisation: None,
        state: ListState::Unavailable,
        refreshed_at: None,
        retry_at: None,
        problem: Some(Problem {
            kind: ProblemKind::OrganisationNeeded,
            message: "Azure DevOps shows the organisations of an account only to a Microsoft Entra sign-in".to_owned(),
            retry_at: None,
            needs_sign_in: false,
        }),
        notes: Vec::new(),
        repos: Arc::from(Vec::new()),
    }]);

    let body = api.get("/api/repos").await.json();

    assert_eq!(body["total"], 0);
    assert_eq!(body["sources"][0]["state"], "unavailable");
    assert_eq!(body["sources"][0]["problem"]["code"], "organisation_needed");
    assert_eq!(body["sources"][0]["refreshed_at"], Value::Null);
}

#[tokio::test]
async fn a_query_outside_the_limits_is_refused_with_the_way_out() {
    let api = start().await;
    for (path, message) in [
        ("/api/repos?limit=0", "limit must be between 1 and 500"),
        ("/api/repos?limit=501", "limit must be between 1 and 500"),
    ] {
        let reply = api.get(path).await;
        assert_eq!(reply.status, 422, "{path}");
        assert_eq!(reply.json()["message"], message);
    }
    let long = api
        .get(&format!("/api/repos?query={}", "x".repeat(201)))
        .await;
    assert_eq!(long.status, 422);
    assert_eq!(long.json()["message"], "query is at most 200 bytes");
    let unknown = api.get("/api/repos?nope=1").await;
    assert_eq!(unknown.status, 400);
}

#[tokio::test]
async fn a_refresh_reads_again_and_answers_how_current_each_list_is() {
    let api = start().await;
    let work = make(&api, "Work").await;
    let mine = make(&api, "Mine").await;
    api.repos.set_lists(vec![
        list(work, vec![repo("acme/web", Role::Write)]),
        list(mine, vec![repo("me/notes", Role::Admin)]),
    ]);

    let all = api
        .send("POST", "/api/repos/refresh", Some(&json!({})))
        .await;
    assert_eq!(all.status, 200, "{}", all.body);
    assert_eq!(all.json()["sources"].as_array().unwrap().len(), 2);
    assert_eq!(all.json()["sources"][0]["repo_count"], 1);

    let one = api
        .send(
            "POST",
            "/api/repos/refresh",
            Some(&json!({"identity_id": work})),
        )
        .await;
    assert_eq!(one.status, 200);
    assert_eq!(one.json()["sources"].as_array().unwrap().len(), 1);
    assert_eq!(one.json()["sources"][0]["identity_id"], work);

    assert_eq!(
        api.repos.reads(),
        [
            Read {
                only: None,
                freshness: Freshness::Reload
            },
            Read {
                only: Some(IdentityId(work)),
                freshness: Freshness::Reload
            },
        ]
    );

    let unknown = api
        .send(
            "POST",
            "/api/repos/refresh",
            Some(&json!({"identity_id": 999})),
        )
        .await;
    assert_eq!(unknown.status, 404);
    let extra = api
        .send("POST", "/api/repos/refresh", Some(&json!({"all": true})))
        .await;
    assert_eq!(extra.status, 422, "{}", extra.body);
}

#[tokio::test]
async fn a_profile_prefills_the_author_and_offers_organisations_and_never_a_secret() {
    let api = start().await;
    let source = SourceSpec::Gh {
        host: HostName::new("github.com").unwrap(),
        account: AccountName::new("me").unwrap(),
    };
    api.repos.set_profile(
        source,
        ProfileRead {
            profile: Profile {
                account: Some("octocat".to_owned()),
                name: Some("The Octocat".to_owned()),
                email: Some("583231+octocat@users.noreply.github.com".to_owned()),
                organisations: vec!["github".to_owned(), "acme-corp".to_owned()],
                notes: vec![Note {
                    kind: NoteKind::OrganisationsMayBeHidden,
                    message: "some organisations may be hidden".to_owned(),
                }],
            },
            problem: None,
        },
    );

    let reply = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(&json!({"source": gh_source()})),
        )
        .await;

    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.json(),
        json!({
            "account": "octocat",
            "name": "The Octocat",
            "email": "583231+octocat@users.noreply.github.com",
            "organisations": ["github", "acme-corp"],
            "notes": [{"code": "organisations_may_be_hidden", "message": "some organisations may be hidden"}],
            "problem": null
        })
    );
}

#[tokio::test]
async fn a_profile_that_cannot_be_read_answers_with_the_reason_and_whether_to_sign_in() {
    let api = start().await;
    let source = SourceSpec::Gh {
        host: HostName::new("github.com").unwrap(),
        account: AccountName::new("me").unwrap(),
    };
    api.repos.set_profile(
        source,
        ProfileRead {
            profile: Profile::default(),
            problem: Some(Problem {
                kind: ProblemKind::NotSignedIn,
                message: "not signed in, or the sign-in has expired".to_owned(),
                retry_at: None,
                needs_sign_in: true,
            }),
        },
    );
    let reply = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(&json!({"source": gh_source()})),
        )
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({
            "account": null, "name": null, "email": null, "organisations": [], "notes": [],
            "problem": {"code": "not_signed_in", "message": "not signed in, or the sign-in has expired", "needs_sign_in": true}
        })
    );
    // A credential the fake host knows nothing of still gets an answer with a reason.
    let other = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(
                &json!({"source": {"kind": "gh", "host": "github.com", "account": "someone-else"}}),
            ),
        )
        .await;
    assert_eq!(other.json()["problem"]["code"], "unreachable");
}

#[tokio::test]
async fn a_source_off_the_closed_list_is_refused_before_anything_is_read() {
    let api = start().await;
    let reply = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(&json!({"source": {"kind": "command", "command": "curl evil"}})),
        )
        .await;
    assert!(reply.status == 400 || reply.status == 422, "{}", reply.body);
    let bad_host = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(&json!({"source": {"kind": "gh", "host": "-x", "account": "me"}})),
        )
        .await;
    assert_eq!(bad_host.status, 422);
}

#[tokio::test]
async fn without_repository_lists_every_call_says_so() {
    let api = start_without_repos().await;
    let list = api.get("/api/repos").await;
    assert_eq!(list.status, 503);
    assert_eq!(list.json()["error"], "unavailable");
    assert_eq!(
        list.json()["message"],
        "repository lists are not available in this build yet"
    );
    let refresh = api
        .send("POST", "/api/repos/refresh", Some(&json!({})))
        .await;
    assert_eq!(refresh.status, 503);
    let profile = api
        .send(
            "POST",
            "/api/credentials/profile",
            Some(&json!({"source": gh_source()})),
        )
        .await;
    assert_eq!(profile.status, 503);
}

#[test]
fn the_fake_describes_itself_without_a_list() {
    let fake: Arc<dyn RepoService> = Arc::new(FakeRepos::new());
    drop(fake);
    assert_eq!(format!("{:?}", FakeRepos::new()), "FakeRepos { .. }");
}
