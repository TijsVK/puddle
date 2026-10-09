// SPDX-License-Identifier: GPL-3.0-or-later
//! Azure DevOps lists: one call per organisation a credential names, the sign-in page a bad token
//! gets, and a credential that names no organisation.

use puddle_repos::{ApiReply, Freshness, ListState, ProblemKind, Role, Visibility};
use puddle_store::RepoRef;

use crate::common::{Rig, binding, data, gcm, identities, ok_json, stored};

const LIST: &str = "/acme/_apis/git/repositories?api-version=7.1";
const PAT: &str = "CANARY-ado-pat-0f3a";

fn json(name: &str) -> ApiReply {
    ok_json(name).with_header("content-type", "application/json; charset=utf-8")
}

#[tokio::test]
async fn a_pasted_token_lists_its_organisation_in_one_call_with_addresses_that_clone() {
    let rig = Rig::new();
    rig.api
        .reply("dev.azure.com", LIST, json("azure_repositories.json"));
    let source = stored("tok-1", "dev.azure.com", Some("acme"));
    rig.tokens.set(&source, PAT);
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["acme"], false)],
    )]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists.len(), 1);
    let list = &lists[0];
    assert_eq!(list.state, ListState::Ok);
    assert_eq!(list.organisation.as_deref(), Some("acme"));
    assert_eq!(list.host, "dev.azure.com");
    assert_eq!(list.notes, [], "a pasted token has nothing standing to say");
    let names: Vec<&str> = list.repos.iter().map(|r| r.full_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "acme/Fabrikam Fiber/AnotherRepository",
            "acme/Web/Web",
            "acme/Web/Tools"
        ]
    );
    let another = &list.repos[0];
    assert_eq!(
        another.url,
        "https://dev.azure.com/acme/Fabrikam%20Fiber/_git/AnotherRepository"
    );
    assert_eq!(another.project.as_deref(), Some("Fabrikam Fiber"));
    assert_eq!(
        (
            another.visibility,
            another.role,
            another.archived,
            another.fork
        ),
        (Visibility::Private, Role::Unknown, false, false)
    );
    let web = &list.repos[1];
    assert_eq!(
        (web.visibility, web.archived, web.fork),
        (Visibility::Public, true, true)
    );
    assert_eq!(list.repos[2].visibility, Visibility::Unknown);

    // One call, as a personal access token: the password of a Basic header.
    let seen = rig.api.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (
            seen[0].host.as_str(),
            seen[0].path.as_str(),
            seen[0].token.as_str(),
            seen[0].bearer
        ),
        ("dev.azure.com", LIST, PAT, false)
    );

    // What is listed is what the create form takes: the table's own parser reads these
    // addresses, except a project with a space, which the table cannot hold.
    assert_eq!(
        RepoRef::from_https_url(&list.repos[2].url)
            .unwrap()
            .to_string(),
        "dev.azure.com/acme/web/tools"
    );
    assert!(RepoRef::from_https_url(&another.url).is_err());
}

#[tokio::test]
async fn an_entra_token_goes_as_bearer() {
    let rig = Rig::new();
    rig.api
        .reply("dev.azure.com", LIST, json("azure_repositories.json"));
    let source = gcm("dev.azure.com", "acme");
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";
    rig.tokens.set(&source, jwt);
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["acme"], false)],
    )]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists[0].state, ListState::Ok);
    assert!(rig.api.seen()[0].bearer);
    // A sign-in through Git Credential Manager is not a pasted token, so it says what it cannot
    // see; on Azure DevOps that is nothing a note can name.
    assert_eq!(lists[0].notes, []);
}

#[tokio::test]
async fn things_that_only_look_like_an_entra_token_stay_basic() {
    for token in [
        "plainpatwithnodots",
        "eyJhbGciOiJSUzI1NiJ9.onlytwo",
        "notjwt.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
        "eyJhbGciOi.has space.c2ln",
        "eyJhbGciOi..c2ln",
    ] {
        let rig = Rig::new();
        rig.api
            .reply("dev.azure.com", LIST, json("azure_repositories.json"));
        let source = stored("tok-1", "dev.azure.com", Some("acme"));
        rig.tokens.set(&source, token);
        let ids = identities(vec![(
            "Work",
            vec![binding("dev.azure.com", source, &["acme"], false)],
        )]);
        rig.lists(&ids, Freshness::Cached).await;
        assert!(!rig.api.seen()[0].bearer, "{token}");
    }
}

#[tokio::test]
async fn a_credential_covering_several_organisations_has_a_list_for_each() {
    let rig = Rig::new();
    rig.api
        .reply("dev.azure.com", LIST, json("azure_repositories.json"));
    rig.api.reply(
        "dev.azure.com",
        "/contoso/_apis/git/repositories?api-version=7.1",
        ApiReply::new(200, r#"{"count":0,"value":[]}"#)
            .with_header("content-type", "application/json"),
    );
    let source = gcm("dev.azure.com", "acme");
    rig.tokens
        .set(&source, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl");
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["contoso"], false)],
    )]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    // The credential's own organisation (its path) and the one it covers.
    let orgs: Vec<_> = lists
        .iter()
        .map(|l| l.organisation.clone().unwrap())
        .collect();
    assert_eq!(orgs, ["acme", "contoso"]);
    assert_eq!(lists[0].repos.len(), 3);
    assert!(lists[1].repos.is_empty());
    assert!(
        lists
            .iter()
            .all(|l| l.state == ListState::Ok && l.credential == 0)
    );
}

#[tokio::test]
async fn a_pasted_token_for_one_organisation_lists_only_that_one() {
    let rig = Rig::new();
    rig.api
        .reply("dev.azure.com", LIST, json("azure_repositories.json"));
    let source = stored("tok-1", "dev.azure.com", Some("acme"));
    rig.tokens.set(&source, PAT);
    // Coverage of a token for one organisation can only be that organisation (the store
    // refuses anything else), so the list is for it and for no other.
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["acme"], false)],
    )]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists.len(), 1);
    assert_eq!(rig.api.count(), 1);
}

#[tokio::test]
async fn a_credential_that_names_no_organisation_says_what_azure_devops_needs() {
    let rig = Rig::new();
    let source = stored("tok-1", "dev.azure.com", None);
    rig.tokens.set(&source, PAT);
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &[], true)],
    )]);

    let lists = rig.lists(&ids, Freshness::Reload).await;

    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].state, ListState::Unavailable);
    assert_eq!(lists[0].organisation, None);
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::OrganisationNeeded);
    assert!(problem.message.contains("Microsoft Entra sign-in"));
    assert!(problem.message.contains("add the organisation"));
    assert_eq!(
        rig.api.count(),
        0,
        "nothing is asked, and the answer is not an empty list"
    );
}

#[tokio::test]
async fn the_gh_cli_has_nothing_to_say_about_azure_devops() {
    let rig = Rig::new();
    let source = crate::common::gh("dev.azure.com", "me");
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &[], true)],
    )]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].state, ListState::Unavailable);
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::Unsupported);
    assert!(
        problem
            .message
            .starts_with("the GitHub CLI signs in to GitHub hosts")
    );
}

#[tokio::test]
async fn the_sign_in_page_azure_devops_answers_a_bad_token_with_is_a_rejected_token() {
    for reply in [
        ApiReply::new(203, data("azure_sign_in.html")).with_header("content-type", "text/html"),
        ApiReply::new(200, data("azure_sign_in.html")).with_header("content-type", "text/html"),
        ApiReply::new(302, "").with_header(
            "location",
            "https://spsprodweu5.vssps.visualstudio.com/_signin",
        ),
        ApiReply::new(401, ""),
    ] {
        let rig = Rig::new();
        rig.api.reply("dev.azure.com", LIST, reply);
        let source = stored("tok-1", "dev.azure.com", Some("acme"));
        rig.tokens.set(&source, PAT);
        let ids = identities(vec![(
            "Work",
            vec![binding("dev.azure.com", source, &["acme"], false)],
        )]);
        let lists = rig.lists(&ids, Freshness::Cached).await;
        let problem = lists[0].problem.as_ref().unwrap();
        assert_eq!(problem.kind, ProblemKind::TokenRejected);
        assert!(
            problem
                .message
                .starts_with("Azure DevOps did not accept the token")
        );
        assert!(problem.message.ends_with("paste a new token"));
        assert!(
            rig.tokens.invalidated().is_empty(),
            "a pasted token is not cached to forget"
        );
    }
}

#[tokio::test]
async fn an_organisation_the_token_cannot_see_is_named_and_a_limit_waits() {
    let rig = Rig::new();
    rig.api.reply("dev.azure.com", LIST, ApiReply::new(404, ""));
    rig.api.reply(
        "dev.azure.com",
        "/other/_apis/git/repositories?api-version=7.1",
        ApiReply::new(429, "").with_header("retry-after", "45"),
    );
    let source = gcm("dev.azure.com", "acme");
    rig.tokens
        .set(&source, "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl");
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["other"], false)],
    )]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists[0].organisation.as_deref(), Some("acme"));
    let missing = lists[0].problem.as_ref().unwrap();
    assert_eq!(missing.kind, ProblemKind::NotFound);
    assert_eq!(
        missing.message,
        "Azure DevOps has no organisation acme that this token can see"
    );
    assert_eq!(
        lists[1].problem.as_ref().unwrap().kind,
        ProblemKind::RateLimited
    );
    assert_eq!(lists[1].retry_at, Some(crate::common::T0 + 45_000));
}

#[tokio::test]
async fn an_answer_that_is_not_the_documented_list_is_refused() {
    for body in [
        r#"{"value":[{"name":"x"}]}"#,
        r#"["not","an","object"]"#,
        r#"{"count":0}"#,
    ] {
        let rig = Rig::new();
        rig.api.reply(
            "dev.azure.com",
            LIST,
            ApiReply::new(200, body).with_header("content-type", "application/json"),
        );
        let source = stored("tok-1", "dev.azure.com", Some("acme"));
        rig.tokens.set(&source, PAT);
        let ids = identities(vec![(
            "Work",
            vec![binding("dev.azure.com", source, &["acme"], false)],
        )]);
        let lists = rig.lists(&ids, Freshness::Cached).await;
        assert_eq!(
            lists[0].problem.as_ref().unwrap().kind,
            ProblemKind::BadAnswer,
            "{body}"
        );
    }
}

#[tokio::test]
async fn a_very_large_organisation_is_cut_at_five_thousand_and_says_so() {
    let rows: Vec<String> = (0..5001)
        .map(|n| format!(r#"{{"name":"r{n}","project":{{"name":"p","visibility":"private"}}}}"#))
        .collect();
    let body = format!(r#"{{"value":[{}]}}"#, rows.join(","));
    let rig = Rig::new();
    rig.api.reply(
        "dev.azure.com",
        LIST,
        ApiReply::new(200, body).with_header("content-type", "application/json"),
    );
    let source = stored("tok-1", "dev.azure.com", Some("acme"));
    rig.tokens.set(&source, PAT);
    let ids = identities(vec![(
        "Work",
        vec![binding("dev.azure.com", source, &["acme"], false)],
    )]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].repos.len(), 5000);
    assert_eq!(lists[0].notes[0].kind, puddle_repos::NoteKind::Truncated);
}
