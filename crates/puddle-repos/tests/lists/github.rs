// SPDX-License-Identifier: GPL-3.0-or-later
//! GitHub lists: paging, mapping, which API a host has, what a list says about itself.

use puddle_repos::{
    ApiReply, Freshness, ListState, NoteKind, ProblemKind, Role, TransportError, Visibility,
};

use crate::common::{REPOS_PATH, Rig, T0, binding, gcm, gh, identities, ok_json, stored};

const PAGE2: &str = "/user/repos?per_page=100&sort=full_name&direction=asc&page=2";
const CANARY: &str = "CANARY-gh-token-41c7";

fn link_to(url: &str) -> String {
    format!(r#"<{url}>; rel="next", <{url}>; rel="last""#)
}

fn rig_with_two_pages() -> Rig {
    let rig = Rig::new();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page1.json").with_header(
            "link",
            &link_to("https://api.github.com/user/repos?per_page=100&sort=full_name&direction=asc&page=2"),
        ),
    );
    rig.api.reply(
        "api.github.com",
        PAGE2,
        ok_json("github_user_repos_page2.json"),
    );
    rig
}

#[tokio::test]
async fn a_gh_account_lists_what_it_reaches_over_every_page_and_the_token_goes_to_the_api_host_only()
 {
    let rig = rig_with_two_pages();
    let source = gh("github.com", "octocat");
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists.len(), 1);
    let list = &lists[0];
    assert_eq!(list.state, ListState::Ok);
    assert_eq!(list.refreshed_at, Some(T0));
    assert_eq!((list.credential, list.host.as_str()), (0, "github.com"));
    assert_eq!(list.organisation, None);
    assert!(list.problem.is_none() && list.retry_at.is_none());
    let names: Vec<&str> = list.repos.iter().map(|r| r.full_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "octocat/Hello-World",
            "Acme-Corp/acme-secret",
            "acme-corp/docs",
            "acme-corp/intranet"
        ]
    );
    let hello = &list.repos[0];
    assert_eq!(hello.url, "https://github.com/octocat/Hello-World");
    assert_eq!(
        (
            hello.owner.as_str(),
            hello.name.as_str(),
            hello.project.as_ref()
        ),
        ("octocat", "Hello-World", None)
    );
    assert_eq!(
        (hello.visibility, hello.role, hello.archived, hello.fork),
        (Visibility::Public, Role::Admin, false, false)
    );
    let secret = &list.repos[1];
    assert_eq!(
        (secret.visibility, secret.role, secret.archived, secret.fork),
        (Visibility::Private, Role::Write, true, true)
    );
    // `private: true` with no `visibility`, and a role read from `pull` alone.
    assert_eq!(
        (list.repos[2].visibility, list.repos[2].role),
        (Visibility::Private, Role::Read)
    );
    // An enterprise `internal` repository with no permissions object.
    assert_eq!(
        (list.repos[3].visibility, list.repos[3].role),
        (Visibility::Internal, Role::Unknown)
    );
    // A sign-in through an app can miss restricted organisations, and the list says so.
    assert_eq!(
        list.notes.iter().map(|n| n.kind).collect::<Vec<_>>(),
        [NoteKind::OrganisationsMayBeHidden]
    );

    let seen = rig.api.seen();
    assert_eq!(
        seen.iter()
            .map(|s| (s.host.as_str(), s.path.as_str()))
            .collect::<Vec<_>>(),
        [("api.github.com", REPOS_PATH), ("api.github.com", PAGE2)]
    );
    assert!(seen.iter().all(|s| s.token == CANARY));
    assert!(!format!("{lists:?}").contains(CANARY));
}

#[tokio::test]
async fn a_next_page_on_another_address_is_refused_and_the_token_never_goes_there() {
    for evil in [
        "https://evil.example/user/repos?page=2",
        "https://api.github.com.evil.example/user/repos?page=2",
        "https://api.github.com/user/other?page=2",
        "https://api.github.com/user/repos/../../x",
        "http://api.github.com/user/repos?page=2",
    ] {
        let rig = Rig::new();
        rig.api.reply(
            "api.github.com",
            REPOS_PATH,
            ok_json("github_user_repos_page1.json").with_header("link", &link_to(evil)),
        );
        let source = gh("github.com", "octocat");
        rig.tokens.set(&source, CANARY);
        let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

        let lists = rig.lists(&ids, Freshness::Cached).await;

        let problem = lists[0].problem.as_ref().expect(evil);
        assert_eq!(problem.kind, ProblemKind::BadAnswer, "{evil}");
        assert!(problem.message.contains("another address"), "{evil}");
        assert_eq!(lists[0].state, ListState::Failed, "{evil}");
        assert_eq!(
            rig.api.count(),
            1,
            "{evil}: nothing was asked after the first page"
        );
    }
}

#[tokio::test]
async fn a_next_page_that_stays_on_the_host_and_the_listing_is_followed_whatever_the_case() {
    let rig = Rig::new();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page1.json")
            .with_header("Link", &link_to("HTTPS://API.GITHUB.COM/user/repos?per_page=100&sort=full_name&direction=asc&page=2")),
    );
    rig.api.reply(
        "api.github.com",
        PAGE2,
        ok_json("github_user_repos_page2.json"),
    );
    let source = gh("github.com", "octocat");
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].repos.len(), 4);
}

#[tokio::test]
async fn a_list_stops_at_three_thousand_repositories_and_says_so() {
    let rig = Rig::new();
    let next = |page: usize| {
        link_to(&format!(
            "https://api.github.com/user/repos?per_page=100&sort=full_name&direction=asc&page={page}"
        ))
    };
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json").with_header("link", &next(2)),
    );
    for page in 2..=30 {
        rig.api.reply(
            "api.github.com",
            &format!("{REPOS_PATH}&page={page}"),
            ok_json("github_user_repos_page2.json").with_header("link", &next(page + 1)),
        );
    }
    let source = stored("tok-1", "github.com", None);
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(rig.api.count(), 30);
    assert_eq!(lists[0].state, ListState::Ok);
    assert_eq!(lists[0].repos.len(), 60);
    let kinds: Vec<_> = lists[0].notes.iter().map(|n| n.kind).collect();
    assert_eq!(kinds, [NoteKind::Truncated]);
    assert!(lists[0].notes[0].message.contains("3000"));
}

#[tokio::test]
async fn a_fine_grained_token_says_it_lists_only_what_it_was_granted() {
    let rig = Rig::new();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let source = stored("tok-1", "github.com", None);
    rig.tokens.set(&source, "github_pat_CANARY_fine");
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    let kinds: Vec<_> = lists[0].notes.iter().map(|n| n.kind).collect();
    assert_eq!(kinds, [NoteKind::FineGrainedToken]);
    assert_eq!(lists[0].repos.len(), 2);
}

#[tokio::test]
async fn github_saying_organisations_are_missing_for_single_sign_on_is_passed_on() {
    let rig = Rig::new();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json").with_header(
            "x-github-sso",
            "partial-results; organizations=21955855,20582480",
        ),
    );
    let source = stored("tok-1", "github.com", None);
    rig.tokens.set(&source, "ghp_CANARY_classic");
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    let kinds: Vec<_> = lists[0].notes.iter().map(|n| n.kind).collect();
    assert_eq!(kinds, [NoteKind::SsoPartial]);
    assert!(lists[0].notes[0].message.contains("single sign-on"));
}

#[tokio::test]
async fn an_enterprise_host_is_asked_on_its_own_name_under_api_v3_and_data_residency_hosts_on_api()
{
    let rig = Rig::new();
    rig.api.reply(
        "ghe.example.org",
        "/api/v3/user/repos?per_page=100&sort=full_name&direction=asc",
        ok_json("github_user_repos_page2.json"),
    );
    rig.api.reply(
        "api.octo.ghe.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let (enterprise, residency, pasted) = (
        gh("ghe.example.org", "me"),
        gcm("octo.ghe.com", "acme"),
        stored("tok-2", "ghe.example.org", None),
    );
    for source in [&enterprise, &residency, &pasted] {
        rig.tokens.set(source, CANARY);
    }
    let ids = identities(vec![(
        "Me",
        vec![
            binding("ghe.example.org", enterprise, &[], true),
            binding("octo.ghe.com", residency, &[], true),
            binding("ghe.example.org", pasted, &["acme"], false),
        ],
    )]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists[0].state, ListState::Ok);
    assert_eq!(
        lists[0].repos[0].url,
        "https://ghe.example.org/acme-corp/docs"
    );
    assert_eq!(lists[1].state, ListState::Ok);
    assert_eq!(lists[1].repos[0].url, "https://octo.ghe.com/acme-corp/docs");
    // A pasted token on a host that is not GitHub's is not guessed to be GitHub.
    assert_eq!(lists[2].state, ListState::Unavailable);
    assert_eq!(
        lists[2].problem.as_ref().unwrap().kind,
        ProblemKind::Unsupported
    );
    assert!(
        lists[2]
            .problem
            .as_ref()
            .unwrap()
            .message
            .contains("GitHub and Azure DevOps; ghe.example.org is neither")
    );
}

#[tokio::test]
async fn a_host_that_is_not_github_or_azure_devops_says_so_and_nothing_is_asked() {
    let rig = Rig::new();
    let source = stored("tok-1", "gitlab.com", None);
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("gitlab.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Reload).await;

    assert_eq!(lists[0].state, ListState::Unavailable);
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::Unsupported);
    assert!(!problem.needs_sign_in);
    assert!(lists[0].repos.is_empty() && lists[0].refreshed_at.is_none());
    assert_eq!(rig.api.count(), 0);
}

#[tokio::test]
async fn a_credential_for_another_host_than_its_binding_is_never_sent_there() {
    // A store edited by hand can hold a binding whose source is for another host.
    let mismatched: puddle_store::CredentialBinding = serde_json::from_value(serde_json::json!({
        "host": "github.com",
        "source": {"kind": "gh", "host": "gitlab.example", "account": "me"},
        "covers": {"owners": [], "rest_of_host": true}
    }))
    .unwrap();
    let rig = Rig::new();
    let ids = identities(vec![("Me", vec![mismatched])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists[0].state, ListState::Unavailable);
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::WrongTarget);
    assert!(
        problem
            .message
            .contains("is for gitlab.example, not github.com")
    );
    assert_eq!(rig.api.count(), 0);
}

#[tokio::test]
async fn an_answer_that_is_not_the_documented_list_is_a_bad_answer_never_a_partial_list() {
    for (body, why) in [
        (r#"{"message":"not a list"}"#, "not an array"),
        (r#"[{"full_name":"no-slash"}]"#, "no owner"),
        (r#"[{"full_name":"../x/y"}]"#, "a dot segment"),
        (r#"[{"full_name":"a/b/c"}]"#, "too many segments"),
        (r#"[{"full_name":"a b/c"}]"#, "a space"),
        (r#"[{"name":"x"}]"#, "no full name"),
    ] {
        let rig = Rig::new();
        rig.api
            .reply("api.github.com", REPOS_PATH, ApiReply::new(200, body));
        let source = gh("github.com", "octocat");
        rig.tokens.set(&source, CANARY);
        let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

        let lists = rig.lists(&ids, Freshness::Cached).await;

        assert_eq!(lists[0].state, ListState::Failed, "{why}");
        assert_eq!(
            lists[0].problem.as_ref().unwrap().kind,
            ProblemKind::BadAnswer,
            "{why}"
        );
    }
}

#[tokio::test]
async fn an_answer_with_no_visibility_or_privacy_has_an_unknown_visibility() {
    let rig = Rig::new();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ApiReply::new(200, r#"[{"full_name":"a/b"}]"#),
    );
    let source = gh("github.com", "octocat");
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].repos[0].visibility, Visibility::Unknown);
}

#[tokio::test]
async fn the_roles_follow_the_permission_flags_from_the_top() {
    let rig = Rig::new();
    let body = r#"[
        {"full_name":"a/admin","permissions":{"admin":true}},
        {"full_name":"a/maintain","permissions":{"maintain":true,"push":true}},
        {"full_name":"a/write","permissions":{"push":true}},
        {"full_name":"a/triage","permissions":{"triage":true,"pull":true}},
        {"full_name":"a/read","permissions":{"pull":true}},
        {"full_name":"a/none","permissions":{}}
    ]"#;
    rig.api
        .reply("api.github.com", REPOS_PATH, ApiReply::new(200, body));
    let source = gh("github.com", "octocat");
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    let roles: Vec<Role> = lists[0].repos.iter().map(|r| r.role).collect();
    assert_eq!(
        roles,
        [
            Role::Admin,
            Role::Maintain,
            Role::Write,
            Role::Triage,
            Role::Read,
            Role::Unknown
        ]
    );
}

#[tokio::test]
async fn a_host_that_cannot_be_reached_says_which_and_why() {
    let rig = Rig::new();
    rig.api.fail(
        "api.github.com",
        REPOS_PATH,
        TransportError::Tls("invalid peer certificate: UnknownIssuer".to_owned()),
    );
    let source = gh("github.com", "octocat");
    rig.tokens.set(&source, CANARY);
    let ids = identities(vec![("Me", vec![binding("github.com", source, &[], true)])]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::Unreachable);
    assert_eq!(
        problem.message,
        "the connection to api.github.com is not trusted: invalid peer certificate: UnknownIssuer; if the company network re-signs HTTPS, its root certificate must be trusted by this computer"
    );
}
