// SPDX-License-Identifier: GPL-3.0-or-later
//! Who a credential's account is: the author and organisations an identity is prefilled with.

use puddle_repos::{ApiReply, NoteKind, ProblemKind};
use puddle_secrets::SourceError;

use crate::common::{Rig, T0, data, gcm, gh, ok_json, stored};

const CANARY: &str = "CANARY-profile-9d2e";
const ORGS: &str = "/user/orgs?per_page=100";

fn rig_with_account() -> Rig {
    let rig = Rig::new();
    rig.tokens.set(&gh("github.com", "octocat"), CANARY);
    rig.api
        .reply("api.github.com", "/user", ok_json("github_user.json"));
    rig
}

#[tokio::test]
async fn a_github_account_gives_its_name_a_private_address_and_its_organisations_over_every_page() {
    let rig = rig_with_account();
    rig.api.reply(
        "api.github.com",
        ORGS,
        ok_json("github_user_orgs_page1.json").with_header(
            "link",
            r#"<https://api.github.com/user/orgs?per_page=100&page=2>; rel="next""#,
        ),
    );
    rig.api.reply(
        "api.github.com",
        "/user/orgs?per_page=100&page=2",
        ok_json("github_user_orgs_page2.json"),
    );

    let read = rig.repos.profile(&gh("github.com", "octocat")).await;

    assert!(read.problem.is_none());
    let profile = read.profile;
    assert_eq!(profile.account.as_deref(), Some("octocat"));
    assert_eq!(profile.name.as_deref(), Some("The Octocat"));
    assert_eq!(
        profile.email.as_deref(),
        Some("583231+octocat@users.noreply.github.com")
    );
    assert_eq!(profile.organisations, ["github", "acme-corp", "Octo-Labs"]);
    // A sign-in through an app can miss organisations, and the profile says so too.
    assert_eq!(
        profile.notes.iter().map(|n| n.kind).collect::<Vec<_>>(),
        [NoteKind::OrganisationsMayBeHidden]
    );
    assert!(rig.api.seen().iter().all(|s| s.token == CANARY));
}

#[tokio::test]
async fn an_account_with_no_name_uses_its_login_and_an_enterprise_host_has_its_own_address() {
    let rig = Rig::new();
    let source = gh("ghe.example.org:8443", "me");
    rig.tokens.set(&source, CANARY);
    rig.api.reply(
        "ghe.example.org:8443",
        "/api/v3/user",
        ApiReply::new(200, r#"{"login":"me","id":7,"name":"  "}"#),
    );
    rig.api.reply(
        "ghe.example.org:8443",
        "/api/v3/user/orgs?per_page=100",
        ApiReply::new(200, "[]"),
    );

    let read = rig.repos.profile(&source).await;

    assert_eq!(read.profile.name.as_deref(), Some("me"));
    assert_eq!(
        read.profile.email.as_deref(),
        Some("7+me@users.noreply.ghe.example.org")
    );
    assert_eq!(read.profile.organisations, Vec::<String>::new());
}

#[tokio::test]
async fn organisations_that_cannot_be_listed_are_a_note_not_a_failed_profile() {
    let rig = rig_with_account();
    let pasted = stored("tok-1", "github.com", None);
    rig.tokens.set(&pasted, "ghp_CANARY_classic");
    rig.api.reply(
        "api.github.com",
        ORGS,
        ApiReply::new(
            403,
            r#"{"message":"Resource not accessible by personal access token"}"#,
        ),
    );

    let read = rig.repos.profile(&pasted).await;

    assert!(read.problem.is_none());
    assert_eq!(read.profile.account.as_deref(), Some("octocat"));
    assert_eq!(read.profile.organisations, Vec::<String>::new());
    assert_eq!(read.profile.notes.len(), 1);
    assert_eq!(
        read.profile.notes[0].kind,
        NoteKind::OrganisationsUnavailable
    );
    assert_eq!(
        read.profile.notes[0].message,
        "the organisations could not be listed: GitHub refused the request: Resource not accessible by personal access token"
    );
}

#[tokio::test]
async fn a_limit_while_asking_stops_the_profile_and_blocks_the_next_ask() {
    let rig = rig_with_account();
    rig.api.reply(
        "api.github.com",
        ORGS,
        ApiReply::new(403, data("github_rate_limit_secondary.json"))
            .with_header("retry-after", "90"),
    );

    let read = rig.repos.profile(&gh("github.com", "octocat")).await;

    let problem = read.problem.unwrap();
    assert_eq!(problem.kind, ProblemKind::RateLimited);
    assert_eq!(problem.retry_at, Some(T0 + 90_000));
    assert!(read.profile.account.is_none());
    let asked = rig.api.count();

    // Asking again before the wait ends sends nothing.
    rig.clock.advance(30_000);
    let again = rig.repos.profile(&gh("github.com", "octocat")).await;
    let problem = again.problem.unwrap();
    assert_eq!(problem.kind, ProblemKind::RateLimited);
    assert_eq!(problem.retry_at, Some(T0 + 90_000));
    assert_eq!(rig.api.count(), asked);
}

#[tokio::test]
async fn a_rejected_token_is_forgotten_by_the_cache_unless_it_was_pasted() {
    let rig = Rig::new();
    let signed_in = gh("github.com", "octocat");
    let pasted = stored("tok-1", "github.com", None);
    rig.tokens.set(&signed_in, CANARY);
    rig.tokens.set(&pasted, CANARY);
    rig.api.reply(
        "api.github.com",
        "/user",
        ApiReply::new(401, r#"{"message":"Bad credentials"}"#),
    );

    let a = rig.repos.profile(&signed_in).await;
    let b = rig.repos.profile(&pasted).await;

    assert_eq!(a.problem.as_ref().unwrap().kind, ProblemKind::TokenRejected);
    assert!(a.problem.unwrap().needs_sign_in);
    assert!(!b.problem.unwrap().needs_sign_in);
    assert_eq!(rig.tokens.invalidated(), [signed_in]);
}

#[tokio::test]
async fn a_source_that_cannot_be_read_and_a_host_that_is_neither_github_nor_azure_say_so() {
    let rig = Rig::new();
    let read = rig.repos.profile(&gh("github.com", "nobody")).await;
    assert_eq!(read.problem.unwrap().kind, ProblemKind::NotSignedIn);

    let source = stored("tok-1", "github.com", None);
    rig.tokens.fail(&source, SourceError::StoreUnavailable);
    let read = rig.repos.profile(&source).await;
    assert_eq!(read.problem.unwrap().kind, ProblemKind::SourceUnavailable);

    let read = rig
        .repos
        .profile(&stored("tok-2", "gitlab.com", None))
        .await;
    assert_eq!(read.problem.unwrap().kind, ProblemKind::Unsupported);
    assert_eq!(rig.api.count(), 0);
}

#[tokio::test]
async fn a_profile_that_is_not_what_github_documents_is_a_bad_answer() {
    let rig = Rig::new();
    rig.tokens.set(&gh("github.com", "octocat"), CANARY);
    rig.api
        .reply("api.github.com", "/user", ApiReply::new(200, "[]"));
    let read = rig.repos.profile(&gh("github.com", "octocat")).await;
    assert_eq!(read.problem.unwrap().kind, ProblemKind::BadAnswer);

    let rig = rig_with_account();
    rig.api.reply(
        "api.github.com",
        ORGS,
        ApiReply::new(200, r#"{"not":"a list"}"#),
    );
    let read = rig.repos.profile(&gh("github.com", "octocat")).await;
    // The account is known; only the organisations are missing, and the note says why.
    assert!(read.problem.is_none());
    assert_eq!(
        read.profile.notes[0].kind,
        NoteKind::OrganisationsUnavailable
    );
}

#[tokio::test]
async fn an_azure_devops_credential_offers_its_organisation_and_says_the_author_is_yours_to_enter()
{
    let rig = Rig::new();
    let pasted = stored("tok-1", "dev.azure.com", Some("Acme"));
    let git = gcm("dev.azure.com", "Contoso/Fabrikam");

    let from_token = rig.repos.profile(&pasted).await;
    let from_git = rig.repos.profile(&git).await;

    assert!(from_token.problem.is_none() && from_git.problem.is_none());
    assert_eq!(from_token.profile.organisations, ["acme"]);
    assert_eq!(from_git.profile.organisations, ["contoso"]);
    assert!(from_token.profile.account.is_none() && from_token.profile.email.is_none());
    assert_eq!(from_token.profile.notes.len(), 1);
    assert_eq!(
        from_token.profile.notes[0].kind,
        NoteKind::AuthorUnavailable
    );
    assert!(
        from_token.profile.notes[0]
            .message
            .contains("Microsoft Entra")
    );
    assert_eq!(rig.api.count(), 0, "nothing is asked of Azure DevOps");
    // A token with no organisation has none to offer.
    let none = rig
        .repos
        .profile(&stored("tok-2", "dev.azure.com", None))
        .await;
    assert_eq!(none.profile.organisations, Vec::<String>::new());
}
