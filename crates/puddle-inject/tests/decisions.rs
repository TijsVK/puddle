// SPDX-License-Identifier: GPL-3.0-or-later
//! What the injector decides for a request on a decrypted Git host: the workspace's own header
//! passes unchanged, a request with none gets the credential of the identity that covers its
//! owner, the repository table gates every push and (when asked) pull, and every refusal says
//! why in one line.
mod support;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use puddle_inject::testing::{StaticSettings, World};
use puddle_inject::{CredentialSource, GitInjector, StoreSettings};
use puddle_proxy::{InjectContext, InjectDecision, Injector as _, RequestView};
use puddle_secrets::{
    Credential, Fetch, Fetched, Secret, SecretCache, SourceError, SourceSpec, Tool,
};
use puddle_store::WorkspaceGit;
use puddle_types::{Event, GitAccess, Host};
use support::{Ask as _, basic, injected, refusal};

const FETCH: &str = "/acme/web.git/info/refs?service=git-upload-pack";
const PUSH_ADVERT: &str = "/acme/web.git/info/refs?service=git-receive-pack";
const OWN: &str = "authorization: Bearer the-workspaces-own-token";
const STAND_IN: &str =
    "authorization: Basic cHVkZGxlLXNlY3JldC1GT08tMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw";

fn token_header(token: &str) -> String {
    basic("x-access-token", token)
}

/// A workspace with Work (owns `acme`), Personal (the rest of github.com) and the workspace's own
/// repository `github.com/acme/web` listed with Pull and Push.
fn world() -> World {
    let w = World::new();
    w.identity("Work", "github.com", &["acme"], false, "CANARY-WORK");
    w.identity("Personal", "github.com", &[], true, "CANARY-PERSONAL");
    w.list("github.com/acme/web", true, true);
    w
}

// On a bound git path: the workspace's header passes unchanged, a request with none gets the
// credential, a stand-in is a header the workspace sent.

#[tokio::test]
async fn on_a_git_path_a_request_without_authorization_gets_the_covering_credential() {
    let w = world();
    let work = w.decide("github.com", "GET", FETCH, &[]).await;
    assert!(injected(&work, &token_header("CANARY-WORK")), "{work:?}");
    let InjectDecision::Inject(injection) = &work else {
        unreachable!()
    };
    assert!(injection.binding_id().starts_with("identity:"));
    assert!(injection.binding_id().ends_with(":github.com"));
    // An owner no identity names is covered by the rest of the host.
    let other = w
        .decide("github.com", "GET", "/someone/else.git/info/refs", &[])
        .await;
    assert!(
        injected(&other, &token_header("CANARY-PERSONAL")),
        "{other:?}"
    );
    assert_eq!(w.credentials.reads(), 2);
}

#[tokio::test]
async fn on_a_git_path_the_workspaces_own_authorization_passes_unchanged() {
    let w = world();
    for header in [
        OWN,
        STAND_IN,
        "Authorization: x",
        "AUTHORIZATION: Basic Zm9v",
    ] {
        for target in [FETCH, PUSH_ADVERT, "/acme/web.git/git-upload-pack"] {
            let method = if target.ends_with("pack") {
                "POST"
            } else {
                "GET"
            };
            let decision = w.decide("github.com", method, target, &[header]).await;
            assert!(
                matches!(decision, InjectDecision::PassThrough),
                "{method} {target} with {header}: {decision:?}"
            );
        }
    }
    assert_eq!(w.credentials.reads(), 0, "no secret was even read");
}

// On a bound host's other paths: nothing is added, whatever the header says.

#[tokio::test]
async fn on_a_bound_host_a_path_that_is_not_git_is_never_given_a_credential() {
    let w = world();
    for target in [
        "/acme/web/archive/refs/heads/main.zip",
        "/acme/web",
        "/",
        "/login/oauth/access_token",
        "/acme/web/blob/main/info/refs",
    ] {
        for headers in [&[][..], &[OWN][..], &[STAND_IN][..]] {
            let decision = w.decide("github.com", "GET", target, headers).await;
            assert!(
                matches!(decision, InjectDecision::PassThrough),
                "{target} with {headers:?}: {decision:?}"
            );
        }
    }
    assert_eq!(w.credentials.reads(), 0);
}

// The repository table.

#[tokio::test]
async fn a_push_to_a_listed_repository_goes_out_with_the_credential() {
    let w = world();
    for (method, target) in [
        ("GET", PUSH_ADVERT),
        ("POST", "/acme/web.git/git-receive-pack"),
        ("POST", "/ACME/Web/git-receive-pack"),
    ] {
        let decision = w.decide("github.com", method, target, &[]).await;
        assert!(
            injected(&decision, &token_header("CANARY-WORK")),
            "{target}: {decision:?}"
        );
    }
    assert_eq!(w.events.events(), []);
}

#[tokio::test]
async fn a_push_to_a_repository_that_is_not_listed_is_refused_and_says_how_to_add_it() {
    let w = world();
    let decision = w
        .decide(
            "github.com",
            "GET",
            "/acme/other.git/info/refs?service=git-receive-pack",
            &[],
        )
        .await;
    let (status, code, message) = refusal(&decision);
    assert_eq!((status, code), (403, "push_denied"));
    assert_eq!(
        message,
        "push to github.com/acme/other is not on this workspace's push list; add it, or turn off \"Only push to listed repos\" on the workspace's Git tab"
    );
    assert_eq!(
        w.events.take(),
        [Event::GitAccessDenied {
            workspace: w.workspace.clone(),
            host: "github.com".into(),
            owner: "acme".into(),
            repo: "other".into(),
            access: GitAccess::Push,
        }]
    );
    assert_eq!(w.credentials.reads(), 0, "the credential was never read");
    // The refusal holds whoever supplies the credential: the workspace's own header does not
    // get a push through, and a Pull-only row does not either.
    w.list("github.com/acme/readonly", true, false);
    for target in [
        "/acme/other.git/git-receive-pack",
        "/acme/readonly.git/git-receive-pack",
    ] {
        let decision = w.decide("github.com", "POST", target, &[OWN]).await;
        assert_eq!(refusal(&decision).1, "push_denied", "{target}");
    }
}

#[tokio::test]
async fn the_same_refusal_is_one_notice_not_a_flood_and_a_later_one_is_a_new_notice() {
    tokio::time::pause();
    let w = world();
    let target = "/acme/other.git/git-receive-pack";
    for _ in 0..5 {
        let _ = w.decide("github.com", "POST", target, &[]).await;
    }
    assert_eq!(w.events.take().len(), 1);
    // Another repository is another notice.
    let _ = w
        .decide(
            "github.com",
            "POST",
            "/acme/third.git/git-receive-pack",
            &[],
        )
        .await;
    assert_eq!(w.events.take().len(), 1);
    tokio::time::advance(Duration::from_secs(11)).await;
    let _ = w.decide("github.com", "POST", target, &[]).await;
    assert_eq!(w.events.take().len(), 1);
}

#[tokio::test]
async fn turning_off_the_push_list_lets_any_push_through_and_a_name_the_table_cannot_hold_is_refused_with_the_switch()
 {
    let w = world();
    let target = "/acme/other.git/git-receive-pack";
    w.switches(false, false);
    assert!(injected(
        &w.decide("github.com", "POST", target, &[]).await,
        &token_header("CANARY-WORK")
    ));
    // On again: a name the table has no spelling for can only be allowed by the switch.
    w.switches(true, false);
    let odd = w
        .decide(
            "dev.azure.com",
            "POST",
            "/org/My%20Project/_git/repo/git-receive-pack",
            &[],
        )
        .await;
    let (status, code, message) = refusal(&odd);
    assert_eq!((status, code), (403, "push_denied"));
    assert!(message.contains("cannot hold this name"), "{message}");
    assert!(message.contains("Only push to listed repos"), "{message}");
    assert!(
        w.events.take().is_empty(),
        "there is no row to add, so no notice"
    );
}

#[tokio::test]
async fn a_fetch_from_anywhere_is_allowed_until_the_pull_list_is_turned_on() {
    let w = world();
    let anywhere = "/someone/private.git/info/refs?service=git-upload-pack";
    assert!(injected(
        &w.decide("github.com", "GET", anywhere, &[]).await,
        &token_header("CANARY-PERSONAL")
    ));
    w.switches(true, true);
    let decision = w.decide("github.com", "GET", anywhere, &[]).await;
    let (status, code, message) = refusal(&decision);
    assert_eq!((status, code), (403, "pull_denied"));
    assert_eq!(
        message,
        "pull from github.com/someone/private is not on this workspace's pull list; add it, or turn off \"Only pull from listed repos\" on the workspace's Git tab"
    );
    assert!(matches!(
        w.events.take().as_slice(),
        [Event::GitAccessDenied { access: GitAccess::Pull, repo, .. }] if repo == "private"
    ));
    // A row with Pull off is refused too; the workspace's own header does not get past it.
    w.list("github.com/someone/pushonly", false, true);
    let decision = w
        .decide(
            "github.com",
            "POST",
            "/someone/pushonly.git/git-upload-pack",
            &[OWN],
        )
        .await;
    assert_eq!(refusal(&decision).1, "pull_denied");
    // Listed with Pull on, it goes out.
    let listed = w.decide("github.com", "GET", FETCH, &[]).await;
    assert!(injected(&listed, &token_header("CANARY-WORK")));
}

// Git LFS: a batch request reads or writes by its body.

#[tokio::test]
async fn an_lfs_batch_is_decided_by_its_operation() {
    let w = world();
    w.switches(true, false);
    let batch = "/someone/big.git/info/lfs/objects/batch";
    assert_eq!(w.body_wanted("github.com", "POST", batch), Some(256 * 1024));
    assert_eq!(w.body_wanted("github.com", "GET", batch), None);
    assert_eq!(w.body_wanted("github.com", "POST", FETCH), None);
    assert_eq!(
        w.body_wanted("github.com", "POST", "/acme/web/blob/main/x"),
        None
    );
    let download =
        br#"{"operation":"download","transfers":["basic"],"objects":[{"oid":"a","size":1}]}"#;
    let upload = br#"{"operation":"upload","objects":[{"oid":"a","size":1}]}"#;
    let ok = w
        .decide_with("github.com", "POST", batch, &[], Some(download))
        .await;
    assert!(injected(&ok, &token_header("CANARY-PERSONAL")), "{ok:?}");
    for body in [
        Some(&upload[..]),
        Some(&b"not json"[..]),
        Some(&b"{}"[..]),
        Some(&br#"{"operation":5}"#[..]),
        None,
    ] {
        let refused = w.decide_with("github.com", "POST", batch, &[], body).await;
        assert_eq!(refusal(&refused).1, "push_denied", "{body:?}");
    }
    // To a repository the push list names, an upload goes out.
    let own = "/acme/web.git/info/lfs/objects/batch";
    let allowed = w
        .decide_with("github.com", "POST", own, &[], Some(upload))
        .await;
    assert!(
        injected(&allowed, &token_header("CANARY-WORK")),
        "{allowed:?}"
    );
    // The other LFS calls are decided by what they do.
    for (method, target, code) in [
        (
            "PUT",
            "/someone/big.git/info/lfs/objects/abc",
            Some("push_denied"),
        ),
        (
            "POST",
            "/someone/big.git/info/lfs/objects/verify",
            Some("push_denied"),
        ),
        (
            "POST",
            "/someone/big.git/info/lfs/locks",
            Some("push_denied"),
        ),
        (
            "POST",
            "/someone/big.git/info/lfs/locks/9/unlock",
            Some("push_denied"),
        ),
        ("GET", "/someone/big.git/info/lfs/objects/abc", None),
        ("POST", "/someone/big.git/info/lfs/locks/verify", None),
        ("GET", "/someone/big.git/info/lfs/locks", None),
    ] {
        let decision = w.decide("github.com", method, target, &[]).await;
        match code {
            Some(code) => assert_eq!(refusal(&decision).1, code, "{method} {target}"),
            None => assert!(
                matches!(decision, InjectDecision::Inject(_)),
                "{method} {target}"
            ),
        }
    }
}

// Path tricks.

#[tokio::test]
async fn a_path_that_names_a_repository_two_ways_is_refused_before_anything_else() {
    let w = world();
    for target in [
        "/acme/web.git/../other.git/git-receive-pack",
        "/acme%2Fother/web.git/git-receive-pack",
        "/acme//web.git/git-receive-pack",
        "/acme\\other/web.git/git-receive-pack",
        "/acme/web.git/git-receive-pack%00",
        "/acme/%77eb.git/git-receive-pack",
    ] {
        for headers in [&[][..], &[OWN][..]] {
            let decision = w.decide("github.com", "POST", target, headers).await;
            let (status, code, message) = refusal(&decision);
            assert_eq!((status, code), (400, "bad_git_path"), "{target}");
            assert!(
                message.contains("nothing was sent to github.com"),
                "{message}"
            );
        }
    }
    assert_eq!(w.credentials.reads(), 0);
}

// Which identity.

#[tokio::test]
async fn a_request_no_identity_covers_goes_out_as_the_workspace_sent_it() {
    let w = World::new();
    w.identity("Work", "github.com", &["acme"], false, "CANARY-WORK");
    // The workspace may supply a token after the server's 401 (a credential helper, the
    // address's user name and password), so the request is neither given a credential nor
    // answered for.
    let decision = w
        .decide(
            "github.com",
            "GET",
            "/someone/private.git/info/refs?service=git-upload-pack",
            &[],
        )
        .await;
    assert!(
        matches!(decision, InjectDecision::PassThrough),
        "{decision:?}"
    );
    assert_eq!(w.credentials.reads(), 0);
    // A host no identity names at all.
    let other = w
        .decide(
            "gitlab.example",
            "GET",
            "/g/p.git/info/refs?service=git-upload-pack",
            &[],
        )
        .await;
    assert!(matches!(other, InjectDecision::PassThrough));
}

#[tokio::test]
async fn an_identity_is_picked_by_owner_and_changes_apply_at_the_next_request() {
    let w = world();
    let personal = w.store.identities().unwrap()[1].id;
    assert!(injected(
        &w.decide("github.com", "GET", "/acme/x.git/info/refs", &[])
            .await,
        &token_header("CANARY-WORK")
    ));
    // Detaching Work: acme falls to the rest of the host, at once.
    let work = w.store.identities().unwrap()[0].id;
    w.store.detach_identity(&w.workspace, work).unwrap();
    assert!(injected(
        &w.decide("github.com", "GET", "/acme/x.git/info/refs", &[])
            .await,
        &token_header("CANARY-PERSONAL")
    ));
    w.store.detach_identity(&w.workspace, personal).unwrap();
    assert!(matches!(
        w.decide("github.com", "GET", "/acme/x.git/info/refs", &[])
            .await,
        InjectDecision::PassThrough
    ));
}

#[tokio::test]
async fn two_candidates_are_refused_never_guessed() {
    let w = World::new();
    let a = w.identity_in_store("Work", "github.com", &["acme"], false, "CANARY-WORK", None);
    let b = w.identity_in_store(
        "Clash",
        "github.com",
        &["acme"],
        false,
        "CANARY-CLASH",
        None,
    );
    let mut git = WorkspaceGit::unconfigured();
    git.identities = vec![
        w.store.identity(a.id).unwrap(),
        w.store.identity(b.id).unwrap(),
    ];
    git.only_push_listed = false;
    let settings = StaticSettings::new(git);
    let injector = GitInjector::new(
        w.workspace.clone(),
        settings,
        w.credentials.clone(),
        w.events.clone(),
    );
    let host = Host::parse_normalised("github.com").unwrap();
    let context = InjectContext {
        workspace: &w.workspace,
        host: &host,
    };
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("GET", "/acme/web.git/info/refs", &lines);
    let decision = injector.decide(&context, &view).await;
    let (status, code, message) = refusal(&decision);
    assert_eq!((status, code), (409, "credential_ambiguous"));
    assert_eq!(
        message,
        "Work and Clash both cover github.com/acme; narrow one in puddle"
    );
    assert_eq!(w.credentials.reads(), 0);
}

// Azure DevOps.

#[tokio::test]
async fn azure_devops_takes_a_pat_as_basic_an_entra_token_as_a_bearer_and_every_host_name_of_the_org()
 {
    let w = World::new();
    w.identity("Contoso", "dev.azure.com", &["contoso"], false, "ADO-PAT");
    w.identity(
        "Fabrikam",
        "dev.azure.com",
        &["fabrikam"],
        false,
        "eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.c2ln",
    );
    w.switches(false, false);
    let pat = w
        .decide(
            "dev.azure.com",
            "GET",
            "/contoso/proj/_git/repo/info/refs?service=git-upload-pack",
            &[],
        )
        .await;
    assert!(injected(&pat, &basic("", "ADO-PAT")), "{pat:?}");
    let entra = w
        .decide(
            "dev.azure.com",
            "POST",
            "/fabrikam/_git/repo/git-upload-pack",
            &[],
        )
        .await;
    assert!(
        injected(&entra, "Bearer eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ.c2ln"),
        "{entra:?}"
    );
    // The same organisation by its other name.
    let old = w
        .decide(
            "contoso.visualstudio.com",
            "GET",
            "/proj/_git/repo/info/refs?service=git-upload-pack",
            &[],
        )
        .await;
    assert!(injected(&old, &basic("", "ADO-PAT")), "{old:?}");
    let elsewhere = w
        .decide(
            "other.visualstudio.com",
            "GET",
            "/proj/_git/repo/info/refs",
            &[],
        )
        .await;
    assert!(matches!(elsewhere, InjectDecision::PassThrough));
}

// A source that cannot supply its secret.

#[tokio::test]
async fn a_source_that_needs_a_sign_in_is_a_502_with_one_notice_and_never_a_401() {
    tokio::time::pause();
    let w = world();
    let work = &w.store.identities().unwrap()[0];
    let source = work.credentials[0].source.clone();
    w.credentials.fail(&source, SourceError::NotSignedIn);
    let decision = w.decide("github.com", "GET", FETCH, &[]).await;
    let (status, code, message) = refusal(&decision);
    assert_eq!((status, code), (502, "credential_unavailable"));
    assert!(message.contains("Work"), "{message}");
    assert!(message.contains("not signed in"), "{message}");
    assert!(message.contains("sign in to it in puddle"), "{message}");
    assert!(message.contains("t-work"), "names the source: {message}");
    let _ = w.decide("github.com", "GET", FETCH, &[]).await;
    assert_eq!(
        w.events.take(),
        [Event::CredentialSignInNeeded {
            host: "github.com".into(),
            source: source.describe(),
        }],
        "one notice for two requests"
    );
    // The same request with the workspace's own header does not need the source.
    assert!(matches!(
        w.decide("github.com", "GET", FETCH, &[OWN]).await,
        InjectDecision::PassThrough
    ));
}

#[tokio::test]
async fn a_source_that_is_broken_is_a_502_without_a_sign_in_notice() {
    let w = world();
    let work = &w.store.identities().unwrap()[0];
    w.credentials.fail(
        &work.credentials[0].source,
        SourceError::ToolMissing(Tool::Gh),
    );
    let (status, code, message) = refusal(&w.decide("github.com", "GET", FETCH, &[]).await);
    assert_eq!((status, code), (502, "credential_unavailable"));
    assert!(message.contains("is not installed"), "{message}");
    assert!(message.contains("check it in puddle"), "{message}");
    assert_eq!(w.events.take(), []);
}

#[tokio::test]
async fn a_token_a_header_cannot_carry_is_a_502_that_names_the_identity() {
    let w = World::new();
    let made = w.identity("Odd", "github.com", &[], true, "ok");
    // The base64 wrapper hides most bytes; a Bearer token on Azure DevOps shows them raw.
    let ado = w.identity("Ado", "dev.azure.com", &["contoso"], false, "x");
    w.credentials.give(&ado.source, "eyJa.b\u{7f}.c");
    let (status, code, message) = refusal(
        &w.decide("dev.azure.com", "GET", "/contoso/p/_git/r/info/refs", &[])
            .await,
    );
    assert_eq!((status, code), (502, "credential_unavailable"));
    assert!(message.contains("not a usable header value"), "{message}");
    assert!(!message.contains('\u{7f}'));
    let _ = made;
}

#[tokio::test]
async fn a_credential_for_somewhere_else_is_never_sent() {
    let w = World::new();
    // A hand-edited store row: the source is for another host than the credential's.
    let made = w.identity("Work", "github.com", &["acme"], false, "CANARY-WORK");
    let mut identity = w.store.identity(made.id).unwrap();
    let mut json = serde_json::to_value(&identity.credentials).unwrap();
    json[0]["source"] = serde_json::json!({
        "kind": "stored", "id": "t-work", "scope": {"host": "gitlab.example"}
    });
    identity.credentials = serde_json::from_value(json).unwrap();
    let mut git = WorkspaceGit::unconfigured();
    git.identities = vec![identity];
    git.only_push_listed = false;
    let injector = GitInjector::new(
        w.workspace.clone(),
        StaticSettings::new(git),
        w.credentials.clone(),
        w.events.clone(),
    );
    let host = Host::parse_normalised("github.com").unwrap();
    let context = InjectContext {
        workspace: &w.workspace,
        host: &host,
    };
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("GET", "/acme/web.git/info/refs", &lines);
    let decision = injector.decide(&context, &view).await;
    let (status, code, message) = refusal(&decision);
    assert_eq!((status, code), (502, "credential_unavailable"));
    assert!(message.contains("is not for github.com/acme"), "{message}");
    assert_eq!(w.credentials.reads(), 0);
    let _: &SourceSpec = &made.source;
}

#[tokio::test]
async fn settings_that_cannot_be_read_are_a_502_and_nothing_goes_out() {
    let w = World::new();
    let settings = StaticSettings::new(WorkspaceGit::unconfigured());
    settings.fail("the database is locked");
    let injector = GitInjector::new(
        w.workspace.clone(),
        settings,
        w.credentials.clone(),
        w.events.clone(),
    );
    let host = Host::parse_normalised("github.com").unwrap();
    let context = InjectContext {
        workspace: &w.workspace,
        host: &host,
    };
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("GET", "/acme/web.git/info/refs", &lines);
    let (status, code, message) = refusal(&injector.decide(&context, &view).await);
    assert_eq!((status, code), (502, "git_settings_unavailable"));
    assert!(message.contains("the database is locked"), "{message}");
    // A path that is not Git never asks for the settings.
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("GET", "/login", &lines);
    assert!(matches!(
        injector.decide(&context, &view).await,
        InjectDecision::PassThrough
    ));
}

#[tokio::test]
async fn no_refusal_or_log_line_carries_a_secret() {
    let w = world();
    let mut seen = String::new();
    for (method, target, headers) in [
        ("GET", FETCH, &[][..]),
        ("POST", "/acme/other.git/git-receive-pack", &[][..]),
        ("POST", "/acme/%77eb.git/git-receive-pack", &[][..]),
        ("GET", "/someone/else.git/info/refs", &[][..]),
    ] {
        let decision = w.decide("github.com", method, target, headers).await;
        let _ = write!(seen, "{decision:?}");
    }
    let work = &w.store.identities().unwrap()[0];
    w.credentials
        .fail(&work.credentials[0].source, SourceError::NotSignedIn);
    let refused = w.decide("github.com", "GET", FETCH, &[]).await;
    let _ = write!(seen, "{refused:?}{:?}", w.events.events());
    assert!(!seen.contains("CANARY"), "{seen}");
}

#[test]
fn the_injector_prints_no_settings() {
    let w = World::default();
    assert_eq!(
        format!("{:?}", w.injector),
        "GitInjector { workspace: WorkspaceName(\"box\"), .. }"
    );
}

#[tokio::test]
async fn forgetting_and_reading_go_through_the_credential_source() {
    let w = world();
    let work = &w.store.identities().unwrap()[0];
    let source = &work.credentials[0].source;
    let before = w.credentials.reads();
    let _ = w.decide("github.com", "GET", FETCH, &[]).await;
    assert_eq!(w.credentials.reads(), before + 1);
    CredentialSource::forget(&*w.credentials, source);
    assert_eq!(w.credentials.forgotten(), std::slice::from_ref(source));
}

#[tokio::test]
async fn a_flood_of_different_refusals_raises_a_bounded_number_of_notices() {
    tokio::time::pause();
    let w = world();
    for n in 0..300 {
        let target = format!("/acme/other{n}.git/git-receive-pack");
        let decision = w.decide("github.com", "POST", &target, &[]).await;
        assert_eq!(refusal(&decision).1, "push_denied");
    }
    assert_eq!(w.events.take().len(), 256, "the notices stop at the bound");
    // Past their window the old ones are forgotten and new ones are raised again.
    tokio::time::advance(Duration::from_secs(11)).await;
    let _ = w
        .decide(
            "github.com",
            "POST",
            "/acme/another.git/git-receive-pack",
            &[],
        )
        .await;
    assert_eq!(w.events.take().len(), 1);
}

#[tokio::test]
async fn settings_a_test_changes_by_hand_apply_to_the_next_request() {
    let w = World::new();
    let settings = StaticSettings::new(WorkspaceGit::unconfigured());
    let injector = GitInjector::new(
        w.workspace.clone(),
        settings.clone(),
        w.credentials.clone(),
        w.events.clone(),
    );
    let host = Host::parse_normalised("github.com").unwrap();
    let context = InjectContext {
        workspace: &w.workspace,
        host: &host,
    };
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("POST", "/acme/web.git/git-receive-pack", &lines);
    // Nothing listed and the push list on by default.
    let first = injector.decide(&context, &view).await;
    assert_eq!(refusal(&first).1, "push_denied");
    let mut git = WorkspaceGit::unconfigured();
    git.only_push_listed = false;
    settings.set(git);
    let second = injector.decide(&context, &view).await;
    assert!(matches!(second, InjectDecision::PassThrough), "{second:?}");
}

/// A source that answers one token and counts its reads, behind the real cache.
struct OneToken(Arc<AtomicUsize>);

impl Fetch for OneToken {
    fn fetch(&self, _: &SourceSpec) -> impl Future<Output = Result<Fetched, SourceError>> + Send {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(Fetched {
            credential: Credential {
                username: None,
                secret: Arc::new(Secret::new("CANARY-CACHED".to_owned())),
            },
            valid_for: None,
        }))
    }
}

#[tokio::test]
async fn the_secrets_cache_is_a_credential_source_that_reads_once_and_forgets_on_request() {
    let w = World::new();
    let made = w.identity("Work", "github.com", &["acme"], false, "unused");
    let reads = Arc::new(AtomicUsize::new(0));
    let cache = Arc::new(SecretCache::new(OneToken(Arc::clone(&reads))));
    let injector = GitInjector::new(
        w.workspace.clone(),
        Arc::new(StoreSettings::new(
            Arc::clone(&w.store),
            w.workspace.clone(),
        )),
        cache.clone(),
        w.events.clone(),
    );
    let host = Host::parse_normalised("github.com").unwrap();
    let context = InjectContext {
        workspace: &w.workspace,
        host: &host,
    };
    let lines = vec!["host: github.com".to_owned()];
    let view = RequestView::new("GET", "/acme/web.git/info/refs", &lines);
    for _ in 0..3 {
        let decision = injector.decide(&context, &view).await;
        assert!(
            injected(&decision, &token_header("CANARY-CACHED")),
            "{decision:?}"
        );
    }
    // Three requests, one read of the source; forgetting it makes the next request read again.
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    CredentialSource::forget(&*cache, &made.source);
    let _ = injector.decide(&context, &view).await;
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}
