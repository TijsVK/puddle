// SPDX-License-Identifier: GPL-3.0-or-later
//! The real Git injector (`puddle-inject`) behind the real proxy, on both HTTP versions, against
//! a fake Git host: the workspace's own header, the credential of the identity that covers the
//! owner, the push and pull lists, what a `401` becomes, what the connection record says.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod git_support;
mod terminate_support;

use bytes::Bytes;
use git_support::{GitRig, H2GitRig, Host, PERSONAL, REAL_SECRET, WORK, denied, token_basic};
use puddle_secrets::SourceError;
use puddle_types::{ConnectionDecision, ConnectionReason, Event, GitAccess};
use terminate_support::h2_rig::full;

const FETCH: &str = "/acme/web.git/info/refs?service=git-upload-pack";
const PUSH_ADVERT: &str = "/acme/web.git/info/refs?service=git-receive-pack";
const OWN: &str = "Bearer mine";
/// Shaped like a stand-in (`puddle-secret-FOO-...`), but no entry of the workspace stands for it.
const UNKNOWN_STAND_IN: &str =
    "Basic cHVkZGxlLXNlY3JldC1GT08tMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw";

async fn get(
    guest: &mut terminate_support::Guest,
    path: &str,
    authorization: Option<&str>,
) -> terminate_support::Response {
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    let extra = authorization.map_or_else(String::new, |v| format!("Authorization: {v}\r\n"));
    client
        .send(format!("GET {path} HTTP/1.1\r\nHost: bound.test\r\n{extra}\r\n").as_bytes())
        .await;
    client.response("GET").await
}

// On a bound git path: the workspace's header passes unchanged, a request with none gets the
// credential, and so on a bound path that is not git, where nothing is added.

#[tokio::test]
async fn on_a_git_path_the_three_cases_of_the_authorization_header() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    // No header: the covering identity's credential, and the record says so.
    assert_eq!(get(&mut guest, FETCH, None).await.status, 200);
    // The workspace's own header, and a value no stand-in entry covers: exactly as sent.
    assert_eq!(get(&mut guest, FETCH, Some(OWN)).await.status, 200);
    assert_eq!(
        get(&mut guest, FETCH, Some(UNKNOWN_STAND_IN)).await.status,
        200
    );
    let seen = t.server.recorded();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].headers_named("authorization"), [token_basic(WORK)]);
    assert_eq!(seen[1].headers_named("authorization"), [OWN]);
    assert_eq!(seen[2].headers_named("authorization"), [UNKNOWN_STAND_IN]);
    let events = t.rig.events(3).await;
    let injected: Vec<_> = events.iter().map(|e| e.injected).collect();
    assert_eq!(injected, [true, false, false]);
    assert!(
        events[0]
            .binding_id
            .as_deref()
            .is_some_and(|id| id.starts_with("identity:"))
    );
    assert!(events[1].binding_id.is_none());
    assert_eq!(t.raised(), []);
}

#[tokio::test]
async fn on_a_bound_path_that_is_not_git_nothing_is_added_and_the_header_passes_unchanged() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    for authorization in [None, Some(OWN), Some(UNKNOWN_STAND_IN)] {
        assert_eq!(
            get(&mut guest, "/acme/web/archive/main.zip", authorization)
                .await
                .status,
            200
        );
    }
    let seen = t.server.recorded();
    assert_eq!(seen[0].header("authorization"), None);
    assert_eq!(seen[1].headers_named("authorization"), [OWN]);
    assert_eq!(seen[2].headers_named("authorization"), [UNKNOWN_STAND_IN]);
    let events = t.rig.events(3).await;
    assert!(events.iter().all(|e| !e.injected && e.binding_id.is_none()));
    assert_eq!(t.world.credentials.reads(), 0);
}

/// What the server must see for each header the workspace sends with its stand-in.
fn real_for(stand_in: &str) -> [(String, String); 2] {
    [
        (
            format!("Bearer {stand_in}"),
            format!("Bearer {REAL_SECRET}"),
        ),
        (token_basic(stand_in), token_basic(REAL_SECRET)),
    ]
}

#[tokio::test]
async fn a_stand_in_is_swapped_on_a_git_path_and_on_a_bound_path_that_is_not_git() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    let pairs = real_for(&t.stand_in);
    let mut expected = Vec::new();
    for path in [FETCH, "/acme/web/archive/main.zip"] {
        for (sent, real) in &pairs {
            assert_eq!(get(&mut guest, path, Some(sent)).await.status, 200);
            expected.push(real.clone());
        }
    }
    let seen = t.server.recorded();
    assert_eq!(seen.len(), 4);
    for (request, real) in seen.iter().zip(&expected) {
        assert_eq!(request.headers_named("authorization"), [real.as_str()]);
    }
    // The workspace's own header was swapped; the identity's credential was not added beside it.
    assert_eq!(t.world.credentials.reads(), 0);
    let events = t.rig.events(4).await;
    for event in &events {
        assert!(event.injected);
        assert_eq!(
            event.binding_id.as_deref(),
            Some("stand-in:secret:GH_TOKEN")
        );
    }
    let audit = format!("{events:?}");
    assert!(!audit.contains(REAL_SECRET) && !audit.contains(&t.stand_in));
    assert_eq!(t.raised(), []);
}

#[tokio::test]
async fn a_stand_in_does_not_open_a_push_the_list_refuses() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    let sent = format!("Bearer {}", t.stand_in);
    let refused = get(
        &mut guest,
        "/acme/other.git/info/refs?service=git-receive-pack",
        Some(&sent),
    )
    .await;
    assert_eq!(refused.status, 403);
    assert_eq!(
        t.server.recorded().len(),
        0,
        "the real server was not asked"
    );
}

#[tokio::test]
async fn each_owner_gets_its_own_identitys_credential_and_never_the_others() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    assert_eq!(
        get(
            &mut guest,
            "/acme/web.git/info/refs?service=git-upload-pack",
            None
        )
        .await
        .status,
        200
    );
    assert_eq!(
        get(
            &mut guest,
            "/someone/else.git/info/refs?service=git-upload-pack",
            None
        )
        .await
        .status,
        200
    );
    let seen = t.server.recorded();
    assert_eq!(seen[0].headers_named("authorization"), [token_basic(WORK)]);
    assert_eq!(
        seen[1].headers_named("authorization"),
        [token_basic(PERSONAL)]
    );
    // The other workspace (no injector of ours) never gets either.
    let mut other = t.rig.other_guest().await;
    let mut client = other.tls("bound.test:443", None).await.unwrap();
    assert_eq!(
        client
            .get("bound.test", "/acme/web.git/info/refs")
            .await
            .status,
        200
    );
    assert_eq!(t.server.recorded()[2].header("authorization"), None);
}

// The repository table.

#[tokio::test]
async fn a_push_off_the_list_is_refused_in_one_readable_line_and_recorded() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    let answer = get(
        &mut guest,
        "/acme/other.git/info/refs?service=git-receive-pack",
        None,
    )
    .await;
    assert_eq!(answer.status, 403);
    assert_eq!(answer.header("x-puddle-blocked"), Some("push_denied"));
    assert_eq!(
        answer.text(),
        "puddle: push to bound.test/acme/other is not on this workspace's push list; add it, or turn off \"Only push to listed repos\" on the workspace's Git tab\n"
    );
    assert!(t.server.recorded().is_empty(), "nothing went upstream");
    assert_eq!(
        t.raised(),
        [denied(&t.world.workspace, "acme/other", GitAccess::Push)]
    );
    let event = &t.rig.events(1).await[0];
    assert_eq!(event.decision, ConnectionDecision::Blocked);
    assert_eq!(event.reason, ConnectionReason::Refused("push_denied"));
    assert!(!event.injected);
    // The listed repository is still fine; the post of a push is gated the same way.
    assert_eq!(get(&mut guest, PUSH_ADVERT, None).await.status, 200);
    let mut client = guest.tls("bound.test:443", None).await.unwrap();
    client
        .send(b"POST /acme/other.git/git-receive-pack HTTP/1.1\r\nHost: bound.test\r\nContent-Length: 4\r\n\r\nPACK")
        .await;
    assert_eq!(client.response("POST").await.status, 403);
    assert_eq!(t.server.recorded().len(), 1);
}

#[tokio::test]
async fn the_pull_list_refuses_a_fetch_with_the_same_kind_of_line() {
    let t = GitRig::new().await;
    t.world.switches(true, true);
    let mut guest = t.rig.guest().await;
    let answer = get(
        &mut guest,
        "/someone/else.git/info/refs?service=git-upload-pack",
        None,
    )
    .await;
    assert_eq!(answer.status, 403);
    assert_eq!(answer.header("x-puddle-blocked"), Some("pull_denied"));
    assert_eq!(
        answer.text(),
        "puddle: pull from bound.test/someone/else is not on this workspace's pull list; add it, or turn off \"Only pull from listed repos\" on the workspace's Git tab\n"
    );
    assert_eq!(
        t.raised(),
        [denied(&t.world.workspace, "someone/else", GitAccess::Pull)]
    );
    assert_eq!(get(&mut guest, FETCH, None).await.status, 200);
}

#[tokio::test]
async fn a_path_that_names_a_repository_two_ways_is_a_400_and_never_goes_upstream() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    for path in [
        "/acme/web.git/../other.git/info/refs?service=git-receive-pack",
        "/acme%2Fother/web.git/info/refs",
        "/acme//web.git/git-receive-pack",
    ] {
        let answer = get(&mut guest, path, None).await;
        assert_eq!(answer.status, 400, "{path}");
        assert_eq!(answer.header("x-puddle-blocked"), Some("bad_git_path"));
        assert!(
            answer
                .text()
                .starts_with("puddle: this request names a Git repository in a way")
        );
    }
    assert!(t.server.recorded().is_empty());
}

// Git LFS: the body of a batch says whether it reads or writes.

#[tokio::test]
async fn an_lfs_batch_is_read_by_its_operation_and_forwarded_whole() {
    let t = GitRig::new().await;
    let mut guest = t.rig.guest().await;
    let download = r#"{"operation":"download","objects":[{"oid":"aa","size":1}]}"#;
    let upload = r#"{"operation":"upload","objects":[{"oid":"aa","size":1}]}"#;
    for (path, body, status) in [
        ("/someone/big.git/info/lfs/objects/batch", download, 200),
        ("/someone/big.git/info/lfs/objects/batch", upload, 403),
        ("/acme/web.git/info/lfs/objects/batch", upload, 200),
    ] {
        let mut client = guest.tls("bound.test:443", None).await.unwrap();
        client
            .send(
                format!(
                    "POST {path} HTTP/1.1\r\nHost: bound.test\r\nContent-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
        assert_eq!(
            client.response("POST").await.status,
            status,
            "{path} {body}"
        );
    }
    let seen = t.server.recorded();
    assert_eq!(seen.len(), 2, "the refused upload went nowhere");
    assert_eq!(seen[0].body, download.as_bytes());
    assert_eq!(
        seen[0].headers_named("authorization"),
        [token_basic(PERSONAL)]
    );
    assert_eq!(seen[1].body, upload.as_bytes());
    assert_eq!(seen[1].headers_named("authorization"), [token_basic(WORK)]);
}

// What a 401 becomes.

#[tokio::test]
async fn a_401_to_the_credential_puddle_added_is_ours_forgets_the_token_and_asks_for_a_sign_in() {
    let t = GitRig::with_host(Host { revoked: true }).await;
    let mut guest = t.rig.guest().await;
    let answer = get(
        &mut guest,
        "/acme/private.git/info/refs?service=git-upload-pack",
        None,
    )
    .await;
    assert_eq!(answer.status, 403);
    assert_eq!(
        answer.header("x-puddle-blocked"),
        Some("credential_rejected")
    );
    assert_eq!(answer.header("www-authenticate"), None);
    let text = answer.text();
    assert!(
        text.starts_with("puddle: bound.test did not accept the credential of identity Work"),
        "{text}"
    );
    assert!(!text.contains(WORK));
    // The token went out (that is what the host rejected), the cache let go of it, the user is asked.
    assert_eq!(
        t.server.recorded()[0].headers_named("authorization"),
        [token_basic(WORK)]
    );
    assert_eq!(t.world.credentials.forgotten().len(), 1);
    let raised = t.raised();
    assert!(
        matches!(raised.as_slice(), [Event::CredentialSignInNeeded { host, .. }] if host == "bound.test"),
        "{raised:?}"
    );
    let event = &t.rig.events(1).await[0];
    assert_eq!(
        event.reason,
        ConnectionReason::Refused("credential_rejected")
    );
    assert!(event.injected, "a credential was added, and refused");
}

#[tokio::test]
async fn a_request_no_identity_covers_goes_out_as_sent_and_its_401_is_the_servers_own() {
    let t = GitRig::new().await;
    // Detach both identities: nothing covers anything.
    for identity in t.world.store.identities().unwrap() {
        t.world
            .store
            .detach_identity(&t.world.workspace, identity.id)
            .unwrap();
    }
    let mut guest = t.rig.guest().await;
    // A tool that has a token of its own sends it after this 401, so the 401 must reach it.
    let private = get(
        &mut guest,
        "/acme/private.git/info/refs?service=git-upload-pack",
        None,
    )
    .await;
    assert_eq!(private.status, 401);
    assert_eq!(
        private.header("www-authenticate"),
        Some("Basic realm=\"fake git host\"")
    );
    assert_eq!(private.header("x-puddle-blocked"), None);
    assert_eq!(private.text(), "Authentication required");
    // A public repository still reads, with no credential.
    let public = get(
        &mut guest,
        "/acme/open.git/info/refs?service=git-upload-pack",
        None,
    )
    .await;
    assert_eq!(public.status, 200);
    assert!(
        t.server
            .recorded()
            .iter()
            .all(|r| r.header("authorization").is_none())
    );
    let events = t.rig.events(2).await;
    assert!(
        events
            .iter()
            .all(|e| e.reason == ConnectionReason::Rule && !e.injected)
    );
    assert_eq!(t.raised(), []);
    assert_eq!(t.world.credentials.reads(), 0);
}

#[tokio::test]
async fn a_401_to_the_workspaces_own_header_is_the_servers_answer_as_without_puddle() {
    let t = GitRig::with_host(Host { revoked: true }).await;
    let mut guest = t.rig.guest().await;
    // Its own token, which the host does not accept (`Bearer other`), on a git path.
    let answer = get(
        &mut guest,
        "/acme/private.git/info/refs?service=git-upload-pack",
        Some("Bearer other"),
    )
    .await;
    assert_eq!(answer.status, 401);
    assert_eq!(
        answer.header("www-authenticate"),
        Some("Basic realm=\"fake git host\"")
    );
    assert_eq!(answer.text(), "Authentication required");
    assert_eq!(answer.header("x-puddle-blocked"), None);
    // Likewise on a path that is not git, with or without a header.
    for authorization in [None, Some("Bearer other")] {
        let answer = get(&mut guest, "/acme/private/archive.zip", authorization).await;
        assert_eq!(answer.status, 401, "{authorization:?}");
        assert_eq!(answer.header("x-puddle-blocked"), None);
    }
    assert_eq!(t.raised(), []);
    assert_eq!(t.world.credentials.reads(), 0);
    let events = t.rig.events(3).await;
    assert!(
        events
            .iter()
            .all(|e| e.reason == ConnectionReason::Rule && !e.injected)
    );
}

#[tokio::test]
async fn a_source_that_cannot_supply_its_secret_is_a_502_never_a_401_and_the_server_is_not_asked() {
    let t = GitRig::new().await;
    let work = &t.world.store.identities().unwrap()[0];
    t.world
        .credentials
        .fail(&work.credentials[0].source, SourceError::NotSignedIn);
    let mut guest = t.rig.guest().await;
    let answer = get(&mut guest, FETCH, None).await;
    assert_eq!(answer.status, 502);
    assert_eq!(
        answer.header("x-puddle-blocked"),
        Some("credential_unavailable")
    );
    assert!(
        answer.text().contains("sign in to it in puddle"),
        "{}",
        answer.text()
    );
    assert!(t.server.recorded().is_empty());
    assert!(matches!(
        t.raised().as_slice(),
        [Event::CredentialSignInNeeded { .. }]
    ));
}

// The same over HTTP/2.

async fn h2_batch(t: &H2GitRig, body: &'static str) -> terminate_support::h2_rig::Got {
    let mut guest = t.rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    client
        .request(
            "POST",
            "bound.test",
            "/someone/big.git/info/lfs/objects/batch",
            &[("content-type", "application/vnd.git-lfs+json")],
            full(Bytes::from(body)),
        )
        .await
}

fn h2_get<'a>(
    client: &'a mut terminate_support::h2_rig::H2Guest,
    path: &'a str,
    authorization: Option<&'a str>,
) -> impl Future<Output = terminate_support::h2_rig::Got> + 'a {
    let headers: Vec<(&str, &str)> = authorization
        .map(|v| ("authorization", v))
        .into_iter()
        .collect();
    async move {
        client
            .request("GET", "bound.test", path, &headers, full(Bytes::new()))
            .await
    }
}

#[tokio::test]
async fn over_http2_the_three_cases_the_lists_and_the_401s() {
    let t = H2GitRig::new(Host::default()).await;
    let mut guest = t.rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;

    // No header, the workspace's own header, a stand-in: the credential, then exactly as sent.
    assert_eq!(h2_get(&mut client, FETCH, None).await.status, 200);
    assert_eq!(h2_get(&mut client, FETCH, Some(OWN)).await.status, 200);
    assert_eq!(
        h2_get(&mut client, FETCH, Some(UNKNOWN_STAND_IN))
            .await
            .status,
        200
    );
    let seen = t.server.recorded();
    assert_eq!(seen[0].headers_named("authorization"), [token_basic(WORK)]);
    assert_eq!(seen[1].headers_named("authorization"), [OWN]);
    assert_eq!(seen[2].headers_named("authorization"), [UNKNOWN_STAND_IN]);
    // Not a git path: nothing added.
    assert_eq!(
        h2_get(&mut client, "/acme/web/archive/main.zip", None)
            .await
            .status,
        200
    );
    assert_eq!(t.server.recorded()[3].header("authorization"), None);

    // The push list.
    let refused = h2_get(
        &mut client,
        "/acme/other.git/info/refs?service=git-receive-pack",
        None,
    )
    .await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.header("x-puddle-blocked"), Some("push_denied"));
    assert!(
        refused.text().starts_with(
            "puddle: push to bound.test/acme/other is not on this workspace's push list"
        )
    );
    assert_eq!(
        t.world.events.take(),
        [denied(&t.world.workspace, "acme/other", GitAccess::Push)]
    );
    assert_eq!(t.server.recorded().len(), 4);

    // An LFS batch: read by its body.
    assert_eq!(
        h2_batch(&t, r#"{"operation":"download"}"#).await.status,
        200
    );
    assert_eq!(h2_batch(&t, r#"{"operation":"upload"}"#).await.status, 403);
    let seen = t.server.recorded();
    assert_eq!(seen.last().unwrap().body, br#"{"operation":"download"}"#);
    assert_eq!(
        seen.last().unwrap().headers_named("authorization"),
        [token_basic(PERSONAL)]
    );
}

#[tokio::test]
async fn over_http2_a_stand_in_is_swapped_on_a_git_path_and_on_a_bound_path_that_is_not_git() {
    let t = H2GitRig::new(Host::default()).await;
    let mut guest = t.rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let pairs = real_for(&t.stand_in);
    let mut expected = Vec::new();
    for path in [FETCH, "/acme/web/archive/main.zip"] {
        for (sent, real) in &pairs {
            assert_eq!(h2_get(&mut client, path, Some(sent)).await.status, 200);
            expected.push(real.clone());
        }
    }
    let seen = t.server.recorded();
    assert_eq!(seen.len(), 4);
    for (request, real) in seen.iter().zip(&expected) {
        assert_eq!(request.headers_named("authorization"), [real.as_str()]);
    }
    assert_eq!(t.world.credentials.reads(), 0);
    client.close().await;
    let events = t.rig.events(1).await;
    assert!(events[0].injected);
    assert_eq!(
        events[0].binding_id.as_deref(),
        Some("stand-in:secret:GH_TOKEN")
    );
    assert!(!format!("{events:?}").contains(REAL_SECRET));
}

#[tokio::test]
async fn over_http2_a_401_is_ours_only_when_puddle_chose_the_credential() {
    let t = H2GitRig::new(Host { revoked: true }).await;
    let mut guest = t.rig.guest().await;
    let mut client = guest.h2("bound.test:443", &[b"h2"]).await;
    let private = "/acme/private.git/info/refs?service=git-upload-pack";
    let ours = h2_get(&mut client, private, None).await;
    assert_eq!(ours.status, 403);
    assert_eq!(ours.header("x-puddle-blocked"), Some("credential_rejected"));
    assert_eq!(ours.header("www-authenticate"), None);
    // The same connection goes on, and the workspace's own header gets the host's own answer.
    let own = h2_get(&mut client, private, Some("Bearer other")).await;
    assert_eq!(own.status, 401);
    assert_eq!(
        own.header("www-authenticate"),
        Some("Basic realm=\"fake git host\"")
    );
    assert_eq!(own.header("x-puddle-blocked"), None);
    let raised = t.world.events.take();
    assert!(
        matches!(raised.as_slice(), [Event::CredentialSignInNeeded { .. }]),
        "{raised:?}"
    );
    client.close().await;
    let events = t.rig.events(1).await;
    assert_eq!(
        events[0].reason,
        ConnectionReason::Refused("credential_rejected")
    );
}
