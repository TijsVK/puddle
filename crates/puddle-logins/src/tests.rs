// SPDX-License-Identifier: GPL-3.0-or-later
//! Tests of the capture of one workspace's logins: what a token endpoint's answer becomes, what
//! is kept, what survives a restart and what is never done.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use puddle_proxy::{AnswerHead, Exchange, ExchangeRewriter, StandIns};
use puddle_secrets::{MemoryStore, SecretStore};
use puddle_types::{Host, WorkspaceName};
use serde_json::{Value, json};

use crate::profile::{CLAUDE, GITHUB, Profile, Role, builtin};
use crate::vault::Vault;
use crate::{ForgetError, LoginNotices, Logins, Problem};

const REAL_ACCESS: &str =
    "sk-ant-oat01-CANARY0access0real0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REAL_REFRESH: &str =
    "sk-ant-ort01-CANARY0refresh0real0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const REAL_KEY: &str = "sk-ant-api03-CANARY0key0real0CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-end-of-key-0123456789";
const REAL_GH: &str = "gho_CANARY0github0real0DDDDDDDDDDDDD";
const ACCESS_B: &str =
    "sk-ant-oat01-CANARY0access0second0EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
const REFRESH_B: &str =
    "sk-ant-ort01-CANARY0refresh0second0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

#[derive(Default)]
struct Notices(Mutex<Vec<(String, Problem)>>);

impl LoginNotices for Notices {
    fn problem(&self, _: &WorkspaceName, profile: &Profile, problem: Problem) {
        self.0
            .lock()
            .unwrap()
            .push((profile.id.to_owned(), problem));
    }
}

impl Notices {
    fn seen(&self) -> Vec<(String, Problem)> {
        self.0.lock().unwrap().clone()
    }
}

struct Rig {
    logins: Logins,
    registry: Arc<StandIns>,
    store: Arc<MemoryStore>,
    notices: Arc<Notices>,
}

fn workspace() -> WorkspaceName {
    WorkspaceName::new("alpha").unwrap()
}

fn rig_on(store: &Arc<MemoryStore>, enabled: bool) -> Rig {
    let registry = Arc::new(StandIns::new());
    let notices = Arc::new(Notices::default());
    let logins = Logins::new(
        workspace(),
        enabled,
        builtin(),
        Arc::clone(&registry),
        Arc::clone(store) as Arc<dyn SecretStore>,
        Arc::clone(&notices) as Arc<dyn LoginNotices>,
    );
    Rig {
        logins,
        registry,
        store: Arc::clone(store),
        notices,
    }
}

fn rig() -> Rig {
    rig_on(&Arc::new(MemoryStore::new()), true)
}

fn host(name: &str) -> Host {
    Host::parse_normalised(name).unwrap()
}

fn vault(rig: &Rig) -> Vault {
    Vault::new(Arc::clone(&rig.store) as Arc<dyn SecretStore>, &workspace())
}

fn claude_answer(access: &str, refresh: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "token_type": "Bearer",
        "access_token": access,
        "expires_in": 28800,
        "refresh_token": refresh,
        "scope": "user:inference user:profile",
        "account": {"uuid": "u-1", "email_address": "me@example.invalid"},
    }))
    .unwrap()
}

/// What the proxy does with an answer: asks the rewriter, shows it the head, gives it the body.
async fn answered(
    exchange: Option<Exchange>,
    status: u16,
    content_type: Option<&str>,
    body: &[u8],
) -> Option<Bytes> {
    let mut exchange = exchange.expect("the request is an exchange");
    let answer = exchange.answer_mut().expect("an exchange reads the answer");
    let head = AnswerHead {
        status,
        content_type,
        content_encoding: None,
        content_length: Some(body.len() as u64),
    };
    if !answer.wants(&head) {
        return None;
    }
    answer.rewrite(&head, body).await
}

async fn claude_login(rig: &Rig, access: &str, refresh: &str) -> Value {
    let exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
    let body = answered(
        exchange,
        200,
        Some("application/json"),
        &claude_answer(access, refresh),
    )
    .await
    .expect("the answer was captured");
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn a_claude_login_keeps_the_tokens_and_the_tool_gets_stand_ins_with_their_shape() {
    let rig = rig();
    let given = claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;

    let access = given["access_token"].as_str().unwrap();
    let refresh = given["refresh_token"].as_str().unwrap();
    assert_ne!(access, REAL_ACCESS);
    assert_ne!(refresh, REAL_REFRESH);
    assert!(access.starts_with("sk-ant-oat01-") && access.len() == REAL_ACCESS.len());
    assert!(refresh.starts_with("sk-ant-ort01-") && refresh.len() == REAL_REFRESH.len());
    // Everything else in the answer is the service's.
    assert_eq!(given["expires_in"], 28800);
    assert_eq!(given["token_type"], "Bearer");
    assert_eq!(given["scope"], "user:inference user:profile");
    assert_eq!(given["account"]["email_address"], "me@example.invalid");
    assert!(!given.to_string().contains("CANARY"));

    assert_eq!(rig.registry.len(), 2);
    assert_eq!(rig.notices.seen(), []);
    let v = vault(&rig);
    let kept = v.read(&CLAUDE, Role::Access).unwrap().unwrap();
    assert_eq!(
        (kept.stand_in.as_str(), kept.real.as_str()),
        (access, REAL_ACCESS)
    );
    let kept = v.read(&CLAUDE, Role::Refresh).unwrap().unwrap();
    assert_eq!(
        (kept.stand_in.as_str(), kept.real.as_str()),
        (refresh, REAL_REFRESH)
    );
    let kept = rig.logins.kept();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].profile, "claude");
    assert_eq!(kept[0].roles, [Role::Access, Role::Refresh]);
}

#[tokio::test]
async fn a_refresh_gives_the_tool_the_same_stand_ins_with_new_tokens_behind_them() {
    let rig = rig();
    let first = claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    let again = claude_login(
        &rig,
        "sk-ant-oat01-CANARY0access0second0EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "sk-ant-ort01-CANARY0refresh0second0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    )
    .await;
    assert_eq!(first["access_token"], again["access_token"]);
    assert_eq!(first["refresh_token"], again["refresh_token"]);
    assert_eq!(rig.registry.len(), 2, "a slot has one stand-in");
    let kept = vault(&rig).read(&CLAUDE, Role::Access).unwrap().unwrap();
    assert!(kept.real.contains("second"));
    assert_eq!(kept.stand_in, again["access_token"].as_str().unwrap());
}

#[tokio::test]
async fn the_token_endpoint_asks_for_the_refresh_swap_and_other_requests_are_not_exchanges() {
    let rig = rig();
    let mut exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token")
        .unwrap();
    assert_eq!(exchange.swap_fields(), ["refresh_token"]);
    assert!(exchange.answer_mut().is_some());
    let github = rig
        .logins
        .begin(&host("github.com"), "POST", "/login/oauth/access_token")
        .unwrap();
    assert_eq!(github.swap_fields(), ["refresh_token"]);
    // The key endpoint answers with a key and takes no refresh token.
    let key = rig
        .logins
        .begin(
            &host("api.anthropic.com"),
            "POST",
            "/api/oauth/claude_cli/create_api_key",
        )
        .unwrap();
    assert_eq!(key.swap_fields().len(), 0);

    for (name, method, path) in [
        ("platform.claude.com", "GET", "/v1/oauth/token"),
        ("platform.claude.com", "POST", "/v1/oauth/authorize"),
        ("platform.claude.com", "POST", "/v1/oauth/token/extra"),
        ("api.anthropic.com", "POST", "/v1/oauth/token"),
        ("github.com", "POST", "/org/repo.git/git-receive-pack"),
        ("github.com", "POST", "/login/device/code"),
        ("example.com", "POST", "/v1/oauth/token"),
    ] {
        assert!(
            rig.logins.begin(&host(name), method, path).is_none(),
            "{method} {name}{path}"
        );
    }
}

#[tokio::test]
async fn hostile_hg33_another_spelling_of_the_token_endpoint_is_still_read() {
    let rig = rig();
    for path in [
        "/v1/oauth/token/",
        "//v1//oauth/token",
        "/v1/./oauth/token",
        "/v1/x/../oauth/token",
        "/V1/OAuth/Token",
        "/v1/oauth/%74oken",
        "/v1/oauth/token;x=1",
        "/v1/oauth/token?grant=refresh_token",
        "\\v1\\oauth\\token",
    ] {
        assert!(
            rig.logins
                .begin(&host("platform.claude.com"), "POST", path)
                .is_some(),
            "{path}"
        );
    }
}

#[tokio::test]
async fn a_github_form_answer_stays_a_form_and_the_scope_and_type_are_kept() {
    let rig = rig();
    let exchange = rig
        .logins
        .begin(&host("github.com"), "POST", "/login/oauth/access_token");
    let body = answered(
        exchange,
        200,
        Some("application/x-www-form-urlencoded; charset=utf-8"),
        format!("access_token={REAL_GH}&scope=repo%2Cread%3Aorg%2Cgist&token_type=bearer")
            .as_bytes(),
    )
    .await
    .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    let (first, rest) = text.split_once('&').unwrap();
    assert_eq!(rest, "scope=repo%2Cread%3Aorg%2Cgist&token_type=bearer");
    let stand_in = first.strip_prefix("access_token=").unwrap();
    assert!(stand_in.starts_with("gho_") && stand_in.len() == REAL_GH.len());
    assert_ne!(stand_in, REAL_GH);
    assert_eq!(rig.registry.len(), 1);
    assert_eq!(
        vault(&rig)
            .read(&GITHUB, Role::Access)
            .unwrap()
            .unwrap()
            .real
            .as_str(),
        REAL_GH
    );
}

#[tokio::test]
async fn a_github_json_answer_stays_json() {
    let rig = rig();
    let exchange = rig
        .logins
        .begin(&host("github.com"), "POST", "/login/oauth/access_token");
    let body = answered(
        exchange,
        200,
        Some("application/json; charset=utf-8"),
        json!({"access_token": REAL_GH, "token_type": "bearer", "scope": "gist,repo"})
            .to_string()
            .as_bytes(),
    )
    .await
    .unwrap();
    let given: Value = serde_json::from_slice(&body).unwrap();
    assert!(given["access_token"].as_str().unwrap().starts_with("gho_"));
    assert_eq!(given["scope"], "gist,repo");
}

#[tokio::test]
async fn the_api_key_a_login_creates_keeps_its_last_twenty_characters() {
    let rig = rig();
    let exchange = rig.logins.begin(
        &host("api.anthropic.com"),
        "POST",
        "/api/oauth/claude_cli/create_api_key",
    );
    let body = answered(
        exchange,
        200,
        Some("application/json"),
        json!({"raw_key": REAL_KEY}).to_string().as_bytes(),
    )
    .await
    .unwrap();
    let given: Value = serde_json::from_slice(&body).unwrap();
    let key = given["raw_key"].as_str().unwrap();
    assert!(key.starts_with("sk-ant-api03-"));
    assert_eq!(key.len(), REAL_KEY.len());
    assert!(key.ends_with(&REAL_KEY[REAL_KEY.len() - 20..]));
    assert_ne!(key, REAL_KEY);
    assert_eq!(rig.logins.kept()[0].roles, [Role::ApiKey]);
}

#[tokio::test]
async fn answers_without_a_token_are_left_alone_and_say_nothing() {
    let rig = rig();
    for (status, content_type, body) in [
        // GitHub's device flow answers 200 with an error until the user approves.
        (
            200,
            "application/x-www-form-urlencoded",
            "error=authorization_pending&interval=5",
        ),
        (
            200,
            "application/json",
            r#"{"error":"authorization_pending"}"#,
        ),
        (200, "application/json", "{}"),
        (200, "application/json", r#"{"access_token":""}"#),
        (200, "application/json", r#"{"access_token":12345}"#),
        // Errors are the tool's to read; nothing is looked at.
        (400, "application/json", r#"{"error":"invalid_grant"}"#),
        (401, "text/html", "no"),
        (204, "application/json", ""),
    ] {
        let exchange = rig
            .logins
            .begin(&host("github.com"), "POST", "/login/oauth/access_token");
        assert_eq!(
            answered(exchange, status, Some(content_type), body.as_bytes()).await,
            None,
            "{status} {body}"
        );
    }
    assert_eq!(rig.registry.len(), 0);
    assert_eq!(rig.notices.seen(), []);
}

#[tokio::test]
async fn a_success_answer_puddle_cannot_read_is_passed_on_and_the_user_is_told() {
    let rig = rig();
    for (content_type, encoding, length) in [
        (Some("text/html"), None, Some(10)),
        (None, None, Some(10)),
        (Some("application/json"), Some("gzip"), Some(10)),
        (Some("application/json"), None, Some(10 * 1024 * 1024)),
    ] {
        let mut exchange = rig
            .logins
            .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token")
            .unwrap();
        let answer = exchange.answer_mut().unwrap();
        let head = AnswerHead {
            status: 200,
            content_type,
            content_encoding: encoding,
            content_length: length,
        };
        assert!(
            !answer.wants(&head),
            "{content_type:?} {encoding:?} {length:?}"
        );
    }
    assert_eq!(rig.notices.seen().len(), 4);
    assert!(
        rig.notices
            .seen()
            .iter()
            .all(|(profile, problem)| profile == "claude" && *problem == Problem::UnexpectedAnswer)
    );
}

#[tokio::test]
async fn an_answer_that_does_not_parse_is_passed_on_and_the_user_is_told() {
    let rig = rig();
    let exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
    assert_eq!(
        answered(
            exchange,
            200,
            Some("application/json"),
            b"{\"access_token\": "
        )
        .await,
        None
    );
    assert_eq!(
        rig.notices.seen(),
        [("claude".to_owned(), Problem::UnexpectedAnswer)]
    );
    assert_eq!(rig.registry.len(), 0);
    assert!(vault(&rig).read(&CLAUDE, Role::Access).unwrap().is_none());
}

#[tokio::test]
async fn a_token_bound_to_a_key_cannot_be_captured() {
    let rig = rig();
    let exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
    let body = json!({"access_token": REAL_ACCESS, "token_type": "DPoP"}).to_string();
    assert_eq!(
        answered(exchange, 200, Some("application/json"), body.as_bytes()).await,
        None
    );
    assert_eq!(
        rig.notices.seen(),
        [("claude".to_owned(), Problem::BoundToken)]
    );
    assert_eq!(rig.registry.len(), 0);
}

#[tokio::test]
async fn a_token_a_stand_in_cannot_copy_is_passed_on_and_the_user_is_told() {
    let rig = rig();
    for token in ["short", "has a space in it, 0123456789"] {
        let exchange = rig
            .logins
            .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
        let body = json!({"access_token": token}).to_string();
        assert_eq!(
            answered(exchange, 200, Some("application/json"), body.as_bytes()).await,
            None
        );
    }
    assert_eq!(
        rig.notices.seen(),
        [
            ("claude".to_owned(), Problem::UnusableToken),
            ("claude".to_owned(), Problem::UnusableToken)
        ]
    );
    assert_eq!(rig.registry.len(), 0);
}

#[tokio::test]
async fn when_the_credential_store_is_not_there_the_login_passes_and_nothing_is_half_done() {
    let rig = rig();
    rig.store.break_it();
    let exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
    assert_eq!(
        answered(
            exchange,
            200,
            Some("application/json"),
            &claude_answer(REAL_ACCESS, REAL_REFRESH)
        )
        .await,
        None
    );
    assert_eq!(
        rig.notices.seen(),
        [("claude".to_owned(), Problem::StoreUnavailable)]
    );
    assert_eq!(
        rig.registry.len(),
        0,
        "no stand-in for a token that was not kept"
    );
    assert_eq!(rig.logins.kept().len(), 0);
}

#[tokio::test]
async fn a_restart_gets_the_stand_ins_the_workspace_still_holds() {
    let first = rig();
    let given = claude_login(&first, REAL_ACCESS, REAL_REFRESH).await;

    // The next start: a new registry and new handle over the same credential store.
    let second = rig_on(&first.store, true);
    assert_eq!(second.registry.len(), 0);
    second.logins.load().await;
    assert_eq!(second.registry.len(), 2);
    assert_eq!(second.notices.seen(), []);
    assert_eq!(second.logins.kept(), first.logins.kept());
    // A refresh now reuses the stand-ins the workspace holds.
    let again = claude_login(&second, REAL_ACCESS, REAL_REFRESH).await;
    assert_eq!(again["access_token"], given["access_token"]);
    assert_eq!(second.registry.len(), 2);
}

#[tokio::test]
async fn with_capture_off_nothing_is_captured_loaded_or_decrypted_and_the_store_is_left_alone() {
    let on = rig();
    claude_login(&on, REAL_ACCESS, REAL_REFRESH).await;

    let off = rig_on(&on.store, false);
    assert!(off.logins.hosts().is_empty());
    assert!(
        off.logins
            .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token")
            .is_none()
    );
    // Not even a store that is broken is asked about: off means off.
    on.store.break_it();
    off.logins.load().await;
    assert_eq!(off.registry.len(), 0, "a login kept before is not swapped");
    assert_eq!(off.notices.seen(), []);
}

#[tokio::test]
async fn a_credential_store_that_is_not_there_at_the_start_is_reported_once_per_service_and_read_once()
 {
    let on = rig();
    claude_login(&on, REAL_ACCESS, REAL_REFRESH).await;
    on.store.break_it();
    let next = rig_on(&on.store, true);
    next.logins.load().await;
    assert_eq!(next.registry.len(), 0);
    // Nothing can be kept either, so this is the notice for a login that is not protected.
    assert_eq!(
        next.notices.seen(),
        [
            ("claude".to_owned(), Problem::StoreUnavailable),
            ("github".to_owned(), Problem::StoreUnavailable)
        ]
    );
}

#[tokio::test]
async fn forgetting_a_login_ends_its_stand_ins_and_deletes_its_tokens() {
    let rig = rig();
    claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    assert_eq!(rig.logins.forget("nope").await, Ok(false));
    assert_eq!(rig.logins.forget("claude").await, Ok(true));
    assert_eq!(rig.registry.len(), 0);
    assert_eq!(rig.logins.kept().len(), 0);
    assert!(vault(&rig).read(&CLAUDE, Role::Access).unwrap().is_none());
    assert!(vault(&rig).read(&CLAUDE, Role::Refresh).unwrap().is_none());
    // The next login starts a slot again.
    claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    assert_eq!(rig.registry.len(), 2);
    rig.store.break_it();
    assert_eq!(rig.logins.forget("claude").await, Err(ForgetError::Store));
    assert_eq!(
        rig.registry.len(),
        0,
        "the stand-ins stop working whatever the store does"
    );
}

#[tokio::test]
async fn deleting_the_workspace_deletes_every_token_kept_for_it() {
    let rig = rig();
    claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    let other = {
        let registry = Arc::new(StandIns::new());
        Logins::new(
            WorkspaceName::new("beta").unwrap(),
            true,
            builtin(),
            registry,
            Arc::clone(&rig.store) as Arc<dyn SecretStore>,
            Arc::clone(&rig.notices) as Arc<dyn LoginNotices>,
        )
    };
    let store: Arc<dyn SecretStore> = Arc::clone(&rig.store) as Arc<dyn SecretStore>;
    other.forget("github").await.unwrap();
    assert_eq!(Logins::delete_workspace(&store, &workspace(), builtin()), 0);
    assert!(vault(&rig).read(&CLAUDE, Role::Access).unwrap().is_none());
    assert!(vault(&rig).read(&CLAUDE, Role::Refresh).unwrap().is_none());
    rig.store.break_it();
    assert_eq!(
        Logins::delete_workspace(&store, &workspace(), builtin()),
        CLAUDE.roles().len() + GITHUB.roles().len()
    );
}

#[tokio::test]
async fn a_workspaces_logins_never_reach_another_workspace() {
    let one = rig();
    claude_login(&one, REAL_ACCESS, REAL_REFRESH).await;
    let beta = Logins::new(
        WorkspaceName::new("beta").unwrap(),
        true,
        builtin(),
        Arc::new(StandIns::new()),
        Arc::clone(&one.store) as Arc<dyn SecretStore>,
        Arc::new(Notices::default()),
    );
    beta.load().await;
    assert_eq!(beta.kept().len(), 0);
}

#[test]
fn the_hosts_are_every_profiles_endpoints_and_api_hosts_while_capture_is_on() {
    let rig = rig();
    let hosts = rig.logins.hosts();
    for name in [
        "platform.claude.com",
        "api.anthropic.com",
        "github.com",
        "api.github.com",
        "api.individual.githubcopilot.com",
    ] {
        assert!(hosts.contains(&host(name)), "{name}");
    }
    assert!(!hosts.contains(&host("example.com")));
}

#[test]
fn the_debug_output_names_no_token() {
    let rig = rig();
    let text = format!("{:?}", rig.logins);
    assert!(text.contains("Logins") && !text.contains("CANARY"));
}

#[test]
fn canonical_paths_collapse_every_spelling_to_one() {
    use crate::logins::canonical_path;
    assert_eq!(canonical_path("/a/b"), "/a/b");
    assert_eq!(canonical_path(""), "/");
    assert_eq!(canonical_path("/"), "/");
    assert_eq!(canonical_path("/A//b/./c/../d/"), "/a/b/d");
    assert_eq!(canonical_path("/%41%62"), "/ab");
    assert_eq!(canonical_path("/a%2fb"), "/a/b");
    assert_eq!(canonical_path("/a%zz"), "/a%zz");
    assert_eq!(canonical_path("/a%"), "/a%");
    assert_eq!(canonical_path("/a;x/b?q#f"), "/a");
    assert_eq!(canonical_path("/../../a"), "/a");
    assert_eq!(canonical_path("/%ff"), "/\u{fffd}");
}

#[tokio::test]
async fn loading_twice_registers_each_stand_in_once() {
    let first = rig();
    claude_login(&first, REAL_ACCESS, REAL_REFRESH).await;
    let second = rig_on(&first.store, true);
    second.logins.load().await;
    second.logins.load().await;
    assert_eq!(second.registry.len(), 2);
    assert_eq!(second.notices.seen(), []);
}

#[tokio::test]
async fn a_saved_pair_the_registry_refuses_is_reported_as_unreadable() {
    let first = rig();
    // A stand-in too short to be one: only a damaged or foreign entry looks like this.
    vault(&first)
        .write(&CLAUDE, Role::Access, "short", REAL_ACCESS)
        .unwrap();
    first.logins.load().await;
    assert_eq!(first.registry.len(), 0);
    assert_eq!(
        first.notices.seen(),
        [("claude".to_owned(), Problem::Unreadable)]
    );
}

#[tokio::test]
async fn a_refresh_with_a_token_a_header_cannot_carry_is_passed_on_and_the_user_is_told() {
    let rig = rig();
    claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    let exchange = rig
        .logins
        .begin(&host("platform.claude.com"), "POST", "/v1/oauth/token");
    let body = json!({"access_token": "has a space in it, 0123456789"}).to_string();
    assert_eq!(
        answered(exchange, 200, Some("application/json"), body.as_bytes()).await,
        None
    );
    assert_eq!(
        rig.notices.seen(),
        [("claude".to_owned(), Problem::UnusableToken)]
    );
    // What was kept is still what the workspace holds.
    assert_eq!(rig.registry.len(), 2);
    let kept = vault(&rig).read(&CLAUDE, Role::Access).unwrap().unwrap();
    assert_eq!(kept.real.as_str(), REAL_ACCESS);
}

#[tokio::test]
async fn a_slot_the_registry_lost_is_made_again_by_the_next_answer() {
    let rig = rig();
    let first = claude_login(&rig, REAL_ACCESS, REAL_REFRESH).await;
    let stand_in = first["access_token"].as_str().unwrap();
    assert!(rig.registry.remove(stand_in), "something else removed it");
    assert_eq!(rig.registry.len(), 1);
    let again = claude_login(&rig, ACCESS_B, REFRESH_B).await;
    assert_eq!(again["access_token"], stand_in, "the slot's stand-in stays");
    assert_eq!(rig.registry.len(), 2);
}

/// A credential store that does not answer until it is let go.
struct Stuck(Mutex<std::sync::mpsc::Receiver<()>>);

impl SecretStore for Stuck {
    fn get(
        &self,
        _: &puddle_secrets::StoredId,
    ) -> Result<Option<puddle_secrets::Secret>, puddle_secrets::StoreError> {
        let _ = self.0.lock().unwrap().recv();
        Err(puddle_secrets::StoreError)
    }

    fn set(
        &self,
        _: &puddle_secrets::StoredId,
        _: &puddle_secrets::Secret,
    ) -> Result<(), puddle_secrets::StoreError> {
        Err(puddle_secrets::StoreError)
    }

    fn delete(&self, _: &puddle_secrets::StoredId) -> Result<(), puddle_secrets::StoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn a_credential_store_that_does_not_answer_is_given_up_on_and_the_start_goes_on() {
    let (release, wait) = std::sync::mpsc::channel();
    let store: Arc<dyn SecretStore> = Arc::new(Stuck(Mutex::new(wait)));
    let notices = Arc::new(Notices::default());
    let logins = Logins::new(
        workspace(),
        true,
        builtin(),
        Arc::new(StandIns::new()),
        store,
        Arc::clone(&notices) as Arc<dyn LoginNotices>,
    );
    logins.set_store_timeout(std::time::Duration::from_millis(50));
    logins.load().await;
    assert!(
        notices
            .seen()
            .contains(&("claude".to_owned(), Problem::StoreUnavailable))
    );
    // Let the blocked threads go, one for each slot that was waiting on the store.
    for _ in 0..8 {
        let _ = release.send(());
    }
}

mod properties {
    use std::fmt::Write as _;

    use proptest::prelude::*;

    use crate::logins::canonical_path;

    proptest! {
        #[test]
        fn no_path_a_guest_sends_panics_and_the_spelling_is_always_plain(path in "\\PC{0,80}") {
            let spelled = canonical_path(&path);
            prop_assert!(spelled.starts_with('/'));
            prop_assert!(!spelled.contains("//"));
            prop_assert!(!spelled.contains("/./"));
            prop_assert!(!spelled.contains("/../"));
            prop_assert!(!spelled.contains('\\'));
            prop_assert_eq!(spelled.clone(), spelled.to_ascii_lowercase());
        }

        #[test]
        fn the_token_endpoint_is_found_in_every_spelling_of_its_letters(
            upper in prop::collection::vec(any::<bool>(), 14),
            encode in prop::collection::vec(any::<bool>(), 14),
            slashes in 1_usize..4,
        ) {
            // "/v1/oauth/token" with each letter in either case and either written as itself or
            // percent-encoded, and the slashes doubled.
            let mut spelled = String::new();
            for (i, c) in "v1/oauth/token".chars().enumerate() {
                if c == '/' {
                    spelled.push_str(&"/".repeat(slashes));
                    continue;
                }
                let c = if upper.get(i).copied().unwrap_or(false) { c.to_ascii_uppercase() } else { c };
                if encode.get(i).copied().unwrap_or(false) {
                    let _ = write!(spelled, "%{:02x}", u32::from(c));
                } else {
                    spelled.push(c);
                }
            }
            let path = format!("/{spelled}");
            prop_assert_eq!(canonical_path(&path), "/v1/oauth/token");
        }
    }
}

#[tokio::test]
async fn a_saved_entry_that_is_not_one_of_ours_is_reported_as_unreadable_and_the_rest_still_loads()
{
    let first = rig();
    claude_login(&first, REAL_ACCESS, REAL_REFRESH).await;
    // The refresh slot's entry is damaged.
    let id = crate::vault::slot_id("alpha", "claude", Role::Refresh).unwrap();
    first
        .store
        .set(&id, &puddle_secrets::Secret::new("not json".into()))
        .unwrap();
    let next = rig_on(&first.store, true);
    next.logins.load().await;
    assert_eq!(next.registry.len(), 1, "the access slot is back");
    assert_eq!(
        next.notices.seen(),
        [("claude".to_owned(), Problem::Unreadable)]
    );
}
