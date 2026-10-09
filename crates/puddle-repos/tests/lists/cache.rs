// SPDX-License-Identifier: GPL-3.0-or-later
//! The cache: when a list is read again, one read at a time, the back-off when a host limits
//! requests, stale lists with their reason, and what is forgotten.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::BoxFuture;
use puddle_repos::{
    Api, ApiReply, ApiRequest, Config, Freshness, ListState, ProblemKind, Repos, TransportError,
};
use puddle_secrets::SourceError;
use puddle_store::{Clock, ManualClock};

use crate::common::{REPOS_PATH, Rig, T0, Tokens, binding, data, gh, identities, ok_json, stored};

const MINUTE: u64 = 60_000;
const CANARY: &str = "CANARY-cache-token-77aa";

fn one_gh_identity() -> Vec<puddle_store::Identity> {
    identities(vec![(
        "Me",
        vec![binding(
            "github.com",
            gh("github.com", "octocat"),
            &[],
            true,
        )],
    )])
}

fn rig_signed_in() -> Rig {
    let rig = Rig::new();
    rig.tokens.set(&gh("github.com", "octocat"), CANARY);
    rig
}

fn secondary_limit() -> ApiReply {
    ApiReply::new(403, data("github_rate_limit_secondary.json"))
}

#[tokio::test]
async fn a_list_is_current_for_ten_minutes_then_read_again_and_a_refresh_waits_ten_seconds() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let ids = one_gh_identity();

    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 1);

    // Nine and a half minutes later it is still current.
    rig.clock.advance(9 * MINUTE + 30_000);
    let again = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 1);
    assert_eq!(again[0].refreshed_at, Some(T0));

    // A refresh moments after a read is answered from it.
    rig.clock.set(T0 + 5_000);
    rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(rig.api.count(), 1);

    // A refresh after the gap reads again, though the list is still current.
    rig.clock.set(T0 + 10_000);
    let refreshed = rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(rig.api.count(), 2);
    assert_eq!(refreshed[0].refreshed_at, Some(T0 + 10_000));

    // Past ten minutes a plain request reads again.
    rig.clock.set(T0 + 10_000 + 10 * MINUTE);
    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 3);
}

#[tokio::test]
async fn a_failed_read_is_not_retried_for_half_a_minute_unless_the_user_asks() {
    let rig = rig_signed_in();
    rig.api.fail(
        "api.github.com",
        REPOS_PATH,
        TransportError::Unreachable("no route to host".to_owned()),
    );
    let ids = one_gh_identity();

    let first = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(first[0].state, ListState::Failed);
    assert_eq!(
        first[0].problem.as_ref().unwrap().kind,
        ProblemKind::Unreachable
    );
    assert_eq!(first[0].refreshed_at, None);
    assert_eq!(rig.api.count(), 1);

    // A screen asking again straight away does not hammer the host.
    rig.clock.advance(20_000);
    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 1);

    // The user's Refresh does.
    rig.api.clear("api.github.com", REPOS_PATH);
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let refreshed = rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(rig.api.count(), 2);
    assert_eq!(refreshed[0].state, ListState::Ok);
    assert!(refreshed[0].problem.is_none());
}

#[tokio::test]
async fn after_thirty_seconds_a_plain_request_tries_a_failed_list_again() {
    let rig = rig_signed_in();
    rig.api.fail(
        "api.github.com",
        REPOS_PATH,
        TransportError::Unreachable("offline".to_owned()),
    );
    let ids = one_gh_identity();
    rig.lists(&ids, Freshness::Cached).await;
    rig.clock.advance(30_000);
    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 2);
}

#[tokio::test]
async fn a_secondary_limit_leaves_the_host_alone_until_it_allows_and_says_when() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        secondary_limit().with_header("retry-after", "120"),
    );
    let ids = one_gh_identity();

    let first = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(first[0].state, ListState::Failed);
    let problem = first[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::RateLimited);
    assert!(problem.message.contains("limiting how fast puddle may ask"));
    assert_eq!(first[0].retry_at, Some(T0 + 120_000));
    assert_eq!(rig.api.count(), 1);

    // A refresh before the wait ends sends nothing, and the reason stays.
    rig.clock.advance(60_000);
    let waiting = rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(rig.api.count(), 1);
    assert_eq!(waiting[0].retry_at, Some(T0 + 120_000));
    assert_eq!(
        waiting[0].problem.as_ref().unwrap().kind,
        ProblemKind::RateLimited
    );

    // When the wait is over the next request reads, and success clears the reason.
    rig.api.clear("api.github.com", REPOS_PATH);
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    rig.clock.set(T0 + 120_001);
    let done = rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(rig.api.count(), 2);
    assert_eq!(done[0].state, ListState::Ok);
    assert!(done[0].problem.is_none() && done[0].retry_at.is_none());
}

#[tokio::test]
async fn repeated_limits_with_no_retry_after_wait_a_minute_then_two_then_four() {
    let rig = rig_signed_in();
    rig.api
        .reply("api.github.com", REPOS_PATH, secondary_limit());
    let ids = one_gh_identity();
    let mut waits = Vec::new();
    for _ in 0..3 {
        let lists = rig.lists(&ids, Freshness::Reload).await;
        let until = lists[0].retry_at.unwrap();
        waits.push((until - rig.clock.now_ms()) / 1000);
        rig.clock.set(until);
    }
    assert_eq!(waits, [60, 120, 240]);
    assert_eq!(rig.api.count(), 3);
}

#[tokio::test]
async fn a_primary_limit_waits_for_the_reset_time() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ApiReply::new(403, data("github_rate_limit_primary.json"))
            .with_header("x-ratelimit-remaining", "0")
            .with_header("x-ratelimit-reset", &((T0 / 1000) + 900).to_string()),
    );
    let ids = one_gh_identity();
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].retry_at, Some(T0 + 900_000));
    assert!(
        lists[0]
            .problem
            .as_ref()
            .unwrap()
            .message
            .contains("rate limit is used up")
    );
}

#[tokio::test]
async fn a_list_that_cannot_be_refreshed_stays_on_screen_marked_stale_with_the_reason() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let ids = one_gh_identity();
    rig.lists(&ids, Freshness::Cached).await;

    rig.clock.advance(11 * MINUTE);
    rig.api.clear("api.github.com", REPOS_PATH);
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        secondary_limit().with_header("retry-after", "300"),
    );
    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists[0].state, ListState::Stale);
    assert_eq!(lists[0].refreshed_at, Some(T0));
    assert_eq!(
        lists[0].repos.len(),
        2,
        "the last good list is still served"
    );
    assert_eq!(lists[0].retry_at, Some(T0 + 11 * MINUTE + 300_000));
    assert_eq!(
        lists[0].problem.as_ref().unwrap().kind,
        ProblemKind::RateLimited
    );
}

#[tokio::test]
async fn a_success_that_used_the_last_request_of_the_hour_blocks_until_the_reset() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json")
            .with_header("x-ratelimit-remaining", "0")
            .with_header("x-ratelimit-reset", &((T0 / 1000) + 600).to_string()),
    );
    let ids = one_gh_identity();
    let first = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(first[0].state, ListState::Ok);
    assert_eq!(first[0].retry_at, Some(T0 + 600_000));

    rig.clock.advance(MINUTE);
    rig.lists(&ids, Freshness::Reload).await;
    assert_eq!(
        rig.api.count(),
        1,
        "nothing is asked until the budget resets"
    );
}

#[tokio::test]
async fn a_source_that_needs_a_sign_in_says_so_and_nothing_is_asked() {
    let rig = Rig::new();
    let ids = one_gh_identity();
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists[0].state, ListState::Failed);
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::NotSignedIn);
    assert!(problem.needs_sign_in);
    assert_eq!(problem.message, "not signed in, or the sign-in has expired");
    assert_eq!(rig.api.count(), 0);
}

#[tokio::test]
async fn a_source_that_cannot_run_is_not_a_sign_in_problem() {
    let rig = Rig::new();
    let source = gh("github.com", "octocat");
    rig.tokens
        .fail(&source, SourceError::ToolMissing(puddle_secrets::Tool::Gh));
    let ids = one_gh_identity();
    let lists = rig.lists(&ids, Freshness::Cached).await;
    let problem = lists[0].problem.as_ref().unwrap();
    assert_eq!(problem.kind, ProblemKind::SourceUnavailable);
    assert!(!problem.needs_sign_in);
    assert_eq!(problem.message, "gh is not installed or not on PATH");
}

#[tokio::test]
async fn a_token_the_host_rejects_is_forgotten_by_the_cache_unless_it_was_pasted() {
    let rig = Rig::new();
    let signed_in = gh("github.com", "octocat");
    let pasted = stored("tok-1", "github.com", None);
    rig.tokens.set(&signed_in, CANARY);
    rig.tokens.set(&pasted, CANARY);
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ApiReply::new(401, r#"{"message":"Bad credentials"}"#),
    );
    let ids = identities(vec![
        (
            "Work",
            vec![binding("github.com", signed_in.clone(), &["acme"], false)],
        ),
        ("Mine", vec![binding("github.com", pasted, &[], true)]),
    ]);

    let lists = rig.lists(&ids, Freshness::Cached).await;

    assert_eq!(lists.len(), 2);
    let (work, mine) = (
        lists[0].problem.as_ref().unwrap(),
        lists[1].problem.as_ref().unwrap(),
    );
    assert_eq!(work.kind, ProblemKind::TokenRejected);
    assert!(work.needs_sign_in);
    assert!(work.message.ends_with("sign in again"));
    assert_eq!(mine.kind, ProblemKind::TokenRejected);
    assert!(!mine.needs_sign_in);
    assert!(mine.message.ends_with("paste a new token"));
    assert_eq!(rig.tokens.invalidated(), [signed_in]);
}

#[tokio::test]
async fn reading_one_identity_reads_and_returns_only_its_credentials() {
    let rig = Rig::new();
    let (work, mine) = (
        gh("github.com", "work"),
        stored("tok-1", "github.com", None),
    );
    rig.tokens.set(&work, "CANARY-work");
    rig.tokens.set(&mine, "CANARY-mine");
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let ids = identities(vec![
        ("Work", vec![binding("github.com", work, &["acme"], false)]),
        ("Mine", vec![binding("github.com", mine, &[], true)]),
    ]);

    let only_mine = rig.lists_of(&ids, ids[1].id, Freshness::Cached).await;

    assert_eq!(only_mine.len(), 1);
    assert_eq!(only_mine[0].identity, ids[1].id);
    let seen = rig.api.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].token, "CANARY-mine", "work's token was not used");

    // The other one's list is read when it is asked for; the first stays cached.
    let both = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(both.len(), 2);
    assert_eq!(rig.api.count(), 2);
}

#[tokio::test]
async fn a_list_nobody_refers_to_any_more_is_forgotten() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let ids = one_gh_identity();
    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 1);

    // The identity goes; its list is dropped with it.
    assert_eq!(rig.lists(&[], Freshness::Cached).await, []);
    // It comes back: nothing is remembered, so it is read again at once.
    rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(rig.api.count(), 2);
}

#[tokio::test]
async fn two_identities_with_the_same_credential_share_one_read() {
    let rig = rig_signed_in();
    rig.api.reply(
        "api.github.com",
        REPOS_PATH,
        ok_json("github_user_repos_page2.json"),
    );
    let source = gh("github.com", "octocat");
    let ids = identities(vec![
        (
            "A",
            vec![binding("github.com", source.clone(), &["acme"], false)],
        ),
        ("B", vec![binding("github.com", source, &["other"], false)]),
    ]);
    let lists = rig.lists(&ids, Freshness::Cached).await;
    assert_eq!(lists.len(), 2);
    assert_eq!(rig.api.count(), 1);
    assert_eq!(lists[0].repos, lists[1].repos);
    assert_ne!(lists[0].identity, lists[1].identity);
}

/// An API that holds every request until released, to see how many arrive.
struct Gate {
    arrived: AtomicUsize,
    release: tokio::sync::Notify,
}

impl Api for Gate {
    fn get(&self, _request: ApiRequest) -> BoxFuture<'_, Result<ApiReply, TransportError>> {
        Box::pin(async move {
            self.arrived.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Ok(ApiReply::new(200, "[]"))
        })
    }
}

#[tokio::test]
async fn many_screens_asking_at_once_cause_one_read() {
    let gate = Arc::new(Gate {
        arrived: AtomicUsize::new(0),
        release: tokio::sync::Notify::new(),
    });
    let tokens = Arc::new(Tokens::default());
    tokens.set(&gh("github.com", "octocat"), CANARY);
    let repos = Arc::new(Repos::new(
        gate.clone(),
        tokens,
        Arc::new(ManualClock::new(T0)),
    ));
    let ids = Arc::new(one_gh_identity());
    let asks: Vec<_> = (0..8)
        .map(|_| {
            let (repos, ids) = (repos.clone(), ids.clone());
            tokio::spawn(async move {
                repos
                    .lists(
                        &ids,
                        puddle_repos::Read {
                            only: None,
                            freshness: Freshness::Cached,
                        },
                    )
                    .await
            })
        })
        .collect();
    while gate.arrived.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    // Give the others every chance to arrive too before the first answer is let go.
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    gate.release.notify_waiters();
    for ask in asks {
        let lists = ask.await.unwrap();
        assert_eq!(lists[0].state, ListState::Ok);
    }
    assert_eq!(gate.arrived.load(Ordering::SeqCst), 1);
}

/// An API that never answers.
struct Silent;

impl Api for Silent {
    fn get(&self, _request: ApiRequest) -> BoxFuture<'_, Result<ApiReply, TransportError>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn a_read_that_takes_too_long_gives_up_with_the_reason() {
    let tokens = Arc::new(Tokens::default());
    tokens.set(&gh("github.com", "octocat"), CANARY);
    let repos = Repos::with_config(
        Arc::new(Silent),
        tokens,
        Arc::new(ManualClock::new(T0)),
        Config {
            deadline: Duration::from_secs(3),
            ..Config::default()
        },
    );
    let lists = repos
        .lists(
            &one_gh_identity(),
            puddle_repos::Read {
                only: None,
                freshness: Freshness::Cached,
            },
        )
        .await;
    assert_eq!(lists[0].state, ListState::Failed);
    assert_eq!(
        lists[0].problem.as_ref().unwrap().message,
        "the host could not be reached: no answer within 3 seconds"
    );
}

#[test]
fn the_defaults_are_ten_minutes_thirty_seconds_ten_seconds_and_four_reads() {
    let config = Config::default();
    assert_eq!(config.fresh_for, Duration::from_secs(600));
    assert_eq!(config.retry_after_failure, Duration::from_secs(30));
    assert_eq!(config.min_reload_gap, Duration::from_secs(10));
    assert_eq!(config.deadline, Duration::from_secs(25));
    assert_eq!(config.concurrent_reads, 4);
    let repos = Repos::new(
        Arc::new(Silent),
        Arc::new(Tokens::default()),
        Arc::new(ManualClock::new(T0)),
    );
    assert_eq!(format!("{repos:?}"), "Repos { .. }");
}
