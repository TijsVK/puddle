// SPDX-License-Identifier: GPL-3.0-or-later
//! One named test (or more) per rule of `docs/spec/rules.md`, through the store's public API.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail the test by panicking"
)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use puddle_store::{
    Actor, AuditRecord, ConnectionDecision, ConnectionEvent, ConnectionReason, Effect,
    HttpRequestLine, Limits, ManualClock, NewRule, Pattern, PatternChoice, PatternError,
    PendingState, Resolution, Scope, ScopeChoice, Store, StoreError, Sweeper,
};
use puddle_types::{
    Decision, EgressRequest, Host, PatternKind, PendingId, PendingOutcome, Policy, RuleId,
    SandboxName, SuffixAllows,
};
use serde_json::Value;

const T0: u64 = 1_800_000_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

fn fixture() -> (Arc<ManualClock>, Store) {
    fixture_with(Limits::default())
}

fn fixture_with(limits: Limits) -> (Arc<ManualClock>, Store) {
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open_in_memory(clock.clone(), limits).unwrap();
    (clock, store)
}

fn sb(id: &str) -> SandboxName {
    SandboxName::new(id).unwrap()
}

fn req(sandbox: &str, host: &str, port: u16) -> EgressRequest {
    EgressRequest::new(sb(sandbox), Host::parse_normalised(host).unwrap(), port)
}

fn decide(store: &Store, sandbox: &str, host: &str) -> Decision {
    store
        .decide(&req(sandbox, host, 443), SuffixAllows::Count)
        .unwrap()
}

fn rule(scope: Option<&str>, pattern: &str, effect: Effect) -> NewRule {
    NewRule {
        scope: scope.map_or(Scope::Global, |s| Scope::Sandbox(sb(s))),
        pattern: Pattern::parse(pattern).unwrap(),
        effect,
        expires_at: None,
        created_by: Actor::Cli,
    }
}

fn add(store: &Store, scope: Option<&str>, pattern: &str, effect: Effect) -> RuleId {
    store.add_rule(&rule(scope, pattern, effect)).unwrap().id
}

fn new_pending(decision: Decision) -> PendingId {
    match decision {
        Decision::Pending(PendingOutcome::New(id)) => id,
        other => panic!("expected a new pending row, got {other:?}"),
    }
}

fn audit(store: &Store) -> Vec<Value> {
    store
        .audit_lines(0, 100_000)
        .unwrap()
        .into_iter()
        .map(|(_, line)| serde_json::from_str(&line).unwrap())
        .collect()
}

fn audit_of(store: &Store, kind: &str) -> Vec<Value> {
    audit(store)
        .into_iter()
        .filter(|v| v["type"] == kind)
        .collect()
}

fn allowed_by(decision: Decision) -> Option<RuleId> {
    match decision {
        Decision::Allow { rule_id, .. } => Some(rule_id),
        _ => None,
    }
}

// §2 Matching

#[test]
fn r01_fresh_install_has_no_rules_and_every_request_goes_pending() {
    let (_, store) = fixture();
    assert_eq!(store.rules(), vec![]);
    for host in ["example.com", "localhost", "10.0.0.1", "github.com"] {
        assert!(matches!(
            decide(&store, "a", host),
            Decision::Pending(PendingOutcome::New(_))
        ));
    }
}

#[test]
fn r02_exact_rule_matches_identical_host_on_any_port() {
    let (_, store) = fixture();
    let id = add(&store, None, "api.example.com", Effect::Allow);
    for port in [80, 443, 8443] {
        let d = store
            .decide(&req("a", "api.example.com", port), SuffixAllows::Count)
            .unwrap();
        assert_eq!(allowed_by(d), Some(id));
    }
    assert!(matches!(
        decide(&store, "a", "v2.api.example.com"),
        Decision::Pending(_)
    ));
}

#[test]
fn r03_suffix_rule_matches_below_but_not_the_apex_nor_ips() {
    let (_, store) = fixture();
    let id = add(&store, None, "*.example.com", Effect::Allow);
    assert_eq!(store.rules()[0].pattern.to_string(), ".example.com");
    assert_eq!(allowed_by(decide(&store, "a", "a.b.example.com")), Some(id));
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Pending(_)
    ));
    assert!(matches!(
        decide(&store, "a", "notexample.com"),
        Decision::Pending(_)
    ));
}

#[test]
fn r04_suffix_must_be_longer_than_a_public_suffix() {
    for bad in [".com", "*.co.uk", ".github.io"] {
        assert!(matches!(
            Pattern::parse(bad),
            Err(PatternError::PublicSuffix(_))
        ));
    }
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "www.example.co.uk"));
    let audit_before = audit(&store).len();
    let mut too_wide = Resolution::allow();
    too_wide.pattern = PatternChoice::Suffix("co.uk".into());
    let err = store.resolve_pending(id, &too_wide, Actor::Ui).unwrap_err();
    assert!(matches!(
        err,
        StoreError::Pattern(PatternError::PublicSuffix(_))
    ));
    assert_eq!(store.pending(id).unwrap().state, PendingState::Requested);
    assert_eq!(audit(&store).len(), audit_before);
}

#[test]
fn r05_another_sandboxes_rules_never_apply() {
    let (_, store) = fixture();
    add(&store, Some("b"), "example.com", Effect::Allow);
    let global = add(&store, None, "global.example", Effect::Allow);
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Pending(_)
    ));
    assert!(matches!(
        decide(&store, "b", "example.com"),
        Decision::Allow { .. }
    ));
    assert_eq!(
        allowed_by(decide(&store, "a", "global.example")),
        Some(global)
    );
}

#[test]
fn r06_most_specific_wins_then_sandbox_then_deny() {
    let (_, store) = fixture();
    let global_deny = add(&store, None, ".example.com", Effect::Deny);
    let sandbox_allow = add(&store, Some("a"), ".example.com", Effect::Allow);
    let exact_deny = add(&store, Some("a"), "bad.example.com", Effect::Deny);
    let exact_allow = add(&store, Some("a"), "bad.example.com", Effect::Allow);
    assert_eq!(
        allowed_by(decide(&store, "a", "x.example.com")),
        Some(sandbox_allow)
    );
    assert_eq!(
        decide(&store, "b", "x.example.com"),
        Decision::Deny {
            rule_id: global_deny,
            pattern: PatternKind::Suffix
        }
    );
    assert_eq!(
        decide(&store, "a", "bad.example.com"),
        Decision::Deny {
            rule_id: exact_deny,
            pattern: PatternKind::Exact
        }
    );
    store.delete_rule(exact_deny, Actor::Cli).unwrap();
    assert_eq!(
        allowed_by(decide(&store, "a", "bad.example.com")),
        Some(exact_allow)
    );
    // A broader sandbox allow never overrides a narrower global deny.
    let narrow_deny = add(&store, None, ".api.example.com", Effect::Deny);
    assert_eq!(
        decide(&store, "a", "v1.api.example.com"),
        Decision::Deny {
            rule_id: narrow_deny,
            pattern: PatternKind::Suffix
        }
    );
}

#[test]
fn r07_expired_rule_never_matches_even_before_the_sweeper() {
    let (clock, store) = fixture();
    let mut temp = rule(None, "example.com", Effect::Allow);
    temp.expires_at = Some(T0 + 1000);
    let id = store.add_rule(&temp).unwrap().id;
    clock.set(T0 + 999);
    assert_eq!(allowed_by(decide(&store, "a", "example.com")), Some(id));
    clock.set(T0 + 1000);
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Pending(_)
    ));
    // The sweeper hasn't run: the rule is still stored.
    assert_eq!(store.rules().len(), 1);
}

#[test]
fn r07_expiry_in_the_past_is_refused() {
    let (_, store) = fixture();
    let mut stale = rule(None, "example.com", Effect::Allow);
    stale.expires_at = Some(T0);
    assert!(matches!(
        store.add_rule(&stale),
        Err(StoreError::ExpiryNotInFuture)
    ));
    let id = add(&store, None, "example.com", Effect::Allow);
    assert!(matches!(
        store.set_rule_expiry(id, Some(T0 - 1), Actor::Cli),
        Err(StoreError::ExpiryNotInFuture)
    ));
}

#[test]
fn r08_changes_apply_to_the_next_request_without_restart() {
    let (_, store) = fixture();
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Pending(_)
    ));
    let id = add(&store, Some("a"), "example.com", Effect::Allow);
    assert_eq!(allowed_by(decide(&store, "a", "example.com")), Some(id));
    let updated = store.set_rule_expiry(id, Some(T0 + 10), Actor::Ui).unwrap();
    assert_eq!(updated.expires_at, Some(T0 + 10));
    store.delete_rule(id, Actor::Ui).unwrap();
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Pending(PendingOutcome::New(_))
    ));
}

#[test]
fn r08_concurrent_decisions_never_see_half_a_change() {
    // An approve creates a rule and closes rows in one change. A decider racing it sees either
    // the old world (pending, the row still open) or the new one (allowed), never an allow while
    // the row is still open.
    let (_, store) = fixture();
    let store = Arc::new(store);
    let id = new_pending(decide(&store, "a", "example.com"));
    let done = Arc::new(AtomicBool::new(false));
    let deciders: Vec<_> = (0..4)
        .map(|_| {
            let (store, done) = (Arc::clone(&store), Arc::clone(&done));
            std::thread::spawn(move || {
                let mut saw_allow = false;
                while !done.load(Ordering::SeqCst) {
                    match decide(&store, "a", "example.com") {
                        Decision::Allow { .. } => {
                            saw_allow = true;
                            let row = store.pending(id).unwrap();
                            assert_eq!(row.state, PendingState::Allowed);
                        }
                        Decision::Pending(PendingOutcome::Repeat(p)) => {
                            assert!(!saw_allow, "pending after allow");
                            assert_eq!(p, id);
                        }
                        other => panic!("unexpected {other:?}"),
                    }
                }
            })
        })
        .collect();
    store
        .resolve_pending(id, &Resolution::allow(), Actor::Ui)
        .unwrap();
    assert!(matches!(
        decide(&store, "a", "example.com"),
        Decision::Allow { .. }
    ));
    done.store(true, Ordering::SeqCst);
    for t in deciders {
        t.join().unwrap();
    }
}

#[test]
fn r09_decision_says_how_it_matched() {
    let (_, store) = fixture();
    let suffix = add(&store, None, ".example.com", Effect::Allow);
    let exact = add(&store, None, "bad.example.org", Effect::Deny);
    assert_eq!(
        decide(&store, "a", "x.example.com"),
        Decision::Allow {
            rule_id: suffix,
            pattern: PatternKind::Suffix
        }
    );
    assert_eq!(
        decide(&store, "a", "bad.example.org"),
        Decision::Deny {
            rule_id: exact,
            pattern: PatternKind::Exact
        }
    );
    let id = new_pending(decide(&store, "a", "new.example.net"));
    assert_eq!(
        decide(&store, "a", "new.example.net"),
        Decision::Pending(PendingOutcome::Repeat(id))
    );
}

#[test]
fn policy_trait_is_implemented_by_the_store() {
    let (_, store) = fixture();
    let policy: &dyn Policy = &store;
    let d = policy
        .decide(&req("a", "example.com", 443), SuffixAllows::Count)
        .unwrap();
    assert!(matches!(d, Decision::Pending(PendingOutcome::New(_))));
}

// §3 Pending requests

#[test]
fn r10_unmatched_request_is_recorded_with_first_and_last_seen() {
    let (clock, store) = fixture();
    let id = new_pending(decide(&store, "a", "example.com"));
    clock.advance(5000);
    decide(&store, "a", "example.com");
    let row = store.pending(id).unwrap();
    assert_eq!(
        (row.sandbox.as_str(), row.host.to_string(), row.port),
        ("a", "example.com".to_owned(), 443)
    );
    assert_eq!((row.first_seen, row.last_seen), (T0, T0 + 5000));
    assert_eq!(row.state, PendingState::Requested);
    assert_eq!(audit_of(&store, "pending_created").len(), 1);
}

#[test]
fn r11_repeats_dedupe_onto_the_open_row() {
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "example.com"));
    for _ in 0..3 {
        assert_eq!(
            decide(&store, "a", "example.com"),
            Decision::Pending(PendingOutcome::Repeat(id))
        );
    }
    assert_eq!(store.pending(id).unwrap().attempts, 4);
    // Another port or sandbox is another key.
    let other_port = store
        .decide(&req("a", "example.com", 80), SuffixAllows::Count)
        .unwrap();
    assert_ne!(new_pending(other_port), id);
    assert_ne!(new_pending(decide(&store, "b", "example.com")), id);
    assert_eq!(store.open_pending(Some(&sb("a"))).unwrap().len(), 2);
}

#[test]
fn r11_request_after_the_row_ended_opens_a_new_row() {
    let (clock, store) = fixture();
    let first = new_pending(decide(&store, "a", "example.com"));
    let mut temporary = Resolution::allow();
    temporary.expires_in = Some(Duration::from_secs(60));
    store.resolve_pending(first, &temporary, Actor::Ui).unwrap();
    clock.advance(60_000);
    let second = new_pending(decide(&store, "a", "example.com"));
    assert!(second > first);
}

#[test]
fn r12_pending_rows_are_immutable_and_ids_never_reused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle.db");
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open(&path, clock.clone(), Limits::default()).unwrap();
    let id = new_pending(decide(&store, "a", "example.com"));
    store
        .resolve_pending(id, &Resolution::deny(), Actor::Cli)
        .unwrap();
    drop(store);

    let conn = rusqlite::Connection::open(&path).unwrap();
    for sql in [
        "UPDATE pending SET host = 'evil.example' WHERE id = 1",
        "UPDATE pending SET sandbox_id = 'b' WHERE id = 1",
        "UPDATE pending SET port = 1 WHERE id = 1",
        "UPDATE pending SET first_seen = 0 WHERE id = 1",
        "UPDATE pending SET id = 9 WHERE id = 1",
        "UPDATE pending SET state = 'requested' WHERE id = 1",
        "UPDATE pending SET state = 'allowed' WHERE id = 1",
        "DELETE FROM pending WHERE id = 1",
    ] {
        assert!(conn.execute(sql, []).is_err(), "{sql}");
    }
    drop(conn);

    let store = Store::open(&path, clock, Limits::default()).unwrap();
    let row = store.pending(id).unwrap();
    assert_eq!(
        (row.host.to_string(), row.state),
        ("example.com".to_owned(), PendingState::Denied)
    );
    // Deleted rules' ids aren't reused either.
    let r = store.rules()[0].id;
    store.delete_rule(r, Actor::Cli).unwrap();
    assert!(add(&store, None, "x.example", Effect::Allow) > r);
    let next = new_pending(decide(&store, "a", "other.example"));
    assert!(next > id);
}

#[test]
fn r13_new_rows_are_rate_limited_per_sandbox() {
    let limits = Limits {
        new_rows_burst: 3,
        new_rows_refill_ms: 1000,
        ..Limits::default()
    };
    let (clock, store) = fixture_with(limits);
    for n in 0..3 {
        new_pending(decide(&store, "a", &format!("h{n}.example")));
    }
    for n in 3..6 {
        assert_eq!(
            decide(&store, "a", &format!("h{n}.example")),
            Decision::Pending(PendingOutcome::Suppressed)
        );
    }
    // Other sandboxes have their own bucket.
    new_pending(decide(&store, "b", "h9.example"));
    let suppression = store.suppression(&sb("a"));
    assert!(suppression.active);
    assert_eq!(suppression.count, 3);
    // One record at the start of suppression; the rest wait for the 60 s interval.
    let records = audit_of(&store, "pending_suppressed");
    assert_eq!(records.len(), 1);
    assert_eq!(
        (
            records[0]["sandbox_id"].clone(),
            records[0]["count"].clone()
        ),
        ("a".into(), 1.into())
    );
    clock.advance(1000);
    new_pending(decide(&store, "a", "h7.example"));
    assert!(!store.suppression(&sb("a")).active);
    let records = audit_of(&store, "pending_suppressed");
    assert_eq!(records.len(), 2);
    assert_eq!(records[1]["count"], 2);
    assert_eq!(store.open_pending(Some(&sb("a"))).unwrap().len(), 4);
}

#[test]
fn r13_open_rows_are_capped_and_repeats_use_no_tokens() {
    let limits = Limits {
        max_open_rows: 2,
        new_rows_burst: 100,
        ..Limits::default()
    };
    let (clock, store) = fixture_with(limits);
    let first = new_pending(decide(&store, "a", "one.example"));
    new_pending(decide(&store, "a", "two.example"));
    assert_eq!(
        decide(&store, "a", "three.example"),
        Decision::Pending(PendingOutcome::Suppressed)
    );
    for _ in 0..200 {
        assert_eq!(
            decide(&store, "a", "one.example"),
            Decision::Pending(PendingOutcome::Repeat(first))
        );
    }
    store
        .resolve_pending(first, &Resolution::deny(), Actor::Ui)
        .unwrap();
    new_pending(decide(&store, "a", "three.example"));
    // Suppression flushes from the sweeper too, once its interval passes.
    assert_eq!(
        decide(&store, "a", "four.example"),
        Decision::Pending(PendingOutcome::Suppressed)
    );
    assert_eq!(
        decide(&store, "a", "five.example"),
        Decision::Pending(PendingOutcome::Suppressed)
    );
    clock.advance(60_000);
    store.sweep().unwrap();
    let counts: Vec<_> = audit_of(&store, "pending_suppressed")
        .iter()
        .map(|r| r["count"].as_u64().unwrap())
        .collect();
    assert_eq!(counts, [1, 1, 1]);
}

#[test]
fn r14_suffix_allow_is_no_match_when_an_exact_allow_is_required() {
    let (_, store) = fixture();
    let suffix = add(&store, None, ".corp.example", Effect::Allow);
    let deny = add(&store, None, ".secret.corp.example", Effect::Deny);
    let first = decide(&store, "a", "db.corp.example");
    assert_eq!(
        first,
        Decision::Allow {
            rule_id: suffix,
            pattern: PatternKind::Suffix
        }
    );
    // The proxy resolved it to a local address: suffix allows don't count.
    let local = req("a", "db.corp.example", 5432);
    let id = new_pending(store.decide(&local, SuffixAllows::Ignore).unwrap());
    assert_eq!(
        store.pending(id).unwrap().host.to_string(),
        "db.corp.example"
    );
    // Suffix denies still count.
    assert_eq!(
        store
            .decide(&req("a", "x.secret.corp.example", 1), SuffixAllows::Ignore)
            .unwrap(),
        Decision::Deny {
            rule_id: deny,
            pattern: PatternKind::Suffix
        }
    );
    let decided = store
        .resolve_pending(id, &Resolution::allow(), Actor::Ui)
        .unwrap();
    assert_eq!(
        store.decide(&local, SuffixAllows::Ignore).unwrap(),
        Decision::Allow {
            rule_id: decided.rule.id,
            pattern: PatternKind::Exact
        }
    );
}

#[test]
fn r14_lookup_finds_an_exact_ip_rule_and_never_writes_a_pending_row() {
    let (clock, store) = fixture();
    let ip = add(&store, Some("a"), "192.168.1.20", Effect::Allow);
    let deny = add(&store, None, "192.168.1.21", Effect::Deny);
    let expiring = store
        .add_rule(&NewRule {
            expires_at: Some(T0 + DAY),
            ..rule(None, "192.168.1.22", Effect::Allow)
        })
        .unwrap()
        .id;
    let lookup = |sandbox: &str, host: &str| {
        Policy::lookup(&store, &req(sandbox, host, 443), SuffixAllows::Ignore).unwrap()
    };
    assert_eq!(
        lookup("a", "192.168.1.20"),
        Some(Decision::Allow {
            rule_id: ip,
            pattern: PatternKind::Exact
        })
    );
    assert_eq!(
        lookup("a", "192.168.1.21"),
        Some(Decision::Deny {
            rule_id: deny,
            pattern: PatternKind::Exact
        })
    );
    assert_eq!(
        lookup("a", "192.168.1.22"),
        Some(Decision::Allow {
            rule_id: expiring,
            pattern: PatternKind::Exact
        })
    );
    // Another sandbox's rule, an unlisted neighbour and an expired rule: no match, no row.
    assert_eq!(lookup("b", "192.168.1.20"), None);
    assert_eq!(lookup("a", "192.168.1.23"), None);
    clock.advance(DAY);
    assert_eq!(lookup("a", "192.168.1.22"), None);
    assert_eq!(store.open_pending(None).unwrap().len(), 0);
}

#[test]
fn r15_approve_defaults_to_this_sandbox_exact_host_permanent() {
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "api.example.com"));
    let decided = store
        .resolve_pending(id, &Resolution::allow(), Actor::Ui)
        .unwrap();
    let rule = decided.rule;
    assert_eq!(rule.scope, Scope::Sandbox(sb("a")));
    assert_eq!(rule.pattern.to_string(), "api.example.com");
    assert_eq!(rule.effect, Effect::Allow);
    assert_eq!(rule.expires_at, None);
    assert_eq!(rule.source_pending_id, Some(id));
    assert_eq!(rule.created_by, Actor::Ui);
    // Not widened: siblings, the apex and other sandboxes are still unknown.
    for (sandbox, host) in [
        ("a", "v2.api.example.com"),
        ("a", "example.com"),
        ("b", "api.example.com"),
    ] {
        assert!(matches!(
            decide(&store, sandbox, host),
            Decision::Pending(_)
        ));
    }
}

#[test]
fn r15_all_four_choices_are_honoured() {
    let (clock, store) = fixture();
    let id = new_pending(decide(&store, "a", "x.api.example.com"));
    let resolution = Resolution {
        effect: Effect::Deny,
        scope: ScopeChoice::Global,
        pattern: PatternChoice::Suffix("*.example.com".into()),
        expires_in: Some(Duration::from_secs(3600)),
    };
    let decided = store.resolve_pending(id, &resolution, Actor::Api).unwrap();
    assert_eq!(decided.row.state, PendingState::Denied);
    assert_eq!(decided.rule.scope, Scope::Global);
    assert_eq!(decided.rule.pattern.to_string(), ".example.com");
    assert_eq!(decided.rule.expires_at, Some(T0 + 3_600_000));
    assert!(matches!(
        decide(&store, "b", "y.example.com"),
        Decision::Deny { .. }
    ));
    clock.advance(3_600_000);
    assert!(matches!(
        decide(&store, "b", "y.example.com"),
        Decision::Pending(_)
    ));
}

#[test]
fn r15_invalid_choices_are_refused() {
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "x.example.com"));
    let ip = new_pending(decide(&store, "a", "10.0.0.1"));
    let mut other = Resolution::allow();
    other.pattern = PatternChoice::Suffix("other.com".into());
    assert!(matches!(
        store.resolve_pending(id, &other, Actor::Ui),
        Err(StoreError::Pattern(PatternError::NotASuffixOf { .. }))
    ));
    let mut wide = Resolution::allow();
    wide.pattern = PatternChoice::Suffix("example.com".into());
    assert!(matches!(
        store.resolve_pending(ip, &wide, Actor::Ui),
        Err(StoreError::Pattern(PatternError::SuffixOfIp))
    ));
    let mut zero = Resolution::allow();
    zero.expires_in = Some(Duration::ZERO);
    assert!(matches!(
        store.resolve_pending(id, &zero, Actor::Ui),
        Err(StoreError::ExpiryNotInFuture)
    ));
    assert!(matches!(
        store.resolve_pending(id, &Resolution::allow(), Actor::System),
        Err(StoreError::SystemActor)
    ));
    let mut system_rule = rule(None, "example.com", Effect::Allow);
    system_rule.created_by = Actor::System;
    assert!(matches!(
        store.add_rule(&system_rule),
        Err(StoreError::SystemActor)
    ));
    assert!(matches!(
        store.set_rule_expiry(RuleId(1), None, Actor::System),
        Err(StoreError::SystemActor)
    ));
    assert_eq!(store.rules(), vec![]);
}

#[test]
fn r16_a_decision_closes_every_other_row_the_rule_decides() {
    let (_, store) = fixture();
    let target = new_pending(decide(&store, "a", "x.example.com"));
    let same_sandbox = new_pending(decide(&store, "a", "y.example.com"));
    let other_sandbox = new_pending(decide(&store, "b", "z.example.com"));
    let apex = new_pending(decide(&store, "a", "example.com"));
    let unrelated = new_pending(decide(&store, "a", "example.org"));

    let mut sandbox_suffix = Resolution::allow();
    sandbox_suffix.pattern = PatternChoice::Suffix("example.com".into());
    let decided = store
        .resolve_pending(target, &sandbox_suffix, Actor::Ui)
        .unwrap();
    assert_eq!(decided.also_closed, vec![same_sandbox]);
    let closed = store.pending(same_sandbox).unwrap();
    assert_eq!(closed.state, PendingState::Allowed);
    assert_eq!(closed.rule_id, Some(decided.rule.id));
    assert_eq!(closed.decided_by, Some(Actor::Ui));
    for open in [other_sandbox, apex, unrelated] {
        assert_eq!(store.pending(open).unwrap().state, PendingState::Requested);
    }

    // A global rule closes the rows it decides in every sandbox.
    let c_row = new_pending(decide(&store, "c", "v.example.com"));
    let id = new_pending(decide(&store, "b", "q.example.com"));
    let mut global_deny = Resolution::deny();
    global_deny.scope = ScopeChoice::Global;
    global_deny.pattern = PatternChoice::Suffix("example.com".into());
    let decided = store.resolve_pending(id, &global_deny, Actor::Ui).unwrap();
    let closed: HashSet<_> = decided.also_closed.into_iter().collect();
    assert_eq!(closed, HashSet::from([other_sandbox, c_row]));
    assert_eq!(
        store.pending(other_sandbox).unwrap().state,
        PendingState::Denied
    );
    assert_eq!(audit_of(&store, "pending_decided").len(), 5);
}

#[test]
fn r16_adding_a_rule_directly_closes_the_rows_it_decides() {
    let (_, store) = fixture();
    let row = new_pending(decide(&store, "a", "example.com"));
    let id = add(&store, None, "example.com", Effect::Allow);
    let closed = store.pending(row).unwrap();
    assert_eq!(
        (closed.state, closed.rule_id),
        (PendingState::Allowed, Some(id))
    );
}

#[test]
fn r17_stale_ids_are_refused_and_nothing_changes() {
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "example.com"));
    store
        .resolve_pending(id, &Resolution::allow(), Actor::Cli)
        .unwrap();
    let before = (store.rules(), audit(&store).len());
    let err = store
        .resolve_pending(id, &Resolution::deny(), Actor::Cli)
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::PendingNotOpen {
            state: PendingState::Allowed,
            ..
        }
    ));
    assert!(err.to_string().contains("already allowed"), "{err}");
    let err = store
        .resolve_pending(PendingId(999), &Resolution::allow(), Actor::Cli)
        .unwrap_err();
    assert!(matches!(err, StoreError::UnknownPending(PendingId(999))));
    assert_eq!((store.rules(), audit(&store).len()), before);
    assert!(matches!(
        store.delete_rule(RuleId(999), Actor::Cli),
        Err(StoreError::UnknownRule(RuleId(999)))
    ));
}

#[test]
fn r17_success_echoes_exactly_what_was_approved() {
    let (_, store) = fixture();
    let id = new_pending(
        store
            .decide(&req("a", "api.example.com", 8443), SuffixAllows::Count)
            .unwrap(),
    );
    let decided = store
        .resolve_pending(id, &Resolution::allow(), Actor::Cli)
        .unwrap();
    assert_eq!(
        (
            decided.row.sandbox.as_str(),
            decided.row.host.to_string(),
            decided.row.port
        ),
        ("a", "api.example.com".to_owned(), 8443)
    );
    assert_eq!(decided.row.state, PendingState::Allowed);
    assert_eq!(decided.row.rule_id, Some(decided.rule.id));
}

#[test]
fn r18_inbox_groups_by_registrable_domain() {
    let (clock, store) = fixture();
    for host in [
        "a.example.co.uk",
        "b.example.co.uk",
        "example.org",
        "10.0.0.1",
    ] {
        decide(&store, "a", host);
        clock.advance(1);
    }
    decide(&store, "b", "c.example.co.uk");
    let groups = store.inbox().unwrap();
    let summary: Vec<_> = groups
        .iter()
        .map(|g| (g.registrable_domain.as_str(), g.rows.len()))
        .collect();
    assert_eq!(
        summary,
        [("example.co.uk", 3), ("10.0.0.1", 1), ("example.org", 1)]
    );
    // Most recent row first within a group.
    assert_eq!(groups[0].rows[0].sandbox.as_str(), "b");
}

// §4 Sweeper

#[test]
fn r19_sweeper_deletes_expired_rules_and_records_them_whole() {
    let (clock, store) = fixture();
    let mut temp = rule(Some("a"), ".example.com", Effect::Allow);
    temp.expires_at = Some(T0 + 10);
    let id = store.add_rule(&temp).unwrap().id;
    let keep = add(&store, None, "example.org", Effect::Allow);
    assert_eq!(store.sweep().unwrap().rules_expired, 0);
    clock.advance(10);
    let report = store.sweep().unwrap();
    assert_eq!(report.rules_expired, 1);
    let ids: Vec<_> = store.rules().iter().map(|r| r.id).collect();
    assert_eq!(ids, [keep]);
    let records = audit_of(&store, "rule_expired");
    assert_eq!(records.len(), 1);
    let r = &records[0]["rule"];
    assert_eq!(r["id"], id.0);
    assert_eq!(r["pattern"], ".example.com");
    assert_eq!(r["sandbox_id"], "a");
    assert_eq!(r["expires_at"], T0 + 10);
}

#[test]
fn r20_open_rows_expire_after_seven_days_without_a_repeat() {
    let (clock, store) = fixture();
    let old = new_pending(decide(&store, "a", "old.example"));
    let busy = new_pending(decide(&store, "a", "busy.example"));
    clock.advance(6 * DAY);
    decide(&store, "a", "busy.example");
    clock.advance(DAY);
    let report = store.sweep().unwrap();
    assert_eq!(report.pending_expired, 1);
    let row = store.pending(old).unwrap();
    assert_eq!(
        (row.state, row.decided_by),
        (PendingState::Expired, Some(Actor::System))
    );
    assert_eq!(store.pending(busy).unwrap().state, PendingState::Requested);
    let records = audit_of(&store, "pending_expired");
    assert_eq!(records[0]["reason"], "stale");
}

#[test]
fn r21_sandbox_deletion_removes_its_rules_and_expires_its_rows() {
    let (_, store) = fixture();
    add(&store, Some("a"), "example.com", Effect::Allow);
    add(&store, Some("a"), ".example.org", Effect::Deny);
    let global = add(&store, None, "example.net", Effect::Allow);
    let b_rule = add(&store, Some("b"), "example.com", Effect::Allow);
    let a_row = new_pending(decide(&store, "a", "x.example"));
    let b_row = new_pending(decide(&store, "b", "x.example"));
    let deletion = store.delete_sandbox(&sb("a")).unwrap();
    assert_eq!((deletion.rules_deleted, deletion.pending_expired), (2, 1));
    let ids: Vec<_> = store.rules().iter().map(|r| r.id).collect();
    assert_eq!(ids, [global, b_rule]);
    assert_eq!(store.pending(a_row).unwrap().state, PendingState::Expired);
    assert_eq!(store.pending(b_row).unwrap().state, PendingState::Requested);
    let deleted = audit_of(&store, "rule_deleted");
    assert_eq!(deleted.len(), 2);
    assert!(
        deleted
            .iter()
            .all(|r| r["reason"] == "sandbox_deleted" && r["actor"] == "system")
    );
    assert_eq!(
        audit_of(&store, "pending_expired")[0]["reason"],
        "sandbox_deleted"
    );
}

#[test]
fn r22_sweeper_enforces_the_audit_cap() {
    let limits = Limits {
        audit_max_bytes: 20_000,
        audit_trim_to_bytes: 10_000,
        new_rows_burst: 1000,
        ..Limits::default()
    };
    let (clock, store) = fixture_with(limits);
    for n in 0..200 {
        clock.advance(1);
        decide(&store, "a", &format!("h{n}.example"));
    }
    let before = store.audit_bytes().unwrap();
    assert!(before > 20_000, "{before}");
    let report = store.sweep().unwrap();
    assert!(report.audit_records_trimmed > 0);
    assert!(store.audit_bytes().unwrap() <= 10_000 + 4096);
    let lines = audit(&store);
    let trimmed = lines.last().unwrap();
    assert_eq!(trimmed["type"], "audit_trimmed");
    assert_eq!(trimmed["deleted_records"], report.audit_records_trimmed);
    // The oldest records went first.
    let oldest_kept = trimmed["oldest_ts_kept"].as_u64().unwrap();
    assert!(
        lines
            .iter()
            .all(|l| l["ts"].as_u64().unwrap() >= oldest_kept)
    );
    assert_eq!(store.sweep().unwrap().audit_records_trimmed, 0);
}

#[tokio::test]
async fn sweeper_task_sweeps_at_start_and_shuts_down() {
    let (clock, store) = fixture();
    let mut temp = rule(None, "example.com", Effect::Allow);
    temp.expires_at = Some(T0 + 1);
    store.add_rule(&temp).unwrap();
    clock.advance(1);
    let store = Arc::new(store);
    let sweeper = Sweeper::spawn(Arc::clone(&store), Duration::from_secs(3600));
    let swept = tokio::time::timeout(Duration::from_secs(10), async {
        while !store.rules().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(swept.is_ok(), "sweeper didn't run its first pass");
    sweeper.shutdown().await;
}

// §5 Audit

#[test]
fn r23_every_stored_line_is_tagged_json_with_nulls_written() {
    let (_, store) = fixture();
    let id = new_pending(decide(&store, "a", "example.com"));
    store
        .resolve_pending(id, &Resolution::allow(), Actor::Ui)
        .unwrap();
    for (_, line) in store.audit_lines(0, 1000).unwrap() {
        let value: Value = serde_json::from_str(&line).unwrap();
        assert!(value["type"].is_string());
        assert!(value["ts"].is_u64());
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back.to_line().unwrap(), line);
    }
    let created = &audit_of(&store, "rule_created")[0]["rule"];
    assert!(created.get("expires_at").unwrap().is_null());
}

#[test]
fn r24_the_store_writes_each_record_type_it_owns() {
    let (clock, store) = fixture_with(Limits {
        new_rows_burst: 2,
        audit_max_bytes: 1,
        audit_trim_to_bytes: 0,
        ..Limits::default()
    });
    let a = new_pending(decide(&store, "a", "a.example"));
    new_pending(decide(&store, "a", "b.example"));
    decide(&store, "a", "c.example");
    let decided = store
        .resolve_pending(a, &Resolution::allow(), Actor::Ui)
        .unwrap();
    store
        .set_rule_expiry(decided.rule.id, Some(T0 + 5), Actor::Ui)
        .unwrap();
    let other = add(&store, None, "d.example", Effect::Deny);
    store.delete_rule(other, Actor::Cli).unwrap();
    store.record_connection(&connection("a")).unwrap();
    clock.advance(8 * DAY);
    let kinds: HashSet<String> = audit(&store)
        .iter()
        .map(|v| v["type"].as_str().unwrap().to_owned())
        .collect();
    store.sweep().unwrap();
    let mut all = kinds;
    all.extend(
        audit(&store)
            .iter()
            .map(|v| v["type"].as_str().unwrap().to_owned()),
    );
    for kind in [
        "connection",
        "pending_created",
        "pending_decided",
        "pending_suppressed",
        "rule_created",
        "rule_updated",
        "rule_deleted",
        "audit_trimmed",
    ] {
        assert!(all.contains(kind), "{kind} missing from {all:?}");
    }
}

fn connection(sandbox: &str) -> ConnectionEvent {
    ConnectionEvent {
        sandbox: sb(sandbox),
        host: Host::parse_normalised("api.example.com").unwrap(),
        port: 443,
        resolved_ip: Some("93.184.216.34".parse().unwrap()),
        decision: ConnectionDecision::Allow,
        reason: ConnectionReason::Rule,
        rule_id: Some(RuleId(1)),
        pending_id: None,
        binding_id: Some("gh".into()),
        injected: true,
        http: Some(HttpRequestLine {
            method: "GET".into(),
            target: "/repos".into(),
        }),
        bytes_up: 1,
        bytes_down: 2,
    }
}

#[test]
fn r25_no_secret_reaches_the_audit() {
    const CANARY: &str = "CANARY-r25-9d1e";
    let (_, store) = fixture();
    let mut event = connection("a");
    event.http = Some(HttpRequestLine {
        method: "POST".into(),
        target: format!("https://x:{CANARY}@api.example.com/o/a?access_token={CANARY}#{CANARY}"),
    });
    store.record_connection(&event).unwrap();
    for (_, line) in store.audit_lines(0, 100).unwrap() {
        assert!(!line.contains(CANARY), "{line}");
    }
    let record = &audit_of(&store, "connection")[0];
    assert_eq!(record["path"], "/o/a");
    assert_eq!(record["binding_id"], "gh");
    assert_eq!(record["injected"], true);
}

#[test]
fn r26_connection_records_are_limited_per_sandbox_per_second() {
    let (clock, store) = fixture_with(Limits {
        connection_records_per_second: 3,
        ..Limits::default()
    });
    for _ in 0..5 {
        store.record_connection(&connection("a")).unwrap();
    }
    store.record_connection(&connection("b")).unwrap();
    assert_eq!(audit_of(&store, "connection").len(), 4);
    clock.advance(1000);
    store.record_connection(&connection("a")).unwrap();
    let records = audit_of(&store, "connection");
    let summary: Vec<_> = records
        .iter()
        .filter(|r| r["reason"] == "suppressed")
        .collect();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["count"], 2);
    assert_eq!(summary[0]["sandbox_id"], "a");
    assert!(summary[0]["host"].is_null());
    // A second with excess but no later record is flushed by the sweeper.
    for _ in 0..4 {
        store.record_connection(&connection("b")).unwrap();
    }
    clock.advance(1000);
    store.sweep().unwrap();
    let flushed: Vec<_> = audit_of(&store, "connection")
        .into_iter()
        .filter(|r| r["reason"] == "suppressed" && r["sandbox_id"] == "b")
        .collect();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0]["count"], 1);
}

#[test]
fn r26_every_line_fits_the_cap() {
    let (_, store) = fixture();
    let mut event = connection("a");
    event.http = Some(HttpRequestLine {
        method: "\u{1}".repeat(3000),
        target: format!("/{}", "\u{85}".repeat(5000)),
    });
    event.binding_id = Some("x".repeat(5000));
    store.record_connection(&event).unwrap();
    for (_, line) in store.audit_lines(0, 10).unwrap() {
        assert!(line.len() <= puddle_store::MAX_LINE_BYTES);
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["path_truncated"], true);
    }
}

// Persistence and the property tests the task asks for.

#[test]
fn rules_and_rows_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle.db");
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open(&path, clock.clone(), Limits::default()).unwrap();
    let id = add(&store, Some("a"), ".example.com", Effect::Allow);
    let row = new_pending(decide(&store, "a", "example.org"));
    drop(store);
    let store = Store::open(&path, clock, Limits::default()).unwrap();
    assert_eq!(allowed_by(decide(&store, "a", "x.example.com")), Some(id));
    assert_eq!(
        decide(&store, "a", "example.org"),
        Decision::Pending(PendingOutcome::Repeat(row))
    );
}

#[test]
fn a_database_from_a_newer_puddle_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", puddle_store::SCHEMA_VERSION + 1)
        .unwrap();
    drop(conn);
    let clock = Arc::new(ManualClock::new(T0));
    assert!(matches!(
        Store::open(&path, clock, Limits::default()),
        Err(StoreError::SchemaTooNew { .. })
    ));
}

#[derive(Debug, Clone)]
enum Step {
    Request { host: u8, port: u8 },
    Approve { row: u8 },
    Advance { ms: u32 },
    Sweep,
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => (0..4u8, 0..2u8).prop_map(|(host, port)| Step::Request { host, port }),
        1 => (0..8u8).prop_map(|row| Step::Approve { row }),
        1 => (0..3_000_000u32).prop_map(|ms| Step::Advance { ms }),
        1 => Just(Step::Sweep),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// R-11 and R-12: whatever happens, there is at most one open row per key, ids only grow,
    /// and a decided row never reopens.
    #[test]
    fn dedupe_keeps_one_open_row_per_key(steps in proptest::collection::vec(step(), 1..40)) {
        let (clock, store) = fixture();
        let mut ids: Vec<PendingId> = Vec::new();
        for s in steps {
            match s {
                Step::Request { host, port } => {
                    let r = req("a", &format!("h{host}.example"), 440 + u16::from(port));
                    if let Decision::Pending(PendingOutcome::New(id)) = store.decide(&r, SuffixAllows::Count).unwrap() {
                        prop_assert!(ids.last().is_none_or(|last| id > *last));
                        ids.push(id);
                    }
                }
                Step::Approve { row } => {
                    if let Some(id) = ids.get(usize::from(row)) {
                        let mut temporary = Resolution::allow();
                        temporary.expires_in = Some(Duration::from_secs(1000));
                        let _ = store.resolve_pending(*id, &temporary, Actor::Ui);
                    }
                }
                Step::Advance { ms } => clock.advance(u64::from(ms)),
                Step::Sweep => { store.sweep().unwrap(); }
            }
            let open = store.open_pending(None).unwrap();
            let keys: HashSet<_> = open.iter().map(|r| (r.host.to_string(), r.port)).collect();
            prop_assert_eq!(keys.len(), open.len());
        }
        for id in ids {
            let row = store.pending(id).unwrap();
            prop_assert!(row.attempts >= 1);
            prop_assert!(row.last_seen >= row.first_seen);
        }
    }

    /// R-7: a rule decides exactly while `now < expires_at`, with or without a sweep.
    #[test]
    fn expiry_is_exact_to_the_millisecond(
        lifetime in 1..10_000u64,
        at in 0..20_000u64,
        sweep in any::<bool>(),
    ) {
        let (clock, store) = fixture();
        let mut temp = rule(Some("a"), "example.com", Effect::Allow);
        temp.expires_at = Some(T0 + lifetime);
        let id = store.add_rule(&temp).unwrap().id;
        clock.set(T0 + at);
        if sweep {
            store.sweep().unwrap();
        }
        let allowed = allowed_by(decide(&store, "a", "example.com")) == Some(id);
        prop_assert_eq!(allowed, at < lifetime);
    }
}
