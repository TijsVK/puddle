// SPDX-License-Identifier: GPL-3.0-or-later
//! The events the store emits for every change, and the filtered audit queries behind
//! `GET /api/audit`.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail the test by panicking"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use puddle_store::{
    Actor, AuditCursor, AuditFilter, AuditOutcome, AuditRecord, ConnectionRecord, Effect, Limits,
    ManualClock, NewRule, Pattern, PendingExpiryReason, PendingWire, Resolution, RuleDeleteReason,
    RuleWire, Scope, Store,
};
use puddle_types::{
    CollectingSink, ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionOrigin,
    ConnectionReason, Decision, EgressRequest, Event, Host, PendingEnd, PendingId, PendingOutcome,
    SandboxName, SuffixAllows,
};
use rusqlite::params;

const T0: u64 = 1_800_000_000_000;

fn sb(id: &str) -> SandboxName {
    SandboxName::new(id).unwrap()
}

fn fixture(limits: Limits) -> (Arc<ManualClock>, Arc<CollectingSink>, Store) {
    let clock = Arc::new(ManualClock::new(T0));
    let sink = Arc::new(CollectingSink::default());
    let store = Store::open_in_memory(clock.clone(), limits)
        .unwrap()
        .with_events(sink.clone());
    (clock, sink, store)
}

fn ask(store: &Store, sandbox: &str, host: &str) -> PendingOutcome {
    match store
        .decide(
            &EgressRequest::new(sb(sandbox), Host::parse_normalised(host).unwrap(), 443),
            SuffixAllows::Count,
        )
        .unwrap()
    {
        Decision::Pending(outcome) => outcome,
        other => panic!("expected pending, got {other:?}"),
    }
}

fn new_id(outcome: PendingOutcome) -> PendingId {
    match outcome {
        PendingOutcome::New(id) => id,
        other => panic!("expected a new row, got {other:?}"),
    }
}

fn newest_audit_id(store: &Store) -> i64 {
    store
        .audit_query(&AuditFilter::default(), AuditCursor::Before(None), 1)
        .unwrap()
        .first()
        .map_or(0, |(id, _)| *id)
}

fn kinds(events: &[Event]) -> Vec<&'static str> {
    events
        .iter()
        .map(|e| match e {
            Event::PendingOpened { .. } => "pending_opened",
            Event::PendingUpdated { .. } => "pending_updated",
            Event::PendingClosed { .. } => "pending_closed",
            Event::SuppressionChanged { .. } => "suppression_changed",
            Event::RulesChanged {} => "rules_changed",
            Event::AuditAppended { .. } => "audit_appended",
            _ => "other",
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Events

#[test]
fn a_new_request_opens_a_pending_row_and_appends_to_the_audit() {
    let (_, sink, store) = fixture(Limits::default());
    let id = new_id(ask(&store, "a", "api.example.co.uk"));
    let events = sink.take();
    assert_eq!(kinds(&events), ["pending_opened", "audit_appended"]);
    let Event::PendingOpened { request } = &events[0] else {
        panic!()
    };
    assert_eq!(
        (request.id, request.sandbox.as_str(), request.host.as_str()),
        (id.0, "a", "api.example.co.uk")
    );
    assert_eq!(request.registrable_domain, "example.co.uk");
    assert_eq!(
        (request.port, request.attempts, request.first_seen),
        (443, 1, T0)
    );
    assert_eq!(
        events[1],
        Event::AuditAppended {
            id: newest_audit_id(&store)
        }
    );
}

#[test]
fn a_repeat_updates_the_row_and_writes_no_audit_record() {
    let (clock, sink, store) = fixture(Limits::default());
    let id = new_id(ask(&store, "a", "example.com"));
    drop(sink.take());
    clock.advance(5000);
    ask(&store, "a", "example.com");
    assert_eq!(
        sink.take(),
        [Event::PendingUpdated {
            sandbox: sb("a"),
            id: id.0,
            attempts: 2,
            last_seen: T0 + 5000,
        }]
    );
}

#[test]
fn approving_closes_the_row_and_reports_the_rule_and_every_other_row_it_decides() {
    let (_, sink, store) = fixture(Limits::default());
    let first = new_id(ask(&store, "a", "api.example.com"));
    let second = new_id(ask(&store, "a", "www.example.com"));
    let other = new_id(ask(&store, "b", "www.example.com"));
    drop(sink.take());
    let mut resolution = Resolution::allow();
    resolution.pattern = puddle_store::PatternChoice::Suffix("example.com".into());
    // The CLI path emits like the API path: events come from the store, not the caller.
    let decided = store
        .resolve_pending(first, &resolution, Actor::Cli)
        .unwrap();
    assert_eq!(decided.also_closed, [second]);
    let events = sink.take();
    let closed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::PendingClosed {
                sandbox,
                id,
                state,
                rule_id,
            } => Some((sandbox.to_string(), *id, *state, *rule_id)),
            _ => None,
        })
        .collect();
    let rule = Some(decided.rule.id.0);
    assert_eq!(
        closed,
        [
            ("a".to_owned(), first.0, PendingEnd::Allowed, rule),
            ("a".to_owned(), second.0, PendingEnd::Allowed, rule),
        ],
        "the other sandbox's row ({other:?}) is not covered by a sandbox rule"
    );
    let tail = kinds(&events);
    assert_eq!(
        &tail[tail.len() - 2..],
        ["rules_changed", "audit_appended"],
        "{tail:?}"
    );
    assert_eq!(
        events.last(),
        Some(&Event::AuditAppended {
            id: newest_audit_id(&store)
        })
    );
}

#[test]
fn denying_reports_denied() {
    let (_, sink, store) = fixture(Limits::default());
    let id = new_id(ask(&store, "a", "bad.example"));
    drop(sink.take());
    store
        .resolve_pending(id, &Resolution::deny(), Actor::Api)
        .unwrap();
    assert!(sink.take().iter().any(|e| matches!(
        e,
        Event::PendingClosed {
            state: PendingEnd::Denied,
            ..
        }
    )));
}

#[test]
fn rule_changes_emit_rules_changed_and_a_rule_that_decides_open_rows_closes_them() {
    let (clock, sink, store) = fixture(Limits::default());
    let id = new_id(ask(&store, "a", "www.example.com"));
    drop(sink.take());
    let rule = store
        .add_rule(&NewRule {
            scope: Scope::Global,
            pattern: Pattern::parse(".example.com").unwrap(),
            effect: Effect::Deny,
            expires_at: Some(T0 + 60_000),
            created_by: Actor::Cli,
        })
        .unwrap();
    let events = sink.take();
    assert!(events.contains(&Event::PendingClosed {
        sandbox: sb("a"),
        id: id.0,
        state: PendingEnd::Denied,
        rule_id: Some(rule.id.0),
    }));
    assert_eq!(kinds(&events).last(), Some(&"audit_appended"));
    assert!(events.contains(&Event::RulesChanged {}));

    store.set_rule_expiry(rule.id, None, Actor::Cli).unwrap();
    assert_eq!(kinds(&sink.take()), ["rules_changed", "audit_appended"]);
    store.delete_rule(rule.id, Actor::Cli).unwrap();
    assert_eq!(kinds(&sink.take()), ["rules_changed", "audit_appended"]);

    // The sweeper's expiry of a rule is a rule change too.
    store
        .add_rule(&NewRule {
            scope: Scope::Global,
            pattern: Pattern::parse("short.example").unwrap(),
            effect: Effect::Allow,
            expires_at: Some(T0 + 1000),
            created_by: Actor::Cli,
        })
        .unwrap();
    drop(sink.take());
    clock.advance(2000);
    store.sweep().unwrap();
    assert_eq!(kinds(&sink.take()), ["rules_changed", "audit_appended"]);
}

#[test]
fn a_change_that_fails_emits_nothing() {
    let (_, sink, store) = fixture(Limits::default());
    let id = new_id(ask(&store, "a", "example.com"));
    store
        .resolve_pending(id, &Resolution::allow(), Actor::Cli)
        .unwrap();
    drop(sink.take());
    store
        .resolve_pending(id, &Resolution::allow(), Actor::Cli)
        .unwrap_err();
    store
        .delete_rule(puddle_types::RuleId(999), Actor::Cli)
        .unwrap_err();
    assert_eq!(sink.take(), []);
}

#[test]
fn stale_rows_and_deleted_sandboxes_close_as_expired() {
    let limits = Limits {
        pending_stale_after_ms: 1000,
        ..Limits::default()
    };
    let (clock, sink, store) = fixture(limits);
    let stale = new_id(ask(&store, "a", "stale.example"));
    clock.advance(2000);
    let gone = new_id(ask(&store, "b", "gone.example"));
    drop(sink.take());
    store.sweep().unwrap();
    let events = sink.take();
    assert!(events.contains(&Event::PendingClosed {
        sandbox: sb("a"),
        id: stale.0,
        state: PendingEnd::Expired,
        rule_id: None,
    }));
    assert_eq!(kinds(&events).last(), Some(&"audit_appended"));
    store.delete_sandbox(&sb("b")).unwrap();
    let events = sink.take();
    assert!(events.contains(&Event::PendingClosed {
        sandbox: sb("b"),
        id: gone.0,
        state: PendingEnd::Expired,
        rule_id: None,
    }));
    // Without rules, no rules_changed.
    assert!(!events.contains(&Event::RulesChanged {}));
}

#[test]
fn deleting_a_sandbox_with_rules_reports_rules_changed() {
    let (_, sink, store) = fixture(Limits::default());
    store
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sb("a")),
            pattern: Pattern::parse("example.com").unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
    drop(sink.take());
    store.delete_sandbox(&sb("a")).unwrap();
    assert!(sink.take().contains(&Event::RulesChanged {}));
}

#[test]
fn suppression_starts_grows_at_a_throttled_pace_and_ends() {
    let limits = Limits {
        new_rows_burst: 1,
        new_rows_refill_ms: 10_000,
        ..Limits::default()
    };
    let (clock, sink, store) = fixture(limits);
    ask(&store, "a", "one.example");
    drop(sink.take());
    let suppression = |events: Vec<Event>| -> Vec<(bool, u64)> {
        events
            .into_iter()
            .filter_map(|e| match e {
                Event::SuppressionChanged { active, count, .. } => Some((active, count)),
                _ => None,
            })
            .collect()
    };
    assert!(matches!(
        ask(&store, "a", "two.example"),
        PendingOutcome::Suppressed
    ));
    assert_eq!(suppression(sink.take()), [(true, 1)]);
    // Within 500 ms the count grows silently.
    for _ in 0..5 {
        clock.advance(50);
        ask(&store, "a", "two.example");
    }
    assert_eq!(suppression(sink.take()), []);
    clock.advance(300);
    ask(&store, "a", "three.example");
    assert_eq!(suppression(sink.take()), [(true, 7)]);
    // The bucket refills; the next admitted request ends the episode with its final count.
    clock.advance(11000);
    assert!(matches!(
        ask(&store, "a", "four.example"),
        PendingOutcome::New(_)
    ));
    assert_eq!(suppression(sink.take()), [(false, 7)]);
    assert!(!store.suppression(&sb("a")).active);
}

#[test]
fn deleting_a_suppressed_sandbox_ends_its_suppression() {
    let limits = Limits {
        new_rows_burst: 1,
        new_rows_refill_ms: 10_000,
        ..Limits::default()
    };
    let (_, sink, store) = fixture(limits);
    ask(&store, "a", "one.example");
    ask(&store, "a", "two.example");
    drop(sink.take());
    store.delete_sandbox(&sb("a")).unwrap();
    assert!(sink.take().contains(&Event::SuppressionChanged {
        sandbox: sb("a"),
        active: false,
        count: 1,
    }));
}

#[test]
fn connection_records_and_flushed_summaries_emit_one_audit_event_per_commit() {
    let (clock, sink, store) = fixture(Limits {
        connection_records_per_second: 1,
        ..Limits::default()
    });
    let request = EgressRequest::new(sb("a"), Host::parse_normalised("example.com").unwrap(), 443);
    let event = ConnectionEvent::new(&request, ConnectionDecision::Allow, ConnectionReason::Rule);
    store.record(&event);
    assert_eq!(
        sink.take(),
        [Event::AuditAppended {
            id: newest_audit_id(&store)
        }]
    );
    // Over the per-second limit: counted, nothing written, nothing emitted.
    store.record(&event);
    assert_eq!(sink.take(), []);
    // The next second writes the summary and the new record in one commit: one event.
    clock.advance(1000);
    store.record(&event);
    assert_eq!(
        sink.take(),
        [Event::AuditAppended {
            id: newest_audit_id(&store)
        }]
    );
    assert_eq!(
        store
            .audit_query(&AuditFilter::default(), AuditCursor::After(0), 100)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn trimming_the_audit_emits_for_its_trim_record() {
    let (_, sink, store) = fixture(Limits {
        audit_max_bytes: 400,
        audit_trim_to_bytes: 200,
        ..Limits::default()
    });
    for i in 0..6 {
        ask(&store, "a", &format!("h{i}.example"));
    }
    drop(sink.take());
    let report = store.sweep().unwrap();
    assert!(report.audit_records_trimmed > 0);
    assert_eq!(
        sink.take().last(),
        Some(&Event::AuditAppended {
            id: newest_audit_id(&store)
        })
    );
}

#[test]
fn a_store_without_a_sink_works() {
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open_in_memory(clock, Limits::default()).unwrap();
    ask(&store, "a", "example.com");
}

// ---------------------------------------------------------------------------------------------
// Audit queries

fn pending_wire(sandbox: &str, host: &str, state: &str) -> PendingWire {
    PendingWire {
        id: 1,
        sandbox_id: sandbox.into(),
        host: host.into(),
        port: 443,
        first_seen: 1,
        last_seen: 1,
        attempts: 1,
        state: state.into(),
        decided_at: None,
        decided_by: None,
        rule_id: None,
    }
}

fn rule_wire(sandbox: Option<&str>, pattern: &str) -> RuleWire {
    RuleWire {
        id: 1,
        scope: sandbox.map_or("global", |_| "sandbox").into(),
        sandbox_id: sandbox.map(Into::into),
        pattern_kind: "exact".into(),
        pattern: pattern.into(),
        effect: "allow".into(),
        expires_at: None,
        created_at: 1,
        created_by: "cli".into(),
        source_pending_id: None,
    }
}

/// A connection record; an empty `sandbox` is one of puddle's own (no sandbox).
fn connection(ts: u64, sandbox: &str, host: &str, decision: ConnectionDecision) -> AuditRecord {
    AuditRecord::Connection(ConnectionRecord {
        ts,
        sandbox_id: (!sandbox.is_empty()).then(|| sandbox.to_owned()),
        origin: if sandbox.is_empty() {
            ConnectionOrigin::Puddle
        } else {
            ConnectionOrigin::Sandbox
        },
        host: Some(host.into()),
        port: Some(443),
        resolved_ip: None,
        upstream: None,
        decision: Some(decision),
        reason: "rule".into(),
        rule_id: None,
        pending_id: None,
        binding_id: None,
        injected: false,
        method: None,
        path: None,
        path_truncated: false,
        bytes_up: 0,
        bytes_down: 0,
        count: None,
    })
}

/// A store on disk, with `records` inserted the way `Store` inserts them (same columns).
fn seeded(records: &[AuditRecord]) -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puddle.db");
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open(&path, clock, Limits::default()).unwrap();
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut insert = tx
            .prepare(
                "INSERT INTO audit (ts, type, sandbox_id, host, outcome, line)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .unwrap();
        for record in records {
            insert
                .execute(params![
                    i64::try_from(record.ts()).unwrap(),
                    record.kind(),
                    record.sandbox_id(),
                    record.host(),
                    record.outcome().map(AuditOutcome::as_str),
                    record.to_line().unwrap(),
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    (dir, store)
}

fn naive(records: &[AuditRecord], filter: &AuditFilter) -> Vec<i64> {
    records
        .iter()
        .zip(1_i64..)
        .filter(|(r, _)| {
            filter
                .sandbox
                .as_ref()
                .is_none_or(|s| r.sandbox_id() == Some(s.as_str()))
                && filter.kind.is_none_or(|k| r.kind() == k)
                && filter.outcome.is_none_or(|o| r.outcome() == Some(o))
                && filter.origin.is_none_or(|o| r.origin() == Some(o))
                && filter.from.is_none_or(|t| r.ts() >= t)
                && filter.to.is_none_or(|t| r.ts() < t)
                && filter.host_contains.as_ref().is_none_or(|h| {
                    r.host()
                        .is_some_and(|host| host.contains(&h.to_lowercase()))
                })
        })
        .map(|(_, id)| id)
        .collect()
}

fn ids(rows: Vec<(i64, String)>) -> Vec<i64> {
    rows.into_iter().map(|(id, _)| id).collect()
}

fn any_record() -> impl Strategy<Value = AuditRecord> {
    let sandbox = prop::sample::select(vec!["a", "b", "c"]);
    let host = prop::sample::select(vec![
        "example.com",
        "api.example.com",
        "github.com",
        "Xn--bcher-kva.example",
        "10.0.0.1",
    ]);
    let ts = (0_u64..20).prop_map(|t| T0 + t * 1000);
    let decision = prop::sample::select(vec![
        ConnectionDecision::Allow,
        ConnectionDecision::Deny,
        ConnectionDecision::Pending,
        ConnectionDecision::Blocked,
    ]);
    let state = prop::sample::select(vec!["requested", "allowed", "denied", "expired"]);
    (0..8_u8, sandbox, host, ts, decision, state).prop_map(|(kind, sb_, host, ts, d, st)| {
        let host = host.to_lowercase();
        match kind {
            0 => connection(ts, sb_, &host, d),
            1 => connection(ts, "", &host, d),
            2 => AuditRecord::PendingCreated {
                ts,
                pending: pending_wire(sb_, &host, "requested"),
            },
            3 => AuditRecord::PendingDecided {
                ts,
                pending: pending_wire(sb_, &host, st),
            },
            4 => AuditRecord::PendingExpired {
                ts,
                pending: pending_wire(sb_, &host, "expired"),
                reason: PendingExpiryReason::Stale,
            },
            5 => AuditRecord::RuleCreated {
                ts,
                rule: rule_wire(Some(sb_), &host),
            },
            6 => AuditRecord::RuleDeleted {
                ts,
                rule: rule_wire(None, &format!(".{host}")),
                reason: RuleDeleteReason::User,
                actor: "cli".into(),
            },
            _ => AuditRecord::PendingSuppressed {
                ts,
                sandbox_id: sb_.into(),
                count: 3,
            },
        }
    })
}

fn any_filter() -> impl Strategy<Value = AuditFilter> {
    (
        prop::option::of(prop::sample::select(vec!["a", "b", "zzz"])),
        prop::option::of(prop::sample::select(AuditRecord::KINDS.to_vec())),
        prop::option::of(prop::sample::select(AuditOutcome::ALL.to_vec())),
        prop::option::of(prop::sample::select(vec![
            ConnectionOrigin::Sandbox,
            ConnectionOrigin::Puddle,
        ])),
        prop::option::of(prop::sample::select(vec![
            "example",
            "EXAMPLE.com",
            ".example",
            "10.0",
            "nothing",
            "git",
        ])),
        prop::option::of(0_u64..22),
        prop::option::of(0_u64..22),
    )
        .prop_map(
            |(sandbox, kind, outcome, origin, host, from, to)| AuditFilter {
                sandbox: sandbox.map(sb),
                kind,
                outcome,
                origin,
                host_contains: host.map(str::to_owned),
                from: from.map(|t| T0 + t * 1000),
                to: to.map(|t| T0 + t * 1000),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Every filter combination returns exactly what filtering the records by hand returns,
    /// in both directions, and paging back with `Before` visits each match once.
    #[test]
    fn filtered_queries_equal_a_naive_filter(
        records in prop::collection::vec(any_record(), 0..60),
        filter in any_filter(),
        page in 1_u32..9,
    ) {
        let (_dir, store) = seeded(&records);
        let want = naive(&records, &filter);
        let up = ids(store.audit_query(&filter, AuditCursor::After(0), 1000).unwrap());
        prop_assert_eq!(&up, &want);
        let mut down = ids(store.audit_query(&filter, AuditCursor::Before(None), 1000).unwrap());
        down.reverse();
        prop_assert_eq!(&down, &want);

        let mut paged = Vec::new();
        let mut cursor = AuditCursor::Before(None);
        loop {
            let rows = ids(store.audit_query(&filter, cursor, page).unwrap());
            let Some(last) = rows.last().copied() else { break };
            prop_assert!(rows.len() <= page as usize);
            paged.extend(rows);
            cursor = AuditCursor::Before(Some(last));
        }
        paged.reverse();
        prop_assert_eq!(paged, want);
    }
}

#[test]
fn filters_combine_and_the_host_is_case_folded() {
    let records = vec![
        connection(T0, "a", "api.example.com", ConnectionDecision::Allow),
        connection(T0 + 1, "a", "api.example.com", ConnectionDecision::Deny),
        connection(T0 + 2, "b", "api.example.com", ConnectionDecision::Allow),
        AuditRecord::RuleCreated {
            ts: T0 + 3,
            rule: rule_wire(Some("a"), "api.example.com"),
        },
    ];
    let (_dir, store) = seeded(&records);
    let q = |filter: AuditFilter| {
        ids(store
            .audit_query(&filter, AuditCursor::After(0), 100)
            .unwrap())
    };
    assert_eq!(q(AuditFilter::default()), [1, 2, 3, 4]);
    assert_eq!(
        q(AuditFilter {
            sandbox: Some(sb("a")),
            kind: Some("connection"),
            outcome: Some(AuditOutcome::Allow),
            host_contains: Some("API.EXAMPLE".into()),
            ..AuditFilter::default()
        }),
        [1]
    );
    // A rule matches on its pattern, and has no outcome.
    assert_eq!(
        q(AuditFilter {
            host_contains: Some("example".into()),
            kind: Some("rule_created"),
            ..AuditFilter::default()
        }),
        [4]
    );
    assert_eq!(
        q(AuditFilter {
            outcome: Some(AuditOutcome::Expired),
            ..AuditFilter::default()
        }),
        Vec::<i64>::new()
    );
    // `from` is inclusive and `to` exclusive.
    assert_eq!(
        q(AuditFilter {
            from: Some(T0 + 1),
            to: Some(T0 + 3),
            ..AuditFilter::default()
        }),
        [2, 3]
    );
}

#[test]
fn hostile_filter_text_is_data_not_sql_or_a_pattern() {
    let (_dir, store) = seeded(&[connection(
        T0,
        "a",
        "example.com",
        ConnectionDecision::Allow,
    )]);
    for needle in ["%", "_", "' OR 1=1 --", "\"; DROP TABLE audit; --", "\u{0}"] {
        let rows = store
            .audit_query(
                &AuditFilter {
                    host_contains: Some(needle.into()),
                    ..AuditFilter::default()
                },
                AuditCursor::After(0),
                10,
            )
            .unwrap();
        assert!(rows.is_empty(), "{needle:?}");
    }
    assert_eq!(
        store
            .audit_query(&AuditFilter::default(), AuditCursor::After(0), 10)
            .unwrap()
            .len(),
        1
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of query cases")]
fn a_hundred_thousand_records_answer_every_filter_quickly() {
    const ROWS: u64 = 100_000;
    let sandboxes = ["alpha", "beta", "gamma", "delta"];
    let decisions = [
        ConnectionDecision::Allow,
        ConnectionDecision::Deny,
        ConnectionDecision::Pending,
        ConnectionDecision::Blocked,
    ];
    let records: Vec<AuditRecord> = (0..ROWS)
        .map(|i| {
            let sandbox = sandboxes[(i % 4) as usize];
            let ts = T0 + i * 10;
            match i % 50 {
                0 => AuditRecord::RuleCreated {
                    ts,
                    rule: rule_wire(Some(sandbox), &format!("rule{i}.example.com")),
                },
                1 => AuditRecord::PendingCreated {
                    ts,
                    pending: pending_wire(sandbox, &format!("host{i}.example.org"), "requested"),
                },
                _ => connection(
                    ts,
                    sandbox,
                    &format!("h{}.site{}.example.net", i % 97, i % 13),
                    decisions[(i % 4) as usize],
                ),
            }
        })
        .collect();
    let (_dir, store) = seeded(&records);
    let last = T0 + ROWS * 10;
    // Each case names the plan step it must use. The wall clock below is only a backstop: the
    // plan is what proves a filter doesn't fall back to scanning the whole table, and it
    // doesn't depend on how busy the machine is.
    let cases: Vec<(&str, AuditFilter, AuditCursor, &str)> = vec![
        (
            "newest page",
            AuditFilter::default(),
            AuditCursor::Before(None),
            "SCAN audit",
        ),
        (
            "older page",
            AuditFilter::default(),
            AuditCursor::Before(Some(50_000)),
            "USING INTEGER PRIMARY KEY (rowid<?)",
        ),
        (
            "sandbox",
            AuditFilter {
                sandbox: Some(sb("beta")),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "USING INDEX audit_sandbox (sandbox_id=?)",
        ),
        (
            "type",
            AuditFilter {
                kind: Some("pending_created"),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "USING INDEX audit_type (type=?)",
        ),
        (
            "outcome",
            AuditFilter {
                outcome: Some(AuditOutcome::Blocked),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "USING INDEX audit_outcome (outcome=?)",
        ),
        (
            "last hour (all of it)",
            AuditFilter {
                from: Some(last - 3_600_000),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "SCAN audit",
        ),
        (
            "narrow time range",
            AuditFilter {
                from: Some(T0 + 400_000),
                to: Some(T0 + 410_000),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "USING INDEX audit_ts (ts>? AND ts<?)",
        ),
        (
            "host, common",
            AuditFilter {
                host_contains: Some("EXAMPLE.net".into()),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "SCAN audit",
        ),
        (
            "host, rare (scans everything)",
            AuditFilter {
                host_contains: Some("rule99950".into()),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "SCAN audit",
        ),
        (
            "host, absent (scans everything)",
            AuditFilter {
                host_contains: Some("absent.invalid".into()),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            "SCAN audit",
        ),
        (
            "everything at once",
            AuditFilter {
                sandbox: Some(sb("gamma")),
                kind: Some("connection"),
                outcome: Some(AuditOutcome::Pending),
                origin: Some(ConnectionOrigin::Sandbox),
                host_contains: Some("site7".into()),
                from: Some(T0),
                to: Some(last),
            },
            AuditCursor::Before(None),
            "USING INDEX audit_outcome (outcome=?)",
        ),
        (
            "tail",
            AuditFilter::default(),
            AuditCursor::After(99_900),
            "USING INTEGER PRIMARY KEY (rowid>?)",
        ),
    ];
    for (name, filter, cursor, step) in cases {
        let plan = store.audit_query_plan(&filter, cursor, 100).unwrap();
        assert!(
            plan.iter().any(|line| line.contains(step)),
            "{name}: expected `{step}` in the plan, got {plan:?}"
        );
        // The best of three, so one scheduler hiccup doesn't trip the backstop.
        let best = (0..3)
            .map(|_| {
                let start = Instant::now();
                let rows = store.audit_query(&filter, cursor, 100).unwrap();
                let took = start.elapsed();
                assert!(rows.len() <= 100);
                took
            })
            .min()
            .unwrap();
        eprintln!("audit query {name}: {best:?}");
        // About 50 times the slowest local scan: it catches a query that went quadratic, not noise.
        assert!(best < Duration::from_secs(1), "{name} took {best:?}");
    }
    // The filtered results are right, not just fast.
    let one = store
        .audit_query(
            &AuditFilter {
                host_contains: Some("rule99950".into()),
                ..AuditFilter::default()
            },
            AuditCursor::Before(None),
            100,
        )
        .unwrap();
    assert_eq!(one.len(), 1);
}
