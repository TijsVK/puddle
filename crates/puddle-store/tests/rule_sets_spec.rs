// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule sets and System managed (`docs/spec/rules.md` §7, R-36 to R-43), through the store's
//! public API.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions fail the test by panicking"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use puddle_store::{
    Actor, BUILT_IN_SETS, Effect, Limits, ManualClock, NewRule, Pattern, PendingState, Resolution,
    Scope, ScopeChoice, Store, StoreError, SystemPlan, SystemReason, parse_rule_set,
};
use puddle_types::{
    ConnectionDecision, ConnectionEvent, ConnectionLog, Decision, EgressRequest, Host, PatternKind,
    PendingId, PendingOutcome, RuleId, RuleSetId, SuffixAllows, WorkspaceName,
};
use serde_json::Value;

const T0: u64 = 1_800_000_000_000;

fn fixture() -> (Arc<ManualClock>, Store) {
    let clock = Arc::new(ManualClock::new(T0));
    let store = Store::open_in_memory(clock.clone(), Limits::default()).unwrap();
    (clock, store)
}

fn sb(id: &str) -> WorkspaceName {
    WorkspaceName::new(id).unwrap()
}

fn req(workspace: &str, host: &str) -> EgressRequest {
    EgressRequest::new(sb(workspace), Host::parse_normalised(host).unwrap(), 443)
}

fn decide(store: &Store, workspace: &str, host: &str) -> Decision {
    store
        .decide(&req(workspace, host), SuffixAllows::Count)
        .unwrap()
}

fn new_rule(scope: Scope, pattern: &str, effect: Effect) -> NewRule {
    NewRule {
        scope,
        pattern: Pattern::parse(pattern).unwrap(),
        effect,
        expires_at: None,
        created_by: Actor::Ui,
    }
}

fn pending(decision: Decision) -> PendingId {
    match decision {
        Decision::Pending(PendingOutcome::New(id) | PendingOutcome::Repeat(id)) => id,
        other => panic!("expected pending, got {other:?}"),
    }
}

fn audit_of(store: &Store, kind: &str) -> Vec<Value> {
    store
        .audit_lines(0, 100_000)
        .unwrap()
        .into_iter()
        .map(|(_, line)| serde_json::from_str::<Value>(&line).unwrap())
        .filter(|v| v["type"] == kind)
        .collect()
}

fn user_set(store: &Store, name: &str) -> i64 {
    match store.create_rule_set(name, "", Actor::Ui).unwrap().id {
        RuleSetId::User(id) => id,
        other => panic!("{other:?}"),
    }
}

fn plan(everywhere: &[SystemReason], per: &[(&str, &[SystemReason])]) -> SystemPlan {
    SystemPlan {
        everywhere: everywhere.iter().copied().collect(),
        workspaces: per
            .iter()
            .map(|(s, r)| (sb(s), r.iter().copied().collect::<BTreeSet<_>>()))
            .collect::<BTreeMap<_, _>>(),
    }
}

#[test]
fn r36_built_in_sets_are_listed_read_only_and_ship_off() {
    let (_, store) = fixture();
    let sets = store.rule_sets().unwrap();
    assert_eq!(sets.len(), BUILT_IN_SETS.len());
    for (set, shipped) in sets.iter().zip(BUILT_IN_SETS) {
        assert_eq!(set.id, RuleSetId::BuiltIn(shipped.slug));
        assert!(!set.on_by_default() && !set.is_on(&sb("a")));
        assert!(
            set.entries
                .iter()
                .all(|e| e.effect == Effect::Allow && e.rule_id.is_none())
        );
        assert_eq!(set.changed_at, None);
    }
    // A fresh install decides nothing: github.com is in a built-in set that is off.
    assert!(matches!(
        decide(&store, "a", "github.com"),
        Decision::Pending(_)
    ));
    // A built-in set has no rule rows to delete or rename.
    assert!(matches!(
        store.update_rule_set(1, "x", "", Actor::Ui),
        Err(StoreError::UnknownRuleSet(_))
    ));
}

#[test]
fn r36_an_update_that_changes_a_built_in_set_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Store::open(&path, clock.clone(), Limits::default()).unwrap());
    // Pretend the previous version shipped GitHub with one other host and without api.github.com.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE builtin_sets_seen SET entries = ?1 WHERE slug = 'github'",
        [r#"["github.com","old.github.com"]"#],
    )
    .unwrap();
    drop(conn);
    clock.advance(5_000);
    let store = Store::open(&path, clock.clone(), Limits::default()).unwrap();
    let changed = audit_of(&store, "rule_set_changed");
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0]["set_id"], "builtin:github");
    assert_eq!(changed[0]["removed"], serde_json::json!(["old.github.com"]));
    assert!(
        changed[0]["added"]
            .as_array()
            .unwrap()
            .contains(&Value::from("api.github.com"))
    );
    let github = store.rule_set(RuleSetId::BuiltIn("github")).unwrap();
    assert_eq!(github.changed_at, Some(T0 + 5_000));
    // Opening again with the same catalogue records nothing new.
    drop(store);
    let store = Store::open(&path, clock, Limits::default()).unwrap();
    assert_eq!(audit_of(&store, "rule_set_changed").len(), 1);
}

#[test]
fn r37_switches_apply_globally_with_a_per_workspace_override_and_close_waiting_requests() {
    let (_, store) = fixture();
    let github = RuleSetId::BuiltIn("github");
    let waiting_a = pending(decide(&store, "a", "api.github.com"));
    let waiting_b = pending(decide(&store, "b", "api.github.com"));
    // Off for b first, then on everywhere: only a's request closes.
    store
        .switch_rule_set(github, Some(&sb("b")), Some(false), Actor::Ui)
        .unwrap();
    let closed = store
        .switch_rule_set(github, None, Some(true), Actor::Ui)
        .unwrap();
    assert_eq!(closed, vec![waiting_a]);
    let row = store.pending(waiting_a).unwrap();
    assert_eq!(row.state, PendingState::Allowed);
    assert_eq!(row.rule_id, None);
    assert_eq!(row.rule_set.as_deref(), Some("builtin:github"));
    assert_eq!(
        store.pending(waiting_b).unwrap().state,
        PendingState::Requested
    );
    assert_eq!(
        decide(&store, "a", "api.github.com"),
        Decision::SetAllow {
            set: github,
            rule_id: None,
            pattern: PatternKind::Exact
        }
    );
    assert!(matches!(
        decide(&store, "b", "api.github.com"),
        Decision::Pending(_)
    ));
    // b back to following the global switch.
    let closed = store
        .switch_rule_set(github, Some(&sb("b")), None, Actor::Ui)
        .unwrap();
    assert_eq!(closed, vec![waiting_b]);
    let info = store.rule_set(github).unwrap();
    assert_eq!((info.global, info.overrides.clone()), (Some(true), vec![]));
    let switched = audit_of(&store, "rule_set_switched");
    assert_eq!(switched.len(), 3);
    assert_eq!(switched[1]["workspace_id"], Value::Null);
    assert_eq!(switched[1]["enabled"], true);
    assert_eq!(switched[2]["enabled"], Value::Null);
    assert_eq!(switched[2]["actor"], "ui");
    // Off again: the next request goes pending (R-8 applies).
    store
        .switch_rule_set(github, None, Some(false), Actor::Ui)
        .unwrap();
    assert!(matches!(
        decide(&store, "a", "api.github.com"),
        Decision::Pending(_)
    ));
}

#[test]
fn r37_only_real_sets_switch_and_only_users_switch_them() {
    let (_, store) = fixture();
    assert!(matches!(
        store.switch_rule_set(RuleSetId::System, None, Some(false), Actor::Ui),
        Err(StoreError::NotSwitchable)
    ));
    assert!(matches!(
        store.switch_rule_set(RuleSetId::User(42), None, Some(true), Actor::Ui),
        Err(StoreError::UnknownRuleSet(id)) if id == "user:42"
    ));
    assert!(matches!(
        store.switch_rule_set(RuleSetId::BuiltIn("nope"), None, Some(true), Actor::Ui),
        Err(StoreError::UnknownRuleSet(_))
    ));
    assert!(matches!(
        store.switch_rule_set(
            RuleSetId::BuiltIn("github"),
            None,
            Some(true),
            Actor::System
        ),
        Err(StoreError::SystemActor)
    ));
}

#[test]
fn r38_sets_you_make_hold_rules_and_inbox_approvals() {
    let (_, store) = fixture();
    let azure = user_set(&store, "Azure work");
    let info = store.rule_set(RuleSetId::User(azure)).unwrap();
    assert!(info.on_by_default() && info.entries.is_empty() && info.created_at == Some(T0));
    // An entry added directly.
    let entry = store
        .add_rule(&new_rule(Scope::Set(azure), "*.azure.com", Effect::Allow))
        .unwrap();
    assert!(matches!(
        decide(&store, "a", "portal.azure.com"),
        Decision::SetAllow { set: RuleSetId::User(id), rule_id: Some(r), pattern: PatternKind::Suffix }
            if id == azure && r == entry.id
    ));
    // Approve into the set from the inbox: the rule joins the set, and other workspaces' rows close.
    let in_a = pending(decide(&store, "a", "login.microsoftonline.com"));
    let in_b = pending(decide(&store, "b", "login.microsoftonline.com"));
    let mut into_set = Resolution::allow();
    into_set.scope = ScopeChoice::Set(azure);
    let decided = store.resolve_pending(in_a, &into_set, Actor::Ui).unwrap();
    assert_eq!(decided.rule.scope, Scope::Set(azure));
    assert_eq!(decided.also_closed, vec![in_b]);
    assert_eq!(
        store
            .rule_set(RuleSetId::User(azure))
            .unwrap()
            .entries
            .len(),
        2
    );
    // Not into a set that is off for the row's workspace: that would allow nothing.
    store
        .switch_rule_set(
            RuleSetId::User(azure),
            Some(&sb("c")),
            Some(false),
            Actor::Ui,
        )
        .unwrap();
    let in_c = pending(decide(&store, "c", "graph.microsoft.com"));
    assert!(matches!(
        store.resolve_pending(in_c, &into_set, Actor::Ui),
        Err(StoreError::RuleSetOff { set, workspace }) if set == format!("user:{azure}") && workspace == "c"
    ));
    assert_eq!(store.pending(in_c).unwrap().state, PendingState::Requested);
    // Nor into a set that doesn't exist.
    into_set.scope = ScopeChoice::Set(999);
    assert!(matches!(
        store.resolve_pending(in_c, &into_set, Actor::Ui),
        Err(StoreError::UnknownRuleSet(_))
    ));
    assert!(matches!(
        store.add_rule(&new_rule(Scope::Set(999), "x.example", Effect::Allow)),
        Err(StoreError::UnknownRuleSet(_))
    ));
}

#[test]
fn r38_set_names_are_checked_renamed_and_deleting_a_set_deletes_its_entries() {
    let (_, store) = fixture();
    let one = user_set(&store, "  Work  ");
    assert_eq!(store.rule_set(RuleSetId::User(one)).unwrap().name, "Work");
    for (name, why) in [
        ("", "a name is needed"),
        ("work", "another rule set has this name"),
        ("GitHub", "another rule set has this name"),
        ("bad\nname", "no control characters"),
    ] {
        assert!(
            matches!(store.create_rule_set(name, "", Actor::Ui), Err(StoreError::RuleSetName(w)) if w == why),
            "{name:?}"
        );
    }
    assert!(matches!(
        store.create_rule_set(&"x".repeat(65), "", Actor::Ui),
        Err(StoreError::RuleSetName(_))
    ));
    assert!(matches!(
        store.create_rule_set("ok", &"d".repeat(501), Actor::Ui),
        Err(StoreError::RuleSetName(_))
    ));
    assert!(matches!(
        store.create_rule_set("sys", "", Actor::System),
        Err(StoreError::SystemActor)
    ));
    let renamed = store
        .update_rule_set(one, "Client X", "hosts for client X", Actor::Api)
        .unwrap();
    assert_eq!(
        (renamed.name.as_str(), renamed.description.as_str()),
        ("Client X", "hosts for client X")
    );
    // Renaming to its own name in another case is fine.
    store
        .update_rule_set(one, "client x", "", Actor::Api)
        .unwrap();
    let r = store
        .add_rule(&new_rule(Scope::Set(one), "x.example", Effect::Deny))
        .unwrap();
    store
        .switch_rule_set(RuleSetId::User(one), None, Some(true), Actor::Ui)
        .unwrap();
    let deleted = store.delete_rule_set(one, Actor::Ui).unwrap();
    assert_eq!(deleted.entries.len(), 1);
    assert!(store.rules().iter().all(|rule| rule.id != r.id));
    assert!(matches!(
        decide(&store, "a", "x.example"),
        Decision::Pending(_)
    ));
    assert_eq!(audit_of(&store, "rule_set_deleted").len(), 1);
    let gone = audit_of(&store, "rule_deleted");
    assert_eq!(gone[0]["reason"], "set_deleted");
    assert_eq!(gone[0]["rule"]["scope"], "set");
    assert_eq!(gone[0]["rule"]["set_id"], one);
    assert_eq!(
        audit_of(&store, "rule_set_created")[0]["rule_set"]["name"],
        "Work"
    );
    assert_eq!(audit_of(&store, "rule_set_updated").len(), 2);
    assert!(matches!(
        store.delete_rule_set(one, Actor::Ui),
        Err(StoreError::UnknownRuleSet(_))
    ));
    // The name is free again.
    user_set(&store, "client x");
}

#[test]
fn r39_your_own_rules_decide_before_any_set() {
    let (_, store) = fixture();
    store
        .set_system_managed(&plan(&[SystemReason::MicrosoftServer], &[]))
        .unwrap();
    // E1: your global deny of *.visualstudio.com beats System managed's exact allow.
    let deny = store
        .add_rule(&new_rule(Scope::Global, "*.visualstudio.com", Effect::Deny))
        .unwrap();
    assert_eq!(
        decide(&store, "a", "update.code.visualstudio.com"),
        Decision::Deny {
            rule_id: deny.id,
            pattern: PatternKind::Suffix
        }
    );
    assert!(decide(&store, "a", "vscode.download.prss.microsoft.com").is_allow());
    // E2: your allow of *.example.com; your set blocks ads.example.com; your exact allow wins.
    let blocks = user_set(&store, "Trackers");
    store
        .add_rule(&new_rule(Scope::Global, "*.example.com", Effect::Allow))
        .unwrap();
    let block = store
        .add_rule(&new_rule(
            Scope::Set(blocks),
            "ads.example.com",
            Effect::Deny,
        ))
        .unwrap();
    assert_eq!(
        decide(&store, "a", "ads.example.com"),
        Decision::SetDeny {
            set: RuleSetId::User(blocks),
            rule_id: block.id,
            pattern: PatternKind::Exact
        }
    );
    let mine = store
        .add_rule(&new_rule(
            Scope::Workspace(sb("a")),
            "ads.example.com",
            Effect::Allow,
        ))
        .unwrap();
    assert_eq!(
        decide(&store, "a", "ads.example.com"),
        Decision::Allow {
            rule_id: mine.id,
            pattern: PatternKind::Exact
        }
    );
    assert!(matches!(
        decide(&store, "b", "ads.example.com"),
        Decision::SetDeny { .. }
    ));
}

#[test]
fn r41_system_managed_follows_the_plan_and_records_each_change() {
    let (_, store) = fixture();
    let waiting = pending(decide(&store, "a", "open-vsx.org"));
    let closed = store
        .set_system_managed(&plan(&[SystemReason::CodeServer], &[]))
        .unwrap();
    assert_eq!(closed, vec![waiting]);
    let row = store.pending(waiting).unwrap();
    assert_eq!(
        (row.state, row.decided_by, row.rule_set.as_deref()),
        (PendingState::Allowed, Some(Actor::System), Some("system"))
    );
    assert!(matches!(
        decide(&store, "a", "openvsx.eclipsecontent.org"),
        Decision::SetAllow {
            set: RuleSetId::System,
            rule_id: None,
            ..
        }
    ));
    // Microsoft's hosts are not allowed for code-server.
    assert!(matches!(
        decide(&store, "a", "marketplace.visualstudio.com"),
        Decision::Pending(_)
    ));
    // Direct SSH on for one workspace: Microsoft's hosts there only.
    store
        .set_system_managed(&plan(
            &[SystemReason::CodeServer],
            &[("ssh", &[SystemReason::DirectSsh])],
        ))
        .unwrap();
    assert!(decide(&store, "ssh", "marketplace.visualstudio.com").is_allow());
    assert!(matches!(
        decide(&store, "a", "marketplace.visualstudio.com"),
        Decision::Pending(_)
    ));
    let hosts = store.system_managed().unwrap();
    assert!(hosts.iter().any(|h| h.pattern == "open-vsx.org"
        && h.reason == SystemReason::CodeServer
        && h.workspace.is_none()));
    assert!(hosts.iter().any(|h| h.pattern == "*.gallery.vsassets.io"
        && h.reason == SystemReason::DirectSsh
        && h.workspace == Some(sb("ssh"))));
    // The same plan again changes and records nothing.
    let before = audit_of(&store, "system_managed_changed").len();
    assert_eq!(before, 2);
    assert_eq!(
        store
            .set_system_managed(&plan(
                &[SystemReason::CodeServer],
                &[("ssh", &[SystemReason::DirectSsh])],
            ))
            .unwrap(),
        Vec::<PendingId>::new()
    );
    assert_eq!(audit_of(&store, "system_managed_changed").len(), before);
    // Switching to Microsoft's server: Open VSX goes, the Marketplace comes, for everyone.
    store
        .set_system_managed(&plan(&[SystemReason::MicrosoftServer], &[]))
        .unwrap();
    let records = audit_of(&store, "system_managed_changed");
    let last_two: Vec<_> = records.iter().rev().take(2).collect();
    assert!(
        last_two.iter().any(
            |r| r["workspace_id"] == "ssh" && r["removed"] == serde_json::json!(["direct_ssh"])
        )
    );
    assert!(last_two.iter().any(|r| r["workspace_id"].is_null()
        && r["added"] == serde_json::json!(["microsoft_server"])
        && r["removed"] == serde_json::json!(["code_server"])));
    assert!(matches!(
        decide(&store, "a", "open-vsx.org"),
        Decision::Pending(_)
    ));
    assert!(decide(&store, "a", "marketplace.visualstudio.com").is_allow());
    // Nothing chosen: nothing allowed.
    store.set_system_managed(&SystemPlan::default()).unwrap();
    assert_eq!(store.system_managed().unwrap(), Vec::new());
    assert!(matches!(
        decide(&store, "a", "marketplace.visualstudio.com"),
        Decision::Pending(_)
    ));
}

#[test]
fn r41_deleting_a_workspace_removes_its_switches_and_system_reasons() {
    let (_, store) = fixture();
    store
        .set_system_managed(&plan(&[], &[("gone", &[SystemReason::DirectSsh])]))
        .unwrap();
    store
        .switch_rule_set(
            RuleSetId::BuiltIn("github"),
            Some(&sb("gone")),
            Some(true),
            Actor::Ui,
        )
        .unwrap();
    store.delete_workspace(&sb("gone")).unwrap();
    assert_eq!(store.system_managed().unwrap(), Vec::new());
    let github = store.rule_set(RuleSetId::BuiltIn("github")).unwrap();
    assert_eq!(github.overrides, Vec::new());
}

#[test]
fn r42_set_allows_need_an_exact_rule_of_your_own_for_local_destinations() {
    let (_, store) = fixture();
    store
        .switch_rule_set(RuleSetId::BuiltIn("github"), None, Some(true), Actor::Ui)
        .unwrap();
    // After a local address, the proxy asks again without wildcard-like allows: no match.
    let again = store
        .decide(&req("a", "github.com"), SuffixAllows::Ignore)
        .unwrap();
    assert!(matches!(again, Decision::Pending(_)));
    // Your own exact allow does count.
    let mine = store
        .add_rule(&new_rule(Scope::Global, "github.com", Effect::Allow))
        .unwrap();
    assert_eq!(
        store
            .decide(&req("a", "github.com"), SuffixAllows::Ignore)
            .unwrap(),
        Decision::Allow {
            rule_id: mine.id,
            pattern: PatternKind::Exact
        }
    );
}

#[test]
fn r43_connection_records_name_the_set_that_decided() {
    let (_, store) = fixture();
    store
        .set_system_managed(&plan(&[SystemReason::CodeServer], &[]))
        .unwrap();
    let request = req("a", "open-vsx.org");
    let decision = decide(&store, "a", "open-vsx.org");
    let event = ConnectionEvent::decided(&request, &decision);
    store.record(&event);
    let record = audit_of(&store, "connection").pop().unwrap();
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["reason"], "rule");
    assert_eq!(record["rule_id"], Value::Null);
    assert_eq!(record["rule_set"], "system");
    assert_eq!(event.decision, ConnectionDecision::Allow);
    let rows: Vec<RuleId> = store.rules().iter().map(|r| r.id).collect();
    assert!(rows.is_empty(), "System managed writes no rule rows");
}

#[test]
fn r40_system_managed_lists_every_host_with_its_reason_and_no_rule_rows() {
    let (_, store) = fixture();
    store
        .set_system_managed(&plan(&[SystemReason::MicrosoftServer], &[]))
        .unwrap();
    let hosts = store.system_managed().unwrap();
    assert_eq!(hosts.len(), SystemReason::MicrosoftServer.hosts().len());
    for host in &hosts {
        assert_eq!(host.reason, SystemReason::MicrosoftServer);
        assert_eq!(host.workspace, None);
        assert_ne!(host.note, "");
    }
    assert!(
        SystemReason::MicrosoftServer
            .describe()
            .contains("Microsoft's VS Code server")
    );
    assert_eq!(store.rules(), Vec::new());
    // Not a set: it can't be listed or switched as one.
    assert!(matches!(
        store.rule_set(RuleSetId::System),
        Err(StoreError::UnknownRuleSet(_))
    ));
}

#[test]
fn set_ids_parse_only_in_their_written_form() {
    assert_eq!(parse_rule_set("user:7"), Some(RuleSetId::User(7)));
    assert_eq!(parse_rule_set("user:+7"), None);
    assert_eq!(parse_rule_set("user:"), None);
    assert_eq!(
        parse_rule_set("builtin:github"),
        Some(RuleSetId::BuiltIn("github"))
    );
    assert_eq!(parse_rule_set("builtin:gone"), None);
    assert_eq!(parse_rule_set("system"), Some(RuleSetId::System));
    assert_eq!(parse_rule_set("other"), None);
}

#[test]
fn r38_the_list_has_your_sets_after_the_built_in_ones_and_only_users_change_them() {
    let (_, store) = fixture();
    let b = user_set(&store, "b set");
    let a = user_set(&store, "A set");
    let ids: Vec<RuleSetId> = store
        .rule_sets()
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(ids.len(), BUILT_IN_SETS.len() + 2);
    assert_eq!(
        &ids[BUILT_IN_SETS.len()..],
        [RuleSetId::User(a), RuleSetId::User(b)]
    );
    assert!(matches!(
        store.update_rule_set(a, "x", "", Actor::System),
        Err(StoreError::SystemActor)
    ));
    assert!(matches!(
        store.delete_rule_set(a, Actor::System),
        Err(StoreError::SystemActor)
    ));
}

#[test]
fn r37_stored_switches_and_reasons_this_version_cannot_read_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.db");
    let clock = Arc::new(ManualClock::new(T0));
    drop(Store::open(&path, clock.clone(), Limits::default()).unwrap());
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "INSERT INTO rule_set_switches (rule_set, workspace_id, enabled, changed_at) VALUES
            ('builtin:gone', NULL, 1, 1),
            ('builtin:github', 'Not A Name', 1, 1),
            ('builtin:github', 'a', 1, 1);
         INSERT INTO system_reasons (workspace_id, reason) VALUES
            (NULL, 'a_later_reason'),
            ('Not A Name', 'code_server'),
            ('a', 'code_server');",
    )
    .unwrap();
    drop(conn);
    let store = Store::open(&path, clock, Limits::default()).unwrap();
    // The readable rows count; the others are skipped.
    assert!(decide(&store, "a", "github.com").is_allow());
    assert!(!decide(&store, "b", "github.com").is_allow());
    let hosts = store.system_managed().unwrap();
    assert!(hosts.iter().all(|h| h.workspace == Some(sb("a"))));
    assert!(decide(&store, "a", "open-vsx.org").is_allow());
}
