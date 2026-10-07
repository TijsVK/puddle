// SPDX-License-Identifier: GPL-3.0-or-later
//! The in-memory rule index and the matching rules R-5 to R-7 and R-39. Pure: no I/O, no clock.

use std::cmp::Reverse;
use std::collections::HashMap;

use puddle_types::{Decision, Host, RuleId, RuleSetId, SandboxName, SuffixAllows};

use crate::catalogue;
use crate::pattern::Pattern;
use crate::rule::{Effect, Rule, Scope};

/// An entry of a built-in set or of System managed: an allow with no rule row (R-36, R-41).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetEntry {
    /// The set it belongs to: [`RuleSetId::BuiltIn`] or [`RuleSetId::System`].
    pub set: RuleSetId,
    /// What it matches.
    pub pattern: Pattern,
    /// For System managed: the one sandbox it applies to, or `None` for every sandbox. Built-in
    /// entries apply where their set is switched on.
    pub sandbox: Option<SandboxName>,
}

/// Which rule sets are switched on where (R-37): an override per sandbox, a value for every
/// sandbox, and the set's own default, in that order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Switches {
    global: HashMap<RuleSetId, bool>,
    sandbox: HashMap<(RuleSetId, SandboxName), bool>,
}

impl Switches {
    /// Records one stored switch.
    pub(crate) fn insert(&mut self, set: RuleSetId, sandbox: Option<SandboxName>, enabled: bool) {
        match sandbox {
            Some(sandbox) => {
                self.sandbox.insert((set, sandbox), enabled);
            }
            None => {
                self.global.insert(set, enabled);
            }
        }
    }

    /// The switch for every sandbox, if set.
    pub(crate) fn global(&self, set: RuleSetId) -> Option<bool> {
        self.global.get(&set).copied()
    }

    /// The sandboxes that override `set`, sorted by name.
    pub(crate) fn overrides(&self, set: RuleSetId) -> Vec<(SandboxName, bool)> {
        let mut out: Vec<_> = self
            .sandbox
            .iter()
            .filter(|((s, _), _)| *s == set)
            .map(|((_, sandbox), on)| (sandbox.clone(), *on))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Whether `set` is on for `sandbox`.
    pub(crate) fn is_on(&self, set: RuleSetId, sandbox: &SandboxName) -> bool {
        self.sandbox
            .get(&(set, sandbox.clone()))
            .or_else(|| self.global.get(&set))
            .copied()
            .unwrap_or_else(|| default_on(set))
    }
}

/// A set's state where nobody switched it: a built-in set as it ships (off), a set the user made
/// on, System managed always (it has no switch).
pub(crate) fn default_on(set: RuleSetId) -> bool {
    match set {
        RuleSetId::BuiltIn(slug) => catalogue::built_in(slug).is_some_and(|s| s.default_on),
        _ => true,
    }
}

/// What decided a request: one of the rows in `rules`, or a built-in or System managed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hit<'a> {
    /// A rule row: the user's own rule, or an entry of a set the user made.
    Rule(&'a Rule),
    /// A built-in or System managed entry (always an allow).
    Entry(&'a SetEntry),
}

impl Hit<'_> {
    /// Allow or deny.
    pub(crate) fn effect(self) -> Effect {
        match self {
            Self::Rule(rule) => rule.effect,
            Self::Entry(_) => Effect::Allow,
        }
    }

    /// The rule row, if any.
    pub(crate) fn rule_id(self) -> Option<RuleId> {
        match self {
            Self::Rule(rule) => Some(rule.id),
            Self::Entry(_) => None,
        }
    }

    /// The set the entry belongs to, if it is a set's entry.
    pub(crate) fn rule_set(self) -> Option<RuleSetId> {
        match self {
            Self::Rule(rule) => rule.scope.set().map(RuleSetId::User),
            Self::Entry(entry) => Some(entry.set),
        }
    }
}

impl<'a> Hit<'a> {
    fn pattern(self) -> &'a Pattern {
        match self {
            Self::Rule(rule) => &rule.pattern,
            Self::Entry(entry) => &entry.pattern,
        }
    }

    /// The engine's answer (R-9, R-39).
    pub(crate) fn decision(self) -> Decision {
        let pattern = self.pattern().kind();
        match (self, self.rule_set()) {
            (Self::Rule(rule), None) => match rule.effect {
                Effect::Allow => Decision::Allow {
                    rule_id: rule.id,
                    pattern,
                },
                Effect::Deny => Decision::Deny {
                    rule_id: rule.id,
                    pattern,
                },
            },
            (Self::Rule(rule), Some(set)) => match rule.effect {
                Effect::Allow => Decision::SetAllow {
                    set,
                    rule_id: Some(rule.id),
                    pattern,
                },
                Effect::Deny => Decision::SetDeny {
                    set,
                    rule_id: rule.id,
                    pattern,
                },
            },
            (Self::Entry(entry), _) => Decision::SetAllow {
                set: entry.set,
                rule_id: None,
                pattern,
            },
        }
    }
}

/// Where a pattern points in the index.
#[derive(Debug, Clone, Copy)]
enum Slot {
    Rule(usize),
    Entry(usize),
}

/// An immutable snapshot of every rule, set entry and switch, indexed for matching. The store
/// replaces it whole after each committed change (R-8), so a decision never sees half a change.
#[derive(Debug, Default)]
pub(crate) struct RuleIndex {
    rules: Vec<Rule>,
    entries: Vec<SetEntry>,
    switches: Switches,
    /// Exact patterns and suffix bases (`.example.com` stored under `example.com`) to slots.
    exact: HashMap<String, Vec<Slot>>,
    suffix: HashMap<String, Vec<Slot>>,
}

/// Precedence among the user's own rules (R-6).
type OwnKey = ((u8, usize), u8, bool, Reverse<RuleId>);
/// Precedence among set entries (R-39): most specific, then deny over allow, then a stable order.
type SetKey = ((u8, usize), bool, Reverse<(RuleSetId, i64)>);

fn own_key(rule: &Rule) -> OwnKey {
    (
        rule.pattern.specificity(),
        rule.scope.rank(),
        rule.effect == Effect::Deny,
        Reverse(rule.id),
    )
}

/// Two entries that tie on all of it decide the same way: same set, same kind of pattern (an
/// exact entry is the host; suffixes of equal length matching one host are equal) and effect.
fn set_key(hit: Hit<'_>) -> SetKey {
    (
        hit.pattern().specificity(),
        hit.effect() == Effect::Deny,
        Reverse((
            hit.rule_set().unwrap_or(RuleSetId::System),
            hit.rule_id().map_or(-1, |id| id.0),
        )),
    )
}

impl RuleIndex {
    /// Indexes rule rows, built-in and System managed entries, and the switches.
    pub(crate) fn new(rules: Vec<Rule>, entries: Vec<SetEntry>, switches: Switches) -> Self {
        let mut exact: HashMap<String, Vec<Slot>> = HashMap::new();
        let mut suffix: HashMap<String, Vec<Slot>> = HashMap::new();
        let mut add = |pattern: &Pattern, slot: Slot| match pattern {
            Pattern::Exact(host) => exact.entry(host.to_string()).or_default().push(slot),
            Pattern::Suffix(s) => suffix
                .entry(s.base().as_str().to_owned())
                .or_default()
                .push(slot),
        };
        for (index, rule) in rules.iter().enumerate() {
            add(&rule.pattern, Slot::Rule(index));
        }
        for (index, entry) in entries.iter().enumerate() {
            add(&entry.pattern, Slot::Entry(index));
        }
        Self {
            rules,
            entries,
            switches,
            exact,
            suffix,
        }
    }

    /// Every rule row, expired ones included until the sweeper removes them.
    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The built-in and System managed entries.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> &[SetEntry] {
        &self.entries
    }

    /// The switches.
    pub(crate) fn switches(&self) -> &Switches {
        &self.switches
    }

    /// What decides `host` requested by `sandbox` at `now`, or `None`.
    ///
    /// The user's own rules: non-expired global rules and non-expired rules of `sandbox` (R-5,
    /// R-7), ranked by R-6. Set entries: those of sets switched on for `sandbox` (R-37), and
    /// System managed entries for every sandbox or for `sandbox`. Then R-39: when an own rule
    /// matches, it decides, unless a set's deny is strictly more specific; when none does, the
    /// most specific set entry decides, deny over allow. With [`SuffixAllows::Ignore`], own
    /// suffix allows and every set allow are treated as no match (R-14, R-42).
    pub(crate) fn decide(
        &self,
        sandbox: &SandboxName,
        host: &Host,
        now: u64,
        suffix_allows: SuffixAllows,
    ) -> Option<Hit<'_>> {
        let ignore = suffix_allows == SuffixAllows::Ignore;
        let mut own: Option<&Rule> = None;
        let mut set_best: Option<(SetKey, Hit<'_>)> = None;
        let mut set_deny: Option<(SetKey, Hit<'_>)> = None;
        for slot in self.candidates(host) {
            let hit = match slot {
                Slot::Rule(index) => {
                    let Some(rule) = self.rules.get(index) else {
                        continue;
                    };
                    if rule.is_expired(now) {
                        continue;
                    }
                    match &rule.scope {
                        Scope::Set(set) => {
                            if !self.switches.is_on(RuleSetId::User(*set), sandbox)
                                || (ignore && rule.effect == Effect::Allow)
                            {
                                continue;
                            }
                            Hit::Rule(rule)
                        }
                        scope => {
                            let applies = scope.sandbox().is_none_or(|s| s == sandbox);
                            let dropped = ignore
                                && rule.effect == Effect::Allow
                                && matches!(rule.pattern, Pattern::Suffix(_));
                            if applies && !dropped && own.is_none_or(|o| own_key(rule) > own_key(o))
                            {
                                own = Some(rule);
                            }
                            continue;
                        }
                    }
                }
                Slot::Entry(index) => {
                    let Some(entry) = self.entries.get(index) else {
                        continue;
                    };
                    let applies = match (&entry.set, &entry.sandbox) {
                        (RuleSetId::System, None) => true,
                        (RuleSetId::System, Some(s)) => s == sandbox,
                        (set, _) => self.switches.is_on(*set, sandbox),
                    };
                    if ignore || !applies {
                        continue;
                    }
                    Hit::Entry(entry)
                }
            };
            let key = set_key(hit);
            if set_best.as_ref().is_none_or(|(best, _)| key > *best) {
                set_best = Some((key, hit));
            }
            if hit.effect() == Effect::Deny && set_deny.as_ref().is_none_or(|(best, _)| key > *best)
            {
                set_deny = Some((key, hit));
            }
        }
        match own {
            Some(rule) => match set_deny {
                Some(((specificity, ..), hit)) if specificity > rule.pattern.specificity() => {
                    Some(hit)
                }
                _ => Some(Hit::Rule(rule)),
            },
            None => set_best.map(|(_, hit)| hit),
        }
    }

    /// Slots whose pattern matches `host`: its exact entry, then every proper suffix.
    fn candidates<'a>(&'a self, host: &Host) -> impl Iterator<Item = Slot> + 'a {
        let exact = self
            .exact
            .get(&host.to_string())
            .into_iter()
            .flatten()
            .copied();
        let suffixes: Vec<Slot> = match host {
            Host::Name(name) => {
                let text = name.as_str();
                text.match_indices('.')
                    .filter_map(|(dot, _)| text.get(dot + 1..))
                    .filter_map(|base| self.suffix.get(base))
                    .flatten()
                    .copied()
                    .collect()
            }
            Host::Ip(_) => Vec::new(),
        };
        exact.chain(suffixes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Actor;
    use proptest::prelude::*;
    use puddle_types::PatternKind;

    pub(crate) fn rule(id: i64, scope: Option<&str>, pattern: &str, effect: Effect) -> Rule {
        Rule {
            id: RuleId(id),
            scope: scope.map_or(Scope::Global, |s| {
                Scope::Sandbox(SandboxName::new(s).unwrap())
            }),
            pattern: Pattern::parse(pattern).unwrap(),
            effect,
            expires_at: None,
            created_at: 0,
            created_by: Actor::Cli,
            source_pending_id: None,
        }
    }

    fn sb(s: &str) -> SandboxName {
        SandboxName::new(s).unwrap()
    }

    fn host(s: &str) -> Host {
        Host::parse_normalised(s).unwrap()
    }

    fn index(rules: Vec<Rule>) -> RuleIndex {
        RuleIndex::new(rules, Vec::new(), Switches::default())
    }

    fn winner(set: &RuleIndex, sandbox: &str, h: &str) -> Option<i64> {
        set.decide(&sb(sandbox), &host(h), 1_000, SuffixAllows::Count)
            .and_then(Hit::rule_id)
            .map(|id| id.0)
    }

    #[test]
    fn r01_empty_rule_set_decides_nothing() {
        let set = RuleIndex::default();
        assert_eq!(set.rules().len(), 0);
        assert_eq!(winner(&set, "a", "example.com"), None);
    }

    #[test]
    fn r05_other_sandboxes_rules_never_apply() {
        let set = index(vec![
            rule(1, Some("other"), "example.com", Effect::Allow),
            rule(2, None, "global.example", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "mine", "example.com"), None);
        assert_eq!(winner(&set, "other", "example.com"), Some(1));
        assert_eq!(winner(&set, "mine", "global.example"), Some(2));
    }

    #[test]
    fn r06_exact_beats_suffix_and_longer_suffix_beats_shorter() {
        let set = index(vec![
            rule(1, Some("a"), ".example.com", Effect::Deny),
            rule(2, None, ".api.example.com", Effect::Allow),
            rule(3, None, "x.api.example.com", Effect::Deny),
        ]);
        assert_eq!(winner(&set, "a", "y.api.example.com"), Some(2));
        assert_eq!(winner(&set, "a", "x.api.example.com"), Some(3));
        assert_eq!(winner(&set, "a", "other.example.com"), Some(1));
    }

    #[test]
    fn r06_sandbox_beats_global_at_equal_specificity() {
        let set = index(vec![
            rule(1, None, ".example.com", Effect::Deny),
            rule(2, Some("a"), ".example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "x.example.com"), Some(2));
        assert_eq!(winner(&set, "b", "x.example.com"), Some(1));
    }

    #[test]
    fn r06_broader_sandbox_allow_never_overrides_narrower_global_deny() {
        let set = index(vec![
            rule(1, None, ".api.example.com", Effect::Deny),
            rule(2, Some("a"), ".example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "x.api.example.com"), Some(1));
    }

    #[test]
    fn r06_deny_beats_allow_at_equal_scope() {
        let set = index(vec![
            rule(1, Some("a"), "example.com", Effect::Allow),
            rule(2, Some("a"), "example.com", Effect::Deny),
            rule(3, Some("a"), "example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "example.com"), Some(2));
    }

    #[test]
    fn scope_rank_leaves_room_below_global() {
        assert_eq!(Scope::Global.rank(), 1);
        assert!(Scope::Sandbox(sb("a")).rank() > Scope::Global.rank());
        assert!(Scope::Set(1).rank() < Scope::Global.rank());
    }

    fn in_set(id: i64, set: i64, pattern: &str, effect: Effect) -> Rule {
        let mut r = rule(id, None, pattern, effect);
        r.scope = Scope::Set(set);
        r
    }

    fn system(pattern: &str, sandbox: Option<&str>) -> SetEntry {
        SetEntry {
            set: RuleSetId::System,
            pattern: Pattern::parse(pattern).unwrap(),
            sandbox: sandbox.map(sb),
        }
    }

    fn built_in(slug: &'static str, pattern: &str) -> SetEntry {
        SetEntry {
            set: RuleSetId::BuiltIn(slug),
            pattern: Pattern::parse(pattern).unwrap(),
            sandbox: None,
        }
    }

    fn decision(index: &RuleIndex, sandbox: &str, h: &str) -> Option<Decision> {
        index
            .decide(&sb(sandbox), &host(h), 1_000, SuffixAllows::Count)
            .map(Hit::decision)
    }

    fn own_allow(id: i64, pattern: PatternKind) -> Decision {
        Decision::Allow {
            rule_id: RuleId(id),
            pattern,
        }
    }

    #[test]
    fn r39_example_one_a_set_allow_never_opens_what_your_rule_closes() {
        // You deny *.visualstudio.com everywhere; System managed allows the update host.
        let index = RuleIndex::new(
            vec![rule(1, None, ".visualstudio.com", Effect::Deny)],
            vec![system("update.code.visualstudio.com", None)],
            Switches::default(),
        );
        assert_eq!(
            decision(&index, "a", "update.code.visualstudio.com"),
            Some(Decision::Deny {
                rule_id: RuleId(1),
                pattern: PatternKind::Suffix
            })
        );
        // Without your rule, the set's allow fills the gap.
        let index = RuleIndex::new(
            Vec::new(),
            vec![system("update.code.visualstudio.com", None)],
            Switches::default(),
        );
        assert_eq!(
            decision(&index, "a", "update.code.visualstudio.com"),
            Some(Decision::SetAllow {
                set: RuleSetId::System,
                rule_id: None,
                pattern: PatternKind::Exact
            })
        );
    }

    #[test]
    fn r39_example_two_a_set_block_competes_at_its_level_of_detail() {
        // You allow *.example.com; your own set blocks ads.example.com.
        let blocked = RuleIndex::new(
            vec![
                rule(1, None, ".example.com", Effect::Allow),
                in_set(2, 7, "ads.example.com", Effect::Deny),
            ],
            Vec::new(),
            Switches::default(),
        );
        assert_eq!(
            decision(&blocked, "a", "ads.example.com"),
            Some(Decision::SetDeny {
                set: RuleSetId::User(7),
                rule_id: RuleId(2),
                pattern: PatternKind::Exact
            })
        );
        assert_eq!(
            decision(&blocked, "a", "www.example.com"),
            Some(own_allow(1, PatternKind::Suffix))
        );
        // Your exact allow of the same host still wins.
        let mut rules = blocked.rules().to_vec();
        rules.push(rule(3, Some("a"), "ads.example.com", Effect::Allow));
        let yours = RuleIndex::new(rules, Vec::new(), Switches::default());
        assert_eq!(
            decision(&yours, "a", "ads.example.com"),
            Some(own_allow(3, PatternKind::Exact))
        );
        // At equal detail your rule ranks above the set's block.
        let equal = RuleIndex::new(
            vec![
                rule(1, None, ".example.com", Effect::Allow),
                in_set(2, 7, ".example.com", Effect::Deny),
            ],
            Vec::new(),
            Switches::default(),
        );
        assert_eq!(
            decision(&equal, "a", "x.example.com"),
            Some(own_allow(1, PatternKind::Suffix))
        );
    }

    #[test]
    fn r39_between_sets_most_specific_then_deny_wins() {
        let index = RuleIndex::new(
            vec![
                in_set(1, 1, ".example.com", Effect::Deny),
                in_set(2, 2, "x.example.com", Effect::Allow),
                in_set(3, 2, ".example.com", Effect::Allow),
            ],
            vec![built_in("github", "y.example.com")],
            {
                let mut s = Switches::default();
                s.insert(RuleSetId::BuiltIn("github"), None, true);
                s
            },
        );
        let set_of = |h| decision(&index, "a", h).and_then(|d| d.rule_set());
        assert_eq!(set_of("x.example.com"), Some(RuleSetId::User(2)));
        assert_eq!(set_of("y.example.com"), Some(RuleSetId::BuiltIn("github")));
        assert!(matches!(
            decision(&index, "a", "z.example.com"),
            Some(Decision::SetDeny { .. })
        ));
    }

    #[test]
    fn r37_switches_decide_where_a_set_applies() {
        let rules = vec![in_set(1, 5, "example.com", Effect::Allow)];
        let entries = vec![built_in("github", "github.com")];
        let mut switches = Switches::default();
        // A set you made is on by default; a built-in set ships off.
        let index = RuleIndex::new(rules.clone(), entries.clone(), switches.clone());
        assert!(decision(&index, "a", "example.com").is_some());
        assert_eq!(decision(&index, "a", "github.com"), None);
        // Global on, one sandbox off; the sandbox's value wins there.
        switches.insert(RuleSetId::BuiltIn("github"), None, true);
        switches.insert(RuleSetId::BuiltIn("github"), Some(sb("b")), false);
        switches.insert(RuleSetId::User(5), None, false);
        switches.insert(RuleSetId::User(5), Some(sb("b")), true);
        let index = RuleIndex::new(rules, entries, switches);
        assert!(decision(&index, "a", "github.com").is_some());
        assert_eq!(decision(&index, "b", "github.com"), None);
        assert_eq!(decision(&index, "a", "example.com"), None);
        assert!(decision(&index, "b", "example.com").is_some());
        assert_eq!(index.switches().global(RuleSetId::User(5)), Some(false));
        assert_eq!(
            index.switches().overrides(RuleSetId::BuiltIn("github")),
            vec![(sb("b"), false)]
        );
        assert_eq!(index.entries().len(), 1);
        assert!(default_on(RuleSetId::User(9)) && default_on(RuleSetId::System));
        assert!(
            !default_on(RuleSetId::BuiltIn("github")) && !default_on(RuleSetId::BuiltIn("gone"))
        );
    }

    #[test]
    fn r41_system_entries_for_one_sandbox_stay_there() {
        let index = RuleIndex::new(
            Vec::new(),
            vec![system("marketplace.visualstudio.com", Some("ssh"))],
            Switches::default(),
        );
        assert!(decision(&index, "ssh", "marketplace.visualstudio.com").is_some());
        assert_eq!(
            decision(&index, "other", "marketplace.visualstudio.com"),
            None
        );
    }

    #[test]
    fn r42_ignore_mode_drops_every_set_allow_and_keeps_set_denies() {
        let index = RuleIndex::new(
            vec![
                in_set(1, 1, "db.corp.example", Effect::Allow),
                in_set(2, 1, "bad.corp.example", Effect::Deny),
            ],
            vec![system("open-vsx.org", None)],
            Switches::default(),
        );
        let ignore = |h: &str| {
            index
                .decide(&sb("a"), &host(h), 0, SuffixAllows::Ignore)
                .map(Hit::decision)
        };
        assert_eq!(ignore("db.corp.example"), None);
        assert_eq!(ignore("open-vsx.org"), None);
        assert!(matches!(
            ignore("bad.corp.example"),
            Some(Decision::SetDeny { .. })
        ));
    }

    #[test]
    fn r07_expired_set_entries_never_match() {
        let mut expired = in_set(1, 1, "example.com", Effect::Deny);
        expired.expires_at = Some(1_000);
        let index = RuleIndex::new(vec![expired], Vec::new(), Switches::default());
        assert_eq!(decision(&index, "a", "example.com"), None);
    }

    #[test]
    fn identical_rules_tie_on_lower_id() {
        let set = index(vec![
            rule(5, None, "example.com", Effect::Allow),
            rule(4, None, "example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "example.com"), Some(4));
    }

    #[test]
    fn r07_expired_rule_never_matches() {
        let mut expired = rule(1, None, "example.com", Effect::Allow);
        expired.expires_at = Some(1_000);
        let mut live = rule(2, None, ".example.com", Effect::Deny);
        live.expires_at = Some(1_001);
        let set = index(vec![expired, live]);
        // At now == expires_at the rule is already expired.
        assert_eq!(winner(&set, "a", "example.com"), None);
        assert_eq!(winner(&set, "a", "x.example.com"), Some(2));
        assert_eq!(
            set.decide(&sb("a"), &host("x.example.com"), 1_001, SuffixAllows::Count)
                .map(Hit::rule_id),
            None
        );
    }

    #[test]
    fn r14_ignore_mode_drops_suffix_allows_but_keeps_suffix_denies() {
        let set = index(vec![
            rule(1, Some("a"), ".example.com", Effect::Allow),
            rule(2, None, ".example.com", Effect::Deny),
            rule(3, None, ".corp.example", Effect::Allow),
            rule(4, None, "db.corp.example", Effect::Allow),
        ]);
        let ignore = |h: &str| {
            set.decide(&sb("a"), &host(h), 0, SuffixAllows::Ignore)
                .map(|hit| (hit.rule_id().unwrap().0, hit.pattern().kind()))
        };
        assert_eq!(ignore("x.example.com"), Some((2, PatternKind::Suffix)));
        assert_eq!(ignore("web.corp.example"), None);
        assert_eq!(ignore("db.corp.example"), Some((4, PatternKind::Exact)));
    }

    #[test]
    fn ip_literals_match_only_exact_rules() {
        let set = index(vec![rule(1, None, "10.0.0.1", Effect::Allow)]);
        assert_eq!(winner(&set, "a", "10.0.0.1"), Some(1));
        assert_eq!(winner(&set, "a", "10.0.0.2"), None);
    }

    /// The precedence of R-6, written as plainly as possible, for the property test below.
    fn reference(rules: &[Rule], sandbox: &SandboxName, h: &Host, now: u64) -> Option<RuleId> {
        let mut best: Option<&Rule> = None;
        for r in rules {
            let applies = r.pattern.matches(h)
                && !r.is_expired(now)
                && r.scope.sandbox().is_none_or(|s| s == sandbox);
            if !applies {
                continue;
            }
            let key = |r: &Rule| {
                (
                    r.pattern.specificity(),
                    r.scope.rank(),
                    r.effect == Effect::Deny,
                    Reverse(r.id),
                )
            };
            if best.is_none_or(|b| key(r) > key(b)) {
                best = Some(r);
            }
        }
        best.map(|r| r.id)
    }

    fn arb_rule() -> impl Strategy<Value = Rule> {
        (
            0..50i64,
            prop_oneof![Just(None), Just(Some("a")), Just(Some("b"))],
            prop_oneof![
                Just("x.y.example.com"),
                Just("y.example.com"),
                Just(".y.example.com"),
                Just(".example.com"),
                Just("example.com"),
                Just("10.0.0.1"),
            ],
            any::<bool>(),
            proptest::option::of(0..20u64),
        )
            .prop_map(|(id, scope, pattern, deny, expires)| {
                let effect = if deny { Effect::Deny } else { Effect::Allow };
                let mut r = rule(id, scope, pattern, effect);
                r.expires_at = expires;
                r
            })
    }

    /// R-39 written as plainly as possible, for the property test below: every candidate
    /// checked one by one.
    fn reference_p3(
        index: &RuleIndex,
        sandbox: &SandboxName,
        h: &Host,
        now: u64,
        suffix_allows: SuffixAllows,
    ) -> Option<Decision> {
        let ignore = suffix_allows == SuffixAllows::Ignore;
        let own: Vec<&Rule> = index
            .rules()
            .iter()
            .filter(|r| r.pattern.matches(h) && !r.is_expired(now))
            .filter(|r| matches!(r.scope, Scope::Global) || r.scope.sandbox() == Some(sandbox))
            .filter(|r| {
                !(ignore && r.effect == Effect::Allow && r.pattern.kind() == PatternKind::Suffix)
            })
            .collect();
        let mut sets: Vec<Hit<'_>> = Vec::new();
        for r in index.rules() {
            if let Scope::Set(set) = r.scope
                && r.pattern.matches(h)
                && !r.is_expired(now)
                && index.switches().is_on(RuleSetId::User(set), sandbox)
                && !(ignore && r.effect == Effect::Allow)
            {
                sets.push(Hit::Rule(r));
            }
        }
        for e in index.entries() {
            let on = match e.set {
                RuleSetId::System => e.sandbox.as_ref().is_none_or(|s| s == sandbox),
                set => index.switches().is_on(set, sandbox),
            };
            if on && !ignore && e.pattern.matches(h) {
                sets.push(Hit::Entry(e));
            }
        }
        let best_set = sets.iter().copied().max_by_key(|hit| set_key(*hit));
        let best_deny = sets
            .iter()
            .copied()
            .filter(|hit| hit.effect() == Effect::Deny)
            .max_by_key(|hit| set_key(*hit));
        match own.into_iter().max_by_key(|r| own_key(r)) {
            Some(r) => match best_deny {
                Some(d) if d.pattern().specificity() > r.pattern.specificity() => {
                    Some(d.decision())
                }
                _ => Some(Hit::Rule(r).decision()),
            },
            None => best_set.map(Hit::decision),
        }
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        prop_oneof![
            Just(Scope::Global),
            Just(Scope::Sandbox(sb("a"))),
            Just(Scope::Sandbox(sb("b"))),
            Just(Scope::Set(1)),
            Just(Scope::Set(2)),
        ]
    }

    fn arb_pattern() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("x.y.example.com"),
            Just("y.example.com"),
            Just(".y.example.com"),
            Just(".example.com"),
            Just("example.com"),
            Just("10.0.0.1"),
        ]
    }

    fn arb_index() -> impl Strategy<Value = RuleIndex> {
        let rules = proptest::collection::vec(
            (
                0..50i64,
                arb_scope(),
                arb_pattern(),
                any::<bool>(),
                proptest::option::of(0..20u64),
            ),
            0..10,
        );
        let entries = proptest::collection::vec(
            (
                prop_oneof![Just(RuleSetId::System), Just(RuleSetId::BuiltIn("github"))],
                arb_pattern(),
                prop_oneof![Just(None), Just(Some("a")), Just(Some("b"))],
            ),
            0..4,
        );
        let switches = proptest::collection::vec(
            (
                prop_oneof![
                    Just(RuleSetId::User(1)),
                    Just(RuleSetId::User(2)),
                    Just(RuleSetId::BuiltIn("github"))
                ],
                prop_oneof![Just(None), Just(Some("a")), Just(Some("b"))],
                any::<bool>(),
            ),
            0..5,
        );
        (rules, entries, switches).prop_map(|(rules, entries, switches)| {
            let rules = rules
                .into_iter()
                .map(|(id, scope, pattern, deny, expires)| {
                    let effect = if deny { Effect::Deny } else { Effect::Allow };
                    let mut r = rule(id, None, pattern, effect);
                    r.scope = scope;
                    r.expires_at = expires;
                    r
                })
                .collect();
            let entries = entries
                .into_iter()
                .map(|(set, pattern, sandbox)| SetEntry {
                    set,
                    pattern: Pattern::parse(pattern).unwrap(),
                    sandbox: if set == RuleSetId::System {
                        sandbox.map(sb)
                    } else {
                        None
                    },
                })
                .collect();
            let mut on = Switches::default();
            for (set, sandbox, enabled) in switches {
                on.insert(set, sandbox.map(sb), enabled);
            }
            RuleIndex::new(rules, entries, on)
        })
    }

    proptest! {
        #[test]
        fn index_agrees_with_the_plain_precedence(
            rules in proptest::collection::vec(arb_rule(), 0..12),
            sandbox in prop_oneof![Just("a"), Just("b")],
            h in prop_oneof![
                Just("x.y.example.com"), Just("y.example.com"), Just("example.com"),
                Just("z.example.com"), Just("10.0.0.1"),
            ],
            now in 0..25u64,
        ) {
            let set = index(rules.clone());
            let got = set.decide(&sb(sandbox), &host(h), now, SuffixAllows::Count).and_then(Hit::rule_id);
            prop_assert_eq!(got, reference(&rules, &sb(sandbox), &host(h), now));
        }

        #[test]
        fn r39_index_agrees_with_the_plain_precedence_with_sets(
            index in arb_index(),
            sandbox in prop_oneof![Just("a"), Just("b")],
            h in prop_oneof![
                Just("x.y.example.com"), Just("y.example.com"), Just("example.com"),
                Just("z.example.com"), Just("10.0.0.1"),
            ],
            now in 0..25u64,
            ignore in any::<bool>(),
        ) {
            let mode = if ignore { SuffixAllows::Ignore } else { SuffixAllows::Count };
            let got = index.decide(&sb(sandbox), &host(h), now, mode).map(Hit::decision);
            prop_assert_eq!(got, reference_p3(&index, &sb(sandbox), &host(h), now, mode));
        }

        #[test]
        fn r39_a_set_never_opens_what_an_own_rule_closes(
            index in arb_index(),
            sandbox in prop_oneof![Just("a"), Just("b")],
            h in prop_oneof![Just("x.y.example.com"), Just("y.example.com"), Just("example.com")],
        ) {
            let own_only = RuleIndex::new(
                index.rules().iter().filter(|r| r.scope.set().is_none()).cloned().collect(),
                Vec::new(),
                Switches::default(),
            );
            let mine = own_only.decide(&sb(sandbox), &host(h), 5, SuffixAllows::Count).map(Hit::effect);
            let all = index.decide(&sb(sandbox), &host(h), 5, SuffixAllows::Count).map(Hit::effect);
            if mine == Some(Effect::Deny) {
                prop_assert_eq!(all, Some(Effect::Deny));
            }
        }

        #[test]
        fn r07_expired_rules_never_decide(
            rules in proptest::collection::vec(arb_rule(), 0..12),
            now in 0..25u64,
        ) {
            let set = index(rules);
            for h in ["x.y.example.com", "example.com", "10.0.0.1"] {
                if let Some(Hit::Rule(r)) = set.decide(&sb("a"), &host(h), now, SuffixAllows::Count) {
                    prop_assert!(!r.is_expired(now));
                }
            }
        }
    }
}
