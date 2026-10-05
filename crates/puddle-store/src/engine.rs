// SPDX-License-Identifier: GPL-3.0-or-later
//! The in-memory rule set and the matching rules R-5 to R-7. Pure: no I/O, no clock.

use std::cmp::Reverse;
use std::collections::HashMap;

use puddle_types::{Host, SandboxName, SuffixAllows};

use crate::pattern::Pattern;
use crate::rule::{Effect, Rule, Scope};

/// An immutable snapshot of every rule, indexed for matching. The store replaces it whole after
/// each committed change (R-8), so a decision never sees half a change.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Exact patterns and suffix bases (`.example.com` stored under `example.com`) to rule indexes.
    exact: HashMap<String, Vec<usize>>,
    suffix: HashMap<String, Vec<usize>>,
}

impl RuleSet {
    /// Indexes `rules`.
    #[must_use]
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut exact: HashMap<String, Vec<usize>> = HashMap::new();
        let mut suffix: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, rule) in rules.iter().enumerate() {
            match &rule.pattern {
                Pattern::Exact(host) => exact.entry(host.to_string()).or_default().push(index),
                Pattern::Suffix(s) => suffix
                    .entry(s.base().as_str().to_owned())
                    .or_default()
                    .push(index),
            }
        }
        Self {
            rules,
            exact,
            suffix,
        }
    }

    /// Every rule, expired ones included until the sweeper removes them.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The deciding rule for `host` requested by `sandbox` at `now`, or `None`.
    ///
    /// Applicable: non-expired global rules and non-expired rules of `sandbox` (R-5, R-7).
    /// Precedence (R-6): exact over suffix, longer suffix over shorter; then sandbox over global;
    /// then deny over allow. Two identical rules tie on the lower id, so the answer is stable.
    #[must_use]
    pub fn decide(
        &self,
        sandbox: &SandboxName,
        host: &Host,
        now: u64,
        suffix_allows: SuffixAllows,
    ) -> Option<&Rule> {
        self.candidates(host)
            .filter_map(|index| self.rules.get(index))
            .filter(|rule| !rule.is_expired(now))
            .filter(|rule| match &rule.scope {
                Scope::Global => true,
                Scope::Sandbox(id) => id == sandbox,
            })
            .filter(|rule| {
                !(suffix_allows == SuffixAllows::Ignore
                    && rule.effect == Effect::Allow
                    && matches!(rule.pattern, Pattern::Suffix(_)))
            })
            .max_by_key(|rule| {
                (
                    rule.pattern.specificity(),
                    matches!(rule.scope, Scope::Sandbox(_)),
                    rule.effect == Effect::Deny,
                    Reverse(rule.id),
                )
            })
    }

    /// Indexes of rules whose pattern matches `host`: its exact entry, then every proper suffix.
    fn candidates<'a>(&'a self, host: &Host) -> impl Iterator<Item = usize> + 'a {
        let exact = self
            .exact
            .get(&host.to_string())
            .into_iter()
            .flatten()
            .copied();
        let suffixes: Vec<usize> = match host {
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
    use puddle_types::{PatternKind, RuleId};

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

    fn winner(set: &RuleSet, sandbox: &str, h: &str) -> Option<i64> {
        set.decide(&sb(sandbox), &host(h), 1_000, SuffixAllows::Count)
            .map(|r| r.id.0)
    }

    #[test]
    fn r01_empty_rule_set_decides_nothing() {
        let set = RuleSet::default();
        assert_eq!(set.rules().len(), 0);
        assert_eq!(winner(&set, "a", "example.com"), None);
    }

    #[test]
    fn r05_other_sandboxes_rules_never_apply() {
        let set = RuleSet::new(vec![
            rule(1, Some("other"), "example.com", Effect::Allow),
            rule(2, None, "global.example", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "mine", "example.com"), None);
        assert_eq!(winner(&set, "other", "example.com"), Some(1));
        assert_eq!(winner(&set, "mine", "global.example"), Some(2));
    }

    #[test]
    fn r06_exact_beats_suffix_and_longer_suffix_beats_shorter() {
        let set = RuleSet::new(vec![
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
        let set = RuleSet::new(vec![
            rule(1, None, ".example.com", Effect::Deny),
            rule(2, Some("a"), ".example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "x.example.com"), Some(2));
        assert_eq!(winner(&set, "b", "x.example.com"), Some(1));
    }

    #[test]
    fn r06_broader_sandbox_allow_never_overrides_narrower_global_deny() {
        let set = RuleSet::new(vec![
            rule(1, None, ".api.example.com", Effect::Deny),
            rule(2, Some("a"), ".example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "x.api.example.com"), Some(1));
    }

    #[test]
    fn r06_deny_beats_allow_at_equal_scope() {
        let set = RuleSet::new(vec![
            rule(1, Some("a"), "example.com", Effect::Allow),
            rule(2, Some("a"), "example.com", Effect::Deny),
            rule(3, Some("a"), "example.com", Effect::Allow),
        ]);
        assert_eq!(winner(&set, "a", "example.com"), Some(2));
    }

    #[test]
    fn identical_rules_tie_on_lower_id() {
        let set = RuleSet::new(vec![
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
        let set = RuleSet::new(vec![expired, live]);
        // At now == expires_at the rule is already expired.
        assert_eq!(winner(&set, "a", "example.com"), None);
        assert_eq!(winner(&set, "a", "x.example.com"), Some(2));
        assert_eq!(
            set.decide(&sb("a"), &host("x.example.com"), 1_001, SuffixAllows::Count),
            None
        );
    }

    #[test]
    fn r14_ignore_mode_drops_suffix_allows_but_keeps_suffix_denies() {
        let set = RuleSet::new(vec![
            rule(1, Some("a"), ".example.com", Effect::Allow),
            rule(2, None, ".example.com", Effect::Deny),
            rule(3, None, ".corp.example", Effect::Allow),
            rule(4, None, "db.corp.example", Effect::Allow),
        ]);
        let ignore = |h: &str| {
            set.decide(&sb("a"), &host(h), 0, SuffixAllows::Ignore)
                .map(|r| (r.id.0, r.pattern.kind()))
        };
        assert_eq!(ignore("x.example.com"), Some((2, PatternKind::Suffix)));
        assert_eq!(ignore("web.corp.example"), None);
        assert_eq!(ignore("db.corp.example"), Some((4, PatternKind::Exact)));
    }

    #[test]
    fn ip_literals_match_only_exact_rules() {
        let set = RuleSet::new(vec![rule(1, None, "10.0.0.1", Effect::Allow)]);
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
                    r.scope.sandbox().is_some(),
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
            let set = RuleSet::new(rules.clone());
            let got = set.decide(&sb(sandbox), &host(h), now, SuffixAllows::Count).map(|r| r.id);
            prop_assert_eq!(got, reference(&rules, &sb(sandbox), &host(h), now));
        }

        #[test]
        fn r07_expired_rules_never_decide(
            rules in proptest::collection::vec(arb_rule(), 0..12),
            now in 0..25u64,
        ) {
            let set = RuleSet::new(rules);
            for h in ["x.y.example.com", "example.com", "10.0.0.1"] {
                if let Some(r) = set.decide(&sb("a"), &host(h), now, SuffixAllows::Count) {
                    prop_assert!(!r.is_expired(now));
                }
            }
        }
    }
}
