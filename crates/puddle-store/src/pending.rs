// SPDX-License-Identifier: GPL-3.0-or-later
//! Pending requests and how the user decides them (`docs/spec/rules.md` §3).

use std::time::Duration;

use puddle_types::{Host, PendingId, RuleId, SandboxName};

use crate::rule::{Actor, Effect, Rule};

/// A pending row's state: `requested → allowed | denied | expired`; the end states are final.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingState {
    /// Waiting for the user.
    Requested,
    /// Approved; `rule_id` names the allow rule.
    Allowed,
    /// Denied; `rule_id` names the deny rule.
    Denied,
    /// Closed without a decision: stale (R-20) or its sandbox was deleted (R-21).
    Expired,
}

impl PendingState {
    /// `requested`, `allowed`, `denied` or `expired`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "requested" => Self::Requested,
            "allowed" => Self::Allowed,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            _ => return None,
        })
    }

    pub(crate) fn decided_by(effect: Effect) -> Self {
        match effect {
            Effect::Allow => Self::Allowed,
            Effect::Deny => Self::Denied,
        }
    }
}

/// A request that matched no rule (R-10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRow {
    /// Row id, never reused (R-12).
    pub id: PendingId,
    /// The requesting sandbox.
    pub sandbox: SandboxName,
    /// The requested host.
    pub host: Host,
    /// The requested port.
    pub port: u16,
    /// Epoch ms of the first request.
    pub first_seen: u64,
    /// Epoch ms of the latest request.
    pub last_seen: u64,
    /// How many requests the row stands for.
    pub attempts: u64,
    /// Where the row is in its life.
    pub state: PendingState,
    /// Epoch ms the row left `requested`.
    pub decided_at: Option<u64>,
    /// Who closed it.
    pub decided_by: Option<Actor>,
    /// The rule that decided it.
    pub rule_id: Option<RuleId>,
    /// The rule set whose entry decided it (`system`, `builtin:<slug>`, `user:<id>`), when a
    /// set's entry did (R-37, R-41).
    pub rule_set: Option<String>,
}

/// Rule scope for a decision (R-15). Defaults to the row's sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeChoice {
    /// Only the row's sandbox.
    #[default]
    Sandbox,
    /// Every sandbox.
    Global,
    /// An entry of the rule set the user made with this id: wherever the set is on (R-38).
    Set(i64),
}

/// Rule pattern for a decision (R-15). Defaults to the row's exact host.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PatternChoice {
    /// The row's host, exactly.
    #[default]
    Exact,
    /// A suffix of the row's host (`example.com`, `.example.com` or `*.example.com`) that passes
    /// the public-suffix check (R-4).
    Suffix(String),
}

/// The four choices of an approve or deny (R-15). Nothing widens implicitly: every choice
/// that isn't made stays at its narrowest default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Allow or deny.
    pub effect: Effect,
    /// This sandbox (default) or every sandbox.
    pub scope: ScopeChoice,
    /// Exact host (default) or a suffix.
    pub pattern: PatternChoice,
    /// `None` is permanent (default).
    pub expires_in: Option<Duration>,
}

impl Resolution {
    /// Allow, this sandbox, exact host, permanent.
    #[must_use]
    pub fn allow() -> Self {
        Self::with_effect(Effect::Allow)
    }

    /// Deny, this sandbox, exact host, permanent.
    #[must_use]
    pub fn deny() -> Self {
        Self::with_effect(Effect::Deny)
    }

    fn with_effect(effect: Effect) -> Self {
        Self {
            effect,
            scope: ScopeChoice::default(),
            pattern: PatternChoice::default(),
            expires_in: None,
        }
    }
}

/// What an approve or deny did (R-17), for the CLI and UI to echo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    /// The row as decided.
    pub row: PendingRow,
    /// The rule created.
    pub rule: Rule,
    /// Other open rows the new rule closed the same way (R-16).
    pub also_closed: Vec<PendingId>,
}

/// One inbox group: open rows that share a registrable domain (R-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxGroup {
    /// `example.co.uk`, or the IP literal.
    pub registrable_domain: String,
    /// Open rows, most recent first.
    pub rows: Vec<PendingRow>,
}

/// A sandbox's pending-row suppression (R-13), for the inbox's "N suppressed" line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Suppression {
    /// Whether requests are being suppressed now.
    pub active: bool,
    /// Requests suppressed in the current (or last) episode.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_through_text() {
        for state in [
            PendingState::Requested,
            PendingState::Allowed,
            PendingState::Denied,
            PendingState::Expired,
        ] {
            assert_eq!(PendingState::parse(state.as_str()), Some(state));
        }
        assert_eq!(PendingState::parse("open"), None);
    }

    #[test]
    fn r15_resolution_defaults_are_narrowest() {
        let allow = Resolution::allow();
        assert_eq!(allow.effect, Effect::Allow);
        assert_eq!(allow.scope, ScopeChoice::Sandbox);
        assert_eq!(allow.pattern, PatternChoice::Exact);
        assert_eq!(allow.expires_in, None);
        assert_eq!(Resolution::deny().effect, Effect::Deny);
    }
}
