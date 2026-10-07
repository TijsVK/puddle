// SPDX-License-Identifier: GPL-3.0-or-later
//! Rules: who they apply to, what they match, what they do, until when (`docs/spec/rules.md` §1).

use puddle_types::{RuleId, SandboxName};

use crate::pattern::Pattern;

/// Which requests a rule applies to (R-5, R-38).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// Every sandbox.
    Global,
    /// One sandbox.
    Sandbox(SandboxName),
    /// An entry of a rule set the user made, by the set's id: it applies wherever the set is
    /// switched on, and ranks below the user's own rules (R-39).
    Set(i64),
}

impl Scope {
    /// Precedence at equal pattern specificity (R-6 step 2): higher wins. `Sandbox` 2,
    /// `Global` 1, `Set` 0.
    #[must_use]
    pub fn rank(&self) -> u8 {
        match self {
            Self::Set(_) => 0,
            Self::Global => 1,
            Self::Sandbox(_) => 2,
        }
    }

    /// The sandbox, for a sandbox rule.
    #[must_use]
    pub fn sandbox(&self) -> Option<&SandboxName> {
        match self {
            Self::Global | Self::Set(_) => None,
            Self::Sandbox(id) => Some(id),
        }
    }

    /// The set, for a rule set's entry.
    #[must_use]
    pub fn set(&self) -> Option<i64> {
        match self {
            Self::Set(id) => Some(*id),
            Self::Global | Self::Sandbox(_) => None,
        }
    }

    /// `global`, `sandbox` or `set`, as stored.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Sandbox(_) => "sandbox",
            Self::Set(_) => "set",
        }
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Let the connection through.
    Allow,
    /// Refuse it.
    Deny,
}

impl Effect {
    /// `allow` or `deny`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Who made a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Actor {
    /// The `puddle` command line.
    Cli,
    /// The desktop UI.
    Ui,
    /// The HTTP API.
    Api,
    /// puddle itself (the sweeper, sandbox deletion). Never creates rules.
    System,
}

impl Actor {
    /// `cli`, `ui`, `api` or `system`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Ui => "ui",
            Self::Api => "api",
            Self::System => "system",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "cli" => Self::Cli,
            "ui" => Self::Ui,
            "api" => Self::Api,
            "system" => Self::System,
            _ => return None,
        })
    }
}

/// A rule as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Row id, never reused.
    pub id: RuleId,
    /// Global or one sandbox.
    pub scope: Scope,
    /// Exact host or suffix.
    pub pattern: Pattern,
    /// Allow or deny.
    pub effect: Effect,
    /// Epoch ms after which the rule never matches (R-7); `None` is permanent.
    pub expires_at: Option<u64>,
    /// Epoch ms.
    pub created_at: u64,
    /// Who created it.
    pub created_by: Actor,
    /// The pending row it was approved or denied from (R-15).
    pub source_pending_id: Option<puddle_types::PendingId>,
}

impl Rule {
    /// Whether the rule has expired at `now` (`expires_at <= now`, R-7).
    #[must_use]
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }
}

/// A rule to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule {
    /// Global or one sandbox.
    pub scope: Scope,
    /// Exact host or suffix.
    pub pattern: Pattern,
    /// Allow or deny.
    pub effect: Effect,
    /// Epoch ms; `None` is permanent.
    pub expires_at: Option<u64>,
    /// Who creates it. [`Actor::System`] is refused.
    pub created_by: Actor,
}
