// SPDX-License-Identifier: GPL-3.0-or-later
//! What the proxy asks the rules engine, and what it gets back (`docs/spec/rules.md` R-9, R-14).
//!
//! The proxy (W2) depends on [`Policy`]; the store (W3) implements it; the host program wires
//! them. Neither crate depends on the other.

use std::fmt;

use crate::{Host, SandboxName};

/// A rule's row id. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleId(pub i64);

/// A pending request's row id. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PendingId(pub i64);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for PendingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How a rule's pattern matched the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternKind {
    /// The identical normalised host or IP literal.
    Exact,
    /// A `.example.com` suffix.
    Suffix,
}

/// What became of a request that matched no rule (R-10 to R-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingOutcome {
    /// A new pending row was written.
    New(PendingId),
    /// An open row for the same `(sandbox, host, port)` already existed; it was updated.
    Repeat(PendingId),
    /// The sandbox is over its rate limit or open-row cap; no row was written.
    Suppressed,
}

impl PendingOutcome {
    /// The pending row, if one exists.
    #[must_use]
    pub fn pending_id(self) -> Option<PendingId> {
        match self {
            Self::New(id) | Self::Repeat(id) => Some(id),
            Self::Suppressed => None,
        }
    }
}

/// The engine's answer for one request (R-9).
///
/// `Pending` means the connection is refused now (R-10) and the request waits in the inbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// An allow rule decided.
    Allow {
        /// The deciding rule.
        rule_id: RuleId,
        /// How it matched; the proxy needs this for local destinations (R-14).
        pattern: PatternKind,
    },
    /// A deny rule decided.
    Deny {
        /// The deciding rule.
        rule_id: RuleId,
        /// How it matched.
        pattern: PatternKind,
    },
    /// No rule decided.
    Pending(PendingOutcome),
}

/// Whether suffix allow rules count for this request (R-14).
///
/// After resolving an allowed name to a local address whose toggle is on, the proxy asks again
/// with [`SuffixAllows::Ignore`] unless "wildcards reach local addresses" is on; the request then
/// needs an exact allow, and goes pending for the exact name otherwise. Suffix *deny* rules
/// always count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixAllows {
    /// Suffix allow rules decide as usual.
    Count,
    /// Suffix allow rules are treated as no match.
    Ignore,
}

/// One connection attempt as the proxy sees it: `(sandbox, host, port)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EgressRequest {
    /// The sandbox, from the route the connection arrived on.
    pub sandbox: SandboxName,
    /// The normalised destination.
    pub host: Host,
    /// The destination port. Rules ignore it (R-2); pending rows and the audit record it.
    pub port: u16,
}

/// The engine could not decide. The proxy fails closed: it refuses the connection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policy unavailable: {reason}")]
pub struct PolicyError {
    /// What went wrong, without secret values.
    pub reason: String,
}

/// Decides egress requests. Implemented by the store, used by the proxy.
///
/// Calls may write to the database (pending rows), so async callers run them on a blocking
/// thread (`spawn_blocking`).
pub trait Policy: Send + Sync {
    /// Decides `request` at the current time.
    ///
    /// # Errors
    /// Returns [`PolicyError`] when the decision could not be made; treat it as a deny.
    fn decide(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Decision, PolicyError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_outcome_exposes_row_id() {
        assert_eq!(
            PendingOutcome::New(PendingId(3)).pending_id(),
            Some(PendingId(3))
        );
        assert_eq!(
            PendingOutcome::Repeat(PendingId(4)).pending_id(),
            Some(PendingId(4))
        );
        assert_eq!(PendingOutcome::Suppressed.pending_id(), None);
    }

    #[test]
    fn ids_and_errors_display() {
        assert_eq!(RuleId(7).to_string(), "7");
        assert_eq!(PendingId(8).to_string(), "8");
        let err = PolicyError {
            reason: "database is locked".into(),
        };
        assert_eq!(err.to_string(), "policy unavailable: database is locked");
    }
}
