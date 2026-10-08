// SPDX-License-Identifier: GPL-3.0-or-later
//! What the proxy asks the rules engine, and what it gets back (`docs/spec/rules.md` R-9, R-14).
//!
//! The proxy depends on [`Policy`]; the store implements it; the host program wires
//! them. Neither crate depends on the other.

use std::fmt;

use crate::{Host, LocalCategory, WorkspaceName};

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

/// A rule set: a named bundle of entries switched on or off as one (`docs/spec/rules.md` §7).
///
/// Written `system`, `builtin:<slug>` or `user:<id>` on the wire and in the audit.
///
/// ```
/// use puddle_types::RuleSetId;
/// assert_eq!(RuleSetId::System.to_string(), "system");
/// assert_eq!(RuleSetId::BuiltIn("github").to_string(), "builtin:github");
/// assert_eq!(RuleSetId::User(3).to_string(), "user:3");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RuleSetId {
    /// "System managed": the hosts puddle allows because of the user's own setup choices
    /// (the browser editor server, direct SSH). Never switched by hand, only derived.
    System,
    /// A set that ships with puddle, by its stable slug.
    BuiltIn(&'static str),
    /// A set the user made, by its row id.
    User(i64),
}

impl fmt::Display for RuleSetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => f.write_str("system"),
            Self::BuiltIn(slug) => write!(f, "builtin:{slug}"),
            Self::User(id) => write!(f, "user:{id}"),
        }
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
    /// An open row for the same `(workspace, host, port)` already existed; it was updated.
    Repeat(PendingId),
    /// The workspace is over its rate limit or open-row cap; no row was written.
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
///
/// `Allow` and `Deny` are the user's own rules; `SetAllow` and `SetDeny` are entries of a rule
/// set (R-36 to R-43).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// A rule set's allow decided: none of the user's own rules matched (R-39). For local
    /// destinations it counts like a wildcard allow, whatever its pattern (R-42).
    SetAllow {
        /// The set.
        set: RuleSetId,
        /// The entry's rule row, for a set the user made; built-in and system entries have none.
        rule_id: Option<RuleId>,
        /// How it matched.
        pattern: PatternKind,
    },
    /// A rule set's deny decided (R-39). Only sets the user made can deny, so there is always
    /// a rule row: puddle ships no deny list.
    SetDeny {
        /// The set.
        set: RuleSetId,
        /// The entry's rule row.
        rule_id: RuleId,
        /// How it matched.
        pattern: PatternKind,
    },
    /// No rule decided.
    Pending(PendingOutcome),
    /// Refused whatever the rules say (R-14, F-8). Never approvable: no pending row is
    /// written and nothing in the inbox can change it; the reason names what would.
    Blocked {
        /// Why.
        reason: BlockReason,
    },
}

impl Decision {
    /// Whether the connection may go ahead.
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. } | Self::SetAllow { .. })
    }

    /// The rule set that decided, if a set's entry did.
    #[must_use]
    pub fn rule_set(&self) -> Option<RuleSetId> {
        match self {
            Self::SetAllow { set, .. } | Self::SetDeny { set, .. } => Some(*set),
            _ => None,
        }
    }
}

/// Why a request was [`Decision::Blocked`]. Each has its audit `reason` code ([`Self::code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BlockReason {
    /// SSH through the proxy isn't supported yet (F-8; audit reason `ssh_unsupported`).
    SshUnsupported,
    /// The destination is one of puddle's own endpoints (`puddle_endpoint`).
    PuddleEndpoint,
    /// Every address of the destination is local and the checker has no toggles to offer
    /// (`local_address`): the fail-closed fallback of a proxy without a toggle-aware address
    /// check. With toggles, the reason is [`Self::LocalToggle`].
    LocalAddress,
    /// The destination is in a local category whose toggle is off (R-14;
    /// `toggle:<category>`). When several categories are off, this names the first one in
    /// [`LocalCategory::ALL`] order; the block message lists them all.
    LocalToggle(LocalCategory),
}

impl BlockReason {
    /// The audit `reason` code (R-24).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::SshUnsupported => "ssh_unsupported",
            Self::PuddleEndpoint => "puddle_endpoint",
            Self::LocalAddress => "local_address",
            Self::LocalToggle(category) => category.audit_reason(),
        }
    }
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// What the guest said it is about to speak, when the proxy knows (F-8). A plain `CONNECT`
/// carries no hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProtocolHint {
    /// A plain-HTTP request in absolute form.
    Http,
    /// SSH, from the agent's `connect` stream (`ProxyCommand`).
    Ssh,
}

/// Whether suffix allow rules count for this request (R-14).
///
/// After resolving an allowed name to a local address whose toggle is on, the proxy asks again
/// with [`SuffixAllows::Ignore`] unless "wildcards reach local addresses" is on or an exact rule
/// for the address allows it ([`Policy::lookup`]); the request then needs an exact allow, and
/// goes pending for the exact name otherwise. Suffix *deny* rules
/// always count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixAllows {
    /// Suffix allow rules decide as usual.
    Count,
    /// Suffix allow rules are treated as no match.
    Ignore,
}

/// One connection attempt as the proxy sees it: `(workspace, host, port)`, plus an optional
/// protocol hint. Non-exhaustive: build it with [`EgressRequest::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EgressRequest {
    /// The workspace, from the route the connection arrived on.
    pub workspace: WorkspaceName,
    /// The normalised destination.
    pub host: Host,
    /// The destination port. Rules ignore it (R-2); pending rows and the audit record it.
    pub port: u16,
    /// What the guest said it will speak, if anything. Rules ignore it.
    pub protocol: Option<ProtocolHint>,
}

impl EgressRequest {
    /// A request with no protocol hint.
    #[must_use]
    pub fn new(workspace: WorkspaceName, host: Host, port: u16) -> Self {
        Self {
            workspace,
            host,
            port,
            protocol: None,
        }
    }

    /// The same request with a protocol hint.
    #[must_use]
    pub fn with_protocol(mut self, protocol: ProtocolHint) -> Self {
        self.protocol = Some(protocol);
        self
    }
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

    /// The rule that decides `request` now, without recording anything: `Some` allow or deny,
    /// or `None` when no rule matches. A miss never writes a pending row.
    ///
    /// The proxy asks it for every address an allowed name resolves to:
    /// - R-27: a deny for the address (an exact IP rule) excludes that address, whatever the
    ///   name's rules say, so a policy that holds IP rules must implement it;
    /// - R-14: after a wildcard allow, an exact allow of a resolved local address admits that
    ///   address.
    ///
    /// The default answers `None` (no IP rules): nothing is excluded or admitted this way.
    ///
    /// # Errors
    /// Returns [`PolicyError`] when the rules could not be read; the proxy then refuses the
    /// connection (fails closed).
    fn lookup(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Option<Decision>, PolicyError> {
        let _ = (request, suffix_allows);
        Ok(None)
    }
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
    fn block_reasons_have_their_audit_codes() {
        assert_eq!(BlockReason::SshUnsupported.to_string(), "ssh_unsupported");
        assert_eq!(BlockReason::PuddleEndpoint.code(), "puddle_endpoint");
        assert_eq!(BlockReason::LocalAddress.code(), "local_address");
        assert_eq!(
            BlockReason::LocalToggle(LocalCategory::LinkLocal).to_string(),
            "toggle:link_local"
        );
    }

    #[test]
    fn set_decisions_name_their_set_and_only_set_allows_let_through() {
        let allow = Decision::SetAllow {
            set: RuleSetId::System,
            rule_id: None,
            pattern: PatternKind::Exact,
        };
        let deny = Decision::SetDeny {
            set: RuleSetId::User(4),
            rule_id: RuleId(9),
            pattern: PatternKind::Suffix,
        };
        assert!(allow.is_allow());
        assert!(!deny.is_allow());
        assert_eq!(allow.rule_set(), Some(RuleSetId::System));
        assert_eq!(deny.rule_set(), Some(RuleSetId::User(4)));
        let own = Decision::Allow {
            rule_id: RuleId(1),
            pattern: PatternKind::Exact,
        };
        assert_eq!(own.rule_set(), None);
        assert!(RuleSetId::System < RuleSetId::BuiltIn("a"));
        assert!(RuleSetId::BuiltIn("z") < RuleSetId::User(0));
    }

    #[test]
    fn only_allow_lets_a_connection_through() {
        let allow = Decision::Allow {
            rule_id: RuleId(1),
            pattern: PatternKind::Exact,
        };
        assert!(allow.is_allow());
        assert!(
            !Decision::Blocked {
                reason: BlockReason::LocalAddress
            }
            .is_allow()
        );
        assert!(!Decision::Pending(PendingOutcome::Suppressed).is_allow());
    }

    #[test]
    fn requests_carry_an_optional_protocol_hint() {
        let workspace = WorkspaceName::new("box").unwrap();
        let host = Host::parse_normalised("example.com").unwrap();
        let plain = EgressRequest::new(workspace, host, 443);
        assert_eq!(plain.protocol, None);
        let ssh = plain.clone().with_protocol(ProtocolHint::Ssh);
        assert_eq!(ssh.protocol, Some(ProtocolHint::Ssh));
        assert_eq!(
            (ssh.port, ssh.host.to_string()),
            (443, "example.com".into())
        );
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
