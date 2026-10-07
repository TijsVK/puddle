// SPDX-License-Identifier: GPL-3.0-or-later
//! One connection as the proxy reports it for the audit (`docs/spec/rules.md` R-24).
//!
//! The proxy (W2) builds a [`ConnectionEvent`] and hands it to a [`ConnectionLog`]; the store
//! (W3) implements the log and turns the event into a `connection` record. Neither crate depends
//! on the other. Nothing secret is representable: there are no header, body or credential
//! fields, and an [`HttpRequestLine`] keeps only the path of a request target (R-25).

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{BlockReason, Decision, EgressRequest, Host, PendingId, RuleId, SandboxName};

/// How the proxy handled a connection (R-24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConnectionDecision {
    /// Let through.
    Allow,
    /// Refused by a deny rule.
    Deny,
    /// Refused while waiting for the user.
    Pending,
    /// Refused regardless of rules (toggle off, puddle's own endpoint, unsupported protocol,
    /// rules unavailable).
    Blocked,
}

/// Why the proxy decided as it did (R-24). Serialised as a string: `rule`, `no_rule`, a
/// [`BlockReason::code`] (`toggle:<category>`, `puddle_endpoint`, `ssh_unsupported`,
/// `local_address`), `policy_unavailable` or `suppressed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionReason {
    /// A rule decided.
    Rule,
    /// No rule matched.
    NoRule,
    /// Blocked whatever the rules say.
    Blocked(BlockReason),
    /// The rules could not be checked; the proxy failed closed.
    PolicyUnavailable,
    /// Summary of connection records over the per-sandbox limit (R-26).
    Suppressed,
}

impl fmt::Display for ConnectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule => f.write_str("rule"),
            Self::NoRule => f.write_str("no_rule"),
            Self::Blocked(reason) => f.write_str(reason.code()),
            Self::PolicyUnavailable => f.write_str("policy_unavailable"),
            Self::Suppressed => f.write_str("suppressed"),
        }
    }
}

/// The path of a request target, without scheme, authority (and userinfo), query string or
/// fragment (R-25).
///
/// ```
/// use puddle_types::request_path;
/// assert_eq!(request_path("/a/b?token=x#f"), "/a/b");
/// assert_eq!(request_path("http://user:pw@h.example/x?q"), "/x");
/// assert_eq!(request_path("http://h.example"), "/");
/// ```
#[must_use]
pub fn request_path(target: &str) -> &str {
    let end = target.find(['?', '#']).unwrap_or(target.len());
    let target = target.get(..end).unwrap_or_default();
    match target.find("://") {
        Some(scheme_end) => {
            let rest = target.get(scheme_end + 3..).unwrap_or_default();
            rest.find('/')
                .and_then(|slash| rest.get(slash..))
                .unwrap_or("/")
        }
        None => target,
    }
}

/// The method and path of a request the proxy saw in clear. Only [`request_path`] of the target
/// is kept, so a query string, fragment or userinfo never gets in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestLine {
    method: String,
    path: String,
}

impl HttpRequestLine {
    /// `target` as received (origin or absolute form); only its path is kept.
    #[must_use]
    pub fn new(method: impl Into<String>, target: &str) -> Self {
        Self {
            method: method.into(),
            path: request_path(target).to_owned(),
        }
    }

    /// `GET`, `POST`, ...
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The path, without query string or fragment.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One connection as the proxy (W2) reports it; the store stamps the time.
///
/// Non-exhaustive: build it with [`ConnectionEvent::new`] or [`ConnectionEvent::decided`] and
/// set the remaining fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectionEvent {
    /// The sandbox it came from (the route's, HO-3).
    pub sandbox: SandboxName,
    /// The requested host.
    pub host: Host,
    /// The requested port.
    pub port: u16,
    /// The address connected to, once connected.
    pub resolved_ip: Option<IpAddr>,
    /// The hop of the company-proxy route that carried the connection (`DIRECT` or
    /// `PROXY host:port`, T-165), once connected; `None` when no upstream route is configured.
    /// Never carries credentials.
    pub upstream: Option<String>,
    /// What happened.
    pub decision: ConnectionDecision,
    /// Why.
    pub reason: ConnectionReason,
    /// The deciding rule.
    pub rule_id: Option<RuleId>,
    /// The pending row, when pending.
    pub pending_id: Option<PendingId>,
    /// The credential binding used, by id only (D-11). Never the credential.
    pub binding_id: Option<String>,
    /// Whether a credential was injected.
    pub injected: bool,
    /// Method and path, when the proxy saw the request in clear.
    pub http: Option<HttpRequestLine>,
    /// Bytes from the guest.
    pub bytes_up: u64,
    /// Bytes to the guest.
    pub bytes_down: u64,
}

impl ConnectionEvent {
    /// An event for `request` with no rule, row, credential, request line or bytes yet.
    #[must_use]
    pub fn new(
        request: &EgressRequest,
        decision: ConnectionDecision,
        reason: ConnectionReason,
    ) -> Self {
        Self {
            sandbox: request.sandbox.clone(),
            host: request.host.clone(),
            port: request.port,
            resolved_ip: None,
            upstream: None,
            decision,
            reason,
            rule_id: None,
            pending_id: None,
            binding_id: None,
            injected: false,
            http: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }

    /// The event for the engine's `decision` on `request`: decision, reason, rule and pending
    /// row filled in.
    ///
    /// ```
    /// use puddle_types::*;
    /// let request = EgressRequest::new(
    ///     SandboxName::new("box").unwrap(),
    ///     Host::parse_normalised("example.com").unwrap(),
    ///     443,
    /// );
    /// let event = ConnectionEvent::decided(
    ///     &request,
    ///     &Decision::Pending(PendingOutcome::New(PendingId(7))),
    /// );
    /// assert_eq!(event.decision, ConnectionDecision::Pending);
    /// assert_eq!(event.reason, ConnectionReason::NoRule);
    /// assert_eq!(event.pending_id, Some(PendingId(7)));
    /// ```
    #[must_use]
    pub fn decided(request: &EgressRequest, decision: &Decision) -> Self {
        let (kind, reason, rule_id, pending_id) = match *decision {
            Decision::Allow { rule_id, .. } => (
                ConnectionDecision::Allow,
                ConnectionReason::Rule,
                Some(rule_id),
                None,
            ),
            Decision::Deny { rule_id, .. } => (
                ConnectionDecision::Deny,
                ConnectionReason::Rule,
                Some(rule_id),
                None,
            ),
            Decision::Pending(outcome) => (
                ConnectionDecision::Pending,
                ConnectionReason::NoRule,
                None,
                outcome.pending_id(),
            ),
            Decision::Blocked { reason } => (
                ConnectionDecision::Blocked,
                ConnectionReason::Blocked(reason),
                None,
                None,
            ),
        };
        let mut event = Self::new(request, kind, reason);
        event.rule_id = rule_id;
        event.pending_id = pending_id;
        event
    }
}

/// Where the proxy reports connections. Implemented by the store (`connection` audit records),
/// used by the proxy; the host program wires them.
///
/// Calls may write to the database, so async callers run them on a blocking thread. A log that
/// fails reports it itself (the proxy has no one to tell); the connection is not affected.
pub trait ConnectionLog: Send + Sync {
    /// Records `event`.
    fn record(&self, event: &ConnectionEvent);
}

/// A [`ConnectionLog`] that drops every event: for tests and tools without an audit.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullConnectionLog;

impl ConnectionLog for NullConnectionLog {
    fn record(&self, _event: &ConnectionEvent) {}
}

impl<T: ConnectionLog + ?Sized> ConnectionLog for std::sync::Arc<T> {
    fn record(&self, event: &ConnectionEvent) {
        (**self).record(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalCategory, PatternKind, PendingOutcome};

    const CANARY: &str = "CANARY-types-41c2";

    fn request() -> EgressRequest {
        EgressRequest::new(
            SandboxName::new("box").unwrap(),
            Host::parse_normalised("api.example.com").unwrap(),
            443,
        )
    }

    #[test]
    fn reasons_serialise_as_documented() {
        let reasons = [
            (ConnectionReason::Rule, "rule"),
            (ConnectionReason::NoRule, "no_rule"),
            (
                ConnectionReason::Blocked(BlockReason::LocalToggle(LocalCategory::Private)),
                "toggle:private",
            ),
            (
                ConnectionReason::Blocked(BlockReason::PuddleEndpoint),
                "puddle_endpoint",
            ),
            (
                ConnectionReason::Blocked(BlockReason::SshUnsupported),
                "ssh_unsupported",
            ),
            (
                ConnectionReason::Blocked(BlockReason::LocalAddress),
                "local_address",
            ),
            (ConnectionReason::PolicyUnavailable, "policy_unavailable"),
            (ConnectionReason::Suppressed, "suppressed"),
        ];
        for (reason, text) in reasons {
            assert_eq!(reason.to_string(), text);
        }
    }

    #[test]
    fn decisions_serialise_snake_case() {
        let text = serde_json::to_string(&[
            ConnectionDecision::Allow,
            ConnectionDecision::Deny,
            ConnectionDecision::Pending,
            ConnectionDecision::Blocked,
        ])
        .unwrap();
        assert_eq!(text, r#"["allow","deny","pending","blocked"]"#);
    }

    #[test]
    fn every_engine_decision_maps_to_its_record() {
        let r = request();
        let allow = ConnectionEvent::decided(
            &r,
            &Decision::Allow {
                rule_id: RuleId(3),
                pattern: PatternKind::Suffix,
            },
        );
        assert_eq!(
            (
                allow.decision,
                allow.reason,
                allow.rule_id,
                allow.pending_id
            ),
            (
                ConnectionDecision::Allow,
                ConnectionReason::Rule,
                Some(RuleId(3)),
                None
            )
        );
        let deny = ConnectionEvent::decided(
            &r,
            &Decision::Deny {
                rule_id: RuleId(4),
                pattern: PatternKind::Exact,
            },
        );
        assert_eq!(
            (deny.decision, deny.rule_id),
            (ConnectionDecision::Deny, Some(RuleId(4)))
        );
        let suppressed =
            ConnectionEvent::decided(&r, &Decision::Pending(PendingOutcome::Suppressed));
        assert_eq!(
            (suppressed.decision, suppressed.pending_id),
            (ConnectionDecision::Pending, None)
        );
        let blocked = ConnectionEvent::decided(
            &r,
            &Decision::Blocked {
                reason: BlockReason::PuddleEndpoint,
            },
        );
        assert_eq!(
            (blocked.decision, blocked.reason, blocked.rule_id),
            (
                ConnectionDecision::Blocked,
                ConnectionReason::Blocked(BlockReason::PuddleEndpoint),
                None
            )
        );
        assert_eq!(
            (
                blocked.sandbox.as_str(),
                blocked.host.to_string(),
                blocked.port
            ),
            ("box", "api.example.com".to_owned(), 443)
        );
        assert_eq!(
            (blocked.bytes_up, blocked.bytes_down, blocked.injected),
            (0, 0, false)
        );
    }

    #[test]
    fn a_request_line_never_keeps_query_fragment_or_userinfo() {
        let line = HttpRequestLine::new(
            "POST",
            &format!("http://u:{CANARY}@h.example/login?token={CANARY}#{CANARY}"),
        );
        assert_eq!((line.method(), line.path()), ("POST", "/login"));
        let line = HttpRequestLine::new("GET", &format!("/a/b?{CANARY}"));
        assert_eq!(line.path(), "/a/b");
        assert!(!format!("{line:?}").contains(CANARY));
    }

    #[test]
    fn request_path_strips_everything_but_the_path() {
        assert_eq!(request_path("/a/b?c=d"), "/a/b");
        assert_eq!(request_path("/a#frag"), "/a");
        assert_eq!(request_path("http://h.example/x/y?z"), "/x/y");
        assert_eq!(request_path("http://u:p@h.example"), "/");
        assert_eq!(request_path("*"), "*");
    }

    #[test]
    fn logs_take_events() {
        let log = std::sync::Arc::new(NullConnectionLog);
        log.record(&ConnectionEvent::new(
            &request(),
            ConnectionDecision::Allow,
            ConnectionReason::Rule,
        ));
    }
}
