// SPDX-License-Identifier: GPL-3.0-or-later
//! The API's wire types: every request and response body, as published in the `OpenAPI` spec
//! (ADR 0002 conventions, ADR 0004 additions).
//!
//! - `snake_case` fields; unit enums as `snake_case` strings; tagged enums use `type` (or
//!   `state` for consents), never untagged.
//! - Responses always carry every field; a missing value is `null`, never an absent key.
//! - Requests (`*Request`) refuse unknown fields; optional request fields may be left out.
//! - Timestamps are epoch milliseconds; row ids are integers; names are strings.
//! - No `#[serde(flatten)]`: storage documents (which keep unknown fields that way) are mapped
//!   to these types field by field.
//!
//! Domain types (`puddle-store`, `puddle-settings`) are mapped here rather than exposed, so a
//! storage change can't silently change the contract.

use std::time::Duration;

use puddle_settings as settings;
use puddle_store as store;
use puddle_types::{MemoryMib, SandboxName};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ApiError;

mod network_health;
mod workspaces;

pub use network_health::{
    DeadProxy, NetworkHealth, PacState, ProxyDetected, ProxyMode, ProxyReport, PullProxyReport,
    RootKind, RootsReport, RouteDecision, RouteSource, SignInAttempt, SignInReport, SignInResult,
    SkippedRoot, SyncedRoot,
};

pub use workspaces::{
    AttachMode, AttachRequest, AttachResponse, DeleteCheck, DeleteWorkspaceRequest, FindingList,
    NewWorkspaceRequest, RepoFindings, Workspace, WorkspaceList, WorkspaceOperation,
};

// ---------------------------------------------------------------------------------------------
// Service

/// The API's identity, for a client to check it reached puddle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Health {
    /// puddle's version.
    pub version: String,
    /// The API contract's version ([`crate::API_VERSION`]).
    pub api_version: String,
}

// ---------------------------------------------------------------------------------------------
// Rules and pending requests (docs/spec/rules.md)

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// Let the connection through.
    Allow,
    /// Refuse it.
    Deny,
}

impl From<store::Effect> for Effect {
    fn from(effect: store::Effect) -> Self {
        match effect {
            store::Effect::Allow => Self::Allow,
            store::Effect::Deny => Self::Deny,
        }
    }
}

impl From<Effect> for store::Effect {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Allow => Self::Allow,
            Effect::Deny => Self::Deny,
        }
    }
}

/// Who made a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// The `puddle` command line.
    Cli,
    /// The desktop UI.
    Ui,
    /// The HTTP API.
    Api,
    /// puddle itself (expiry, sandbox deletion).
    System,
}

impl Actor {
    pub(crate) fn from_store(actor: store::Actor) -> Result<Self, ApiError> {
        Ok(match actor {
            store::Actor::Cli => Self::Cli,
            store::Actor::Ui => Self::Ui,
            store::Actor::Api => Self::Api,
            store::Actor::System => Self::System,
            other => {
                return Err(ApiError::internal(&format_args!(
                    "unmapped actor {other:?}"
                )));
            }
        })
    }
}

/// Where a pending request is in its life (R-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// Waiting for the user.
    Requested,
    /// Approved.
    Allowed,
    /// Denied.
    Denied,
    /// Closed without a decision.
    Expired,
}

impl From<store::PendingState> for PendingState {
    fn from(state: store::PendingState) -> Self {
        match state {
            store::PendingState::Requested => Self::Requested,
            store::PendingState::Allowed => Self::Allowed,
            store::PendingState::Denied => Self::Denied,
            store::PendingState::Expired => Self::Expired,
        }
    }
}

/// A connection that matched no rule and waits for the user (R-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingRequest {
    /// Row id, never reused.
    pub id: i64,
    /// The requesting sandbox.
    pub sandbox: SandboxName,
    /// The requested host: a normalised name (punycode, lower case) or an IP literal. Untrusted
    /// (it comes from the guest): escape it when rendering.
    pub host: String,
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
    /// Epoch ms it was decided or expired.
    #[schema(required = true)]
    pub decided_at: Option<u64>,
    /// Who closed it.
    #[schema(required = true)]
    pub decided_by: Option<Actor>,
    /// The rule that decided it.
    #[schema(required = true)]
    pub rule_id: Option<i64>,
    /// For an open request to a local destination (host loopback, private network, link-local,
    /// metadata, special) whose toggle is off in this workspace: the toggle that blocks approval.
    /// An allow rule would not let the connection through until the toggle is on. `null`
    /// otherwise, and always for a closed request.
    #[schema(required = true)]
    pub blocked_by: Option<puddle_types::LocalCategory>,
}

impl PendingRequest {
    pub(crate) fn from_store(row: store::PendingRow) -> Result<Self, ApiError> {
        let store::PendingRow {
            id,
            sandbox,
            host,
            port,
            first_seen,
            last_seen,
            attempts,
            state,
            decided_at,
            decided_by,
            rule_id,
        } = row;
        Ok(Self {
            id: id.0,
            sandbox,
            host: host.to_string(),
            port,
            first_seen,
            last_seen,
            attempts,
            state: state.into(),
            decided_at,
            decided_by: decided_by.map(Actor::from_store).transpose()?,
            rule_id: rule_id.map(|r| r.0),
            blocked_by: None,
        })
    }
}

/// Pending requests, most recent first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PendingList {
    /// The requests.
    pub requests: Vec<PendingRequest>,
}

/// Open requests that share a registrable domain (R-18). Grouping is for display only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct InboxGroup {
    /// `example.co.uk`, or the IP literal.
    pub registrable_domain: String,
    /// Open requests, most recent first.
    pub requests: Vec<PendingRequest>,
}

/// The inbox: open requests grouped by registrable domain, most recent group first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Inbox {
    /// The groups.
    pub groups: Vec<InboxGroup>,
}

/// Whether a sandbox's new pending requests are being suppressed (R-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Suppression {
    /// The sandbox.
    pub sandbox: SandboxName,
    /// Whether requests are being suppressed now.
    pub active: bool,
    /// Requests suppressed in the current (or last) episode.
    pub count: u64,
}

/// Which sandboxes a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleScope {
    /// Every sandbox.
    Global,
    /// One sandbox.
    Sandbox {
        /// The sandbox.
        sandbox: SandboxName,
    },
}

impl RuleScope {
    pub(crate) fn from_store(scope: store::Scope) -> Result<Self, ApiError> {
        Ok(match scope {
            store::Scope::Global => Self::Global,
            store::Scope::Sandbox(sandbox) => Self::Sandbox { sandbox },
            other => {
                return Err(ApiError::internal(&format_args!(
                    "unmapped scope {other:?}"
                )));
            }
        })
    }
}

impl From<RuleScope> for store::Scope {
    fn from(scope: RuleScope) -> Self {
        match scope {
            RuleScope::Global => Self::Global,
            RuleScope::Sandbox { sandbox } => Self::Sandbox(sandbox),
        }
    }
}

/// How a rule's pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    /// The identical host.
    Exact,
    /// The host and every name under it (`.example.com`).
    Suffix,
}

/// A rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Rule {
    /// Row id, never reused.
    pub id: i64,
    /// Global or one sandbox.
    pub scope: RuleScope,
    /// `example.com` (exact) or `.example.com` (suffix).
    pub pattern: String,
    /// Exact or suffix.
    pub pattern_kind: PatternKind,
    /// Allow or deny.
    pub effect: Effect,
    /// Epoch ms from which the rule no longer matches; `null` is permanent.
    #[schema(required = true)]
    pub expires_at: Option<u64>,
    /// Epoch ms.
    pub created_at: u64,
    /// Who created it.
    pub created_by: Actor,
    /// The pending request it was decided from.
    #[schema(required = true)]
    pub source_pending_id: Option<i64>,
}

impl Rule {
    pub(crate) fn from_store(rule: store::Rule) -> Result<Self, ApiError> {
        let store::Rule {
            id,
            scope,
            pattern,
            effect,
            expires_at,
            created_at,
            created_by,
            source_pending_id,
        } = rule;
        Ok(Self {
            id: id.0,
            scope: RuleScope::from_store(scope)?,
            pattern_kind: match pattern.kind() {
                puddle_types::PatternKind::Exact => PatternKind::Exact,
                puddle_types::PatternKind::Suffix => PatternKind::Suffix,
            },
            pattern: pattern.to_string(),
            effect: effect.into(),
            expires_at,
            created_at,
            created_by: Actor::from_store(created_by)?,
            source_pending_id: source_pending_id.map(|p| p.0),
        })
    }
}

/// Every rule, expired ones the sweeper hasn't removed yet included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RuleList {
    /// The rules.
    pub rules: Vec<Rule>,
}

/// Whether an approval or denial covers only the request's sandbox or every sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeChoice {
    /// Only the request's sandbox (the default).
    #[default]
    Sandbox,
    /// Every sandbox.
    Global,
}

/// The choices of an approve or deny (R-15). Each one left out stays at its narrowest default:
/// this sandbox, the exact host, permanent.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionRequest {
    /// This sandbox (default) or every sandbox.
    #[serde(default)]
    pub scope: ScopeChoice,
    /// A suffix of the host (`example.com`, `.example.com` or `*.example.com`) to cover every
    /// name under it; left out or `null` means the exact host. A public suffix is refused.
    #[serde(default)]
    pub suffix: Option<String>,
    /// Seconds until the rule expires; left out or `null` is permanent.
    #[serde(default)]
    #[schema(minimum = 1)]
    pub expires_in_secs: Option<u64>,
}

impl DecisionRequest {
    pub(crate) fn into_resolution(self, effect: Effect) -> Result<store::Resolution, ApiError> {
        let Self {
            scope,
            suffix,
            expires_in_secs,
        } = self;
        let mut resolution = match effect {
            Effect::Allow => store::Resolution::allow(),
            Effect::Deny => store::Resolution::deny(),
        };
        resolution.scope = match scope {
            ScopeChoice::Sandbox => store::ScopeChoice::Sandbox,
            ScopeChoice::Global => store::ScopeChoice::Global,
        };
        resolution.pattern = match suffix {
            None => store::PatternChoice::Exact,
            Some(text) => {
                let (_, base) = normalise_pattern("suffix", &text)?;
                store::PatternChoice::Suffix(base)
            }
        };
        resolution.expires_in = expires_in_secs.map(Duration::from_secs);
        Ok(resolution)
    }
}

/// What an approve or deny did (R-16, R-17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DecisionOutcome {
    /// The request, now decided.
    pub request: PendingRequest,
    /// The rule created.
    pub rule: Rule,
    /// Other open requests the new rule closed the same way.
    pub also_closed: Vec<i64>,
}

impl DecisionOutcome {
    pub(crate) fn from_store(decided: store::Decided) -> Result<Self, ApiError> {
        let store::Decided {
            row,
            rule,
            also_closed,
        } = decided;
        Ok(Self {
            request: PendingRequest::from_store(row)?,
            rule: Rule::from_store(rule)?,
            also_closed: also_closed.into_iter().map(|p| p.0).collect(),
        })
    }
}

/// A rule to create directly (not from a pending request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewRuleRequest {
    /// Global or one sandbox.
    pub scope: RuleScope,
    /// `example.com` (exact), or `.example.com` / `*.example.com` (suffix; a public suffix is
    /// refused).
    pub pattern: String,
    /// Allow or deny.
    pub effect: Effect,
    /// Epoch ms from which the rule no longer matches; left out or `null` is permanent.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

impl NewRuleRequest {
    pub(crate) fn into_new_rule(self) -> Result<store::NewRule, ApiError> {
        let Self {
            scope,
            pattern,
            effect,
            expires_at,
        } = self;
        let (suffix, base) = normalise_pattern("pattern", &pattern)?;
        let text = if suffix { format!(".{base}") } else { base };
        Ok(store::NewRule {
            scope: scope.into(),
            pattern: store::Pattern::parse(&text)
                .map_err(|err| ApiError::invalid(format!("pattern: {err}")))?,
            effect: effect.into(),
            expires_at,
            created_by: store::Actor::Api,
        })
    }
}

/// Normalises what a person typed as a rule pattern or suffix, with the proxy's own normaliser, so
/// a rule matches exactly what the proxy will look up. Returns whether it was written as a suffix
/// (`.example.com` or `*.example.com`) and the normalised host: lower case, Unicode to punycode,
/// one trailing dot dropped, IPv6 in its canonical form. Surrounding whitespace is ignored.
///
/// URLs, ports and anything else that is not a host are refused with a message that starts with
/// `field`, so a client can show it next to that field.
pub(crate) fn normalise_pattern(field: &str, input: &str) -> Result<(bool, String), ApiError> {
    let text = input.trim();
    let (suffix, rest) = match text.strip_prefix("*.").or_else(|| text.strip_prefix('.')) {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let refuse = |reason: &str| Err(ApiError::invalid(format!("{field}: {reason}")));
    if rest.contains('/') || rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return refuse("give a host name, not a URL");
    }
    if let Some((host, port)) = rest.rsplit_once(':')
        && !host.contains(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return refuse("a rule covers every port, leave the port out");
    }
    let target = puddle_netpolicy::normalise_host(rest)
        .map_err(|err| ApiError::invalid(format!("{field}: {err}")))?;
    Ok((suffix, target.host().to_string()))
}

/// A rule's new expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleExpiryRequest {
    /// Epoch ms in the future, or `null` to make the rule permanent.
    #[schema(required = true)]
    pub expires_at: Option<u64>,
}

// ---------------------------------------------------------------------------------------------
// Audit (docs/spec/rules.md §5)

/// A rule as an audit record shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditRule {
    /// Row id.
    pub id: i64,
    /// `global` or `sandbox`.
    pub scope: String,
    /// The sandbox, for a sandbox rule.
    #[schema(required = true)]
    pub sandbox_id: Option<String>,
    /// `exact` or `suffix`.
    pub pattern_kind: String,
    /// `example.com` or `.example.com`.
    pub pattern: String,
    /// `allow` or `deny`.
    pub effect: String,
    /// Epoch ms, or `null` for permanent.
    #[schema(required = true)]
    pub expires_at: Option<u64>,
    /// Epoch ms.
    pub created_at: u64,
    /// `cli`, `ui` or `api`.
    pub created_by: String,
    /// The pending request it came from.
    #[schema(required = true)]
    pub source_pending_id: Option<i64>,
}

impl From<store::RuleWire> for AuditRule {
    fn from(rule: store::RuleWire) -> Self {
        let store::RuleWire {
            id,
            scope,
            sandbox_id,
            pattern_kind,
            pattern,
            effect,
            expires_at,
            created_at,
            created_by,
            source_pending_id,
        } = rule;
        Self {
            id,
            scope,
            sandbox_id,
            pattern_kind,
            pattern,
            effect,
            expires_at,
            created_at,
            created_by,
            source_pending_id,
        }
    }
}

/// A pending request as an audit record shows it. `host` comes from the guest: escape it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditPending {
    /// Row id.
    pub id: i64,
    /// The sandbox.
    pub sandbox_id: String,
    /// The requested host.
    pub host: String,
    /// The requested port.
    pub port: u16,
    /// Epoch ms.
    pub first_seen: u64,
    /// Epoch ms.
    pub last_seen: u64,
    /// Requests the row stands for.
    pub attempts: u64,
    /// `requested`, `allowed`, `denied` or `expired`.
    pub state: String,
    /// Epoch ms.
    #[schema(required = true)]
    pub decided_at: Option<u64>,
    /// `cli`, `ui`, `api` or `system`.
    #[schema(required = true)]
    pub decided_by: Option<String>,
    /// The deciding rule.
    #[schema(required = true)]
    pub rule_id: Option<i64>,
}

impl From<store::PendingWire> for AuditPending {
    fn from(row: store::PendingWire) -> Self {
        let store::PendingWire {
            id,
            sandbox_id,
            host,
            port,
            first_seen,
            last_seen,
            attempts,
            state,
            decided_at,
            decided_by,
            rule_id,
        } = row;
        Self {
            id,
            sandbox_id,
            host,
            port,
            first_seen,
            last_seen,
            attempts,
            state,
            decided_at,
            decided_by,
            rule_id,
        }
    }
}

/// How the proxy handled a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDecision {
    /// Let through.
    Allow,
    /// Refused by a deny rule.
    Deny,
    /// Refused while waiting for the user.
    Pending,
    /// Refused regardless of rules.
    Blocked,
}

impl From<puddle_types::ConnectionDecision> for ConnectionDecision {
    fn from(decision: puddle_types::ConnectionDecision) -> Self {
        match decision {
            puddle_types::ConnectionDecision::Allow => Self::Allow,
            puddle_types::ConnectionDecision::Deny => Self::Deny,
            puddle_types::ConnectionDecision::Pending => Self::Pending,
            // A decision this API doesn't know yet is a refusal.
            _ => Self::Blocked,
        }
    }
}

/// Whose connection an audit record describes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOrigin {
    /// A sandbox's connection.
    #[default]
    Sandbox,
    /// puddle's own connection on the host, such as an image pull; it has no sandbox.
    Puddle,
}

impl From<puddle_types::ConnectionOrigin> for ConnectionOrigin {
    fn from(origin: puddle_types::ConnectionOrigin) -> Self {
        match origin {
            puddle_types::ConnectionOrigin::Puddle => Self::Puddle,
            // An origin this API doesn't know yet is read as a sandbox's.
            _ => Self::Sandbox,
        }
    }
}

impl From<ConnectionOrigin> for puddle_types::ConnectionOrigin {
    fn from(origin: ConnectionOrigin) -> Self {
        match origin {
            ConnectionOrigin::Sandbox => Self::Sandbox,
            ConnectionOrigin::Puddle => Self::Puddle,
        }
    }
}

/// Why a pending request expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingExpiryReason {
    /// No repeat for the stale period.
    Stale,
    /// Its sandbox was deleted.
    SandboxDeleted,
}

/// Why a rule was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleDeleteReason {
    /// A user deleted it.
    User,
    /// Its sandbox was deleted.
    SandboxDeleted,
}

/// One audit record (rules spec R-24): a tagged union on `type`. `host`, `path` and the like come
/// from the guest, so escape them when rendering. Records written by an older puddle lack the
/// fields added since, which read as `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditRecord {
    /// A connection the proxy handled. `host`, `port` and `decision` are `null` on a
    /// `suppressed` summary, which carries `count`.
    Connection {
        /// Epoch ms.
        ts: u64,
        /// The sandbox; `null` for puddle's own connections (`origin` is `puddle`).
        #[schema(required = true)]
        sandbox_id: Option<String>,
        /// Whose connection it is. Records written before it existed read as `sandbox`.
        #[serde(default)]
        #[schema(required = true)]
        origin: ConnectionOrigin,
        /// The requested host.
        #[schema(required = true)]
        host: Option<String>,
        /// The requested port.
        #[schema(required = true)]
        port: Option<u16>,
        /// The address connected to.
        #[schema(required = true)]
        resolved_ip: Option<String>,
        /// The company-proxy hop that carried it: `DIRECT` or `PROXY host:port`; `null` when no
        /// upstream route is configured.
        #[schema(required = true)]
        upstream: Option<String>,
        /// What happened.
        #[schema(required = true)]
        decision: Option<ConnectionDecision>,
        /// Why: `rule`, `no_rule`, or a block reason.
        reason: String,
        /// The deciding rule.
        #[schema(required = true)]
        rule_id: Option<i64>,
        /// The pending request.
        #[schema(required = true)]
        pending_id: Option<i64>,
        /// The credential binding, by id.
        #[schema(required = true)]
        binding_id: Option<String>,
        /// Whether a credential was injected.
        injected: bool,
        /// HTTP method, where the proxy saw the request in clear.
        #[schema(required = true)]
        method: Option<String>,
        /// HTTP path without query string, where `method` is set.
        #[schema(required = true)]
        path: Option<String>,
        /// Whether `path` was cut to fit.
        path_truncated: bool,
        /// Bytes from the guest.
        bytes_up: u64,
        /// Bytes to the guest.
        bytes_down: u64,
        /// Records summarised, on a `suppressed` summary.
        #[schema(required = true)]
        count: Option<u64>,
    },
    /// A new pending request.
    PendingCreated {
        /// Epoch ms.
        ts: u64,
        /// The request.
        pending: AuditPending,
    },
    /// A pending request approved or denied.
    PendingDecided {
        /// Epoch ms.
        ts: u64,
        /// The request as decided.
        pending: AuditPending,
    },
    /// A pending request expired.
    PendingExpired {
        /// Epoch ms.
        ts: u64,
        /// The request as expired.
        pending: AuditPending,
        /// Why.
        reason: PendingExpiryReason,
    },
    /// Requests over a sandbox's limit, not written as rows.
    PendingSuppressed {
        /// Epoch ms.
        ts: u64,
        /// The sandbox.
        sandbox_id: String,
        /// Requests suppressed since the previous record.
        count: u64,
    },
    /// A rule created.
    RuleCreated {
        /// Epoch ms.
        ts: u64,
        /// The rule.
        rule: AuditRule,
    },
    /// A rule changed.
    RuleUpdated {
        /// Epoch ms.
        ts: u64,
        /// The rule before.
        before: AuditRule,
        /// The rule after.
        rule: AuditRule,
        /// Who changed it.
        actor: String,
    },
    /// A rule deleted.
    RuleDeleted {
        /// Epoch ms.
        ts: u64,
        /// The rule as it was.
        rule: AuditRule,
        /// Why.
        reason: RuleDeleteReason,
        /// Who deleted it.
        actor: String,
    },
    /// A rule removed after it expired.
    RuleExpired {
        /// Epoch ms.
        ts: u64,
        /// The rule.
        rule: AuditRule,
    },
    /// The oldest records were deleted to keep the audit under its size cap.
    AuditTrimmed {
        /// Epoch ms.
        ts: u64,
        /// Records deleted.
        deleted_records: u64,
        /// `ts` of the oldest record left; `null` if none.
        #[schema(required = true)]
        oldest_ts_kept: Option<u64>,
    },
}

impl From<store::ConnectionRecord> for AuditRecord {
    fn from(record: store::ConnectionRecord) -> Self {
        let store::ConnectionRecord {
            ts,
            sandbox_id,
            origin,
            host,
            port,
            resolved_ip,
            upstream,
            decision,
            reason,
            rule_id,
            pending_id,
            binding_id,
            injected,
            method,
            path,
            path_truncated,
            bytes_up,
            bytes_down,
            count,
        } = record;
        Self::Connection {
            ts,
            sandbox_id,
            host,
            port,
            resolved_ip,
            upstream,
            origin: origin.into(),
            decision: decision.map(Into::into),
            reason,
            rule_id,
            pending_id,
            binding_id,
            injected,
            method,
            path,
            path_truncated,
            bytes_up,
            bytes_down,
            count,
        }
    }
}

impl From<store::AuditRecord> for AuditRecord {
    fn from(record: store::AuditRecord) -> Self {
        use store::AuditRecord as R;
        match record {
            R::Connection(record) => record.into(),
            R::PendingCreated { ts, pending } => Self::PendingCreated {
                ts,
                pending: pending.into(),
            },
            R::PendingDecided { ts, pending } => Self::PendingDecided {
                ts,
                pending: pending.into(),
            },
            R::PendingExpired {
                ts,
                pending,
                reason,
            } => Self::PendingExpired {
                ts,
                pending: pending.into(),
                reason: match reason {
                    store::PendingExpiryReason::Stale => PendingExpiryReason::Stale,
                    store::PendingExpiryReason::SandboxDeleted => {
                        PendingExpiryReason::SandboxDeleted
                    }
                },
            },
            R::PendingSuppressed {
                ts,
                sandbox_id,
                count,
            } => Self::PendingSuppressed {
                ts,
                sandbox_id,
                count,
            },
            R::RuleCreated { ts, rule } => Self::RuleCreated {
                ts,
                rule: rule.into(),
            },
            R::RuleUpdated {
                ts,
                before,
                rule,
                actor,
            } => Self::RuleUpdated {
                ts,
                before: before.into(),
                rule: rule.into(),
                actor,
            },
            R::RuleDeleted {
                ts,
                rule,
                reason,
                actor,
            } => Self::RuleDeleted {
                ts,
                rule: rule.into(),
                reason: match reason {
                    store::RuleDeleteReason::User => RuleDeleteReason::User,
                    store::RuleDeleteReason::SandboxDeleted => RuleDeleteReason::SandboxDeleted,
                },
                actor,
            },
            R::RuleExpired { ts, rule } => Self::RuleExpired {
                ts,
                rule: rule.into(),
            },
            R::AuditTrimmed {
                ts,
                deleted_records,
                oldest_ts_kept,
            } => Self::AuditTrimmed {
                ts,
                deleted_records,
                oldest_ts_kept,
            },
        }
    }
}

/// One audit record with its position in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditEntry {
    /// Position in the log: pass the newest one as `after` to read on, or the oldest as `before`
    /// to read back.
    pub id: i64,
    /// The record.
    pub record: AuditRecord,
}

/// A page of the audit log: newest first for a read without `after`, oldest first with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditPage {
    /// The records.
    pub entries: Vec<AuditEntry>,
    /// The `after` for reading what comes after this page, and the one to tail the log with: the
    /// newest id here, or the request's `after` (0 without one) if the page is empty.
    pub next_after: i64,
    /// The `before` for the next older page: the oldest id here; `null` when this page is the
    /// oldest matching one (it holds fewer records than `limit`) or the read ran oldest first.
    #[schema(required = true)]
    pub next_before: Option<i64>,
}

/// What an audit record says happened, for the `outcome` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// A connection let through, or a pending request approved.
    Allow,
    /// A connection refused by a deny rule, or a pending request denied.
    Deny,
    /// A connection refused while waiting for the user, or a pending request opened.
    Pending,
    /// A connection refused regardless of rules.
    Blocked,
    /// A pending request that expired.
    Expired,
}

impl From<AuditOutcome> for store::AuditOutcome {
    fn from(outcome: AuditOutcome) -> Self {
        match outcome {
            AuditOutcome::Allow => Self::Allow,
            AuditOutcome::Deny => Self::Deny,
            AuditOutcome::Pending => Self::Pending,
            AuditOutcome::Blocked => Self::Blocked,
            AuditOutcome::Expired => Self::Expired,
        }
    }
}

/// The record types, for the `type` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditType {
    /// A connection.
    Connection,
    /// A new pending request.
    PendingCreated,
    /// A pending request decided.
    PendingDecided,
    /// A pending request expired.
    PendingExpired,
    /// Requests suppressed over a sandbox's limit.
    PendingSuppressed,
    /// A rule created.
    RuleCreated,
    /// A rule changed.
    RuleUpdated,
    /// A rule deleted.
    RuleDeleted,
    /// A rule expired.
    RuleExpired,
    /// The audit trimmed to its size cap.
    AuditTrimmed,
}

impl AuditType {
    /// The record `type` tag.
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::PendingCreated => "pending_created",
            Self::PendingDecided => "pending_decided",
            Self::PendingExpired => "pending_expired",
            Self::PendingSuppressed => "pending_suppressed",
            Self::RuleCreated => "rule_created",
            Self::RuleUpdated => "rule_updated",
            Self::RuleDeleted => "rule_deleted",
            Self::RuleExpired => "rule_expired",
            Self::AuditTrimmed => "audit_trimmed",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Settings (puddle-settings)

/// The settings every sandbox has. On a global document they are the defaults for every
/// sandbox; on a sandbox they override those. `null` means "not set here": the next level (the
/// global value, then puddle's default) applies.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SettingsLayer {
    /// Guest memory in MiB (256 to 1 048 576); applies at the next start.
    #[serde(default)]
    #[schema(required = true, minimum = 256, maximum = 1_048_576)]
    pub memory: Option<u32>,
    /// Which local destination categories may be approved (all off by default).
    #[serde(default)]
    #[schema(required = true)]
    pub local_toggles: LocalToggles,
    /// Whether a suffix rule may reach local addresses.
    #[serde(default)]
    #[schema(required = true)]
    pub wildcards_reach_local: Option<bool>,
    /// Seconds a browser VS Code session survives a disconnect (30 to 86 400).
    #[serde(default)]
    #[schema(required = true, minimum = 30, maximum = 86_400)]
    pub reconnection_grace: Option<u32>,
    /// Whether the browser window's zoom hotkeys work.
    #[serde(default)]
    #[schema(required = true)]
    pub zoom_hotkeys: Option<bool>,
    /// What a programmatic clipboard read does.
    #[serde(default)]
    #[schema(required = true)]
    pub clipboard_read: Option<ClipboardRead>,
    /// Whether puddle opens an SSH way into the workspace for the user's own tools (desktop
    /// VS Code, a terminal `ssh`). Off by default; while off there is no SSH endpoint and no ssh
    /// config entry. Turning it on marks the workspace trusted.
    #[serde(default)]
    #[schema(required = true)]
    pub direct_ssh: Option<bool>,
}

impl From<&settings::SandboxLayer> for SettingsLayer {
    fn from(layer: &settings::SandboxLayer) -> Self {
        Self {
            memory: layer.memory.map(MemoryMib::get),
            local_toggles: (&layer.local_toggles).into(),
            wildcards_reach_local: layer.wildcards_reach_local,
            reconnection_grace: layer
                .reconnection_grace
                .map(settings::ReconnectionGrace::secs),
            zoom_hotkeys: layer.zoom_hotkeys,
            clipboard_read: layer.clipboard_read.map(Into::into),
            direct_ssh: layer.direct_ssh,
        }
    }
}

impl SettingsLayer {
    /// Writes these values into `layer`, leaving its unknown fields alone.
    pub(crate) fn apply_to(self, layer: &mut settings::SandboxLayer) -> Result<(), ApiError> {
        let invalid = |err: puddle_types::ValidationError| ApiError::invalid(err.to_string());
        let Self {
            memory,
            local_toggles,
            wildcards_reach_local,
            reconnection_grace,
            zoom_hotkeys,
            clipboard_read,
            direct_ssh,
        } = self;
        layer.memory = memory.map(MemoryMib::new).transpose().map_err(invalid)?;
        local_toggles.apply_to(&mut layer.local_toggles);
        layer.wildcards_reach_local = wildcards_reach_local;
        layer.reconnection_grace = reconnection_grace
            .map(settings::ReconnectionGrace::new)
            .transpose()
            .map_err(invalid)?;
        layer.zoom_hotkeys = zoom_hotkeys;
        layer.clipboard_read = clipboard_read.map(Into::into);
        layer.direct_ssh = direct_ssh;
        Ok(())
    }
}

/// Local destination categories a sandbox may approve. `null` inherits.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalToggles {
    /// The host's loopback addresses.
    #[serde(default)]
    #[schema(required = true)]
    pub loopback: Option<bool>,
    /// Private networks (RFC 1918, ULA).
    #[serde(default)]
    #[schema(required = true)]
    pub private: Option<bool>,
    /// Link-local addresses.
    #[serde(default)]
    #[schema(required = true)]
    pub link_local: Option<bool>,
    /// Cloud metadata endpoints.
    #[serde(default)]
    #[schema(required = true)]
    pub metadata: Option<bool>,
    /// Other special-purpose ranges.
    #[serde(default)]
    #[schema(required = true)]
    pub special: Option<bool>,
}

impl From<&settings::LocalToggles> for LocalToggles {
    fn from(t: &settings::LocalToggles) -> Self {
        Self {
            loopback: t.loopback,
            private: t.private,
            link_local: t.link_local,
            metadata: t.metadata,
            special: t.special,
        }
    }
}

impl LocalToggles {
    fn apply_to(self, toggles: &mut settings::LocalToggles) {
        let Self {
            loopback,
            private,
            link_local,
            metadata,
            special,
        } = self;
        toggles.loopback = loopback;
        toggles.private = private;
        toggles.link_local = link_local;
        toggles.metadata = metadata;
        toggles.special = special;
    }
}

/// What a programmatic clipboard read in the browser window does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardRead {
    /// Ask each time.
    Ask,
    /// Always allow.
    Allow,
    /// Always refuse.
    Deny,
}

impl From<settings::ClipboardRead> for ClipboardRead {
    fn from(c: settings::ClipboardRead) -> Self {
        match c {
            settings::ClipboardRead::Ask => Self::Ask,
            settings::ClipboardRead::Allow => Self::Allow,
            settings::ClipboardRead::Deny => Self::Deny,
        }
    }
}

impl From<ClipboardRead> for settings::ClipboardRead {
    fn from(c: ClipboardRead) -> Self {
        match c {
            ClipboardRead::Ask => Self::Ask,
            ClipboardRead::Allow => Self::Allow,
            ClipboardRead::Deny => Self::Deny,
        }
    }
}

/// Options for the VS Code server in the guest. `null` means puddle's default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct VsCodeServer {
    /// Which server browser VS Code runs (default `code_server`). `microsoft` is refused
    /// until the user agreed to Microsoft's terms (`PUT /api/consents/vscode_server`).
    #[serde(default)]
    #[schema(required = true)]
    pub server: Option<ServerChoice>,
    /// Whether the server may send Microsoft telemetry (default off).
    #[serde(default)]
    #[schema(required = true)]
    pub telemetry: Option<bool>,
    /// Whether puddle updates the server (default on).
    #[serde(default)]
    #[schema(required = true)]
    pub auto_update: Option<bool>,
}

/// Which VS Code server browser VS Code runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServerChoice {
    /// The bundled code-server.
    CodeServer,
    /// Microsoft's VS Code server, downloaded after the user's consent.
    Microsoft,
}

impl From<settings::ServerChoice> for ServerChoice {
    fn from(c: settings::ServerChoice) -> Self {
        match c {
            settings::ServerChoice::CodeServer => Self::CodeServer,
            settings::ServerChoice::Microsoft => Self::Microsoft,
        }
    }
}

impl From<ServerChoice> for settings::ServerChoice {
    fn from(c: ServerChoice) -> Self {
        match c {
            ServerChoice::CodeServer => Self::CodeServer,
            ServerChoice::Microsoft => Self::Microsoft,
        }
    }
}

/// The colour theme of puddle's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// Follow the operating system.
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl From<settings::ThemeChoice> for ThemeChoice {
    fn from(c: settings::ThemeChoice) -> Self {
        match c {
            settings::ThemeChoice::System => Self::System,
            settings::ThemeChoice::Light => Self::Light,
            settings::ThemeChoice::Dark => Self::Dark,
        }
    }
}

impl From<ThemeChoice> for settings::ThemeChoice {
    fn from(c: ThemeChoice) -> Self {
        match c {
            ThemeChoice::System => Self::System,
            ThemeChoice::Light => Self::Light,
            ThemeChoice::Dark => Self::Dark,
        }
    }
}

/// What closing the window does while a sandbox runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CloseBehaviour {
    /// Keep running in the tray.
    Tray,
    /// Quit puddle.
    Quit,
}

impl From<settings::CloseBehaviour> for CloseBehaviour {
    fn from(c: settings::CloseBehaviour) -> Self {
        match c {
            settings::CloseBehaviour::Tray => Self::Tray,
            settings::CloseBehaviour::Quit => Self::Quit,
        }
    }
}

impl From<CloseBehaviour> for settings::CloseBehaviour {
    fn from(c: CloseBehaviour) -> Self {
        match c {
            CloseBehaviour::Tray => Self::Tray,
            CloseBehaviour::Quit => Self::Quit,
        }
    }
}

/// Preferences for puddle's own window. `null` means puddle's default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UiPrefs {
    /// Light, dark or follow the system (default `system`).
    #[serde(default)]
    #[schema(required = true)]
    pub theme: Option<ThemeChoice>,
    /// A system notification for a new request (default on).
    #[serde(default)]
    #[schema(required = true)]
    pub notifications: Option<bool>,
    /// The system sound with a notification (default off).
    #[serde(default)]
    #[schema(required = true)]
    pub sound: Option<bool>,
    /// What closing the window does while a sandbox runs (default `tray`).
    #[serde(default)]
    #[schema(required = true)]
    pub close_behaviour: Option<CloseBehaviour>,
}

impl From<&settings::UiPrefs> for UiPrefs {
    fn from(u: &settings::UiPrefs) -> Self {
        Self {
            theme: u.theme.map(Into::into),
            notifications: u.notifications,
            sound: u.sound,
            close_behaviour: u.close_behaviour.map(Into::into),
        }
    }
}

impl UiPrefs {
    fn apply_to(self, prefs: &mut settings::UiPrefs) {
        let Self {
            theme,
            notifications,
            sound,
            close_behaviour,
        } = self;
        prefs.theme = theme.map(Into::into);
        prefs.notifications = notifications;
        prefs.sound = sound;
        prefs.close_behaviour = close_behaviour.map(Into::into);
    }
}

/// Which level an effective value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettingSource {
    /// The sandbox's override.
    Sandbox,
    /// The global setting.
    Global,
    /// puddle's built-in default.
    Default,
}

impl From<settings::Source> for SettingSource {
    fn from(source: settings::Source) -> Self {
        match source {
            settings::Source::Sandbox => Self::Sandbox,
            settings::Source::Global => Self::Global,
            settings::Source::Default => Self::Default,
        }
    }
}

/// An effective on/off value and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedBool {
    /// The value.
    pub value: bool,
    /// Where it came from.
    pub source: SettingSource,
}

/// An effective number (MiB or seconds, see the field) and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedNumber {
    /// The value.
    pub value: u32,
    /// Where it came from.
    pub source: SettingSource,
}

/// The effective clipboard-read setting and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedClipboardRead {
    /// The value.
    pub value: ClipboardRead,
    /// Where it came from.
    pub source: SettingSource,
}

fn rb(r: settings::Resolved<bool>) -> ResolvedBool {
    ResolvedBool {
        value: r.value,
        source: r.source.into(),
    }
}

/// The effective local toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EffectiveToggles {
    /// Loopback.
    pub loopback: ResolvedBool,
    /// Private networks.
    pub private: ResolvedBool,
    /// Link-local.
    pub link_local: ResolvedBool,
    /// Cloud metadata.
    pub metadata: ResolvedBool,
    /// Other special-purpose ranges.
    pub special: ResolvedBool,
}

/// The values a sandbox gets: its override, else the global value, else puddle's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EffectiveSettings {
    /// Guest memory in MiB.
    pub memory: ResolvedNumber,
    /// Local destination toggles.
    pub local_toggles: EffectiveToggles,
    /// Whether suffix rules reach local addresses.
    pub wildcards_reach_local: ResolvedBool,
    /// Reconnection grace in seconds.
    pub reconnection_grace: ResolvedNumber,
    /// Zoom hotkeys.
    pub zoom_hotkeys: ResolvedBool,
    /// Clipboard reads.
    pub clipboard_read: ResolvedClipboardRead,
    /// Whether direct SSH is on.
    pub direct_ssh: ResolvedBool,
}

impl From<settings::Effective> for EffectiveSettings {
    fn from(e: settings::Effective) -> Self {
        let settings::Effective {
            memory,
            local_toggles,
            wildcards_reach_local,
            reconnection_grace,
            zoom_hotkeys,
            clipboard_read,
            direct_ssh,
        } = e;
        let settings::EffectiveToggles {
            loopback,
            private,
            link_local,
            metadata,
            special,
        } = local_toggles;
        Self {
            memory: ResolvedNumber {
                value: memory.value.get(),
                source: memory.source.into(),
            },
            local_toggles: EffectiveToggles {
                loopback: rb(loopback),
                private: rb(private),
                link_local: rb(link_local),
                metadata: rb(metadata),
                special: rb(special),
            },
            wildcards_reach_local: rb(wildcards_reach_local),
            reconnection_grace: ResolvedNumber {
                value: reconnection_grace.value.secs(),
                source: reconnection_grace.source.into(),
            },
            zoom_hotkeys: rb(zoom_hotkeys),
            clipboard_read: ResolvedClipboardRead {
                value: clipboard_read.value.into(),
                source: clipboard_read.source.into(),
            },
            direct_ssh: rb(direct_ssh),
        }
    }
}

/// The global settings, and what a sandbox without overrides gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct GlobalSettingsView {
    /// Defaults for every sandbox.
    pub sandbox_defaults: SettingsLayer,
    /// VS Code server options.
    pub vscode_server: VsCodeServer,
    /// Preferences for puddle's window.
    pub ui: UiPrefs,
    /// The effective values for a sandbox with no overrides.
    pub effective: EffectiveSettings,
    /// Fields in the stored document this puddle doesn't know (written by a newer one); they
    /// are kept.
    pub unknown_fields: Vec<String>,
}

/// New global settings. Replaces every value listed here; unknown stored fields are kept.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalSettingsRequest {
    /// Defaults for every sandbox.
    #[serde(default)]
    pub sandbox_defaults: SettingsLayer,
    /// VS Code server options.
    #[serde(default)]
    pub vscode_server: VsCodeServer,
    /// Preferences for puddle's window.
    #[serde(default)]
    pub ui: UiPrefs,
}

impl GlobalSettingsRequest {
    pub(crate) fn apply_to(self, global: &mut settings::GlobalSettings) -> Result<(), ApiError> {
        let Self {
            sandbox_defaults,
            vscode_server:
                VsCodeServer {
                    server,
                    telemetry,
                    auto_update,
                },
            ui,
        } = self;
        sandbox_defaults.apply_to(&mut global.sandbox_defaults)?;
        global.vscode_server.server = server.map(Into::into);
        global.vscode_server.telemetry = telemetry;
        global.vscode_server.auto_update = auto_update;
        ui.apply_to(&mut global.ui);
        Ok(())
    }
}

impl GlobalSettingsView {
    pub(crate) fn new(loaded: &settings::Loaded<settings::GlobalSettings>) -> Self {
        let global = &loaded.settings;
        Self {
            sandbox_defaults: (&global.sandbox_defaults).into(),
            vscode_server: VsCodeServer {
                server: global.vscode_server.server.map(Into::into),
                telemetry: global.vscode_server.telemetry,
                auto_update: global.vscode_server.auto_update,
            },
            ui: (&global.ui).into(),
            effective: settings::resolve(global, None).into(),
            unknown_fields: loaded.unknown_fields.clone(),
        }
    }
}

/// One sandbox's overrides and effective values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SandboxSettingsView {
    /// The sandbox.
    pub sandbox: SandboxName,
    /// Its overrides; `null` inherits.
    pub overrides: SettingsLayer,
    /// What it gets.
    pub effective: EffectiveSettings,
    /// Unknown fields in its stored document (kept).
    pub unknown_fields: Vec<String>,
}

/// New overrides for one sandbox. Replaces every value listed; `null` inherits.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxSettingsRequest {
    /// The overrides.
    #[serde(default)]
    pub overrides: SettingsLayer,
}

// ---------------------------------------------------------------------------------------------
// Consents

/// What the user agreed to or declined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Consent {
    /// Never asked.
    NotAsked,
    /// Agreed.
    Granted {
        /// Epoch ms.
        at: u64,
        /// The terms version shown.
        terms_version: String,
    },
    /// Declined.
    Declined {
        /// Epoch ms.
        at: u64,
        /// The terms version shown.
        terms_version: String,
    },
}

impl From<&settings::Consent> for Consent {
    fn from(c: &settings::Consent) -> Self {
        match c {
            settings::Consent::NotAsked => Self::NotAsked,
            settings::Consent::Granted { at, terms_version } => Self::Granted {
                at: at.0,
                terms_version: terms_version.to_string(),
            },
            settings::Consent::Declined { at, terms_version } => Self::Declined {
                at: at.0,
                terms_version: terms_version.to_string(),
            },
        }
    }
}

/// Every consent puddle asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Consents {
    /// Usage telemetry.
    pub telemetry: Consent,
    /// Crash reports.
    pub crash_reports: Consent,
    /// Microsoft's VS Code server and its licence terms.
    pub vscode_server: Consent,
}

impl From<&settings::Consents> for Consents {
    fn from(c: &settings::Consents) -> Self {
        Self {
            telemetry: c.get(settings::ConsentKind::Telemetry).into(),
            crash_reports: c.get(settings::ConsentKind::CrashReports).into(),
            vscode_server: c.get(settings::ConsentKind::VsCodeServer).into(),
        }
    }
}

/// Which consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentKind {
    /// Usage telemetry.
    Telemetry,
    /// Crash reports.
    CrashReports,
    /// Microsoft's VS Code server.
    VscodeServer,
}

impl From<ConsentKind> for settings::ConsentKind {
    fn from(kind: ConsentKind) -> Self {
        match kind {
            ConsentKind::Telemetry => Self::Telemetry,
            ConsentKind::CrashReports => Self::CrashReports,
            ConsentKind::VscodeServer => Self::VsCodeServer,
        }
    }
}

/// The user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    /// Agreed.
    Granted,
    /// Declined.
    Declined,
}

/// Records the user's answer to a consent prompt. puddle stamps the time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequest {
    /// Agreed or declined.
    pub decision: ConsentDecision,
    /// The version of the terms shown (a date or a licence URL; 1 to 256 visible ASCII
    /// characters).
    #[schema(min_length = 1, max_length = 256)]
    pub terms_version: String,
}

impl ConsentRequest {
    pub(crate) fn into_consent(self, now_ms: u64) -> Result<settings::Consent, ApiError> {
        let terms_version = settings::TermsVersion::new(&self.terms_version)
            .map_err(|err| ApiError::invalid(err.to_string()))?;
        let at = settings::UnixMillis(now_ms);
        Ok(match self.decision {
            ConsentDecision::Granted => settings::Consent::Granted { at, terms_version },
            ConsentDecision::Declined => settings::Consent::Declined { at, terms_version },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use puddle_types::{Host, PendingId, RuleId};
    use serde_json::json;

    use super::*;
    use serde_json::Value;

    fn keys(v: &Value) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        collect(v, "", &mut out);
        out
    }

    fn collect(v: &Value, prefix: &str, out: &mut BTreeSet<String>) {
        if let Value::Object(map) = v {
            for (k, child) in map {
                let path = format!("{prefix}{k}");
                if child.is_object() {
                    collect(child, &format!("{path}."), out);
                } else {
                    out.insert(path);
                }
            }
        }
    }

    /// A storage layer with every known field set, built from JSON so a new storage field shows
    /// up here as an unknown field and fails the key comparison below.
    fn full_layer() -> settings::SandboxLayer {
        let doc = json!({
            "schema_version": 1,
            "overrides": {
                "memory": 1024,
                "local_toggles": {
                    "loopback": true, "private": false, "link_local": true,
                    "metadata": false, "special": true
                },
                "wildcards_reach_local": true,
                "reconnection_grace": 60,
                "zoom_hotkeys": false,
                "clipboard_read": "deny",
                "direct_ssh": true
            }
        });
        let loaded = settings::SandboxSettings::from_document(doc).unwrap();
        assert_eq!(loaded.unknown_fields, Vec::<String>::new());
        loaded.settings.overrides
    }

    #[test]
    fn settings_layer_has_exactly_the_storage_fields() {
        let layer = full_layer();
        let storage = serde_json::to_value(&layer).unwrap();
        let wire = serde_json::to_value(SettingsLayer::from(&layer)).unwrap();
        assert_eq!(keys(&storage), keys(&wire));
        assert_eq!(
            storage, wire,
            "same names and values when every field is set"
        );
    }

    #[test]
    fn settings_layer_round_trips_and_keeps_unknown_stored_fields() {
        let mut stored = settings::SandboxSettings::from_document(
            json!({"overrides": {"cpus": 4, "memory": 2048}}),
        )
        .unwrap()
        .settings;
        let wire = SettingsLayer::from(&full_layer());
        wire.clone().apply_to(&mut stored.overrides).unwrap();
        assert_eq!(SettingsLayer::from(&stored.overrides), wire);
        assert_eq!(stored.to_document()["overrides"]["cpus"], 4);
        // Clearing every value leaves only the unknown field.
        SettingsLayer::default()
            .apply_to(&mut stored.overrides)
            .unwrap();
        assert_eq!(
            stored.to_document(),
            json!({"schema_version": 1, "overrides": {"cpus": 4}})
        );
    }

    #[test]
    fn out_of_range_settings_are_refused() {
        let mut layer = settings::SandboxLayer::default();
        for bad in [
            SettingsLayer {
                memory: Some(1),
                ..SettingsLayer::default()
            },
            SettingsLayer {
                reconnection_grace: Some(1),
                ..SettingsLayer::default()
            },
        ] {
            let err = bad.apply_to(&mut layer).unwrap_err();
            assert_eq!(err.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[test]
    fn global_request_sets_vscode_options() {
        let mut g = settings::GlobalSettings::default();
        GlobalSettingsRequest {
            sandbox_defaults: SettingsLayer {
                zoom_hotkeys: Some(false),
                ..SettingsLayer::default()
            },
            vscode_server: VsCodeServer {
                server: Some(ServerChoice::Microsoft),
                telemetry: Some(true),
                auto_update: Some(false),
            },
            ui: UiPrefs {
                theme: Some(ThemeChoice::Dark),
                notifications: Some(false),
                sound: Some(true),
                close_behaviour: Some(CloseBehaviour::Quit),
            },
        }
        .apply_to(&mut g)
        .unwrap();
        assert_eq!(g.vscode_server.server(), settings::ServerChoice::Microsoft);
        assert_eq!(g.ui.theme(), settings::ThemeChoice::Dark);
        assert!(!g.ui.notifications());
        assert!(g.ui.sound());
        assert_eq!(g.ui.close_behaviour(), settings::CloseBehaviour::Quit);
        assert!(g.vscode_server.telemetry());
        assert!(!g.vscode_server.auto_update());
        let view = GlobalSettingsView::new(&settings::Loaded {
            settings: g,
            migrated_from: None,
            unknown_fields: vec![],
        });
        assert_eq!(view.effective.zoom_hotkeys.source, SettingSource::Global);
        assert!(!view.effective.zoom_hotkeys.value);
        assert_eq!(view.effective.memory.source, SettingSource::Default);
    }

    #[test]
    fn decision_request_defaults_are_narrowest() {
        let r = DecisionRequest::default()
            .into_resolution(Effect::Allow)
            .unwrap();
        assert_eq!(r, store::Resolution::allow());
        let r = DecisionRequest {
            scope: ScopeChoice::Global,
            suffix: Some("example.com".into()),
            expires_in_secs: Some(60),
        }
        .into_resolution(Effect::Deny)
        .unwrap();
        assert_eq!(r.effect, store::Effect::Deny);
        assert_eq!(r.scope, store::ScopeChoice::Global);
        assert_eq!(
            r.pattern,
            store::PatternChoice::Suffix("example.com".into())
        );
        assert_eq!(r.expires_in, Some(Duration::from_secs(60)));
        let parsed: DecisionRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, DecisionRequest::default());
        assert!(serde_json::from_str::<DecisionRequest>(r#"{"scope":"everything"}"#).is_err());
        assert!(serde_json::from_str::<DecisionRequest>(r#"{"extra":1}"#).is_err());
    }

    #[test]
    fn rules_map_with_their_scope_and_pattern_kind() {
        let sandbox = SandboxName::new("box").unwrap();
        let rule = store::Rule {
            id: RuleId(3),
            scope: store::Scope::Sandbox(sandbox.clone()),
            pattern: store::Pattern::parse("*.example.com").unwrap(),
            effect: store::Effect::Deny,
            expires_at: None,
            created_at: 5,
            created_by: store::Actor::Ui,
            source_pending_id: Some(PendingId(9)),
        };
        let wire = Rule::from_store(rule).unwrap();
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            json!({
                "id": 3, "scope": {"type": "sandbox", "sandbox": "box"},
                "pattern": ".example.com", "pattern_kind": "suffix", "effect": "deny",
                "expires_at": null, "created_at": 5, "created_by": "ui",
                "source_pending_id": 9
            })
        );
        assert_eq!(
            serde_json::to_value(RuleScope::Global).unwrap(),
            json!({"type": "global"})
        );
        // Input is normalised, not refused: case, punycode, a trailing dot, a wildcard.
        let typed = NewRuleRequest {
            scope: RuleScope::Global,
            pattern: "  *.Bücher.Example.COM. ".into(),
            effect: Effect::Allow,
            expires_at: None,
        };
        assert_eq!(
            typed.into_new_rule().unwrap().pattern.to_string(),
            ".xn--bcher-kva.example.com"
        );
        let new = NewRuleRequest {
            scope: RuleScope::Global,
            pattern: "example.com".into(),
            effect: Effect::Allow,
            expires_at: None,
        }
        .into_new_rule()
        .unwrap();
        assert_eq!(new.pattern.to_string(), "example.com");
        assert_eq!(new.created_by, store::Actor::Api);
        assert!(
            NewRuleRequest {
                scope: RuleScope::Global,
                pattern: "*.com".into(),
                effect: Effect::Allow,
                expires_at: None,
            }
            .into_new_rule()
            .is_err()
        );
    }

    #[test]
    fn pending_rows_always_carry_every_field() {
        let row = store::PendingRow {
            id: PendingId(1),
            sandbox: SandboxName::new("box").unwrap(),
            host: Host::parse_normalised("example.com").unwrap(),
            port: 443,
            first_seen: 1,
            last_seen: 2,
            attempts: 3,
            state: store::PendingState::Requested,
            decided_at: None,
            decided_by: None,
            rule_id: None,
        };
        let v = serde_json::to_value(PendingRequest::from_store(row).unwrap()).unwrap();
        assert_eq!(v["decided_at"], Value::Null);
        assert_eq!(v["decided_by"], Value::Null);
        assert_eq!(v["rule_id"], Value::Null);
        assert_eq!(v["state"], "requested");
        for (state, text) in [
            (store::PendingState::Allowed, "allowed"),
            (store::PendingState::Denied, "denied"),
            (store::PendingState::Expired, "expired"),
        ] {
            assert_eq!(
                serde_json::to_value(PendingState::from(state)).unwrap(),
                text
            );
        }
        for (actor, text) in [
            (store::Actor::Cli, "cli"),
            (store::Actor::Api, "api"),
            (store::Actor::System, "system"),
        ] {
            assert_eq!(
                serde_json::to_value(Actor::from_store(actor).unwrap()).unwrap(),
                text
            );
        }
    }

    #[test]
    fn consents_map_and_validate_terms() {
        let granted = ConsentRequest {
            decision: ConsentDecision::Granted,
            terms_version: "v1".into(),
        }
        .into_consent(42)
        .unwrap();
        assert_eq!(
            serde_json::to_value(Consent::from(&granted)).unwrap(),
            json!({"state": "granted", "at": 42, "terms_version": "v1"})
        );
        let declined = ConsentRequest {
            decision: ConsentDecision::Declined,
            terms_version: "v1".into(),
        }
        .into_consent(1)
        .unwrap();
        assert!(matches!(Consent::from(&declined), Consent::Declined { .. }));
        assert!(
            ConsentRequest {
                decision: ConsentDecision::Granted,
                terms_version: "has space".into(),
            }
            .into_consent(1)
            .is_err()
        );
        let mut all = settings::Consents::default();
        all.set(
            settings::ConsentKind::from(ConsentKind::CrashReports),
            granted,
        );
        let wire = Consents::from(&all);
        assert_eq!(wire.telemetry, Consent::NotAsked);
        assert!(matches!(wire.crash_reports, Consent::Granted { .. }));
        assert_eq!(
            settings::ConsentKind::from(ConsentKind::VscodeServer),
            settings::ConsentKind::VsCodeServer
        );
        assert_eq!(
            serde_json::to_value(ConsentKind::VscodeServer).unwrap(),
            "vscode_server"
        );
    }

    #[test]
    fn clipboard_and_effect_map_both_ways() {
        for c in [
            ClipboardRead::Ask,
            ClipboardRead::Allow,
            ClipboardRead::Deny,
        ] {
            assert_eq!(ClipboardRead::from(settings::ClipboardRead::from(c)), c);
        }
        for e in [Effect::Allow, Effect::Deny] {
            assert_eq!(Effect::from(store::Effect::from(e)), e);
        }
    }

    #[test]
    fn patterns_are_normalised_with_the_proxy_normaliser() {
        for (input, want) in [
            ("example.com", (false, "example.com")),
            ("EXAMPLE.com.", (false, "example.com")),
            (".example.com", (true, "example.com")),
            ("*.Example.Com", (true, "example.com")),
            ("Bücher.example", (false, "xn--bcher-kva.example")),
            ("\t10.0.0.1\n", (false, "10.0.0.1")),
            ("[2001:DB8::1]", (false, "2001:db8::1")),
            ("2001:DB8:0::1", (false, "2001:db8::1")),
        ] {
            assert_eq!(
                normalise_pattern("pattern", input).unwrap(),
                (want.0, want.1.to_owned()),
                "{input:?}"
            );
        }
    }

    #[test]
    fn patterns_that_are_not_hosts_are_refused_naming_the_field() {
        for (input, why) in [
            ("", "invalid host"),
            ("https://example.com/a", "not a URL"),
            ("user@example.com", "not a URL"),
            ("example.com/path", "not a URL"),
            ("example.com:443", "leave the port out"),
            ("*.example.com:8080", "leave the port out"),
            ("a b.example", "invalid host"),
            ("127.1", "canonical"),
            ("exa*mple.com", "invalid host"),
            ("-.", "invalid host"),
        ] {
            let err = normalise_pattern("suffix", input).unwrap_err();
            assert_eq!(err.status(), axum::http::StatusCode::UNPROCESSABLE_ENTITY);
            let body = format!("{err:?}");
            assert!(body.contains("suffix: "), "{input:?}: {body}");
            assert!(body.contains(why), "{input:?}: {body}");
        }
    }

    #[test]
    fn a_decision_suffix_is_normalised_too() {
        let r = DecisionRequest {
            scope: ScopeChoice::Sandbox,
            suffix: Some("*.GitHub.COM".into()),
            expires_in_secs: None,
        }
        .into_resolution(Effect::Allow)
        .unwrap();
        assert_eq!(r.pattern, store::PatternChoice::Suffix("github.com".into()));
        assert!(
            DecisionRequest {
                scope: ScopeChoice::Sandbox,
                suffix: Some("https://github.com".into()),
                expires_in_secs: None,
            }
            .into_resolution(Effect::Allow)
            .is_err()
        );
    }

    #[test]
    fn audit_types_and_outcomes_cover_the_stores() {
        let tags: Vec<&str> = [
            AuditType::Connection,
            AuditType::PendingCreated,
            AuditType::PendingDecided,
            AuditType::PendingExpired,
            AuditType::PendingSuppressed,
            AuditType::RuleCreated,
            AuditType::RuleUpdated,
            AuditType::RuleDeleted,
            AuditType::RuleExpired,
            AuditType::AuditTrimmed,
        ]
        .into_iter()
        .map(AuditType::tag)
        .collect();
        assert_eq!(tags, store::AuditRecord::KINDS);
        for kind in [AuditType::PendingCreated, AuditType::RuleExpired] {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.tag());
        }
        for (wire, domain) in [
            (AuditOutcome::Allow, store::AuditOutcome::Allow),
            (AuditOutcome::Deny, store::AuditOutcome::Deny),
            (AuditOutcome::Pending, store::AuditOutcome::Pending),
            (AuditOutcome::Blocked, store::AuditOutcome::Blocked),
            (AuditOutcome::Expired, store::AuditOutcome::Expired),
        ] {
            assert_eq!(
                serde_json::to_value(wire).unwrap(),
                domain.as_str(),
                "{wire:?}"
            );
            assert_eq!(store::AuditOutcome::from(wire), domain);
        }
    }

    /// The typed record serialises to the very JSON the store wrote, so the API adds no layer
    /// that could drop or rename a field, including `upstream` and records older than it.
    #[test]
    fn typed_audit_records_serialise_as_stored() {
        let stored = serde_json::json!({
            "type": "connection", "ts": 5, "sandbox_id": "box", "origin": "sandbox", "host": "example.com",
            "port": 443, "resolved_ip": "93.184.216.34", "upstream": "PROXY corp:3128",
            "decision": "allow", "reason": "rule", "rule_id": 4, "pending_id": null,
            "binding_id": null, "injected": false, "method": "GET", "path": "/",
            "path_truncated": false, "bytes_up": 1, "bytes_down": 2, "count": null
        });
        let record: store::AuditRecord = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(AuditRecord::from(record)).unwrap(),
            stored
        );
        // Written before `upstream` existed.
        let mut old = stored;
        old.as_object_mut().unwrap().remove("upstream");
        let record: store::AuditRecord = serde_json::from_value(old.clone()).unwrap();
        let mut back = serde_json::to_value(AuditRecord::from(record)).unwrap();
        assert_eq!(back["upstream"], Value::Null);
        back.as_object_mut().unwrap().remove("upstream");
        assert_eq!(back, old);
        // Written before `origin` existed: a sandbox's connection.
        let mut older = serde_json::to_value(AuditRecord::from(
            serde_json::from_value::<store::AuditRecord>(old).unwrap(),
        ))
        .unwrap();
        older.as_object_mut().unwrap().remove("origin");
        let record: store::AuditRecord = serde_json::from_value(older).unwrap();
        let back = serde_json::to_value(AuditRecord::from(record)).unwrap();
        assert_eq!(back["origin"], "sandbox");
        assert_eq!(back["sandbox_id"], "box");
        // puddle's own connection: no sandbox.
        let mut own = back;
        own["origin"] = "puddle".into();
        own["sandbox_id"] = Value::Null;
        let record: store::AuditRecord = serde_json::from_value(own.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(AuditRecord::from(record)).unwrap(),
            own
        );
    }
}
