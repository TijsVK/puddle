// SPDX-License-Identifier: GPL-3.0-or-later
//! The audit log's wire format (`docs/spec/rules.md` §5, ADR 0002).
//!
//! Every record is one variant of [`AuditRecord`], serialised by `serde_json` only (R-23), with
//! control characters escaped and the size caps of R-26 applied in [`AuditRecord::to_line`], the
//! one place a record becomes text. Nothing secret is representable: there are no header, body,
//! query-string or credential fields (R-25).

use std::io;

use puddle_types::{
    ConnectionDecision, ConnectionEvent, ConnectionOrigin, ConnectionReason, WorkspaceName,
    request_path,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pattern::Pattern;
use crate::pending::PendingRow;
use crate::rule::{Actor, Rule};

/// Longest audit line, in bytes (R-26).
pub const MAX_LINE_BYTES: usize = 4096;
/// Longest string field, in bytes, before the line cap applies (R-26).
pub const MAX_FIELD_BYTES: usize = 1024;

/// A record could not be turned into a line.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// `serde_json` failed (it can't for these types; kept rather than panicking).
    #[error("audit record did not serialise: {0}")]
    Serialise(#[from] serde_json::Error),
    /// The record is over the line cap with every string already empty.
    #[error("audit record exceeds {MAX_LINE_BYTES} bytes without its strings")]
    TooLarge,
}

/// A `connection` record (R-24). `host`, `port` and `decision` are `null` only on a
/// `reason: suppressed` summary, which carries `count` instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    /// Epoch ms.
    pub ts: u64,
    /// The workspace; `null` for puddle's own connections (`origin: puddle`).
    #[serde(alias = "sandbox_id")]
    pub workspace_id: Option<String>,
    /// Whose connection it is: `workspace` or `puddle`. Absent in records written before it
    /// existed, which read as `workspace`.
    #[serde(default)]
    pub origin: ConnectionOrigin,
    /// The requested host.
    pub host: Option<String>,
    /// The requested port.
    pub port: Option<u16>,
    /// The address connected to.
    pub resolved_ip: Option<String>,
    /// The company-proxy hop that carried it (`DIRECT`, `PROXY host:port`), when an upstream
    /// route is configured. Absent in records written before it existed.
    #[serde(default)]
    pub upstream: Option<String>,
    /// What happened.
    pub decision: Option<ConnectionDecision>,
    /// Why (see [`ConnectionReason`]).
    pub reason: String,
    /// The deciding rule.
    pub rule_id: Option<i64>,
    /// The rule set whose entry decided (`system`, `builtin:<slug>`, `user:<id>`). Absent in
    /// records written before rule sets existed.
    #[serde(default)]
    pub rule_set: Option<String>,
    /// The pending row.
    pub pending_id: Option<i64>,
    /// The credential binding, by id.
    pub binding_id: Option<String>,
    /// Whether a credential was injected.
    pub injected: bool,
    /// Whether a secret stand-in went to a host outside its hosts, unchanged. Absent in records
    /// written before it existed.
    #[serde(default)]
    pub placeholder_unbound: bool,
    /// HTTP method: plain-HTTP requests, tunnels that carry plain HTTP, terminated hosts.
    pub method: Option<String>,
    /// HTTP path without query string, where `method` is set.
    pub path: Option<String>,
    /// Whether `path` was cut to fit (R-26).
    pub path_truncated: bool,
    /// Bytes from the guest.
    pub bytes_up: u64,
    /// Bytes to the guest.
    pub bytes_down: u64,
    /// Records summarised, on a `suppressed` summary.
    pub count: Option<u64>,
}

impl ConnectionRecord {
    pub(crate) fn from_event(ts: u64, event: &ConnectionEvent) -> Self {
        let (method, path) = event.http.as_ref().map_or((None, None), |http| {
            (Some(http.method().to_owned()), Some(http.path().to_owned()))
        });
        Self {
            ts,
            workspace_id: event.workspace.as_ref().map(ToString::to_string),
            origin: event.origin,
            host: Some(event.host.to_string()),
            port: Some(event.port),
            resolved_ip: event.resolved_ip.map(|ip| ip.to_string()),
            upstream: event.upstream.clone(),
            decision: Some(event.decision),
            reason: event.reason.to_string(),
            rule_id: event.rule_id.map(|id| id.0),
            rule_set: event.rule_set.map(|set| set.to_string()),
            pending_id: event.pending_id.map(|id| id.0),
            binding_id: event.binding_id.clone(),
            injected: event.injected,
            placeholder_unbound: event.placeholder_unbound,
            method,
            path,
            path_truncated: false,
            bytes_up: event.bytes_up,
            bytes_down: event.bytes_down,
            count: None,
        }
    }

    /// The `suppressed` summary for a workspace, or for puddle's own connections when `workspace` is
    /// `None`.
    pub(crate) fn suppressed_summary(
        ts: u64,
        workspace: Option<&WorkspaceName>,
        count: u64,
    ) -> Self {
        Self {
            ts,
            workspace_id: workspace.map(ToString::to_string),
            origin: if workspace.is_some() {
                ConnectionOrigin::Workspace
            } else {
                ConnectionOrigin::Puddle
            },
            host: None,
            port: None,
            resolved_ip: None,
            upstream: None,
            decision: None,
            reason: ConnectionReason::Suppressed.to_string(),
            rule_id: None,
            rule_set: None,
            pending_id: None,
            binding_id: None,
            injected: false,
            placeholder_unbound: false,
            method: None,
            path: None,
            path_truncated: false,
            bytes_up: 0,
            bytes_down: 0,
            count: Some(count),
        }
    }
}

/// Reads a stored rule scope, mapping the name `sandbox` that older records carry.
fn scope_name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let scope = String::deserialize(d)?;
    Ok(if scope == "sandbox" {
        "workspace".to_owned()
    } else {
        scope
    })
}

/// A rule as it appears in the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleWire {
    /// Row id.
    pub id: i64,
    /// `global`, `workspace` or `set`. Records written before the rename read `sandbox` as
    /// `workspace`.
    #[serde(deserialize_with = "scope_name")]
    pub scope: String,
    /// The workspace, for a workspace rule.
    #[serde(alias = "sandbox_id")]
    pub workspace_id: Option<String>,
    /// The rule set the user made, for a set's entry. Absent in records written before rule
    /// sets existed.
    #[serde(default)]
    pub set_id: Option<i64>,
    /// `exact` or `suffix`.
    pub pattern_kind: String,
    /// `example.com` or `.example.com`.
    pub pattern: String,
    /// `allow` or `deny`.
    pub effect: String,
    /// Epoch ms, or `null` for permanent.
    pub expires_at: Option<u64>,
    /// Epoch ms.
    pub created_at: u64,
    /// `cli`, `ui` or `api`.
    pub created_by: String,
    /// The pending row it came from.
    pub source_pending_id: Option<i64>,
}

impl From<&Rule> for RuleWire {
    fn from(rule: &Rule) -> Self {
        Self {
            id: rule.id.0,
            scope: rule.scope.as_str().to_owned(),
            workspace_id: rule.scope.workspace().map(ToString::to_string),
            set_id: rule.scope.set(),
            pattern_kind: match rule.pattern {
                Pattern::Exact(_) => "exact",
                Pattern::Suffix(_) => "suffix",
            }
            .to_owned(),
            pattern: rule.pattern.to_string(),
            effect: rule.effect.as_str().to_owned(),
            expires_at: rule.expires_at,
            created_at: rule.created_at,
            created_by: rule.created_by.as_str().to_owned(),
            source_pending_id: rule.source_pending_id.map(|id| id.0),
        }
    }
}

/// A pending row as it appears in the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWire {
    /// Row id.
    pub id: i64,
    /// The workspace.
    #[serde(alias = "sandbox_id")]
    pub workspace_id: String,
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
    pub decided_at: Option<u64>,
    /// `cli`, `ui`, `api` or `system`.
    pub decided_by: Option<String>,
    /// The deciding rule.
    pub rule_id: Option<i64>,
    /// The rule set whose entry decided it. Absent in records written before rule sets existed.
    #[serde(default)]
    pub rule_set: Option<String>,
}

impl From<&PendingRow> for PendingWire {
    fn from(row: &PendingRow) -> Self {
        Self {
            id: row.id.0,
            workspace_id: row.workspace.to_string(),
            host: row.host.to_string(),
            port: row.port,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
            attempts: row.attempts,
            state: row.state.as_str().to_owned(),
            decided_at: row.decided_at,
            decided_by: row.decided_by.map(|a| a.as_str().to_owned()),
            rule_id: row.rule_id.map(|id| id.0),
            rule_set: row.rule_set.clone(),
        }
    }
}

/// Why a pending row expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingExpiryReason {
    /// No repeat for the stale period (R-20).
    Stale,
    /// Its workspace was deleted (R-21).
    #[serde(alias = "sandbox_deleted")]
    WorkspaceDeleted,
}

/// Why a rule was deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDeleteReason {
    /// A user deleted it.
    User,
    /// Its workspace was deleted (R-21).
    #[serde(alias = "sandbox_deleted")]
    WorkspaceDeleted,
    /// It was an entry of a rule set the user deleted (R-38).
    SetDeleted,
}

/// A rule set the user made, as it appears in the audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetWire {
    /// Row id; the set's wire id is `user:<id>`.
    pub id: i64,
    /// Display name.
    pub name: String,
    /// What it is for.
    pub description: String,
    /// Epoch ms.
    pub created_at: u64,
    /// `cli`, `ui` or `api`.
    pub created_by: String,
}

/// One audit record (R-24). Internally tagged: `{"type": "rule_created", ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditRecord {
    /// A connection the proxy handled (written by the proxy).
    Connection(ConnectionRecord),
    /// A new pending row.
    PendingCreated {
        /// Epoch ms.
        ts: u64,
        /// The row.
        pending: PendingWire,
    },
    /// A pending row approved or denied, by the user or by a rule that now covers it (R-16).
    PendingDecided {
        /// Epoch ms.
        ts: u64,
        /// The row as decided.
        pending: PendingWire,
    },
    /// A pending row expired.
    PendingExpired {
        /// Epoch ms.
        ts: u64,
        /// The row as expired.
        pending: PendingWire,
        /// Stale or workspace deleted.
        reason: PendingExpiryReason,
    },
    /// Requests over a workspace's limit, not written as rows (R-13).
    PendingSuppressed {
        /// Epoch ms.
        ts: u64,
        /// The workspace.
        #[serde(alias = "sandbox_id")]
        workspace_id: String,
        /// Requests suppressed since the previous record.
        count: u64,
    },
    /// A rule created.
    RuleCreated {
        /// Epoch ms.
        ts: u64,
        /// The rule.
        rule: RuleWire,
    },
    /// A rule changed.
    RuleUpdated {
        /// Epoch ms.
        ts: u64,
        /// The rule before.
        before: RuleWire,
        /// The rule after.
        rule: RuleWire,
        /// Who changed it.
        actor: String,
    },
    /// A rule deleted.
    RuleDeleted {
        /// Epoch ms.
        ts: u64,
        /// The rule as it was.
        rule: RuleWire,
        /// User or workspace deletion.
        reason: RuleDeleteReason,
        /// Who deleted it.
        actor: String,
    },
    /// A rule removed by the sweeper after it expired (R-19).
    RuleExpired {
        /// Epoch ms.
        ts: u64,
        /// The whole rule.
        rule: RuleWire,
    },
    /// A rule set made by the user (R-43).
    RuleSetCreated {
        /// Epoch ms.
        ts: u64,
        /// The set.
        rule_set: RuleSetWire,
        /// Who made it.
        actor: String,
    },
    /// A rule set renamed or described anew.
    RuleSetUpdated {
        /// Epoch ms.
        ts: u64,
        /// The set before.
        before: RuleSetWire,
        /// The set after.
        rule_set: RuleSetWire,
        /// Who changed it.
        actor: String,
    },
    /// A rule set deleted, with its entries (each also gets a `rule_deleted`).
    RuleSetDeleted {
        /// Epoch ms.
        ts: u64,
        /// The set as it was.
        rule_set: RuleSetWire,
        /// Who deleted it.
        actor: String,
    },
    /// A rule set switched on or off, or back to following the next level (R-37).
    RuleSetSwitched {
        /// Epoch ms.
        ts: u64,
        /// `builtin:<slug>` or `user:<id>`.
        set_id: String,
        /// The workspace whose override changed, or `null` for every workspace.
        #[serde(alias = "sandbox_id")]
        workspace_id: Option<String>,
        /// On, off, or `null` to follow the next level.
        enabled: Option<bool>,
        /// Who switched it.
        actor: String,
    },
    /// A puddle update changed a built-in set's entries (R-36).
    RuleSetChanged {
        /// Epoch ms.
        ts: u64,
        /// `builtin:<slug>`.
        set_id: String,
        /// Patterns the update added.
        added: Vec<String>,
        /// Patterns the update removed.
        removed: Vec<String>,
    },
    /// The reasons puddle allows System managed hosts changed, because the user's setup did
    /// (R-41).
    SystemManagedChanged {
        /// Epoch ms.
        ts: u64,
        /// The workspace, or `null` for every workspace.
        #[serde(alias = "sandbox_id")]
        workspace_id: Option<String>,
        /// Reasons that now apply (`microsoft_server`, `code_server`, `direct_ssh`).
        added: Vec<String>,
        /// Reasons that no longer apply.
        removed: Vec<String>,
    },
    /// Oldest records deleted to keep the audit under its cap (R-26).
    AuditTrimmed {
        /// Epoch ms.
        ts: u64,
        /// Records deleted.
        deleted_records: u64,
        /// `ts` of the oldest record left, `null` if none.
        oldest_ts_kept: Option<u64>,
    },
}

/// What a record says happened, for filtering (`GET /api/audit?outcome=`). Only records that
/// are about a decision have one: connections, and pending requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// A pending request that expired without a decision.
    Expired,
}

impl AuditOutcome {
    /// Every outcome.
    pub const ALL: [Self; 5] = [
        Self::Allow,
        Self::Deny,
        Self::Pending,
        Self::Blocked,
        Self::Expired,
    ];

    /// The `snake_case` name stored in the `audit.outcome` column and used on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Expired => "expired",
        }
    }
}

impl AuditRecord {
    /// Every `type` tag, in declaration order.
    pub const KINDS: [&'static str; 16] = [
        "connection",
        "pending_created",
        "pending_decided",
        "pending_expired",
        "pending_suppressed",
        "rule_created",
        "rule_updated",
        "rule_deleted",
        "rule_expired",
        "rule_set_created",
        "rule_set_updated",
        "rule_set_deleted",
        "rule_set_switched",
        "rule_set_changed",
        "system_managed_changed",
        "audit_trimmed",
    ];

    /// The host the record is about, lower case: a connection's or pending request's host, or a
    /// rule's pattern (`.example.com` for a suffix). Stored in a column so `host_contains` needs
    /// no JSON parsing. The migration that added the column derives the same value in SQL
    /// (`schema.rs`); a test keeps the two equal.
    #[must_use]
    pub fn host(&self) -> Option<String> {
        let host = match self {
            Self::Connection(record) => record.host.as_deref()?,
            Self::PendingCreated { pending, .. }
            | Self::PendingDecided { pending, .. }
            | Self::PendingExpired { pending, .. } => &pending.host,
            Self::RuleCreated { rule, .. }
            | Self::RuleUpdated { rule, .. }
            | Self::RuleDeleted { rule, .. }
            | Self::RuleExpired { rule, .. } => &rule.pattern,
            Self::PendingSuppressed { .. }
            | Self::RuleSetCreated { .. }
            | Self::RuleSetUpdated { .. }
            | Self::RuleSetDeleted { .. }
            | Self::RuleSetSwitched { .. }
            | Self::RuleSetChanged { .. }
            | Self::SystemManagedChanged { .. }
            | Self::AuditTrimmed { .. } => return None,
        };
        Some(host.to_ascii_lowercase())
    }

    /// Whose connection the record describes: `connection` records only (every other record
    /// has none). A puddle connection is the one with no workspace, which is how the `origin`
    /// filter finds it without a column of its own.
    #[must_use]
    pub fn origin(&self) -> Option<ConnectionOrigin> {
        match self {
            Self::Connection(record) => Some(record.origin),
            _ => None,
        }
    }

    /// The record's [`AuditOutcome`], if it has one.
    #[must_use]
    pub fn outcome(&self) -> Option<AuditOutcome> {
        match self {
            Self::Connection(record) => record.decision.map(|d| match d {
                ConnectionDecision::Allow => AuditOutcome::Allow,
                ConnectionDecision::Deny => AuditOutcome::Deny,
                ConnectionDecision::Pending => AuditOutcome::Pending,
                // `ConnectionDecision` is non-exhaustive; a new decision is a refusal until
                // this match learns it.
                _ => AuditOutcome::Blocked,
            }),
            Self::PendingCreated { .. } => Some(AuditOutcome::Pending),
            Self::PendingDecided { pending, .. } => match pending.state.as_str() {
                "allowed" => Some(AuditOutcome::Allow),
                "denied" => Some(AuditOutcome::Deny),
                _ => None,
            },
            Self::PendingExpired { .. } => Some(AuditOutcome::Expired),
            Self::PendingSuppressed { .. }
            | Self::RuleCreated { .. }
            | Self::RuleUpdated { .. }
            | Self::RuleDeleted { .. }
            | Self::RuleExpired { .. }
            | Self::RuleSetCreated { .. }
            | Self::RuleSetUpdated { .. }
            | Self::RuleSetDeleted { .. }
            | Self::RuleSetSwitched { .. }
            | Self::RuleSetChanged { .. }
            | Self::SystemManagedChanged { .. }
            | Self::AuditTrimmed { .. } => None,
        }
    }

    /// The `type` tag.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Connection(_) => "connection",
            Self::PendingCreated { .. } => "pending_created",
            Self::PendingDecided { .. } => "pending_decided",
            Self::PendingExpired { .. } => "pending_expired",
            Self::PendingSuppressed { .. } => "pending_suppressed",
            Self::RuleCreated { .. } => "rule_created",
            Self::RuleUpdated { .. } => "rule_updated",
            Self::RuleDeleted { .. } => "rule_deleted",
            Self::RuleExpired { .. } => "rule_expired",
            Self::RuleSetCreated { .. } => "rule_set_created",
            Self::RuleSetUpdated { .. } => "rule_set_updated",
            Self::RuleSetDeleted { .. } => "rule_set_deleted",
            Self::RuleSetSwitched { .. } => "rule_set_switched",
            Self::RuleSetChanged { .. } => "rule_set_changed",
            Self::SystemManagedChanged { .. } => "system_managed_changed",
            Self::AuditTrimmed { .. } => "audit_trimmed",
        }
    }

    /// Epoch ms.
    #[must_use]
    pub fn ts(&self) -> u64 {
        match self {
            Self::Connection(record) => record.ts,
            Self::PendingCreated { ts, .. }
            | Self::PendingDecided { ts, .. }
            | Self::PendingExpired { ts, .. }
            | Self::PendingSuppressed { ts, .. }
            | Self::RuleCreated { ts, .. }
            | Self::RuleUpdated { ts, .. }
            | Self::RuleDeleted { ts, .. }
            | Self::RuleExpired { ts, .. }
            | Self::RuleSetCreated { ts, .. }
            | Self::RuleSetUpdated { ts, .. }
            | Self::RuleSetDeleted { ts, .. }
            | Self::RuleSetSwitched { ts, .. }
            | Self::RuleSetChanged { ts, .. }
            | Self::SystemManagedChanged { ts, .. }
            | Self::AuditTrimmed { ts, .. } => *ts,
        }
    }

    /// The workspace the record is about, if any (indexed for per-workspace reads).
    #[must_use]
    pub fn workspace_id(&self) -> Option<&str> {
        match self {
            Self::Connection(record) => record.workspace_id.as_deref(),
            Self::PendingCreated { pending, .. }
            | Self::PendingDecided { pending, .. }
            | Self::PendingExpired { pending, .. } => Some(&pending.workspace_id),
            Self::PendingSuppressed { workspace_id, .. } => Some(workspace_id),
            Self::RuleCreated { rule, .. }
            | Self::RuleUpdated { rule, .. }
            | Self::RuleDeleted { rule, .. }
            | Self::RuleExpired { rule, .. } => rule.workspace_id.as_deref(),
            Self::RuleSetSwitched { workspace_id, .. }
            | Self::SystemManagedChanged { workspace_id, .. } => workspace_id.as_deref(),
            Self::RuleSetCreated { .. }
            | Self::RuleSetUpdated { .. }
            | Self::RuleSetDeleted { .. }
            | Self::RuleSetChanged { .. }
            | Self::AuditTrimmed { .. } => None,
        }
    }

    /// The record as one JSONL line (no newline), at most [`MAX_LINE_BYTES`].
    ///
    /// Every string longer than [`MAX_FIELD_BYTES`] is cut to it; `path` is also stripped of any
    /// query string and marks `path_truncated`. If the line is still too long, the longest
    /// string is halved until it fits. Control characters (C0, DEL, C1) and U+2028/U+2029 come
    /// out as `\uXXXX`.
    ///
    /// # Errors
    /// [`AuditError`] if the record can't be serialised or can't fit.
    pub fn to_line(&self) -> Result<String, AuditError> {
        let mut value = serde_json::to_value(self)?;
        let path = value
            .get("path")
            .and_then(Value::as_str)
            .map(|p| request_path(p).to_owned());
        if let (Some(path), Some(slot)) = (path, value.get_mut("path")) {
            *slot = Value::String(path);
        }
        let mut cut = Vec::new();
        cap_strings(&mut value, MAX_FIELD_BYTES, "", &mut cut);
        let mut line = encode(&value)?;
        while line.len() > MAX_LINE_BYTES {
            let Some((_, pointer)) = longest_string(&value, "") else {
                return Err(AuditError::TooLarge);
            };
            if let Some(Value::String(s)) = value.pointer_mut(&pointer) {
                let keep = s.floor_char_boundary(s.len() / 2);
                s.truncate(keep);
            }
            cut.push(pointer);
            line = encode(&value)?;
        }
        if cut.iter().any(|p| p == "/path")
            && let Some(flag) = value.get_mut("path_truncated")
        {
            *flag = Value::Bool(true);
            line = encode(&value)?;
        }
        Ok(line)
    }
}

/// Cuts every string over `max` bytes, recording the JSON pointer of each one cut.
fn cap_strings(value: &mut Value, max: usize, pointer: &str, cut: &mut Vec<String>) {
    match value {
        Value::String(s) if s.len() > max => {
            let keep = s.floor_char_boundary(max);
            s.truncate(keep);
            cut.push(pointer.to_owned());
        }
        Value::Object(map) => {
            for (key, child) in map {
                cap_strings(child, max, &format!("{pointer}/{key}"), cut);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter_mut().enumerate() {
                cap_strings(child, max, &format!("{pointer}/{index}"), cut);
            }
        }
        _ => {}
    }
}

/// The JSON pointer and encoded length of the non-empty string whose encoding is longest.
fn longest_string(value: &Value, pointer: &str) -> Option<(usize, String)> {
    match value {
        Value::String(s) if !s.is_empty() => Some((encoded_len(s), pointer.to_owned())),
        Value::Object(map) => map
            .iter()
            .filter_map(|(key, child)| longest_string(child, &format!("{pointer}/{key}")))
            .max_by_key(|(len, _)| *len),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .filter_map(|(index, child)| longest_string(child, &format!("{pointer}/{index}")))
            .max_by_key(|(len, _)| *len),
        _ => None,
    }
}

fn encoded_len(s: &str) -> usize {
    s.chars()
        .map(|c| if needs_escape(c) { 6 } else { c.len_utf8() })
        .sum()
}

fn needs_escape(c: char) -> bool {
    c.is_control() || c == '"' || c == '\\' || c == '\u{2028}' || c == '\u{2029}'
}

fn encode(value: &Value) -> Result<String, AuditError> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, EscapingFormatter);
    value.serialize(&mut ser)?;
    // serde_json only ever writes UTF-8.
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `serde_json`'s compact formatter, plus `\uXXXX` for DEL, C1 controls and U+2028/U+2029,
/// which `serde_json` leaves raw. C0 controls are already escaped before they get here.
struct EscapingFormatter;

impl serde_json::ser::Formatter for EscapingFormatter {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (index, c) in fragment.char_indices() {
            if needs_escape(c) {
                writer.write_all(fragment.get(start..index).unwrap_or_default().as_bytes())?;
                write!(writer, "\\u{:04x}", u32::from(c))?;
                start = index + c.len_utf8();
            }
        }
        writer.write_all(fragment.get(start..).unwrap_or_default().as_bytes())
    }
}

/// Per-workspace limit on `connection` records (R-26): at most `limit` per wall-clock second; the
/// excess is counted and written as one summary record when the second is over.
#[derive(Debug, Default)]
pub(crate) struct ConnectionWindow {
    second: u64,
    written: u32,
    excess: u64,
    /// A summary whose audit write failed: `(second_start_ms, count)`, handed out again by the
    /// next [`ConnectionWindow::roll`].
    owed: Option<(u64, u64)>,
}

impl ConnectionWindow {
    /// Whether a record at `now` may be written, and a summary `(second_start_ms, count)` for a
    /// finished second that had excess.
    pub(crate) fn admit(&mut self, now: u64, limit: u32) -> (bool, Option<(u64, u64)>) {
        let finished = self.roll(now);
        if self.written < limit {
            self.written += 1;
            (true, finished)
        } else {
            self.excess += 1;
            (false, finished)
        }
    }

    /// The summary of a finished second with excess, if `now` is past it, merged with one owed
    /// from a failed write.
    pub(crate) fn roll(&mut self, now: u64) -> Option<(u64, u64)> {
        let second = now / 1000;
        let finished = if second == self.second {
            None
        } else {
            let finished = (self.excess > 0).then_some((self.second * 1000, self.excess));
            *self = Self {
                second,
                written: 0,
                excess: 0,
                owed: self.owed,
            };
            finished
        };
        match (self.owed.take(), finished) {
            (Some((a_ts, a)), Some((b_ts, b))) => Some((a_ts.min(b_ts), a + b)),
            (owed, finished) => owed.or(finished),
        }
    }

    /// Keeps a summary whose audit write failed, to hand out again.
    pub(crate) fn owe(&mut self, ts: u64, count: u64) {
        self.owed = match self.owed {
            Some((owed_ts, owed)) => Some((owed_ts.min(ts), owed + count)),
            None => Some((ts, count)),
        };
    }
}

/// Maps a stored actor to the wire string.
pub(crate) fn actor_str(actor: Actor) -> String {
    actor.as_str().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pending::PendingState;
    use proptest::prelude::*;
    use puddle_types::{BlockReason, EgressRequest, Host, HttpRequestLine, LocalCategory, RuleId};
    use serde_json::json;

    const CANARY: &str = "CANARY-7f3a9c";

    fn sb() -> WorkspaceName {
        WorkspaceName::new("sb-1").unwrap()
    }

    fn event() -> ConnectionEvent {
        let request = EgressRequest::new(
            sb(),
            Host::parse_normalised("api.example.com").unwrap(),
            443,
        );
        let mut event =
            ConnectionEvent::new(&request, ConnectionDecision::Allow, ConnectionReason::Rule);
        event.resolved_ip = Some("93.184.216.34".parse().unwrap());
        event.rule_id = Some(RuleId(4));
        event.binding_id = Some("github".into());
        event.injected = true;
        event.http = Some(HttpRequestLine::new("GET", "/v1/items?id=1"));
        event.bytes_up = 10;
        event.bytes_down = 20;
        event
    }

    fn rule_wire() -> RuleWire {
        RuleWire {
            id: 1,
            scope: "workspace".into(),
            workspace_id: Some("sb-1".into()),
            pattern_kind: "exact".into(),
            pattern: "example.com".into(),
            effect: "allow".into(),
            expires_at: None,
            created_at: 5,
            created_by: "cli".into(),
            source_pending_id: Some(2),
            set_id: None,
        }
    }

    fn pending_wire() -> PendingWire {
        PendingWire {
            id: 2,
            workspace_id: "sb-1".into(),
            host: "example.com".into(),
            port: 443,
            first_seen: 1,
            last_seen: 2,
            attempts: 3,
            state: PendingState::Requested.as_str().into(),
            decided_at: None,
            decided_by: None,
            rule_id: None,
            rule_set: None,
        }
    }

    fn every_record() -> Vec<AuditRecord> {
        vec![
            AuditRecord::Connection(ConnectionRecord::from_event(9, &event())),
            AuditRecord::Connection(ConnectionRecord::suppressed_summary(9, Some(&sb()), 12)),
            AuditRecord::PendingCreated {
                ts: 9,
                pending: pending_wire(),
            },
            AuditRecord::PendingDecided {
                ts: 9,
                pending: pending_wire(),
            },
            AuditRecord::PendingExpired {
                ts: 9,
                pending: pending_wire(),
                reason: PendingExpiryReason::Stale,
            },
            AuditRecord::PendingSuppressed {
                ts: 9,
                workspace_id: "sb-1".into(),
                count: 3,
            },
            AuditRecord::RuleCreated {
                ts: 9,
                rule: rule_wire(),
            },
            AuditRecord::RuleUpdated {
                ts: 9,
                before: rule_wire(),
                rule: rule_wire(),
                actor: "ui".into(),
            },
            AuditRecord::RuleDeleted {
                ts: 9,
                rule: rule_wire(),
                reason: RuleDeleteReason::WorkspaceDeleted,
                actor: "system".into(),
            },
            AuditRecord::RuleExpired {
                ts: 9,
                rule: rule_wire(),
            },
            AuditRecord::AuditTrimmed {
                ts: 9,
                deleted_records: 100,
                oldest_ts_kept: None,
            },
        ]
    }

    /// Lines written before a workspace was called a sandbox in the audit still read: the owner's
    /// key, the connection origin, the rule scope and the deletion reason, each under the old name.
    #[test]
    fn lines_written_with_the_old_names_still_read() {
        let rule = |scope: &str| {
            json!({"id": 1, "scope": scope, "sandbox_id": "sb-1", "pattern_kind": "exact",
                "pattern": "example.com", "effect": "allow", "expires_at": null, "created_at": 5,
                "created_by": "cli", "source_pending_id": null})
        };
        let pending = json!({"id": 2, "sandbox_id": "sb-1", "host": "example.com", "port": 443,
            "first_seen": 1, "last_seen": 2, "attempts": 3, "state": "requested",
            "decided_at": null, "decided_by": null, "rule_id": null});
        let old = [
            json!({"type": "connection", "ts": 9, "sandbox_id": "sb-1", "origin": "sandbox",
                "host": "example.com", "port": 443, "resolved_ip": null, "decision": "allow",
                "reason": "rule", "rule_id": 1, "pending_id": null, "binding_id": null,
                "injected": false, "method": null, "path": null, "path_truncated": false,
                "bytes_up": 0, "bytes_down": 0, "count": null}),
            json!({"type": "pending_expired", "ts": 9, "pending": pending, "reason": "sandbox_deleted"}),
            json!({"type": "pending_suppressed", "ts": 9, "sandbox_id": "sb-1", "count": 3}),
            json!({"type": "rule_deleted", "ts": 9, "rule": rule("sandbox"),
                "reason": "sandbox_deleted", "actor": "system"}),
            json!({"type": "rule_set_switched", "ts": 9, "set_id": "builtin:x",
                "sandbox_id": null, "enabled": true, "actor": "ui"}),
        ];
        for line in old {
            let record: AuditRecord = serde_json::from_value(line.clone()).unwrap();
            assert_eq!(
                record.workspace_id().is_some(),
                line["type"] != "rule_set_switched"
            );
            let written = serde_json::to_string(&record).unwrap();
            assert!(!written.contains("sandbox"), "{written}");
        }
        let record: AuditRecord = serde_json::from_value(
            json!({"type": "rule_created", "ts": 9, "rule": rule("sandbox")}),
        )
        .unwrap();
        assert!(
            matches!(record, AuditRecord::RuleCreated { rule, .. } if rule.scope == "workspace")
        );
    }

    /// A line written before the flag existed reads as not flagged.
    #[test]
    fn a_connection_line_without_the_stand_in_flag_reads_as_not_flagged() {
        let line = json!({"type": "connection", "ts": 9, "workspace_id": "sb-1",
            "origin": "workspace", "host": "example.com", "port": 443, "resolved_ip": null,
            "decision": "allow", "reason": "rule", "rule_id": 1, "pending_id": null,
            "binding_id": null, "injected": false, "method": null, "path": null,
            "path_truncated": false, "bytes_up": 0, "bytes_down": 0, "count": null});
        let record: AuditRecord = serde_json::from_value(line).unwrap();
        assert!(matches!(
            record,
            AuditRecord::Connection(ConnectionRecord {
                placeholder_unbound: false,
                ..
            })
        ));
        let flagged = ConnectionRecord::from_event(1, &{
            let mut event = event();
            event.placeholder_unbound = true;
            event
        });
        assert!(flagged.placeholder_unbound);
    }

    #[test]
    fn r23_records_are_internally_tagged_snake_case_with_nulls_written() {
        for record in every_record() {
            let line = record.to_line().unwrap();
            let value: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["type"], record.kind(), "{line}");
            assert_eq!(value["ts"], 9);
            let back: AuditRecord = serde_json::from_str(&line).unwrap();
            assert_eq!(back, record);
        }
        let line =
            AuditRecord::Connection(ConnectionRecord::suppressed_summary(9, Some(&sb()), 12))
                .to_line()
                .unwrap();
        assert!(line.contains(r#""host":null"#), "{line}");
        assert!(line.contains(r#""reason":"suppressed""#));
        assert!(line.contains(r#""count":12"#));
    }

    #[test]
    fn r23_control_characters_come_out_escaped() {
        let mut e = event();
        e.binding_id = Some("a\u{1b}[31m\u{7f}\u{9b}\u{2028}\n\"\\z".into());
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e))
            .to_line()
            .unwrap();
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(!line.contains('\u{2028}'));
        assert!(
            line.contains(r#"a\u001b[31m\u007f\u009b\u2028\n\"\\z"#),
            "{line}"
        );
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["binding_id"], e.binding_id.unwrap());
    }

    #[test]
    fn r24_record_types_and_connection_fields() {
        let kinds: Vec<_> = every_record().iter().map(AuditRecord::kind).collect();
        for kind in [
            "connection",
            "pending_created",
            "pending_decided",
            "pending_expired",
            "pending_suppressed",
            "rule_created",
            "rule_updated",
            "rule_deleted",
            "rule_expired",
            "audit_trimmed",
        ] {
            assert!(kinds.contains(&kind), "{kind}");
        }
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &event()))
            .to_line()
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        let fields: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        for field in [
            "type",
            "ts",
            "workspace_id",
            "host",
            "port",
            "resolved_ip",
            "upstream",
            "decision",
            "reason",
            "rule_id",
            "pending_id",
            "binding_id",
            "injected",
            "placeholder_unbound",
            "method",
            "path",
            "path_truncated",
            "bytes_up",
            "bytes_down",
            "count",
        ] {
            assert!(fields.iter().any(|f| f == field), "{field}");
        }
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["path"], "/v1/items");
    }

    #[test]
    fn r24_reason_and_decision_reach_the_record_as_codes() {
        let mut e = event();
        e.decision = ConnectionDecision::Blocked;
        e.reason = ConnectionReason::Blocked(BlockReason::LocalToggle(LocalCategory::Private));
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e))
            .to_line()
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["decision"], "blocked");
        assert_eq!(value["reason"], "toggle:private");
    }

    #[test]
    fn r25_no_secrets_in_connection_records() {
        let mut e = event();
        e.http = Some(HttpRequestLine::new(
            "POST",
            &format!("https://user:{CANARY}@api.example.com/login?token={CANARY}#{CANARY}"),
        ));
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e))
            .to_line()
            .unwrap();
        assert!(!line.contains(CANARY), "{line}");
        assert!(line.contains(r#""path":"/login""#), "{line}");
    }

    #[test]
    fn r25_query_string_is_dropped_even_from_a_hand_built_record() {
        let mut record = ConnectionRecord::from_event(1, &event());
        record.path = Some(format!("/a?secret={CANARY}"));
        let line = AuditRecord::Connection(record).to_line().unwrap();
        assert!(!line.contains(CANARY), "{line}");
    }

    #[test]
    fn r25_every_record_type_carries_no_secret_fields() {
        // Credential material has no field to go in; this pins that no record grows one.
        for record in every_record() {
            let line = record.to_line().unwrap();
            for word in [
                "header",
                "authorization",
                "cookie",
                "body",
                "query",
                "token",
                "secret",
            ] {
                assert!(!line.contains(word), "{word} in {line}");
            }
        }
    }

    #[test]
    fn r26_path_cut_to_1kib_and_flagged() {
        let mut e = event();
        e.http = Some(HttpRequestLine::new(
            "GET",
            &format!("/{}", "é".repeat(2000)),
        ));
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e))
            .to_line()
            .unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        assert!(value["path"].as_str().unwrap().len() <= MAX_FIELD_BYTES);
        assert_eq!(value["path_truncated"], true);
    }

    #[test]
    fn r26_line_never_exceeds_4kib_even_with_escapes() {
        let mut e = event();
        let nasty = "\u{1}".repeat(1024);
        e.binding_id = Some(nasty.clone());
        e.http = Some(HttpRequestLine::new(nasty.clone(), &format!("/{nasty}")));
        let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e))
            .to_line()
            .unwrap();
        assert!(line.len() <= MAX_LINE_BYTES, "{}", line.len());
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["path_truncated"], true);
    }

    #[test]
    fn connection_window_counts_excess_per_second() {
        let mut w = ConnectionWindow::default();
        assert_eq!(w.admit(5_000, 2), (true, None));
        assert_eq!(w.admit(5_100, 2), (true, None));
        assert_eq!(w.admit(5_200, 2), (false, None));
        assert_eq!(w.admit(5_999, 2), (false, None));
        assert_eq!(w.admit(6_000, 2), (true, Some((5_000, 2))));
        assert_eq!(w.roll(6_500), None);
        assert_eq!(w.roll(9_000), None);
    }

    #[test]
    fn a_summary_whose_write_failed_is_handed_out_again_merged_with_the_next_one() {
        let mut w = ConnectionWindow::default();
        assert_eq!(w.admit(5_000, 1), (true, None));
        assert_eq!(w.admit(5_100, 1), (false, None));
        // The second ended, its summary was taken and its write failed twice.
        assert_eq!(w.roll(6_000), Some((5_000, 1)));
        w.owe(5_000, 1);
        w.owe(4_000, 2);
        assert_eq!(
            w.roll(6_100),
            Some((4_000, 3)),
            "owed counts add up, oldest second"
        );
        assert_eq!(w.roll(6_200), None, "handed out once");
        // Owed while the next second also had excess: both come out as one summary.
        assert_eq!(w.admit(6_300, 1), (true, None));
        assert_eq!(w.admit(6_400, 1), (false, None));
        w.owe(5_000, 4);
        assert_eq!(w.roll(7_000), Some((5_000, 5)));
    }

    #[test]
    fn actor_strings() {
        assert_eq!(actor_str(Actor::Ui), "ui");
    }

    proptest! {
        #[test]
        fn r26_any_strings_give_a_parseable_line_within_the_cap(
            binding in ".{0,1500}",
            target in ".{0,3000}",
            method in ".{0,1500}",
        ) {
            let mut e = event();
            e.binding_id = Some(binding);
            e.http = Some(HttpRequestLine::new(method, &target));
            let line = AuditRecord::Connection(ConnectionRecord::from_event(1, &e)).to_line().unwrap();
            prop_assert!(line.len() <= MAX_LINE_BYTES);
            prop_assert!(!line.chars().any(char::is_control));
            let value: Value = serde_json::from_str(&line).unwrap();
            prop_assert_eq!(&value["type"], "connection");
            prop_assert!(!value["path"].as_str().unwrap().contains('?'));
        }
    }

    #[test]
    fn kinds_lists_every_type_tag_once() {
        let kinds: Vec<&str> = every_record().iter().map(AuditRecord::kind).collect();
        for kind in kinds {
            assert!(AuditRecord::KINDS.contains(&kind), "{kind}");
        }
        let mut sorted = AuditRecord::KINDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), AuditRecord::KINDS.len());
    }

    #[test]
    fn host_and_outcome_per_record_kind() {
        let mut denied = pending_wire();
        denied.state = "denied".into();
        let mut allowed = pending_wire();
        allowed.state = "allowed".into();
        let decided = |pending| AuditRecord::PendingDecided { ts: 1, pending };
        assert_eq!(decided(allowed).outcome(), Some(AuditOutcome::Allow));
        assert_eq!(decided(denied).outcome(), Some(AuditOutcome::Deny));
        assert_eq!(decided(pending_wire()).outcome(), None);
        let mut upper = rule_wire();
        upper.pattern = ".Example.COM".into();
        let created = AuditRecord::RuleCreated { ts: 1, rule: upper };
        assert_eq!(created.host().as_deref(), Some(".example.com"));
        assert_eq!(created.outcome(), None);
        let summary =
            AuditRecord::Connection(ConnectionRecord::suppressed_summary(1, Some(&sb()), 5));
        assert_eq!((summary.host(), summary.outcome()), (None, None));
        for decision in [
            ConnectionDecision::Allow,
            ConnectionDecision::Deny,
            ConnectionDecision::Pending,
            ConnectionDecision::Blocked,
        ] {
            let mut record = ConnectionRecord::from_event(1, &event());
            record.decision = Some(decision);
            let outcome = AuditRecord::Connection(record).outcome().unwrap();
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                serde_json::to_value(decision).unwrap()
            );
        }
        for outcome in AuditOutcome::ALL {
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                outcome.as_str(),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn migration_backfills_host_and_outcome_as_the_code_derives_them() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::schema::migrate_up_to(&mut conn, 1).unwrap();
        let mut records = every_record();
        let mut allowed = pending_wire();
        allowed.state = "allowed".into();
        let mut denied = pending_wire();
        denied.state = "denied".into();
        records.extend([
            AuditRecord::PendingDecided {
                ts: 9,
                pending: allowed,
            },
            AuditRecord::PendingDecided {
                ts: 9,
                pending: denied,
            },
        ]);
        // The database as version 1 left it: the owner column still has its old name.
        for record in &records {
            conn.execute(
                "INSERT INTO audit (ts, type, sandbox_id, line) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    i64::try_from(record.ts()).unwrap(),
                    record.kind(),
                    record.workspace_id(),
                    record.to_line().unwrap()
                ],
            )
            .unwrap();
        }
        crate::schema::migrate(&mut conn).unwrap();
        let mut stmt = conn
            .prepare("SELECT type, host, outcome FROM audit ORDER BY id")
            .unwrap();
        let rows: Vec<(String, Option<String>, Option<String>)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(rows.len(), records.len());
        for (record, (kind, host, outcome)) in records.iter().zip(rows) {
            assert_eq!(kind, record.kind());
            assert_eq!(host, record.host(), "{kind} host");
            assert_eq!(
                outcome.as_deref(),
                record.outcome().map(AuditOutcome::as_str),
                "{kind} outcome"
            );
        }
    }
}
