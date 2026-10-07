// SPDX-License-Identifier: GPL-3.0-or-later
//! The audit log (docs/spec/rules.md §5).

use axum::Json;
use axum::extract::State;
use puddle_store::{AuditCursor, AuditFilter};
use puddle_types::SandboxName;
use serde::Deserialize;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Query;
use crate::routes::AppState;
use crate::wire::{AuditEntry, AuditOutcome, AuditPage, AuditRecord, AuditType, ConnectionOrigin};

/// Records per page when the client doesn't say.
const DEFAULT_LIMIT: u32 = 100;
/// Most records per page.
const MAX_LIMIT: u32 = 500;
/// Longest `host_contains`, in bytes (a host name is at most 253).
const MAX_HOST_NEEDLE: usize = 253;

/// Which records to read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditQuery {
    after: Option<i64>,
    before: Option<i64>,
    limit: Option<u32>,
    sandbox: Option<String>,
    #[serde(rename = "type")]
    kind: Option<AuditType>,
    outcome: Option<AuditOutcome>,
    origin: Option<ConnectionOrigin>,
    host_contains: Option<String>,
    from: Option<u64>,
    to: Option<u64>,
}

impl AuditQuery {
    /// The filter and the cursor, or why the query is refused.
    fn parse(self) -> Result<(AuditFilter, AuditCursor, u32), ApiError> {
        let limit = self.limit.unwrap_or(DEFAULT_LIMIT);
        if !(1..=MAX_LIMIT).contains(&limit) {
            return Err(ApiError::invalid(format!(
                "limit must be between 1 and {MAX_LIMIT}"
            )));
        }
        let cursor = match (self.after, self.before) {
            (Some(_), Some(_)) => {
                return Err(ApiError::invalid("after and before can't be combined"));
            }
            (Some(after), None) => AuditCursor::After(after),
            (None, before) => AuditCursor::Before(before),
        };
        let sandbox = self
            .sandbox
            .filter(|s| !s.is_empty())
            .map(|s| {
                SandboxName::new(&s).map_err(|err| ApiError::invalid(format!("sandbox: {err}")))
            })
            .transpose()?;
        let host_contains = self.host_contains.filter(|h| !h.is_empty());
        if host_contains
            .as_ref()
            .is_some_and(|h| h.len() > MAX_HOST_NEEDLE)
        {
            return Err(ApiError::invalid(format!(
                "host_contains is at most {MAX_HOST_NEEDLE} bytes"
            )));
        }
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from >= to
        {
            return Err(ApiError::invalid("from must be before to"));
        }
        let filter = AuditFilter {
            sandbox,
            kind: self.kind.map(AuditType::tag),
            outcome: self.outcome.map(Into::into),
            origin: self.origin.map(Into::into),
            host_contains,
            from: self.from,
            to: self.to,
        };
        Ok((filter, cursor, limit))
    }
}

/// A page of the audit log, filtered on the server. Without `after` the newest matching records
/// come first and `before` pages back; with `after` the records come oldest first, for following
/// the tail.
#[utoipa::path(
    get,
    path = "/api/audit",
    tag = "audit",
    params(
        ("after" = Option<i64>, Query, description = "records after this id, oldest first (to follow the tail)"),
        ("before" = Option<i64>, Query, description = "records before this id, newest first (to page back); can't be combined with `after`"),
        ("limit" = Option<u32>, Query, minimum = 1, maximum = 500, description = "records per page (default 100)"),
        ("sandbox" = Option<String>, Query, description = "records about this sandbox"),
        ("type" = Option<AuditType>, Query, description = "records of this type"),
        ("outcome" = Option<AuditOutcome>, Query, description = "records with this outcome; types that have none never match"),
        ("origin" = Option<ConnectionOrigin>, Query, description = "`connection` records of this origin (`sandbox` or `puddle`); other types have none and never match"),
        ("host_contains" = Option<String>, Query, description = "records whose host (a rule's pattern) contains this text, case-insensitive"),
        ("from" = Option<u64>, Query, description = "records at or after this epoch ms"),
        ("to" = Option<u64>, Query, description = "records before this epoch ms")
    ),
    responses(
        (status = OK, description = "audit records", body = AuditPage),
        (status = BAD_REQUEST, description = "invalid query", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a filter or the limit out of range", body = ApiErrorBody)
    )
)]
pub(crate) async fn audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, ApiError> {
    let after = query.after;
    let (filter, cursor, limit) = query.parse()?;
    let lines = blocking(move || Ok(state.store.audit_query(&filter, cursor, limit)?)).await?;
    let entries = lines
        .iter()
        .map(|(id, line)| {
            let record: puddle_store::AuditRecord = serde_json::from_str(line).map_err(|err| {
                ApiError::internal(&format_args!("audit record {id} is not a record: {err}"))
            })?;
            Ok(AuditEntry {
                id: *id,
                record: AuditRecord::from(record),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let newest = lines.iter().map(|(id, _)| *id).max();
    let oldest = lines.iter().map(|(id, _)| *id).min();
    let full = lines.len() == limit as usize;
    let next_before = match cursor {
        AuditCursor::Before(_) if full => oldest,
        _ => None,
    };
    Ok(Json(AuditPage {
        entries,
        next_after: newest.or(after).unwrap_or(0),
        next_before,
    }))
}
