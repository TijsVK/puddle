// SPDX-License-Identifier: GPL-3.0-or-later
//! The audit log (docs/spec/rules.md §5).

use axum::Json;
use axum::extract::State;
use serde::Deserialize;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Query;
use crate::routes::AppState;
use crate::wire::{AuditEntry, AuditPage};

/// Records per page when the client doesn't say.
const DEFAULT_LIMIT: u32 = 100;
/// Most records per page.
const MAX_LIMIT: u32 = 1000;

/// Which records to read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditQuery {
    /// Records after this id (default 0: from the start).
    after: Option<i64>,
    /// Records per page, 1 to 1000 (default 100).
    limit: Option<u32>,
}

/// A page of the audit log, oldest first.
#[utoipa::path(
    get,
    path = "/api/audit",
    tag = "audit",
    params(
        ("after" = Option<i64>, Query, description = "records after this id (default 0: from the start)"),
        ("limit" = Option<u32>, Query, minimum = 1, maximum = 1000, description = "records per page (default 100)")
    ),
    responses(
        (status = OK, description = "audit records", body = AuditPage),
        (status = BAD_REQUEST, description = "invalid query", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "limit out of range", body = ApiErrorBody)
    )
)]
pub(crate) async fn audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditPage>, ApiError> {
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::invalid(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let lines = blocking(move || Ok(state.store.audit_lines(after, limit)?)).await?;
    let next_after = lines.last().map_or(after, |(id, _)| *id);
    let entries = lines
        .into_iter()
        .map(|(id, line)| {
            let record = serde_json::from_str(&line).map_err(|err| {
                ApiError::internal(&format_args!("audit record {id} is not JSON: {err}"))
            })?;
            Ok(AuditEntry { id, record })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(AuditPage {
        entries,
        next_after,
    }))
}
