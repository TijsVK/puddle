// SPDX-License-Identifier: GPL-3.0-or-later
//! Pending requests: list, inbox, approve, deny (docs/spec/rules.md §3).

use axum::Json;
use axum::extract::State;
use puddle_store::Actor;
use puddle_types::{PendingId, SandboxName};
use serde::Deserialize;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::{Path, Query};
use crate::routes::AppState;
use crate::wire::{
    DecisionOutcome, DecisionRequest, Effect, Inbox, InboxGroup, PendingList, PendingRequest,
    Suppression,
};

/// Which open requests to list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingQuery {
    /// Only this sandbox's requests. All sandboxes if left out.
    sandbox: Option<SandboxName>,
}

/// Open (`requested`) requests, most recent first.
#[utoipa::path(
    get,
    path = "/api/pending",
    tag = "pending",
    params(("sandbox" = Option<SandboxName>, Query, description = "only this sandbox's requests")),
    responses(
        (status = OK, description = "open requests", body = PendingList),
        (status = BAD_REQUEST, description = "invalid sandbox name", body = ApiErrorBody)
    )
)]
pub(crate) async fn list_pending(
    State(state): State<AppState>,
    Query(query): Query<PendingQuery>,
) -> Result<Json<PendingList>, ApiError> {
    let rows = blocking(move || Ok(state.store.open_pending(query.sandbox.as_ref())?)).await?;
    Ok(Json(PendingList {
        requests: rows
            .into_iter()
            .map(PendingRequest::from_store)
            .collect::<Result<_, _>>()?,
    }))
}

/// Open requests grouped by registrable domain, most recent group first (R-18).
#[utoipa::path(
    get,
    path = "/api/inbox",
    tag = "pending",
    responses((status = OK, description = "the inbox", body = Inbox))
)]
pub(crate) async fn inbox(State(state): State<AppState>) -> Result<Json<Inbox>, ApiError> {
    let groups = blocking(move || Ok(state.store.inbox()?)).await?;
    let groups = groups
        .into_iter()
        .map(|g| {
            Ok(InboxGroup {
                registrable_domain: g.registrable_domain,
                requests: g
                    .rows
                    .into_iter()
                    .map(PendingRequest::from_store)
                    .collect::<Result<_, ApiError>>()?,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(Inbox { groups }))
}

/// One pending request, in any state.
#[utoipa::path(
    get,
    path = "/api/pending/{id}",
    tag = "pending",
    params(("id" = i64, Path, description = "pending request id")),
    responses(
        (status = OK, description = "the request", body = PendingRequest),
        (status = NOT_FOUND, description = "no such request", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_pending(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<PendingRequest>, ApiError> {
    let row = blocking(move || Ok(state.store.pending(PendingId(id))?)).await?;
    Ok(Json(PendingRequest::from_store(row)?))
}

/// Approves an open request: creates an allow rule (this sandbox, exact host, permanent unless
/// the body says otherwise) and closes the other open requests it now decides.
#[utoipa::path(
    post,
    path = "/api/pending/{id}/approve",
    tag = "pending",
    params(("id" = i64, Path, description = "pending request id")),
    request_body = DecisionRequest,
    responses(
        (status = OK, description = "approved", body = DecisionOutcome),
        (status = NOT_FOUND, description = "no such request", body = ApiErrorBody),
        (status = CONFLICT, description = "already decided or expired", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "invalid suffix or expiry", body = ApiErrorBody)
    )
)]
pub(crate) async fn approve(
    state: State<AppState>,
    id: Path<i64>,
    body: crate::extract::Json<DecisionRequest>,
) -> Result<Json<DecisionOutcome>, ApiError> {
    decide(state, id, body, Effect::Allow).await
}

/// Denies an open request: creates a deny rule (this sandbox, exact host, permanent unless the
/// body says otherwise) and closes the other open requests it now decides.
#[utoipa::path(
    post,
    path = "/api/pending/{id}/deny",
    tag = "pending",
    params(("id" = i64, Path, description = "pending request id")),
    request_body = DecisionRequest,
    responses(
        (status = OK, description = "denied", body = DecisionOutcome),
        (status = NOT_FOUND, description = "no such request", body = ApiErrorBody),
        (status = CONFLICT, description = "already decided or expired", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "invalid suffix or expiry", body = ApiErrorBody)
    )
)]
pub(crate) async fn deny(
    state: State<AppState>,
    id: Path<i64>,
    body: crate::extract::Json<DecisionRequest>,
) -> Result<Json<DecisionOutcome>, ApiError> {
    decide(state, id, body, Effect::Deny).await
}

async fn decide(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    crate::extract::Json(body): crate::extract::Json<DecisionRequest>,
    effect: Effect,
) -> Result<Json<DecisionOutcome>, ApiError> {
    let resolution = body.into_resolution(effect)?;
    let decided = blocking(move || {
        Ok(state
            .store
            .resolve_pending(PendingId(id), &resolution, Actor::Api)?)
    })
    .await?;
    Ok(Json(DecisionOutcome::from_store(decided)?))
}

/// Whether a sandbox's new pending requests are being suppressed (R-13), for the inbox's
/// "N requests suppressed" line.
#[utoipa::path(
    get,
    path = "/api/sandboxes/{sandbox}/suppression",
    tag = "pending",
    params(("sandbox" = SandboxName, Path, description = "sandbox name")),
    responses(
        (status = OK, description = "the sandbox's suppression state", body = Suppression),
        (status = BAD_REQUEST, description = "invalid sandbox name", body = ApiErrorBody)
    )
)]
pub(crate) async fn suppression(
    State(state): State<AppState>,
    Path(sandbox): Path<SandboxName>,
) -> Json<Suppression> {
    let s = state.store.suppression(&sandbox);
    Json(Suppression {
        sandbox,
        active: s.active,
        count: s.count,
    })
}
