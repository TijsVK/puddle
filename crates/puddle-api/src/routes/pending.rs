// SPDX-License-Identifier: GPL-3.0-or-later
//! Pending requests: list, inbox, approve, deny (docs/spec/rules.md §3).

use axum::Json;
use axum::extract::State;
use std::collections::HashMap;

use puddle_netpolicy::{Target, classify_ip};
use puddle_settings::resolve;
use puddle_store::{Actor, PendingRow, PendingState};
use puddle_types::{Host, LocalCategory, PendingId, WorkspaceName};
use serde::Deserialize;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::{Path, Query};
use crate::routes::AppState;
use crate::routes::settings::{load_global, load_workspace};
use crate::wire::{
    DecisionOutcome, DecisionRequest, Effect, Inbox, InboxGroup, PendingList, PendingRequest,
    Suppression,
};

/// Which open requests to list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingQuery {
    /// Only this workspace's requests. All workspaces if left out.
    workspace: Option<WorkspaceName>,
}

/// The local category a destination is in by itself: an IP literal's class, or a name such as
/// `localhost` or the metadata names. Other names are classified by what they resolve to, which
/// puddle only knows when the connection is made.
fn local_category(host: &Host) -> Option<LocalCategory> {
    match host {
        Host::Ip(ip) => classify_ip(*ip).category(),
        Host::Name(_) => Target::from_host(host.clone()).named_category(),
    }
}

/// Maps rows to wire requests, naming for each open one the local-destination toggle that blocks
/// its approval. Settings are read only if some open row is to a local destination; a workspace
/// whose settings can't be read counts as unblocked (the decision itself never depends on this).
async fn present(state: &AppState, rows: Vec<PendingRow>) -> Result<Vec<PendingRequest>, ApiError> {
    let wanted = rows
        .iter()
        .any(|r| r.state == PendingState::Requested && local_category(&r.host).is_some());
    let blocked: HashMap<PendingId, LocalCategory> = if wanted {
        let _lock = state.settings_lock.lock().await;
        let settings = state.settings.clone();
        let candidates: Vec<(PendingId, WorkspaceName, LocalCategory)> = rows
            .iter()
            .filter(|r| r.state == PendingState::Requested)
            .filter_map(|r| Some((r.id, r.workspace.clone(), local_category(&r.host)?)))
            .collect();
        blocking(move || {
            let repo = settings.as_ref();
            let Ok(global) = load_global(repo) else {
                tracing::warn!("global settings unreadable; no pending request is marked blocked");
                return Ok(HashMap::new());
            };
            let mut per_workspace = HashMap::new();
            let mut blocked = HashMap::new();
            for (id, workspace, category) in candidates {
                let loaded = per_workspace
                    .entry(workspace.clone())
                    .or_insert_with(|| load_workspace(repo, &workspace).ok());
                let Some(loaded) = loaded else { continue };
                let effective = resolve(&global.settings, Some(&loaded.settings));
                if !effective.local_toggles.get(category).value {
                    blocked.insert(id, category);
                }
            }
            Ok(blocked)
        })
        .await?
    } else {
        HashMap::new()
    };
    rows.into_iter()
        .map(|row| {
            let id = row.id;
            let mut request = PendingRequest::from_store(row)?;
            request.blocked_by = blocked.get(&id).copied();
            Ok(request)
        })
        .collect()
}

/// Open (`requested`) requests, most recent first.
#[utoipa::path(
    get,
    path = "/api/pending",
    tag = "pending",
    params(("workspace" = Option<WorkspaceName>, Query, description = "only this workspace's requests")),
    responses(
        (status = OK, description = "open requests", body = PendingList),
        (status = BAD_REQUEST, description = "invalid workspace name", body = ApiErrorBody)
    )
)]
pub(crate) async fn list_pending(
    State(state): State<AppState>,
    Query(query): Query<PendingQuery>,
) -> Result<Json<PendingList>, ApiError> {
    let store = state.store.clone();
    let rows = blocking(move || Ok(store.open_pending(query.workspace.as_ref())?)).await?;
    Ok(Json(PendingList {
        requests: present(&state, rows).await?,
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
    let store = state.store.clone();
    let groups = blocking(move || Ok(store.inbox()?)).await?;
    let mut out = Vec::with_capacity(groups.len());
    for group in groups {
        out.push(InboxGroup {
            registrable_domain: group.registrable_domain,
            requests: present(&state, group.rows).await?,
        });
    }
    Ok(Json(Inbox { groups: out }))
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
    let store = state.store.clone();
    let row = blocking(move || Ok(store.pending(PendingId(id))?)).await?;
    Ok(Json(present(&state, vec![row]).await?.remove(0)))
}

/// Approves an open request: creates an allow rule (this workspace, exact host, permanent unless
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

/// Denies an open request: creates a deny rule (this workspace, exact host, permanent unless the
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

/// Whether a workspace's new pending requests are being suppressed (R-13), for the inbox's
/// "N requests suppressed" line.
#[utoipa::path(
    get,
    path = "/api/workspaces/{workspace}/suppression",
    tag = "pending",
    params(("workspace" = WorkspaceName, Path, description = "workspace name")),
    responses(
        (status = OK, description = "the workspace's suppression state", body = Suppression),
        (status = BAD_REQUEST, description = "invalid workspace name", body = ApiErrorBody)
    )
)]
pub(crate) async fn suppression(
    State(state): State<AppState>,
    Path(workspace): Path<WorkspaceName>,
) -> Json<Suppression> {
    let s = state.store.suppression(&workspace);
    Json(Suppression {
        workspace,
        active: s.active,
        count: s.count,
    })
}
