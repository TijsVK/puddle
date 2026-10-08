// SPDX-License-Identifier: GPL-3.0-or-later
//! Workspaces: list, create, detail, start, stop, reclaim space, the delete check, delete and
//! attach. The routes only translate; [`crate::WorkspaceService`] does the work. Long
//! operations answer 202 with the workspace marked busy and report through `status_changed` and
//! `workspace_progress` events.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_settings::resolve;
use puddle_types::WorkspaceId;

use crate::ApiErrorBody;
use crate::WorkspaceRecord;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{
    AttachRequest, AttachResponse, DeleteCheck, DeleteWorkspaceRequest, NewWorkspaceRequest,
    Workspace, WorkspaceList,
};

/// The id in a path. A string that can't be an id names no workspace.
fn workspace_id(raw: &str) -> Result<WorkspaceId, ApiError> {
    WorkspaceId::new(raw).map_err(|_| ApiError::not_found(format!("no workspace {raw:?}")))
}

/// Whether direct SSH is on for each workspace, in order. A settings document that cannot be
/// read counts as off: the answer fails closed, as the host's own check does.
async fn direct_ssh_of(state: &AppState, records: &[WorkspaceRecord]) -> Vec<bool> {
    let names: Vec<_> = records.iter().map(|r| r.name.clone()).collect();
    let settings = state.settings.clone();
    let _lock = state.settings_lock.lock().await;
    blocking(move || {
        let repo = settings.as_ref();
        let global = crate::routes::settings::load_global(repo)?;
        Ok(names
            .iter()
            .map(|name| {
                crate::routes::settings::load_sandbox(repo, name).is_ok_and(|own| {
                    resolve(&global.settings, Some(&own.settings))
                        .direct_ssh
                        .value
                })
            })
            .collect())
    })
    .await
    .unwrap_or_else(|_| vec![false; records.len()])
}

/// Whether direct SSH is on for one workspace.
async fn direct_ssh_on(state: &AppState, record: WorkspaceRecord) -> bool {
    direct_ssh_of(state, &[record]).await.first() == Some(&true)
}

/// The workspaces as the API shows them.
async fn views(state: &AppState, records: Vec<WorkspaceRecord>) -> Vec<Workspace> {
    let direct = direct_ssh_of(state, &records).await;
    records
        .into_iter()
        .zip(direct)
        .map(|(record, on)| Workspace::new(record, on))
        .collect()
}

/// One workspace as the API shows it.
async fn view(state: &AppState, record: WorkspaceRecord) -> Workspace {
    let on = direct_ssh_on(state, record.clone()).await;
    Workspace::new(record, on)
}

/// Every workspace.
#[utoipa::path(
    get,
    path = "/api/workspaces",
    tag = "workspaces",
    responses((status = OK, description = "the workspaces", body = WorkspaceList))
)]
pub(crate) async fn list_workspaces(
    State(state): State<AppState>,
) -> Result<Json<WorkspaceList>, ApiError> {
    let workspaces = state.workspaces.list().await?;
    Ok(Json(WorkspaceList {
        workspaces: views(&state, workspaces).await,
    }))
}

/// Creates a workspace: its disk, then a clone of the repository. Answers 202; follow it with
/// `workspace_progress` events.
#[utoipa::path(
    post,
    path = "/api/workspaces",
    tag = "workspaces",
    request_body = NewWorkspaceRequest,
    responses(
        (status = ACCEPTED, description = "creation started", body = Workspace),
        (status = CONFLICT, description = "the name is taken", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "invalid name, repository URL (including SSH remotes), image or memory", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "workspaces are not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn create_workspace(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<NewWorkspaceRequest>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let record = state.workspaces.create(body.into_new()?).await?;
    // A new workspace may start with direct SSH on (the global default).
    crate::system_managed::refresh(&state).await;
    Ok((StatusCode::ACCEPTED, Json(view(&state, record).await)))
}

/// One workspace.
#[utoipa::path(
    get,
    path = "/api/workspaces/{id}",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = OK, description = "the workspace", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Workspace>, ApiError> {
    let record = state.workspaces.get(&workspace_id(&id)?).await?;
    Ok(Json(view(&state, record).await))
}

/// Starts a workspace that is down. Answers 202.
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/start",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = ACCEPTED, description = "start accepted", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "already running or busy", body = ApiErrorBody)
    )
)]
pub(crate) async fn start_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let record = state.workspaces.start(&workspace_id(&id)?).await?;
    Ok((StatusCode::ACCEPTED, Json(view(&state, record).await)))
}

/// Stops a running workspace. Answers 202.
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/stop",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = ACCEPTED, description = "stop accepted", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "not running or busy", body = ApiErrorBody)
    )
)]
pub(crate) async fn stop_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let record = state.workspaces.stop(&workspace_id(&id)?).await?;
    Ok((StatusCode::ACCEPTED, Json(view(&state, record).await)))
}

/// Gives the disk space the workspace freed back to the host. Answers 202.
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/reclaim",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = ACCEPTED, description = "reclaim accepted", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "busy", body = ApiErrorBody)
    )
)]
pub(crate) async fn reclaim_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let record = state.workspaces.reclaim(&workspace_id(&id)?).await?;
    Ok((StatusCode::ACCEPTED, Json(view(&state, record).await)))
}

/// What deleting the workspace would lose: uncommitted changes, unpushed commits, stashes and
/// data outside any checkout. Can take a while (it looks inside the workspace).
#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/delete-check",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = OK, description = "the report", body = DeleteCheck),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_check(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<DeleteCheck>, ApiError> {
    Ok(Json(
        state
            .workspaces
            .delete_check(&workspace_id(&id)?)
            .await?
            .into(),
    ))
}

/// Deletes a stopped workspace, its disk included. The body must confirm. The service checks
/// again first and refuses (409) unless the fresh check has the `fingerprint` the user saw, or
/// is clean when none is sent. Answers 202.
#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    request_body = DeleteWorkspaceRequest,
    responses(
        (status = ACCEPTED, description = "delete accepted", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "running, busy, or changed since it was checked", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "not confirmed", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<DeleteWorkspaceRequest>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let id = workspace_id(&id)?;
    if !body.confirm {
        return Err(ApiError::invalid(
            "deleting a workspace needs `confirm: true`",
        ));
    }
    let record = state
        .workspaces
        .delete(&id, body.fingerprint.as_deref())
        .await?;
    Ok((StatusCode::ACCEPTED, Json(view(&state, record).await)))
}

/// Opens a running workspace in VS Code: on the desktop (puddle opens it) or in the browser
/// (the response has the URL, the caller opens it).
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/attach",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    request_body = AttachRequest,
    responses(
        (status = OK, description = "what was done", body = AttachResponse),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "not running, or direct SSH is off for a desktop attach", body = ApiErrorBody)
    )
)]
pub(crate) async fn attach_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<AttachRequest>,
) -> Result<Json<AttachResponse>, ApiError> {
    let id = workspace_id(&id)?;
    let mode = crate::AttachMode::from(body.mode);
    if mode == crate::AttachMode::Desktop {
        // Desktop editors connect over SSH, which puddle only opens when the user allowed it.
        // A workspace that is not up gets the service's own "start it first" answer.
        let record = state.workspaces.get(&id).await?;
        let up = record.busy.is_none() && record.status == puddle_types::SandboxStatus::Running;
        if up && !direct_ssh_on(&state, record).await {
            return Err(crate::WorkspaceError::Conflict(
                "direct SSH is off for this workspace; allow it first".to_owned(),
            )
            .into());
        }
    }
    let attached = state.workspaces.attach(&id, mode).await?;
    Ok(Json(attached.into()))
}
