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
/// Whether direct SSH is on for a workspace, and why that is only a guess when the settings
/// cannot be read.
struct DirectSsh {
    on: bool,
    /// Set when the settings could not be read: direct SSH then counts as off (the safe side).
    unreadable: Option<String>,
}

impl DirectSsh {
    fn unreadable(reason: &str) -> Self {
        Self {
            on: false,
            unreadable: Some(format!(
                "the settings cannot be read ({reason}); direct SSH counts as off and local destinations stay blocked until they can"
            )),
        }
    }
}

/// `direct_ssh` of each of `records`, in order. Settings that cannot be read count as off and say
/// why, so a damaged document is not shown as "off" by the user's choice.
async fn direct_ssh_of(state: &AppState, records: &[WorkspaceRecord]) -> Vec<DirectSsh> {
    let names: Vec<_> = records.iter().map(|r| r.name.clone()).collect();
    let settings = state.settings.clone();
    let _lock = state.settings_lock.lock().await;
    let loaded = blocking(move || {
        let repo = settings.as_ref();
        let global = match crate::routes::settings::load_global(repo) {
            Ok(global) => global,
            Err(e) => return Ok(all_unreadable(names.len(), e.reason())),
        };
        Ok(names
            .iter()
            .map(
                |name| match crate::routes::settings::load_workspace(repo, name) {
                    Ok(own) => DirectSsh {
                        on: resolve(&global.settings, Some(&own.settings))
                            .direct_ssh
                            .value,
                        unreadable: None,
                    },
                    Err(e) => DirectSsh::unreadable(e.reason()),
                },
            )
            .collect())
    })
    .await;
    match loaded {
        Ok(all) => all,
        Err(e) => all_unreadable(records.len(), e.reason()),
    }
}

fn all_unreadable(count: usize, reason: &str) -> Vec<DirectSsh> {
    (0..count).map(|_| DirectSsh::unreadable(reason)).collect()
}

/// `direct_ssh_of` for one record.
async fn direct_ssh_of_one(state: &AppState, record: &WorkspaceRecord) -> DirectSsh {
    let mut all = direct_ssh_of(state, std::slice::from_ref(record)).await;
    all.pop().unwrap_or(DirectSsh {
        on: false,
        unreadable: None,
    })
}

/// Whether direct SSH is on for one workspace; the error says why it cannot be known.
async fn direct_ssh_on(state: &AppState, record: WorkspaceRecord) -> Result<bool, String> {
    let d = direct_ssh_of_one(state, &record).await;
    d.unreadable.map_or(Ok(d.on), Err)
}

/// The workspaces as the API shows them.
async fn views(state: &AppState, records: Vec<WorkspaceRecord>) -> Vec<Workspace> {
    let direct = direct_ssh_of(state, &records).await;
    records
        .into_iter()
        .zip(direct)
        .map(|(record, d)| Workspace::new(record, d.on).with_settings_error(d.unreadable))
        .collect()
}

/// One workspace as the API shows it.
async fn view(state: &AppState, record: WorkspaceRecord) -> Workspace {
    let d = direct_ssh_of_one(state, &record).await;
    Workspace::new(record, d.on).with_settings_error(d.unreadable)
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

/// A new workspace's Git settings: the identity that covers its repository (else the default) and
/// the repository in the table. A failure here does not undo the workspace: its Git tab then
/// shows no identity, which says what is missing.
async fn start_git(state: &AppState, record: &WorkspaceRecord) {
    let store = state.store.clone();
    let (name, url) = (record.name.clone(), record.repo_url.clone());
    let started = blocking(move || {
        let repo = puddle_store::RepoRef::from_https_url(&url)?;
        Ok(store.start_workspace_git(&name, &repo)?)
    })
    .await;
    if let Err(err) = started {
        tracing::warn!(workspace = %record.name, error = ?err, "could not set up the new workspace's Git settings");
    }
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
    start_git(&state, &record).await;
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
        let up = record.busy.is_none() && record.status == puddle_types::WorkspaceStatus::Running;
        if up {
            match direct_ssh_on(&state, record).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(crate::WorkspaceError::Conflict(
                        "direct SSH is off for this workspace; allow it first".to_owned(),
                    )
                    .into());
                }
                Err(reason) => return Err(crate::WorkspaceError::Conflict(reason).into()),
            }
        }
    }
    let attached = state.workspaces.attach(&id, mode).await?;
    Ok(Json(attached.into()))
}
