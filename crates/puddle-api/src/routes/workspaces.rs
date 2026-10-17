// SPDX-License-Identifier: GPL-3.0-or-later
//! Workspaces: list, create, detail, start, stop, reclaim space, the delete check, delete and
//! attach. The routes only translate; [`crate::WorkspaceService`] does the work. Long
//! operations answer 202 with the workspace marked busy and report through `status_changed` and
//! `workspace_progress` events.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use futures_util::future::BoxFuture;
use puddle_settings::resolve;
use puddle_store::{IdentityId, RepoGitRequest, RepoRef, Store};
use puddle_types::{WorkspaceId, WorkspaceName};

use crate::ApiErrorBody;
use crate::WorkspaceRecord;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{
    AttachRequest, AttachResponse, DeleteCheck, DeleteWorkspaceRequest, NewWorkspaceIdentity,
    NewWorkspaceRequest, RenameWorkspaceRequest, Workspace, WorkspaceList,
};
use crate::workspaces::{GitSetup, NewRepository};

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

/// What the store asks of one repository's Git settings; `None` when its address names no
/// repository the table can hold.
fn git_request(repository: &NewRepository) -> Option<RepoGitRequest> {
    let repo = RepoRef::from_https_url(repository.repository.url.as_str()).ok()?;
    Some(RepoGitRequest {
        repo,
        identity: repository.identity,
        pull: repository.pull,
        push: repository.push,
    })
}

/// Sets a new workspace's repositories up in the store, in order, and keeps what each got for
/// the answer. A repository it cannot set up is cloned without its Git settings, and its entry
/// in the answer says so; the workspace is not undone for it.
struct StoreGitSetup {
    store: Arc<Store>,
    started: Mutex<Vec<NewWorkspaceIdentity>>,
}

impl StoreGitSetup {
    fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            started: Mutex::new(Vec::new()),
        }
    }

    fn take(&self) -> Vec<NewWorkspaceIdentity> {
        std::mem::take(&mut *self.started.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

fn start_one(
    store: &Store,
    workspace: &WorkspaceName,
    repository: &NewRepository,
) -> NewWorkspaceIdentity {
    let url = repository.repository.url.as_str();
    let Some(request) = git_request(repository) else {
        return NewWorkspaceIdentity::not_set_up(format!(
            "Puddle cannot tell which repository {url} is, so it set up no identity or repository \
             table row for it. Add them on the Git tab."
        ));
    };
    match store.start_repository_git(workspace, &request) {
        Ok(start) => NewWorkspaceIdentity::from_store(&start, &request.repo),
        Err(err) => {
            tracing::warn!(%workspace, %url, error = ?err, "could not set up a new repository's Git settings");
            NewWorkspaceIdentity::not_set_up(format!(
                "Puddle could not set up the Git settings of {url} ({err}), so it is cloned without \
                 them. Set them on the Git tab."
            ))
        }
    }
}

impl GitSetup for StoreGitSetup {
    fn set_up<'a>(
        &'a self,
        workspace: &'a WorkspaceName,
        repositories: &'a [NewRepository],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // On this thread, not a blocking task: a few small writes, and a task that could not
            // run would leave repositories set up without the answer saying which.
            let started = repositories
                .iter()
                .map(|repository| start_one(&self.store, workspace, repository))
                .collect();
            *self.started.lock().unwrap_or_else(PoisonError::into_inner) = started;
        })
    }
}

/// Creates a workspace: its disk, then a clone of each repository in the list, one at a time.
/// The list is checked whole before anything exists. Each repository's identity joins the
/// workspace and its repository table row is made before the first clone. A clone that fails
/// fails only its repository: a background problem names it and the create still ends `done`.
/// Answers 202; follow it with `workspace_progress` events.
#[utoipa::path(
    post,
    path = "/api/workspaces",
    tag = "workspaces",
    request_body = NewWorkspaceRequest,
    responses(
        (status = ACCEPTED, description = "creation started", body = Workspace),
        (status = CONFLICT, description = "the name is taken, or two identities of the list cover the same place (`identity_collision`)", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "invalid name, repository (address, SSH remote, directory clash, the same repository twice, unknown identity, more than 100), start folder, image or memory, or `repo_url` sent", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "workspaces are not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn create_workspace(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<NewWorkspaceRequest>,
) -> Result<(StatusCode, Json<Workspace>), ApiError> {
    let store = state.store.clone();
    let known: BTreeSet<IdentityId> =
        blocking(move || Ok(store.identities()?.into_iter().map(|i| i.id).collect())).await?;
    let new = body.into_new(|id| known.contains(&id))?;
    let (store, name) = (state.store.clone(), new.name.clone());
    let requests: Vec<RepoGitRequest> = new.repositories.iter().filter_map(git_request).collect();
    blocking(move || Ok(store.check_repository_git(&name, &requests)?)).await?;
    let git = StoreGitSetup::new(state.store.clone());
    let record = state.workspaces.create(new, &git).await?;
    // A new workspace may start with direct SSH on (the global default).
    crate::system_managed::refresh(&state).await;
    Ok((
        StatusCode::ACCEPTED,
        Json(view(&state, record).await.with_identities(git.take())),
    ))
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

/// Renames a workspace: sets the display name the UI shows. Only the label changes (the id, the
/// name, the volume and the sandbox stay), so it works on a running workspace and restarts
/// nothing. A name another workspace already goes by (ignoring case) is refused with 409, and so
/// is a rename while the workspace is being created or deleted.
#[utoipa::path(
    patch,
    path = "/api/workspaces/{id}",
    tag = "workspaces",
    params(("id" = String, Path, description = "workspace id")),
    request_body = RenameWorkspaceRequest,
    responses(
        (status = OK, description = "the renamed workspace", body = Workspace),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "another workspace has that name, or this one is being created or deleted", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "empty, too long or contains control characters", body = ApiErrorBody)
    )
)]
pub(crate) async fn rename_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<RenameWorkspaceRequest>,
) -> Result<Json<Workspace>, ApiError> {
    let id = workspace_id(&id)?;
    let display_name = body.into_display_name()?;
    let record = state.workspaces.rename(&id, display_name).await?;
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

/// Opens a running workspace in VS Code: on the desktop (Puddle opens it) or in the browser
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
        // Desktop editors connect over SSH, which Puddle only opens when the user allowed it.
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

#[cfg(test)]
mod tests {
    use puddle_store::{Limits, ManualClock};

    use super::*;
    use crate::workspaces::{RepoUrl, Repository};

    #[test]
    fn a_repository_the_store_cannot_set_up_is_cloned_without_and_its_entry_says_why() {
        let store =
            Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap();
        let ws = WorkspaceName::new("w").unwrap();
        // An identity that is gone by the time the create sets it up.
        let gone = NewRepository {
            repository: Repository::at_default_directory(
                RepoUrl::parse("https://github.com/acme/api").unwrap(),
            ),
            identity: Some(IdentityId(42)),
            pull: true,
            push: true,
        };
        let answer = start_one(&store, &ws, &gone);
        assert_eq!(answer.identity, None);
        let warning = answer.warning.unwrap();
        assert!(
            warning.starts_with(
                "Puddle could not set up the Git settings of https://github.com/acme/api ("
            ),
            "{warning}"
        );
        assert!(warning.ends_with("Set them on the Git tab."), "{warning}");
        assert_eq!(store.workspace_git(&ws).unwrap().repos, []);
    }
}
