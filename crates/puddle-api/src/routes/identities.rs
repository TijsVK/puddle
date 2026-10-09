// SPDX-License-Identifier: GPL-3.0-or-later
//! Git identities and each workspace's Git settings (credentials spec §7, §8). Credentials are
//! references to sources: nothing here reads, takes or returns a secret value.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_store::{IdentityId, Store};
use puddle_types::{WorkspaceId, WorkspaceName};

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{
    AttachIdentityRequest, GitRepoRequest, GitRepoToggles, GitRepoView, GitSwitchesRequest,
    IdentityDeleted, IdentityList, IdentityOrderRequest, IdentityRequest, IdentityView,
    WorkspaceGitView, WorkspaceIdentitiesRequest,
};

fn view(store: &Store, identity: puddle_store::Identity) -> Result<IdentityView, ApiError> {
    let workspaces = store.identity_workspaces(identity.id)?;
    Ok(IdentityView::from_store(identity, workspaces))
}

fn git_view(
    store: &Store,
    workspace: WorkspaceName,
    git: puddle_store::WorkspaceGit,
) -> Result<WorkspaceGitView, ApiError> {
    Ok(WorkspaceGitView {
        workspace,
        identities: git
            .identities
            .into_iter()
            .map(|identity| view(store, identity))
            .collect::<Result<_, _>>()?,
        repos: git.repos.into_iter().map(GitRepoView::from_store).collect(),
        only_push_listed: git.only_push_listed,
        only_pull_listed: git.only_pull_listed,
    })
}

/// The workspace a path names, as the name the store keys it by; 404 for none.
pub(super) async fn workspace(state: &AppState, raw: &str) -> Result<WorkspaceName, ApiError> {
    let id =
        WorkspaceId::new(raw).map_err(|_| ApiError::not_found(format!("no workspace {raw:?}")))?;
    Ok(state.workspaces.get(&id).await?.name)
}

/// Every identity, in your order.
#[utoipa::path(
    get,
    path = "/api/identities",
    tag = "identities",
    responses((status = OK, description = "the identities", body = IdentityList))
)]
pub(crate) async fn list_identities(
    State(state): State<AppState>,
) -> Result<Json<IdentityList>, ApiError> {
    let list = blocking(move || {
        let identities = state
            .store
            .identities()?
            .into_iter()
            .map(|identity| view(&state.store, identity))
            .collect::<Result<_, _>>()?;
        Ok(IdentityList { identities })
    })
    .await?;
    Ok(Json(list))
}

/// Makes an identity, last in the order. The first one made is the default.
#[utoipa::path(
    post,
    path = "/api/identities",
    tag = "identities",
    request_body = IdentityRequest,
    responses(
        (status = CREATED, description = "the new identity", body = IdentityView),
        (status = CONFLICT, description = "the label is taken", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a value refused", body = ApiErrorBody)
    )
)]
pub(crate) async fn create_identity(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<IdentityRequest>,
) -> Result<(StatusCode, Json<IdentityView>), ApiError> {
    let draft = body.into_draft()?;
    let made = blocking(move || {
        let identity = state.store.create_identity(draft)?;
        view(&state.store, identity)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(made)))
}

/// One identity.
#[utoipa::path(
    get,
    path = "/api/identities/{id}",
    tag = "identities",
    params(("id" = i64, Path, description = "identity id")),
    responses(
        (status = OK, description = "the identity", body = IdentityView),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_identity(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<IdentityView>, ApiError> {
    let found = blocking(move || {
        let identity = state.store.identity(IdentityId(id))?;
        view(&state.store, identity)
    })
    .await?;
    Ok(Json(found))
}

/// Replaces an identity's label, author and credentials. Refused with 409
/// `identity_collision` when the new coverage meets another identity on a workspace that has both.
#[utoipa::path(
    put,
    path = "/api/identities/{id}",
    tag = "identities",
    params(("id" = i64, Path, description = "identity id")),
    request_body = IdentityRequest,
    responses(
        (status = OK, description = "the identity", body = IdentityView),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody),
        (status = CONFLICT, description = "the label is taken, or the coverage collides on a workspace", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a value refused", body = ApiErrorBody)
    )
)]
pub(crate) async fn update_identity(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    crate::extract::Json(body): crate::extract::Json<IdentityRequest>,
) -> Result<Json<IdentityView>, ApiError> {
    let draft = body.into_draft()?;
    let updated = blocking(move || {
        let identity = state.store.update_identity(IdentityId(id), draft)?;
        view(&state.store, identity)
    })
    .await?;
    Ok(Json(updated))
}

/// Deletes an identity and takes it off every workspace; the answer lists them.
#[utoipa::path(
    delete,
    path = "/api/identities/{id}",
    tag = "identities",
    params(("id" = i64, Path, description = "identity id")),
    responses(
        (status = OK, description = "the workspaces it left", body = IdentityDeleted),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_identity(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<IdentityDeleted>, ApiError> {
    let detached_from = blocking(move || Ok(state.store.delete_identity(IdentityId(id))?)).await?;
    Ok(Json(IdentityDeleted { detached_from }))
}

/// Makes an identity the default.
#[utoipa::path(
    put,
    path = "/api/identities/{id}/default",
    tag = "identities",
    params(("id" = i64, Path, description = "identity id")),
    responses(
        (status = OK, description = "the identity", body = IdentityView),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody)
    )
)]
pub(crate) async fn set_default_identity(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<IdentityView>, ApiError> {
    let found = blocking(move || {
        let identity = state.store.set_default_identity(IdentityId(id))?;
        view(&state.store, identity)
    })
    .await?;
    Ok(Json(found))
}

/// Puts the identities in a new order; the body lists every identity once.
#[utoipa::path(
    put,
    path = "/api/identities/order",
    tag = "identities",
    request_body = IdentityOrderRequest,
    responses(
        (status = OK, description = "the identities in the new order", body = IdentityList),
        (status = UNPROCESSABLE_ENTITY, description = "not every identity exactly once", body = ApiErrorBody)
    )
)]
pub(crate) async fn reorder_identities(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<IdentityOrderRequest>,
) -> Result<Json<IdentityList>, ApiError> {
    let ids: Vec<_> = body.ids.into_iter().map(IdentityId).collect();
    let list = blocking(move || {
        let identities = state
            .store
            .reorder_identities(&ids)?
            .into_iter()
            .map(|identity| view(&state.store, identity))
            .collect::<Result<_, _>>()?;
        Ok(IdentityList { identities })
    })
    .await?;
    Ok(Json(list))
}

/// A workspace's Git settings: identities in order, the repository table and the two switches.
#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/git",
    tag = "identities",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = OK, description = "the settings", body = WorkspaceGitView),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_workspace_git(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WorkspaceGitView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let found = blocking(move || {
        let git = state.store.workspace_git(&name)?;
        git_view(&state.store, name, git)
    })
    .await?;
    Ok(Json(found))
}

/// Replaces the workspace's ordered identity list. 409 `identity_collision` names both identities
/// when two cover the same owner or both cover the rest of a host.
#[utoipa::path(
    put,
    path = "/api/workspaces/{id}/identities",
    tag = "identities",
    params(("id" = String, Path, description = "workspace id")),
    request_body = WorkspaceIdentitiesRequest,
    responses(
        (status = OK, description = "the settings", body = WorkspaceGitView),
        (status = NOT_FOUND, description = "no such workspace or identity", body = ApiErrorBody),
        (status = CONFLICT, description = "two identities collide", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "an identity listed twice", body = ApiErrorBody)
    )
)]
pub(crate) async fn set_workspace_identities(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<WorkspaceIdentitiesRequest>,
) -> Result<Json<WorkspaceGitView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let ids: Vec<_> = body.ids.into_iter().map(IdentityId).collect();
    let set = blocking(move || {
        let git = state.store.set_workspace_identities(&name, &ids)?;
        git_view(&state.store, name, git)
    })
    .await?;
    Ok(Json(set))
}

/// Adds an identity to the workspace, last unless `position` says otherwise. 409
/// `identity_collision` when it covers what another identity there covers.
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/identities",
    tag = "identities",
    params(("id" = String, Path, description = "workspace id")),
    request_body = AttachIdentityRequest,
    responses(
        (status = OK, description = "the settings", body = WorkspaceGitView),
        (status = NOT_FOUND, description = "no such workspace or identity", body = ApiErrorBody),
        (status = CONFLICT, description = "already on the workspace, or it collides", body = ApiErrorBody)
    )
)]
pub(crate) async fn attach_identity(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<AttachIdentityRequest>,
) -> Result<Json<WorkspaceGitView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let set = blocking(move || {
        let position = body
            .position
            .map(|p| usize::try_from(p).unwrap_or(usize::MAX));
        let git = state
            .store
            .attach_identity(&name, IdentityId(body.identity), position)?;
        git_view(&state.store, name, git)
    })
    .await?;
    Ok(Json(set))
}

/// Takes an identity off the workspace.
#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/identities/{identity}",
    tag = "identities",
    params(
        ("id" = String, Path, description = "workspace id"),
        ("identity" = i64, Path, description = "identity id")
    ),
    responses(
        (status = OK, description = "the settings", body = WorkspaceGitView),
        (status = NOT_FOUND, description = "no such workspace, or the identity is not on it", body = ApiErrorBody)
    )
)]
pub(crate) async fn detach_identity(
    State(state): State<AppState>,
    Path((id, identity)): Path<(String, i64)>,
) -> Result<Json<WorkspaceGitView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let set = blocking(move || {
        let git = state.store.detach_identity(&name, IdentityId(identity))?;
        git_view(&state.store, name, git)
    })
    .await?;
    Ok(Json(set))
}

/// Sets "only push to listed repos" and "only pull from listed repos"; a switch left out stays.
#[utoipa::path(
    put,
    path = "/api/workspaces/{id}/git/switches",
    tag = "identities",
    params(("id" = String, Path, description = "workspace id")),
    request_body = GitSwitchesRequest,
    responses(
        (status = OK, description = "the settings", body = WorkspaceGitView),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody)
    )
)]
pub(crate) async fn set_git_switches(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<GitSwitchesRequest>,
) -> Result<Json<WorkspaceGitView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let set = blocking(move || {
        let git =
            state
                .store
                .set_git_switches(&name, body.only_push_listed, body.only_pull_listed)?;
        git_view(&state.store, name, git)
    })
    .await?;
    Ok(Json(set))
}

/// Adds a repository to the workspace's table.
#[utoipa::path(
    post,
    path = "/api/workspaces/{id}/git/repos",
    tag = "identities",
    params(("id" = String, Path, description = "workspace id")),
    request_body = GitRepoRequest,
    responses(
        (status = CREATED, description = "the row", body = GitRepoView),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = CONFLICT, description = "already in the table", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "not a repository name", body = ApiErrorBody)
    )
)]
pub(crate) async fn add_git_repo(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<GitRepoRequest>,
) -> Result<(StatusCode, Json<GitRepoView>), ApiError> {
    let name = workspace(&state, &id).await?;
    let repo = body.repo_ref()?;
    let row = blocking(move || {
        let entry = state.store.add_repo(&name, &repo, body.pull, body.push)?;
        Ok(GitRepoView::from_store(entry))
    })
    .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Sets a row's Pull and Push toggles.
#[utoipa::path(
    put,
    path = "/api/workspaces/{id}/git/repos/{repo}",
    tag = "identities",
    params(
        ("id" = String, Path, description = "workspace id"),
        ("repo" = i64, Path, description = "row id")
    ),
    request_body = GitRepoToggles,
    responses(
        (status = OK, description = "the row", body = GitRepoView),
        (status = NOT_FOUND, description = "no such workspace or row", body = ApiErrorBody)
    )
)]
pub(crate) async fn set_git_repo(
    State(state): State<AppState>,
    Path((id, repo)): Path<(String, i64)>,
    crate::extract::Json(body): crate::extract::Json<GitRepoToggles>,
) -> Result<Json<GitRepoView>, ApiError> {
    let name = workspace(&state, &id).await?;
    let row = blocking(move || {
        let entry = state
            .store
            .set_repo_toggles(&name, repo, body.pull, body.push)?;
        Ok(GitRepoView::from_store(entry))
    })
    .await?;
    Ok(Json(row))
}

/// Removes a row from the table.
#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/git/repos/{repo}",
    tag = "identities",
    params(
        ("id" = String, Path, description = "workspace id"),
        ("repo" = i64, Path, description = "row id")
    ),
    responses(
        (status = NO_CONTENT, description = "removed"),
        (status = NOT_FOUND, description = "no such workspace or row", body = ApiErrorBody)
    )
)]
pub(crate) async fn remove_git_repo(
    State(state): State<AppState>,
    Path((id, repo)): Path<(String, i64)>,
) -> Result<StatusCode, ApiError> {
    let name = workspace(&state, &id).await?;
    blocking(move || Ok(state.store.remove_repo(&name, repo)?)).await?;
    Ok(StatusCode::NO_CONTENT)
}
