// SPDX-License-Identifier: GPL-3.0-or-later
//! Settings and consents (`puddle-settings`). Documents are read through their versioning rules:
//! an older one is migrated and written back, unknown fields are kept and logged, one from a
//! newer puddle is refused with 409.

use axum::Json;
use axum::extract::State;
use puddle_settings::{
    GLOBAL_SCHEMA_VERSION, GlobalSettings, Loaded, WORKSPACE_SCHEMA_VERSION, WorkspaceSettings,
    resolve,
};
use puddle_types::WorkspaceName;
use serde_json::{Value, json};

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::settings::SettingsRepo;
use crate::wire::{
    ConsentKind, ConsentRequest, Consents, GlobalSettingsRequest, GlobalSettingsView,
    SettingsLayer, WorkspaceSettingsRequest, WorkspaceSettingsView,
};

/// The document of a kind that was never saved: current, so reading it migrates and writes nothing.
fn empty(version: u32) -> Value {
    json!({ "schema_version": version })
}

pub(crate) fn load_global(repo: &dyn SettingsRepo) -> Result<Loaded<GlobalSettings>, ApiError> {
    let loaded = GlobalSettings::from_document(
        repo.load_global()?
            .unwrap_or_else(|| empty(GLOBAL_SCHEMA_VERSION)),
    )?;
    if !loaded.unknown_fields.is_empty() {
        tracing::warn!(fields = ?loaded.unknown_fields, "global settings have fields this puddle doesn't know; kept");
    }
    if let Some(from) = loaded.migrated_from {
        repo.save_global(loaded.settings.to_document())?;
        tracing::info!(from, "global settings migrated");
    }
    Ok(loaded)
}

pub(crate) fn load_workspace(
    repo: &dyn SettingsRepo,
    workspace: &WorkspaceName,
) -> Result<Loaded<WorkspaceSettings>, ApiError> {
    let loaded = WorkspaceSettings::from_document(
        repo.load_workspace(workspace)?
            .unwrap_or_else(|| empty(WORKSPACE_SCHEMA_VERSION)),
    )?;
    if !loaded.unknown_fields.is_empty() {
        tracing::warn!(%workspace, fields = ?loaded.unknown_fields, "workspace settings have fields this puddle doesn't know; kept");
    }
    if let Some(from) = loaded.migrated_from {
        repo.save_workspace(workspace, loaded.settings.to_document())?;
        tracing::info!(%workspace, from, "workspace settings migrated");
    }
    Ok(loaded)
}

fn workspace_view(
    workspace: WorkspaceName,
    global: &GlobalSettings,
    loaded: &Loaded<WorkspaceSettings>,
) -> WorkspaceSettingsView {
    WorkspaceSettingsView {
        workspace,
        overrides: SettingsLayer::from(&loaded.settings.overrides),
        effective: resolve(global, Some(&loaded.settings)).into(),
        unknown_fields: loaded.unknown_fields.clone(),
    }
}

/// The global settings and the effective values of a workspace without overrides.
#[utoipa::path(
    get,
    path = "/api/settings",
    tag = "settings",
    responses(
        (status = OK, description = "global settings", body = GlobalSettingsView),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_global(
    State(state): State<AppState>,
) -> Result<Json<GlobalSettingsView>, ApiError> {
    let _lock = state.settings_lock.lock().await;
    let loaded = blocking(move || load_global(state.settings.as_ref())).await?;
    Ok(Json(GlobalSettingsView::new(&loaded)))
}

/// Replaces the global settings listed in the body; `null` falls back to puddle's default.
/// Consents are changed through `/api/consents`.
#[utoipa::path(
    put,
    path = "/api/settings",
    tag = "settings",
    request_body = GlobalSettingsRequest,
    responses(
        (status = OK, description = "the new global settings", body = GlobalSettingsView),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a value out of range, or Microsoft's server chosen without consent", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_global(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<GlobalSettingsRequest>,
) -> Result<Json<GlobalSettingsView>, ApiError> {
    let workspaces = state.workspaces.clone();
    let after = state.clone();
    let lock = state.settings_lock.lock().await;
    let loaded = blocking(move || {
        let repo = state.settings.as_ref();
        let mut loaded = load_global(repo)?;
        body.apply_to(&mut loaded.settings)?;
        // Consent fails closed: Microsoft's server is only chosen after the user agreed.
        if loaded.settings.vscode_server.server() == puddle_settings::ServerChoice::Microsoft
            && !matches!(
                loaded
                    .settings
                    .consents
                    .get(puddle_settings::ConsentKind::VsCodeServer),
                puddle_settings::Consent::Granted { .. }
            )
        {
            return Err(ApiError::invalid(
                "vscode_server.server: Microsoft's server needs the user's consent first",
            ));
        }
        repo.save_global(loaded.settings.to_document())?;
        Ok(loaded)
    })
    .await?;
    tracing::info!("global settings changed");
    workspaces.settings_changed().await;
    drop(lock);
    crate::system_managed::refresh(&after).await;
    Ok(Json(GlobalSettingsView::new(&loaded)))
}

/// One workspace's overrides and effective values. A workspace without stored settings has no
/// overrides.
#[utoipa::path(
    get,
    path = "/api/settings/workspaces/{workspace}",
    tag = "settings",
    params(("workspace" = WorkspaceName, Path, description = "workspace name")),
    responses(
        (status = OK, description = "the workspace's settings", body = WorkspaceSettingsView),
        (status = BAD_REQUEST, description = "invalid workspace name", body = ApiErrorBody),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_workspace_settings(
    State(state): State<AppState>,
    Path(workspace): Path<WorkspaceName>,
) -> Result<Json<WorkspaceSettingsView>, ApiError> {
    let _lock = state.settings_lock.lock().await;
    let view = blocking(move || {
        let repo = state.settings.as_ref();
        let global = load_global(repo)?;
        let loaded = load_workspace(repo, &workspace)?;
        Ok(workspace_view(workspace, &global.settings, &loaded))
    })
    .await?;
    Ok(Json(view))
}

/// Replaces one workspace's overrides; `null` inherits the global value.
#[utoipa::path(
    put,
    path = "/api/settings/workspaces/{workspace}",
    tag = "settings",
    params(("workspace" = WorkspaceName, Path, description = "workspace name")),
    request_body = WorkspaceSettingsRequest,
    responses(
        (status = OK, description = "the workspace's new settings", body = WorkspaceSettingsView),
        (status = BAD_REQUEST, description = "invalid workspace name", body = ApiErrorBody),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a value out of range", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_workspace_settings(
    State(state): State<AppState>,
    Path(workspace): Path<WorkspaceName>,
    crate::extract::Json(body): crate::extract::Json<WorkspaceSettingsRequest>,
) -> Result<Json<WorkspaceSettingsView>, ApiError> {
    let workspaces = state.workspaces.clone();
    let after = state.clone();
    let lock = state.settings_lock.lock().await;
    let view = blocking(move || {
        let repo = state.settings.as_ref();
        let global = load_global(repo)?;
        let mut loaded = load_workspace(repo, &workspace)?;
        body.overrides.apply_to(&mut loaded.settings.overrides)?;
        repo.save_workspace(&workspace, loaded.settings.to_document())?;
        tracing::info!(%workspace, "workspace settings changed");
        Ok(workspace_view(workspace, &global.settings, &loaded))
    })
    .await?;
    workspaces.settings_changed().await;
    drop(lock);
    crate::system_managed::refresh(&after).await;
    Ok(Json(view))
}

/// Every consent and its state.
#[utoipa::path(
    get,
    path = "/api/consents",
    tag = "consents",
    responses(
        (status = OK, description = "the consents", body = Consents),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_consents(
    State(state): State<AppState>,
) -> Result<Json<Consents>, ApiError> {
    let _lock = state.settings_lock.lock().await;
    let loaded = blocking(move || load_global(state.settings.as_ref())).await?;
    Ok(Json(Consents::from(&loaded.settings.consents)))
}

/// Records the user's answer to a consent prompt, with the terms version shown. puddle stamps
/// the time.
#[utoipa::path(
    put,
    path = "/api/consents/{kind}",
    tag = "consents",
    params(("kind" = ConsentKind, Path, description = "which consent")),
    request_body = ConsentRequest,
    responses(
        (status = OK, description = "every consent, after the change", body = Consents),
        (status = BAD_REQUEST, description = "unknown consent kind", body = ApiErrorBody),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "invalid terms version", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_consent(
    State(state): State<AppState>,
    Path(kind): Path<ConsentKind>,
    crate::extract::Json(body): crate::extract::Json<ConsentRequest>,
) -> Result<Json<Consents>, ApiError> {
    let consent = body.into_consent(state.clock.now_ms())?;
    let after = state.clone();
    let lock = state.settings_lock.lock().await;
    let consents = blocking(move || {
        let repo = state.settings.as_ref();
        let mut loaded = load_global(repo)?;
        loaded.settings.consents.set(kind.into(), consent);
        repo.save_global(loaded.settings.to_document())?;
        Ok(Consents::from(&loaded.settings.consents))
    })
    .await?;
    drop(lock);
    crate::system_managed::refresh(&after).await;
    tracing::info!(kind = ?kind, "consent recorded");
    Ok(Json(consents))
}
