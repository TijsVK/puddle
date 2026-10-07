// SPDX-License-Identifier: GPL-3.0-or-later
//! Settings and consents (`puddle-settings`). Documents are read through their versioning rules:
//! an older one is migrated and written back, unknown fields are kept and logged, one from a
//! newer puddle is refused with 409.

use axum::Json;
use axum::extract::State;
use puddle_settings::{GlobalSettings, Loaded, SandboxSettings, resolve};
use puddle_types::SandboxName;
use serde_json::{Value, json};

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::settings::SettingsRepo;
use crate::wire::{
    ConsentKind, ConsentRequest, Consents, GlobalSettingsRequest, GlobalSettingsView,
    SandboxSettingsRequest, SandboxSettingsView, SettingsLayer,
};

fn empty() -> Value {
    json!({})
}

pub(crate) fn load_global(repo: &dyn SettingsRepo) -> Result<Loaded<GlobalSettings>, ApiError> {
    let loaded = GlobalSettings::from_document(repo.load_global()?.unwrap_or_else(empty))?;
    if !loaded.unknown_fields.is_empty() {
        tracing::warn!(fields = ?loaded.unknown_fields, "global settings have fields this puddle doesn't know; kept");
    }
    if let Some(from) = loaded.migrated_from {
        repo.save_global(loaded.settings.to_document())?;
        tracing::info!(from, "global settings migrated");
    }
    Ok(loaded)
}

pub(crate) fn load_sandbox(
    repo: &dyn SettingsRepo,
    sandbox: &SandboxName,
) -> Result<Loaded<SandboxSettings>, ApiError> {
    let loaded = SandboxSettings::from_document(repo.load_sandbox(sandbox)?.unwrap_or_else(empty))?;
    if !loaded.unknown_fields.is_empty() {
        tracing::warn!(%sandbox, fields = ?loaded.unknown_fields, "sandbox settings have fields this puddle doesn't know; kept");
    }
    if let Some(from) = loaded.migrated_from {
        repo.save_sandbox(sandbox, loaded.settings.to_document())?;
        tracing::info!(%sandbox, from, "sandbox settings migrated");
    }
    Ok(loaded)
}

fn sandbox_view(
    sandbox: SandboxName,
    global: &GlobalSettings,
    loaded: &Loaded<SandboxSettings>,
) -> SandboxSettingsView {
    SandboxSettingsView {
        sandbox,
        overrides: SettingsLayer::from(&loaded.settings.overrides),
        effective: resolve(global, Some(&loaded.settings)).into(),
        unknown_fields: loaded.unknown_fields.clone(),
    }
}

/// The global settings and the effective values of a sandbox without overrides.
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
    let _lock = state.settings_lock.lock().await;
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
        crate::system_managed::refresh(&state.store, repo)?;
        Ok(loaded)
    })
    .await?;
    tracing::info!("global settings changed");
    workspaces.settings_changed().await;
    Ok(Json(GlobalSettingsView::new(&loaded)))
}

/// One sandbox's overrides and effective values. A sandbox without stored settings has no
/// overrides.
#[utoipa::path(
    get,
    path = "/api/settings/sandboxes/{sandbox}",
    tag = "settings",
    params(("sandbox" = SandboxName, Path, description = "sandbox name")),
    responses(
        (status = OK, description = "the sandbox's settings", body = SandboxSettingsView),
        (status = BAD_REQUEST, description = "invalid sandbox name", body = ApiErrorBody),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_sandbox(
    State(state): State<AppState>,
    Path(sandbox): Path<SandboxName>,
) -> Result<Json<SandboxSettingsView>, ApiError> {
    let _lock = state.settings_lock.lock().await;
    let view = blocking(move || {
        let repo = state.settings.as_ref();
        let global = load_global(repo)?;
        let loaded = load_sandbox(repo, &sandbox)?;
        Ok(sandbox_view(sandbox, &global.settings, &loaded))
    })
    .await?;
    Ok(Json(view))
}

/// Replaces one sandbox's overrides; `null` inherits the global value.
#[utoipa::path(
    put,
    path = "/api/settings/sandboxes/{sandbox}",
    tag = "settings",
    params(("sandbox" = SandboxName, Path, description = "sandbox name")),
    request_body = SandboxSettingsRequest,
    responses(
        (status = OK, description = "the sandbox's new settings", body = SandboxSettingsView),
        (status = BAD_REQUEST, description = "invalid sandbox name", body = ApiErrorBody),
        (status = CONFLICT, description = "written by a newer puddle", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a value out of range", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_sandbox(
    State(state): State<AppState>,
    Path(sandbox): Path<SandboxName>,
    crate::extract::Json(body): crate::extract::Json<SandboxSettingsRequest>,
) -> Result<Json<SandboxSettingsView>, ApiError> {
    let workspaces = state.workspaces.clone();
    let _lock = state.settings_lock.lock().await;
    let view = blocking(move || {
        let repo = state.settings.as_ref();
        let global = load_global(repo)?;
        let mut loaded = load_sandbox(repo, &sandbox)?;
        body.overrides.apply_to(&mut loaded.settings.overrides)?;
        repo.save_sandbox(&sandbox, loaded.settings.to_document())?;
        tracing::info!(%sandbox, "sandbox settings changed");
        Ok(sandbox_view(sandbox, &global.settings, &loaded))
    })
    .await?;
    workspaces.settings_changed().await;
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
    let _lock = state.settings_lock.lock().await;
    let consents = blocking(move || {
        let repo = state.settings.as_ref();
        let mut loaded = load_global(repo)?;
        loaded.settings.consents.set(kind.into(), consent);
        repo.save_global(loaded.settings.to_document())?;
        crate::system_managed::refresh(&state.store, repo)?;
        Ok(Consents::from(&loaded.settings.consents))
    })
    .await?;
    tracing::info!(kind = ?kind, "consent recorded");
    Ok(Json(consents))
}
