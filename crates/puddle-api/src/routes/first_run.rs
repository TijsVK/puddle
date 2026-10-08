// SPDX-License-Identifier: GPL-3.0-or-later
//! The first-run flow's state: shown until the user has been through it or skipped it, kept in
//! the global settings document with the user's other settings.

use axum::Json;
use axum::extract::State;
use puddle_settings::UnixMillis;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::routes::AppState;
use crate::routes::settings::load_global;
use crate::wire::{DevCertificate, FirstRun, FirstRunRequest};

/// What the certificates step says about a development certificate. puddle does not look for
/// one yet, so this is always "not checked".
const DEV_CERTIFICATE: DevCertificate = DevCertificate::NotChecked;

fn view(first_run: &puddle_settings::FirstRun) -> FirstRun {
    FirstRun {
        completed: first_run.is_completed(),
        completed_at: first_run.completed_at.map(|at| at.0),
        dev_certificate: DEV_CERTIFICATE,
    }
}

/// Whether the first-run flow has been through, and what its certificates step shows.
#[utoipa::path(
    get,
    path = "/api/first-run",
    tag = "first-run",
    responses(
        (status = OK, description = "the flow's state", body = FirstRun),
        (status = CONFLICT, description = "settings written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn get_first_run(
    State(state): State<AppState>,
) -> Result<Json<FirstRun>, ApiError> {
    let _lock = state.settings_lock.lock().await;
    let loaded = blocking(move || load_global(state.settings.as_ref())).await?;
    Ok(Json(view(&loaded.settings.first_run)))
}

/// Records that the first-run flow was finished or skipped (`true`), or makes it run again at the
/// next start (`false`). Doing it twice keeps the first time.
#[utoipa::path(
    put,
    path = "/api/first-run",
    tag = "first-run",
    request_body = FirstRunRequest,
    responses(
        (status = OK, description = "the flow's state after the change", body = FirstRun),
        (status = CONFLICT, description = "settings written by a newer puddle", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_first_run(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<FirstRunRequest>,
) -> Result<Json<FirstRun>, ApiError> {
    let now = state.clock.now_ms();
    let _lock = state.settings_lock.lock().await;
    let first_run = blocking(move || {
        let repo = state.settings.as_ref();
        let mut loaded = load_global(repo)?;
        let first_run = &mut loaded.settings.first_run;
        match (body.completed, first_run.completed_at) {
            (true, None) => first_run.completed_at = Some(UnixMillis(now)),
            (false, Some(_)) => first_run.completed_at = None,
            _ => return Ok(view(first_run)),
        }
        repo.save_global(loaded.settings.to_document())?;
        tracing::info!(completed = body.completed, "first-run state changed");
        Ok(view(&loaded.settings.first_run))
    })
    .await?;
    Ok(Json(first_run))
}
