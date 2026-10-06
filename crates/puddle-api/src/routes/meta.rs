// SPDX-License-Identifier: GPL-3.0-or-later
//! Service routes.

use axum::Json;

use crate::wire::Health;

/// puddle's version and the API contract's version.
#[utoipa::path(
    get,
    path = "/api/health",
    tag = "service",
    responses((status = OK, description = "puddle is up", body = Health))
)]
pub(crate) async fn health() -> Json<Health> {
    Json(Health {
        version: puddle_types::VERSION.to_owned(),
        api_version: crate::API_VERSION.to_owned(),
    })
}
