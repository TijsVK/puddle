// SPDX-License-Identifier: GPL-3.0-or-later
//! The network-health report: how puddle reaches the internet from this machine.

use axum::Json;
use axum::extract::State;

use crate::ApiErrorBody;
use crate::error::ApiError;
use crate::routes::AppState;
use crate::wire::NetworkHealth;

/// The proxy setup puddle sees (PAC, WPAD, fixed proxy or environment), how it signs in to the
/// company proxy, the company roots copied into workspaces, the route chosen per destination
/// and whether image pulls go through the pull proxy. Safe to show: it holds no password, token,
/// proxy credential or PAC script. A client refetches on the `network_changed` event.
#[utoipa::path(
    get,
    path = "/api/network-health",
    tag = "network",
    responses(
        (status = OK, description = "the report", body = NetworkHealth),
        (status = SERVICE_UNAVAILABLE, description = "the report is not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn network_health(
    State(state): State<AppState>,
) -> Result<Json<NetworkHealth>, ApiError> {
    Ok(Json(state.network_health.report().await?))
}
