// SPDX-License-Identifier: GPL-3.0-or-later
//! The background problems that stand: things puddle does on its own that failed.

use axum::Json;
use axum::extract::State;

use crate::routes::AppState;
use crate::wire::ProblemList;

/// What puddle did on its own that failed and has not been put right: a sweep that could not
/// write, a clean-up that left something behind, a step at start-up that did not finish. Each
/// entry names what went wrong and what to do; one ends by itself when its cause does. A client
/// refetches on the `problems_changed` event.
#[utoipa::path(
    get,
    path = "/api/problems",
    tag = "service",
    responses((status = OK, description = "the problems that stand now", body = ProblemList))
)]
pub(crate) async fn list_problems(State(state): State<AppState>) -> Json<ProblemList> {
    Json(ProblemList {
        problems: state.problems.list(),
    })
}
