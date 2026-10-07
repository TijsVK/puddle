// SPDX-License-Identifier: GPL-3.0-or-later
//! Rule sets and System managed (docs/spec/rules.md §7).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_store::{Actor, parse_rule_set};
use puddle_types::RuleSetId;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{
    NewRuleSetRequest, RuleSetList, RuleSetSwitchRequest, RuleSetSwitched, RuleSetUpdateRequest,
    RuleSetView, SystemManagedHost,
};

/// The set a path names, or 404.
fn set_id(text: &str) -> Result<RuleSetId, ApiError> {
    parse_rule_set(text).ok_or_else(|| ApiError::not_found(format!("no rule set {text}")))
}

/// The number of a set you made, or 404 for anything else (built-in sets are read-only).
fn user_set(text: &str) -> Result<i64, ApiError> {
    match set_id(text)? {
        RuleSetId::User(id) => Ok(id),
        _ => Err(ApiError::invalid(format!(
            "{text} ships with puddle and can't be changed; switch it off instead"
        ))),
    }
}

/// Every rule set (built-in first, then yours) and the System managed hosts with their reasons.
#[utoipa::path(
    get,
    path = "/api/rule-sets",
    tag = "rules",
    responses((status = OK, description = "the rule sets", body = RuleSetList))
)]
pub(crate) async fn list_rule_sets(
    State(state): State<AppState>,
) -> Result<Json<RuleSetList>, ApiError> {
    let list = blocking(move || {
        let sets = state.store.rule_sets()?;
        let system = state.store.system_managed()?;
        Ok(RuleSetList {
            sets: sets.into_iter().map(RuleSetView::from_store).collect(),
            system_managed: system
                .into_iter()
                .filter_map(SystemManagedHost::from_store)
                .collect(),
        })
    })
    .await?;
    Ok(Json(list))
}

/// Makes a rule set of your own, empty and on everywhere. Add entries with `POST /api/rules`
/// (scope `set`) or by approving a request into it.
#[utoipa::path(
    post,
    path = "/api/rule-sets",
    tag = "rules",
    request_body = NewRuleSetRequest,
    responses(
        (status = CREATED, description = "the new set", body = RuleSetView),
        (status = UNPROCESSABLE_ENTITY, description = "name empty, too long or taken", body = ApiErrorBody)
    )
)]
pub(crate) async fn create_rule_set(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<NewRuleSetRequest>,
) -> Result<(StatusCode, Json<RuleSetView>), ApiError> {
    let set = blocking(move || {
        Ok(state
            .store
            .create_rule_set(&body.name, &body.description, Actor::Api)?)
    })
    .await?;
    Ok((StatusCode::CREATED, Json(RuleSetView::from_store(set))))
}

/// Renames a rule set of yours or changes its description.
#[utoipa::path(
    put,
    path = "/api/rule-sets/{id}",
    tag = "rules",
    params(("id" = String, Path, description = "`user:<id>`")),
    request_body = RuleSetUpdateRequest,
    responses(
        (status = OK, description = "the set", body = RuleSetView),
        (status = NOT_FOUND, description = "no such set", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a built-in set, or name empty, too long or taken", body = ApiErrorBody)
    )
)]
pub(crate) async fn update_rule_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<RuleSetUpdateRequest>,
) -> Result<Json<RuleSetView>, ApiError> {
    let id = user_set(&id)?;
    let set = blocking(move || {
        Ok(state
            .store
            .update_rule_set(id, &body.name, &body.description, Actor::Api)?)
    })
    .await?;
    Ok(Json(RuleSetView::from_store(set)))
}

/// Deletes a rule set of yours with its entries and switches.
#[utoipa::path(
    delete,
    path = "/api/rule-sets/{id}",
    tag = "rules",
    params(("id" = String, Path, description = "`user:<id>`")),
    responses(
        (status = OK, description = "the deleted set", body = RuleSetView),
        (status = NOT_FOUND, description = "no such set", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a built-in set", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_rule_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RuleSetView>, ApiError> {
    let id = user_set(&id)?;
    let set = blocking(move || Ok(state.store.delete_rule_set(id, Actor::Api)?)).await?;
    Ok(Json(RuleSetView::from_store(set)))
}

/// Switches a set on or off for every sandbox or for one (`enabled: null` removes that switch),
/// and closes the open requests the set now decides.
#[utoipa::path(
    put,
    path = "/api/rule-sets/{id}/switch",
    tag = "rules",
    params(("id" = String, Path, description = "`builtin:<slug>` or `user:<id>`")),
    request_body = RuleSetSwitchRequest,
    responses(
        (status = OK, description = "the set and the requests it closed", body = RuleSetSwitched),
        (status = NOT_FOUND, description = "no such set", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "System managed has no switch", body = ApiErrorBody)
    )
)]
pub(crate) async fn switch_rule_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
    crate::extract::Json(body): crate::extract::Json<RuleSetSwitchRequest>,
) -> Result<Json<RuleSetSwitched>, ApiError> {
    let id = set_id(&id)?;
    let switched = blocking(move || {
        let closed =
            state
                .store
                .switch_rule_set(id, body.sandbox.as_ref(), body.enabled, Actor::Api)?;
        Ok(RuleSetSwitched {
            set: RuleSetView::from_store(state.store.rule_set(id)?),
            closed: closed.into_iter().map(|p| p.0).collect(),
        })
    })
    .await?;
    Ok(Json(switched))
}
