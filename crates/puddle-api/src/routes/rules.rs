// SPDX-License-Identifier: GPL-3.0-or-later
//! Rules: list, create, delete, change expiry (docs/spec/rules.md §1–2).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_store::Actor;
use puddle_types::RuleId;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{NewRuleRequest, Rule, RuleExpiryRequest, RuleList};

/// Every rule, including expired ones the sweeper hasn't removed yet.
#[utoipa::path(
    get,
    path = "/api/rules",
    tag = "rules",
    responses((status = OK, description = "the rules", body = RuleList))
)]
pub(crate) async fn list_rules(State(state): State<AppState>) -> Result<Json<RuleList>, ApiError> {
    Ok(Json(RuleList {
        rules: state
            .store
            .rules()
            .into_iter()
            .map(Rule::from_store)
            .collect::<Result<_, _>>()?,
    }))
}

/// Creates a rule directly. Open requests it now decides are closed the same way.
#[utoipa::path(
    post,
    path = "/api/rules",
    tag = "rules",
    request_body = NewRuleRequest,
    responses(
        (status = CREATED, description = "the new rule", body = Rule),
        (status = UNPROCESSABLE_ENTITY, description = "invalid pattern or expiry", body = ApiErrorBody)
    )
)]
pub(crate) async fn create_rule(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<NewRuleRequest>,
) -> Result<(StatusCode, Json<Rule>), ApiError> {
    let new = body.into_new_rule()?;
    let rule = blocking(move || Ok(state.store.add_rule(&new)?)).await?;
    Ok((StatusCode::CREATED, Json(Rule::from_store(rule)?)))
}

/// Deletes a rule.
#[utoipa::path(
    delete,
    path = "/api/rules/{id}",
    tag = "rules",
    params(("id" = i64, Path, description = "rule id")),
    responses(
        (status = OK, description = "the deleted rule", body = Rule),
        (status = NOT_FOUND, description = "no such rule", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Rule>, ApiError> {
    let rule = blocking(move || Ok(state.store.delete_rule(RuleId(id), Actor::Api)?)).await?;
    Ok(Json(Rule::from_store(rule)?))
}

/// Changes a rule's expiry, or makes it permanent with `null`.
#[utoipa::path(
    put,
    path = "/api/rules/{id}/expiry",
    tag = "rules",
    params(("id" = i64, Path, description = "rule id")),
    request_body = RuleExpiryRequest,
    responses(
        (status = OK, description = "the changed rule", body = Rule),
        (status = NOT_FOUND, description = "no such rule", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "expiry not in the future", body = ApiErrorBody)
    )
)]
pub(crate) async fn set_rule_expiry(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    crate::extract::Json(body): crate::extract::Json<RuleExpiryRequest>,
) -> Result<Json<Rule>, ApiError> {
    let rule = blocking(move || {
        Ok(state
            .store
            .set_rule_expiry(RuleId(id), body.expires_at, Actor::Api)?)
    })
    .await?;
    Ok(Json(Rule::from_store(rule)?))
}
