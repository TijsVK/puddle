// SPDX-License-Identifier: GPL-3.0-or-later
//! The repositories an identity's credentials reach, and who a credential's account is
//! (credentials spec §8). Read on the host with the credential's own token; nothing here returns
//! a secret and nothing reaches a workspace.

use axum::Json;
use axum::extract::State;
use puddle_repos::listing::{Query as Search, page};
use puddle_repos::{Freshness, Read};
use puddle_store::IdentityId;
use serde::Deserialize;

use crate::ApiErrorBody;
use crate::error::{ApiError, blocking};
use crate::extract::Query;
use crate::routes::AppState;
use crate::wire::{
    AccountProfile, AccountProfileRequest, RepoListing, RepoRefreshRequest, RepoSource,
    RepoSources, RepoView,
};

/// Repositories per page when the client doesn't say.
const DEFAULT_LIMIT: u32 = 100;
/// Most repositories per page.
const MAX_LIMIT: u32 = 500;
/// Longest search text, in bytes.
const MAX_TEXT: usize = 200;

/// What to show.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReposQuery {
    identity: Option<i64>,
    query: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// The repositories the identities' credentials reach, one entry each, by name, with how current
/// each credential's list is. One list for the Identities tab (`identity`) and the create form
/// (`query`, no `identity`): it is read from the cache, and read from the Git host when missing
/// or older than ten minutes, never more than once at a time per credential. A list that cannot
/// be read says why in `sources`, and the last good one stays on show as `stale`.
#[utoipa::path(
    get,
    path = "/api/repos",
    tag = "identities",
    params(
        ("identity" = Option<i64>, Query, description = "only the repositories this identity's credentials reach, and read only its lists"),
        ("query" = Option<String>, Query, description = "words that must all appear in the full name, whatever the case"),
        ("limit" = Option<u32>, Query, minimum = 1, maximum = 500, description = "repositories per page (default 100)"),
        ("offset" = Option<u32>, Query, description = "repositories to skip")
    ),
    responses(
        (status = OK, description = "the repositories and how current each list is", body = RepoListing),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "the limit or the text out of range", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn list_repos(
    State(state): State<AppState>,
    Query(query): Query<ReposQuery>,
) -> Result<Json<RepoListing>, ApiError> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::invalid(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let text = query.query.unwrap_or_default();
    if text.len() > MAX_TEXT {
        return Err(ApiError::invalid(format!(
            "query is at most {MAX_TEXT} bytes"
        )));
    }
    let offset = query.offset.unwrap_or(0);
    let only = query.identity.map(IdentityId);
    let identities = identities(&state, only).await?;
    let lists = state
        .repos
        .lists(
            &identities,
            Read {
                only,
                freshness: Freshness::Cached,
            },
        )
        .await?;
    let found = page(
        &lists,
        &Search {
            text,
            only,
            offset: offset as usize,
            limit: limit as usize,
        },
    );
    Ok(Json(RepoListing {
        sources: lists.iter().map(RepoSource::from_list).collect(),
        repos: found.repos.iter().map(RepoView::from_found).collect(),
        total: u32::try_from(found.total).unwrap_or(u32::MAX),
        offset,
        limit,
    }))
}

/// Every identity, and a 404 when `only` names one that does not exist.
async fn identities(
    state: &AppState,
    only: Option<IdentityId>,
) -> Result<Vec<puddle_store::Identity>, ApiError> {
    let store = state.store.clone();
    blocking(move || {
        if let Some(id) = only {
            store.identity(id)?;
        }
        Ok(store.identities()?)
    })
    .await
}

/// Reads the lists again now (a "Refresh"): every identity's, or one's. A list read a few
/// seconds ago is not read again, and a host that said to wait is left alone until it allows; the
/// answer says how current each list is, and why one is not.
#[utoipa::path(
    post,
    path = "/api/repos/refresh",
    tag = "identities",
    request_body = RepoRefreshRequest,
    responses(
        (status = OK, description = "how current each list is now", body = RepoSources),
        (status = NOT_FOUND, description = "no such identity", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn refresh_repos(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<RepoRefreshRequest>,
) -> Result<Json<RepoSources>, ApiError> {
    let only = body.identity_id.map(IdentityId);
    let identities = identities(&state, only).await?;
    let lists = state
        .repos
        .lists(
            &identities,
            Read {
                only,
                freshness: Freshness::Reload,
            },
        )
        .await?;
    Ok(Json(RepoSources {
        sources: lists.iter().map(RepoSource::from_list).collect(),
    }))
}

/// Who a credential's account is, to prefill an identity: the commit author (GitHub's name and
/// private no-reply address) and the organisations to offer as coverage. A host that cannot say
/// answers `200` with `problem`; Azure DevOps lets only a Microsoft Entra sign-in read a profile,
/// so it answers with the credential's own organisation and a note. Never opens a sign-in.
#[utoipa::path(
    post,
    path = "/api/credentials/profile",
    tag = "identities",
    request_body = AccountProfileRequest,
    responses(
        (status = OK, description = "the profile, or why it could not be read", body = AccountProfile),
        (status = UNPROCESSABLE_ENTITY, description = "a value refused", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn credential_profile(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<AccountProfileRequest>,
) -> Result<Json<AccountProfile>, ApiError> {
    let source = body.source.into_store()?;
    Ok(Json(state.repos.profile(source).await?.into()))
}
