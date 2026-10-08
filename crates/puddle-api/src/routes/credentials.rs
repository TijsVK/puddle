// SPDX-License-Identifier: GPL-3.0-or-later
//! What the identities screens ask of the host about credentials: the accounts already signed in
//! here, whether a credential can be read now, a pasted token (write-only) and signing in on a
//! click. Nothing here returns a secret value.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_secrets::StoredId;

use crate::ApiErrorBody;
use crate::credentials::Check;
use crate::error::ApiError;
use crate::extract::Path;
use crate::routes::AppState;
use crate::wire::{
    CheckRequest, CheckResult, CredentialSource, FoundAccount, FoundAccounts, FoundProblem,
    FoundVia, SignInRequest, SignInStarted, StoreTokenRequest, StoredToken,
};

/// The accounts already signed in on this computer (names only), from a fixed list of listing
/// commands. A listing that could not run is named in `problems`.
#[utoipa::path(
    get,
    path = "/api/credentials/found",
    tag = "identities",
    responses(
        (status = OK, description = "the accounts found", body = FoundAccounts),
        (status = SERVICE_UNAVAILABLE, description = "not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn found_accounts(
    State(state): State<AppState>,
) -> Result<Json<FoundAccounts>, ApiError> {
    let found = state.credentials.found().await?;
    Ok(Json(FoundAccounts {
        accounts: found
            .accounts
            .iter()
            .map(FoundAccount::from_discovered)
            .collect(),
        problems: found
            .problems
            .iter()
            .map(|(listing, err)| FoundProblem {
                via: FoundVia::from_listing(*listing),
                message: crate::wire::source_problem(err),
            })
            .collect(),
    }))
}

/// Reads a credential once and says whether that worked, never the value. Never opens a sign-in.
#[utoipa::path(
    post,
    path = "/api/credentials/check",
    tag = "identities",
    request_body = CheckRequest,
    responses(
        (status = OK, description = "whether it can be read", body = CheckResult),
        (status = UNPROCESSABLE_ENTITY, description = "a value refused", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "not available in this build", body = ApiErrorBody)
    )
)]
pub(crate) async fn check_credential(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<CheckRequest>,
) -> Result<Json<CheckResult>, ApiError> {
    let source = body.source.into_store()?;
    Ok(Json(match state.credentials.check(source).await? {
        Check::Readable => CheckResult::readable(),
        Check::Problem(err) => CheckResult::from_error(&err),
    }))
}

/// Keeps a pasted token in the operating system's credential store and answers with the source
/// that names it. The token is never read back.
#[utoipa::path(
    post,
    path = "/api/credentials/stored",
    tag = "identities",
    request_body = StoreTokenRequest,
    responses(
        (status = CREATED, description = "the token is kept", body = StoredToken),
        (status = UNPROCESSABLE_ENTITY, description = "the host, organisation or token is refused", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn store_token(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<StoreTokenRequest>,
) -> Result<(StatusCode, Json<StoredToken>), ApiError> {
    let (scope, token) = body.into_parts()?;
    let source = state.credentials.store_token(scope, token).await?;
    let source = CredentialSource::from_store(&source)
        .ok_or_else(|| ApiError::internal(&"a stored token came back as another kind of source"))?;
    Ok((StatusCode::CREATED, Json(StoredToken { source })))
}

/// Removes a pasted token from the credential store; one that is already gone counts as removed.
#[utoipa::path(
    delete,
    path = "/api/credentials/stored/{id}",
    tag = "identities",
    params(("id" = String, Path, description = "the stored entry's id")),
    responses(
        (status = NO_CONTENT, description = "removed"),
        (status = UNPROCESSABLE_ENTITY, description = "not a stored entry's id", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn forget_token(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let id =
        StoredId::new(id).map_err(|_| ApiError::invalid("not a valid stored credential id"))?;
    state.credentials.forget_token(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Starts a sign-in the user finishes outside puddle: `gh` shows a one-time code and an address,
/// Git Credential Manager opens its own window. Only from a click; a request from a workspace
/// never does this. Check the credential until it reads; puddle ends an unfinished sign-in after
/// five minutes.
#[utoipa::path(
    post,
    path = "/api/credentials/sign-in",
    tag = "identities",
    request_body = SignInRequest,
    responses(
        (status = OK, description = "the sign-in is open", body = SignInStarted),
        (status = UNPROCESSABLE_ENTITY, description = "a pasted token has nothing to sign in to", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the tool is missing or showed no code", body = ApiErrorBody)
    )
)]
pub(crate) async fn sign_in(
    State(state): State<AppState>,
    crate::extract::Json(body): crate::extract::Json<SignInRequest>,
) -> Result<Json<SignInStarted>, ApiError> {
    let source = body.source.into_store()?;
    Ok(Json(state.credentials.sign_in(source).await?.into()))
}
