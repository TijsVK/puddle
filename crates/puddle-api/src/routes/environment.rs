// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment variables and secrets, global and per workspace (credentials spec §9).
//!
//! A plain variable is kept in the database. A secret's value goes to the operating system's
//! credential store and nowhere else: the database keeps only the id it is filed under, and no
//! response carries the value, its length or any part of it. Where a change needs both, the
//! credential store is written first, so the host never sees a secret in the database whose value
//! is not there yet.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use puddle_secrets::{SecretStore, StoredId};
use puddle_store::{EnvDraft, EnvName, EnvScope, EnvValue, SecretHost, Store, check_secret_value};

use crate::ApiErrorBody;
use crate::error::{ApiError, ErrorCode, blocking};
use crate::extract::Path;
use crate::routes::AppState;
use crate::routes::identities::workspace;
use crate::wire::{EnvList, EnvSetRequest, EnvVariable, WorkspaceEnv};

fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
        "the operating system's credential store is not available; nothing was changed",
    )
}

/// A fresh id for a secret's value: `env-` and 128 random bits.
fn new_stored_id() -> Result<StoredId, ApiError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| ApiError::internal(&err))?;
    let id = bytes
        .iter()
        .fold(String::from("env-"), |id, byte| format!("{id}{byte:02x}"));
    StoredId::new(id).map_err(|err| ApiError::internal(&err))
}

/// Removes a secret's value that nothing refers to any more. The variable is already changed, so a
/// credential store that fails here only leaves an entry nobody reads: it is logged, not an error
/// for the caller.
fn drop_value(vault: &Arc<dyn SecretStore>, id: &StoredId) {
    if vault.delete(id).is_err() {
        tracing::warn!(secret = %id, "a secret's old value could not be removed from the credential store");
    }
}

/// Sets `name` in `scope`.
async fn set(
    state: &AppState,
    scope: EnvScope,
    name: &str,
    request: EnvSetRequest,
) -> Result<EnvVariable, ApiError> {
    let name = EnvName::new(name)?;
    let (store, vault): (Arc<Store>, Arc<dyn SecretStore>) =
        (Arc::clone(&state.store), Arc::clone(&state.secrets));
    blocking(move || match request {
        EnvSetRequest::Plain { value } => {
            let draft = EnvDraft::plain(&value)?;
            let change = store.set_env(&scope, &name, draft)?;
            // A secret that became a plain variable has no value to keep.
            if let Some(EnvValue::Secret(old)) = change.replaced.map(|e| e.value) {
                drop_value(&vault, &old.id);
            }
            Ok(EnvVariable::from_store(change.entry, false))
        }
        EnvSetRequest::Secret { value, hosts } => {
            let hosts = SecretHost::list(&hosts)?;
            let kept = match store.env_entry(&scope, &name)?.map(|e| e.value) {
                Some(EnvValue::Secret(secret)) => Some(secret.id),
                _ => None,
            };
            let (id, fresh) = match &kept {
                Some(id) => (id.clone(), false),
                None => (new_stored_id()?, true),
            };
            match value {
                Some(value) => {
                    check_secret_value(value.0.expose())?;
                    // Before the database: a secret in the database always has its value.
                    vault.set(&id, &value.0).map_err(|_| unavailable())?;
                }
                None if fresh => {
                    return Err(ApiError::invalid(
                        "a new secret needs its value; only one that is already a secret can keep its value",
                    ));
                }
                None => {}
            }
            let change = match store.set_env(&scope, &name, EnvDraft::secret(id.clone(), hosts)?) {
                Ok(change) => change,
                Err(err) => {
                    if fresh {
                        drop_value(&vault, &id);
                    }
                    return Err(err.into());
                }
            };
            // A value that replaced another secret's (two requests crossed) leaves that one alone
            // in the credential store.
            if let Some(EnvValue::Secret(old)) = change.replaced.map(|e| e.value)
                && old.id != id
            {
                drop_value(&vault, &old.id);
            }
            Ok(EnvVariable::from_store(change.entry, false))
        }
    })
    .await
}

/// Removes `name` from `scope`, and a secret's value from the credential store.
async fn remove(state: &AppState, scope: EnvScope, name: &str) -> Result<(), ApiError> {
    // Shape only: a name that is stored must stay removable.
    let name = EnvName::existing(name)?;
    let (store, vault): (Arc<Store>, Arc<dyn SecretStore>) =
        (Arc::clone(&state.store), Arc::clone(&state.secrets));
    blocking(move || {
        let Some(entry) = store.env_entry(&scope, &name)? else {
            // Says it in the store's words: no such variable in this scope.
            store.delete_env(&scope, &name)?;
            return Ok(());
        };
        // The value first: when the credential store is not there, the variable stays and the
        // user can try again, instead of a value left behind with nothing naming it.
        if let EnvValue::Secret(secret) = &entry.value {
            vault.delete(&secret.id).map_err(|_| unavailable())?;
        }
        store.delete_env(&scope, &name)?;
        Ok(())
    })
    .await
}

/// The global variables and secrets, by name. A secret shows its hosts and never its value.
#[utoipa::path(
    get,
    path = "/api/env",
    tag = "environment",
    responses((status = OK, description = "the global variables", body = EnvList))
)]
pub(crate) async fn list_global(State(state): State<AppState>) -> Result<Json<EnvList>, ApiError> {
    let list = blocking(move || {
        let variables = state
            .store
            .env_entries(&EnvScope::Global)?
            .into_iter()
            .map(|entry| EnvVariable::from_store(entry, false))
            .collect();
        Ok(EnvList { variables })
    })
    .await?;
    Ok(Json(list))
}

/// Sets a global variable or secret: every workspace gets it at its next start, unless it has its
/// own of the same name. A secret's hosts and value apply at once in running workspaces.
#[utoipa::path(
    put,
    path = "/api/env/{name}",
    tag = "environment",
    params(("name" = String, Path, description = "the variable's name")),
    request_body = EnvSetRequest,
    responses(
        (status = OK, description = "the variable now", body = EnvVariable),
        (status = UNPROCESSABLE_ENTITY, description = "a name, value or host that is refused, and why", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_global(
    State(state): State<AppState>,
    Path(name): Path<String>,
    crate::extract::Json(body): crate::extract::Json<EnvSetRequest>,
) -> Result<Json<EnvVariable>, ApiError> {
    Ok(Json(set(&state, EnvScope::Global, &name, body).await?))
}

/// Removes a global variable or secret, and a secret's value from the credential store.
#[utoipa::path(
    delete,
    path = "/api/env/{name}",
    tag = "environment",
    params(("name" = String, Path, description = "the variable's name")),
    responses(
        (status = NO_CONTENT, description = "removed"),
        (status = NOT_FOUND, description = "no such variable", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available; nothing was removed", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_global(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    remove(&state, EnvScope::Global, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What a workspace sees: its own variables and the global ones, by name. A global variable that
/// the workspace's own of the same name hides follows it with `overridden` set.
#[utoipa::path(
    get,
    path = "/api/workspaces/{id}/env",
    tag = "environment",
    params(("id" = String, Path, description = "workspace id")),
    responses(
        (status = OK, description = "the workspace's variables", body = WorkspaceEnv),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody)
    )
)]
pub(crate) async fn list_workspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WorkspaceEnv>, ApiError> {
    let name = workspace(&state, &id).await?;
    let shown = name.clone();
    let variables = blocking(move || {
        Ok(state
            .store
            .workspace_env(&name)?
            .into_iter()
            .map(|row| EnvVariable::from_store(row.entry, row.overridden))
            .collect())
    })
    .await?;
    Ok(Json(WorkspaceEnv {
        workspace: shown,
        variables,
    }))
}

/// Sets a variable or secret for one workspace; it wins over a global one of the same name. The
/// workspace's environment is read when it starts, so a plain variable reaches a running workspace
/// at its next start; a secret's hosts and value apply from the next connection.
#[utoipa::path(
    put,
    path = "/api/workspaces/{id}/env/{name}",
    tag = "environment",
    params(
        ("id" = String, Path, description = "workspace id"),
        ("name" = String, Path, description = "the variable's name")
    ),
    request_body = EnvSetRequest,
    responses(
        (status = OK, description = "the variable now", body = EnvVariable),
        (status = NOT_FOUND, description = "no such workspace", body = ApiErrorBody),
        (status = UNPROCESSABLE_ENTITY, description = "a name, value or host that is refused, and why", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available", body = ApiErrorBody)
    )
)]
pub(crate) async fn put_workspace(
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
    crate::extract::Json(body): crate::extract::Json<EnvSetRequest>,
) -> Result<Json<EnvVariable>, ApiError> {
    let workspace = workspace(&state, &id).await?;
    Ok(Json(
        set(&state, EnvScope::Workspace(workspace), &name, body).await?,
    ))
}

/// Removes a variable or secret from one workspace, and a secret's value from the credential
/// store. A global variable of the same name applies again.
#[utoipa::path(
    delete,
    path = "/api/workspaces/{id}/env/{name}",
    tag = "environment",
    params(
        ("id" = String, Path, description = "workspace id"),
        ("name" = String, Path, description = "the variable's name")
    ),
    responses(
        (status = NO_CONTENT, description = "removed"),
        (status = NOT_FOUND, description = "no such workspace, or no such variable of its own", body = ApiErrorBody),
        (status = SERVICE_UNAVAILABLE, description = "the credential store is not available; nothing was removed", body = ApiErrorBody)
    )
)]
pub(crate) async fn delete_workspace(
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let workspace = workspace(&state, &id).await?;
    remove(&state, EnvScope::Workspace(workspace), &name).await?;
    Ok(StatusCode::NO_CONTENT)
}
