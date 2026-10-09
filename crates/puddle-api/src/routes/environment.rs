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
use puddle_store::{
    EnvDraft, EnvEntry, EnvName, EnvScope, EnvValue, SecretHost, Store, check_secret_value,
};

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

/// Removes the value of the secret a change replaced, unless the new entry keeps it (`kept`): a
/// secret that became a plain variable has none to keep, and one replaced by another request's
/// secret (two requests crossed) leaves its value behind with nothing that names it.
fn drop_replaced(
    vault: &Arc<dyn SecretStore>,
    replaced: Option<EnvEntry>,
    kept: Option<&StoredId>,
) {
    if let Some(old) = replaced.as_ref().and_then(|e| e.value.as_secret())
        && Some(&old.id) != kept
    {
        drop_value(vault, &old.id);
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
            drop_replaced(&vault, change.replaced, None);
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
            drop_replaced(&vault, change.replaced, Some(&id));
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
        // The value first: when the credential store is not there, the variable stays and the
        // user can try again, instead of a value left behind with nothing naming it.
        let entry = store.env_entry(&scope, &name)?;
        if let Some(secret) = entry.as_ref().and_then(|e| e.value.as_secret()) {
            vault.delete(&secret.id).map_err(|_| unavailable())?;
        }
        // A name that is not set says so here, in the store's words: no such variable in this scope.
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

#[cfg(test)]
mod tests {
    use puddle_secrets::{MemoryStore, Secret};
    use puddle_store::{Limits, ManualClock};

    use super::*;

    fn entry_of(store: &Store, name: &str, draft: EnvDraft) -> EnvEntry {
        store
            .set_env(&EnvScope::Global, &EnvName::new(name).unwrap(), draft)
            .unwrap()
            .entry
    }

    #[test]
    fn the_value_of_a_replaced_secret_is_removed_unless_the_new_entry_keeps_it() {
        let store =
            Store::open_in_memory(Arc::new(ManualClock::new(1)), Limits::default()).unwrap();
        let memory = Arc::new(MemoryStore::new());
        let vault: Arc<dyn SecretStore> = memory.clone();
        let id = |text: &str| StoredId::new(text).unwrap();
        let hosts = || SecretHost::list(&["a.example.com"]).unwrap();
        for name in ["env-a", "env-b"] {
            memory.set(&id(name), &Secret::new("v".to_owned())).unwrap();
        }
        let secret_a = entry_of(&store, "A", EnvDraft::secret(id("env-a"), hosts()).unwrap());
        let plain = entry_of(&store, "P", EnvDraft::plain("x").unwrap());

        // Kept: the same id stays. Another request's secret replaced it: the other id goes.
        drop_replaced(&vault, Some(secret_a.clone()), Some(&id("env-a")));
        assert_eq!(memory.ids(), ["env-a", "env-b"]);
        drop_replaced(&vault, Some(secret_a.clone()), Some(&id("env-b")));
        assert_eq!(memory.ids(), ["env-b"]);
        // Nothing replaced, or a plain variable replaced: nothing to remove.
        drop_replaced(&vault, None, Some(&id("env-b")));
        drop_replaced(&vault, Some(plain), None);
        assert_eq!(memory.ids(), ["env-b"]);
        // A secret that became plain has no value to keep.
        drop_replaced(
            &vault,
            Some(entry_of(
                &store,
                "B",
                EnvDraft::secret(id("env-b"), hosts()).unwrap(),
            )),
            None,
        );
        assert_eq!(memory.ids(), Vec::<String>::new());
        // A credential store that fails is logged, not an error.
        memory.break_it();
        drop_replaced(&vault, Some(secret_a), None);
    }
}
