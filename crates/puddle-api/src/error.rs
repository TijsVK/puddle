// SPDX-License-Identifier: GPL-3.0-or-later
//! Error responses: one JSON shape for every refusal and failure.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use puddle_settings::SettingsError;
use puddle_store::StoreError;
use serde::Serialize;
use utoipa::ToSchema;

use crate::network_health::NetworkHealthError;
use crate::settings::SettingsRepoError;
use crate::workspaces::WorkspaceError;

/// What went wrong, as a stable code a client can switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The `Host` header isn't the API's own address (421).
    MisdirectedHost,
    /// The `Origin` header names another site (403).
    ForbiddenOrigin,
    /// The bearer token is missing or wrong (401).
    Unauthorized,
    /// The request is malformed: bad JSON, a bad path or query value (400).
    BadRequest,
    /// The body isn't `application/json` (415).
    UnsupportedMediaType,
    /// The body is too large (413).
    PayloadTooLarge,
    /// A value in the request is out of range or refused (422).
    Invalid,
    /// No such route, rule or pending request (404).
    NotFound,
    /// The request conflicts with the current state, e.g. an already decided request (409).
    Conflict,
    /// Two identities on one workspace cover the same owner or both cover the rest of a host
    /// (409); the message names both.
    IdentityCollision,
    /// The stored settings were written by a newer puddle and can't be changed by this one (409).
    NewerSettings,
    /// The feature isn't available in this build or state (503).
    Unavailable,
    /// puddle failed; the details are in its log (500).
    Internal,
}

/// The body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct ApiErrorBody {
    /// Stable error code.
    pub error: ErrorCode,
    /// Human-readable, lower case, no trailing period. Never contains a token.
    pub message: String,
}

/// An error a handler or the guard returns; becomes a status and an [`ApiErrorBody`].
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    body: ApiErrorBody,
    /// What went wrong, for the host's own use; never serialized (the client of an internal
    /// error learns only that it failed).
    detail: Option<String>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, error: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiErrorBody {
                error,
                message: message.into(),
            },
            detail: None,
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ErrorCode::NotFound, message)
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::Invalid,
            message,
        )
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::BadRequest, message)
    }

    /// A failure inside puddle. `detail` is logged here (this is where the error is consumed);
    /// the client only learns that something failed.
    pub(crate) fn internal(detail: &dyn std::fmt::Display) -> Self {
        tracing::error!(error = %detail, "api request failed");
        let mut err = Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error; see puddle's log",
        );
        err.detail = Some(detail.to_string());
        err
    }

    /// The cause as the host sees it: the detail of an internal error, else the message.
    pub(crate) fn reason(&self) -> &str {
        self.detail.as_deref().unwrap_or(&self.body.message)
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    #[cfg(test)]
    pub(crate) fn code(&self) -> ErrorCode {
        self.body.error
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.body)).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"puddle\""),
            );
        }
        response
    }
}

impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::UnknownPending(_)
            | StoreError::UnknownRule(_)
            | StoreError::UnknownRuleSet(_) => Self::not_found(err.to_string()),
            StoreError::UnknownIdentity(_) | StoreError::UnknownRepo(_) => {
                Self::not_found(err.to_string())
            }
            StoreError::IdentityCollision(_) => Self::new(
                StatusCode::CONFLICT,
                ErrorCode::IdentityCollision,
                err.to_string(),
            ),
            StoreError::PendingNotOpen { .. }
            | StoreError::RuleSetOff { .. }
            | StoreError::IdentityLabelTaken(_)
            | StoreError::IdentityAttached { .. }
            | StoreError::RepoListed(_) => {
                Self::new(StatusCode::CONFLICT, ErrorCode::Conflict, err.to_string())
            }
            StoreError::Pattern(_)
            | StoreError::ExpiryNotInFuture
            | StoreError::NotSwitchable
            | StoreError::RuleSetName(_)
            | StoreError::IdentityInvalid(_) => Self::invalid(err.to_string()),
            _ => Self::internal(&err),
        }
    }
}

impl From<SettingsError> for ApiError {
    fn from(err: SettingsError) -> Self {
        match err {
            SettingsError::NewerSchema { .. } => Self::new(
                StatusCode::CONFLICT,
                ErrorCode::NewerSettings,
                format!("{err}; update puddle to change these settings"),
            ),
            _ => Self::internal(&err),
        }
    }
}

impl From<WorkspaceError> for ApiError {
    fn from(err: WorkspaceError) -> Self {
        match err {
            WorkspaceError::NotFound(m) => Self::not_found(m),
            WorkspaceError::Conflict(m) => Self::new(StatusCode::CONFLICT, ErrorCode::Conflict, m),
            WorkspaceError::Invalid(m) => Self::invalid(m),
            WorkspaceError::Unavailable(m) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable, m)
            }
            WorkspaceError::Internal(m) => Self::internal(&m),
        }
    }
}

impl From<NetworkHealthError> for ApiError {
    fn from(err: NetworkHealthError) -> Self {
        match err {
            NetworkHealthError::Unavailable(m) => {
                Self::new(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable, m)
            }
        }
    }
}

impl From<SettingsRepoError> for ApiError {
    fn from(err: SettingsRepoError) -> Self {
        Self::internal(&err)
    }
}

/// Runs blocking work (`SQLite`, settings storage) off the async threads. A panic in it becomes a
/// 500, never a crashed server.
pub(crate) async fn blocking<T, F>(work: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|err| ApiError::internal(&err))?
}

#[cfg(test)]
mod tests {
    use puddle_types::{PendingId, RuleId};

    use super::*;

    #[test]
    fn store_errors_map_to_client_statuses() {
        let cases = [
            (
                StoreError::UnknownPending(PendingId(1)),
                StatusCode::NOT_FOUND,
            ),
            (StoreError::UnknownRule(RuleId(1)), StatusCode::NOT_FOUND),
            (
                StoreError::UnknownRuleSet("user:1".into()),
                StatusCode::NOT_FOUND,
            ),
            (
                StoreError::RuleSetOff {
                    set: "user:1".into(),
                    workspace: "a".into(),
                },
                StatusCode::CONFLICT,
            ),
            (StoreError::NotSwitchable, StatusCode::UNPROCESSABLE_ENTITY),
            (
                StoreError::RuleSetName("taken".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                StoreError::PendingNotOpen {
                    id: PendingId(1),
                    state: puddle_store::PendingState::Allowed,
                },
                StatusCode::CONFLICT,
            ),
            (
                StoreError::ExpiryNotInFuture,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (StoreError::SystemActor, StatusCode::INTERNAL_SERVER_ERROR),
            (
                StoreError::UnknownIdentity(puddle_store::IdentityId(1)),
                StatusCode::NOT_FOUND,
            ),
            (StoreError::UnknownRepo(1), StatusCode::NOT_FOUND),
            (
                StoreError::IdentityInvalid("x".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                StoreError::IdentityLabelTaken("x".into()),
                StatusCode::CONFLICT,
            ),
            (
                StoreError::IdentityAttached { label: "x".into() },
                StatusCode::CONFLICT,
            ),
            (StoreError::RepoListed("x".into()), StatusCode::CONFLICT),
        ];
        for (err, status) in cases {
            assert_eq!(ApiError::from(err).status(), status);
        }
    }

    #[test]
    fn settings_errors_map_newer_schema_to_a_conflict() {
        let newer = ApiError::from(SettingsError::NewerSchema {
            kind: "global",
            found: 9,
            supported: 1,
        });
        assert_eq!(newer.status(), StatusCode::CONFLICT);
        assert_eq!(newer.code(), ErrorCode::NewerSettings);
        let other = ApiError::from(SettingsError::NotAnObject { kind: "global" });
        assert_eq!(other.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let repo = ApiError::from(SettingsRepoError::new("disk full"));
        assert_eq!(repo.code(), ErrorCode::Internal);
    }

    #[test]
    fn workspace_errors_map_to_client_statuses() {
        let cases = [
            (
                WorkspaceError::NotFound("x".into()),
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
            ),
            (
                WorkspaceError::Conflict("x".into()),
                StatusCode::CONFLICT,
                ErrorCode::Conflict,
            ),
            (
                WorkspaceError::Invalid("x".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
                ErrorCode::Invalid,
            ),
            (
                WorkspaceError::Unavailable("x".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::Unavailable,
            ),
            (
                WorkspaceError::Internal("disk path /secret".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::Internal,
            ),
        ];
        for (err, status, code) in cases {
            let api = ApiError::from(err);
            assert_eq!(api.status(), status);
            assert_eq!(api.code(), code);
            assert!(!api.body.message.contains("secret"));
        }
    }

    #[tokio::test]
    async fn a_panicking_blocking_task_is_a_500() {
        let err = blocking::<(), _>(|| panic!("boom")).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let ok = blocking(|| Ok(7)).await.unwrap();
        assert_eq!(ok, 7);
    }
}
