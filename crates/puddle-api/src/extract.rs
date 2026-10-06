// SPDX-License-Identifier: GPL-3.0-or-later
//! axum extractors whose rejections are [`ApiErrorBody`](crate::ApiErrorBody) JSON like every
//! other error, instead of axum's plain-text ones.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{ApiError, ErrorCode};

/// A JSON object body (`Content-Type: application/json` required). Anything but an object is
/// refused, so serde can't read a struct from an array.
#[derive(Debug)]
pub(crate) struct Json<T>(pub(crate) T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Json<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        let axum::Json(value) = axum::Json::<Value>::from_request(request, state).await?;
        if !value.is_object() {
            return Err(ApiError::invalid("the body must be a JSON object"));
        }
        T::deserialize(value)
            .map(Json)
            .map_err(|err| ApiError::invalid(format!("invalid body: {err}")))
    }
}

/// Path parameters.
#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub(crate) struct Path<T>(pub(crate) T);

/// Query parameters.
#[derive(Debug, FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub(crate) struct Query<T>(pub(crate) T);

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        let message = rejection.body_text();
        match rejection {
            JsonRejection::MissingJsonContentType(_) => Self::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ErrorCode::UnsupportedMediaType,
                "the body must be application/json",
            ),
            JsonRejection::BytesRejection(ref bytes)
                if bytes.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                Self::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorCode::PayloadTooLarge,
                    "the body is too large",
                )
            }
            _ => Self::bad_request(message),
        }
    }
}

impl From<PathRejection> for ApiError {
    fn from(rejection: PathRejection) -> Self {
        Self::bad_request(rejection.body_text())
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rejection: QueryRejection) -> Self {
        Self::bad_request(rejection.body_text())
    }
}
