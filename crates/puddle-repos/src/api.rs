// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam between the listing logic and the network: one `GET` to a Git host's API.
//!
//! The listing code never opens a connection itself, so its tests run on scripted answers
//! ([`crate::FakeApi`]) and the real route (company proxy, platform TLS) is exercised once, in
//! `transport`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::future::BoxFuture;
use http::HeaderValue;
use puddle_secrets::Secret;

/// How a request proves who sends it. The token stays inside; nothing prints it.
#[derive(Clone)]
#[non_exhaustive]
pub enum Authorization {
    /// `Authorization: Bearer <token>` (GitHub tokens; an Entra access token).
    Bearer(Arc<Secret>),
    /// `Authorization: Basic base64(:<token>)` (an Azure DevOps personal access token).
    BasicPassword(Arc<Secret>),
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bearer(_) => "Authorization::Bearer(<redacted>)",
            Self::BasicPassword(_) => "Authorization::BasicPassword(<redacted>)",
        })
    }
}

impl Authorization {
    /// The header value, marked sensitive so nothing logs it. `None` when the token has a
    /// character a header cannot carry.
    pub(crate) fn header_value(&self) -> Option<HeaderValue> {
        let text = match self {
            Self::Bearer(token) => format!("Bearer {}", token.expose()),
            Self::BasicPassword(token) => {
                format!("Basic {}", STANDARD.encode(format!(":{}", token.expose())))
            }
        };
        let mut value = HeaderValue::from_str(&text).ok()?;
        value.set_sensitive(true);
        Some(value)
    }

    /// Whether the token starts with `prefix`, to tell a kind of token without keeping it.
    pub(crate) fn token_starts_with(&self, prefix: &str) -> bool {
        match self {
            Self::Bearer(token) | Self::BasicPassword(token) => token.expose().starts_with(prefix),
        }
    }

    /// The token itself, for a check that it is the one a test expects.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn token(&self) -> &str {
        match self {
            Self::Bearer(token) | Self::BasicPassword(token) => token.expose(),
        }
    }

    /// Whether it goes as `Bearer`, for a check of which scheme a test expects.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn is_bearer(&self) -> bool {
        matches!(self, Self::Bearer(_))
    }
}

/// One `GET`.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// The API's host with its port when it is not 443: `api.github.com`, `dev.azure.com`.
    pub host: String,
    /// The path and query, starting with `/`.
    pub path: String,
    /// The `Accept` header.
    pub accept: &'static str,
    /// Extra fixed headers (an API version).
    pub headers: &'static [(&'static str, &'static str)],
    /// The credential.
    pub authorization: Authorization,
}

/// A host's answer, headers lower-cased (the first value of a repeated header wins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiReply {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: BTreeMap<String, String>,
    /// The body, at most [`MAX_BODY`] bytes.
    pub body: Vec<u8>,
}

/// The most a single answer may carry. A list of ten thousand repositories is a few megabytes.
pub const MAX_BODY: usize = 16 * 1024 * 1024;

impl ApiReply {
    /// An answer with this status and body and no headers.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    /// The same answer with one more header (the name is lower-cased).
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .insert(name.to_ascii_lowercase(), value.to_owned());
        self
    }

    /// A header by lower-case name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// Why no answer came.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// No connection could be made (no route, a refused proxy, DNS).
    #[error("{0}")]
    Unreachable(String),
    /// The server's certificate or the TLS handshake failed.
    #[error("{0}")]
    Tls(String),
    /// The exchange took too long.
    #[error("no answer within {0} seconds")]
    Timeout(u64),
    /// The answer was larger than [`MAX_BODY`].
    #[error("the answer is larger than {} MiB", MAX_BODY / (1024 * 1024))]
    TooLarge,
    /// The server spoke something other than HTTP, or hung up.
    #[error("{0}")]
    Protocol(String),
    /// The request could not be made: the token has a character a header cannot carry.
    #[error("the token has a character an HTTP header cannot carry")]
    BadToken,
}

/// Sends a `GET` to a Git host's API.
pub trait Api: Send + Sync {
    /// One request, one answer. Never follows a redirect: the token goes to the host asked for
    /// and nowhere else.
    fn get(&self, request: ApiRequest) -> BoxFuture<'_, Result<ApiReply, TransportError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_value_is_built_per_scheme_and_is_marked_sensitive() {
        let token = Arc::new(Secret::new("CANARY-token".to_owned()));
        let bearer = Authorization::Bearer(token.clone()).header_value().unwrap();
        assert_eq!(bearer.to_str().unwrap(), "Bearer CANARY-token");
        assert!(bearer.is_sensitive());
        let basic = Authorization::BasicPassword(token).header_value().unwrap();
        assert_eq!(
            basic.to_str().unwrap(),
            format!("Basic {}", STANDARD.encode(":CANARY-token"))
        );
    }

    #[test]
    fn a_token_a_header_cannot_carry_gives_no_header_and_debug_never_shows_it() {
        let bad = Arc::new(Secret::new("CANARY-line\nbreak".to_owned()));
        let auth = Authorization::Bearer(bad);
        assert!(auth.header_value().is_none());
        assert_eq!(format!("{auth:?}"), "Authorization::Bearer(<redacted>)");
        assert_eq!(
            format!(
                "{:?}",
                Authorization::BasicPassword(Arc::new(Secret::new("CANARY-x".to_owned())))
            ),
            "Authorization::BasicPassword(<redacted>)"
        );
    }

    #[test]
    fn a_header_is_found_by_its_lower_case_name() {
        let reply = ApiReply::new(200, "[]").with_header("Link", "<x>");
        assert_eq!(reply.header("link"), Some("<x>"));
        assert_eq!(reply.header("etag"), None);
        assert_eq!(reply.body, b"[]");
    }
}
