// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam where a credential joins a terminated request.
//!
//! The terminating proxy parses each request and asks an [`Injector`] what to do with it. The
//! injector lives outside the transport: it knows bindings, secret sources and path rules, the
//! proxy knows TLS and HTTP framing. Everything that must hold whatever the injector says is
//! enforced here, not trusted to it: the injector never sees the connection, only a read-only
//! [`RequestView`], and what it returns is a closed set of outcomes.

use std::fmt;

use ::http::{HeaderName, HeaderValue};
use puddle_types::{Host, WorkspaceName};

use crate::destination::BoxFuture;

/// A header value that is a secret: never printed, never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps `value`.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One header to add to a request, with a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectedHeader {
    name: HeaderName,
    value: SecretValue,
}

/// Why a header could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// The name is not a valid header name, or is one the proxy owns (`Host`, framing,
    /// connection management).
    #[error("not a header an injector may set")]
    Name,
    /// The value has bytes a header cannot carry.
    #[error("the header value has characters a header cannot carry")]
    Value,
}

impl InjectedHeader {
    /// A header `name: value`. The name must be a plain end-to-end header: `Host`, `Connection`,
    /// `Content-Length`, `Transfer-Encoding` and the other hop-by-hop headers belong to the
    /// proxy.
    ///
    /// # Errors
    /// [`HeaderError`].
    pub fn new(name: &str, value: SecretValue) -> Result<Self, HeaderError> {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| HeaderError::Name)?;
        if crate::terminate::request::is_proxy_owned(&name) {
            return Err(HeaderError::Name);
        }
        HeaderValue::from_str(value.expose()).map_err(|_| HeaderError::Value)?;
        Ok(Self { name, value })
    }

    pub(crate) fn name(&self) -> &HeaderName {
        &self.name
    }

    pub(crate) fn header_value(&self) -> Option<HeaderValue> {
        let mut value = HeaderValue::from_str(self.value.expose()).ok()?;
        value.set_sensitive(true);
        Some(value)
    }
}

/// What the proxy adds to a request: the headers, and the binding that supplied them (by id,
/// for the audit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injection {
    binding_id: String,
    headers: Vec<InjectedHeader>,
}

impl Injection {
    /// `headers` for the request, from the binding `binding_id`.
    #[must_use]
    pub fn new(binding_id: impl Into<String>, headers: Vec<InjectedHeader>) -> Self {
        Self {
            binding_id: binding_id.into(),
            headers,
        }
    }

    pub(crate) fn binding_id(&self) -> &str {
        &self.binding_id
    }

    pub(crate) fn headers(&self) -> &[InjectedHeader] {
        &self.headers
    }
}

/// An error answer the injector wants sent to the guest instead of forwarding the request: a
/// push to a repository that is not on the list, a secret that could not be read.
///
/// The status is 4xx or 5xx but never `401` or `407`: either would make the guest's tool
/// prompt for a password that does not exist. Those (and anything out of range) become `502`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectRefusal {
    status: u16,
    code: &'static str,
    message: String,
}

impl InjectRefusal {
    /// A refusal with `status`, a machine-readable `code` (sent as `x-puddle-blocked: <code>`)
    /// and a one-line `message` for the user.
    #[must_use]
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        let status = if (400..=599).contains(&status) && !matches!(status, 401 | 407) {
            status
        } else {
            502
        };
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// What to do with one terminated request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectDecision {
    /// Forward it with these headers added. The guest's own `Authorization` and
    /// `Proxy-Authorization` are removed first, so nothing the guest sent competes with the
    /// credential.
    Inject(Injection),
    /// Forward it as the guest sent it (no credential applies to it).
    PassThrough,
    /// Answer the guest with this error; nothing is sent upstream.
    Refuse(InjectRefusal),
}

/// The connection a request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct InjectContext<'a> {
    /// The workspace, from the route.
    pub workspace: &'a WorkspaceName,
    /// The host the guest `CONNECT`ed to, which the certificate, the `Host` header and the
    /// upstream connection are all pinned to.
    pub host: &'a Host,
}

/// A parsed request as the injector sees it. The proxy has already checked its framing, its
/// `Host` and its target.
#[derive(Debug, Clone, Copy)]
pub struct RequestView<'a> {
    pub(crate) method: &'a str,
    pub(crate) target: &'a str,
    pub(crate) headers: &'a [String],
}

impl<'a> RequestView<'a> {
    /// The method as sent (case kept).
    #[must_use]
    pub fn method(&self) -> &'a str {
        self.method
    }

    /// The path and query as sent, always starting with `/`. Not decoded or normalised: a rule
    /// that matches paths must reject non-canonical forms itself.
    #[must_use]
    pub fn target(&self) -> &'a str {
        self.target
    }

    /// The path, without the query.
    #[must_use]
    pub fn path(&self) -> &'a str {
        self.target
            .split_once('?')
            .map_or(self.target, |(path, _)| path)
    }

    /// The query string, without the `?`.
    #[must_use]
    pub fn query(&self) -> Option<&'a str> {
        self.target.split_once('?').map(|(_, query)| query)
    }

    /// The values of every header called `name` (case-insensitive), in order.
    pub fn header_values(&self, name: &str) -> impl Iterator<Item = &'a str> + use<'a, '_> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(move |line| crate::http::header_name(line) == wanted)
            .map(|line| crate::http::header_value(line))
    }

    /// The first value of the header `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.header_values(name).next()
    }
}

/// Decides, per terminated request, whether a credential goes with it.
///
/// One injector serves one workspace. `decide` runs after the upstream's certificate has been
/// verified, so a failed verification never reaches it, and before any request byte is sent
/// upstream. It may take its time (a secret source), but the guest is waiting.
pub trait Injector: Send + Sync + fmt::Debug {
    /// The outcome for `request`.
    fn decide<'a>(
        &'a self,
        context: &'a InjectContext<'a>,
        request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision>;
}

/// An injector that never injects: every request passes through untouched. Terminating with it
/// changes what the proxy can see and nothing else.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoInjection;

impl Injector for NoInjection {
    fn decide<'a>(
        &'a self,
        _context: &'a InjectContext<'a>,
        _request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision> {
        Box::pin(std::future::ready(InjectDecision::PassThrough))
    }
}
