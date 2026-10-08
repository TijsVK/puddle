// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam where a credential joins a terminated request.
//!
//! The terminating proxy parses each request and asks an [`Injector`] what to do with it. The
//! injector lives outside the transport: it knows bindings, secret sources and path rules, the
//! proxy knows TLS and HTTP framing. Everything that must hold whatever the injector says is
//! enforced here, not trusted to it: the injector never sees the connection, only a read-only
//! [`RequestView`], and what it returns is a closed set of outcomes.

use std::fmt;
use std::sync::Arc;

use ::http::{HeaderName, HeaderValue};
use puddle_types::{Host, WorkspaceName};
use zeroize::Zeroize as _;

use crate::destination::BoxFuture;
use crate::proxy::Refusal;

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

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
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

    /// The header's name.
    #[must_use]
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Whether the value is exactly `expected`. For a test or a check that already holds the
    /// value; the value itself is never handed out.
    #[must_use]
    pub fn value_is(&self, expected: &str) -> bool {
        self.value.expose() == expected
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
    unauthorized: Option<Unauthorized>,
}

impl Injection {
    /// `headers` for the request, from the binding `binding_id`.
    #[must_use]
    pub fn new(binding_id: impl Into<String>, headers: Vec<InjectedHeader>) -> Self {
        Self {
            binding_id: binding_id.into(),
            headers,
            unauthorized: None,
        }
    }

    /// If the real server answers this request with `401`, send the guest `unauthorized`'s
    /// refusal instead: the credential that was added was not accepted, and a `401` would make
    /// the guest's tool ask for a password the workspace does not have.
    #[must_use]
    pub fn on_unauthorized(mut self, unauthorized: Unauthorized) -> Self {
        self.unauthorized = Some(unauthorized);
        self
    }

    /// The binding that supplied the headers, as the audit records it.
    #[must_use]
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// The headers to add.
    #[must_use]
    pub fn headers(&self) -> &[InjectedHeader] {
        &self.headers
    }
}

/// What to answer the guest when the real server answers a request with `401`, for a request the
/// injector chose the credential for: it added one ([`Injection::on_unauthorized`]) or had none
/// to add ([`InjectDecision::PassThroughGuarded`]). The proxy calls it when the `401` arrives and
/// sends the refusal it returns instead of the server's answer, so the guest's tool never prompts
/// for a password the workspace does not hold. A request that carried the guest's own
/// credentials is never given one: the server's `401` is the tool's to handle.
#[derive(Clone)]
pub struct Unauthorized(Arc<dyn Fn() -> InjectRefusal + Send + Sync>);

impl Unauthorized {
    /// `answer` runs each time a `401` is replaced, so it can also forget what it cached.
    #[must_use]
    pub fn new(answer: impl Fn() -> InjectRefusal + Send + Sync + 'static) -> Self {
        Self(Arc::new(answer))
    }

    /// The refusal to answer with now. The proxy calls it when the server's `401` arrives; so may
    /// a test.
    #[must_use]
    pub fn refusal(&self) -> InjectRefusal {
        (self.0)()
    }
}

impl fmt::Debug for Unauthorized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Unauthorized")
    }
}

impl PartialEq for Unauthorized {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Unauthorized {}

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

    /// The HTTP status the guest gets (`4xx`/`5xx`, never `401` or `407`).
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The machine-readable code, sent as `x-puddle-blocked`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The one-line message for the user.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The answer the guest gets: the status line, `x-puddle-blocked: <code>` and the message.
    pub(crate) fn to_refusal(&self) -> Refusal {
        let status =
            ::http::StatusCode::from_u16(self.status).unwrap_or(::http::StatusCode::BAD_GATEWAY);
        let line = format!(
            "{} {}",
            status.as_str(),
            status.canonical_reason().unwrap_or("")
        );
        Refusal::new(line, self.message.clone()).header("x-puddle-blocked", self.code)
    }
}

/// What to do with one terminated request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectDecision {
    /// Forward it with these headers added. A header of the same name the guest sent is
    /// replaced; any other header of the guest's is left alone.
    Inject(Injection),
    /// Forward it as the guest sent it (no credential applies to it).
    PassThrough,
    /// Forward it as the guest sent it, but if the real server answers `401`, send the guest
    /// this instead: the injector is responsible for the credentials of this request and has
    /// none to add.
    PassThroughGuarded(Unauthorized),
    /// Answer the guest with this error; nothing is sent upstream.
    Refuse(InjectRefusal),
}

/// What the proxy does with a request after the injector decided.
pub(crate) struct Forwarding {
    pub(crate) injection: Option<Injection>,
    pub(crate) unauthorized: Option<Unauthorized>,
}

impl InjectDecision {
    /// What to send upstream, or the refusal for the guest.
    pub(crate) fn into_forwarding(self) -> Result<Forwarding, InjectRefusal> {
        match self {
            Self::Inject(injection) => Ok(Forwarding {
                unauthorized: injection.unauthorized.clone(),
                injection: Some(injection),
            }),
            Self::PassThrough => Ok(Forwarding {
                injection: None,
                unauthorized: None,
            }),
            Self::PassThroughGuarded(unauthorized) => Ok(Forwarding {
                injection: None,
                unauthorized: Some(unauthorized),
            }),
            Self::Refuse(refusal) => Err(refusal),
        }
    }
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
    pub(crate) body: Option<&'a [u8]>,
}

impl<'a> RequestView<'a> {
    /// A view of a request: `headers` are `name: value` lines, as an HTTP/1.1 head has them.
    #[must_use]
    pub fn new(method: &'a str, target: &'a str, headers: &'a [String]) -> Self {
        Self {
            method,
            target,
            headers,
            body: None,
        }
    }

    /// The same view with the request body the injector asked for ([`Injector::body_wanted`]).
    #[must_use]
    pub fn with_body(self, body: &'a [u8]) -> Self {
        Self {
            body: Some(body),
            ..self
        }
    }

    /// The whole request body, decoded, when the injector asked to see it and the request
    /// carried it within the limit it named; `None` otherwise.
    #[must_use]
    pub fn body(&self) -> Option<&'a [u8]> {
        self.body
    }

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

    /// How many bytes of this request's body the injector needs to see before it can decide, if
    /// any. The proxy then reads the whole body (a request with a larger one is refused with
    /// `413` and `x-puddle-blocked: body_too_large`; nothing is sent upstream), hands it to
    /// [`Injector::decide`] through [`RequestView::body`] and forwards it unchanged. It is asked
    /// before `decide`, with a view that has no body, and must be cheap.
    fn body_wanted(
        &self,
        _context: &InjectContext<'_>,
        _request: &RequestView<'_>,
    ) -> Option<usize> {
        None
    }
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
