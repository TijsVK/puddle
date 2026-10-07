// SPDX-License-Identifier: GPL-3.0-or-later
//! The guard in front of every route: `Host`, then `Origin`, then the bearer token (T-029 AP-1,
//! AP-2). See the crate docs for why each check exists.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::{ApiError, ErrorCode};
use crate::token::ApiToken;

/// What a request must match. Built once per server, after the port is known.
#[derive(Clone)]
pub(crate) struct Guard {
    inner: Arc<Inner>,
}

struct Inner {
    token: ApiToken,
    /// `127.0.0.1:<port>` and `localhost:<port>`, lower case.
    hosts: [String; 2],
    /// Whether the app's files are served, so reads outside `/api` need no token.
    serves_ui: bool,
    /// The API's own origins plus the configured extra ones, lower case.
    origins: Vec<String>,
}

/// Why a request was refused. The reason is logged; header values never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Host,
    Origin,
    Token,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Origin => "origin",
            Self::Token => "token",
        }
    }
}

impl From<Refusal> for ApiError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Host => ApiError::new(
                StatusCode::MISDIRECTED_REQUEST,
                ErrorCode::MisdirectedHost,
                "the Host header must be 127.0.0.1:<port> or localhost:<port>",
            ),
            Refusal::Origin => ApiError::new(
                StatusCode::FORBIDDEN,
                ErrorCode::ForbiddenOrigin,
                "requests from this origin are not allowed",
            ),
            Refusal::Token => ApiError::new(
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                "missing or wrong bearer token",
            ),
        }
    }
}

impl Guard {
    pub(crate) fn new(token: ApiToken, port: u16, extra_origins: &[String]) -> Self {
        let hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        let mut origins: Vec<String> = hosts.iter().map(|h| format!("http://{h}")).collect();
        origins.extend(extra_origins.iter().map(|o| o.to_ascii_lowercase()));
        Self {
            inner: Arc::new(Inner {
                token,
                hosts,
                serves_ui: false,
                origins,
            }),
        }
    }

    /// Lets `GET`/`HEAD` outside `/api` through without a token (the app's own files). The
    /// `Host` and `Origin` checks still apply.
    pub(crate) fn serving_ui(mut self, serves_ui: bool) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.serves_ui = serves_ui;
        }
        self
    }

    /// Checks one request's head.
    pub(crate) fn check(&self, uri: &Uri, headers: &HeaderMap) -> Result<(), Refusal> {
        self.check_host(uri, headers)?;
        self.check_origin(headers)?;
        self.check_token(headers)
    }

    /// Like [`Guard::check`], but a read of the app's own files needs no token.
    fn check_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(), Refusal> {
        let is_read = method == Method::GET || method == Method::HEAD;
        if self.inner.serves_ui && is_read && !is_api_path(uri.path()) {
            self.check_host(uri, headers)?;
            self.check_origin(headers)
        } else {
            self.check(uri, headers)
        }
    }

    fn check_host(&self, uri: &Uri, headers: &HeaderMap) -> Result<(), Refusal> {
        let host = single(headers, &header::HOST).ok_or(Refusal::Host)?;
        let host = host.to_str().map_err(|_| Refusal::Host)?;
        if !self.is_own_host(host) {
            return Err(Refusal::Host);
        }
        // An absolute-form target (`GET http://other/ HTTP/1.1`) must name us too.
        match uri.authority() {
            Some(authority) if !self.is_own_host(authority.as_str()) => Err(Refusal::Host),
            _ => Ok(()),
        }
    }

    fn is_own_host(&self, host: &str) -> bool {
        self.inner
            .hosts
            .iter()
            .any(|own| own.eq_ignore_ascii_case(host))
    }

    fn check_origin(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let mut values = headers.get_all(header::ORIGIN).iter();
        let Some(origin) = values.next() else {
            // Not a browser, or a same-origin GET: the token still decides.
            return Ok(());
        };
        if values.next().is_some() {
            return Err(Refusal::Origin);
        }
        let origin = origin.to_str().map_err(|_| Refusal::Origin)?;
        if self
            .inner
            .origins
            .iter()
            .any(|own| own.eq_ignore_ascii_case(origin))
        {
            Ok(())
        } else {
            Err(Refusal::Origin)
        }
    }

    fn check_token(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let value = single(headers, &header::AUTHORIZATION).ok_or(Refusal::Token)?;
        let value = value.as_bytes();
        // The scheme is case-insensitive (RFC 9110 §11.1); exactly one space before the token.
        let (scheme, token) = value.split_at_checked(7).ok_or(Refusal::Token)?;
        if !scheme.eq_ignore_ascii_case(b"bearer ") {
            return Err(Refusal::Token);
        }
        if self.inner.token.matches(token) {
            Ok(())
        } else {
            Err(Refusal::Token)
        }
    }
}

/// The header's value if it appears exactly once.
fn single<'a>(
    headers: &'a HeaderMap,
    name: &header::HeaderName,
) -> Option<&'a header::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

/// Whether `path` is the API (`/api` or below), whose every route needs the token.
pub(crate) fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// axum middleware running [`Guard::check_request`] before the route.
pub(crate) async fn guard(State(guard): State<Guard>, request: Request, next: Next) -> Response {
    match guard.check_request(request.method(), request.uri(), request.headers()) {
        Ok(()) => next.run(request).await,
        Err(refusal) => {
            tracing::warn!(
                reason = refusal.reason(),
                method = %request.method(),
                path = request.uri().path(),
                "api request refused"
            );
            ApiError::from(refusal).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    const PORT: u16 = 4321;

    fn guard() -> (Guard, ApiToken) {
        let token = ApiToken::generate().unwrap();
        (
            Guard::new(token.clone(), PORT, &["tauri://localhost".to_owned()]),
            token,
        )
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn check(pairs: &[(&str, &str)]) -> Result<(), Refusal> {
        let (g, _) = guard();
        g.check(&Uri::from_static("/api/health"), &headers(pairs))
    }

    #[test]
    fn host_must_be_our_loopback_address_and_port() {
        let (g, token) = guard();
        let auth = format!("Bearer {}", token.expose());
        let uri = Uri::from_static("/api/health");
        for ok in ["127.0.0.1:4321", "localhost:4321", "LOCALHOST:4321"] {
            assert_eq!(
                g.check(&uri, &headers(&[("host", ok), ("authorization", &auth)])),
                Ok(()),
                "{ok}"
            );
        }
        for bad in [
            "127.0.0.1",
            "localhost",
            "127.0.0.1:4322",
            "[::1]:4321",
            "evil.example:4321",
            "127.0.0.1.nip.io:4321",
            "",
        ] {
            assert_eq!(
                g.check(&uri, &headers(&[("host", bad), ("authorization", &auth)])),
                Err(Refusal::Host),
                "{bad}"
            );
        }
        assert_eq!(
            g.check(&uri, &headers(&[("authorization", &auth)])),
            Err(Refusal::Host)
        );
        assert_eq!(
            check(&[("host", "127.0.0.1:4321"), ("host", "127.0.0.1:4321")]),
            Err(Refusal::Host)
        );
        let non_utf8 = {
            let mut h = HeaderMap::new();
            h.insert(header::HOST, HeaderValue::from_bytes(b"\xff:4321").unwrap());
            h
        };
        assert_eq!(g.check(&uri, &non_utf8), Err(Refusal::Host));
    }

    #[test]
    fn an_absolute_target_must_name_us_too() {
        let (g, token) = guard();
        let auth = format!("Bearer {}", token.expose());
        let h = headers(&[("host", "127.0.0.1:4321"), ("authorization", &auth)]);
        let evil: Uri = "http://evil.example/api/health".parse().unwrap();
        assert_eq!(g.check(&evil, &h), Err(Refusal::Host));
        let own: Uri = "http://127.0.0.1:4321/api/health".parse().unwrap();
        assert_eq!(g.check(&own, &h), Ok(()));
    }

    #[test]
    fn origin_when_present_must_be_ours_or_configured() {
        let (g, token) = guard();
        let auth = format!("Bearer {}", token.expose());
        let uri = Uri::from_static("/api/health");
        let with = |origin: &str| {
            g.check(
                &uri,
                &headers(&[
                    ("host", "127.0.0.1:4321"),
                    ("origin", origin),
                    ("authorization", &auth),
                ]),
            )
        };
        for ok in [
            "http://127.0.0.1:4321",
            "http://localhost:4321",
            "tauri://localhost",
        ] {
            assert_eq!(with(ok), Ok(()), "{ok}");
        }
        for bad in [
            "null",
            "http://evil.example",
            "http://127.0.0.1:4322",
            "https://127.0.0.1:4321",
            "http://127.0.0.1:4321/",
            "http://localhost",
        ] {
            assert_eq!(with(bad), Err(Refusal::Origin), "{bad}");
        }
        assert_eq!(
            g.check(
                &uri,
                &headers(&[
                    ("host", "127.0.0.1:4321"),
                    ("origin", "http://127.0.0.1:4321"),
                    ("origin", "http://127.0.0.1:4321"),
                    ("authorization", &auth),
                ])
            ),
            Err(Refusal::Origin)
        );
    }

    #[test]
    fn token_must_be_a_single_exact_bearer_header() {
        let (g, token) = guard();
        let uri = Uri::from_static("/api/health");
        let with = |values: &[&str]| {
            let mut pairs = vec![("host", "127.0.0.1:4321")];
            pairs.extend(values.iter().map(|v| ("authorization", *v)));
            g.check(&uri, &headers(&pairs))
        };
        let t = token.expose();
        assert_eq!(with(&[&format!("Bearer {t}")]), Ok(()));
        assert_eq!(with(&[&format!("bearer {t}")]), Ok(()));
        for bad in [
            String::new(),
            "Bearer".to_owned(),
            "Bearer ".to_owned(),
            format!("Basic {t}"),
            format!("Bearer  {t}"),
            format!("Bearer {t} "),
            format!("Bearer {}", &t[..63]),
            format!("Bearer {}", "0".repeat(64)),
            t.to_owned(),
        ] {
            assert_eq!(with(&[&bad]), Err(Refusal::Token), "{bad:?}");
        }
        assert_eq!(with(&[]), Err(Refusal::Token));
        let good = format!("Bearer {t}");
        assert_eq!(with(&[&good, &good]), Err(Refusal::Token));
    }

    #[test]
    fn host_is_checked_before_origin_before_token() {
        assert_eq!(
            check(&[("host", "evil:1"), ("origin", "http://evil")]),
            Err(Refusal::Host)
        );
        assert_eq!(
            check(&[("host", "127.0.0.1:4321"), ("origin", "http://evil")]),
            Err(Refusal::Origin)
        );
        assert_eq!(check(&[("host", "127.0.0.1:4321")]), Err(Refusal::Token));
    }

    #[test]
    fn refusals_map_to_statuses_and_codes() {
        for (refusal, status, code) in [
            (
                Refusal::Host,
                StatusCode::MISDIRECTED_REQUEST,
                ErrorCode::MisdirectedHost,
            ),
            (
                Refusal::Origin,
                StatusCode::FORBIDDEN,
                ErrorCode::ForbiddenOrigin,
            ),
            (
                Refusal::Token,
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
            ),
        ] {
            let err = ApiError::from(refusal);
            assert_eq!(err.status(), status);
            assert_eq!(err.code(), code);
        }
    }
}
