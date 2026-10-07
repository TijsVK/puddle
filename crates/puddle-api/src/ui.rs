// SPDX-License-Identifier: GPL-3.0-or-later
//! Serving the single-page app from the API's own origin (T-161 default 1). The page and the API
//! share one origin, so there is no CORS (AP-2 stays intact), SSE works, and the shell and a
//! browser tab run identical code.
//!
//! Static files need no token (the page has to load before it can present one) but keep the
//! `Host` and `Origin` checks. They are served with a strict `Content-Security-Policy` and no
//! framing. The only inline script in the build is `SvelteKit`'s bootstrap, which changes with
//! every build, so its hash is computed from `index.html` when the server starts.

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

/// One file of the app.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UiFile {
    /// The bytes.
    pub body: Cow<'static, [u8]>,
    /// The `Content-Type`.
    pub content_type: String,
}

impl UiFile {
    /// A file of `body` served as `content_type`.
    #[must_use]
    pub fn new(body: impl Into<Cow<'static, [u8]>>, content_type: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            content_type: content_type.into(),
        }
    }
}

/// Where the app's files come from: the embedded build, or a fake in tests.
pub trait UiAssets: Debug + Send + Sync {
    /// The file at `path` (relative, no leading slash, e.g. `_app/version.json`), if any.
    fn get(&self, path: &str) -> Option<UiFile>;
}

/// The build embedded in the binary (feature `embedded-ui`): `ui/build` as it was at compile time.
#[cfg(feature = "embedded-ui")]
#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedUi;

#[cfg(feature = "embedded-ui")]
#[derive(rust_embed::RustEmbed)]
#[folder = "../../ui/build/"]
#[allow_missing = true]
struct Build;

#[cfg(feature = "embedded-ui")]
impl UiAssets for EmbeddedUi {
    fn get(&self, path: &str) -> Option<UiFile> {
        let file = <Build as rust_embed::Embed>::get(path)?;
        Some(UiFile::new(file.data, file.metadata.mimetype().to_owned()))
    }
}

/// The app's files plus the headers they are served with.
#[derive(Clone)]
pub(crate) struct UiService {
    assets: Arc<dyn UiAssets>,
    csp: HeaderValue,
}

const INDEX: &str = "index.html";

impl UiService {
    pub(crate) fn new(assets: Arc<dyn UiAssets>) -> Self {
        let scripts = assets
            .get(INDEX)
            .map(|index| inline_script_hashes(&String::from_utf8_lossy(&index.body)))
            .unwrap_or_default();
        let csp = content_security_policy(&scripts);
        Self { assets, csp }
    }

    /// Answers a request that is not for `/api`.
    pub(crate) fn respond(&self, method: &Method, path: &str) -> Response {
        if method != Method::GET && method != Method::HEAD {
            return ApiError::not_found("no such route").into_response();
        }
        let relative = path.trim_start_matches('/');
        let file = if relative.is_empty() {
            self.assets.get(INDEX)
        } else {
            self.assets.get(relative).or_else(|| {
                // A path with an extension is a missing file; any other path is a client-side
                // route, answered by the app shell.
                let last = relative.rsplit('/').next().unwrap_or_default();
                (!last.contains('.'))
                    .then(|| self.assets.get(INDEX))
                    .flatten()
            })
        };
        let Some(file) = file else {
            return self.with_security_headers(
                ApiError::not_found("no such file (is the UI built?)").into_response(),
            );
        };
        let immutable = relative.starts_with("_app/immutable/");
        let mut response = Response::new(if method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(file.body.into_owned())
        });
        let headers = response.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&file.content_type) {
            headers.insert(header::CONTENT_TYPE, value);
        }
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if immutable {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        *response.status_mut() = StatusCode::OK;
        self.with_security_headers(response)
    }

    fn with_security_headers(&self, mut response: Response) -> Response {
        const NOSNIFF: HeaderName = header::X_CONTENT_TYPE_OPTIONS;
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_SECURITY_POLICY, self.csp.clone());
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(NOSNIFF, HeaderValue::from_static("nosniff"));
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
        response
    }
}

/// `default-src 'self'` with the page's own inline scripts allowed by hash, and no framing.
/// `style-src-attr 'unsafe-inline'` is for `SvelteKit`'s route announcer, which hides itself with
/// a `style` attribute (blocked, it would show its text on screen); an inline style can't run
/// script, and `<style>` elements and `style-src` stay locked to `'self'`.
fn content_security_policy(script_hashes: &[String]) -> HeaderValue {
    let mut scripts = String::from("'self'");
    for hash in script_hashes {
        scripts.push_str(" 'sha256-");
        scripts.push_str(hash);
        scripts.push('\'');
    }
    let policy = format!(
        "default-src 'self'; script-src {scripts}; style-src-attr 'unsafe-inline'; \
         img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    );
    HeaderValue::from_str(&policy)
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'"))
}

/// Base64 SHA-256 of every inline `<script>` body in `html` (the form a CSP hash source takes).
fn inline_script_hashes(html: &str) -> Vec<String> {
    let mut hashes = Vec::new();
    let mut rest = html;
    while let Some((_, after)) = rest.split_once("<script") {
        let Some((attributes, body)) = after.split_once('>') else {
            break;
        };
        let Some((script, next)) = body.split_once("</script>") else {
            break;
        };
        if !attributes.contains("src=") {
            hashes.push(STANDARD.encode(Sha256::digest(script.as_bytes())));
        }
        rest = next;
    }
    hashes
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Debug)]
    struct Fake(HashMap<&'static str, (&'static str, &'static str)>);

    impl UiAssets for Fake {
        fn get(&self, path: &str) -> Option<UiFile> {
            self.0
                .get(path)
                .map(|(body, kind)| UiFile::new(body.as_bytes(), *kind))
        }
    }

    fn service() -> UiService {
        UiService::new(Arc::new(Fake(HashMap::from([
            (
                "index.html",
                (
                    "<html><script src=\"/a.js\"></script><script>let a = 1;</script></html>",
                    "text/html",
                ),
            ),
            ("_app/immutable/x.js", ("1", "text/javascript")),
            ("robots.txt", ("none", "text/plain")),
        ]))))
    }

    fn header<'a>(r: &'a Response, name: &str) -> &'a str {
        r.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
    }

    #[test]
    fn hashes_only_inline_scripts() {
        let hashes = inline_script_hashes(
            "<script src=\"a.js\"></script><script>{ x }</script><script type=\"module\">y</script>",
        );
        assert_eq!(hashes.len(), 2);
        // sha256("{ x }"), base64.
        assert_eq!(
            hashes[0],
            STANDARD.encode(Sha256::digest(b"{ x }")),
            "{hashes:?}"
        );
        assert_eq!(inline_script_hashes("<script>unterminated").len(), 0);
        assert_eq!(inline_script_hashes("<script").len(), 0);
        assert_eq!(inline_script_hashes("no scripts").len(), 0);
    }

    #[test]
    fn files_get_types_caching_and_security_headers() {
        let ui = service();
        let r = ui.respond(&Method::GET, "/robots.txt");
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(header(&r, "content-type"), "text/plain");
        assert_eq!(header(&r, "cache-control"), "no-cache");
        assert_eq!(header(&r, "x-frame-options"), "DENY");
        assert_eq!(header(&r, "x-content-type-options"), "nosniff");
        assert_eq!(header(&r, "referrer-policy"), "no-referrer");
        let csp = header(&r, "content-security-policy");
        assert!(csp.contains("default-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(csp.contains("script-src 'self' 'sha256-"), "{csp}");
        assert!(csp.contains("style-src-attr 'unsafe-inline'"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        let r = ui.respond(&Method::GET, "/_app/immutable/x.js");
        assert_eq!(
            header(&r, "cache-control"),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn routes_without_a_file_get_the_app_shell() {
        let ui = service();
        for path in ["/", "/inbox", "/workspaces/a/b"] {
            let r = ui.respond(&Method::GET, path);
            assert_eq!(r.status(), StatusCode::OK, "{path}");
            assert_eq!(header(&r, "content-type"), "text/html", "{path}");
        }
        let r = ui.respond(&Method::GET, "/missing.js");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(header(&r, "content-type"), "application/json");
        assert!(r.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn head_has_no_body_and_other_methods_are_not_routes() {
        let ui = service();
        let r = ui.respond(&Method::HEAD, "/robots.txt");
        assert_eq!(r.status(), StatusCode::OK);
        let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());
        let r = ui.respond(&Method::POST, "/inbox");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_build_without_index_answers_404_not_a_panic() {
        let ui = UiService::new(Arc::new(Fake(HashMap::new())));
        let r = ui.respond(&Method::GET, "/");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = ui.respond(&Method::GET, "/inbox");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(feature = "embedded-ui")]
    #[test]
    fn the_embedded_build_serves_its_index_when_it_was_built() {
        let ui = EmbeddedUi;
        assert!(ui.get("no/such/file.txt").is_none());
        if let Some(index) = ui.get("index.html") {
            assert!(index.content_type.starts_with("text/html"));
            let service = UiService::new(Arc::new(ui));
            assert!(service.csp.to_str().unwrap().contains("'sha256-"));
        }
    }
}
