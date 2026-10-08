// SPDX-License-Identifier: GPL-3.0-or-later
//! One request read from a terminated connection: checked, then rebuilt for the upstream.
//!
//! The checks are the plain-HTTP path's (`http.rs`: size limits, no obsolete line folding, no
//! `Content-Length` with `Transfer-Encoding`, no invalid coding) plus what only a terminated
//! connection needs: the request must be for the host the certificate and the `CONNECT` named.
//! A request is never forwarded as received. It is rebuilt from the parsed pieces, so what the
//! upstream sees is what was checked.

use ::http::header::{HeaderMap, HeaderName, HeaderValue};
use puddle_netpolicy::normalise_host;

use super::inject::Injection;
use crate::http::{self, Body, Head};
use crate::proxy::Refusal;
use crate::target::Target;

/// The default port of `https`, the only port that is terminated.
pub(crate) const HTTPS_PORT: u16 = 443;

/// Headers the proxy sets or owns itself: never copied from the guest, never set by an injector.
pub(crate) fn is_proxy_owned(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "expect"
    )
}

/// A request that passed the checks.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts about one request head; an enum would only rename them"
)]
pub(crate) struct Parsed {
    pub(crate) method: String,
    /// Origin form: path and query, starting with `/`.
    pub(crate) target: String,
    pub(crate) http11: bool,
    pub(crate) body: Body,
    /// The guest waits for `100 Continue` before sending the body.
    pub(crate) expect_continue: bool,
    /// The guest asked to close after this request.
    pub(crate) close: bool,
    /// A WebSocket handshake (`Connection: upgrade`, `Upgrade: websocket`).
    pub(crate) upgrade: bool,
}

pub(crate) fn bad(why: impl Into<String>) -> Refusal {
    Refusal::new("400 Bad Request", why)
}

/// Checks `head` as a request to `target` (the `CONNECT` host, port 443).
pub(crate) fn parse(head: &Head, target: &Target) -> Result<Parsed, Refusal> {
    if head.is_connect() {
        return Err(bad("CONNECT inside a tunnel is not supported"));
    }
    let http11 = head.version == "HTTP/1.1";
    let path = origin_target(&head.uri, target)?;
    let hosts: Vec<&str> = head
        .headers
        .iter()
        .filter(|h| http::header_name(h) == "host")
        .map(|h| http::header_value(h))
        .collect();
    match hosts.as_slice() {
        [] if http11 => return Err(bad("missing Host header")),
        [] => {}
        [host] => {
            if !authority_is(host, target) {
                return Err(misdirected(target));
            }
        }
        _ => return Err(bad("more than one Host header")),
    }
    let body = http::body_framing(&head.headers).map_err(bad)?;
    if !http11 && body == Body::Chunked {
        return Err(bad("Transfer-Encoding in an HTTP/1.0 request"));
    }
    let mut expect_continue = false;
    for line in head
        .headers
        .iter()
        .filter(|h| http::header_name(h) == "expect")
    {
        if !http::header_value(line).eq_ignore_ascii_case("100-continue") {
            return Err(Refusal::new(
                "417 Expectation Failed",
                "only Expect: 100-continue is supported",
            ));
        }
        expect_continue = http11 && body != Body::None;
    }
    let tokens = connection_tokens(head);
    let close = !http11 || tokens.iter().any(|t| t == "close");
    let upgrade_values: Vec<&str> = head
        .headers
        .iter()
        .filter(|h| http::header_name(h) == "upgrade")
        .map(|h| http::header_value(h))
        .collect();
    let upgrade = http11
        && head.method == "GET"
        && body == Body::None
        && super::ws::is_upgrade_request(&tokens, &upgrade_values);
    Ok(Parsed {
        method: head.method.clone(),
        target: path,
        http11,
        body,
        expect_continue,
        close,
        upgrade,
    })
}

pub(crate) fn misdirected(target: &Target) -> Refusal {
    Refusal::new(
        "421 Misdirected Request",
        format!(
            "this connection is for {}; send requests for other hosts on their own connection",
            target.host
        ),
    )
}

/// Whether an authority (`host` or `host:port`) names `target`.
pub(crate) fn authority_is(authority: &str, target: &Target) -> bool {
    let Ok((host, port)) = http::split_host_port(authority) else {
        return false;
    };
    let Ok(host) = normalise_host(&host) else {
        return false;
    };
    host.into_host() == target.host && port.unwrap_or(HTTPS_PORT) == target.port
}

/// The path and query of the request target, which is origin-form or absolute-form for this
/// connection's own host.
fn origin_target(uri: &str, target: &Target) -> Result<String, Refusal> {
    if uri.contains('#') {
        return Err(bad("a fragment in the request target"));
    }
    let path = if uri.starts_with('/') {
        uri.to_owned()
    } else if let Some((scheme, rest)) = uri.split_once("://") {
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(bad("an absolute http:// target inside an https connection"));
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(bad("userinfo (user@host) is not allowed"));
        }
        if !authority_is(authority, target) {
            return Err(misdirected(target));
        }
        if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        }
    } else {
        return Err(bad("the request target must be a path"));
    };
    path.parse::<::http::uri::PathAndQuery>()
        .map_err(|_| bad("malformed request target"))?;
    Ok(path)
}

/// The lower-cased tokens of every `Connection` header.
fn connection_tokens(head: &Head) -> Vec<String> {
    head.headers
        .iter()
        .filter(|h| http::header_name(h) == "connection")
        .flat_map(|h| http::header_value(h).split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// The headers to send upstream: `Host` first, then the guest's end-to-end headers, then the
/// injected ones. Hop-by-hop headers and the headers the proxy owns are dropped, and so are the
/// guest's `Authorization` and `Proxy-Authorization` when a credential is injected, so the
/// credential never has a competitor.
pub(crate) fn upstream_headers(
    head: &Head,
    target: &Target,
    injection: Option<&Injection>,
) -> Result<HeaderMap, Refusal> {
    let mut map = HeaderMap::new();
    let host = if target.port == HTTPS_PORT {
        target.host.to_string()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    map.insert(
        HeaderName::from_static("host"),
        HeaderValue::from_str(&host).map_err(|_| bad("host"))?,
    );
    let named_in_connection = connection_tokens(head);
    for line in &head.headers {
        let name = HeaderName::from_bytes(http::header_name(line).as_bytes())
            .map_err(|_| bad("malformed header name"))?;
        if is_proxy_owned(&name)
            || named_in_connection.iter().any(|t| t == name.as_str())
            || (injection.is_some() && name.as_str() == "authorization")
        {
            continue;
        }
        let value = HeaderValue::from_str(http::header_value(line))
            .map_err(|_| bad("malformed header value"))?;
        map.append(name, value);
    }
    if let Some(injection) = injection {
        for header in injection.headers() {
            let Some(value) = header.header_value() else {
                return Err(Refusal::new(
                    "502 Bad Gateway",
                    "an injected header could not be built",
                ));
            };
            map.insert(header.name().clone(), value);
        }
    }
    Ok(map)
}

/// Which HTTP version the real server is spoken to in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamVersion {
    H1,
    H2,
}

/// The headers to send upstream for a request that came in over HTTP/2: the guest's end-to-end
/// headers, then the injected ones. The same rules as [`upstream_headers`]: hop-by-hop headers
/// and the headers the proxy owns are dropped, and so is the guest's `Authorization` when a
/// credential is injected. `te: trailers` is the one hop-by-hop header kept, and only toward an
/// HTTP/2 server (gRPC needs it). Toward an HTTP/1.1 server `Host` is added and the cookie
/// crumbs are joined into one `Cookie` header (RFC 9113 §8.2.3). The `:authority` of an HTTP/2
/// server comes from the request's URI, so no `Host` is added there.
pub(crate) fn upstream_headers_h2(
    headers: &HeaderMap,
    target: &Target,
    injection: Option<&Injection>,
    version: UpstreamVersion,
) -> Result<HeaderMap, Refusal> {
    let mut map = HeaderMap::new();
    if version == UpstreamVersion::H1 {
        let host = if target.port == HTTPS_PORT {
            target.host.to_string()
        } else {
            format!("{}:{}", target.host, target.port)
        };
        map.insert(
            HeaderName::from_static("host"),
            HeaderValue::from_str(&host).map_err(|_| bad("host"))?,
        );
    }
    let mut cookies: Vec<&[u8]> = Vec::new();
    for (name, value) in headers {
        if name == ::http::header::TE {
            if version == UpstreamVersion::H2 && value.as_bytes().eq_ignore_ascii_case(b"trailers")
            {
                map.insert(name.clone(), value.clone());
            }
            continue;
        }
        if is_proxy_owned(name) || (injection.is_some() && name.as_str() == "authorization") {
            continue;
        }
        if version == UpstreamVersion::H1 && name == ::http::header::COOKIE {
            cookies.push(value.as_bytes());
            continue;
        }
        map.append(name.clone(), value.clone());
    }
    if !cookies.is_empty() {
        let joined = cookies.join(&b"; "[..]);
        map.insert(
            ::http::header::COOKIE,
            HeaderValue::from_bytes(&joined).map_err(|_| bad("malformed cookie"))?,
        );
    }
    if let Some(injection) = injection {
        for header in injection.headers() {
            let value = header.header_value().ok_or_else(unbuildable_header)?;
            map.insert(header.name().clone(), value);
        }
    }
    Ok(map)
}

/// An injected header that [`InjectedHeader::new`] accepted could not be turned into a header
/// value: the two checks disagree, and nothing is sent.
fn unbuildable_header() -> Refusal {
    Refusal::new("502 Bad Gateway", "an injected header could not be built")
}

#[cfg(test)]
mod tests {
    use puddle_types::Host;

    use super::*;

    fn target(host: &str, port: u16) -> Target {
        Target {
            host: Host::parse_normalised(host).unwrap(),
            port,
        }
    }

    fn head(request: &str) -> Head {
        let mut lines = request.split("\r\n");
        let first = lines.next().unwrap();
        let mut parts = first.split(' ');
        Head {
            method: parts.next().unwrap().into(),
            uri: parts.next().unwrap().into(),
            version: parts.next().unwrap().into(),
            headers: lines.filter(|l| !l.is_empty()).map(Into::into).collect(),
        }
    }

    fn status(r: &Refusal) -> &str {
        r.status.split(' ').next().unwrap()
    }

    #[test]
    fn a_request_for_the_connection_host_passes() {
        let t = target("github.com", 443);
        for req in [
            "GET /a/b?c=d HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: GitHub.com:443\r\n\r\n",
            "GET https://github.com/a HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET https://GITHUB.com:443?x=1 HTTP/1.1\r\nHost: github.com\r\n\r\n",
        ] {
            let parsed = parse(&head(req), &t).unwrap_or_else(|r| panic!("{req}: {r:?}"));
            assert!(parsed.target.starts_with('/'), "{req}");
        }
        assert_eq!(
            parse(
                &head("GET https://github.com?x=1 HTTP/1.1\r\nHost: github.com\r\n\r\n"),
                &t
            )
            .unwrap()
            .target,
            "/?x=1"
        );
    }

    #[test]
    fn another_host_is_421_and_malformed_is_400() {
        let t = target("github.com", 443);
        for req in [
            "GET /a HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com:8443\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: 140.82.112.3\r\n\r\n",
            "GET https://evil.example/a HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET https://github.com:444/a HTTP/1.1\r\nHost: github.com\r\n\r\n",
        ] {
            assert_eq!(status(&parse(&head(req), &t).unwrap_err()), "421", "{req}");
        }
        for req in [
            "GET /a HTTP/1.1\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com\r\nHost: github.com\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com\r\nhost: evil.example\r\n\r\n",
            "GET /a#frag HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET a HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET http://github.com/a HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "GET https://user@github.com/a HTTP/1.1\r\nHost: github.com\r\n\r\n",
            "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com\r\nTransfer-Encoding: gzip\r\n\r\n",
            "GET /a HTTP/1.1\r\nHost: github.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            "GET /a HTTP/1.0\r\nHost: github.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_eq!(status(&parse(&head(req), &t).unwrap_err()), "400", "{req}");
        }
        assert_eq!(
            status(
                &parse(
                    &head("POST /a HTTP/1.1\r\nHost: github.com\r\nExpect: 200-ok\r\nContent-Length: 1\r\n\r\n"),
                    &t
                )
                .unwrap_err()
            ),
            "417"
        );
    }

    #[test]
    fn flags_come_from_the_headers() {
        let t = target("github.com", 443);
        let p = parse(
            &head("POST /a HTTP/1.1\r\nHost: github.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n"),
            &t,
        )
        .unwrap();
        assert!(p.expect_continue && !p.close && p.http11);
        assert_eq!(p.body, Body::Length(4));
        let p = parse(
            &head("GET /a HTTP/1.1\r\nHost: github.com\r\nConnection: Keep-Alive, close\r\n\r\n"),
            &t,
        )
        .unwrap();
        assert!(p.close);
        let p = parse(&head("GET /a HTTP/1.0\r\n\r\n"), &t).unwrap();
        assert!(p.close && !p.http11);
    }

    #[test]
    fn upstream_headers_are_rebuilt() {
        let t = target("github.com", 443);
        let h = head(
            "POST /a HTTP/1.1\r\nHost: github.com\r\nConnection: x-hop, keep-alive\r\nX-Hop: 1\r\nAuthorization: Bearer guest\r\nProxy-Authorization: Basic zz\r\nContent-Length: 4\r\nTE: trailers\r\nUpgrade: websocket\r\nAccept: */*\r\nAccept: text/plain\r\n\r\n",
        );
        let plain = upstream_headers(&h, &t, None).unwrap();
        let names: Vec<_> = plain.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["host", "authorization", "accept"]);
        assert_eq!(plain.get_all("accept").iter().count(), 2);
        assert_eq!(plain["host"], "github.com");
        let other = target("github.com", 8443);
        assert_eq!(
            upstream_headers(&h, &other, None).unwrap()["host"],
            "github.com:8443"
        );
    }

    #[test]
    fn injection_replaces_the_guests_credentials() {
        use super::super::inject::{InjectedHeader, SecretValue};
        let t = target("github.com", 443);
        let h = head(
            "GET /a HTTP/1.1\r\nHost: github.com\r\nAuthorization: Bearer guest\r\nX-Extra: guest\r\n\r\n",
        );
        let injection = Injection::new(
            "b1",
            vec![
                InjectedHeader::new("Authorization", SecretValue::new("Basic abc")).unwrap(),
                InjectedHeader::new("x-extra", SecretValue::new("injected")).unwrap(),
            ],
        );
        let map = upstream_headers(&h, &t, Some(&injection)).unwrap();
        assert_eq!(map.get_all("authorization").iter().count(), 1);
        assert_eq!(map["authorization"], "Basic abc");
        assert!(map["authorization"].is_sensitive());
        assert_eq!(map.get_all("x-extra").iter().count(), 1);
        assert_eq!(map["x-extra"], "injected");
        assert!(!format!("{injection:?}").contains("abc"));
    }

    #[test]
    fn injectors_cannot_set_proxy_owned_headers() {
        use super::super::inject::{HeaderError, InjectedHeader, SecretValue};
        for name in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "connection",
            "proxy-authorization",
            "Upgrade",
        ] {
            assert_eq!(
                InjectedHeader::new(name, SecretValue::new("x")).unwrap_err(),
                HeaderError::Name,
                "{name}"
            );
        }
        assert_eq!(
            InjectedHeader::new("authorization", SecretValue::new("a\r\nb: c")).unwrap_err(),
            HeaderError::Value
        );
        assert_eq!(
            InjectedHeader::new("bad name", SecretValue::new("x")).unwrap_err(),
            HeaderError::Name
        );
    }
}

#[cfg(test)]
mod h2_tests {
    #[test]
    fn an_unbuildable_injected_header_is_a_bad_gateway() {
        assert_eq!(unbuildable_header().status, "502 Bad Gateway");
    }

    use puddle_types::Host;

    use super::*;
    use crate::terminate::inject::{InjectedHeader, SecretValue};

    fn target() -> Target {
        Target {
            host: Host::parse_normalised("bound.test").unwrap(),
            port: 443,
        }
    }

    fn guest_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("bound.test"));
        headers.insert("authorization", HeaderValue::from_static("Bearer guest"));
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers.insert("content-length", HeaderValue::from_static("3"));
        headers.insert("expect", HeaderValue::from_static("100-continue"));
        headers.insert("user-agent", HeaderValue::from_static("tool"));
        headers.append("cookie", HeaderValue::from_static("a=1"));
        headers.append("cookie", HeaderValue::from_static("b=2"));
        headers
    }

    fn injection() -> Injection {
        Injection::new(
            "binding-1",
            vec![InjectedHeader::new("authorization", SecretValue::new("Basic xyz")).unwrap()],
        )
    }

    #[test]
    fn toward_an_http2_server_te_trailers_stays_and_crumbs_are_not_joined() {
        let map =
            upstream_headers_h2(&guest_headers(), &target(), None, UpstreamVersion::H2).unwrap();
        assert_eq!(map["te"], "trailers");
        assert!(map.get("host").is_none());
        assert!(map.get("content-length").is_none() && map.get("expect").is_none());
        assert_eq!(map.get_all("cookie").iter().count(), 2);
        assert_eq!(map["authorization"], "Bearer guest");
    }

    #[test]
    fn toward_an_http11_server_te_goes_host_is_set_and_cookies_are_joined() {
        let map =
            upstream_headers_h2(&guest_headers(), &target(), None, UpstreamVersion::H1).unwrap();
        assert!(map.get("te").is_none());
        assert_eq!(map["host"], "bound.test");
        assert_eq!(map["cookie"], "a=1; b=2");
        assert_eq!(map["user-agent"], "tool");
    }

    #[test]
    fn a_te_that_is_not_trailers_never_goes_on() {
        let mut headers = guest_headers();
        headers.insert("te", HeaderValue::from_static("gzip"));
        let map = upstream_headers_h2(&headers, &target(), None, UpstreamVersion::H2).unwrap();
        assert!(map.get("te").is_none());
    }

    #[test]
    fn an_injected_credential_replaces_the_guests_and_is_sensitive() {
        for version in [UpstreamVersion::H1, UpstreamVersion::H2] {
            let map = upstream_headers_h2(&guest_headers(), &target(), Some(&injection()), version)
                .unwrap();
            assert_eq!(map.get_all("authorization").iter().count(), 1);
            assert_eq!(map["authorization"], "Basic xyz");
            assert!(map["authorization"].is_sensitive());
        }
    }

    #[test]
    fn a_port_other_than_443_is_part_of_the_host_header() {
        let other = Target {
            host: Host::parse_normalised("bound.test").unwrap(),
            port: 8443,
        };
        let map =
            upstream_headers_h2(&HeaderMap::new(), &other, None, UpstreamVersion::H1).unwrap();
        assert_eq!(map["host"], "bound.test:8443");
    }
}
