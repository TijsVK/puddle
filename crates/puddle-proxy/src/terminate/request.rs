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
}

fn bad(why: impl Into<String>) -> Refusal {
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
    let close = !http11 || connection_tokens(head).iter().any(|t| t == "close");
    Ok(Parsed {
        method: head.method.clone(),
        target: path,
        http11,
        body,
        expect_continue,
        close,
    })
}

fn misdirected(target: &Target) -> Refusal {
    Refusal::new(
        "421 Misdirected Request",
        format!(
            "this connection is for {}; send requests for other hosts on their own connection",
            target.host
        ),
    )
}

/// Whether an authority (`host` or `host:port`) names `target`.
fn authority_is(authority: &str, target: &Target) -> bool {
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
