// SPDX-License-Identifier: GPL-3.0-or-later
//! Just enough HTTP/1.1 for a forward proxy: the request head with hard limits, the request
//! target, and request-body framing so exactly one plain-HTTP request is forwarded per connection.
//!
//! Everything here parses guest input, so it never trusts a length, never buffers more than
//! [`MAX_HEAD`], and refuses ambiguous framing instead of guessing.

use std::fmt::Write as _;
use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest request head (request line plus headers). Larger heads get `431`, so a guest can't
/// grow the proxy's memory.
pub(crate) const MAX_HEAD: usize = 64 * 1024;

/// Most header lines in one head.
pub(crate) const MAX_HEADERS: usize = 200;

/// Longest chunk-size line in a chunked body.
const MAX_CHUNK_LINE: usize = 1024;

/// Longest trailer line in a chunked body.
const MAX_TRAILER_LINE: usize = 8 * 1024;

/// A request head as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    /// `CONNECT`, `GET`, ... as sent (case kept).
    pub(crate) method: String,
    /// The request target as sent.
    pub(crate) uri: String,
    /// `HTTP/1.1` or `HTTP/1.0`.
    pub(crate) version: String,
    /// Raw header lines, line ending removed.
    pub(crate) headers: Vec<String>,
}

impl Head {
    /// Whether this is a `CONNECT` request.
    pub(crate) fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case("CONNECT")
    }
}

/// Why a head was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// The connection closed before a request line.
    Empty,
    /// Over [`MAX_HEAD`] bytes or [`MAX_HEADERS`] lines: `431`.
    TooLarge,
    /// Malformed: `400`, with the reason.
    Bad(&'static str),
}

/// Reads the request head. Never buffers more than [`MAX_HEAD`] bytes, whatever the guest sends.
///
/// The outer `Err` is an I/O error on the stream; the inner one a head the proxy refuses.
pub(crate) async fn read_head<R: AsyncBufRead + Unpin>(
    r: &mut R,
) -> io::Result<Result<Head, HeadError>> {
    let mut budget = MAX_HEAD;
    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut buf = Vec::new();
        let n = (&mut *r)
            .take(budget as u64 + 1)
            .read_until(b'\n', &mut buf)
            .await?;
        if n == 0 {
            return Ok(Err(if lines.is_empty() {
                HeadError::Empty
            } else {
                HeadError::Bad("head ended early")
            }));
        }
        if n > budget {
            return Ok(Err(HeadError::TooLarge));
        }
        budget -= n;
        if !buf.ends_with(b"\n") {
            return Ok(Err(HeadError::Bad("head ended early")));
        }
        let Ok(line) = String::from_utf8(buf) else {
            return Ok(Err(HeadError::Bad("non-UTF-8 head")));
        };
        let line = line
            .strip_suffix('\n')
            .map_or(line.as_str(), |l| l.strip_suffix('\r').unwrap_or(l));
        if line.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t')) {
            return Ok(Err(HeadError::Bad("control character in head")));
        }
        if line.is_empty() {
            if lines.is_empty() {
                continue; // RFC 9112 §2.2: ignore an empty line before the request line
            }
            break;
        }
        lines.push(line.to_owned());
        if lines.len() > MAX_HEADERS + 1 {
            return Ok(Err(HeadError::TooLarge));
        }
    }
    let mut lines = lines.into_iter();
    let request_line = lines.next().unwrap_or_default();
    let headers: Vec<String> = lines.collect();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Ok(Err(HeadError::Bad("malformed request line")));
    };
    if method.is_empty() || uri.is_empty() || !method.bytes().all(is_tchar) {
        return Ok(Err(HeadError::Bad("malformed request line")));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Ok(Err(HeadError::Bad("unsupported HTTP version")));
    }
    if headers.iter().any(|h| !valid_header_line(h)) {
        return Ok(Err(HeadError::Bad("malformed header line")));
    }
    Ok(Ok(Head {
        method: method.to_owned(),
        uri: uri.to_owned(),
        version: version.to_owned(),
        headers,
    }))
}

/// RFC 9110 `tchar`: what a method or header name may contain.
pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A `name: value` line with a token name and no obsolete line folding.
fn valid_header_line(line: &str) -> bool {
    match line.split_once(':') {
        Some((name, _)) => !name.is_empty() && name.bytes().all(is_tchar),
        None => false,
    }
}

/// The lower-cased name of a header line.
pub(crate) fn header_name(line: &str) -> String {
    line.split_once(':')
        .map_or(line, |(name, _)| name)
        .to_ascii_lowercase()
}

/// The trimmed value of a header line.
pub(crate) fn header_value(line: &str) -> &str {
    line.split_once(':').map_or("", |(_, v)| v.trim())
}

/// The destination a request names, before host normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawTarget {
    /// The host as sent, without brackets around an IPv6 literal.
    pub(crate) host: String,
    /// The port: from the request, or 80 for an absolute `http://` URI without one.
    pub(crate) port: u16,
    /// For an absolute-form request: the origin-form path (`/a?b`) to send upstream.
    pub(crate) path: Option<String>,
}

/// `CONNECT host:port`, or an absolute-form `GET http://host[:port]/path`. Anything else is a
/// client that wasn't pointed at a proxy.
pub(crate) fn parse_target(method: &str, uri: &str) -> Result<RawTarget, &'static str> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(uri)?;
        let port = port.ok_or("CONNECT needs host:port")?;
        return Ok(RawTarget {
            host,
            port,
            path: None,
        });
    }
    let rest = match uri.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("http://") => uri.get(7..).unwrap_or(""),
        _ => return Err("not a proxy request (expected CONNECT or an absolute http:// URI)"),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let tail = tail.split('#').next().unwrap_or("");
    let path = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    let (host, port) = split_host_port(authority)?;
    Ok(RawTarget {
        host,
        port: port.unwrap_or(80),
        path: Some(path),
    })
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`. Userinfo is refused, not stripped: it has no
/// business in a proxy request and hides the real host from anyone reading the line.
fn split_host_port(authority: &str) -> Result<(String, Option<u16>), &'static str> {
    if authority.contains('@') {
        return Err("userinfo (user@host) is not allowed");
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or("unclosed [ in host")?;
        if !h.contains(':') {
            return Err("brackets around a non-IPv6 host");
        }
        match after {
            "" => (h, None),
            p => (h, Some(p.strip_prefix(':').ok_or("junk after ]")?)),
        }
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("empty host");
    }
    let port = match port {
        None | Some("") => None, // RFC 3986: an empty port means the default
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => match p.parse::<u16>() {
            Ok(0) | Err(_) => return Err("port out of range"),
            Ok(n) => Some(n),
        },
        Some(_) => return Err("port is not a number"),
    };
    Ok((host.to_owned(), port))
}

/// How a request body is framed (RFC 9112 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Body {
    /// No body.
    None,
    /// Exactly this many bytes.
    Length(u64),
    /// Chunked transfer coding.
    Chunked,
}

/// Request-body framing. Ambiguous framing is refused: a proxy and a server that disagree on where
/// a request ends is how a second, unchecked request gets smuggled through.
pub(crate) fn body_framing(headers: &[String]) -> Result<Body, &'static str> {
    let mut length: Option<u64> = None;
    let mut codings: Vec<String> = Vec::new();
    for h in headers {
        match header_name(h).as_str() {
            "content-length" => {
                for v in header_value(h).split(',') {
                    let v = v.trim();
                    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("bad Content-Length");
                    }
                    let n: u64 = v.parse().map_err(|_| "bad Content-Length")?;
                    if length.is_some_and(|l| l != n) {
                        return Err("conflicting Content-Length");
                    }
                    length = Some(n);
                }
            }
            "transfer-encoding" => codings.extend(
                header_value(h)
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase())
                    .filter(|v| !v.is_empty()),
            ),
            _ => {}
        }
    }
    if codings.is_empty() {
        return Ok(length.map_or(Body::None, Body::Length));
    }
    if length.is_some() {
        return Err("both Content-Length and Transfer-Encoding");
    }
    if codings.last().map(String::as_str) != Some("chunked") {
        return Err("Transfer-Encoding without final chunked");
    }
    Ok(Body::Chunked)
}

/// Copies exactly one request body from `r` to `w`, so bytes after it (a pipelined second
/// request) are never forwarded.
pub(crate) async fn copy_body<R, W>(r: &mut R, w: &mut W, body: Body) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        Body::None => Ok(()),
        Body::Length(n) => copy_exact(r, w, n, "body shorter than Content-Length").await,
        Body::Chunked => loop {
            let line = read_line_limited(r, MAX_CHUNK_LINE).await?;
            w.write_all(&line).await?;
            let size = chunk_size(&line)?;
            if size == 0 {
                // Trailer section, up to the empty line.
                loop {
                    let t = read_line_limited(r, MAX_TRAILER_LINE).await?;
                    w.write_all(&t).await?;
                    if t == b"\r\n" || t == b"\n" {
                        return Ok(());
                    }
                }
            }
            copy_exact(r, w, size, "chunk cut short").await?;
            let crlf = read_line_limited(r, 2).await?;
            if crlf != b"\r\n" && crlf != b"\n" {
                return Err(invalid("chunk not followed by CRLF"));
            }
            w.write_all(&crlf).await?;
        },
    }
}

async fn copy_exact<R, W>(r: &mut R, w: &mut W, n: u64, short: &'static str) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut (&mut *r).take(n), w).await?;
    if copied == n {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, short))
    }
}

/// The size in a chunk-size line (`1a;ext=1\r\n`).
fn chunk_size(line: &[u8]) -> io::Result<u64> {
    let text = std::str::from_utf8(line).map_err(|_| invalid("bad chunk size"))?;
    let hex = text.trim_end().split(';').next().unwrap_or("").trim();
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("bad chunk size"));
    }
    u64::from_str_radix(hex, 16).map_err(|_| invalid("bad chunk size"))
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

async fn read_line_limited<R: AsyncBufRead + Unpin>(
    r: &mut R,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    (&mut *r)
        .take(limit as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    if buf.ends_with(b"\n") {
        Ok(buf)
    } else {
        Err(invalid("line too long or cut short"))
    }
}

/// Request headers a proxy never forwards (RFC 9110 §7.6.1), plus `Host` (replaced) and the
/// proxy's own credentials.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "host",
    "te",
    "upgrade",
];

/// The head sent upstream for a plain-HTTP request. Hop-by-hop and proxy headers are dropped,
/// `Host` is replaced by the checked target (RFC 9112 §3.2.2: a proxy ignores the client's `Host`
/// for an absolute-form target), and `Connection: close` ends the upstream connection after this
/// one request, so nothing on it goes unchecked.
pub(crate) fn upstream_head(head: &Head, path: &str, host_header: &str) -> String {
    let mut hop: Vec<String> = HOP_BY_HOP.iter().map(|h| (*h).to_owned()).collect();
    for h in &head.headers {
        if header_name(h) == "connection" {
            hop.extend(
                header_value(h)
                    .split(',')
                    .map(|v| v.trim().to_ascii_lowercase()),
            );
        }
    }
    let mut out = format!("{} {path} {}\r\n", head.method, head.version);
    let _ = write!(out, "Host: {host_header}\r\n");
    for h in &head.headers {
        if !hop.contains(&header_name(h)) {
            out.push_str(h);
            out.push_str("\r\n");
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn t(host: &str, port: u16, path: Option<&str>) -> RawTarget {
        RawTarget {
            host: host.into(),
            port,
            path: path.map(Into::into),
        }
    }

    #[test]
    fn connect_and_absolute_form_parse() {
        assert_eq!(
            parse_target("CONNECT", "github.com:443"),
            Ok(t("github.com", 443, None))
        );
        assert_eq!(
            parse_target("connect", "github.com:443"),
            Ok(t("github.com", 443, None))
        );
        assert_eq!(
            parse_target("GET", "http://example.com/a/b"),
            Ok(t("example.com", 80, Some("/a/b")))
        );
        assert_eq!(
            parse_target("GET", "HTTP://Example.com:8080?q=1"),
            Ok(t("Example.com", 8080, Some("/?q=1")))
        );
        assert_eq!(
            parse_target("GET", "http://example.com"),
            Ok(t("example.com", 80, Some("/")))
        );
        assert_eq!(
            parse_target("GET", "http://example.com/x#frag"),
            Ok(t("example.com", 80, Some("/x")))
        );
        assert!(parse_target("GET", "/relative").is_err());
        assert!(parse_target("GET", "https://example.com/").is_err());
        assert!(parse_target("GET", "http:/").is_err());
    }

    #[test]
    fn ipv6_literals_need_brackets() {
        assert_eq!(
            parse_target("GET", "http://[::1]:8080/").unwrap(),
            t("::1", 8080, Some("/"))
        );
        assert_eq!(parse_target("GET", "http://[::1]/x").unwrap().port, 80);
        assert_eq!(
            parse_target("CONNECT", "[::ffff:a9fe:a9fe]:443").unwrap(),
            t("::ffff:a9fe:a9fe", 443, None)
        );
        for bad in ["[::1", "[::1]", "[::1]x:1"] {
            assert!(parse_target("CONNECT", bad).is_err(), "{bad}");
        }
        assert!(parse_target("GET", "http://[github.com]/").is_err());
        assert!(parse_target("GET", "http://::1/").is_err());
    }

    #[test]
    fn userinfo_is_refused() {
        assert!(parse_target("GET", "http://user@169.254.169.254/").is_err());
        assert!(parse_target("GET", "http://u:p@github.com/").is_err());
        assert!(parse_target("CONNECT", "u@h:443").is_err());
        // An @ in the path is not userinfo.
        assert!(parse_target("GET", "http://example.com/@x").is_ok());
    }

    #[test]
    fn a_bad_port_is_an_error_not_80() {
        for uri in [
            "http://host:abc/",
            "http://host:65536/",
            "http://host:0/",
            "http://host:-1/",
            "http://host:8o/",
            "http://:80/",
        ] {
            assert!(parse_target("GET", uri).is_err(), "{uri}");
        }
        for uri in ["host:abc", ":443", "host", "host:", "host:99999"] {
            assert!(parse_target("CONNECT", uri).is_err(), "{uri}");
        }
        assert_eq!(parse_target("GET", "http://host:/").unwrap().port, 80);
    }

    async fn head(bytes: &[u8]) -> Result<Head, HeadError> {
        let mut r = tokio::io::BufReader::new(bytes);
        read_head(&mut r).await.unwrap()
    }

    #[tokio::test]
    async fn heads_over_the_limits_are_too_large() {
        let big = format!("GET http://x/{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_HEAD));
        assert_eq!(head(big.as_bytes()).await, Err(HeadError::TooLarge));
        let no_newline = "G".repeat(10 * 1024 * 1024);
        assert_eq!(head(no_newline.as_bytes()).await, Err(HeadError::TooLarge));
        let many = format!(
            "GET http://x/ HTTP/1.1\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 5)
        );
        assert_eq!(head(many.as_bytes()).await, Err(HeadError::TooLarge));
        // Just under the byte limit is fine.
        let pad = MAX_HEAD - "GET http://x/ HTTP/1.1\r\nA: \r\n\r\n".len();
        let fits = format!("GET http://x/ HTTP/1.1\r\nA: {}\r\n\r\n", "b".repeat(pad));
        assert!(head(fits.as_bytes()).await.is_ok());
    }

    #[tokio::test]
    async fn malformed_heads_are_bad_requests() {
        for bad in [
            &b"GET http://x/ HTTP/1.1\r\nA: \xff\r\n\r\n"[..],
            b"GET http://x/\0 HTTP/1.1\r\n\r\n",
            b"GET http://x/ HTTP/1.1\r\nA: \x1b[31m\r\n\r\n",
            b"GET http://x/ HTTP/1.1",
            b"GET http://x/ HTTP/1.1\r\nA: b\r\n",
            b"GET http://x/ HTTP/2\r\n\r\n",
            b"GET a b c HTTP/1.1\r\n\r\n",
            b"GET  http://x/ HTTP/1.1\r\n\r\n",
            b"G(T http://x/ HTTP/1.1\r\n\r\n",
            b"GET http://x/ HTTP/1.1\r\nno colon\r\n\r\n",
            b"GET http://x/ HTTP/1.1\r\nA: b\r\n folded\r\n\r\n",
            b"GET http://x/ HTTP/1.1\r\nBad Name: b\r\n\r\n",
            b"GET http://x/ HTTP/1.1\r\n: empty name\r\n\r\n",
        ] {
            assert!(
                matches!(head(bad).await, Err(HeadError::Bad(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(head(b"").await, Err(HeadError::Empty));
    }

    #[tokio::test]
    async fn a_good_head_parses() {
        let ok = head(b"\r\nGET http://x/ HTTP/1.1\r\nHost: x\nAccept:\t*/*\r\n\r\nrest")
            .await
            .unwrap();
        assert_eq!(ok.method, "GET");
        assert_eq!(ok.uri, "http://x/");
        assert_eq!(ok.version, "HTTP/1.1");
        assert_eq!(ok.headers, vec!["Host: x", "Accept:\t*/*"]);
        assert!(!ok.is_connect());
        let c = head(b"CONNECT a:1 HTTP/1.0\r\n\r\n").await.unwrap();
        assert!(c.is_connect());
    }

    fn hs(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|l| (*l).to_owned()).collect()
    }

    #[test]
    fn body_framing_refuses_ambiguity() {
        assert_eq!(body_framing(&hs(&["Host: x"])), Ok(Body::None));
        assert_eq!(
            body_framing(&hs(&["Content-Length: 5"])),
            Ok(Body::Length(5))
        );
        assert_eq!(
            body_framing(&hs(&["Content-Length: 5, 5"])),
            Ok(Body::Length(5))
        );
        assert_eq!(
            body_framing(&hs(&["Transfer-Encoding: gzip, chunked"])),
            Ok(Body::Chunked)
        );
        for bad in [
            &["Content-Length: 5", "Content-Length: 6"][..],
            &["Content-Length: 5", "Transfer-Encoding: chunked"],
            &["Transfer-Encoding: chunked, gzip"],
            &["Content-Length: -1"],
            &["Content-Length: +5"],
            &["Content-Length: "],
            &["Content-Length: 99999999999999999999999"],
        ] {
            assert!(body_framing(&hs(bad)).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn body_copy_stops_at_the_end_of_the_request() {
        let input = b"hello GET http://other/ HTTP/1.1\r\n\r\n";
        let mut r = tokio::io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        copy_body(&mut r, &mut out, Body::Length(5)).await.unwrap();
        assert_eq!(out, b"hello");

        let chunked = b"5\r\nhello\r\n3;ext=1\r\nabc\r\n0\r\nX-T: 1\r\n\r\n";
        let input = [&chunked[..], b"GET http://other/ HTTP/1.1\r\n\r\n"].concat();
        let mut r = tokio::io::BufReader::new(&input[..]);
        let mut out = Vec::new();
        copy_body(&mut r, &mut out, Body::Chunked).await.unwrap();
        assert_eq!(out, chunked);

        let mut out = Vec::new();
        let mut r = tokio::io::BufReader::new(&b"anything"[..]);
        copy_body(&mut r, &mut out, Body::None).await.unwrap();
        assert_eq!(out.len(), 0);
    }

    #[tokio::test]
    async fn broken_bodies_are_errors() {
        for (input, body) in [
            (&b"zz\r\n"[..], Body::Chunked),
            (b"\r\n", Body::Chunked),
            (b"5\r\nhel", Body::Chunked),
            (b"5\r\nhelloXX", Body::Chunked),
            (b"ffffffffffffffffff\r\n", Body::Chunked),
            (b"0\r\nX-T: 1", Body::Chunked),
            (b"abc", Body::Length(5)),
        ] {
            let mut r = tokio::io::BufReader::new(input);
            assert!(
                copy_body(&mut r, &mut Vec::new(), body).await.is_err(),
                "{}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn upstream_head_rewrites_host_and_drops_hop_headers() {
        let head = Head {
            method: "GET".into(),
            uri: "http://allowed.test/x".into(),
            version: "HTTP/1.1".into(),
            headers: hs(&[
                "Host: denied.test",
                "Connection: keep-alive, X-Secret",
                "X-Secret: 1",
                "Proxy-Authorization: x",
                "Accept: */*",
            ]),
        };
        assert_eq!(
            upstream_head(&head, "/x", "allowed.test"),
            "GET /x HTTP/1.1\r\nHost: allowed.test\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert!(upstream_head(&head, "/x", "[::1]:8080").contains("Host: [::1]:8080\r\n"));
    }

    proptest! {
        /// Whatever the guest sends, the head reader ends with a head or a refusal, never reads
        /// past the limit, and a head it accepts has only clean lines.
        #[test]
        fn read_head_never_panics_and_accepts_only_clean_heads(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let got = rt.block_on(async {
                let mut r = tokio::io::BufReader::new(&bytes[..]);
                read_head(&mut r).await.unwrap()
            });
            if let Ok(h) = got {
                prop_assert!(!h.method.is_empty());
                for line in std::iter::once(&h.uri).chain(&h.headers) {
                    prop_assert!(!line.bytes().any(|b| b < 0x20 && b != b'\t'));
                }
            }
        }

        #[test]
        fn parse_target_never_panics(method in "(CONNECT|GET|POST)", uri in "\\PC{0,64}") {
            if let Ok(t) = parse_target(&method, &uri) {
                prop_assert!(!t.host.is_empty());
                prop_assert!(t.port != 0);
                prop_assert!(!t.host.contains('@'));
            }
        }

        #[test]
        fn framing_never_panics(lines in proptest::collection::vec("\\PC{0,40}", 0..8)) {
            let _ = body_framing(&lines);
        }
    }
}
