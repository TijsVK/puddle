// SPDX-License-Identifier: GPL-3.0-or-later
//! The first request line inside a `CONNECT` tunnel, for the audit.
//!
//! Node `fetch` (`NODE_USE_ENV_PROXY`) and Yarn Berry send a plain `http://` request as
//! `CONNECT host:80` followed by the request itself, not as an absolute-form request. The tunnel is
//! decided like any other request (the rules see `(workspace, host, port)` either way, R-2), and its
//! bytes are relayed unchanged; [`RequestTap`] only watches the start of the upload so the
//! `connection` record can name the method and path, as it does for an absolute-form request.
//!
//! The tap never waits for bytes, never holds them back and never changes them: a tunnel that
//! doesn't start with an HTTP/1.x request line (TLS, a server-first protocol) behaves exactly
//! as before and is recorded without a request line. (An SSH identification line ends the tunnel
//! instead: [`crate::ssh`].)

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use puddle_types::HttpRequestLine;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http::is_tchar;

/// Most upload bytes kept while looking for the first request line. A longer line is not
/// recorded (common servers refuse request lines over 8 KiB too).
pub(crate) const MAX_TAPPED: usize = 8 * 1024;

/// A guest stream that keeps a copy of the first upload bytes, up to the end of the first
/// request line or [`MAX_TAPPED`].
#[derive(Debug)]
pub(crate) struct RequestTap<S> {
    inner: S,
    seen: Vec<u8>,
    full: bool,
}

impl<S> RequestTap<S> {
    /// Taps `inner`; `early` are upload bytes already read past the `CONNECT` head.
    pub(crate) fn new(inner: S, early: &[u8]) -> Self {
        let mut tap = Self {
            inner,
            seen: Vec::new(),
            full: false,
        };
        tap.keep(early);
        tap
    }

    fn keep(&mut self, bytes: &[u8]) {
        if self.full {
            return;
        }
        let room = MAX_TAPPED.saturating_sub(self.seen.len());
        self.seen
            .extend_from_slice(bytes.get(..room.min(bytes.len())).unwrap_or_default());
        self.full = self.seen.len() >= MAX_TAPPED || line_end(&self.seen).is_some();
    }

    /// The first request line, if the upload started with a well-formed HTTP/1.x one.
    pub(crate) fn request_line(&self) -> Option<HttpRequestLine> {
        first_request_line(&self.seen)
    }
}

/// Where the first request line ends (its `\n`), after any empty lines before it.
fn line_end(bytes: &[u8]) -> Option<usize> {
    let start = bytes.iter().position(|b| *b != b'\r' && *b != b'\n')?;
    bytes
        .get(start..)?
        .iter()
        .position(|b| *b == b'\n')
        .map(|n| start + n)
}

/// The method and path of `bytes`' first line if it is an HTTP/1.x request line with an
/// origin-form (`/...`) or absolute-form (`http://...`) target. Empty lines before it are skipped
/// (RFC 9112 §2.2). The path loses its query string (`HttpRequestLine`, R-25).
pub(crate) fn first_request_line(bytes: &[u8]) -> Option<HttpRequestLine> {
    let end = line_end(bytes)?;
    let start = bytes.iter().position(|b| *b != b'\r' && *b != b'\n')?;
    let line = bytes.get(start..end)?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.iter().any(|b| !(0x21..0x7f).contains(b) && *b != b' ') {
        return None;
    }
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let method_ok = !method.is_empty() && method.bytes().all(is_tchar);
    let target_ok = target.starts_with('/')
        || target
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http://"));
    let version_ok = version == "HTTP/1.1" || version == "HTTP/1.0";
    (method_ok && target_ok && version_ok).then(|| HttpRequestLine::new(method, target))
}

impl<S: AsyncRead + Unpin> AsyncRead for RequestTap<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if !self.full
            && let Poll::Ready(Ok(())) = polled
        {
            let new = buf.filled().get(before..).unwrap_or_default().to_vec();
            self.keep(&new);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RequestTap<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testing::node_fetch;

    fn line(bytes: &[u8]) -> Option<(String, String)> {
        first_request_line(bytes).map(|l| (l.method().to_owned(), l.path().to_owned()))
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "compared with what `line` returns"
    )]
    fn some(method: &str, path: &str) -> Option<(String, String)> {
        Some((method.to_owned(), path.to_owned()))
    }

    #[test]
    fn node_fetch_tunnelled_request_gives_method_and_path_without_the_query() {
        assert_eq!(
            line(node_fetch::TUNNELED.as_bytes()),
            some("POST", "/some/path")
        );
    }

    #[test]
    fn request_lines_that_are_recorded() {
        assert_eq!(line(b"GET / HTTP/1.1\r\n"), some("GET", "/"));
        assert_eq!(line(b"\r\n\r\nGET /a HTTP/1.0\n"), some("GET", "/a"));
        assert_eq!(
            line(b"GET http://h.test:81/x?y#z HTTP/1.1\r\n"),
            some("GET", "/x")
        );
        assert_eq!(
            line(b"PROPFIND /dav HTTP/1.1\r\n"),
            some("PROPFIND", "/dav")
        );
    }

    #[test]
    fn anything_else_is_not_a_request_line() {
        for bytes in [
            &b""[..],
            b"GET / HTTP/1.1",                               // no line end yet
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", // TLS ClientHello
            b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", // h2c prior knowledge
            b"CONNECT other.test:443 HTTP/1.1\r\n", // authority form
            b"OPTIONS * HTTP/1.1\r\n",
            b"GET  / HTTP/1.1\r\n",
            b"GET / HTTP/1.1 x\r\n",
            b"GET /\x01 HTTP/1.1\r\n",
            b"G\xc3\xa9T / HTTP/1.1\r\n",
            b"GET /\xc3\xa9t\xc3\xa9 HTTP/1.1\r\n",
            b"GET ftp://h/ HTTP/1.1\r\n",
            b"GET / HTTP/2\r\n",
            b"ping",
            b"\r\n\r\n",
        ] {
            assert_eq!(line(bytes), None, "{}", String::from_utf8_lossy(bytes));
        }
    }

    #[tokio::test]
    async fn the_tap_passes_every_byte_through_and_keeps_only_the_first_line() {
        let (near, mut far) = tokio::io::duplex(4096);
        let mut tap = RequestTap::new(near, b"GET /fir");
        let rest = b"st?secret=1 HTTP/1.1\r\nHost: a\r\n\r\n".repeat(10);
        far.write_all(&rest).await.unwrap();
        far.shutdown().await.unwrap();
        let mut got = Vec::new();
        tap.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, rest);
        assert!(tap.seen.len() < 64, "kept {} bytes", tap.seen.len());
        let l = tap.request_line().unwrap();
        assert_eq!((l.method(), l.path()), ("GET", "/first"));
        tap.write_all(b"down").await.unwrap();
        tap.flush().await.unwrap();
        tap.shutdown().await.unwrap();
        let mut back = Vec::new();
        far.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"down");
    }

    #[tokio::test]
    async fn a_line_longer_than_the_cap_is_not_recorded_and_the_tap_stops_keeping() {
        let (near, mut far) = tokio::io::duplex(1024);
        let mut tap = RequestTap::new(near, b"GET /");
        let long = vec![b'a'; MAX_TAPPED * 2];
        let writer = tokio::spawn(async move {
            far.write_all(&long).await.unwrap();
            far.write_all(b" HTTP/1.1\r\n\r\n").await.unwrap();
            far.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        tap.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got.len(), MAX_TAPPED * 2 + 13);
        assert_eq!(tap.seen.len(), MAX_TAPPED);
        assert!(tap.request_line().is_none());
    }

    proptest! {
        #[test]
        fn parsing_never_panics_and_a_recorded_path_never_has_a_query(
            bytes in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            if let Some(l) = first_request_line(&bytes) {
                prop_assert!(!l.path().contains('?') && !l.path().contains('#'));
                prop_assert!(!l.method().is_empty());
            }
        }

        #[test]
        fn the_tap_never_changes_the_bytes(
            early in proptest::collection::vec(any::<u8>(), 0..64),
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..256), 0..8)
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                let (near, mut far) = tokio::io::duplex(4096);
                let mut tap = RequestTap::new(near, &early);
                let sent: Vec<u8> = chunks.concat();
                let writer = async {
                    for c in &chunks {
                        far.write_all(c).await.unwrap();
                    }
                    far.shutdown().await.unwrap();
                };
                let mut got = Vec::new();
                let ((), read) = tokio::join!(writer, tap.read_to_end(&mut got));
                read.unwrap();
                assert_eq!(got, sent);
                assert!(tap.seen.len() <= MAX_TAPPED);
            });
        }
    }
}
