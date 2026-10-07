// SPDX-License-Identifier: GPL-3.0-or-later
//! The small piece of HTTP/1.1 a client of a proxy needs: write a request head, read a response
//! head with hard limits. Everything read here comes from a proxy that may be broken or hostile,
//! so nothing is trusted: heads are bounded, lengths are capped, parsing never panics.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Largest response head accepted.
pub(crate) const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Largest body of a `407` that is read and thrown away to keep the connection.
pub(crate) const MAX_DRAIN: usize = 64 * 1024;

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) http10: bool,
    /// Header names lower-cased; values trimmed.
    pub(crate) headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Every value of `name` (a lower-case header name), in order.
    pub(crate) fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// `Content-Length`, when there is exactly one valid value.
    pub(crate) fn content_length(&self) -> Option<usize> {
        let mut values = self.values("content-length");
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }
        first.parse().ok()
    }

    /// Whether the connection can carry another request: HTTP/1.1 without `close`.
    pub(crate) fn keeps_alive(&self) -> bool {
        if self.http10 {
            return false;
        }
        !self
            .values("connection")
            .chain(self.values("proxy-connection"))
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
    }

    /// The challenges of every `Proxy-Authenticate` header, in order.
    pub(crate) fn challenges(&self) -> Vec<&str> {
        self.values("proxy-authenticate").collect()
    }
}

/// The scheme words of `challenges` (`Negotiate`, `NTLM`, `Basic`), de-duplicated, in order.
/// A value may carry several challenges separated by commas; only the leading word of each
/// header is a scheme name here, which is how real proxies send them (one scheme per header).
pub(crate) fn schemes(challenges: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for challenge in challenges {
        if let Some(word) = challenge.split_whitespace().next() {
            let word = word.trim_end_matches(',');
            if !word.is_empty() && !out.iter().any(|s| s.eq_ignore_ascii_case(word)) {
                out.push(word.to_owned());
            }
        }
    }
    out
}

/// Reads a response head one byte at a time, so that nothing after it is consumed: a tunnel's
/// first bytes belong to the client.
pub(crate) async fn read_response_head<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<ResponseHead> {
    let mut buf = Vec::with_capacity(256);
    loop {
        if buf.len() >= MAX_RESPONSE_HEAD {
            return Err(bad("response head too large"));
        }
        buf.push(r.read_u8().await.map_err(|err| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(io::ErrorKind::UnexpectedEof, "proxy closed the connection")
            } else {
                err
            }
        })?);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
    }
    parse_head(&buf)
}

fn bad(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_owned())
}

fn parse_head(buf: &[u8]) -> io::Result<ResponseHead> {
    let text = std::str::from_utf8(buf).map_err(|_| bad("non-UTF-8 response head"))?;
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let status_line = lines.next().ok_or_else(|| bad("empty response"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(bad("not an HTTP/1.x response")),
    };
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=999).contains(s))
        .ok_or_else(|| bad("bad status code"))?;
    let reason = parts.next().unwrap_or_default().trim().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| bad("bad header line"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(ResponseHead {
        status,
        reason,
        http10,
        headers,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    async fn read(bytes: &[u8]) -> io::Result<ResponseHead> {
        let mut slice = bytes;
        read_response_head(&mut slice).await
    }

    #[tokio::test]
    async fn a_407_with_several_challenges_is_parsed() {
        let head = read(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nproxy-authenticate: NTLM\r\nPROXY-AUTHENTICATE: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(head.status, 407);
        assert_eq!(head.reason, "Proxy Authentication Required");
        assert_eq!(
            head.challenges(),
            vec!["Negotiate", "NTLM", "Basic realm=\"x\""]
        );
        assert_eq!(schemes(&head.challenges()), ["Negotiate", "NTLM", "Basic"]);
        assert_eq!(head.content_length(), Some(0));
        assert!(head.keeps_alive());
    }

    #[tokio::test]
    async fn only_the_head_is_consumed() {
        let mut data: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-server\r\n";
        let head = read_response_head(&mut data).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(data, b"SSH-2.0-server\r\n");
    }

    #[tokio::test]
    async fn connection_close_and_http10_end_keep_alive() {
        let close = read(b"HTTP/1.1 407 x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(!close.keeps_alive());
        let old = read(b"HTTP/1.0 407 x\r\n\r\n").await.unwrap();
        assert!(!old.keeps_alive());
        let proxy_close = read(b"HTTP/1.1 407 x\r\nProxy-Connection: Close\r\n\r\n")
            .await
            .unwrap();
        assert!(!proxy_close.keeps_alive());
    }

    #[tokio::test]
    async fn ambiguous_or_missing_lengths_are_none() {
        let two = read(b"HTTP/1.1 407 x\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(two.content_length(), None);
        let junk = read(b"HTTP/1.1 407 x\r\nContent-Length: -1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(junk.content_length(), None);
    }

    #[tokio::test]
    async fn malformed_heads_are_errors_not_panics() {
        for bytes in [
            &b"garbage\r\n\r\n"[..],
            b"HTTP/2 200 OK\r\n\r\n",
            b"HTTP/1.1 abc OK\r\n\r\n",
            b"HTTP/1.1 99 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\xff\xfe: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"",
        ] {
            assert!(read(bytes).await.is_err(), "{bytes:?}");
        }
    }

    #[tokio::test]
    async fn an_endless_head_is_cut_off() {
        let mut big = b"HTTP/1.1 200 OK\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_RESPONSE_HEAD * 2));
        let err = read(&big).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn schemes_are_deduplicated_in_order() {
        assert_eq!(
            schemes(&["NTLM abc", "ntlm", "Basic realm=\"r\"", ""]),
            ["NTLM", "Basic"]
        );
    }

    proptest! {
        #[test]
        fn parsing_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let _ = rt.block_on(async { read(&bytes).await });
        }
    }
}
