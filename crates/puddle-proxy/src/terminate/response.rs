// SPDX-License-Identifier: GPL-3.0-or-later
//! The upstream's response, written to the guest.
//!
//! The upstream client (hyper) has already framed and checked the response; what is written here
//! is rebuilt from its parts: a fresh status line, the end-to-end headers, and framing chosen for
//! the guest. 3xx responses are passed through like any other: puddle never follows a redirect,
//! so a `Location` for another host is the guest's to follow, and it goes through the proxy as a
//! new `CONNECT`.

use std::io;
use std::time::Duration;

use ::http::header::{self, HeaderMap, HeaderName};
use ::http::{Response, StatusCode};
use http_body::Body as _;
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Headers that describe the upstream connection, not the message.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

/// How the body is sent to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// No body follows the head (`HEAD`, `1xx`, `204`, `304`).
    None,
    Length(u64),
    Chunked,
    /// The body runs to the end of the connection (an HTTP/1.0 guest, unknown length).
    UntilClose,
}

/// What came of writing a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Written {
    /// The guest connection may carry another request.
    KeepOpen,
    /// It may not (the guest asked to close, or the body ran to the end of the stream).
    Close,
}

/// Writes `response` to `writer` for a guest speaking HTTP/1.1 (`http11`) or 1.0, answering a
/// `method` request. `idle` bounds the wait for each piece of the body.
///
/// # Errors
/// The upstream failed or stalled, or the guest went away; the response may be partly written,
/// so the caller must drop the connection without a clean close.
pub(crate) async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: Response<Incoming>,
    method: &str,
    http11: bool,
    close_requested: bool,
    idle: Duration,
) -> io::Result<Written> {
    let (mut parts, mut body) = response.into_parts();
    super::alt_svc::strip_h3(&mut parts.headers);
    let status = parts.status;
    let no_body = method.eq_ignore_ascii_case("HEAD")
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED;
    let framing = if no_body {
        Framing::None
    } else if let Some(n) = body.size_hint().exact() {
        Framing::Length(n)
    } else if http11 {
        Framing::Chunked
    } else {
        Framing::UntilClose
    };
    let close = close_requested || !http11 || framing == Framing::UntilClose;
    let mut head = head_bytes(status, &parts.headers, framing, close, no_body);
    writer.write_all(&head).await?;
    head.clear();
    let mut sent: u64 = 0;
    if framing != Framing::None {
        loop {
            let frame = tokio::time::timeout(idle, body.frame())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream stopped sending"))?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(io::Error::other)?;
            let Ok(data) = frame.into_data() else {
                continue; // trailers are not forwarded
            };
            if data.is_empty() {
                continue;
            }
            sent += data.len() as u64;
            if let Framing::Length(n) = framing
                && sent > n
            {
                return Err(io::Error::other(
                    "upstream sent more than its Content-Length",
                ));
            }
            if framing == Framing::Chunked {
                writer
                    .write_all(format!("{:x}\r\n", data.len()).as_bytes())
                    .await?;
                writer.write_all(&data).await?;
                writer.write_all(b"\r\n").await?;
            } else {
                writer.write_all(&data).await?;
            }
        }
        match framing {
            Framing::Length(n) if sent != n => {
                return Err(io::Error::other(
                    "upstream sent less than its Content-Length",
                ));
            }
            Framing::Chunked => writer.write_all(b"0\r\n\r\n").await?,
            _ => {}
        }
    }
    writer.flush().await?;
    Ok(if close {
        Written::Close
    } else {
        Written::KeepOpen
    })
}

fn head_bytes(
    status: StatusCode,
    headers: &HeaderMap,
    framing: Framing,
    close: bool,
    no_body: bool,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {} {}\r\n",
        status.as_str(),
        status.canonical_reason().unwrap_or("Unknown")
    )
    .into_bytes();
    let named_in_connection: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    for (name, value) in headers {
        if is_hop_by_hop(name) || named_in_connection.iter().any(|t| t == name.as_str()) {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    match framing {
        Framing::Length(n) => out.extend_from_slice(format!("content-length: {n}\r\n").as_bytes()),
        Framing::Chunked => out.extend_from_slice(b"transfer-encoding: chunked\r\n"),
        Framing::None | Framing::UntilClose => {}
    }
    if no_body
        && status != StatusCode::NO_CONTENT
        && !status.is_informational()
        && let Some(length) = headers
            .get(header::CONTENT_LENGTH)
            .filter(|v| v.as_bytes().iter().all(u8::is_ascii_digit))
    {
        // `HEAD` and `304` describe the body they leave out.
        out.extend_from_slice(b"content-length: ");
        out.extend_from_slice(length.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if close {
        out.extend_from_slice(b"connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use ::http::HeaderValue;

    use super::*;

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn hop_by_hop_and_framing_headers_are_rebuilt() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("x-secret-hop, keep-alive"),
        );
        headers.insert("x-secret-hop", HeaderValue::from_static("1"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        headers.insert("content-length", HeaderValue::from_static("99"));
        headers.append("set-cookie", HeaderValue::from_static("a=1"));
        headers.append("set-cookie", HeaderValue::from_static("b=2"));
        let head = text(&head_bytes(
            StatusCode::OK,
            &headers,
            Framing::Length(5),
            false,
            false,
        ));
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head.contains("content-type: text/plain\r\n"));
        assert!(head.contains("content-length: 5\r\n"));
        assert!(
            !head.contains("99") && !head.contains("x-secret-hop") && !head.contains("keep-alive")
        );
        assert_eq!(head.matches("set-cookie").count(), 2);
        assert!(!head.contains("connection:"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn head_and_not_modified_keep_their_length_and_204_has_none() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("1234"));
        let head = text(&head_bytes(
            StatusCode::OK,
            &headers,
            Framing::None,
            false,
            true,
        ));
        assert!(head.contains("content-length: 1234\r\n"));
        let head = text(&head_bytes(
            StatusCode::NO_CONTENT,
            &headers,
            Framing::None,
            false,
            true,
        ));
        assert!(!head.contains("content-length"));
        let head = text(&head_bytes(
            StatusCode::OK,
            &HeaderMap::new(),
            Framing::Chunked,
            true,
            false,
        ));
        assert!(
            head.contains("transfer-encoding: chunked\r\n")
                && head.contains("connection: close\r\n")
        );
    }
}
