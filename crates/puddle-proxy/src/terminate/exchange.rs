// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam where puddle reads a login's token exchange.
//!
//! Everything else on a terminated connection streams; a token endpoint is the one place the
//! proxy reads bodies. A workspace's [`ExchangeRewriter`] is asked, for each request, whether it is
//! such an exchange. If it is, two things can happen:
//!
//! - **The request.** A field of the request body that holds one of the workspace's stand-ins (the
//!   refresh token the tool sends back) is swapped for the real value, if the connection's host
//!   is one the stand-in is for. The body is read in full first ([`MAX_EXCHANGE_BODY`]); nothing
//!   else in it changes.
//! - **The answer.** When the rewriter wants it, the answer is read in full and handed to the
//!   rewriter, which may give back a new body: the real token replaced by a stand-in. The new body
//!   is what the guest gets, with its own framing. An answer larger than the cap, or in an
//!   encoding the rewriter did not ask for, goes through as it is.
//!
//! The seam knows nothing about tokens: which fields hold what, how a stand-in is made and where
//! the real token is kept belong to whoever implements [`ExchangeRewriter`].

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use ::http::header::{self, HeaderMap};
use ::http::{HeaderValue, Response, StatusCode};
use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use puddle_types::Host;

use super::stand_in::{StandIns, Swapped};
use super::token_body::TokenBody;
use crate::destination::BoxFuture;

/// The most of a request or answer body an exchange reads. A token message is a few hundred
/// bytes; this leaves room for a server that sends profile data with it.
pub const MAX_EXCHANGE_BODY: usize = 64 * 1024;

/// What an [`ExchangeRewriter`] wants of one request.
#[must_use]
pub struct Exchange {
    swap_fields: Vec<String>,
    answer: Option<Box<dyn AnswerRewriter>>,
}

impl fmt::Debug for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exchange")
            .field("swap_fields", &self.swap_fields)
            .field("answer", &self.answer.is_some())
            .finish()
    }
}

impl Exchange {
    /// An exchange that reads nothing yet; add what it wants with [`Self::swapping`] and
    /// [`Self::answered_by`].
    pub fn new() -> Self {
        Self {
            swap_fields: Vec::new(),
            answer: None,
        }
    }

    /// Swaps the stand-in in the request body's top-level text field `field` (`refresh_token`)
    /// for its real value.
    pub fn swapping(mut self, field: impl Into<String>) -> Self {
        self.swap_fields.push(field.into());
        self
    }

    /// Hands the answer to `rewriter`.
    pub fn answered_by(mut self, rewriter: Box<dyn AnswerRewriter>) -> Self {
        self.answer = Some(rewriter);
        self
    }

    /// The request body fields whose stand-ins are swapped for the real value.
    #[must_use]
    pub fn swap_fields(&self) -> &[String] {
        &self.swap_fields
    }

    pub(crate) fn wants_request_body(&self) -> bool {
        !self.swap_fields.is_empty()
    }

    /// The rewriter that reads the answer, if the exchange has one.
    pub fn answer_mut(&mut self) -> Option<&mut (dyn AnswerRewriter + 'static)> {
        self.answer.as_deref_mut()
    }
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

/// The head of an answer, as the rewriter sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerHead<'a> {
    /// The status code.
    pub status: u16,
    /// The `Content-Type` value, if it is text.
    pub content_type: Option<&'a str>,
    /// The `Content-Encoding` value, if there is one and it is text.
    pub content_encoding: Option<&'a str>,
    /// The `Content-Length`, if the server sent one that is a number.
    pub content_length: Option<u64>,
}

impl<'a> AnswerHead<'a> {
    pub(crate) fn of(status: StatusCode, headers: &'a HeaderMap) -> Self {
        let text = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        Self {
            status: status.as_u16(),
            content_type: text("content-type"),
            content_encoding: text("content-encoding"),
            content_length: text("content-length").and_then(|n| n.trim().parse().ok()),
        }
    }
}

/// Reads one answer and may replace its body.
pub trait AnswerRewriter: Send {
    /// Whether to read this answer in full: asked from the head alone, so a rewriter passes an
    /// error, a body it cannot read or a body in an encoding it does not decode on without the
    /// proxy holding it.
    fn wants(&mut self, head: &AnswerHead<'_>) -> bool;

    /// The answer's body, read in full (at most [`MAX_EXCHANGE_BODY`]). `Some(new)` replaces the
    /// body the guest gets; `None` leaves it.
    fn rewrite<'a>(
        &'a mut self,
        head: &'a AnswerHead<'a>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Option<Bytes>>;

    /// The answer turned out larger than [`MAX_EXCHANGE_BODY`] (it had no length to say so up
    /// front) and went to the guest as it is.
    fn too_large(&mut self) {}
}

/// Decides, per terminated request, whether it is an exchange to read. One rewriter serves one
/// workspace.
pub trait ExchangeRewriter: Send + Sync + fmt::Debug {
    /// What the request `method` `path` (as sent, without the query) to `host` needs, if it is an
    /// exchange. Asked after the upstream certificate is verified and the injector has decided,
    /// for every request on a decrypted host, so it answers from memory and never waits.
    fn begin(&self, host: &Host, method: &str, path: &str) -> Option<Exchange>;
}

/// The request body of an exchange with its stand-ins swapped: `Some` with the new body when
/// anything changed. A body that is not a token message (another content type, malformed) is left
/// as it is.
pub(crate) fn swap_request_body(
    stand_ins: &StandIns,
    exchange: &Exchange,
    content_type: Option<&str>,
    body: &[u8],
    host: &Host,
) -> (Option<Bytes>, Swapped) {
    let Ok(mut parsed) = TokenBody::parse(content_type, body) else {
        return (None, Swapped::default());
    };
    let (report, changed) = stand_ins.swap_fields(&mut parsed, exchange.swap_fields(), host);
    (
        changed.then(|| Bytes::copy_from_slice(&parsed.render())),
        report,
    )
}

/// An answer's body on its way to the guest: the upstream's own, or what the rewriter had in hand.
pub(crate) enum AnswerBody {
    /// Passed through as it comes.
    Streaming(Incoming),
    /// Read in full (and perhaps replaced): sent as one piece.
    Buffered(Option<Bytes>),
    /// Read up to the cap, which the answer then went over: what was read, then the rest.
    Rejoined {
        first: Option<Bytes>,
        rest: Incoming,
    },
}

impl Body for AnswerBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        match &mut *self {
            Self::Streaming(body) => Pin::new(body).poll_frame(cx),
            Self::Buffered(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Self::Rejoined { first, rest } => match first.take() {
                Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
                None => Pin::new(rest).poll_frame(cx),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Streaming(body) => body.is_end_stream(),
            Self::Buffered(bytes) => bytes.is_none(),
            Self::Rejoined { .. } => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Streaming(body) => body.size_hint(),
            Self::Buffered(bytes) => {
                SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64))
            }
            Self::Rejoined { first, rest } => {
                let inner = rest.size_hint();
                let held = first.as_ref().map_or(0, |b| b.len() as u64);
                let mut hint = SizeHint::new();
                if let Some(upper) = inner.upper() {
                    hint.set_upper(upper.saturating_add(held));
                }
                // The upper bound is set first: a lower bound above it is refused.
                hint.set_lower(inner.lower().saturating_add(held));
                hint
            }
        }
    }
}

/// Lets `answer` see `response` and gives back what the guest gets: the response itself when the
/// rewriter does not want it, else its body read in full (at most [`MAX_EXCHANGE_BODY`]; a
/// larger one is passed on whole, the part read first) and replaced when the rewriter says so.
///
/// # Errors
/// The upstream failed or stalled while its answer was read.
pub(crate) async fn read_answer(
    answer: &mut dyn AnswerRewriter,
    response: Response<Incoming>,
    idle: Duration,
) -> io::Result<Response<AnswerBody>> {
    let (mut parts, mut body) = response.into_parts();
    let head = AnswerHead::of(parts.status, &parts.headers);
    if !answer.wants(&head) {
        return Ok(Response::from_parts(parts, AnswerBody::Streaming(body)));
    }
    let mut whole = BytesMut::new();
    loop {
        let frame = tokio::time::timeout(idle, body.frame())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream stopped sending"))?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(io::Error::other)?;
        // Trailers are not part of a token answer and are not forwarded.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        whole.extend_from_slice(&data);
        if whole.len() > MAX_EXCHANGE_BODY {
            tracing::info!("a token answer is larger than expected and goes through unread");
            answer.too_large();
            return Ok(Response::from_parts(
                parts,
                AnswerBody::Rejoined {
                    first: Some(whole.freeze()),
                    rest: body,
                },
            ));
        }
    }
    let whole = whole.freeze();
    let replaced = answer.rewrite(&head, &whole).await;
    let body = replaced.unwrap_or(whole);
    // Whatever framing the upstream used, the guest gets this body at its own length.
    if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
        parts.headers.insert(header::CONTENT_LENGTH, length);
    }
    parts.headers.remove(header::TRANSFER_ENCODING);
    Ok(Response::from_parts(
        parts,
        AnswerBody::Buffered(Some(body)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Plain;

    impl AnswerRewriter for Plain {
        fn wants(&mut self, _: &AnswerHead<'_>) -> bool {
            false
        }

        fn rewrite<'a>(
            &'a mut self,
            _: &'a AnswerHead<'a>,
            _: &'a [u8],
        ) -> BoxFuture<'a, Option<Bytes>> {
            Box::pin(std::future::ready(None))
        }
    }

    #[test]
    fn an_exchange_says_what_it_asks_for_and_holds_nothing_a_log_should_not_have() {
        let exchange = Exchange::new()
            .swapping("refresh_token")
            .answered_by(Box::new(Plain));
        assert_eq!(
            format!("{exchange:?}"),
            r#"Exchange { swap_fields: ["refresh_token"], answer: true }"#
        );
        let nothing = Exchange::default();
        assert_eq!(
            format!("{nothing:?}"),
            "Exchange { swap_fields: [], answer: false }"
        );
        assert!(!nothing.wants_request_body());
    }

    #[tokio::test]
    async fn an_answer_too_large_is_nothing_to_a_rewriter_that_does_not_care() {
        let mut plain = Plain;
        plain.too_large();
        let head = AnswerHead {
            status: 200,
            content_type: None,
            content_encoding: None,
            content_length: None,
        };
        assert!(!plain.wants(&head));
        assert_eq!(plain.rewrite(&head, b"{}").await, None);
    }

    #[test]
    fn the_head_of_an_answer_is_read_from_its_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static(" 42 "));
        assert_eq!(
            AnswerHead::of(StatusCode::OK, &headers),
            AnswerHead {
                status: 200,
                content_type: Some("application/json"),
                content_encoding: Some("gzip"),
                content_length: Some(42),
            }
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("many"));
        assert_eq!(
            AnswerHead::of(StatusCode::BAD_GATEWAY, &headers).content_length,
            None
        );
        assert_eq!(
            AnswerHead::of(StatusCode::OK, &HeaderMap::new()).content_type,
            None
        );
    }
}
