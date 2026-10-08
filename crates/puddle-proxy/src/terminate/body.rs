// SPDX-License-Identifier: GPL-3.0-or-later
//! Request bodies on a terminated connection: decoded from the guest's framing frame by frame,
//! and handed to the upstream client as a streaming body.
//!
//! The guest's framing is parsed here (same limits as the plain-HTTP path) and never forwarded:
//! the upstream client frames the body itself from what was decoded, so a chunk extension, a
//! trailer or an odd chunk size cannot ride along.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::mpsc;

use crate::http::{self, Body};

/// Largest piece read at once.
const PIECE: usize = 64 * 1024;

/// Most trailer bytes accepted after the last chunk.
const MAX_TRAILER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Length(u64),
    ChunkHeader,
    ChunkData(u64),
    ChunkEnd,
    Trailers(usize),
    Done,
}

/// Reads one request body from the guest, decoded.
#[derive(Debug)]
pub(crate) struct BodyReader {
    state: State,
}

impl BodyReader {
    pub(crate) fn new(body: Body) -> Self {
        Self {
            state: match body {
                Body::None | Body::Length(0) => State::Done,
                Body::Length(n) => State::Length(n),
                Body::Chunked => State::ChunkHeader,
            },
        }
    }

    /// The next piece of the body, or `None` once it is complete.
    ///
    /// # Errors
    /// The guest's framing is wrong or the stream ended early.
    pub(crate) async fn next<R: AsyncBufRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<Bytes>> {
        loop {
            match self.state {
                State::Done => return Ok(None),
                State::Length(left) | State::ChunkData(left) => {
                    let piece = take_piece(r, left).await?;
                    let left = left - piece.len() as u64;
                    self.state = match (self.state, left) {
                        (State::Length(_), 0) => State::Done,
                        (State::ChunkData(_), 0) => State::ChunkEnd,
                        (State::Length(_), n) => State::Length(n),
                        (_, n) => State::ChunkData(n),
                    };
                    return Ok(Some(piece));
                }
                State::ChunkHeader => {
                    let line = http::read_line_limited(r, http::MAX_CHUNK_LINE).await?;
                    self.state = match http::chunk_size(&line)? {
                        0 => State::Trailers(0),
                        n => State::ChunkData(n),
                    };
                }
                State::ChunkEnd => {
                    let crlf = http::read_line_limited(r, 2).await?;
                    if crlf != b"\r\n" && crlf != b"\n" {
                        return Err(http::invalid("chunk not followed by CRLF"));
                    }
                    self.state = State::ChunkHeader;
                }
                State::Trailers(seen) => {
                    let line = http::read_line_limited(r, http::MAX_TRAILER_LINE).await?;
                    let seen = seen + line.len();
                    if seen > MAX_TRAILER_BYTES {
                        return Err(http::invalid("trailers too large"));
                    }
                    self.state = if line == b"\r\n" || line == b"\n" {
                        State::Done
                    } else {
                        State::Trailers(seen)
                    };
                }
            }
        }
    }
}

async fn take_piece<R: AsyncBufRead + Unpin>(r: &mut R, left: u64) -> io::Result<Bytes> {
    let buf = r.fill_buf().await?;
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "body cut short",
        ));
    }
    let n = usize::try_from(left)
        .map_or(PIECE, |l| l.min(PIECE))
        .min(buf.len());
    let piece = Bytes::copy_from_slice(buf.get(..n).unwrap_or_default());
    r.consume(n);
    Ok(piece)
}

/// Copies the guest's body into `tx` until it is complete, then drops `tx` (which is what ends
/// the body). Each read is bounded by `idle`.
///
/// # Errors
/// The framing is wrong, the guest stalls or goes away, or the receiver is gone.
pub(crate) async fn pump<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    body: Body,
    tx: mpsc::Sender<Bytes>,
    idle: Duration,
) -> io::Result<()> {
    let mut decoder = BodyReader::new(body);
    loop {
        let piece = tokio::time::timeout(idle, decoder.next(reader))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "guest stopped sending the body")
            })??;
        match piece {
            Some(bytes) => tx.send(bytes).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "upstream stopped reading")
            })?,
            None => return Ok(()),
        }
    }
}

/// Marks a [`ChannelBody`] as cut off, so it ends in an error whatever else happens to the
/// channel: a body that stops early is never mistaken for a complete one.
#[derive(Debug, Clone)]
pub(crate) struct Abort(Arc<AtomicBool>);

impl Abort {
    pub(crate) fn abort(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A request body that streams what [`pump`] decodes. It ends when the sender is dropped, or in
/// an error once [`Abort::abort`] was called.
#[derive(Debug)]
pub(crate) struct ChannelBody {
    rx: Option<mpsc::Receiver<Bytes>>,
    exact: Option<u64>,
    aborted: Arc<AtomicBool>,
}

impl ChannelBody {
    /// A body for `framing`, the sender to feed it and the handle that cuts it off.
    pub(crate) fn new(framing: Body) -> (Self, mpsc::Sender<Bytes>, Abort) {
        let (tx, rx) = mpsc::channel(4);
        let (rx, exact) = match framing {
            Body::None | Body::Length(0) => (None, Some(0)),
            Body::Length(n) => (Some(rx), Some(n)),
            Body::Chunked => (Some(rx), None),
        };
        let aborted = Arc::new(AtomicBool::new(false));
        (
            Self {
                rx,
                exact,
                aborted: Arc::clone(&aborted),
            },
            tx,
            Abort(aborted),
        )
    }
}

impl ChannelBody {
    /// A body that is already complete in `bytes` (read for an injector that decides on it): the
    /// sender is the one [`ChannelBody::new`] would give, and dropping it ends the body.
    pub(crate) fn prefetched(bytes: Bytes) -> (Self, mpsc::Sender<Bytes>, Abort) {
        let len = bytes.len() as u64;
        let (body, tx, abort) = Self::new(if len == 0 {
            Body::None
        } else {
            Body::Length(len)
        });
        if len > 0 {
            // The channel holds four pieces and this is the first.
            let _ = tx.try_send(bytes);
        }
        (body, tx, abort)
    }
}

impl HttpBody for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let cut = || io::Error::new(io::ErrorKind::ConnectionAborted, "request body cut off");
        if self.aborted.load(Ordering::SeqCst) {
            self.rx = None;
            return Poll::Ready(Some(Err(cut())));
        }
        let Some(rx) = self.rx.as_mut() else {
            return Poll::Ready(None);
        };
        match rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => {
                self.rx = None;
                if self.aborted.load(Ordering::SeqCst) {
                    Poll::Ready(Some(Err(cut())))
                } else {
                    Poll::Ready(None)
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.rx.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.exact.map_or_else(SizeHint::new, SizeHint::with_exact)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;

    async fn decode(input: &[u8], body: Body) -> io::Result<Vec<u8>> {
        let mut r = BufReader::new(input);
        let mut decoder = BodyReader::new(body);
        let mut out = Vec::new();
        while let Some(piece) = decoder.next(&mut r).await? {
            out.extend_from_slice(&piece);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn length_and_chunked_bodies_decode_and_leave_the_next_request() {
        assert_eq!(
            decode(b"hello world", Body::Length(5)).await.unwrap(),
            b"hello"
        );
        assert_eq!(decode(b"", Body::None).await.unwrap(), b"");
        let chunked = b"3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nx-trailer: 1\r\n\r\nGET / HTTP/1.1\r\n";
        let mut r = BufReader::new(&chunked[..]);
        let mut decoder = BodyReader::new(Body::Chunked);
        let mut out = Vec::new();
        while let Some(piece) = decoder.next(&mut r).await.unwrap() {
            out.extend_from_slice(&piece);
        }
        assert_eq!(out, b"abcde");
        let mut rest = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut r, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, "GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn broken_framing_is_an_error() {
        for (input, body) in [
            (&b"abc"[..], Body::Length(5)),
            (b"zz\r\nabc\r\n0\r\n\r\n", Body::Chunked),
            (b"3\r\nabcXX0\r\n\r\n", Body::Chunked),
            (b"3\r\nab", Body::Chunked),
            (b"ffffffffffffffffff\r\n", Body::Chunked),
            (b"0\r\n", Body::Chunked),
        ] {
            assert!(decode(input, body).await.is_err(), "{input:?}");
        }
    }

    #[tokio::test]
    async fn endless_trailers_are_cut_off() {
        let mut input = b"0\r\n".to_vec();
        for _ in 0..10_000 {
            input.extend_from_slice(b"x-a: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        assert!(decode(&input, Body::Chunked).await.is_err());
    }
}
