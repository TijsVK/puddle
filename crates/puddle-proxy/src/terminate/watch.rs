// SPDX-License-Identifier: GPL-3.0-or-later
//! A watch over the guest's HTTP/2 frames, for the limits the HTTP/2 library does not have.
//!
//! The library bounds what a stream or a header list may use, but not how long a half-sent header
//! block may stay open, nor how many control frames a peer may send. [`Watch`] reads the frame
//! headers as the bytes go by (it never changes them) and ends the connection when the guest
//!
//! - leaves a header block open (a `HEADERS` or `CONTINUATION` frame without `END_HEADERS`)
//!   longer than the header timeout: a slow-loris, or the slow half of a `CONTINUATION` flood;
//! - sends more than [`MAX_CONTROL_FRAMES`] stream resets, pings, settings, priorities or empty
//!   data frames in [`WINDOW`]: rapid reset (CVE-2023-44487), ping and settings floods, and the
//!   empty-frame flood.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Control frames the guest may send in [`WINDOW`]. Real clients send a handful per second.
pub(crate) const MAX_CONTROL_FRAMES: usize = 1000;

/// The span [`MAX_CONTROL_FRAMES`] is counted over.
pub(crate) const WINDOW: Duration = Duration::from_secs(10);

const PREFACE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 9;

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// Why a connection was ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Violation {
    /// A header block stayed open too long.
    HeaderBlockTooSlow,
    /// More control frames than [`MAX_CONTROL_FRAMES`] in [`WINDOW`].
    ControlFrameFlood,
}

impl Violation {
    fn message(self) -> &'static str {
        match self {
            Self::HeaderBlockTooSlow => "HTTP/2 header block not completed in time",
            Self::ControlFrameFlood => "too many HTTP/2 control frames",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    Preface(usize),
    Header(usize),
    Payload(usize),
}

/// The frame parser: sees every byte once, in order, in pieces of any size.
#[derive(Debug)]
pub(crate) struct Frames {
    phase: Phase,
    header: [u8; FRAME_HEADER_LEN],
    kind: u8,
    flags: u8,
    /// A header block is open since this moment.
    block_open_since: Option<Instant>,
    /// The frame being read ends the open block when its payload is complete.
    ends_block: bool,
    control: std::collections::VecDeque<Instant>,
}

impl Frames {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Preface(PREFACE_LEN),
            header: [0; FRAME_HEADER_LEN],
            kind: 0,
            flags: 0,
            block_open_since: None,
            ends_block: false,
            control: std::collections::VecDeque::new(),
        }
    }

    /// When the open header block (if any) must be complete.
    pub(crate) fn block_open_since(&self) -> Option<Instant> {
        self.block_open_since
    }

    /// Feeds the next bytes read at `now`.
    ///
    /// # Errors
    /// The guest broke a limit.
    pub(crate) fn observe(&mut self, mut bytes: &[u8], now: Instant) -> Result<(), Violation> {
        while !bytes.is_empty() {
            match self.phase {
                Phase::Preface(left) => {
                    let n = left.min(bytes.len());
                    bytes = bytes.get(n..).unwrap_or_default();
                    self.phase = if left == n {
                        Phase::Header(0)
                    } else {
                        Phase::Preface(left - n)
                    };
                }
                Phase::Header(have) => {
                    let n = (FRAME_HEADER_LEN - have).min(bytes.len());
                    if let (Some(dst), Some(src)) =
                        (self.header.get_mut(have..have + n), bytes.get(..n))
                    {
                        dst.copy_from_slice(src);
                    }
                    bytes = bytes.get(n..).unwrap_or_default();
                    if have + n < FRAME_HEADER_LEN {
                        self.phase = Phase::Header(have + n);
                        continue;
                    }
                    let length = (usize::from(self.header[0]) << 16)
                        | (usize::from(self.header[1]) << 8)
                        | usize::from(self.header[2]);
                    self.kind = self.header[3];
                    self.flags = self.header[4];
                    self.frame_started(length, now)?;
                    self.phase = if length == 0 {
                        self.frame_done();
                        Phase::Header(0)
                    } else {
                        Phase::Payload(length)
                    };
                }
                Phase::Payload(left) => {
                    let n = left.min(bytes.len());
                    bytes = bytes.get(n..).unwrap_or_default();
                    self.phase = if left == n {
                        self.frame_done();
                        Phase::Header(0)
                    } else {
                        Phase::Payload(left - n)
                    };
                }
            }
        }
        Ok(())
    }

    fn frame_started(&mut self, length: usize, now: Instant) -> Result<(), Violation> {
        if matches!(self.kind, HEADERS | CONTINUATION) {
            self.block_open_since.get_or_insert(now);
            self.ends_block = self.flags & END_HEADERS != 0;
        } else {
            self.ends_block = false;
        }
        let counts = match self.kind {
            RST_STREAM | PING | PRIORITY => true,
            // Acknowledgements of our own settings are the peer's reply, not a flood.
            SETTINGS => self.flags & 0x1 == 0,
            DATA => length == 0 && self.flags & END_STREAM == 0,
            _ => false,
        };
        if counts {
            while self
                .control
                .front()
                .is_some_and(|at| now.duration_since(*at) > WINDOW)
            {
                self.control.pop_front();
            }
            self.control.push_back(now);
            if self.control.len() > MAX_CONTROL_FRAMES {
                return Err(Violation::ControlFrameFlood);
            }
        }
        Ok(())
    }

    fn frame_done(&mut self) {
        if self.ends_block {
            self.block_open_since = None;
            self.ends_block = false;
        }
    }
}

/// The guest's stream, watched. Writes pass through untouched.
pub(crate) struct Watch<S> {
    inner: S,
    frames: Frames,
    header_timeout: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> Watch<S> {
    pub(crate) fn new(inner: S, header_timeout: Duration) -> Self {
        Self {
            inner,
            frames: Frames::new(),
            header_timeout,
            deadline: None,
        }
    }
}

fn violation(why: Violation) -> io::Error {
    tracing::info!(reason = why.message(), "guest HTTP/2 connection ended");
    io::Error::new(io::ErrorKind::InvalidData, why.message())
}

impl<S: AsyncRead + Unpin> AsyncRead for Watch<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let fresh = buf.filled().get(before..).unwrap_or_default();
                if let Err(why) = this.frames.observe(fresh, Instant::now()) {
                    return Poll::Ready(Err(violation(why)));
                }
                match (this.frames.block_open_since(), this.deadline.is_some()) {
                    (Some(_), false) => {
                        this.deadline = Some(Box::pin(tokio::time::sleep(this.header_timeout)));
                    }
                    (None, true) => this.deadline = None,
                    _ => {}
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                if let Some(deadline) = this.deadline.as_mut()
                    && deadline.as_mut().poll(cx).is_ready()
                {
                    return Poll::Ready(Err(violation(Violation::HeaderBlockTooSlow)));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watch<S> {
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
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let [_, a, b, c] = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let mut out = vec![a, b, c, kind, flags];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn start() -> Vec<u8> {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()
    }

    #[test]
    fn a_header_block_is_open_from_headers_to_end_headers_whatever_the_read_sizes() {
        let mut bytes = start();
        bytes.extend(frame(HEADERS, 0, 1, b"abc"));
        bytes.extend(frame(CONTINUATION, 0, 1, b"def"));
        let mut open = Frames::new();
        let now = Instant::now();
        open.observe(&bytes, now).unwrap();
        assert_eq!(open.block_open_since(), Some(now));
        open.observe(&frame(CONTINUATION, END_HEADERS, 1, b"g"), now)
            .unwrap();
        assert_eq!(open.block_open_since(), None);
        // Byte by byte gives the same answer.
        let mut piecewise = Frames::new();
        for byte in &bytes {
            piecewise.observe(&[*byte], now).unwrap();
        }
        assert_eq!(piecewise.block_open_since(), Some(now));
        for byte in frame(CONTINUATION, END_HEADERS, 1, b"g") {
            piecewise.observe(&[byte], now).unwrap();
        }
        assert_eq!(piecewise.block_open_since(), None);
    }

    #[test]
    fn a_block_that_ends_in_the_same_frame_stays_open_until_its_payload_is_in() {
        let mut frames = Frames::new();
        let now = Instant::now();
        let mut bytes = start();
        let whole = frame(HEADERS, END_HEADERS, 1, b"abcdef");
        bytes.extend_from_slice(&whole[..whole.len() - 2]);
        frames.observe(&bytes, now).unwrap();
        assert!(frames.block_open_since().is_some());
        frames.observe(&whole[whole.len() - 2..], now).unwrap();
        assert!(frames.block_open_since().is_none());
    }

    #[test]
    fn control_frames_over_the_cap_in_the_window_are_a_violation() {
        let mut frames = Frames::new();
        let now = Instant::now();
        frames.observe(&start(), now).unwrap();
        let mut failed_at = None;
        for i in 0..=MAX_CONTROL_FRAMES {
            if frames
                .observe(&frame(RST_STREAM, 0, 1, &[0, 0, 0, 8]), now)
                .is_err()
            {
                failed_at = Some(i);
                break;
            }
        }
        assert_eq!(failed_at, Some(MAX_CONTROL_FRAMES));
    }

    #[test]
    fn the_cap_counts_a_window_not_the_connection() {
        let mut frames = Frames::new();
        let t0 = Instant::now();
        frames.observe(&start(), t0).unwrap();
        for _ in 0..MAX_CONTROL_FRAMES {
            frames.observe(&frame(PING, 0, 0, &[0; 8]), t0).unwrap();
        }
        let later = t0 + WINDOW + Duration::from_secs(1);
        for _ in 0..MAX_CONTROL_FRAMES {
            frames.observe(&frame(PING, 0, 0, &[0; 8]), later).unwrap();
        }
    }

    #[test]
    fn data_settings_acks_and_window_updates_are_not_counted() {
        let mut frames = Frames::new();
        let now = Instant::now();
        frames.observe(&start(), now).unwrap();
        for _ in 0..(MAX_CONTROL_FRAMES * 3) {
            frames.observe(&frame(DATA, 0, 1, b"x"), now).unwrap();
            frames.observe(&frame(SETTINGS, 1, 0, b""), now).unwrap();
            frames.observe(&frame(8, 0, 1, &[0, 0, 1, 0]), now).unwrap();
            frames
                .observe(&frame(DATA, END_STREAM, 1, b""), now)
                .unwrap();
        }
        assert!(
            frames.observe(&frame(DATA, 0, 1, b""), now).is_ok(),
            "one empty data frame is fine"
        );
    }

    /// A connection whose reads fail.
    struct Broken;

    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
        }
    }

    #[tokio::test]
    async fn a_read_error_of_the_connection_is_passed_on_as_it_is() {
        use tokio::io::AsyncReadExt as _;
        let mut watched = Watch::new(Broken, Duration::from_secs(1));
        let err = watched.read(&mut [0_u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }
}
