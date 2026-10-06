// SPDX-License-Identifier: GPL-3.0-or-later
//! Byte counts of a guest stream, for the audit's `bytes_up` / `bytes_down` (R-24).
//!
//! Counting on the guest side covers every path (refusal, `CONNECT` splice, plain-HTTP forward)
//! and survives an abort, when the relay itself returns no totals.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bytes read from and written to one stream so far.
#[derive(Debug, Default)]
pub(crate) struct ByteCounts {
    read: AtomicU64,
    written: AtomicU64,
}

impl ByteCounts {
    /// Bytes read from the stream (from the guest: up).
    pub(crate) fn read(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    /// Bytes written to the stream (to the guest: down).
    pub(crate) fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

/// A stream that counts what passes through it.
#[derive(Debug)]
pub(crate) struct Counted<S> {
    inner: S,
    counts: Arc<ByteCounts>,
}

impl<S> Counted<S> {
    /// `inner`, counted; the counts stay readable after the stream is gone.
    pub(crate) fn new(inner: S) -> (Self, Arc<ByteCounts>) {
        let counts = Arc::new(ByteCounts::default());
        (
            Self {
                inner,
                counts: Arc::clone(&counts),
            },
            counts,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let n = buf.filled().len().saturating_sub(before);
            self.counts.read.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = polled {
            self.counts.written.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn counts_both_directions_and_outlive_the_stream() {
        let (near, mut far) = tokio::io::duplex(64);
        let (mut stream, counts) = Counted::new(near);
        far.write_all(b"hello").await.unwrap();
        let mut buf = [0; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(b"abc").await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let mut back = Vec::new();
        far.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"abc");
        assert_eq!((counts.read(), counts.written()), (5, 3));
    }
}
