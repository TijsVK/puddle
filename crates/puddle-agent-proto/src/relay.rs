// SPDX-License-Identifier: GPL-3.0-or-later
//! Splicing a TCP connection to a yamux stream so that an abort stays an abort.
//!
//! If one side of a proxied connection fails (the client aborted its upload, the server reset, or
//! the session died), the other side must see a **reset**, not a clean close: a FIN would make a
//! cut-off upload or download look complete to a peer that reads until close.
//!
//! - The TCP side gets RST because [`splice`] sets zero linger on it before it is dropped.
//! - The yamux side gets RST because a stream dropped without a shutdown sends one. Callers
//!   therefore **drop** the stream after an error, never shut it down.
//!
//! The agent splices the guest application's TCP connection; the host splices the server's.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Copies both ways between `tcp` and `other` until both sides are done. Returns the bytes
/// copied `(tcp → other, other → tcp)`.
///
/// # Errors
///
/// The first I/O error on either side. Before returning it, `tcp` is set to zero linger, so
/// dropping it sends a TCP reset; drop `other` without shutting it down so it resets too.
pub async fn splice<S>(tcp: &mut TcpStream, other: &mut S) -> io::Result<(u64, u64)>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match tokio::io::copy_bidirectional(tcp, other).await {
        Ok(counts) => Ok(counts),
        Err(err) => {
            if let Err(linger) = tcp.set_zero_linger() {
                // The socket is already gone; there is nothing left to reset.
                tracing::debug!(error = %linger, "zero linger after a failed splice");
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpListener;

    use super::*;

    /// A stream that takes every byte, then fails reads like a yamux stream that got RST.
    struct ResetStream;

    impl AsyncRead for ResetStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }

    impl AsyncWrite for ResetStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (ours, _) = listener.accept().await.unwrap();
        (peer, ours)
    }

    #[tokio::test]
    async fn a_reset_on_the_stream_reaches_the_tcp_peer_as_a_reset_not_a_clean_eof() {
        let (mut peer, mut ours) = pair().await;
        assert!(splice(&mut ours, &mut ResetStream).await.is_err());
        drop(ours);
        let mut got = Vec::new();
        let read = peer.read_to_end(&mut got).await;
        assert_eq!(
            read.map_err(|e| e.kind()).err(),
            Some(io::ErrorKind::ConnectionReset)
        );
    }

    #[tokio::test]
    async fn a_clean_close_on_both_sides_stays_clean_and_counts_bytes() {
        let (mut peer, mut ours) = pair().await;
        let (mut near, mut far) = tokio::io::duplex(1024);
        let echo = tokio::spawn(async move {
            let mut buf = Vec::new();
            far.read_to_end(&mut buf).await.unwrap();
            far.write_all(&buf).await.unwrap();
            far.shutdown().await.unwrap();
        });
        let relay = tokio::spawn(async move { splice(&mut ours, &mut near).await });
        peer.write_all(b"hello").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut back = Vec::new();
        peer.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"hello");
        assert_eq!(relay.await.unwrap().unwrap(), (5, 5));
        echo.await.unwrap();
    }
}
