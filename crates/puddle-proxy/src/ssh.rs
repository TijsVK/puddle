// SPDX-License-Identifier: GPL-3.0-or-later
//! Recognising SSH on a `CONNECT` tunnel and refusing it.
//!
//! Every SSH connection from a workspace is refused at once, whatever the host and the port: the
//! client's identification line (`SSH-2.0-...`) is what tells SSH from anything else
//! ([`puddle_agent_proto::ssh`]). Two places can see it:
//!
//! - **Before the decision:** the `CONNECT` carries it. The agent's `connect` command sets the
//!   [`PROTOCOL_HEADER`] once it has read the banner, and a client may send the banner right behind
//!   the head. [`announced`] and [`started`] find either, so the request is blocked before the
//!   rules, the resolver or the inbox hear of it.
//! - **In an established tunnel:** a client that waits for the `200` (an SSH client behind a
//!   proxy helper that speaks `CONNECT`, a captured connection) has been allowed through by a rule.
//!   [`Gate`] looks at the first bytes of its upload and, on a banner, ends the tunnel with a
//!   message instead of forwarding them: the server never gets the client's identification.
//!
//! The gate never holds anything back otherwise: it looks at the first chunk the guest sends, once,
//! and passes every byte on unchanged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use puddle_agent_proto::ssh::{PROTOCOL_HEADER, SSH, is_banner};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http::{Head, header_name, header_value};

/// Whether the request says the tunnel carries SSH.
pub(crate) fn announced(head: &Head) -> bool {
    head.headers
        .iter()
        .any(|h| header_name(h) == PROTOCOL_HEADER && header_value(h).eq_ignore_ascii_case(SSH))
}

/// Whether the bytes the client sent with the request head are an SSH identification line.
pub(crate) fn started(early: &[u8]) -> bool {
    is_banner(early)
}

/// What the guest is told when an established tunnel turns out to carry SSH: the refusal as
/// lines an SSH client skips before the server's own identification (RFC 4253 section 4.2: lines
/// that don't start with `SSH-`), so a client that shows them (`ssh -v`) shows the reason.
pub(crate) fn pre_banner(message: &str) -> Vec<u8> {
    format!("puddle: {message}\r\n").into_bytes()
}

/// The error the [`Gate`] fails its first read with when the upload starts with a banner.
const BANNER_SEEN: &str = "SSH identification line";

/// A guest stream that refuses to pass on an upload that starts with an SSH identification line.
#[derive(Debug)]
pub(crate) struct Gate<S> {
    inner: S,
    watching: bool,
    ssh: bool,
}

impl<S> Gate<S> {
    /// Wraps `inner`; with `watching` its first upload bytes are checked, otherwise it only
    /// passes bytes on (the client already sent some with its request, so they are not the start).
    pub(crate) fn new(inner: S, watching: bool) -> Self {
        Self {
            inner,
            watching,
            ssh: false,
        }
    }

    /// Whether the first upload bytes were an SSH identification line (they were dropped).
    pub(crate) fn ssh_seen(&self) -> bool {
        self.ssh
    }

    /// The stream under the gate.
    pub(crate) fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Gate<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if self.watching
            && let Poll::Ready(Ok(())) = polled
            && buf.filled().len() > before
        {
            self.watching = false;
            if is_banner(buf.filled().get(before..).unwrap_or_default()) {
                buf.set_filled(before);
                self.ssh = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    BANNER_SEEN,
                )));
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Gate<S> {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn head(headers: &[&str]) -> Head {
        Head {
            method: "CONNECT".into(),
            uri: "github.com:22".into(),
            version: "HTTP/1.1".into(),
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
        }
    }

    #[test]
    fn only_the_protocol_header_with_the_value_ssh_announces_it() {
        assert!(announced(&head(&["x-puddle-protocol: ssh"])));
        assert!(announced(&head(&["Host: a", "X-Puddle-Protocol:  SSH "])));
        for headers in [
            &[][..],
            &["x-puddle-protocol: ssh2"],
            &["x-puddle-protocol: "],
            &["x-puddle-protocol-extra: ssh"],
            &["x-other: ssh"],
            &["host: x-puddle-protocol: ssh"],
        ] {
            assert!(!announced(&head(headers)), "{headers:?}");
        }
    }

    #[test]
    fn bytes_behind_the_head_start_ssh_only_with_an_identification_line() {
        assert!(started(b"SSH-2.0-OpenSSH_10.0\r\n"));
        assert!(!started(b""));
        assert!(!started(b"\x16\x03\x01"));
        assert!(!started(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn the_pre_banner_line_is_one_line_that_is_not_a_banner() {
        let line = pre_banner("SSH is not supported yet");
        assert_eq!(line, b"puddle: SSH is not supported yet\r\n");
        assert!(!is_banner(&line));
    }

    #[tokio::test]
    async fn a_first_chunk_that_is_a_banner_fails_the_read_and_drops_the_bytes() {
        let (near, mut far) = tokio::io::duplex(256);
        let mut gate = Gate::new(near, true);
        far.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let err = gate.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(gate.ssh_seen());
        // The line was taken from the stream and not handed on.
        far.shutdown().await.unwrap();
        assert_eq!(gate.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn any_other_first_chunk_and_every_later_one_pass_unchanged() {
        let (near, mut far) = tokio::io::duplex(256);
        let mut gate = Gate::new(near, true);
        far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(gate.read(&mut buf).await.unwrap(), 5);
        far.write_all(b"SSH-2.0-later\r\n").await.unwrap();
        let n = gate.read(&mut buf).await.unwrap();
        assert_eq!(buf.get(..n), Some(&b"SSH-2.0-later\r\n"[..]));
        assert!(!gate.ssh_seen());
    }

    #[tokio::test]
    async fn a_gate_that_is_not_watching_passes_a_banner_and_writes_go_through() {
        let (near, mut far) = tokio::io::duplex(256);
        let mut gate = Gate::new(near, false);
        far.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = gate.read(&mut buf).await.unwrap();
        assert_eq!(buf.get(..n), Some(&b"SSH-2.0-test\r\n"[..]));
        gate.write_all(b"down").await.unwrap();
        gate.flush().await.unwrap();
        gate.shutdown().await.unwrap();
        let mut back = Vec::new();
        far.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"down");
        assert!(!gate.ssh_seen());
    }

    #[tokio::test]
    async fn the_end_of_the_stream_before_any_byte_is_not_ssh() {
        let (near, mut far) = tokio::io::duplex(256);
        let mut gate = Gate::new(near, true);
        far.shutdown().await.unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(gate.read(&mut buf).await.unwrap(), 0);
        assert!(!gate.ssh_seen());
    }
}
