// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest's side of a terminated connection: a TLS server whose one certificate is the
//! sandbox CA's leaf for the host the guest `CONNECT`ed to.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use puddle_ca::SandboxCa;
use puddle_netpolicy::normalise_host;
use puddle_types::Host;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;

/// The only protocol offered to the guest: terminated connections are HTTP/1.1.
const ALPN_HTTP11: &[u8] = b"http/1.1";

fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

/// Serves the leaf for `host` to a client that asks for `host` by name, and for nothing else.
///
/// The check is on the name in the `ClientHello`: a client that sends no name, an IP address or
/// another name gets a TLS alert and no certificate, and the connection never reaches the
/// upstream. Only the one leaf is ever reachable through it, whatever the client asks.
#[derive(Debug)]
struct SniGate {
    ca: Arc<SandboxCa>,
    host: String,
    mismatch: Arc<AtomicBool>,
}

impl ResolvesServerCert for SniGate {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wanted = hello
            .server_name()
            .and_then(|name| normalise_host(name).ok())
            .map(puddle_netpolicy::Target::into_host);
        let matches = matches!(&wanted, Some(Host::Name(name)) if name.to_string() == self.host);
        if !matches {
            self.mismatch.store(true, Ordering::Relaxed);
            return None;
        }
        match self.ca.leaf(&self.host) {
            Ok(leaf) => Some(leaf),
            Err(err) => {
                tracing::warn!(host = %self.host, error = %err, "no certificate for a bound host");
                None
            }
        }
    }
}

/// An acceptor for one connection to `host`, and the flag that says the client asked for another
/// name.
pub(crate) fn acceptor(
    ca: &Arc<SandboxCa>,
    host: &Host,
) -> Result<(TlsAcceptor, Arc<AtomicBool>), rustls::Error> {
    let mismatch = Arc::new(AtomicBool::new(false));
    let gate = SniGate {
        ca: Arc::clone(ca),
        host: host.to_string(),
        mismatch: Arc::clone(&mismatch),
    };
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(gate));
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    // One connection per config: nothing to resume, and no tickets that outlive it.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok((TlsAcceptor::from(Arc::new(config)), mismatch))
}

/// A stream that first yields bytes already read from it, then reads on.
#[derive(Debug)]
pub(crate) struct Prefixed<S> {
    prefix: io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let start = usize::try_from(this.prefix.position()).unwrap_or(usize::MAX);
        let rest = this.prefix.get_ref().get(start..).unwrap_or_default();
        if !rest.is_empty() {
            let n = rest.len().min(buf.remaining());
            buf.put_slice(rest.get(..n).unwrap_or_default());
            this.prefix.set_position((start + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
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
    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn the_prefix_is_read_before_the_stream() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"-tail")
            .await
            .unwrap();
        drop(a);
        let mut s = Prefixed::new(b, b"head".to_vec());
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "head-tail");
    }
}
