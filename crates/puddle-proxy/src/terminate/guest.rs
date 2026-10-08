// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest's side of a terminated connection: a TLS server whose one certificate is the
//! workspace CA's leaf for the host the guest `CONNECT`ed to.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use puddle_ca::WorkspaceCa;
use puddle_netpolicy::normalise_host;
use puddle_types::Host;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The protocol names of ALPN (RFC 7301) puddle speaks on a terminated connection.
pub(crate) const ALPN_HTTP11: &[u8] = b"http/1.1";
pub(crate) const ALPN_H2: &[u8] = b"h2";

/// What the guest's `ClientHello` says, which decides what the upstream is offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hello {
    /// The name asked for is the `CONNECT` host.
    pub(crate) name_matches: bool,
    /// ALPN lists `h2`.
    pub(crate) offers_h2: bool,
    /// ALPN lists `http/1.1`, or there is no ALPN at all (such a client speaks HTTP/1.1).
    pub(crate) offers_h1: bool,
}

/// Which protocol a leg of a terminated connection speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proto {
    H1,
    H2,
}

impl Proto {
    pub(crate) fn alpn(self) -> &'static [u8] {
        match self {
            Self::H1 => ALPN_HTTP11,
            Self::H2 => ALPN_H2,
        }
    }

    pub(crate) fn from_alpn(chosen: Option<&[u8]>) -> Self {
        if chosen == Some(ALPN_H2) {
            Self::H2
        } else {
            Self::H1
        }
    }
}

impl Hello {
    /// The protocols to offer the real server, best first: `h2` whenever the guest can speak it
    /// (a server that only speaks HTTP/1.1 then answers `http/1.1`, and the proxy translates),
    /// else `http/1.1`.
    pub(crate) fn upstream_offer(self) -> Vec<&'static [u8]> {
        if self.offers_h2 {
            vec![ALPN_H2, ALPN_HTTP11]
        } else {
            vec![ALPN_HTTP11]
        }
    }

    /// The protocol the guest is served, given what the real server chose: the same one, except
    /// that a guest that offered only `h2` gets `h2` over an HTTP/1.1 server (translated), and a
    /// guest that offered both gets the server's own choice.
    pub(crate) fn guest_proto(self, upstream: Proto) -> Proto {
        match upstream {
            Proto::H2 => Proto::H2,
            Proto::H1 if self.offers_h2 && !self.offers_h1 => Proto::H2,
            Proto::H1 => Proto::H1,
        }
    }
}

/// Reads the guest's `ClientHello` without answering it, so that the proxy can look at the
/// name and the protocols before it decides anything.
///
/// # Errors
/// The stream failed, or what arrived is not a `ClientHello`.
pub(crate) async fn read_hello<S>(
    stream: S,
    host: &Host,
) -> io::Result<(tokio_rustls::StartHandshake<S>, Hello)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
    let hello = start.client_hello();
    let name_matches = name_is(hello.server_name(), &host.to_string());
    let (mut offers_h2, mut offers_h1, mut any) = (false, false, false);
    for proto in hello.alpn().into_iter().flatten() {
        any = true;
        offers_h2 |= proto == ALPN_H2;
        offers_h1 |= proto == ALPN_HTTP11;
    }
    Ok((
        start,
        Hello {
            name_matches,
            offers_h2,
            offers_h1: offers_h1 || !any,
        },
    ))
}

/// Whether a `ClientHello`'s name is `host`.
fn name_is(sni: Option<&str>, host: &str) -> bool {
    let wanted = sni
        .and_then(|name| normalise_host(name).ok())
        .map(puddle_netpolicy::Target::into_host);
    matches!(&wanted, Some(Host::Name(name)) if name.to_string() == host)
}

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
    ca: Arc<WorkspaceCa>,
    host: String,
    mismatch: Arc<AtomicBool>,
}

impl ResolvesServerCert for SniGate {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !name_is(hello.server_name(), &self.host) {
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

/// The server configuration for one connection to `host`, offering `alpn`, and the flag that
/// says the client asked for another name.
pub(crate) fn server_config(
    ca: &Arc<WorkspaceCa>,
    host: &Host,
    alpn: &[&[u8]],
) -> Result<(Arc<ServerConfig>, Arc<AtomicBool>), rustls::Error> {
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
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // One connection per config: nothing to resume, and no tickets that outlive it.
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    Ok((Arc::new(config), mismatch))
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
