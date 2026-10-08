// SPDX-License-Identifier: GPL-3.0-or-later
//! TLS from the host to a real server: puddle's side of a terminated connection, and of its own
//! requests.
//!
//! The server's certificate is checked the way the host's own programs check it, so a host on a
//! company network that re-signs traffic works when its root is trusted:
//!
//! - **Windows**: the platform verifier (`CryptoAPI`), which already honours the machine's and
//!   the user's root stores, plus any extra roots the caller passes;
//! - **elsewhere**: the system's roots plus the extra roots, checked by `WebPKI`.
//!
//! Nothing the guest says reaches the check: the name is the one the host already admitted and
//! the clock is the host's. Session resumption is off, so no TLS state is shared between
//! connections (and so between workspaces).

use std::io;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use rustls_platform_verifier::Verifier;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The only protocol offered to servers: terminated connections speak HTTP/1.1 end to end.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Why the verifier could not be built.
#[derive(Debug, thiserror::Error)]
#[error("could not set up certificate verification: {0}")]
pub struct TlsSetupError(String);

/// Why a TLS connection to a server was not made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TlsConnectError {
    /// The name is not a valid DNS name (an IP literal is refused too: puddle verifies names).
    #[error("{0:?} is not a valid server name")]
    InvalidName(String),
    /// The server's certificate was not accepted: unknown issuer, expired, wrong name, ... The
    /// text is rustls's own reason.
    #[error("{0}")]
    Certificate(String),
    /// Any other handshake or transport failure.
    #[error("{0}")]
    Handshake(String),
}

impl TlsConnectError {
    fn from_io(err: &io::Error) -> Self {
        let tls = err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>());
        match tls {
            Some(inner @ rustls::Error::InvalidCertificate(_)) => {
                Self::Certificate(inner.to_string())
            }
            Some(other) => Self::Handshake(other.to_string()),
            None => Self::Handshake(err.to_string()),
        }
    }
}

/// An extra root certificate [`TlsClient::new`] could not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRoot {
    /// The certificate as it was passed in, so the caller can name it (subject, fingerprint).
    pub der: CertificateDer<'static>,
    /// Why the verifier refused it, in rustls's words.
    pub reason: String,
}

/// A TLS client with puddle's verification policy. Cheap to clone; build one per process.
#[derive(Clone)]
pub struct TlsClient {
    config: Arc<ClientConfig>,
    rejected: Arc<[RejectedRoot]>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient").finish_non_exhaustive()
    }
}

impl TlsClient {
    /// A client that trusts what the platform trusts plus `extra_roots` (the corporate roots
    /// puddle syncs into the guest, and any the caller adds). A root the verifier cannot use is
    /// left out, with a warning, rather than failing every connection: it is listed in
    /// [`TlsClient::rejected_roots`], and a site that chains to it fails with an unknown issuer.
    ///
    /// # Errors
    /// [`TlsSetupError`] when the platform's trust store cannot be read at all.
    pub fn new(
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, TlsSetupError> {
        Self::build(extra_roots, None)
    }

    /// As [`Self::new`], with the verification clock fixed at `now` (tests of the clock rule).
    ///
    /// # Errors
    /// As [`Self::new`].
    #[cfg(any(test, feature = "testing"))]
    pub fn with_clock(
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
        now: std::time::SystemTime,
    ) -> Result<Self, TlsSetupError> {
        Self::build(extra_roots, Some(Arc::new(FixedClock(now))))
    }

    fn build(
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
        clock: Option<Arc<dyn rustls::time_provider::TimeProvider>>,
    ) -> Result<Self, TlsSetupError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut kept = Vec::new();
        let mut rejected = Vec::new();
        for root in extra_roots {
            match RootCertStore::empty().add(root.clone()) {
                Ok(()) => kept.push(root),
                Err(err) => rejected.push(RejectedRoot {
                    der: root,
                    reason: err.to_string(),
                }),
            }
        }
        if !rejected.is_empty() {
            let reasons: Vec<&str> = rejected.iter().map(|r| r.reason.as_str()).collect();
            tracing::warn!(
                rejected = rejected.len(),
                reasons = %reasons.join("; "),
                "extra root certificates the verifier cannot use were left out; servers that chain to them will fail with an unknown issuer"
            );
        }
        let verifier = Verifier::new_with_extra_roots(kept, Arc::clone(&provider))
            .map_err(|err| TlsSetupError(err.to_string()))?;
        let builder = match clock {
            Some(clock) => ClientConfig::builder_with_details(Arc::clone(&provider), clock),
            None => ClientConfig::builder_with_provider(Arc::clone(&provider)),
        };
        let mut config = builder
            .with_safe_default_protocol_versions()
            .map_err(|err| TlsSetupError(err.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        config.resumption = Resumption::disabled();
        Ok(Self {
            config: Arc::new(config),
            rejected: rejected.into(),
        })
    }

    /// The extra roots [`TlsClient::new`] left out, and why. Empty when every one was used.
    #[must_use]
    pub fn rejected_roots(&self) -> &[RejectedRoot] {
        &self.rejected
    }

    /// Runs the handshake with `server_name` over `stream` (any connection already made: direct,
    /// or a tunnel through the company proxy) and returns the encrypted stream.
    ///
    /// # Errors
    /// [`TlsConnectError`]; the stream is dropped.
    pub async fn connect<S>(
        &self,
        server_name: &str,
        stream: S,
    ) -> Result<TlsStream<S>, TlsConnectError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Ok(name @ ServerName::DnsName(_)) = ServerName::try_from(server_name.to_owned()) else {
            return Err(TlsConnectError::InvalidName(server_name.to_owned()));
        };
        TlsConnector::from(Arc::clone(&self.config))
            .connect(name, stream)
            .await
            .map_err(|err| TlsConnectError::from_io(&err))
    }
}

/// Connects `stream` to `server_name` over TLS with `client`: [`TlsClient::connect`] for puddle's
/// own requests, after [`crate::host::connect`] made the connection.
///
/// # Errors
/// As [`TlsClient::connect`].
pub async fn tls_connect<S>(
    client: &TlsClient,
    server_name: &str,
    stream: S,
) -> Result<TlsStream<S>, TlsConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client.connect(server_name, stream).await
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
struct FixedClock(std::time::SystemTime);

#[cfg(any(test, feature = "testing"))]
impl rustls::time_provider::TimeProvider for FixedClock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            self.0.duration_since(std::time::UNIX_EPOCH).ok()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use rustls::pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    struct Server {
        port: u16,
        root: CertificateDer<'static>,
    }

    /// A TLS server with a leaf for `name` (SAN `san`) from a fresh root, valid `years` around
    /// now; it answers every connection with `hello` and closes.
    async fn server(san: &str, years: (i64, i64)) -> Server {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "tls test root");
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let mut leaf = rcgen::CertificateParams::new(vec![san.to_owned()]).unwrap();
        let now = time_now_year();
        leaf.not_before = rcgen::date_time_ymd(i32::try_from(now + years.0).unwrap(), 1, 1);
        leaf.not_after = rcgen::date_time_ymd(i32::try_from(now + years.1).unwrap(), 1, 1);
        let cert = leaf.signed_by(&key, &issuer).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::from(key))
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let _ = tls.write_all(b"hello").await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        Server {
            port,
            root: ca_cert.der().clone(),
        }
    }

    fn time_now_year() -> i64 {
        let secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        1970 + i64::try_from(secs / 31_556_952).unwrap()
    }

    async fn dial(
        server: &Server,
        client: &TlsClient,
        name: &str,
    ) -> Result<String, TlsConnectError> {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        let mut tls = tls_connect(client, name, tcp).await?;
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        let mut out = String::new();
        let _ = tls.read_to_string(&mut out).await;
        Ok(out)
    }

    #[tokio::test]
    async fn a_certificate_from_a_trusted_extra_root_is_accepted() {
        let server = server("host.test", (-1, 1)).await;
        let client = TlsClient::new([server.root.clone()]).unwrap();
        assert_eq!(dial(&server, &client, "host.test").await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn a_root_nobody_trusts_is_refused_with_the_reason() {
        let server = server("host.test", (-1, 1)).await;
        let client = TlsClient::new([]).unwrap();
        let err = dial(&server, &client, "host.test").await.unwrap_err();
        assert!(
            matches!(&err, TlsConnectError::Certificate(r) if r.contains("UnknownIssuer")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_wrong_name_and_the_wrong_time_are_refused() {
        let wrong_name = server("other.test", (-1, 1)).await;
        let client = TlsClient::new([wrong_name.root.clone()]).unwrap();
        let err = dial(&wrong_name, &client, "host.test").await.unwrap_err();
        assert!(matches!(err, TlsConnectError::Certificate(_)), "{err}");
        let expired = server("host.test", (-3, -2)).await;
        let client = TlsClient::new([expired.root.clone()]).unwrap();
        let err = dial(&expired, &client, "host.test").await.unwrap_err();
        // The platform verifier words it per OS: "certificate expired: ..." through webpki,
        // "Expired" from the Windows chain engine.
        assert!(
            matches!(&err, TlsConnectError::Certificate(r) if r.to_lowercase().contains("expired")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_verification_clock_is_the_one_the_client_was_built_with() {
        let server = server("host.test", (-1, 1)).await;
        let far_future = SystemTime::now() + Duration::from_hours(20 * 365 * 24);
        let client = TlsClient::with_clock([server.root.clone()], far_future).unwrap();
        let err = dial(&server, &client, "host.test").await.unwrap_err();
        assert!(matches!(err, TlsConnectError::Certificate(_)), "{err}");
        let client = TlsClient::with_clock([server.root.clone()], SystemTime::now()).unwrap();
        assert_eq!(dial(&server, &client, "host.test").await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn only_dns_names_are_verified() {
        let server = server("host.test", (-1, 1)).await;
        let client = TlsClient::new([server.root.clone()]).unwrap();
        for name in ["127.0.0.1", "::1", "", "not a name", "bad_\u{0}name"] {
            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
                .await
                .unwrap();
            let err = client.connect(name, tcp).await.unwrap_err();
            assert_eq!(
                err,
                TlsConnectError::InvalidName(name.to_owned()),
                "{name:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_server_that_is_not_tls_is_a_handshake_error() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut tcp, _)) = listener.accept().await {
                let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            }
        });
        let client = TlsClient::new([]).unwrap();
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let err = client.connect("host.test", tcp).await.unwrap_err();
        assert!(matches!(err, TlsConnectError::Handshake(_)), "{err}");
    }

    #[test]
    fn roots_that_do_not_parse_are_skipped_and_listed_with_the_reason() {
        let junk = CertificateDer::from(vec![0_u8, 1, 2, 3]);
        let client = TlsClient::new([junk.clone()]).unwrap();
        let rejected = client.rejected_roots();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].der, junk);
        assert_ne!(rejected[0].reason, "");
        let _ = format!("{:?}", TlsClient::new([]).unwrap());
    }

    #[tokio::test]
    async fn a_root_the_verifier_can_use_is_not_listed_and_a_bad_one_beside_it_does_not_spoil_it() {
        let server = server("host.test", (-1, 1)).await;
        let junk = CertificateDer::from(vec![9_u8; 12]);
        let client = TlsClient::new([junk, server.root.clone()]).unwrap();
        assert_eq!(client.rejected_roots().len(), 1);
        assert_eq!(dial(&server, &client, "host.test").await.unwrap(), "hello");
        assert_eq!(
            TlsClient::new([server.root.clone()])
                .unwrap()
                .rejected_roots(),
            []
        );
    }
}
