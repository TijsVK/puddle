// SPDX-License-Identifier: GPL-3.0-or-later
//! Test rig for terminated connections: a fake TLS upstream with a recording handler, a sandbox
//! proxy with a termination, and a guest that speaks TLS through the route.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use puddle_agent_proto::tokio_yamux::{Control, Session, StreamHandle};
use puddle_agent_proto::yamux::client_config;
use puddle_ca::{CaBuilder, SandboxCa};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, CollectingConnectionLog, StaticPolicy};
use puddle_proxy::{
    BoxFuture, InjectContext, InjectDecision, InjectRefusal, InjectedHeader, Injection, Injector,
    Proxy, ProxyConfig, RequestView, Resolver, Route, SecretValue, Termination, TerminationSet,
    Terminations,
};
use puddle_types::{ConnectionEvent, DomainName, Host, NullSink, SandboxName};
use puddle_upstream::TlsClient;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub(crate) const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The secret the test injector adds. Never expected anywhere but at the fake upstream.
pub(crate) const CANARY: &str = "canary-9f3a7c51e2b84d06";

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

// ---------------------------------------------------------------------------------------------
// PKI of the fake internet.

/// A certificate authority of the fake internet and the leaves it signs.
pub(crate) struct Pki {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pub(crate) root: CertificateDer<'static>,
}

/// What is wrong with a leaf, if anything.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flaw {
    None,
    Expired,
    NotYetValid,
    /// Signed by a root nobody trusts.
    UnknownRoot,
    /// Valid for another name.
    WrongName,
    /// Self-signed, no CA at all.
    SelfSigned,
}

impl Pki {
    pub(crate) fn new() -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("fake internet root {}", NEXT.fetch_add(1, Ordering::SeqCst)),
        );
        let cert = params.self_signed(&key).unwrap();
        Self {
            root: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    pub(crate) fn server_config(&self, name: &str, flaw: Flaw) -> Arc<rustls::ServerConfig> {
        let sans = if flaw == Flaw::WrongName {
            "other.example".to_owned()
        } else {
            name.to_owned()
        };
        let mut params = rcgen::CertificateParams::new(vec![sans]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        match flaw {
            Flaw::Expired => {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            Flaw::NotYetValid => {
                params.not_before = rcgen::date_time_ymd(2090, 1, 1);
                params.not_after = rcgen::date_time_ymd(2091, 1, 1);
            }
            _ => {
                params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                params.not_after = rcgen::date_time_ymd(2090, 1, 1);
            }
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = match flaw {
            Flaw::UnknownRoot => Pki::new().sign(&params, &key),
            Flaw::SelfSigned => params.self_signed(&key).unwrap(),
            _ => self.sign(&params, &key),
        };
        let config = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], PrivateKeyDer::from(key))
            .unwrap();
        Arc::new(config)
    }

    fn sign(&self, params: &rcgen::CertificateParams, key: &rcgen::KeyPair) -> rcgen::Certificate {
        params.signed_by(key, &self.issuer).unwrap()
    }

    /// A client for the proxy to reach this PKI's servers (and the system's).
    pub(crate) fn tls_client(&self) -> TlsClient {
        TlsClient::new([self.root.clone()]).unwrap()
    }
}

// ---------------------------------------------------------------------------------------------
// The fake upstream.

/// One request the fake upstream received.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub(crate) conn: usize,
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Recorded {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// What the fake upstream sends back.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) bytes: Vec<u8>,
    /// Close the connection after this reply.
    pub(crate) close: bool,
    /// Send one byte at a time with this pause (a slowloris server).
    pub(crate) trickle: Option<Duration>,
    /// Wait this long before replying.
    pub(crate) delay: Option<Duration>,
}

impl Reply {
    pub(crate) fn raw(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            close: false,
            trickle: None,
            delay: None,
        }
    }

    pub(crate) fn ok(body: &str) -> Self {
        Self::raw(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    pub(crate) fn status(code: u16, extra: &str, body: &str) -> Self {
        Self::raw(format!(
            "HTTP/1.1 {code} X\r\n{extra}content-length: {}\r\n\r\n{body}",
            body.len()
        ))
    }

    pub(crate) fn closing(mut self) -> Self {
        self.close = true;
        self
    }

    pub(crate) fn trickling(mut self, pause: Duration) -> Self {
        self.trickle = Some(pause);
        self
    }

    pub(crate) fn after(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

pub(crate) type Handler = Arc<dyn Fn(&Recorded) -> Reply + Send + Sync>;

/// A TLS (or plain) HTTP/1.1 server on loopback that records requests and answers by script.
pub(crate) struct FakeServer {
    pub(crate) addr: SocketAddr,
    /// Connections accepted (TCP).
    pub(crate) accepted: Arc<AtomicUsize>,
    /// TLS handshakes completed.
    pub(crate) handshakes: Arc<AtomicUsize>,
    pub(crate) requests: Arc<Mutex<Vec<Recorded>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeServer {
    pub(crate) async fn tls(config: Arc<rustls::ServerConfig>, handler: Handler) -> Self {
        Self::start(Some(config), handler).await
    }

    pub(crate) async fn plain(handler: Handler) -> Self {
        Self::start(None, handler).await
    }

    async fn start(config: Option<Arc<rustls::ServerConfig>>, handler: Handler) -> Self {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let accepted = Arc::clone(&accepted);
            let handshakes = Arc::clone(&handshakes);
            let requests = Arc::clone(&requests);
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let conn = accepted.fetch_add(1, Ordering::SeqCst);
                    let config = config.clone();
                    let handler = Arc::clone(&handler);
                    let requests = Arc::clone(&requests);
                    let handshakes = Arc::clone(&handshakes);
                    tokio::spawn(async move {
                        match config {
                            Some(config) => {
                                let Ok(tls) = TlsAcceptor::from(config).accept(tcp).await else {
                                    return;
                                };
                                handshakes.fetch_add(1, Ordering::SeqCst);
                                serve_http(tls, conn, handler, requests).await;
                            }
                            None => serve_http(tcp, conn, handler, requests).await,
                        }
                    });
                }
            })
        };
        Self {
            addr,
            accepted,
            handshakes,
            requests,
            task,
        }
    }

    pub(crate) fn recorded(&self) -> Vec<Recorded> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

async fn serve_http<S: AsyncRead + AsyncWriteExt + Unpin>(
    stream: S,
    conn: usize,
    handler: Handler,
    requests: Arc<Mutex<Vec<Recorded>>>,
) {
    let mut reader = BufReader::new(stream);
    loop {
        let Some(recorded) = read_request(&mut reader, conn).await else {
            return;
        };
        requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(recorded.clone());
        let reply = handler(&recorded);
        if let Some(delay) = reply.delay {
            tokio::time::sleep(delay).await;
        }
        let stream = reader.get_mut();
        match reply.trickle {
            Some(pause) => {
                for byte in &reply.bytes {
                    if stream.write_all(&[*byte]).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    tokio::time::sleep(pause).await;
                }
            }
            None => {
                if stream.write_all(&reply.bytes).await.is_err() {
                    return;
                }
            }
        }
        let _ = stream.flush().await;
        if reply.close {
            let _ = stream.shutdown().await;
            return;
        }
    }
}

async fn read_request<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
    conn: usize,
) -> Option<Recorded> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h).await.ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (name, value) = h.split_once(':')?;
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if let Some(length) = find("content-length") {
        body.resize(length.parse().ok()?, 0);
        reader.read_exact(&mut body).await.ok()?;
    } else if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).await.ok()?;
            let size = usize::from_str_radix(size.trim().split(';').next()?, 16).ok()?;
            if size == 0 {
                let mut end = String::new();
                reader.read_line(&mut end).await.ok()?;
                break;
            }
            let at = body.len();
            body.resize(at + size, 0);
            reader.read_exact(body.get_mut(at..)?).await.ok()?;
            let mut crlf = [0_u8; 2];
            reader.read_exact(&mut crlf).await.ok()?;
        }
    }
    Some(Recorded {
        conn,
        method,
        target,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------------------------
// The injector.

/// An injector with a script that records what it was asked.
pub(crate) struct TestInjector {
    script: Box<dyn Fn(&RequestView<'_>) -> InjectDecision + Send + Sync>,
    pub(crate) seen: Mutex<Vec<(String, String)>>,
    pub(crate) calls: AtomicUsize,
}

impl std::fmt::Debug for TestInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestInjector")
    }
}

impl TestInjector {
    pub(crate) fn new(
        script: impl Fn(&RequestView<'_>) -> InjectDecision + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            script: Box::new(script),
            seen: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        })
    }

    /// Injects `Authorization: Basic <canary>` into every request.
    pub(crate) fn always() -> Arc<Self> {
        Self::new(|_| inject(CANARY))
    }

    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn paths(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(_, t)| t.clone())
            .collect()
    }
}

pub(crate) fn inject(secret: &str) -> InjectDecision {
    InjectDecision::Inject(Injection::new(
        "binding-1",
        vec![
            InjectedHeader::new("authorization", SecretValue::new(format!("Basic {secret}")))
                .unwrap(),
        ],
    ))
}

pub(crate) fn refuse(status: u16, code: &'static str) -> InjectDecision {
    InjectDecision::Refuse(InjectRefusal::new(status, code, "refused by the test"))
}

impl Injector for TestInjector {
    fn decide<'a>(
        &'a self,
        _context: &'a InjectContext<'a>,
        request: &'a RequestView<'a>,
    ) -> BoxFuture<'a, InjectDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((request.method().to_owned(), request.target().to_owned()));
        let decision = (self.script)(request);
        Box::pin(std::future::ready(decision))
    }
}

// ---------------------------------------------------------------------------------------------
// The proxy under test.

/// Resolves each name to a fixed loopback address, whatever the port.
#[derive(Debug, Default)]
pub(crate) struct Fixed(Mutex<HashMap<String, SocketAddr>>);

impl Fixed {
    pub(crate) fn with(self, name: &str, addr: SocketAddr) -> Self {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), addr);
        self
    }
}

impl Resolver for Fixed {
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        _port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        let found = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name.as_str())
            .copied();
        Box::pin(async move {
            found
                .map(|a| vec![a])
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
        })
    }
}

pub(crate) fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

pub(crate) fn sandbox(name: &str) -> SandboxName {
    SandboxName::new(name).unwrap()
}

/// A sandbox's CA for `names`.
pub(crate) fn sandbox_ca(name: &str, names: &[&str]) -> Arc<SandboxCa> {
    let set = TerminationSet::parse(names.iter().copied()).unwrap();
    Arc::new(
        CaBuilder::new(
            &format!("puddle test CA ({name})"),
            set.name_constraints().unwrap(),
        )
        .build()
        .unwrap(),
    )
}

pub(crate) struct RigBuilder {
    pub(crate) bound: Vec<&'static str>,
    pub(crate) config: ProxyConfig,
    pub(crate) injector: Arc<dyn Injector>,
    pub(crate) tls: Option<TlsClient>,
    pub(crate) names: Vec<(&'static str, SocketAddr)>,
    pub(crate) allow: Vec<&'static str>,
}

impl RigBuilder {
    pub(crate) fn new(pki: &Pki) -> Self {
        Self {
            bound: vec!["bound.test"],
            config: ProxyConfig::default(),
            injector: TestInjector::always(),
            tls: Some(pki.tls_client()),
            names: Vec::new(),
            allow: vec!["bound.test"],
        }
    }

    pub(crate) fn name(mut self, name: &'static str, addr: SocketAddr) -> Self {
        self.names.push((name, addr));
        self
    }

    pub(crate) fn injector(mut self, injector: Arc<dyn Injector>) -> Self {
        self.injector = injector;
        self
    }

    pub(crate) fn config(mut self, config: ProxyConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) fn bound(mut self, bound: Vec<&'static str>) -> Self {
        self.bound = bound;
        self
    }

    pub(crate) fn tls(mut self, tls: TlsClient) -> Self {
        self.tls = Some(tls);
        self
    }

    pub(crate) fn allow(mut self, allow: Vec<&'static str>) -> Self {
        self.allow = allow;
        self
    }

    pub(crate) fn build(self) -> Rig {
        capture_logs();
        let policy = Arc::new(StaticPolicy::new());
        for name in &self.allow {
            policy.allow(&host(name));
        }
        let log = Arc::new(CollectingConnectionLog::new());
        let mut resolver = Fixed::default();
        for (name, addr) in &self.names {
            resolver = resolver.with(name, *addr);
        }
        let ca = sandbox_ca("box", &self.bound);
        let terminations = Arc::new(Terminations::new());
        terminations.insert(
            sandbox("box"),
            Termination::new(
                TerminationSet::parse(self.bound.iter().copied()).unwrap(),
                Arc::clone(&ca),
                self.injector,
            )
            .unwrap(),
        );
        // A second sandbox with its own CA for the same names (HO-4).
        let other_ca = sandbox_ca("other", &self.bound);
        terminations.insert(
            sandbox("other"),
            Termination::new(
                TerminationSet::parse(self.bound.iter().copied()).unwrap(),
                Arc::clone(&other_ca),
                Arc::new(puddle_proxy::NoInjection),
            )
            .unwrap(),
        );
        let proxy = Proxy::new(policy.clone(), Arc::new(NullSink))
            .with_connection_log(log.clone())
            .with_resolver(Arc::new(resolver))
            .with_address_check(Arc::new(AnyAddress))
            .with_config(self.config)
            .with_termination(terminations, self.tls.unwrap());
        let proxy = Arc::new(proxy);
        let root = IpcRoot::new().unwrap();
        let route = proxy.serve_route(root.listen().unwrap(), sandbox("box"));
        let other_root = IpcRoot::new().unwrap();
        let other_route = proxy.serve_route(other_root.listen().unwrap(), sandbox("other"));
        Rig {
            policy,
            log,
            route,
            other_route,
            ca,
            other_ca,
            _roots: (root, other_root),
        }
    }
}

pub(crate) struct Rig {
    pub(crate) policy: Arc<StaticPolicy>,
    pub(crate) log: Arc<CollectingConnectionLog>,
    pub(crate) route: Route,
    pub(crate) other_route: Route,
    pub(crate) ca: Arc<SandboxCa>,
    pub(crate) other_ca: Arc<SandboxCa>,
    _roots: (IpcRoot, IpcRoot),
}

impl Rig {
    pub(crate) async fn guest(&self) -> Guest {
        Guest::connect(&self.route, Arc::clone(&self.ca)).await
    }

    pub(crate) async fn other_guest(&self) -> Guest {
        Guest::connect(&self.other_route, Arc::clone(&self.other_ca)).await
    }

    pub(crate) async fn events(&self, count: usize) -> Vec<ConnectionEvent> {
        let events = self.log.wait_for(count, Duration::from_secs(5)).await;
        assert!(events.len() >= count, "{count} events expected: {events:?}");
        events
    }
}

pub(crate) struct Guest {
    pub(crate) control: Control,
    driver: JoinHandle<()>,
    ca: Arc<SandboxCa>,
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Guest {
    async fn connect(route: &Route, ca: Arc<SandboxCa>) -> Self {
        let conn = puddle_ipc::connect(route.endpoint().path()).await.unwrap();
        let mut session = Session::new_client(conn, client_config());
        let control = session.control();
        let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
        Self {
            control,
            driver,
            ca,
        }
    }

    /// A TLS client config trusting `roots` only.
    pub(crate) fn client_config(
        roots: &[CertificateDer<'static>],
        alpn: &[&[u8]],
    ) -> rustls::ClientConfig {
        let mut store = rustls::RootCertStore::empty();
        for root in roots {
            store.add(root.clone()).unwrap();
        }
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }

    /// Opens a `CONNECT authority` tunnel; the status line and the tunnel's stream.
    pub(crate) async fn connect_to(&mut self, authority: &str) -> (u16, BufReader<StreamHandle>) {
        let mut stream = self.control.open_stream().await.unwrap();
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let code = line.split(' ').nth(1).unwrap().parse().unwrap();
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).await.unwrap();
            if h == "\r\n" || h.is_empty() {
                return (code, reader);
            }
        }
    }

    /// `CONNECT authority`, then a TLS handshake that trusts the sandbox CA, with `sni` as the
    /// name asked for (the authority's host by default).
    pub(crate) async fn tls(&mut self, authority: &str, sni: Option<&str>) -> io::Result<Client> {
        self.tls_with(authority, sni, &[b"http/1.1"], true).await
    }

    pub(crate) async fn tls_with(
        &mut self,
        authority: &str,
        sni: Option<&str>,
        alpn: &[&[u8]],
        send_sni: bool,
    ) -> io::Result<Client> {
        let (code, reader) = self.connect_to(authority).await;
        assert_eq!(code, 200, "CONNECT {authority}");
        let roots = [self.ca.certificate().der().clone()];
        let mut config = Self::client_config(&roots, alpn);
        config.enable_sni = send_sni;
        let name = sni.unwrap_or_else(|| authority.rsplit_once(':').unwrap().0);
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name.to_owned()).unwrap(), reader)
            .await?;
        Ok(Client {
            alpn: tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
            stream: BufReader::new(tls),
        })
    }

    /// A TLS handshake to `authority` trusting `roots` (for spliced hosts).
    pub(crate) async fn tls_trusting(
        &mut self,
        authority: &str,
        roots: &[CertificateDer<'static>],
    ) -> io::Result<Client> {
        let (code, reader) = self.connect_to(authority).await;
        assert_eq!(code, 200);
        let config = Self::client_config(roots, &[b"http/1.1"]);
        let name = authority.rsplit_once(':').unwrap().0.to_owned();
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(name).unwrap(), reader)
            .await?;
        Ok(Client {
            alpn: None,
            stream: BufReader::new(tls),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// A raw HTTP/1.1 client over the guest's TLS stream.

pub(crate) type TlsStream = tokio_rustls::client::TlsStream<BufReader<StreamHandle>>;

pub(crate) struct Client {
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) stream: BufReader<TlsStream>,
}

#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Client {
    pub(crate) async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// Sends `GET path` with `Host: host` and reads the response.
    pub(crate) async fn get(&mut self, host: &str, path: &str) -> Response {
        self.send(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await;
        self.response("GET").await
    }

    pub(crate) async fn response(&mut self, method: &str) -> Response {
        self.try_response(method).await.expect("a response")
    }

    pub(crate) async fn try_response(&mut self, method: &str) -> Option<Response> {
        read_response(&mut self.stream, method).await
    }

    /// Closes the TLS connection cleanly, as a client that is done.
    pub(crate) async fn close(mut self) {
        let _ = self.stream.shutdown().await;
        let mut rest = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), self.stream.read_to_end(&mut rest)).await;
    }

    /// Whether the server side has closed the connection.
    pub(crate) async fn closed(&mut self) -> bool {
        let mut byte = [0_u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(2), self.stream.read(&mut byte)).await,
            Ok(Ok(0) | Err(_))
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Logs, to prove no secret reaches them.

static LOGS: std::sync::OnceLock<Arc<Mutex<Vec<u8>>>> = std::sync::OnceLock::new();

#[derive(Clone)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Starts capturing every log line of this test binary at TRACE level (once).
pub(crate) fn capture_logs() {
    let logs = LOGS.get_or_init(|| Arc::new(Mutex::new(Vec::new())));
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(LogWriter(Arc::clone(logs)))
        .try_init();
}

/// Everything logged so far.
pub(crate) fn captured_logs() -> String {
    LOGS.get()
        .map(|logs| {
            String::from_utf8_lossy(&logs.lock().unwrap_or_else(PoisonError::into_inner))
                .into_owned()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------------
// A loopback TCP bridge into the guest's route, for clients that are separate programs.

impl Guest {
    /// Listens on a loopback port; each connection becomes `CONNECT authority` on the route and
    /// is then relayed byte for byte, as if the program had opened the tunnel itself.
    pub(crate) async fn bridge(&self, authority: &'static str) -> (u16, JoinHandle<()>) {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut control = self.control.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let Ok(mut stream) = control.open_stream().await else {
                    return;
                };
                tokio::spawn(async move {
                    let head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
                    if stream.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let mut seen = Vec::new();
                    let mut byte = [0_u8; 1];
                    while !seen.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        seen.push(byte[0]);
                    }
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                });
            }
        });
        (port, task)
    }
}

/// Reads one response from `stream`.
pub(crate) async fn read_response<R: AsyncBufReadExt + Unpin>(
    stream: &mut R,
    method: &str,
) -> Option<Response> {
    let mut line = String::new();
    if stream.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let status = line.split(' ').nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if stream.read_line(&mut h).await.ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (n, v) = h.split_once(':')?;
        headers.push((n.to_owned(), v.trim().to_owned()));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    let bodyless = method == "HEAD" || status == 204 || status == 304 || status / 100 == 1;
    if bodyless {
    } else if let Some(length) = find("content-length") {
        body.resize(length.parse().ok()?, 0);
        stream.read_exact(&mut body).await.ok()?;
    } else if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            stream.read_line(&mut size).await.ok()?;
            let size = usize::from_str_radix(size.trim(), 16).ok()?;
            if size == 0 {
                let mut end = String::new();
                stream.read_line(&mut end).await.ok()?;
                break;
            }
            let at = body.len();
            body.resize(at + size, 0);
            stream.read_exact(body.get_mut(at..)?).await.ok()?;
            let mut crlf = [0_u8; 2];
            stream.read_exact(&mut crlf).await.ok()?;
        }
    } else {
        let _ = stream.read_to_end(&mut body).await;
    }
    Some(Response {
        status,
        headers,
        body,
    })
}
