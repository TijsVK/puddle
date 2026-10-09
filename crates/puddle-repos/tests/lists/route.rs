// SPDX-License-Identifier: GPL-3.0-or-later
//! The real route: puddle's own connection (direct, or through a company proxy with Basic
//! sign-in), TLS checked against the roots it is given, one HTTP/1.1 request, and every way that
//! can go wrong. The servers are local; nothing here touches the internet.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::pending;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use puddle_repos::{Api, ApiRequest, Authorization, HostApi, MAX_BODY, TransportError};
use puddle_secrets::Secret;
use puddle_upstream::{
    BasicAuth, Behaviour, Chain, ChainConfig, Config, Credentials, Discovery, FakeOs, FakeProxy,
    Hop, NoAuth, ProxyConfig, TlsClient,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const CANARY: &str = "CANARY-route-token-3b19";

/// A request the server saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    /// Headers with bytes outside printable ASCII, which a client cannot read as text.
    raw_headers: Vec<(&'static str, &'static [u8])>,
    body: Vec<u8>,
}

impl Reply {
    fn ok(body: &str) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            raw_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }
}

enum Mode {
    Answer(Arc<dyn Fn(&Seen) -> Reply + Send + Sync>),
    Hang,
    Raw(&'static [u8]),
    HangUp,
}

struct Pki {
    root: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

impl Pki {
    fn new(san: &str) -> Self {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "git host test root");
        let root = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![san.to_owned()]).unwrap();
        let cert = leaf.signed_by(&key, &issuer).unwrap();
        Self {
            root: root.der().clone(),
            cert: cert.der().clone(),
            key: key.serialize_der(),
        }
    }

    fn acceptor(&self) -> TlsAcceptor {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![self.cert.clone()],
            PrivateKeyDer::try_from(self.key.clone()).unwrap(),
        )
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    async fn start(pki: &Pki, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let acceptor = pki.acceptor();
        let mode = Arc::new(mode);
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, mode, log) = (acceptor.clone(), mode.clone(), log.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    match &*mode {
                        Mode::Raw(bytes) => {
                            let _ = tls.write_all(bytes).await;
                            let _ = tls.shutdown().await;
                        }
                        Mode::HangUp => drop(tls),
                        Mode::Hang => pending::<()>().await,
                        Mode::Answer(answer) => {
                            let answer = answer.clone();
                            let service = service_fn(move |request: Request<Incoming>| {
                                let (answer, log) = (answer.clone(), log.clone());
                                async move {
                                    let seen = Seen {
                                        method: request.method().to_string(),
                                        path: request
                                            .uri()
                                            .path_and_query()
                                            .map(ToString::to_string)
                                            .unwrap_or_default(),
                                        headers: request
                                            .headers()
                                            .iter()
                                            .map(|(n, v)| {
                                                (
                                                    n.to_string(),
                                                    v.to_str().unwrap_or_default().to_owned(),
                                                )
                                            })
                                            .collect(),
                                    };
                                    let reply = answer(&seen);
                                    log.lock()
                                        .unwrap_or_else(PoisonError::into_inner)
                                        .push(seen);
                                    let mut response = Response::builder().status(reply.status);
                                    for (name, value) in reply.headers {
                                        response = response.header(name, value);
                                    }
                                    for (name, value) in reply.raw_headers {
                                        response = response
                                            .header(name, HeaderValue::from_bytes(value).unwrap());
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        response.body(Full::new(Bytes::from(reply.body))).unwrap(),
                                    )
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(tls), service)
                                .await;
                        }
                    }
                });
            }
        });
        Self { addr, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn direct_chain() -> Arc<Chain> {
    Chain::new(
        Discovery::new(FakeOs::new(ProxyConfig::default()), Config::default()),
        Arc::new(NoAuth),
    )
}

fn through_proxy(proxy: &FakeProxy) -> Arc<Chain> {
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..ProxyConfig::default()
    });
    let hops = vec![Hop::Proxy(proxy.proxy_addr())];
    os.set_pac(move |_| Ok(hops.clone()));
    Chain::with_config(
        Discovery::new(os, Config::default()),
        Arc::new(BasicAuth::new().with_default(Credentials::new("corp", "proxy-pw"))),
        ChainConfig::default()
            .with_timeouts(Duration::from_millis(500), Duration::from_millis(400)),
    )
}

fn request(host: &str, path: &str) -> ApiRequest {
    ApiRequest {
        host: host.to_owned(),
        path: path.to_owned(),
        accept: "application/vnd.github+json",
        headers: &[("x-github-api-version", "2022-11-28")],
        authorization: Authorization::Bearer(Arc::new(Secret::new(CANARY.to_owned()))),
    }
}

fn api(chain: Arc<Chain>, pki: &Pki) -> HostApi {
    HostApi::new(chain, TlsClient::new([pki.root.clone()]).unwrap())
}

#[tokio::test]
async fn a_request_goes_out_with_the_headers_a_git_host_expects_and_the_answer_comes_back() {
    let pki = Pki::new("localhost");
    let server = Server::start(
        &pki,
        Mode::Answer(Arc::new(|_| Reply {
            status: 200,
            headers: vec![
                ("link", r#"<https://api.example.test/next>; rel="next""#),
                ("x-ratelimit-remaining", "4999"),
                ("x-repeated", "first"),
                ("x-repeated", "second"),
            ],
            raw_headers: vec![("x-not-text", b"value-\xe9")],
            body: br#"[{"full_name":"a/b"}]"#.to_vec(),
        })),
    )
    .await;
    let host = format!("localhost:{}", server.addr.port());

    let reply = api(direct_chain(), &pki)
        .get(request(&host, "/user/repos?per_page=1"))
        .await
        .unwrap();

    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, br#"[{"full_name":"a/b"}]"#);
    assert_eq!(reply.header("x-ratelimit-remaining"), Some("4999"));
    assert_eq!(
        reply.header("link"),
        Some(r#"<https://api.example.test/next>; rel="next""#)
    );
    assert_eq!(reply.header("x-repeated"), Some("first"));
    // A header whose value is not text is left out; the rest of the answer is unaffected.
    assert_eq!(reply.header("x-not-text"), None);
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("GET", "/user/repos?per_page=1")
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {CANARY}"))
    );
    assert_eq!(seen[0].header("user-agent"), Some("puddle"));
    assert_eq!(
        seen[0].header("accept"),
        Some("application/vnd.github+json")
    );
    assert_eq!(seen[0].header("x-github-api-version"), Some("2022-11-28"));
    assert_eq!(seen[0].header("connection"), Some("close"));
    assert_eq!(seen[0].header("host"), Some(host.as_str()));
}

#[tokio::test]
async fn a_company_proxy_that_asks_for_sign_in_is_signed_in_to_and_the_host_is_reached_by_name() {
    let pki = Pki::new("api.git-host.test");
    let server = Server::start(&pki, Mode::Answer(Arc::new(|_| Reply::ok("[]")))).await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "corp".into(),
        password: "proxy-pw".into(),
    })
    .await;
    proxy.resolve_name("api.git-host.test", server.addr);

    let reply = api(through_proxy(&proxy), &pki)
        .get(request("api.git-host.test", "/user"))
        .await
        .unwrap();

    assert_eq!(reply.status, 200);
    let proxied = proxy.seen();
    assert!(
        proxied
            .iter()
            .any(|s| s.method == "CONNECT" && s.target == "api.git-host.test:443"),
        "{proxied:?}"
    );
    // The token reached the host inside the tunnel and never the proxy.
    assert_eq!(
        server.seen()[0].header("authorization"),
        Some(&*format!("Bearer {CANARY}"))
    );
    assert!(!format!("{proxied:?}").contains(CANARY));
}

#[tokio::test]
async fn a_redirect_is_handed_back_never_followed() {
    let pki = Pki::new("localhost");
    let server = Server::start(
        &pki,
        Mode::Answer(Arc::new(|_| Reply {
            status: 302,
            headers: vec![("location", "https://evil.example/steal")],
            raw_headers: Vec::new(),
            body: Vec::new(),
        })),
    )
    .await;
    let host = format!("localhost:{}", server.addr.port());

    let reply = api(direct_chain(), &pki)
        .get(request(&host, "/user"))
        .await
        .unwrap();

    assert_eq!(reply.status, 302);
    assert_eq!(reply.header("location"), Some("https://evil.example/steal"));
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn an_answer_over_the_size_limit_is_refused() {
    let pki = Pki::new("localhost");
    let server = Server::start(
        &pki,
        Mode::Answer(Arc::new(|_| Reply {
            status: 200,
            headers: Vec::new(),
            raw_headers: Vec::new(),
            body: vec![b' '; MAX_BODY + 1],
        })),
    )
    .await;
    let host = format!("localhost:{}", server.addr.port());

    let err = api(direct_chain(), &pki)
        .get(request(&host, "/user"))
        .await
        .unwrap_err();

    assert_eq!(err, TransportError::TooLarge);
}

#[tokio::test]
async fn a_certificate_nobody_trusts_is_a_tls_failure_naming_the_reason() {
    let pki = Pki::new("localhost");
    let other = Pki::new("localhost");
    let server = Server::start(&pki, Mode::Answer(Arc::new(|_| Reply::ok("[]")))).await;
    let host = format!("localhost:{}", server.addr.port());

    // The client trusts another root than the one that signed the server's certificate.
    let err = api(direct_chain(), &other)
        .get(request(&host, "/user"))
        .await
        .unwrap_err();

    assert!(
        matches!(&err, TransportError::Tls(why) if why.to_lowercase().contains("certificate") || why.to_lowercase().contains("issuer")),
        "{err:?}"
    );
    assert!(
        server.seen().is_empty(),
        "no request was sent over a connection that is not trusted"
    );
}

#[tokio::test]
async fn an_address_instead_of_a_name_is_refused_before_anything_is_sent() {
    let pki = Pki::new("localhost");
    let server = Server::start(&pki, Mode::Answer(Arc::new(|_| Reply::ok("[]")))).await;

    let err = api(direct_chain(), &pki)
        .get(request(
            &format!("127.0.0.1:{}", server.addr.port()),
            "/user",
        ))
        .await
        .unwrap_err();

    assert!(
        matches!(&err, TransportError::Unreachable(why) if why.contains("not a valid server name")),
        "{err:?}"
    );
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn a_host_nothing_listens_on_is_unreachable() {
    let pki = Pki::new("localhost");
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let err = api(direct_chain(), &pki)
        .get(request(&format!("localhost:{closed}"), "/user"))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Unreachable(_)), "{err:?}");
}

#[tokio::test]
async fn a_host_that_never_answers_times_out() {
    let pki = Pki::new("localhost");
    let server = Server::start(&pki, Mode::Hang).await;
    let host = format!("localhost:{}", server.addr.port());
    let started = std::time::Instant::now();

    let err = api(direct_chain(), &pki)
        .with_timeout(Duration::from_millis(300))
        .get(request(&host, "/user"))
        .await
        .unwrap_err();

    assert_eq!(err, TransportError::Timeout(1));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn a_host_that_hangs_up_or_does_not_speak_http_is_a_protocol_failure() {
    let pki = Pki::new("localhost");
    for mode in [
        Mode::HangUp,
        Mode::Raw(b"NOT HTTP AT ALL\r\n\r\n"),
        // An answer that promises a hundred bytes and stops after five.
        Mode::Raw(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort"),
    ] {
        let server = Server::start(&pki, mode).await;
        let host = format!("localhost:{}", server.addr.port());
        let err = api(direct_chain(), &pki)
            .get(request(&host, "/user"))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::Protocol(_)), "{err:?}");
    }
}

#[tokio::test]
async fn a_token_a_header_cannot_carry_is_refused_before_connecting() {
    let pki = Pki::new("localhost");
    let mut bad = request("localhost:1", "/user");
    bad.authorization = Authorization::Bearer(Arc::new(Secret::new("CANARY-a\nb".to_owned())));
    let err = api(direct_chain(), &pki).get(bad).await.unwrap_err();
    assert_eq!(err, TransportError::BadToken);
}

#[tokio::test]
async fn a_path_that_is_not_a_uri_is_a_protocol_failure() {
    let pki = Pki::new("localhost");
    let server = Server::start(&pki, Mode::Answer(Arc::new(|_| Reply::ok("[]")))).await;
    let host = format!("localhost:{}", server.addr.port());
    let err = api(direct_chain(), &pki)
        .get(request(&host, "/user repos"))
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Protocol(_)), "{err:?}");
    assert!(server.seen().is_empty());
}

#[test]
fn the_route_describes_itself_without_a_secret() {
    let pki = Pki::new("localhost");
    let api = api(direct_chain(), &pki);
    assert_eq!(format!("{api:?}"), "HostApi { .. }");
}
