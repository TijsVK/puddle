// SPDX-License-Identifier: GPL-3.0-or-later
//! The chain against a scripted proxy on loopback: `CONNECT`, absolute form, `407` rounds on one
//! connection, dead-hop fallback, and what a hop is never allowed to reach.
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use puddle_upstream::{
    AuthError, AuthList, AuthSession, AuthStep, BasicAuth, Behaviour, Chain, ChainConfig,
    ChainError, Config, Credentials, Destination, Discovery, FakeOs, FakeProxy, Form, Hop,
    ProxyAddr, ProxyAuth, ProxyConfig, Request, Scheme,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An echo server that counts the connections it accepted.
struct Echo {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

async fn start_echo() -> Echo {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0_u8; 1024];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Echo { addr, accepted }
}

/// A discovery whose PAC answers `hops` for every URL.
fn discovery(hops: Vec<Hop>) -> Arc<Discovery> {
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..ProxyConfig::default()
    });
    os.set_pac(move |_| Ok(hops.clone()));
    Discovery::new(os, Config::default())
}

fn fast() -> ChainConfig {
    ChainConfig::default().with_timeouts(Duration::from_millis(500), Duration::from_millis(400))
}

fn chain(hops: Vec<Hop>, auth: Arc<dyn ProxyAuth>) -> Arc<Chain> {
    Chain::with_config(discovery(hops), auth, fast())
}

fn via(proxy: &FakeProxy) -> Hop {
    Hop::Proxy(proxy.proxy_addr())
}

fn https(host: &str) -> Destination {
    Destination::new(Scheme::Https, host, 443)
}

fn http(host: &str) -> Destination {
    Destination::new(Scheme::Http, host, 80)
}

fn basic(user: &str, password: &str) -> Arc<dyn ProxyAuth> {
    Arc::new(BasicAuth::new().with_default(Credentials::new(user, password)))
}

async fn round_trip(stream: &mut TcpStream, text: &[u8]) {
    stream.write_all(text).await.unwrap();
    let mut back = vec![0_u8; text.len()];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, text);
}

/// A proxy address nothing answers on. The socket is bound but never listens, so the port stays
/// ours (a released port could be taken by another test's server) and connecting is refused.
fn dead_port() -> (ProxyAddr, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    (ProxyAddr::new("127.0.0.1", port), socket)
}

#[tokio::test]
async fn connect_goes_through_an_open_proxy_by_name() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("registry.corp.test", echo.addr);
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = https("registry.corp.test");
    let request = Request::new(&dest, Form::Tunnel, &[]).name_ok(true);
    let mut connected = chain.connect(&request).await.unwrap();
    assert_eq!(connected.hop, via(&proxy));
    assert_eq!(connected.addr, None);
    round_trip(&mut connected.stream, b"through the company proxy").await;
    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "CONNECT");
    assert_eq!(seen[0].target, "registry.corp.test:443");
    assert_eq!(seen[0].proxy_authorization, None);
}

#[tokio::test]
async fn without_name_ok_the_proxy_is_sent_a_checked_address_never_the_name() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = https("rebind.evil.test");
    let checked = [echo.addr];
    let request = Request::new(&dest, Form::Tunnel, &checked);
    let mut connected = chain.connect(&request).await.unwrap();
    round_trip(&mut connected.stream, b"pinned").await;
    assert_eq!(proxy.seen()[0].target, echo.addr.to_string());
    assert!(
        !proxy.seen().iter().any(|s| s.target.contains("evil")),
        "the name must not reach the proxy"
    );
}

#[tokio::test]
async fn a_proxy_gets_nothing_when_there_is_no_name_and_no_checked_address() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = https("x.test");
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]))
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::Unreachable { .. }), "{err}");
    assert_eq!(proxy.connections(), 0);
}

#[tokio::test]
async fn a_basic_407_is_answered_on_the_same_connection_then_sent_up_front() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "t165".into(),
        password: "s3cret".into(),
    })
    .await;
    proxy.resolve_name("a.test", echo.addr);
    let chain = chain(vec![via(&proxy)], basic("t165", "s3cret"));
    let dest = https("a.test");
    let request = Request::new(&dest, Form::Tunnel, &[]).name_ok(true);

    let mut first = chain.connect(&request).await.unwrap();
    round_trip(&mut first.stream, b"one").await;
    let seen = proxy.seen();
    assert_eq!(seen.len(), 2, "407, then the credential");
    assert_eq!(seen[0].proxy_authorization, None);
    assert!(
        seen[1]
            .proxy_authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
    assert_eq!(seen[0].conn, seen[1].conn, "both legs on one connection");
    assert_eq!(proxy.connections(), 1);

    let mut second = chain.connect(&request).await.unwrap();
    round_trip(&mut second.stream, b"two").await;
    let seen = proxy.seen();
    assert_eq!(seen.len(), 3, "the credential goes up front: no second 407");
    assert!(seen[2].proxy_authorization.is_some());
}

#[tokio::test]
async fn a_wrong_password_is_one_attempt_not_a_loop() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "t165".into(),
        password: "right".into(),
    })
    .await;
    let chain = chain(vec![via(&proxy), Hop::Direct], basic("t165", "wrong"));
    let dest = https("a.test");
    let echo = start_echo().await;
    let checked = [echo.addr];
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &checked).name_ok(true))
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::AuthFailed { .. }), "{err}");
    assert_eq!(proxy.seen().len(), 2, "one 407, one rejected credential");
    assert_eq!(
        echo.accepted.load(Ordering::SeqCst),
        0,
        "a refused login never falls through to DIRECT"
    );
    assert!(
        !err.to_string().contains("wrong"),
        "no password in the error"
    );
}

#[tokio::test]
async fn a_proxy_that_wants_credentials_nobody_configured_is_reported_with_its_schemes() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "u".into(),
        password: "p".into(),
    })
    .await;
    let chain = chain(vec![via(&proxy)], Arc::new(BasicAuth::new()));
    let dest = https("a.test");
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    match err {
        ChainError::AuthRequired { proxy: p, schemes } => {
            assert_eq!(p, proxy.proxy_addr());
            assert_eq!(schemes, ["Basic"]);
        }
        other => panic!("{other}"),
    }
}

/// A scripted NTLM client: `NTLM T1` for the bare challenge, `NTLM T3` for the proxy's token.
#[derive(Debug)]
struct NtlmAuth;

#[derive(Debug)]
struct NtlmSession;

impl AuthSession for NtlmSession {
    fn step(&mut self, challenge: Option<&str>) -> Result<AuthStep, AuthError> {
        match challenge.map(str::trim) {
            Some("NTLM") => Ok(AuthStep::Authorization("NTLM T1".into())),
            Some("NTLM CHALLENGE") => Ok(AuthStep::Authorization("NTLM T3".into())),
            other => Err(AuthError::Failed(format!("unexpected challenge {other:?}"))),
        }
    }
}

impl ProxyAuth for NtlmAuth {
    fn begin(
        &self,
        _proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        Ok(offered
            .iter()
            .any(|s| s.eq_ignore_ascii_case("ntlm"))
            .then(|| Box::new(NtlmSession) as Box<dyn AuthSession>))
    }
}

#[tokio::test]
async fn a_three_leg_exchange_stays_on_one_connection() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Ntlm).await;
    proxy.resolve_name("ntlm.test", echo.addr);
    let chain = chain(vec![via(&proxy)], Arc::new(NtlmAuth));
    let dest = https("ntlm.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    round_trip(&mut connected.stream, b"signed in").await;
    let seen = proxy.seen();
    let auth: Vec<_> = seen
        .iter()
        .map(|s| s.proxy_authorization.as_deref())
        .collect();
    assert_eq!(auth, [None, Some("NTLM T1"), Some("NTLM T3")]);
    assert!(
        seen.iter().all(|s| s.conn == 1),
        "one connection throughout"
    );
}

#[tokio::test]
async fn a_connection_based_scheme_that_loses_its_connection_ends_after_the_leg_limit() {
    let proxy = FakeProxy::start(Behaviour::NtlmClosing).await;
    let chain = chain(vec![via(&proxy)], Arc::new(NtlmAuth));
    let dest = https("ntlm.test");
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::AuthFailed { .. }), "{err}");
    assert!(proxy.seen().len() <= ChainConfig::default().max_legs + 1);
}

#[tokio::test]
async fn a_proxy_that_never_stops_asking_is_cut_off() {
    let proxy = FakeProxy::start(Behaviour::Always407).await;
    let chain = chain(vec![via(&proxy)], basic("u", "p"));
    let dest = https("loop.test");
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::AuthFailed { .. }), "{err}");
    assert!(proxy.seen().len() <= 3);
}

#[tokio::test]
async fn a_refusal_is_passed_on_and_never_falls_through_to_direct() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Refuse(403)).await;
    let chain = chain(
        vec![via(&proxy), Hop::Direct],
        Arc::new(puddle_upstream::NoAuth),
    );
    let dest = https("blocked.corp.test");
    let checked = [echo.addr];
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &checked).name_ok(true))
        .await
        .unwrap_err();
    match err {
        ChainError::Refused {
            status, proxy: p, ..
        } => {
            assert_eq!(status, 403);
            assert_eq!(p, proxy.proxy_addr());
        }
        other => panic!("{other}"),
    }
    assert_eq!(echo.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_unreachable_proxy_falls_back_in_order_and_is_marked_dead() {
    let echo = start_echo().await;
    let (dead, _held) = dead_port();
    let silent = FakeProxy::start(Behaviour::Silent).await;
    let garbage = FakeProxy::start(Behaviour::Garbage).await;
    let good = FakeProxy::start(Behaviour::Open).await;
    good.resolve_name("fallback.test", echo.addr);
    let hops = vec![
        Hop::Proxy(dead.clone()),
        via(&silent),
        via(&garbage),
        via(&good),
        Hop::Direct,
    ];
    let discovery = discovery(hops);
    let chain = Chain::with_config(
        Arc::clone(&discovery),
        Arc::new(puddle_upstream::NoAuth),
        fast(),
    );
    let dest = https("fallback.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    assert_eq!(connected.hop, via(&good));
    round_trip(&mut connected.stream, b"fell through three hops").await;

    // The three that failed moved behind the working hop (never removed), DIRECT stays put.
    let route = discovery.route(&dest).await.route;
    let order: Vec<_> = route.hops().to_vec();
    assert_eq!(order.first(), Some(&via(&good)));
    assert_eq!(order.len(), 5);
    assert!(order.contains(&Hop::Proxy(dead)));
    // A second connect now starts at the good proxy.
    let before = silent.connections();
    chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    assert_eq!(
        silent.connections(),
        before,
        "the dead hop is not asked first any more"
    );
}

#[tokio::test]
async fn direct_connects_only_to_a_checked_address() {
    let echo = start_echo().await;
    let other = start_echo().await;
    let chain = chain(vec![Hop::Direct], Arc::new(puddle_upstream::NoAuth));
    let dest = https("name.that.resolves.elsewhere.test");
    let checked = [echo.addr];
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Tunnel, &checked).name_ok(true))
        .await
        .unwrap();
    assert_eq!(connected.hop, Hop::Direct);
    assert_eq!(connected.addr, Some(echo.addr));
    round_trip(&mut connected.stream, b"direct").await;
    assert_eq!(other.accepted.load(Ordering::SeqCst), 0);

    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    match err {
        ChainError::Unreachable { tried } => {
            assert_eq!(tried.len(), 1);
            assert_eq!(tried[0].0, Hop::Direct);
        }
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn every_hop_failing_lists_each_with_its_reason() {
    let (dead, _held) = dead_port();
    let chain = chain(
        vec![Hop::Proxy(dead.clone()), Hop::Direct],
        Arc::new(puddle_upstream::NoAuth),
    );
    let dest = https("nowhere.test");
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains(&format!("PROXY {dead}")), "{text}");
    assert!(text.contains("DIRECT"), "{text}");
}

#[tokio::test]
async fn an_ipv6_address_is_sent_with_brackets() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = https("v6.test");
    let checked: [SocketAddr; 1] = ["[2001:db8::1]:443".parse().unwrap()];
    // The fake cannot reach it; only the request line matters.
    let err = chain
        .connect(&Request::new(&dest, Form::Tunnel, &checked))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ChainError::Refused { status: 502, .. }),
        "{err}"
    );
    assert_eq!(proxy.seen()[0].target, "[2001:db8::1]:443");
}

#[tokio::test]
async fn absolute_form_probes_authenticates_and_carries_basic_on_each_request() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "t165".into(),
        password: "s3cret".into(),
    })
    .await;
    let chain = chain(vec![via(&proxy)], basic("t165", "s3cret"));
    let dest = http("plain.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Absolute, &[]).name_ok(true))
        .await
        .unwrap();
    let authorization = connected.authorization.clone().expect("Basic is carried");
    assert_eq!(connected.authority.as_deref(), Some("plain.test:80"));
    let get = format!(
        "GET http://plain.test:80/x HTTP/1.1\r\nHost: plain.test\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
        authorization.expose()
    );
    connected.stream.write_all(get.as_bytes()).await.unwrap();
    let mut body = String::new();
    connected.stream.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.ends_with("via-proxy http://plain.test:80/x"), "{body}");
    let seen = proxy.seen();
    assert_eq!(seen[0].method, "HEAD");
    assert_eq!(seen[0].proxy_authorization, None);
    assert_eq!(seen[1].method, "HEAD");
    assert!(seen[1].proxy_authorization.is_some());
    assert_eq!(seen[2].method, "GET");
    assert_eq!(proxy.connections(), 1);
    assert!(!format!("{authorization:?}").contains("Basic"));
}

#[tokio::test]
async fn absolute_form_on_an_open_proxy_skips_the_probe_after_the_first_time() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = http("plain.test");
    let request = Request::new(&dest, Form::Absolute, &[]).name_ok(true);
    let first = chain.connect(&request).await.unwrap();
    assert_eq!(first.authorization, None);
    let _second = chain.connect(&request).await.unwrap();
    let probes = proxy.seen().iter().filter(|s| s.method == "HEAD").count();
    assert_eq!(probes, 1, "an open proxy is probed once per network epoch");
}

#[tokio::test]
async fn absolute_form_ntlm_authenticates_the_connection_with_no_header_per_request() {
    let proxy = FakeProxy::start(Behaviour::Ntlm).await;
    let chain = chain(vec![via(&proxy)], Arc::new(NtlmAuth));
    let dest = http("plain.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Absolute, &[]).name_ok(true))
        .await
        .unwrap();
    assert!(connected.authorization.is_none());
    connected
        .stream
        .write_all(
            b"GET http://plain.test:80/ HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut body = String::new();
    connected.stream.read_to_string(&mut body).await.unwrap();
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert_eq!(proxy.connections(), 1);
}

#[tokio::test]
async fn the_auth_list_lets_basic_answer_when_the_first_member_does_not_speak_the_scheme() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "u".into(),
        password: "p".into(),
    })
    .await;
    let list = AuthList::new().with(Arc::new(NtlmAuth)).with(Arc::new(
        BasicAuth::new().with_default(Credentials::new("u", "p")),
    ));
    let chain = chain(vec![via(&proxy)], Arc::new(list));
    let echo = start_echo().await;
    proxy.resolve_name("list.test", echo.addr);
    let dest = https("list.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    round_trip(&mut connected.stream, b"x").await;
}

#[tokio::test]
async fn host_side_connections_use_the_same_route_and_let_the_proxy_resolve_unknown_names() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("telemetry.nowhere.invalid", echo.addr);
    let chain = chain(vec![via(&proxy)], Arc::new(puddle_upstream::NoAuth));
    let dest = https("telemetry.nowhere.invalid");
    let mut connected = puddle_upstream::host::connect(&chain, &dest, Form::Tunnel)
        .await
        .unwrap();
    round_trip(&mut connected.stream, b"host side").await;
    assert_eq!(proxy.seen()[0].target, "telemetry.nowhere.invalid:443");
}

/// Signs in with Negotiate before any challenge, like Kerberos does.
#[derive(Debug)]
struct PreemptiveNegotiate;

#[derive(Debug)]
struct NegotiateSession;

impl AuthSession for NegotiateSession {
    fn step(&mut self, _challenge: Option<&str>) -> Result<AuthStep, AuthError> {
        Ok(AuthStep::Authorization("Negotiate tok".into()))
    }
}

impl ProxyAuth for PreemptiveNegotiate {
    fn begin(
        &self,
        _proxy: &ProxyAddr,
        offered: &[&str],
    ) -> Result<Option<Box<dyn AuthSession>>, AuthError> {
        Ok(
            (offered.is_empty() || offered.iter().any(|s| s.eq_ignore_ascii_case("negotiate")))
                .then(|| Box::new(NegotiateSession) as Box<dyn AuthSession>),
        )
    }
}

#[tokio::test]
async fn a_preemptive_negotiate_meets_a_basic_only_proxy_and_falls_back_on_the_same_request() {
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "u".into(),
        password: "p".into(),
    })
    .await;
    proxy.resolve_name("basic.test", echo.addr);
    let list = AuthList::new()
        .with(Arc::new(PreemptiveNegotiate))
        .with(Arc::new(
            BasicAuth::new().with_default(Credentials::new("u", "p")),
        ));
    let chain = chain(vec![via(&proxy)], Arc::new(list));
    let dest = https("basic.test");
    let mut connected = chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    round_trip(&mut connected.stream, b"first request").await;
    let seen = proxy.seen();
    let auth: Vec<_> = seen
        .iter()
        .map(|s| {
            s.proxy_authorization
                .as_deref()
                .map(|a| a.split(' ').next().unwrap())
        })
        .collect();
    assert_eq!(auth, [Some("Negotiate"), Some("Basic")]);
}

#[tokio::test]
async fn the_last_sign_in_to_each_proxy_is_kept_without_its_secrets() {
    use puddle_upstream::SignInOutcome;
    let echo = start_echo().await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "t188".into(),
        password: "pw-right".into(),
    })
    .await;
    proxy.resolve_name("a.test", echo.addr);
    let dest = https("a.test");
    let request = Request::new(&dest, Form::Tunnel, &[]).name_ok(true);

    let chain = chain(vec![via(&proxy)], basic("t188", "pw-right"));
    assert_eq!(chain.auth_methods(), ["basic"]);
    assert_eq!(chain.sign_ins().len(), 0);
    chain.connect(&request).await.unwrap();
    let kept = chain.sign_ins();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].proxy, proxy.proxy_addr());
    assert_eq!(kept[0].scheme.as_deref(), Some("Basic"));
    assert_eq!(kept[0].outcome, SignInOutcome::SignedIn);
    // The second connection sends the credential up front and is still a sign-in with Basic.
    chain.connect(&request).await.unwrap();
    assert_eq!(chain.sign_ins()[0].scheme.as_deref(), Some("Basic"));

    let wrong = self::chain(vec![via(&proxy)], basic("t188", "pw-wrong"));
    wrong.connect(&request).await.unwrap_err();
    let kept = wrong.sign_ins();
    assert_eq!(kept[0].outcome, SignInOutcome::Failed);
    let shown = format!("{:?}", kept[0]);
    assert!(
        !shown.contains("pw-wrong") && !shown.contains("pw-right"),
        "{shown}"
    );

    let none = self::chain(vec![via(&proxy)], Arc::new(BasicAuth::new()));
    none.connect(&request).await.unwrap_err();
    let kept = none.sign_ins();
    assert_eq!(kept[0].outcome, SignInOutcome::Unsupported);
    assert!(kept[0].detail.as_deref().unwrap().contains("Basic"));
}

#[tokio::test]
async fn an_open_proxy_is_recorded_as_needing_no_sign_in_and_a_dead_one_is_not_recorded() {
    use puddle_upstream::SignInOutcome;
    let echo = start_echo().await;
    let open = FakeProxy::start(Behaviour::Open).await;
    open.resolve_name("a.test", echo.addr);
    let (dead, _socket) = dead_port();
    let chain = chain(
        vec![Hop::Proxy(dead.clone()), via(&open)],
        Arc::new(puddle_upstream::NoAuth),
    );
    assert_eq!(chain.auth_methods().len(), 0);
    let dest = https("a.test");
    chain
        .connect(&Request::new(&dest, Form::Tunnel, &[]).name_ok(true))
        .await
        .unwrap();
    let kept = chain.sign_ins();
    assert_eq!(
        kept.len(),
        1,
        "an unreachable proxy says nothing about sign-in"
    );
    assert_eq!(kept[0].proxy, open.proxy_addr());
    assert_eq!(kept[0].outcome, SignInOutcome::NotRequired);
    assert_eq!(kept[0].scheme, None);
}

#[tokio::test]
async fn a_list_names_the_methods_of_its_members_once() {
    let list = AuthList::new()
        .with(basic("u", "p"))
        .with(basic("v", "q"))
        .with(Arc::new(puddle_upstream::NoAuth));
    assert_eq!(list.methods(), ["basic"]);
}
