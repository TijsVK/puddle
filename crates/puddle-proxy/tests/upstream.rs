// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests of upstream chaining: the workspace proxy and the pull proxy send admitted
//! connections out along a company-proxy route, against a scripted proxy on loopback. The hostile
//! cases pin what chaining must never change: the rules, the address guard and the IP rules run
//! first, and no hop is ever contacted for a request admission refused.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
mod pull_support;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures_util::StreamExt;
use puddle_agent_proto::tokio_yamux::{Control, Session, StreamHandle};
use puddle_agent_proto::yamux::client_config;
use puddle_ipc::IpcRoot;
use puddle_netpolicy::PuddleEndpoints;
use puddle_proxy::testing::{AnyAddress, CollectingConnectionLog, StaticPolicy, StaticResolver};
use puddle_proxy::{Proxy, PullProxy, Route, Upstream};
use puddle_types::{ConnectionEvent, Host, NullSink, WorkspaceName};
use puddle_upstream::{
    BasicAuth, Behaviour, Chain, ChainConfig, Config, Credentials, Discovery, FakeOs, FakeProxy,
    Hop, NoAuth, ProxyAddr, ProxyAuth, ProxyConfig,
};
use pull_support::{LOCAL, echo};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A discovery whose PAC answers `hops` for every URL; the fake OS is returned to count calls.
fn discovery(hops: Vec<Hop>) -> (Arc<Discovery>, Arc<FakeOs>) {
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..ProxyConfig::default()
    });
    os.set_pac(move |_| Ok(hops.clone()));
    (Discovery::new(os.clone(), Config::default()), os)
}

fn upstream(hops: Vec<Hop>, auth: Arc<dyn ProxyAuth>) -> (Upstream, Arc<FakeOs>) {
    let (discovery, os) = discovery(hops);
    let config = ChainConfig::default()
        .with_timeouts(Duration::from_millis(500), Duration::from_millis(400));
    (
        Upstream::new(Chain::with_config(discovery, auth, config)),
        os,
    )
}

fn via(proxy: &FakeProxy) -> Hop {
    Hop::Proxy(proxy.proxy_addr())
}

fn basic(user: &str, password: &str) -> Arc<dyn ProxyAuth> {
    Arc::new(BasicAuth::new().with_default(Credentials::new(user, password)))
}

/// A proxy address nothing answers on. The socket is bound but never listens, so the port stays
/// ours (a released port could be taken by another test's server) and connecting is refused.
fn dead_proxy() -> (ProxyAddr, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    (ProxyAddr::new("127.0.0.1", port), socket)
}

/// The workspace proxy with one route, an in-memory policy and a connection log.
struct Rig {
    policy: Arc<StaticPolicy>,
    log: Arc<CollectingConnectionLog>,
    route: Route,
    _root: IpcRoot,
}

impl Rig {
    fn new(
        resolver: StaticResolver,
        upstream: Upstream,
        check: Option<Arc<dyn puddle_proxy::AddressCheck>>,
    ) -> Self {
        let policy = Arc::new(StaticPolicy::new());
        let log = Arc::new(CollectingConnectionLog::new());
        let proxy = Proxy::new(policy.clone(), Arc::new(NullSink))
            .with_connection_log(log.clone())
            .with_resolver(Arc::new(resolver))
            .with_address_check(check.unwrap_or_else(|| Arc::new(AnyAddress)))
            .with_upstream(upstream);
        let root = IpcRoot::new().unwrap();
        let route =
            Arc::new(proxy).serve_route(root.listen().unwrap(), WorkspaceName::new("box").unwrap());
        Self {
            policy,
            log,
            route,
            _root: root,
        }
    }

    async fn guest(&self) -> Guest {
        let conn = puddle_ipc::connect(self.route.endpoint().path())
            .await
            .unwrap();
        let mut session = Session::new_client(conn, client_config());
        let control = session.control();
        let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
        Guest { control, driver }
    }

    async fn events(&self, count: usize) -> Vec<ConnectionEvent> {
        let events = self.log.wait_for(count, Duration::from_secs(5)).await;
        assert!(events.len() >= count, "{count} events expected: {events:?}");
        events
    }
}

struct Guest {
    control: Control,
    driver: JoinHandle<()>,
}

impl Drop for Guest {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Guest {
    async fn request(&mut self, text: &str) -> (u16, Vec<String>, BufReader<StreamHandle>) {
        let mut stream = self.control.open_stream().await.unwrap();
        stream.write_all(text.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(stream);
        let (code, headers) = response_head(&mut reader).await.unwrap();
        (code, headers, reader)
    }

    async fn connect_to(&mut self, authority: &str) -> (u16, Vec<String>, BufReader<StreamHandle>) {
        self.request(&format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        ))
        .await
    }
}

async fn response_head<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> io::Result<(u16, Vec<String>)> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let code = line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other(format!("bad status line {line:?}")))?;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await?;
        if h == "\r\n" || h.is_empty() {
            return Ok((code, headers));
        }
        headers.push(h.trim_end().to_ascii_lowercase());
    }
}

fn header<'a>(headers: &'a [String], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|h| h.strip_prefix(&format!("{name}:")))
        .map(str::trim)
}

async fn echo_through<R: AsyncRead + AsyncWriteExt + Unpin>(
    stream: &mut BufReader<R>,
    text: &[u8],
) {
    stream.write_all(text).await.unwrap();
    let mut back = vec![0_u8; text.len()];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, text);
}

async fn read_to_end<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> String {
    let mut out = String::new();
    let _ = reader.read_to_string(&mut out).await;
    out
}

// ---- the happy paths ----

#[tokio::test]
async fn connect_goes_through_the_company_proxy_and_the_audit_names_the_hop() {
    let server = echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("site.test", server.addr);
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new().with("site.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("site.test"));
    let mut guest = rig.guest().await;
    let (code, _, mut tunnel) = guest
        .connect_to(&format!("site.test:{}", server.addr.port()))
        .await;
    assert_eq!(code, 200);
    echo_through(&mut tunnel, b"through the company proxy").await;
    drop(tunnel);
    assert_eq!(
        proxy.seen()[0].target,
        format!("site.test:{}", server.addr.port()),
        "a proxy is told the name when every address passed"
    );
    let events = rig.events(1).await;
    assert_eq!(
        events[0].upstream.as_deref(),
        Some(format!("PROXY {}", proxy.proxy_addr()).as_str())
    );
    assert_eq!(events[0].resolved_ip, None);
}

#[tokio::test]
async fn absolute_form_goes_through_the_company_proxy() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new().with("plain.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("plain.test"));
    let mut guest = rig.guest().await;
    let (code, _, mut body) = guest
        .request("GET http://plain.test:8080/a/b?q=1 HTTP/1.1\r\nHost: plain.test:8080\r\n\r\n")
        .await;
    assert_eq!(code, 200);
    assert_eq!(
        read_to_end(&mut body).await,
        "via-proxy http://plain.test:8080/a/b?q=1"
    );
    let get = proxy
        .seen()
        .into_iter()
        .find(|s| s.method == "GET")
        .unwrap();
    assert_eq!(get.target, "http://plain.test:8080/a/b?q=1");
    let events = rig.events(1).await;
    assert!(events[0].upstream.as_deref().unwrap().starts_with("PROXY "));
}

#[tokio::test]
async fn a_407_from_the_company_proxy_is_answered_with_the_configured_credentials() {
    let server = echo().await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "alice".into(),
        password: "CANARY-s3cret".into(),
    })
    .await;
    proxy.resolve_name("site.test", server.addr);
    let (up, _) = upstream(vec![via(&proxy)], basic("alice", "CANARY-s3cret"));
    let rig = Rig::new(StaticResolver::new().with("site.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("site.test"));
    let mut guest = rig.guest().await;

    let (code, headers, mut tunnel) = guest
        .connect_to(&format!("site.test:{}", server.addr.port()))
        .await;
    assert_eq!(code, 200);
    echo_through(&mut tunnel, b"signed in").await;
    let leaked = headers.join("\n");
    assert!(
        !leaked.contains("authorization") && !leaked.contains("CANARY"),
        "{leaked}"
    );
    drop(tunnel);

    // Plain HTTP on the same proxy: probe, credential, request carrying Basic.
    let (code, _, body) = guest
        .request("GET http://plain.test:80/x HTTP/1.1\r\nHost: plain.test\r\n\r\n")
        .await;
    assert_eq!(
        code, 403,
        "plain.test is not allowed yet: the rules said no first"
    );
    drop(body);
    rig.policy.allow(&host("plain.test"));
    let (code, _, mut body) = guest
        .request("GET http://plain.test:80/x HTTP/1.1\r\nHost: plain.test\r\n\r\n")
        .await;
    assert_eq!(code, 200);
    assert!(
        read_to_end(&mut body)
            .await
            .ends_with("via-proxy http://plain.test:80/x")
    );
    let get = proxy
        .seen()
        .into_iter()
        .find(|s| s.method == "GET")
        .unwrap();
    assert!(
        get.proxy_authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
}

#[tokio::test]
async fn no_configured_credentials_is_a_502_that_says_so_and_does_not_name_the_proxy() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "u".into(),
        password: "p".into(),
    })
    .await;
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(BasicAuth::new()));
    let rig = Rig::new(StaticResolver::new().with("site.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("site.test"));
    let mut guest = rig.guest().await;
    let (code, headers, mut body) = guest.connect_to("site.test:443").await;
    assert_eq!(code, 502);
    assert_eq!(
        header(&headers, "x-puddle-blocked-by"),
        Some("upstream-auth")
    );
    let text = read_to_end(&mut body).await;
    assert!(text.contains("Basic"), "{text}");
    assert!(!text.contains(&proxy.addr().port().to_string()), "{text}");
}

#[tokio::test]
async fn a_refusal_from_the_company_proxy_is_passed_on_and_never_retried_direct() {
    let direct = echo().await;
    let proxy = FakeProxy::start(Behaviour::Refuse(403)).await;
    let (up, _) = upstream(vec![via(&proxy), Hop::Direct], Arc::new(NoAuth));
    let rig = Rig::new(
        StaticResolver::new().with("blocked.test", &[LOCAL]),
        up,
        None,
    );
    rig.policy.allow(&host("blocked.test"));
    let mut guest = rig.guest().await;
    let (code, headers, _) = guest
        .connect_to(&format!("blocked.test:{}", direct.addr.port()))
        .await;
    assert_eq!(code, 403);
    assert_eq!(header(&headers, "x-puddle-blocked-by"), Some("upstream"));
    assert_eq!(
        direct.accepted.load(Ordering::SeqCst),
        0,
        "no silent DIRECT after a refusal"
    );
}

#[tokio::test]
async fn a_dead_proxy_falls_through_to_direct_which_uses_only_the_checked_address() {
    let server = echo().await;
    let (dead, _held) = dead_proxy();
    let (up, _) = upstream(vec![Hop::Proxy(dead), Hop::Direct], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new().with("site.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("site.test"));
    let mut guest = rig.guest().await;
    let (code, headers, mut tunnel) = guest
        .connect_to(&format!("site.test:{}", server.addr.port()))
        .await;
    assert_eq!(code, 200, "{headers:?} {}", read_to_end(&mut tunnel).await);
    echo_through(&mut tunnel, b"direct after a dead hop").await;
    drop(tunnel);
    let events = rig.events(1).await;
    assert_eq!(events[0].upstream.as_deref(), Some("DIRECT"));
    assert_eq!(events[0].resolved_ip, Some(LOCAL));
}

#[tokio::test]
async fn a_name_only_the_company_proxy_can_resolve_goes_by_name_after_the_rules_say_yes() {
    let server = echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("wiki.corp.test", server.addr);
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new(), up, None);
    let authority = format!("wiki.corp.test:{}", server.addr.port());

    // Not allowed: refused by the rules before the proxy is involved.
    let mut guest = rig.guest().await;
    let (code, headers, _) = guest.connect_to(&authority).await;
    assert_eq!(code, 403);
    assert_eq!(header(&headers, "x-puddle-decision"), Some("pending"));
    assert_eq!(proxy.connections(), 0);

    rig.policy.allow(&host("wiki.corp.test"));
    let (code, _, mut tunnel) = guest.connect_to(&authority).await;
    assert_eq!(code, 200);
    echo_through(&mut tunnel, b"split dns").await;
    drop(tunnel);
    let events = rig.events(2).await;
    let last = events.last().unwrap();
    assert_eq!(
        last.resolved_ip, None,
        "nothing was resolved here to record"
    );
    assert!(last.upstream.as_deref().unwrap().starts_with("PROXY "));
}

#[tokio::test]
async fn unresolvable_names_stay_a_502_when_resolving_via_the_upstream_is_off() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(
        StaticResolver::new(),
        up.with_resolve_via_upstream(false),
        None,
    );
    rig.policy.allow(&host("wiki.corp.test"));
    let mut guest = rig.guest().await;
    let (code, _, _) = guest.connect_to("wiki.corp.test:443").await;
    assert_eq!(code, 502);
    assert_eq!(proxy.connections(), 0);
}

// ---- hostile guest ----

/// A guard that blocks loopback like production does, but only in the name stage and per address.
fn production_check() -> Arc<dyn puddle_proxy::AddressCheck> {
    Arc::new(puddle_netpolicy::NetPolicy::new(Arc::new(
        puddle_netpolicy::LocalAccess::NONE,
    )))
}

#[tokio::test]
async fn hostile_a_name_that_resolves_to_a_local_address_never_reaches_any_hop() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, os) = upstream(vec![via(&proxy), Hop::Direct], Arc::new(NoAuth));
    let rig = Rig::new(
        StaticResolver::new().with("rebind.test", &[ip("127.0.0.1")]),
        up,
        Some(production_check()),
    );
    rig.policy.allow(&host("rebind.test"));
    let mut guest = rig.guest().await;
    let (code, headers, _) = guest.connect_to("rebind.test:443").await;
    assert_eq!(code, 403);
    assert_eq!(header(&headers, "x-puddle-decision"), Some("blocked"));
    assert_eq!(
        proxy.connections(),
        0,
        "the guard runs before the route is asked"
    );
    assert_eq!(os.pac_calls(), 0, "not even discovery ran");
    assert_eq!(rig.events(1).await[0].upstream, None);
}

#[tokio::test]
async fn hostile_a_literal_metadata_address_is_blocked_before_the_route_is_asked() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, os) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new(), up, Some(production_check()));
    let mut guest = rig.guest().await;
    for target in ["169.254.169.254:80", "[fd00:ec2::254]:80", "10.0.0.5:22"] {
        let (code, headers, _) = guest.connect_to(target).await;
        assert_eq!(code, 403, "{target}");
        assert!(header(&headers, "x-puddle-blocked").is_some(), "{target}");
    }
    let (code, _, _) = guest
        .request("GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    assert_eq!(code, 403);
    assert_eq!(proxy.connections(), 0);
    assert_eq!(os.pac_calls(), 0);
}

#[tokio::test]
async fn hostile_an_ip_deny_rule_beats_the_proxy_the_proxy_never_gets_the_name_or_the_address() {
    // `mixed.test` resolves to a denied address (127.0.0.2, R-27) and an allowed one (127.0.0.1).
    // The company proxy would resolve the name to the denied one if it were told the name.
    let secret = TcpListener::bind("127.0.0.2:0").await;
    let Ok(secret) = secret else {
        eprintln!("skipped: 127.0.0.2 is not available here");
        return;
    };
    let secret_addr = secret.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    tokio::spawn(async move {
        while secret.accept().await.is_ok() {
            count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let allowed = echo().await;
    let proxy = FakeProxy::start(Behaviour::Open).await;
    proxy.resolve_name("mixed.test", secret_addr);
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(
        StaticResolver::new().with("mixed.test", &[ip("127.0.0.2"), ip("127.0.0.1")]),
        up,
        None,
    );
    rig.policy.allow(&host("mixed.test"));
    rig.policy.deny_host(&host("127.0.0.2"));
    let mut guest = rig.guest().await;
    let (code, _, mut tunnel) = guest
        .connect_to(&format!("mixed.test:{}", allowed.addr.port()))
        .await;
    assert_eq!(code, 200);
    echo_through(&mut tunnel, b"only the allowed address").await;
    drop(tunnel);
    let target = &proxy.seen()[0].target;
    assert_eq!(
        *target,
        allowed.addr.to_string(),
        "an address, not the name"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the denied address was never contacted"
    );
    assert_eq!(rig.events(1).await[0].resolved_ip, Some(ip("127.0.0.1")));
}

#[tokio::test]
async fn hostile_when_every_address_is_ip_denied_no_hop_is_contacted() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, os) = upstream(vec![via(&proxy), Hop::Direct], Arc::new(NoAuth));
    let rig = Rig::new(
        StaticResolver::new().with("denied.test", &[ip("127.0.0.2")]),
        up,
        None,
    );
    rig.policy.allow(&host("denied.test"));
    rig.policy.deny_host(&host("127.0.0.2"));
    let mut guest = rig.guest().await;
    let (code, headers, _) = guest.connect_to("denied.test:443").await;
    assert_eq!(code, 403);
    assert_eq!(header(&headers, "x-puddle-decision"), Some("deny"));
    assert_eq!(proxy.connections(), 0);
    assert_eq!(os.pac_calls(), 0);
}

#[tokio::test]
async fn hostile_a_guest_cannot_supply_proxy_credentials_or_a_second_request() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, _) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = Rig::new(StaticResolver::new().with("plain.test", &[LOCAL]), up, None);
    rig.policy.allow(&host("plain.test"));
    let mut guest = rig.guest().await;
    let (code, _, mut body) = guest
        .request(concat!(
            "GET http://plain.test/one HTTP/1.1\r\n",
            "Host: elsewhere.test\r\n",
            "Proxy-Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "\r\n",
            "GET http://plain.test/two HTTP/1.1\r\nHost: plain.test\r\n\r\n",
        ))
        .await;
    assert_eq!(code, 200);
    let _ = read_to_end(&mut body).await;
    let gets: Vec<_> = proxy
        .seen()
        .into_iter()
        .filter(|s| s.method == "GET")
        .collect();
    assert_eq!(gets.len(), 1, "the pipelined request was dropped");
    assert_eq!(gets[0].target, "http://plain.test:80/one");
    assert_eq!(
        gets[0].proxy_authorization, None,
        "the guest's credential is not forwarded"
    );
    let host_header = gets[0].headers.iter().find(|(n, _)| n == "host").unwrap();
    assert_eq!(host_header.1, "plain.test", "Host is the checked target");
}

#[tokio::test]
async fn hostile_a_hostile_company_proxy_cannot_hang_or_loop_the_workspace_proxy() {
    for behaviour in [Behaviour::Garbage, Behaviour::Silent, Behaviour::Always407] {
        let proxy = FakeProxy::start(behaviour).await;
        let (up, _) = upstream(vec![via(&proxy)], basic("u", "p"));
        let rig = Rig::new(StaticResolver::new().with("site.test", &[LOCAL]), up, None);
        rig.policy.allow(&host("site.test"));
        let mut guest = rig.guest().await;
        let (code, _, _) =
            tokio::time::timeout(Duration::from_secs(10), guest.connect_to("site.test:443"))
                .await
                .expect("the proxy must answer in bounded time");
        assert_eq!(code, 502);
        // And it still serves the next request.
        let (code, _, _) = guest.connect_to("site.test:443").await;
        assert_eq!(code, 502);
    }
}

// ---- the pull proxy ----

struct PullRig {
    route: puddle_proxy::PullRoute,
    credentials: String,
    log: Arc<CollectingConnectionLog>,
}

fn pull_rig(resolver: StaticResolver, upstream: Upstream) -> PullRig {
    let log = Arc::new(CollectingConnectionLog::new());
    let proxy = PullProxy::bind(&PuddleEndpoints::new())
        .unwrap()
        .with_resolver(Arc::new(resolver))
        .with_upstream(upstream)
        .with_connection_log(log.clone());
    let credentials = BASE64.encode(format!("puddle:{}", proxy.token().expose()));
    PullRig {
        route: proxy.serve().unwrap(),
        credentials,
        log,
    }
}

async fn pull_connect(rig: &PullRig, target: &str) -> (String, tokio::net::TcpStream) {
    pull_support::send(
        rig.route.local_addr(),
        &pull_support::connect(target, Some(&format!("Basic {}", rig.credentials))),
    )
    .await
}

#[tokio::test]
async fn pulls_go_through_the_company_proxy_with_basic_auth_and_unknown_names_resolve_there() {
    let server = echo().await;
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "alice".into(),
        password: "s3cret".into(),
    })
    .await;
    proxy.resolve_name("registry.corp.test", server.addr);
    let (up, _) = upstream(vec![via(&proxy)], basic("alice", "s3cret"));
    // The registry name is unknown to this host's resolver: only the company proxy has it.
    let rig = pull_rig(StaticResolver::new(), up);
    let target = format!("registry.corp.test:{}", server.addr.port());
    let (head, mut stream) = pull_connect(&rig, &target).await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    stream.write_all(b"layer bytes").await.unwrap();
    let mut back = [0_u8; 11];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"layer bytes");
    // The audit names the hop that carried the pull, never its credential.
    drop(stream);
    let events = rig.log.wait_for(1, Duration::from_secs(5)).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].origin, puddle_types::ConnectionOrigin::Puddle);
    assert_eq!(
        events[0].upstream,
        Some(format!("PROXY {}", proxy.proxy_addr()))
    );
    assert!(!format!("{events:?}").contains("s3cret"));
    let seen = proxy.seen();
    assert_eq!(seen.len(), 2, "one 407, then the credential");
    assert_eq!(seen[1].target, target);
    // The pull token is the pull proxy's own and never goes upstream.
    assert!(!format!("{seen:?}").contains(&rig.credentials));
}

#[tokio::test]
async fn pulls_still_need_the_token_and_the_guard_before_any_hop() {
    let proxy = FakeProxy::start(Behaviour::Open).await;
    let (up, os) = upstream(vec![via(&proxy)], Arc::new(NoAuth));
    let rig = pull_rig(
        StaticResolver::new().with("meta.test", &[ip("169.254.169.254")]),
        up,
    );
    let (head, _) = pull_support::send(
        rig.route.local_addr(),
        &pull_support::connect("registry.test:443", None),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    let (head, _) = pull_connect(&rig, "meta.test:80").await;
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    let (head, _) = pull_connect(&rig, "169.254.169.254:80").await;
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    assert_eq!(proxy.connections(), 0);
    assert_eq!(os.pac_calls(), 0);
}

#[tokio::test]
async fn pulls_fall_back_from_a_dead_proxy_to_direct_with_a_checked_address() {
    let server = echo().await;
    let (dead, _held) = dead_proxy();
    let (up, _) = upstream(vec![Hop::Proxy(dead), Hop::Direct], Arc::new(NoAuth));
    let rig = pull_rig(StaticResolver::new().with("registry.test", &[LOCAL]), up);
    let (head, mut stream) =
        pull_connect(&rig, &format!("registry.test:{}", server.addr.port())).await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    stream.write_all(b"x").await.unwrap();
    let mut back = [0_u8; 1];
    stream.read_exact(&mut back).await.unwrap();
}

#[tokio::test]
async fn plain_http_pulls_carry_the_proxy_credential_not_the_pull_token() {
    let proxy = FakeProxy::start(Behaviour::Basic {
        user: "alice".into(),
        password: "s3cret".into(),
    })
    .await;
    let (up, _) = upstream(vec![via(&proxy)], basic("alice", "s3cret"));
    let rig = pull_rig(StaticResolver::new().with("mirror.test", &[LOCAL]), up);
    let (head, mut stream) = pull_support::send(
        rig.route.local_addr(),
        &format!(
            "GET http://mirror.test:8081/v2/ HTTP/1.1\r\nHost: mirror.test\r\nProxy-Authorization: Basic {}\r\n\r\n",
            rig.credentials
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    let mut body = String::new();
    stream.read_to_string(&mut body).await.unwrap();
    assert!(
        body.ends_with("via-proxy http://mirror.test:8081/v2/"),
        "{body}"
    );
    let get = proxy
        .seen()
        .into_iter()
        .find(|s| s.method == "GET")
        .unwrap();
    let sent = get.proxy_authorization.unwrap();
    assert_ne!(sent, format!("Basic {}", rig.credentials));
    assert_eq!(sent, format!("Basic {}", BASE64.encode("alice:s3cret")));
}
