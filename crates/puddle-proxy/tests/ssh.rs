// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests for SSH from a workspace: every SSH connection is refused at once, whatever the host
//! and port, with the reason `ssh_unsupported`; it never reaches the rules, the inbox or the
//! resolver, and nothing of it reaches a server. A fake guest (yamux client) on a real
//! per-workspace endpoint, the real proxy behind it.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::StreamExt;
use puddle_agent_proto::tokio_yamux::{Control, Session, StreamHandle};
use puddle_agent_proto::yamux::client_config;
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, CollectingConnectionLog, StaticPolicy, StaticResolver};
use puddle_proxy::{BoxFuture, Proxy, Resolver, Route};
use puddle_types::{
    BlockReason, ConnectionDecision, ConnectionEvent, ConnectionReason, Host, NullSink,
    WorkspaceName,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const BANNER: &[u8] = b"SSH-2.0-OpenSSH_10.0p2 Debian-7\r\n";

fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

struct Rig {
    policy: Arc<StaticPolicy>,
    resolver: Arc<StaticResolver>,
    log: Arc<CollectingConnectionLog>,
    route: Route,
    _root: IpcRoot,
}

impl Rig {
    /// Loopback servers are reachable (`AnyAddress`), and `names` resolve to loopback.
    fn new(names: &[&str]) -> Self {
        Self::build(names, true)
    }

    /// The default address check: loopback is blocked until its toggle is on.
    fn with_default_guard() -> Self {
        Self::build(&[], false)
    }

    fn build(names: &[&str], any_address: bool) -> Self {
        let policy = Arc::new(StaticPolicy::new());
        let log = Arc::new(CollectingConnectionLog::new());
        let resolver = names
            .iter()
            .fold(StaticResolver::new(), |r, n| r.with(n, &[LOCAL]));
        let resolver = Arc::new(resolver);
        let mut proxy = Proxy::new(policy.clone(), Arc::new(NullSink))
            .with_connection_log(log.clone())
            .with_resolver(resolver.clone());
        if any_address {
            proxy = proxy.with_address_check(Arc::new(AnyAddress));
        }
        let proxy = Arc::new(proxy);
        let root = IpcRoot::new().unwrap();
        let route = proxy.serve_route(root.listen().unwrap(), WorkspaceName::new("box").unwrap());
        Self {
            policy,
            resolver,
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
    /// Sends `bytes` on a new stream and reads the answer to its end.
    async fn exchange(&mut self, bytes: &[u8]) -> String {
        let mut stream = self.control.open_stream().await.unwrap();
        stream.write_all(bytes).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
            .await
            .expect("the proxy ends the connection")
            .unwrap();
        String::from_utf8_lossy(&answer).into_owned()
    }

    /// `CONNECT` to `authority`, with the header a `connect` command sets once it saw a banner.
    async fn announce(&mut self, authority: &str) -> String {
        self.exchange(connect(authority, &["x-puddle-protocol: ssh"]).as_bytes())
            .await
    }

    /// Opens a tunnel to `authority`; the stream is positioned after the `200`.
    async fn tunnel(&mut self, authority: &str) -> StreamHandle {
        let mut stream = self.control.open_stream().await.unwrap();
        stream
            .write_all(connect(authority, &[]).as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.extend_from_slice(&byte);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        stream
    }
}

fn connect(authority: &str, headers: &[&str]) -> String {
    let mut head = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    for header in headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head
}

/// A server that records what it receives and answers nothing.
struct Silent {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<u8>>>,
    connections: Arc<Mutex<u32>>,
}

impl Silent {
    async fn start() -> Self {
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(Mutex::new(0));
        let (r, c) = (received.clone(), connections.clone());
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = listener.accept().await.unwrap();
                *c.lock().unwrap_or_else(PoisonError::into_inner) += 1;
                let r = r.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = conn.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        r.lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .extend_from_slice(buf.get(..n).unwrap_or_default());
                    }
                });
            }
        });
        Self {
            addr,
            received,
            connections,
        }
    }

    fn received(&self) -> Vec<u8> {
        self.received
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn connections(&self) -> u32 {
        *self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Every event of an SSH refusal says the same, and none of them is a rule or a pending row.
fn assert_ssh_refusals(events: &[ConnectionEvent], count: usize) {
    assert_eq!(events.len(), count, "{events:?}");
    for event in events {
        assert_eq!(event.decision, ConnectionDecision::Blocked, "{event:?}");
        assert_eq!(
            event.reason,
            ConnectionReason::Blocked(BlockReason::SshUnsupported),
            "{event:?}"
        );
        assert_eq!(event.pending_id, None, "{event:?}");
    }
}

#[tokio::test]
async fn an_announced_ssh_connect_is_refused_for_any_host_and_port_before_any_rule() {
    let rig = Rig::new(&[]);
    // A rule that would allow the host does not matter: SSH is refused before the rules.
    rig.policy.allow(&host("github.com"));
    let mut guest = rig.guest().await;
    let authorities = [
        "github.com:22",
        "ssh.github.com:443",
        "gitlab.com:22",
        "bitbucket.org:22",
        "ssh.dev.azure.com:22",
        "vs-ssh.visualstudio.com:22",
        "git.example.test:2222",
        "nas.example.test:22",
        "[2001:db8::1]:22",
        "203.0.113.7:22",
    ];
    for authority in authorities {
        let answer = guest.announce(authority).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "{authority}: {answer}");
        assert!(
            answer.contains("x-puddle-decision: blocked\r\n")
                && answer.contains("x-puddle-blocked: ssh_unsupported\r\n"),
            "{authority}: {answer}"
        );
        assert!(
            answer.contains("puddle: SSH is not supported yet"),
            "{authority}: {answer}"
        );
    }
    assert_eq!(rig.policy.decisions(), 0, "the rules were never asked");
    assert_eq!(rig.policy.pending().len(), 0, "nothing in the inbox");
    assert_eq!(rig.resolver.lookups(), 0, "nothing was resolved");
    assert_ssh_refusals(&rig.events(authorities.len()).await, authorities.len());
}

#[tokio::test]
async fn the_refusal_gives_the_https_form_of_a_known_git_hosts_remote_and_no_other() {
    let rig = Rig::new(&[]);
    let mut guest = rig.guest().await;
    for (authority, https) in [
        ("github.com:22", "https://github.com/OWNER/REPO.git"),
        ("ssh.github.com:443", "https://github.com/OWNER/REPO.git"),
        ("gitlab.com:22", "https://gitlab.com/GROUP/PROJECT.git"),
        (
            "bitbucket.org:22",
            "https://bitbucket.org/WORKSPACE/REPO.git",
        ),
        (
            "ssh.dev.azure.com:22",
            "https://dev.azure.com/ORGANIZATION/PROJECT/_git/REPO",
        ),
        (
            "vs-ssh.visualstudio.com:22",
            "https://dev.azure.com/ORGANIZATION/PROJECT/_git/REPO",
        ),
    ] {
        let answer = guest.announce(authority).await;
        assert!(
            answer.ends_with(&format!(
                "puddle: SSH is not supported yet, use HTTPS: the remote becomes {https}\n"
            )),
            "{authority}: {answer}"
        );
    }
    let answer = guest.announce("git.example.test:22").await;
    assert!(
        answer.ends_with("puddle: SSH is not supported yet; no rule or setting allows it\n"),
        "{answer}"
    );
}

#[tokio::test]
async fn the_banner_sent_with_the_connect_is_enough_and_the_header_is_not_case_sensitive() {
    let rig = Rig::new(&[]);
    let mut guest = rig.guest().await;
    let mut early = connect("ssh.github.com:443", &[]).into_bytes();
    early.extend_from_slice(BANNER);
    let answer = guest.exchange(&early).await;
    assert!(
        answer.starts_with("HTTP/1.1 403") && answer.contains("x-puddle-blocked: ssh_unsupported"),
        "{answer}"
    );
    let answer = guest
        .exchange(connect("github.com:22", &["X-Puddle-Protocol:  SSH "]).as_bytes())
        .await;
    assert!(
        answer.contains("x-puddle-blocked: ssh_unsupported"),
        "{answer}"
    );
    assert_eq!(rig.policy.decisions(), 0);
    assert_eq!(rig.policy.pending().len(), 0);
    assert_ssh_refusals(&rig.events(2).await, 2);
}

#[tokio::test]
async fn ssh_to_an_address_whose_toggle_is_off_is_the_ssh_refusal_not_a_toggle_refusal() {
    let rig = Rig::with_default_guard();
    let mut guest = rig.guest().await;
    for authority in ["127.0.0.1:22", "10.1.2.3:22", "localhost:22"] {
        let answer = guest.announce(authority).await;
        assert!(
            answer.contains("x-puddle-blocked: ssh_unsupported"),
            "{authority}: {answer}"
        );
        assert!(!answer.contains("toggle"), "{authority}: {answer}");
    }
    assert_ssh_refusals(&rig.events(3).await, 3);
}

#[tokio::test]
async fn ssh_that_waits_for_the_200_is_ended_at_its_first_bytes_and_the_server_gets_nothing() {
    let server = Silent::start().await;
    let rig = Rig::new(&["git.test"]);
    // The host is allowed (rules ignore the port), so the tunnel opens.
    rig.policy.allow(&host("git.test"));
    let mut guest = rig.guest().await;
    let mut tunnel = guest
        .tunnel(&format!("git.test:{}", server.addr.port()))
        .await;
    tunnel.write_all(BANNER).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut answer))
        .await
        .expect("the tunnel ends")
        .unwrap();
    let answer = String::from_utf8(answer).unwrap();
    assert_eq!(
        answer,
        "puddle: SSH is not supported yet; no rule or setting allows it\r\n"
    );
    assert!(
        !answer.starts_with("SSH-"),
        "a pre-banner line, not a banner"
    );
    assert!(
        server.received().is_empty(),
        "the client's identification never went upstream: {:?}",
        server.received()
    );
    let events = rig.events(1).await;
    assert_ssh_refusals(&events, 1);
    assert_eq!(events.first().unwrap().resolved_ip, Some(LOCAL));
    assert_eq!(server.connections(), 1, "only the tunnel's own connect");
}

#[tokio::test]
async fn ssh_inside_an_allowed_tunnel_to_a_git_host_gets_the_https_form_too() {
    let server = Silent::start().await;
    // Any name that resolves to the server stands in for the Git host's port 22.
    let rig = Rig::new(&["gitlab.com"]);
    rig.policy.allow(&host("gitlab.com"));
    let mut guest = rig.guest().await;
    let mut tunnel = guest
        .tunnel(&format!("gitlab.com:{}", server.addr.port()))
        .await;
    tunnel.write_all(BANNER).await.unwrap();
    let mut answer = Vec::new();
    tunnel.read_to_end(&mut answer).await.unwrap();
    assert_eq!(
        String::from_utf8(answer).unwrap(),
        "puddle: SSH is not supported yet, use HTTPS: the remote becomes https://gitlab.com/GROUP/PROJECT.git\r\n"
    );
    assert_eq!(server.received().len(), 0);
}

#[tokio::test]
async fn tunnels_that_are_not_ssh_pass_every_byte_unchanged() {
    let server = Silent::start().await;
    let rig = Rig::new(&["svc.test"]);
    rig.policy.allow(&host("svc.test"));
    let mut guest = rig.guest().await;
    let authority = format!("svc.test:{}", server.addr.port());
    // The first chunk decides: TLS, plain text, a banner-like prefix that is too short or has no
    // version, and an SSH identification line that is not the first thing sent.
    let sent: Vec<Vec<u8>> = vec![
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03".to_vec(),
        b"hello ".to_vec(),
        b"SSH-".to_vec(),
        b"SSH-x".to_vec(),
        BANNER.to_vec(),
    ];
    let mut tunnel = guest.tunnel(&authority).await;
    let mut expected = Vec::new();
    for chunk in &sent {
        tunnel.write_all(chunk).await.unwrap();
        tunnel.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        expected.extend_from_slice(chunk);
    }
    tunnel.shutdown().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.received().len() < expected.len() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.received(), expected);
    // The ones that are not SSH are not recorded as refusals.
    let events = rig.events(1).await;
    assert_eq!(events.first().unwrap().decision, ConnectionDecision::Allow);
}

#[tokio::test]
async fn a_hint_that_is_not_ssh_changes_nothing() {
    let server = Silent::start().await;
    let rig = Rig::new(&["svc.test"]);
    rig.policy.allow(&host("svc.test"));
    let mut guest = rig.guest().await;
    let authority = format!("svc.test:{}", server.addr.port());
    for value in ["telnet", "", "ssh2"] {
        let mut stream = guest.control.open_stream().await.unwrap();
        stream
            .write_all(connect(&authority, &[&format!("x-puddle-protocol: {value}")]).as_bytes())
            .await
            .unwrap();
        let mut first = [0u8; 12];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"HTTP/1.1 200", "{value:?}");
    }
    assert_eq!(rig.policy.pending().len(), 0);
}

#[tokio::test]
async fn an_unannounced_connect_to_port_22_is_an_ordinary_destination_until_it_speaks_ssh() {
    // Port 22 alone does not make a connection SSH: a name nothing allows is pending as any
    // other, and an allowed one is a tunnel that ends only when its first bytes are SSH.
    let rig = Rig::new(&["other.test"]);
    let mut guest = rig.guest().await;
    let answer = guest
        .exchange(connect("other.test:22", &[]).as_bytes())
        .await;
    assert!(
        answer.contains("x-puddle-decision: pending"),
        "not blocked as SSH: {answer}"
    );
    assert_eq!(rig.policy.pending().len(), 1);
}

#[tokio::test]
async fn the_hosts_direct_ssh_into_a_workspace_needs_still_pass_https_untouched() {
    // Direct SSH into a workspace (an editor's Remote-SSH) is puddle's own endpoint and never
    // reaches this proxy. What the editor's server does inside the workspace afterwards is HTTPS to
    // the hosts the direct-SSH setting allows: the refusal of the workspace's own SSH leaves it
    // alone, while an SSH client to the same host is still refused.
    let server = Silent::start().await;
    let hosts = [
        "update.code.visualstudio.com",
        "vscode.download.prss.microsoft.com",
        "marketplace.visualstudio.com",
        "ms-vscode.gallery.vsassets.io",
        "ms-vscode.gallerycdn.vsassets.io",
    ];
    let rig = Rig::new(&hosts);
    for h in hosts {
        rig.policy.allow(&host(h));
    }
    let mut guest = rig.guest().await;
    let hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03client hello bytes";
    for h in hosts {
        let mut tunnel = guest.tunnel(&format!("{h}:{}", server.addr.port())).await;
        tunnel.write_all(hello).await.unwrap();
        tunnel.flush().await.unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while server.received().len() < hello.len() * hosts.len()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.received().len(), hello.len() * hosts.len());
    let answer = guest.announce("update.code.visualstudio.com:22").await;
    assert!(
        answer.contains("x-puddle-blocked: ssh_unsupported"),
        "{answer}"
    );
}

/// Resolves every name to one address, after a pause.
struct SlowResolver(SocketAddr);

impl Resolver for SlowResolver {
    fn resolve<'a>(
        &'a self,
        _name: &'a puddle_types::DomainName,
        _port: u16,
    ) -> BoxFuture<'a, std::io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            Ok(vec![self.0])
        })
    }
}

#[tokio::test]
async fn a_guest_that_leaves_before_the_200_ends_its_tunnel_quietly() {
    let server = Silent::start().await;
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("slow.test"));
    let log = Arc::new(CollectingConnectionLog::new());
    let proxy = Arc::new(
        Proxy::new(policy, Arc::new(NullSink))
            .with_connection_log(log.clone())
            .with_resolver(Arc::new(SlowResolver(server.addr)))
            .with_address_check(Arc::new(AnyAddress)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), WorkspaceName::new("box").unwrap());
    let conn = puddle_ipc::connect(route.endpoint().path()).await.unwrap();
    let mut session = Session::new_client(conn, client_config());
    let mut control = session.control();
    let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
    let mut stream = control.open_stream().await.unwrap();
    stream
        .write_all(connect("slow.test:22", &[]).as_bytes())
        .await
        .unwrap();
    // Gone while the proxy still resolves: the 200 has nobody to go to.
    drop(stream);
    let events = log.wait_for(1, Duration::from_secs(5)).await;
    assert_eq!(events.first().unwrap().decision, ConnectionDecision::Allow);
    assert_eq!(server.received().len(), 0);
    driver.abort();
}
