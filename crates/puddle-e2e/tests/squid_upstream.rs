// SPDX-License-Identifier: GPL-3.0-or-later
//! L2 end to end against a real Squid with Basic proxy authentication (T-165, T-116 P4): a guest
//! TCP client → the real guest agent → yamux over the sandbox's real endpoint → the real proxy
//! (real SQLite rules and audit) → upstream chaining (route from a PAC, dead hop, `407` Basic) →
//! Squid → a local server. The audit must name the hop, and Squid's own access log is the witness
//! that traffic went through it as the configured user.
//!
//! Squid is started from `PUDDLE_SQUID_BIN` (a `squid` binary, as on the CI runner) or
//! `PUDDLE_SQUID_DOCKER` (an image such as `ubuntu/squid`, run with host networking, as in the
//! T-033 lab). With neither set the tests skip, unless `PUDDLE_SQUID_REQUIRED=1`, which makes a
//! missing Squid a failure (CI sets it).
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticResolver};
use puddle_proxy::{Proxy, Route, Upstream};
use puddle_store::{Actor, Effect, Limits, NewRule, Pattern, Scope, Store, SystemClock};
use puddle_types::{NullSink, SandboxName};
use puddle_upstream::{
    BasicAuth, Chain, Config as DiscoveryConfig, Credentials, Discovery, FakeOs, Hop, ProxyAddr,
    ProxyAuth, ProxyConfig,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const USER: &str = "t165";
const PASSWORD: &str = "lab-only-pw-7Qx2";

/// A running Squid; stopped on drop.
struct Squid {
    port: u16,
    dir: tempfile::TempDir,
    stop: Stop,
}

enum Stop {
    Process(Child),
    Container(String),
}

impl Drop for Squid {
    fn drop(&mut self) {
        match &mut self.stop {
            Stop::Process(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Stop::Container(name) => {
                let _ = Command::new("docker")
                    .args(["rm", "-f", name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind((LOCAL, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

impl Squid {
    /// Starts Squid with Basic auth for [`USER`], allowing `CONNECT` and plain requests to
    /// `origin_port` only, and `*.corp.test` names resolved from its own hosts file (split DNS:
    /// this host cannot resolve them).
    fn start(origin_port: u16) -> Option<Self> {
        let bin = std::env::var_os("PUDDLE_SQUID_BIN");
        let image = std::env::var("PUDDLE_SQUID_DOCKER").ok();
        if bin.is_none() && image.is_none() {
            assert!(
                std::env::var_os("PUDDLE_SQUID_REQUIRED").is_none(),
                "PUDDLE_SQUID_REQUIRED is set but neither PUDDLE_SQUID_BIN nor PUDDLE_SQUID_DOCKER is"
            );
            eprintln!("skipped: set PUDDLE_SQUID_BIN or PUDDLE_SQUID_DOCKER to run against Squid");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        // Where Squid sees the directory: here, or at /lab in the container.
        let seen = if image.is_some() {
            PathBuf::from("/lab")
        } else {
            dir.path().to_path_buf()
        };
        let port = free_port();
        let helper = dir.path().join("basic-helper.sh");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\nwhile read -r user pass; do\n  if [ \"$user\" = \"{USER}\" ] && [ \"$pass\" = \"{PASSWORD}\" ]; then echo OK; else echo ERR; fi\ndone\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dir.path().join("hosts"),
            "127.0.0.1 echo.corp.test web.corp.test\n",
        )
        .unwrap();
        let at = |name: &str| seen.join(name).display().to_string();
        fs::write(
            dir.path().join("squid.conf"),
            format!(
                "http_port 127.0.0.1:{port}\n\
                 auth_param basic program /bin/sh {helper}\n\
                 auth_param basic realm puddle-t165-lab\n\
                 auth_param basic children 2\n\
                 acl authed proxy_auth REQUIRED\n\
                 acl SSL_ports port {origin_port}\n\
                 acl Safe_ports port {origin_port}\n\
                 acl CONNECT method CONNECT\n\
                 http_access deny !Safe_ports\n\
                 http_access deny CONNECT !SSL_ports\n\
                 http_access allow authed\n\
                 http_access deny all\n\
                 hosts_file {hosts}\n\
                 cache deny all\n\
                 buffered_logs off\n\
                 access_log daemon:{access}\n\
                 cache_log stdio:{cache}\n\
                 pid_filename {pid}\n\
                 coredump_dir {core}\n\
                 visible_hostname puddle-lab\n",
                helper = at("basic-helper.sh"),
                hosts = at("hosts"),
                access = at("access.log"),
                cache = at("cache.log"),
                pid = at("squid.pid"),
                core = seen.display(),
            ),
        )
        .unwrap();
        let stop = if let Some(image) = image {
            let name = format!("puddle-t165-squid-{port}");
            let status = Command::new("docker")
                .args(["run", "-d", "--name", &name, "--network", "host", "-v"])
                .arg(format!("{}:/lab", dir.path().display()))
                .args([&image, "-f", "/lab/squid.conf", "-NYC"])
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "docker run failed");
            Stop::Container(name)
        } else {
            let log = fs::File::create(dir.path().join("squid.stderr")).unwrap();
            let child = Command::new(bin.unwrap())
                .arg("-f")
                .arg(dir.path().join("squid.conf"))
                .args(["-N", "-Y", "-C"])
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()
                .unwrap();
            Stop::Process(child)
        };
        let squid = Self { port, dir, stop };
        squid.wait_ready();
        Some(squid)
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect((LOCAL, self.port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let stderr = fs::read_to_string(self.dir.path().join("squid.stderr")).unwrap_or_default();
        let cache = fs::read_to_string(self.dir.path().join("cache.log")).unwrap_or_default();
        panic!("squid did not start\n{stderr}\n{cache}");
    }

    fn addr(&self) -> ProxyAddr {
        ProxyAddr::new("127.0.0.1", self.port)
    }

    /// Squid's access log (what it forwarded, and as which user).
    fn access_log(&self) -> String {
        // Squid flushes stdio logs lazily; give it a moment.
        std::thread::sleep(Duration::from_millis(300));
        let log = match &self.stop {
            // The container's Squid writes its logs as its own user, mode 0640.
            Stop::Container(name) => Command::new("docker")
                .args(["exec", name, "cat", "/lab/access.log"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default(),
            Stop::Process(_) => {
                fs::read_to_string(self.dir.path().join("access.log")).unwrap_or_default()
            }
        };
        if log.is_empty() {
            let cache = fs::read_to_string(self.dir.path().join("cache.log")).unwrap_or_default();
            let files: Vec<_> = fs::read_dir(self.dir.path())
                .unwrap()
                .flatten()
                .map(|e| e.file_name())
                .collect();
            return format!("(empty access log; files {files:?}; cache.log:\n{cache})");
        }
        log
    }
}

fn sandbox() -> SandboxName {
    SandboxName::new("e2e").unwrap()
}

struct Rig {
    store: Arc<Store>,
    agent: Agent,
    _route: Route,
    _root: IpcRoot,
}

/// The proxy over `hops` (a PAC answer), authenticating with `auth`; names are unknown to the
/// resolver, so only Squid can reach them.
async fn rig(hops: Vec<Hop>, auth: Arc<dyn ProxyAuth>) -> Rig {
    let store = Arc::new(Store::open_in_memory(Arc::new(SystemClock), Limits::default()).unwrap());
    let os = FakeOs::new(ProxyConfig {
        pac_url: Some("http://pac.corp/proxy.pac".into()),
        ..ProxyConfig::default()
    });
    os.set_pac(move |_| Ok(hops.clone()));
    let chain = Chain::new(Discovery::new(os, DiscoveryConfig::default()), auth);
    let proxy = Arc::new(
        Proxy::new(store.clone(), Arc::new(NullSink))
            .with_connection_log(store.clone())
            .with_resolver(Arc::new(StaticResolver::new()))
            .with_address_check(Arc::new(AnyAddress))
            .with_upstream(Upstream::new(chain)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), sandbox());
    let config = Config {
        listen: SocketAddr::new(LOCAL, 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        bridge: None,
        ..Config::default()
    };
    let agent = Agent::start(config).await.unwrap();
    Rig {
        store,
        agent,
        _route: route,
        _root: root,
    }
}

fn allow(store: &Store, host: &str) {
    store
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sandbox()),
            pattern: Pattern::parse(host).unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
}

async fn connection_records(store: &Store, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let records: Vec<Value> = store
            .audit_lines(0, 100_000)
            .unwrap()
            .into_iter()
            .map(|(_, line)| serde_json::from_str::<Value>(&line).unwrap())
            .filter(|v| v["type"] == "connection")
            .collect();
        if records.len() >= count || Instant::now() >= deadline {
            assert!(
                records.len() >= count,
                "{count} records expected: {records:?}"
            );
            return records;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// An echo server on loopback.
async fn echo_server() -> SocketAddr {
    let echo = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    echo_addr
}

async fn status_and_body(agent: SocketAddr, request: &str) -> (u16, Vec<String>, String) {
    let mut conn = TcpStream::connect(agent).await.unwrap();
    conn.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let code: u16 = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await.unwrap();
        if h == "\r\n" || h.is_empty() {
            break;
        }
        headers.push(h.trim_end().to_ascii_lowercase());
    }
    let mut body = String::new();
    let _ = reader.read_to_string(&mut body).await;
    (code, headers, body)
}

fn basic(user: &str, password: &str) -> Arc<dyn ProxyAuth> {
    Arc::new(BasicAuth::new().with_default(Credentials::new(user, password)))
}

/// A proxy address nothing answers on: bound but never listening, so the port stays ours and
/// connecting is refused.
fn dead_proxy() -> (ProxyAddr, tokio::net::TcpSocket) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(LOCAL, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    (ProxyAddr::new("127.0.0.1", port), socket)
}

#[tokio::test]
async fn a_tunnel_goes_through_basic_auth_squid_after_a_dead_pac_hop() {
    let echo = echo_server().await;
    let Some(squid) = Squid::start(echo.port()) else {
        return;
    };
    let (dead, _held) = dead_proxy();
    let rig = rig(
        vec![Hop::Proxy(dead), Hop::Proxy(squid.addr()), Hop::Direct],
        basic(USER, PASSWORD),
    )
    .await;
    allow(&rig.store, "echo.corp.test");
    let authority = format!("echo.corp.test:{}", echo.port());
    let mut conn = TcpStream::connect(rig.agent.local_addr()).await.unwrap();
    conn.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await.unwrap();
        if h == "\r\n" {
            break;
        }
    }
    let payload: Vec<u8> = (0..64 * 1024usize)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    // No half-close: Squid ends the whole tunnel on the client's FIN, so read the echo in full.
    let (mut rd, mut wr) = tokio::io::split(reader);
    let upload = async {
        wr.write_all(&payload).await.unwrap();
    };
    let download = async {
        let mut back = vec![0_u8; payload.len()];
        rd.read_exact(&mut back).await.unwrap();
        back
    };
    let ((), back) = tokio::join!(upload, download);
    assert_eq!(back, payload, "64 KiB through Squid, byte for byte");
    drop((rd, wr));

    let records = connection_records(&rig.store, 1).await;
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["upstream"], format!("PROXY {}", squid.addr()));
    let log = squid.access_log();
    assert!(
        log.contains("TCP_TUNNEL/200")
            && log.contains(&format!("{USER} "))
            && log.contains(&authority),
        "Squid's access log must show the tunnel for {USER}:\n{log}"
    );
    assert!(
        log.contains("TCP_DENIED/407"),
        "the 407 round trip happened:\n{log}"
    );
}

#[tokio::test]
async fn plain_http_goes_through_squid_with_the_basic_credential() {
    let origin = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let origin_addr = origin.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (conn, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let mut reader = BufReader::new(conn);
                loop {
                    let mut l = String::new();
                    if reader.read_line(&mut l).await.unwrap_or(0) == 0 || l == "\r\n" {
                        break;
                    }
                }
                let _ = reader
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 21\r\nconnection: close\r\n\r\nhello from the origin")
                    .await;
                let _ = reader.get_mut().shutdown().await;
            });
        }
    });
    let Some(squid) = Squid::start(origin_addr.port()) else {
        return;
    };
    let rig = rig(vec![Hop::Proxy(squid.addr())], basic(USER, PASSWORD)).await;
    allow(&rig.store, "web.corp.test");
    let (code, _, body) = status_and_body(
        rig.agent.local_addr(),
        &format!(
            "GET http://web.corp.test:{}/hello HTTP/1.1\r\nHost: web.corp.test\r\n\r\n",
            origin_addr.port()
        ),
    )
    .await;
    assert_eq!((code, body.as_str()), (200, "hello from the origin"));
    let records = connection_records(&rig.store, 1).await;
    assert_eq!(records[0]["upstream"], format!("PROXY {}", squid.addr()));
    assert_eq!(records[0]["method"], "GET");
    let log = squid.access_log();
    assert!(
        log.contains("TCP_MISS/200") && log.contains(&format!("{USER} ")) && log.contains("/hello"),
        "{log}"
    );
}

#[tokio::test]
async fn a_wrong_or_missing_password_is_a_502_naming_upstream_auth_and_squid_never_tunnels() {
    let echo = echo_server().await;
    let Some(squid) = Squid::start(echo.port()) else {
        return;
    };
    for auth in [
        basic(USER, "not-the-password"),
        Arc::new(BasicAuth::new()) as Arc<dyn ProxyAuth>,
    ] {
        let rig = rig(vec![Hop::Proxy(squid.addr()), Hop::Direct], auth).await;
        allow(&rig.store, "echo.corp.test");
        let (code, headers, body) = status_and_body(
            rig.agent.local_addr(),
            &format!(
                "CONNECT echo.corp.test:{port} HTTP/1.1\r\nHost: echo.corp.test:{port}\r\n\r\n",
                port = echo.port()
            ),
        )
        .await;
        assert_eq!(code, 502, "{body}");
        assert!(
            headers
                .iter()
                .any(|h| h == "x-puddle-blocked-by: upstream-auth"),
            "{headers:?}"
        );
        assert!(!body.contains("not-the-password"));
    }
    let log = squid.access_log();
    assert!(log.contains("TCP_DENIED/407"), "{log}");
    assert!(
        !log.contains("TCP_TUNNEL"),
        "no tunnel without a valid login:\n{log}"
    );
}
