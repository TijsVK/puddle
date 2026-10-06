// SPDX-License-Identifier: GPL-3.0-or-later
//! I tests: a fake guest (yamux client with the agent's settings) on a real per-sandbox endpoint
//! (`puddle-ipc`), the real proxy behind it, an in-memory policy and local servers.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use puddle_agent_proto::tokio_yamux::{Control, Session, StreamHandle};
use puddle_agent_proto::yamux::client_config;
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticPolicy, StaticResolver};
use puddle_proxy::{Proxy, ProxyConfig, Route};
use puddle_types::{Host, NullSink, PendingId, SandboxName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

fn sandbox(name: &str) -> SandboxName {
    SandboxName::new(name).unwrap()
}

/// A proxy serving one route, its policy and IPC root.
struct Rig {
    policy: Arc<StaticPolicy>,
    proxy: Arc<Proxy>,
    root: IpcRoot,
    route: Route,
}

impl Rig {
    fn new(config: ProxyConfig) -> Self {
        Self::with_resolver(config, StaticResolver::new())
    }

    /// `*.test` names from `resolver`, every address allowed (the servers are on loopback).
    fn with_resolver(config: ProxyConfig, resolver: StaticResolver) -> Self {
        let policy = Arc::new(StaticPolicy::new());
        let proxy = Arc::new(
            Proxy::new(policy.clone(), Arc::new(NullSink))
                .with_resolver(Arc::new(resolver))
                .with_address_check(Arc::new(AnyAddress))
                .with_config(config),
        );
        let root = IpcRoot::new().unwrap();
        let route = proxy.serve_route(root.listen().unwrap(), sandbox("box"));
        Self {
            policy,
            proxy,
            root,
            route,
        }
    }

    async fn guest(&self) -> Guest {
        Guest::connect(&self.route).await
    }
}

/// One agent connection: a yamux client session on the route.
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
    async fn connect(route: &Route) -> Self {
        let conn = puddle_ipc::connect(route.endpoint().path()).await.unwrap();
        let mut session = Session::new_client(conn, client_config());
        let control = session.control();
        let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
        Self { control, driver }
    }

    async fn stream(&mut self) -> StreamHandle {
        self.control.open_stream().await.unwrap()
    }

    /// Sends `head` on a new stream and returns the response status code with the reader.
    async fn request(&mut self, head: &str) -> (u16, BufReader<StreamHandle>) {
        let mut stream = self.stream().await;
        stream.write_all(head.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(stream);
        let code = status(&mut reader).await.unwrap();
        (code, reader)
    }

    async fn connect_to(&mut self, authority: &str) -> (u16, BufReader<StreamHandle>) {
        self.request(&format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        ))
        .await
    }
}

/// Reads a response head; returns the status code.
async fn status<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> io::Result<u16> {
    let (code, _) = response_head(reader).await?;
    Ok(code)
}

/// Reads a response head; returns the status code and the header lines.
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
        headers.push(h.trim_end().to_owned());
    }
}

fn header_value(headers: &[String], name: &str) -> Option<String> {
    headers.iter().find_map(|h| {
        let (n, v) = h.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
    })
}

/// Reads to the end; a reset or other error is returned as is.
async fn read_all<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await?;
    Ok(out)
}

/// An echo server: sends back everything, then closes after the client's FIN.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

/// A one-shot HTTP server: reads one request head (and `body_len` body bytes), sends it back to
/// the test, answers with `response`, and closes. Returns its address and a channel with what it
/// received (head + body, and everything after until close).
async fn http_server(
    response: &'static str,
    body_len: usize,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<(String, Vec<u8>)>,
) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(conn);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            head.push_str(&line);
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        let mut body = vec![0u8; body_len];
        reader.read_exact(&mut body).await.unwrap();
        reader
            .get_mut()
            .write_all(response.as_bytes())
            .await
            .unwrap();
        reader.get_mut().shutdown().await.unwrap();
        // Anything after the request (a pipelined second request) would arrive here.
        let mut rest = Vec::new();
        let _ = reader.read_to_end(&mut rest).await;
        body.extend(rest);
        let _ = tx.send((head, body));
    });
    (addr, rx)
}

/// One `CONNECT` through `guest`, 64 KiB each way, checked byte for byte. Returns its duration.
async fn round_trip(control: &mut Control, authority: &str, i: usize) -> io::Result<Duration> {
    let started = Instant::now();
    let mut stream = control
        .open_stream()
        .await
        .map_err(|e| io::Error::other(format!("open: {e:?}")))?;
    stream
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(stream);
    let code = status(&mut reader).await?;
    if code != 200 {
        return Err(io::Error::other(format!("connection {i}: status {code}")));
    }
    let payload: Vec<u8> = (0..64 * 1024usize)
        .map(|n| u8::try_from((n + i) % 251).unwrap())
        .collect();
    let (mut rd, mut wr) = tokio::io::split(reader);
    let upload = async {
        wr.write_all(&payload).await?;
        wr.shutdown().await
    };
    let mut back = Vec::new();
    let download = rd.read_to_end(&mut back);
    let (up, down) = tokio::join!(upload, download);
    up?;
    down?;
    if back != payload {
        return Err(io::Error::other(format!("connection {i}: echo mismatch")));
    }
    Ok(started.elapsed())
}

/// The T-131 bar (D-2): 256 parallel `CONNECT`s over 4 agent sessions on one Unix-socket/pipe
/// route, 0 failures and none slower than 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_connects_256_all_succeed_with_no_stall_over_5_s() {
    let echo = echo_server().await;
    let rig = Rig::with_resolver(
        ProxyConfig::default(),
        StaticResolver::new().with("echo.test", &[LOCAL]),
    );
    rig.policy.allow(&host("echo.test"));
    let authority = format!("echo.test:{}", echo.port());
    let mut guests = Vec::new();
    for _ in 0..4 {
        guests.push(rig.guest().await);
    }
    let mut set = tokio::task::JoinSet::new();
    for i in 0..256 {
        let mut control = guests[i % 4].control.clone();
        let authority = authority.clone();
        set.spawn(async move { round_trip(&mut control, &authority, i).await });
    }
    let results = tokio::time::timeout(Duration::from_secs(60), async {
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.unwrap());
        }
        out
    })
    .await
    .expect("256 connections did not finish within 60 s");
    let failures: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert!(
        failures.is_empty(),
        "{} of 256 failed: {:?}",
        failures.len(),
        failures.first()
    );
    let slowest = results
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .max()
        .unwrap();
    assert!(
        *slowest < Duration::from_secs(5),
        "slowest connection took {slowest:?}"
    );
    assert_eq!(rig.policy.pending().len(), 0);
}

/// Deny ⇒ 403 and a pending item; approve ⇒ the next attempt passes, with no restart (R-8, R-10).
#[tokio::test]
async fn an_unknown_host_is_refused_and_pending_then_passes_once_approved() {
    let echo = echo_server().await;
    let rig = Rig::with_resolver(
        ProxyConfig::default(),
        StaticResolver::new().with("new.test", &[LOCAL]),
    );
    let mut guest = rig.guest().await;
    let authority = format!("new.test:{}", echo.port());

    let (code, mut reader) = guest.connect_to(&authority).await;
    assert_eq!(code, 403);
    // `status` consumed the head; the body says what to do.
    let body = String::from_utf8(read_all(&mut reader).await.unwrap()).unwrap();
    assert!(body.contains("new.test is not allowed yet"), "{body}");

    let items = rig.policy.pending();
    assert_eq!(items.len(), 1);
    assert_eq!(
        (
            &items[0].sandbox,
            items[0].host.to_string(),
            items[0].port,
            items[0].open
        ),
        (&sandbox("box"), "new.test".to_owned(), echo.port(), true)
    );

    rig.policy.approve(items[0].id).unwrap();
    let (code, mut reader) = guest.connect_to(&authority).await;
    assert_eq!(code, 200);
    reader.get_mut().write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    reader.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    assert_eq!(rig.policy.pending().len(), 1, "no new pending item");
}

#[tokio::test]
async fn refusals_carry_decision_headers_and_end_cleanly() {
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.deny_host(&host("bad.test"));
    let mut guest = rig.guest().await;

    let mut stream = guest.stream().await;
    stream
        .write_all(b"CONNECT bad.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let (code, headers) = response_head(&mut reader).await.unwrap();
    assert_eq!(code, 403);
    assert_eq!(
        header_value(&headers, "x-puddle-decision").as_deref(),
        Some("deny")
    );
    // A clean end of stream after the body, not a reset.
    let body = read_all(&mut reader).await.unwrap();
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("denied by a rule")
    );

    let mut stream = guest.stream().await;
    stream
        .write_all(b"CONNECT new.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let (code, headers) = response_head(&mut reader).await.unwrap();
    assert_eq!(code, 403);
    assert_eq!(
        header_value(&headers, "x-puddle-decision").as_deref(),
        Some("pending")
    );
    let id: i64 = header_value(&headers, "x-puddle-pending")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(rig.policy.pending()[0].id, PendingId(id));
}

#[tokio::test]
async fn a_head_over_64_kib_gets_431() {
    let rig = Rig::new(ProxyConfig::default());
    let mut guest = rig.guest().await;
    let head = format!(
        "GET http://a.test/ HTTP/1.1\r\nX-Big: {}\r\n\r\n",
        "a".repeat(64 * 1024)
    );
    let (code, _) = guest.request(&head).await;
    assert_eq!(code, 431);
    assert_eq!(rig.policy.decisions(), 0);
}

#[tokio::test]
async fn a_head_that_never_ends_gets_408() {
    let rig = Rig::new(ProxyConfig::default().with_head_timeout(Duration::from_millis(200)));
    let mut guest = rig.guest().await;
    let started = Instant::now();
    let (code, _) = guest
        .request("CONNECT slow.test:443 HTTP/1.1\r\nX-Slow: ")
        .await;
    assert_eq!(code, 408);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(rig.policy.decisions(), 0);
}

#[tokio::test]
async fn requests_that_are_not_for_a_proxy_get_400() {
    let rig = Rig::new(ProxyConfig::default());
    let mut guest = rig.guest().await;
    for head in [
        "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n",
        "GET https://a.test/ HTTP/1.1\r\n\r\n",
        "CONNECT a.test HTTP/1.1\r\n\r\n",
        "CONNECT user@a.test:443 HTTP/1.1\r\n\r\n",
        "CONNECT bücher.test:443 HTTP/1.1\r\n\r\n",
        "CONNECT 0x7f.1:443 HTTP/1.1\r\n\r\n",
        "POST http://a.test/ HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET http://a.test/ HTTP/9\r\n\r\n",
    ] {
        let (code, _) = guest.request(head).await;
        assert_eq!(code, 400, "{head:?}");
    }
    assert_eq!(rig.policy.decisions(), 0);
}

#[tokio::test]
async fn a_stream_closed_before_a_request_is_dropped_quietly() {
    let rig = Rig::new(ProxyConfig::default());
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    stream.write_all(b"\r\n").await.unwrap();
    stream.shutdown().await.unwrap();
    let got = read_all(&mut stream).await.unwrap_or_default();
    assert_eq!(got.len(), 0);
    assert_eq!(rig.policy.decisions(), 0);
}

#[tokio::test]
async fn a_plain_http_request_is_forwarded_once_with_the_checked_host() {
    let response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
    let (server, received) = http_server(response, 4).await;
    let rig = Rig::with_resolver(
        ProxyConfig::default(),
        StaticResolver::new().with("web.test", &[LOCAL]),
    );
    rig.policy.allow(&host("web.test"));
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    let port = server.port();
    let request = format!(
        "POST http://Web.Test:{port}/up?x=1 HTTP/1.1\r\nHost: evil.test\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\nProxy-Authorization: Basic Zm9v\r\nContent-Length: 4\r\nAccept: */*\r\n\r\nbody\
         GET http://evil.test/ HTTP/1.1\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let response_back = String::from_utf8(read_all(&mut stream).await.unwrap()).unwrap();
    assert_eq!(response_back, response);
    let (head, rest) = received.await.unwrap();
    assert_eq!(
        head,
        format!(
            "POST /up?x=1 HTTP/1.1\r\nHost: web.test:{port}\r\nContent-Length: 4\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
    );
    assert_eq!(rest, b"body", "the pipelined request must not be forwarded");
}

#[tokio::test]
async fn a_chunked_upload_is_forwarded_with_its_framing() {
    let response = "HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n";
    let chunked = "4\r\nabcd\r\n0\r\n\r\n";
    let (server, received) = http_server(response, chunked.len()).await;
    let rig = Rig::with_resolver(
        ProxyConfig::default(),
        StaticResolver::new().with("web.test", &[LOCAL]),
    );
    rig.policy.allow(&host("web.test"));
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    let request = format!(
        "PUT http://web.test:{}/f HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n{chunked}",
        server.port()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let back = String::from_utf8(read_all(&mut stream).await.unwrap()).unwrap();
    assert!(back.starts_with("HTTP/1.1 201"), "{back}");
    let (head, body) = received.await.unwrap();
    assert!(head.contains("Transfer-Encoding: chunked\r\n"), "{head}");
    assert_eq!(body, chunked.as_bytes());
}

#[tokio::test]
async fn bytes_sent_with_the_connect_reach_the_server() {
    let echo = echo_server().await;
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.allow(&host("127.0.0.1"));
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    // The TLS ClientHello often arrives in the same packet as the CONNECT.
    stream
        .write_all(format!("CONNECT {echo} HTTP/1.1\r\n\r\nearly").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    assert_eq!(status(&mut reader).await.unwrap(), 200);
    let mut back = [0u8; 5];
    reader.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"early");
}

#[tokio::test]
async fn an_unreachable_server_is_a_502() {
    let closed = {
        let l = TcpListener::bind((LOCAL, 0)).await.unwrap();
        l.local_addr().unwrap()
    };
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.allow(&host("127.0.0.1"));
    let mut guest = rig.guest().await;
    let (code, _) = guest.connect_to(&closed.to_string()).await;
    assert_eq!(code, 502);
}

#[tokio::test]
async fn a_policy_failure_is_a_503() {
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.allow(&host("127.0.0.1"));
    rig.policy.set_unavailable(true);
    let mut guest = rig.guest().await;
    let (code, _) = guest.connect_to("127.0.0.1:443").await;
    assert_eq!(code, 503);
}

#[tokio::test]
async fn the_default_address_check_blocks_loopback_even_when_allowed() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("127.0.0.1"));
    let proxy = Arc::new(Proxy::new(policy.clone(), Arc::new(NullSink)));
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(root.listen().unwrap(), sandbox("box"));
    let mut guest = Guest::connect(&route).await;
    let mut stream = guest.stream().await;
    stream
        .write_all(b"CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let (code, headers) = response_head(&mut reader).await.unwrap();
    assert_eq!(code, 403);
    assert_eq!(
        header_value(&headers, "x-puddle-blocked").as_deref(),
        Some("local_address")
    );
    assert_eq!(policy.pending().len(), 0);
}

/// HO-3: the sandbox is the route's. Two routes, the same request: each pending item names the
/// sandbox of the route it came in on.
#[tokio::test]
async fn each_route_speaks_for_its_own_sandbox() {
    let policy = Arc::new(StaticPolicy::new());
    let proxy = Arc::new(Proxy::new(policy.clone(), Arc::new(NullSink)));
    let root = IpcRoot::new().unwrap();
    let a = proxy.serve_route(root.listen().unwrap(), sandbox("alpha"));
    let b = proxy.serve_route(root.listen().unwrap(), sandbox("beta"));
    assert_eq!(a.sandbox(), &sandbox("alpha"));
    for route in [&a, &b] {
        let mut guest = Guest::connect(route).await;
        let (code, _) = guest.connect_to("same.test:443").await;
        assert_eq!(code, 403);
    }
    let sandboxes: Vec<_> = policy.pending().into_iter().map(|p| p.sandbox).collect();
    assert_eq!(sandboxes, vec![sandbox("alpha"), sandbox("beta")]);
}

#[tokio::test]
async fn connections_over_the_sandbox_limit_get_503_until_one_closes() {
    let echo = echo_server().await;
    let rig = Rig::new(ProxyConfig::default().with_max_streams_per_sandbox(2));
    rig.policy.allow(&host("127.0.0.1"));
    let mut guest = rig.guest().await;
    let target = echo.to_string();
    let (c1, first) = guest.connect_to(&target).await;
    let (c2, _second) = guest.connect_to(&target).await;
    assert_eq!((c1, c2), (200, 200));
    let (c3, _) = guest.connect_to(&target).await;
    assert_eq!(c3, 503);
    // Closing one frees its slot.
    let mut first = first.into_inner();
    first.shutdown().await.unwrap();
    let _ = read_all(&mut first).await;
    drop(first);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (code, _) = guest.connect_to(&target).await;
        if code == 200 {
            break;
        }
        assert!(Instant::now() < deadline, "the slot was never freed");
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn agent_connections_over_the_route_limit_are_dropped() {
    let rig = Rig::new(ProxyConfig::default().with_max_sessions_per_route(1));
    let mut first = rig.guest().await;
    // The first session is served (and counted once its first frame arrives).
    let (code, _) = first.connect_to("x.test:443").await;
    assert_eq!(code, 403);
    let mut second = rig.guest().await;
    // The host drops the connection: opening a stream fails, or the stream ends with nothing.
    if let Ok(mut stream) = second.control.open_stream().await {
        let _ = stream
            .write_all(b"CONNECT x.test:443 HTTP/1.1\r\n\r\n")
            .await;
        let got = tokio::time::timeout(Duration::from_secs(5), read_all(&mut stream))
            .await
            .expect("the refused session must end, not hang");
        assert!(
            !matches!(got, Ok(ref bytes) if !bytes.is_empty()),
            "{got:?}"
        );
    }
    assert_eq!(rig.policy.pending()[0].attempts, 1);
}

#[tokio::test]
async fn a_shut_down_route_accepts_no_one() {
    let rig = Rig::new(ProxyConfig::default());
    let path = rig.route.endpoint().path().to_path_buf();
    let mut guest = rig.guest().await;
    let (code, _) = guest.connect_to("x.test:443").await;
    assert_eq!(code, 403);
    let Rig {
        route, root, proxy, ..
    } = rig;
    route.shutdown().await;
    // On Windows the pipe goes away once the runtime has cancelled its acceptors (puddle-ipc).
    #[cfg(unix)]
    assert!(puddle_ipc::connect(&path).await.is_err());
    let _ = path;
    // The proxy itself still serves other routes.
    let again = proxy.serve_route(root.listen().unwrap(), sandbox("box"));
    let mut guest = Guest::connect(&again).await;
    let (code, _) = guest.connect_to("x.test:443").await;
    assert_eq!(code, 403);
}

/// A hostile or confused client on the route that doesn't speak yamux is dropped; the route
/// keeps serving the real agent.
#[tokio::test]
async fn a_connection_that_is_not_an_agent_is_dropped_and_the_route_keeps_serving() {
    let rig = Rig::new(ProxyConfig::default());
    let mut intruder = puddle_ipc::connect(rig.route.endpoint().path())
        .await
        .unwrap();
    intruder
        .write_all(b"CONNECT x.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), read_all(&mut intruder))
        .await
        .expect("the host must close the connection");
    assert!(
        !matches!(got, Ok(ref bytes) if !bytes.is_empty()),
        "{got:?}"
    );
    assert_eq!(rig.policy.decisions(), 0);
    let mut guest = rig.guest().await;
    let (code, _) = guest.connect_to("x.test:443").await;
    assert_eq!(code, 403);
}

/// A server may answer before it has read the whole upload (an early `413`, say): the guest gets
/// the answer and a clean end.
#[tokio::test]
async fn a_server_answering_before_the_upload_ends_reaches_the_guest() {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf).await;
        conn.write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
        conn.shutdown().await.unwrap();
        // Keep reading so the upload doesn't fail on our side first.
        let _ = tokio::io::copy(&mut conn, &mut tokio::io::sink()).await;
    });
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.allow(&host("127.0.0.1"));
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    stream
        .write_all(
            format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let code = tokio::time::timeout(Duration::from_secs(5), status(&mut reader))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, 413);
}

/// T-048 for plain HTTP: a server that resets mid-request makes the guest stream fail, not end
/// cleanly as if the response were complete.
#[tokio::test]
async fn a_server_reset_during_a_plain_http_request_reaches_the_guest_as_an_error() {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf).await;
        conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npart")
            .await
            .unwrap();
        conn.set_zero_linger().unwrap();
        drop(conn);
    });
    let rig = Rig::new(ProxyConfig::default());
    rig.policy.allow(&host("127.0.0.1"));
    let mut guest = rig.guest().await;
    let mut stream = guest.stream().await;
    stream
        .write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), read_all(&mut stream))
        .await
        .unwrap();
    assert!(got.is_err(), "the guest saw a clean end: {got:?}");
}
