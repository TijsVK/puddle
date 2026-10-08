// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP/2 pieces of the terminate test rig: an upstream that speaks h2 (or serves h1 behind ALPN)
//! and a guest client that speaks h2 through the proxy's route.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]
#![allow(dead_code, reason = "each test binary uses a different subset")]

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use http::{HeaderMap, Request, Response};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client;
use hyper::server::conn::http2 as server;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::{Guest, LOCAL, Pki};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type Reply = Response<UnsyncBoxBody<Bytes, BoxError>>;
pub(crate) type ReqBody = UnsyncBoxBody<Bytes, BoxError>;
/// Answers a request as it arrives (`Incoming` is the live request body); the number is the
/// connection the request came on.
pub(crate) type Handler = Arc<
    dyn Fn(Request<Incoming>, usize) -> Pin<Box<dyn Future<Output = Reply> + Send>> + Send + Sync,
>;
/// Answers a request that was read completely and recorded.
pub(crate) type Script = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A reply with `status` and a whole `body`.
pub(crate) fn reply(status: u16, body: &str) -> Reply {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from(body.to_owned()))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}

/// What a request looked like when it reached an upstream.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) conn: usize,
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) authority: Option<String>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) trailers: Option<Vec<(String, String)>>,
    pub(crate) version: http::Version,
}

impl Seen {
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

fn pairs(map: &HeaderMap) -> Vec<(String, String)> {
    map.iter()
        .map(|(n, v)| {
            (
                n.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// A TLS server that speaks HTTP/2 only (ALPN `h2`).
pub(crate) struct H2Server {
    pub(crate) addr: SocketAddr,
    /// TCP connections accepted.
    pub(crate) accepted: Arc<AtomicUsize>,
    pub(crate) seen: Arc<Mutex<Vec<Seen>>>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    task: JoinHandle<()>,
}

impl Drop for H2Server {
    fn drop(&mut self) {
        self.task.abort();
        self.drop_connections();
    }
}

impl H2Server {
    /// Reads each request completely, records it, and answers with `script`.
    pub(crate) async fn recording(pki: &Pki, name: &str, script: Script) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let handler: Handler = Arc::new(move |request, conn| {
            let script = Arc::clone(&script);
            let log = Arc::clone(&log);
            Box::pin(async move {
                let method = request.method().to_string();
                let path = request
                    .uri()
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let authority = request.uri().authority().map(ToString::to_string);
                let headers = pairs(request.headers());
                let version = request.version();
                let collected = request.into_body().collect().await;
                let (body, trailers) = match collected {
                    Ok(c) => {
                        let trailers = c.trailers().map(pairs);
                        (c.to_bytes().to_vec(), trailers)
                    }
                    Err(_) => (Vec::new(), None),
                };
                let seen = Seen {
                    conn,
                    method,
                    path,
                    authority,
                    headers,
                    body,
                    trailers,
                    version,
                };
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(seen.clone());
                script(&seen)
            })
        });
        Self::start(pki, name, handler, false, seen).await
    }

    /// Hands every request to `handler` as it arrives.
    pub(crate) async fn streaming(pki: &Pki, name: &str, handler: Handler) -> Self {
        Self::start(pki, name, handler, false, Arc::default()).await
    }

    /// As [`Self::streaming`], with the flow-control windows and frame size of a server built for
    /// bulk transfers (4 MiB per stream, 16 MiB per connection, 64 KiB frames), for throughput tests.
    pub(crate) async fn bulk(pki: &Pki, name: &str, handler: Handler) -> Self {
        Self::start_tuned(pki, name, handler, false, Arc::default(), true).await
    }

    /// As [`Self::streaming`], advertising RFC 8441 extended CONNECT.
    pub(crate) async fn streaming_with_connect(pki: &Pki, name: &str, handler: Handler) -> Self {
        Self::start(pki, name, handler, true, Arc::default()).await
    }

    async fn start(
        pki: &Pki,
        name: &str,
        handler: Handler,
        connect_protocol: bool,
        seen: Arc<Mutex<Vec<Seen>>>,
    ) -> Self {
        Self::start_tuned(pki, name, handler, connect_protocol, seen, false).await
    }

    async fn start_tuned(
        pki: &Pki,
        name: &str,
        handler: Handler,
        connect_protocol: bool,
        seen: Arc<Mutex<Vec<Seen>>>,
        bulk: bool,
    ) -> Self {
        let mut config = Arc::into_inner(pki.server_config(name, super::Flaw::None))
            .expect("one owner of a fresh config");
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let accepted = Arc::clone(&accepted);
            let connections = Arc::clone(&connections);
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let conn = accepted.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let handler = Arc::clone(&handler);
                    let handle = tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = service_fn(move |request: Request<Incoming>| {
                            let answer = handler(request, conn);
                            async move { Ok::<_, std::convert::Infallible>(answer.await) }
                        });
                        let mut builder = server::Builder::new(TokioExecutor::new());
                        builder.timer(TokioTimer::new());
                        if connect_protocol {
                            builder.enable_connect_protocol();
                        }
                        if bulk {
                            builder
                                .initial_stream_window_size(4 << 20)
                                .initial_connection_window_size(16 << 20)
                                .max_frame_size(64 << 10);
                        }
                        let _ = builder.serve_connection(TokioIo::new(tls), service).await;
                    });
                    connections
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(handle);
                }
            })
        };
        Self {
            addr,
            accepted,
            seen,
            connections,
            task,
        }
    }

    /// Cuts every connection now open (the server restarts, or a load balancer drops them).
    pub(crate) fn drop_connections(&self) {
        for handle in self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            handle.abort();
        }
    }

    pub(crate) fn recorded(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

// ---------------------------------------------------------------------------------------------
// The guest's side.

/// What a guest's HTTP/2 client got back.
#[derive(Debug)]
pub(crate) struct Got {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) trailers: Option<Vec<(String, String)>>,
}

impl Got {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn trailer(&self, name: &str) -> Option<&str> {
        self.trailers
            .as_ref()?
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An HTTP/2 client over the guest's terminated TLS connection.
pub(crate) struct H2Guest {
    pub(crate) sender: client::SendRequest<ReqBody>,
    pub(crate) alpn: Option<Vec<u8>>,
    driver: Option<JoinHandle<()>>,
}

impl Drop for H2Guest {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

impl H2Guest {
    /// Ends the connection as a client that is done: no more requests, then the driver finishes
    /// (a GOAWAY and a TLS close).
    pub(crate) async fn close(mut self) {
        let driver = self.driver.take();
        drop(self);
        if let Some(driver) = driver {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), driver).await;
        }
    }
}

impl Guest {
    /// `CONNECT authority`, a TLS handshake offering `alpn`, then an HTTP/2 client on it.
    pub(crate) async fn h2(&mut self, authority: &str, alpn: &[&[u8]]) -> H2Guest {
        let client = self.tls_with(authority, None, alpn, true).await.unwrap();
        assert_eq!(
            client.alpn.as_deref(),
            Some(&b"h2"[..]),
            "h2 was negotiated"
        );
        Self::h2_over(client).await
    }

    /// An HTTP/2 client over an already negotiated connection.
    pub(crate) async fn h2_over(client: super::Client) -> H2Guest {
        Self::h2_over_with(client, false).await
    }

    /// An HTTP/2 client with the windows and frame size of a client built for bulk transfers (4 MiB
    /// per stream, 16 MiB per connection, 64 KiB frames), for throughput tests.
    pub(crate) async fn h2_bulk(&mut self, authority: &str) -> H2Guest {
        let client = self
            .tls_with(authority, None, &[b"h2"], true)
            .await
            .unwrap();
        Self::h2_over_with(client, true).await
    }

    /// As [`Self::h2_over`], tuned for bulk transfers.
    pub(crate) async fn h2_over_bulk(client: super::Client) -> H2Guest {
        Self::h2_over_with(client, true).await
    }

    async fn h2_over_with(client: super::Client, bulk: bool) -> H2Guest {
        let alpn = client.alpn.clone();
        let tls = client.stream.into_inner();
        let mut builder = client::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if bulk {
            builder
                .initial_stream_window_size(4 << 20)
                .initial_connection_window_size(16 << 20)
                .max_frame_size(64 << 10);
        }
        let (sender, connection) = builder
            .handshake::<_, ReqBody>(TokioIo::new(tls))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        H2Guest {
            sender,
            alpn,
            driver: Some(driver),
        }
    }
}

/// A request body of `bytes`.
pub(crate) fn full(bytes: impl Into<Bytes>) -> ReqBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

impl H2Guest {
    /// Sends `method path` for `authority` with `headers` and `body`, and reads the whole answer.
    pub(crate) async fn request(
        &mut self,
        method: &str,
        authority: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: ReqBody,
    ) -> Got {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://{authority}{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = self
            .sender
            .send_request(builder.body(body).unwrap())
            .await
            .unwrap();
        collect(response).await
    }

    pub(crate) async fn get(&mut self, authority: &str, path: &str) -> Got {
        self.request("GET", authority, path, &[], full(Bytes::new()))
            .await
    }
}

/// Reads a response to its end.
pub(crate) async fn collect(response: Response<Incoming>) -> Got {
    let status = response.status().as_u16();
    let headers = pairs(response.headers());
    let collected = response.into_body().collect().await.unwrap();
    let trailers = collected.trailers().map(pairs);
    Got {
        status,
        headers,
        body: collected.to_bytes().to_vec(),
        trailers,
    }
}

// ---------------------------------------------------------------------------------------------
// A WebSocket server over HTTP/1.1 (the bytes after the handshake are echoed).

use std::fmt::Write as _;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// The request line and headers of one handshake the server saw (names lower-cased).
pub(crate) type Handshake = Vec<(String, String)>;

/// An HTTP/1.1 TLS server (ALPN `http/1.1`) that accepts a WebSocket handshake and then echoes
/// every byte it is sent. Any other request is answered `404`.
pub(crate) struct WsServer {
    pub(crate) addr: SocketAddr,
    pub(crate) handshakes: Arc<Mutex<Vec<Handshake>>>,
    task: JoinHandle<()>,
}

impl Drop for WsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl WsServer {
    pub(crate) async fn start(pki: &Pki, name: &str) -> Self {
        let mut config = Arc::into_inner(pki.server_config(name, super::Flaw::None)).unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let handshakes = Arc::clone(&handshakes);
            tokio::spawn(async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let handshakes = Arc::clone(&handshakes);
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut stream = BufReader::new(tls);
                        let mut line = String::new();
                        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let mut headers = vec![("request-line".to_owned(), line.trim().to_owned())];
                        loop {
                            let mut h = String::new();
                            if stream.read_line(&mut h).await.unwrap_or(0) == 0 {
                                return;
                            }
                            let h = h.trim_end();
                            if h.is_empty() {
                                break;
                            }
                            if let Some((n, v)) = h.split_once(':') {
                                headers.push((n.to_ascii_lowercase(), v.trim().to_owned()));
                            }
                        }
                        let find = |name: &str| {
                            headers
                                .iter()
                                .find(|(n, _)| n == name)
                                .map(|(_, v)| v.clone())
                        };
                        let upgrade =
                            find("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
                        let key = find("sec-websocket-key");
                        handshakes
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(headers.clone());
                        let (true, Some(key)) = (upgrade, key) else {
                            let _ = stream
                                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                                .await;
                            return;
                        };
                        let accept = accept_for(&key);
                        let mut answer = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-accept: {accept}\r\n"
                        );
                        if let Some(protocol) = find("sec-websocket-protocol") {
                            let first = protocol.split(',').next().unwrap_or("").trim().to_owned();
                            let _ = write!(answer, "sec-websocket-protocol: {first}\r\n");
                        }
                        answer.push_str("\r\n");
                        if stream.write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                        let mut buf = [0_u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if stream
                                        .write_all(buf.get(..n).unwrap_or_default())
                                        .await
                                        .is_err()
                                    {
                                        return;
                                    }
                                    let _ = stream.flush().await;
                                }
                            }
                        }
                    });
                }
            })
        };
        Self {
            addr,
            handshakes,
            task,
        }
    }

    pub(crate) fn handshakes(&self) -> Vec<Handshake> {
        self.handshakes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// RFC 6455 §4.2.2.
pub(crate) fn accept_for(key: &str) -> String {
    use base64::Engine as _;
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// A request body that never ends (the stream of an extended `CONNECT`).
pub(crate) fn open_body() -> ReqBody {
    http_body_util::StreamBody::new(futures_util::stream::pending::<
        Result<http_body::Frame<Bytes>, BoxError>,
    >())
    .boxed_unsync()
}

/// A server that speaks just enough HTTP/2 to hand over the first `HEADERS` block it is sent, as
/// the bytes on the wire (HPACK). It never answers.
pub(crate) async fn capture_first_headers_block(
    pki: &Pki,
    name: &str,
) -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
    JoinHandle<()>,
) {
    let mut config = Arc::into_inner(pki.server_config(name, super::Flaw::None)).unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return;
        };
        let mut preface = [0_u8; 24];
        if tls.read_exact(&mut preface).await.is_err() {
            return;
        }
        // Our SETTINGS, so that the client's connection is usable.
        let _ = tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
        loop {
            let mut head = [0_u8; 9];
            if tls.read_exact(&mut head).await.is_err() {
                return;
            }
            let len =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let mut payload = vec![0_u8; len];
            if tls.read_exact(&mut payload).await.is_err() {
                return;
            }
            if head[3] == 4 && head[4] & 1 == 0 {
                let _ = tls.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await;
            }
            if head[3] == 1 {
                let _ = tx.send(payload);
                // Hold the connection open so the proxy waits for an answer.
                std::future::pending::<()>().await;
                return;
            }
        }
    });
    (addr, rx, task)
}

/// One frame as it crossed the wire: its type, flags, stream and payload length.
pub(crate) type RawFrame = (u8, u8, u32, usize);

/// A server that speaks just enough HTTP/2 to keep a connection open and records every frame it
/// is sent (after the preface). With `answer_early` it answers each request's `HEADERS` with a
/// complete `200` at once, before the request body ends (which HTTP/2 allows); otherwise it never
/// answers.
pub(crate) async fn record_frames(
    pki: &Pki,
    name: &str,
    answer_early: bool,
) -> (SocketAddr, Arc<Mutex<Vec<RawFrame>>>, JoinHandle<()>) {
    let mut config = Arc::into_inner(pki.server_config(name, super::Flaw::None)).unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let frames = Arc::new(Mutex::new(Vec::new()));
    let task = {
        let frames = Arc::clone(&frames);
        tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut preface = [0_u8; 24];
            if tls.read_exact(&mut preface).await.is_err() {
                return;
            }
            let _ = tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await;
            loop {
                let mut head = [0_u8; 9];
                if tls.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len = (usize::from(head[0]) << 16)
                    | (usize::from(head[1]) << 8)
                    | usize::from(head[2]);
                let mut payload = vec![0_u8; len];
                if tls.read_exact(&mut payload).await.is_err() {
                    return;
                }
                if head[3] == 4 && head[4] & 1 == 0 {
                    let _ = tls.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0]).await;
                }
                let stream = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);
                if answer_early && head[3] == 1 {
                    // `:status 200` (HPACK static index 8), END_STREAM | END_HEADERS.
                    let mut answer = vec![0, 0, 1, 1, 0x5];
                    answer.extend_from_slice(&stream.to_be_bytes());
                    answer.push(0x88);
                    let _ = tls.write_all(&answer).await;
                }
                frames
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((head[3], head[4], stream, len));
            }
        })
    };
    (addr, frames, task)
}
