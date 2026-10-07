// SPDX-License-Identifier: GPL-3.0-or-later
//! [`FakeProxy`]: a scripted HTTP proxy on loopback for tests (feature `testing`). It speaks just
//! enough of a company proxy to drive the chain: `CONNECT` spliced to a local target, absolute-form
//! requests, Basic and NTLM-shaped `407` rounds, refusals, silence and garbage.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::hop::ProxyAddr;

/// How the fake proxy treats requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Behaviour {
    /// No authentication.
    Open,
    /// Basic authentication with these credentials; offers only `Basic`.
    Basic {
        /// The user.
        user: String,
        /// The password.
        password: String,
    },
    /// Three-leg NTLM-shaped authentication per connection (`NTLM T1`, then `NTLM T3`); offers
    /// only `NTLM`.
    Ntlm,
    /// Like [`Behaviour::Ntlm`] but closes the connection after every `407`.
    NtlmClosing,
    /// Answers every request with this status and closes.
    Refuse(u16),
    /// Always `407` offering Basic, whatever the credentials.
    Always407,
    /// Accepts and never answers.
    Silent,
    /// Answers with bytes that are not HTTP.
    Garbage,
}

/// One request the fake proxy received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The connection number (from 1).
    pub conn: usize,
    /// `CONNECT`, `GET`, `HEAD`, ...
    pub method: String,
    /// The request target as sent.
    pub target: String,
    /// The `Proxy-Authorization` value, if sent.
    pub proxy_authorization: Option<String>,
    /// Every header, names lower-cased.
    pub headers: Vec<(String, String)>,
}

/// A scripted proxy. Dropping it stops it.
#[derive(Debug)]
pub struct FakeProxy {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    conns: Arc<AtomicUsize>,
    names: Arc<Mutex<HashMap<String, SocketAddr>>>,
    task: JoinHandle<()>,
}

impl FakeProxy {
    /// Starts a proxy on a loopback port.
    ///
    /// # Panics
    /// When no loopback port can be bound.
    #[expect(
        clippy::panic,
        reason = "a test double: failing to bind fails the test"
    )]
    pub async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|err| panic!("fake proxy cannot bind: {err}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("fake proxy has no address: {err}"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let conns = Arc::new(AtomicUsize::new(0));
        let names = Arc::new(Mutex::new(HashMap::new()));
        let shared = Shared {
            behaviour,
            seen: Arc::clone(&seen),
            names: Arc::clone(&names),
        };
        let counter = Arc::clone(&conns);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let number = counter.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(serve(shared.clone(), stream, number));
            }
        });
        Self {
            addr,
            seen,
            conns,
            names,
            task,
        }
    }

    /// Where it listens.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The same as a hop's proxy address.
    #[must_use]
    pub fn proxy_addr(&self) -> ProxyAddr {
        ProxyAddr::new("127.0.0.1", self.addr.port())
    }

    /// A name this proxy resolves for `CONNECT` (split DNS: only the proxy knows it).
    pub fn resolve_name(&self, name: &str, to: SocketAddr) {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), to);
    }

    /// Every request received so far.
    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// TCP connections accepted so far.
    #[must_use]
    pub fn connections(&self) -> usize {
        self.conns.load(Ordering::SeqCst)
    }
}

impl Drop for FakeProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Shared {
    behaviour: Behaviour,
    seen: Arc<Mutex<Vec<Seen>>>,
    names: Arc<Mutex<HashMap<String, SocketAddr>>>,
}

struct Req {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

async fn read_req(reader: &mut BufReader<TcpStream>) -> Option<Req> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        if reader.read_line(&mut l).await.ok()? == 0 {
            return None;
        }
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        let (n, v) = l.split_once(':')?;
        headers.push((n.trim().to_ascii_lowercase(), v.trim().to_owned()));
    }
    Some(Req {
        method,
        target,
        headers,
    })
}

fn response(status: &str, headers: &[(&str, &str)], body: &str, head_only: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (n, v) in headers {
        let _ = write!(out, "{n}: {v}\r\n");
    }
    let _ = write!(out, "Content-Length: {}\r\n\r\n", body.len());
    if !head_only {
        out.push_str(body);
    }
    out.into_bytes()
}

#[expect(
    clippy::too_many_lines,
    reason = "one scripted state machine, clearer in one place"
)]
async fn serve(shared: Shared, stream: TcpStream, number: usize) {
    if matches!(shared.behaviour, Behaviour::Silent) {
        // Hold the connection open without a word.
        let mut stream = stream;
        let mut sink = [0_u8; 64];
        while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        return;
    }
    let mut reader = BufReader::new(stream);
    let mut ntlm_authed = false;
    let mut t1_seen = false;
    while let Some(req) = read_req(&mut reader).await {
        let authorization = req.header("proxy-authorization").map(ToOwned::to_owned);
        shared
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Seen {
                conn: number,
                method: req.method.clone(),
                target: req.target.clone(),
                proxy_authorization: authorization.clone(),
                headers: req.headers.clone(),
            });
        let head_only = req.method == "HEAD";
        let challenge = |scheme: &str| {
            // Real proxies send the length of the body a GET would have had, even for HEAD.
            let mut out = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {scheme}\r\nContent-Length: 6\r\n\r\n"
            );
            if !head_only {
                out.push_str("denied");
            }
            out.into_bytes()
        };
        let reply: Option<Vec<u8>> = match &shared.behaviour {
            Behaviour::Basic { user, password } => {
                let expected = format!("Basic {}", BASE64.encode(format!("{user}:{password}")));
                (authorization.as_deref() != Some(expected.as_str()))
                    .then(|| challenge("Basic realm=\"fake\""))
            }
            Behaviour::Ntlm | Behaviour::NtlmClosing => match authorization.as_deref() {
                // The last token only counts on the connection that saw the first.
                Some("NTLM T3") if t1_seen => {
                    ntlm_authed = true;
                    None
                }
                Some("NTLM T1") => {
                    t1_seen = true;
                    Some(challenge("NTLM CHALLENGE"))
                }
                _ if ntlm_authed => None,
                _ => Some(challenge("NTLM")),
            },
            Behaviour::Always407 => Some(challenge("Basic realm=\"fake\"")),
            Behaviour::Refuse(status) => Some(response(
                &format!("{status} Refused"),
                &[("Connection", "close")],
                "refused",
                false,
            )),
            Behaviour::Garbage => Some(b"\x00\x01 this is not http\r\n\r\n".to_vec()),
            Behaviour::Open | Behaviour::Silent => None,
        };
        if let Some(bytes) = reply {
            let closing = matches!(
                shared.behaviour,
                Behaviour::NtlmClosing | Behaviour::Refuse(_) | Behaviour::Garbage
            );
            let stream = reader.get_mut();
            if closing && matches!(shared.behaviour, Behaviour::NtlmClosing) {
                let text = String::from_utf8_lossy(&bytes)
                    .replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n");
                let _ = stream.write_all(text.as_bytes()).await;
            } else {
                let _ = stream.write_all(&bytes).await;
            }
            let _ = stream.flush().await;
            if closing {
                let _ = stream.shutdown().await;
                return;
            }
            continue;
        }
        if req.method == "CONNECT" {
            tunnel(&shared, reader, &req.target).await;
            return;
        }
        let (status, body) = if req.target.contains("puddle.invalid") {
            ("503 Service Unavailable", String::new())
        } else {
            ("200 OK", format!("via-proxy {}", req.target))
        };
        let bytes = response(status, &[], &body, req.method == "HEAD");
        if reader.get_mut().write_all(&bytes).await.is_err() {
            return;
        }
        // A request body is not expected in these tests.
        let closes = req
            .header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));
        if closes || req.header("content-length").is_some() {
            let _ = reader.get_mut().shutdown().await;
            return;
        }
    }
}

async fn tunnel(shared: &Shared, mut reader: BufReader<TcpStream>, target: &str) {
    let resolved = target.parse::<SocketAddr>().ok().or_else(|| {
        let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
        shared
            .names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(host)
            .copied()
    });
    let Some(resolved) = resolved else {
        let _ = reader
            .get_mut()
            .write_all(&response(
                "502 Bad Gateway",
                &[("Connection", "close")],
                "no such host",
                false,
            ))
            .await;
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(resolved).await else {
        let _ = reader
            .get_mut()
            .write_all(&response(
                "502 Bad Gateway",
                &[("Connection", "close")],
                "cannot connect",
                false,
            ))
            .await;
        return;
    };
    let early = reader.buffer().to_vec();
    let mut client = reader.into_inner();
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .is_err()
        || upstream.write_all(&early).await.is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}
