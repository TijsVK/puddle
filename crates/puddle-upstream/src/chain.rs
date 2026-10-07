// SPDX-License-Identifier: GPL-3.0-or-later
//! Connecting through the route [`Discovery`] picked (T-165): the hops in order, the `CONNECT`
//! and absolute-form exchanges with a proxy, and the `407` loop driven by [`ProxyAuth`].
//!
//! The caller (the sandbox proxy, the pull proxy, a host-side client) has already decided that
//! the connection may happen: the rules said yes and the resolved addresses passed the guard.
//! [`Chain`] only decides *how* to reach the destination, and keeps that decision from widening
//! what was checked:
//!
//! - a `DIRECT` hop connects only to an address in [`Request::checked`], never to a name;
//! - a proxy hop is told the destination **name** only when the caller says every address the
//!   name resolved to passed ([`Request::name_ok`]) or the name could not be resolved here at all
//!   (the company's proxy does the resolving, as in networks without external DNS). Otherwise it
//!   is sent a checked **address**, so a name that also resolves to a denied address cannot make
//!   the proxy connect there.
//!
//! Hop order and fallback follow PAC rules: a hop that cannot be reached (connect error, timeout,
//! closed or garbled answer) is reported to [`Discovery::report_failure`] and the next hop is
//! tried. A proxy that answers (`403`, `407` it cannot satisfy, `5xx`) ends the attempt: browsers
//! do not fail over on an answer, and silently going `DIRECT` after a refusal would bypass the
//! company's policy.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::{AuthSession, AuthStep, ProxyAuth};
use crate::discovery::Discovery;
use crate::hop::{Destination, Hop, ProxyAddr};
use crate::wire::{self, MAX_DRAIN, ResponseHead};

/// The host the authentication probe asks the proxy for. `.invalid` never resolves (RFC 6761), so
/// no origin server is ever contacted by it.
const PROBE_HOST: &str = "puddle.invalid";

/// Checked addresses tried per proxy when the proxy is sent an address and answers `5xx`.
const MAX_PINNED: usize = 4;

/// Timeouts and limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChainConfig {
    /// Connecting to one address (the proxy, or a checked address for `DIRECT`).
    pub connect_timeout: Duration,
    /// One request/response exchange with a proxy, so a proxy that accepts and never answers
    /// counts as down.
    pub head_timeout: Duration,
    /// `407` rounds before giving up (NTLM needs three legs; a proxy that keeps asking is
    /// broken or hostile).
    pub max_legs: usize,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            head_timeout: Duration::from_secs(15),
            max_legs: 6,
        }
    }
}

impl ChainConfig {
    /// The defaults with other timeouts.
    #[must_use]
    pub fn with_timeouts(mut self, connect: Duration, head: Duration) -> Self {
        self.connect_timeout = connect;
        self.head_timeout = head;
        self
    }
}

/// What the proxy is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Form {
    /// `CONNECT host:port`: the connection becomes a tunnel to the destination.
    Tunnel,
    /// A plain-HTTP request in absolute form follows on the returned connection.
    Absolute,
}

/// One connection to make.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Request<'a> {
    /// Where it is going. Its scheme and name pick the route (`Https` for a tunnel, `Http` for
    /// absolute form).
    pub destination: &'a Destination,
    /// Tunnel or absolute form.
    pub form: Form,
    /// The addresses the guard passed. `DIRECT` connects to these and nothing else.
    pub checked: &'a [SocketAddr],
    /// Whether a proxy may be told the destination's name (see the module documentation). Off by
    /// default: a proxy then gets a checked address.
    pub name_ok: bool,
}

impl<'a> Request<'a> {
    /// A request for `destination` that may use `checked` addresses; a proxy is sent an address.
    #[must_use]
    pub fn new(destination: &'a Destination, form: Form, checked: &'a [SocketAddr]) -> Self {
        Self {
            destination,
            form,
            checked,
            name_ok: false,
        }
    }

    /// Lets a proxy be told the destination's name.
    #[must_use]
    pub fn name_ok(mut self, ok: bool) -> Self {
        self.name_ok = ok;
        self
    }
}

/// A secret header value that never prints.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// The value, for the one place that sends it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A connection that is ready for the caller.
#[derive(Debug)]
#[non_exhaustive]
pub struct Connected {
    /// For [`Form::Tunnel`]: the tunnel, after the proxy's `200` (or the direct connection). For
    /// [`Form::Absolute`]: a connection to the proxy that is ready for the request.
    pub stream: TcpStream,
    /// The hop that worked, for the audit.
    pub hop: Hop,
    /// The address connected to, for a `DIRECT` hop.
    pub addr: Option<SocketAddr>,
    /// The authority (`host:port`, brackets for IPv6) the proxy was told, for a proxy hop. An
    /// absolute-form request puts it in its URI.
    pub authority: Option<String>,
    /// A `Proxy-Authorization` value every absolute-form request on `stream` must carry (Basic
    /// credentials are per request; connection-based schemes need no header after the probe).
    pub authorization: Option<Secret>,
}

/// Why no connection was made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// Every hop failed to connect. Each entry names the hop and why.
    #[error("no hop could be reached: {}", join(.tried))]
    Unreachable {
        /// The hops tried, with the reason for each.
        tried: Vec<(Hop, String)>,
    },
    /// A proxy answered the request with a refusal (`403`, `5xx`, ...). It is passed on, not
    /// retried elsewhere.
    #[error("proxy {proxy} answered {status} {reason}")]
    Refused {
        /// The proxy.
        proxy: ProxyAddr,
        /// Its status code.
        status: u16,
        /// Its reason phrase.
        reason: String,
    },
    /// A proxy wants authentication puddle cannot give (no implementation speaks the schemes it
    /// offers, or no credentials are configured).
    #[error("proxy {proxy} requires authentication ({})", schemes.join(", "))]
    AuthRequired {
        /// The proxy.
        proxy: ProxyAddr,
        /// The schemes it offers.
        schemes: Vec<String>,
    },
    /// Authentication was tried and failed (rejected credentials, a refused token, too many
    /// rounds).
    #[error("proxy {proxy} authentication failed: {why}")]
    AuthFailed {
        /// The proxy.
        proxy: ProxyAddr,
        /// What went wrong. Never contains a credential.
        why: String,
    },
}

fn join(tried: &[(Hop, String)]) -> String {
    tried
        .iter()
        .map(|(hop, why)| format!("{hop}: {why}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// What a hop attempt came to.
enum HopError {
    /// The proxy could not be used: mark it down and try the next hop.
    Down(String),
    /// Nothing was wrong with the hop, it just cannot serve this request (no address to send).
    Skip(String),
    /// The answer to give; no further hops.
    Final(ChainError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthState {
    /// The proxy let a request through without credentials.
    Open,
    /// The proxy asked for credentials.
    Required,
}

#[derive(Debug, Clone)]
struct Memo {
    epoch: u64,
    state: AuthState,
    /// The Basic header that worked, sent up front next time.
    basic: Option<String>,
}

/// Connects along the route [`Discovery`] picks, authenticating to proxies with [`ProxyAuth`].
/// Cheap to share: wrap in an [`Arc`].
#[derive(Debug)]
pub struct Chain {
    discovery: Arc<Discovery>,
    auth: Arc<dyn ProxyAuth>,
    config: ChainConfig,
    memo: Mutex<HashMap<ProxyAddr, Memo>>,
}

impl Chain {
    /// A chain over `discovery`, answering `407`s with `auth`.
    #[must_use]
    pub fn new(discovery: Arc<Discovery>, auth: Arc<dyn ProxyAuth>) -> Arc<Self> {
        Self::with_config(discovery, auth, ChainConfig::default())
    }

    /// Like [`Chain::new`] with other timeouts and limits.
    #[must_use]
    pub fn with_config(
        discovery: Arc<Discovery>,
        auth: Arc<dyn ProxyAuth>,
        config: ChainConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            discovery,
            auth,
            config,
            memo: Mutex::default(),
        })
    }

    /// The discovery in use.
    #[must_use]
    pub fn discovery(&self) -> &Arc<Discovery> {
        &self.discovery
    }

    /// Connects to `request.destination` over the first hop that works.
    ///
    /// # Errors
    /// [`ChainError`]: every hop unreachable, or a proxy's refusal or authentication failure.
    pub async fn connect(&self, request: &Request<'_>) -> Result<Connected, ChainError> {
        let decision = self.discovery.route(request.destination).await;
        tracing::debug!(route = %decision.route, source = ?decision.source, "route for connection");
        let mut tried = Vec::new();
        for hop in decision.route.hops() {
            match hop {
                Hop::Direct => match self.direct(request).await {
                    Ok(connected) => return Ok(connected),
                    Err(why) => tried.push((hop.clone(), why)),
                },
                Hop::Proxy(proxy) => match self.via(proxy, request).await {
                    Ok(connected) => return Ok(connected),
                    Err(HopError::Down(why)) => {
                        tracing::info!(%proxy, %why, "upstream proxy unreachable, trying the next hop");
                        self.discovery.report_failure(proxy);
                        tried.push((hop.clone(), why));
                    }
                    Err(HopError::Skip(why)) => tried.push((hop.clone(), why)),
                    Err(HopError::Final(error)) => return Err(error),
                },
            }
        }
        Err(ChainError::Unreachable { tried })
    }

    async fn direct(&self, request: &Request<'_>) -> Result<Connected, String> {
        if request.checked.is_empty() {
            return Err("no checked address to connect to".into());
        }
        let (stream, addr) = connect_first(request.checked, self.config.connect_timeout)
            .await
            .map_err(|err| err.to_string())?;
        Ok(Connected {
            stream,
            hop: Hop::Direct,
            addr: Some(addr),
            authority: None,
            authorization: None,
        })
    }

    async fn via(&self, proxy: &ProxyAddr, request: &Request<'_>) -> Result<Connected, HopError> {
        let targets: Vec<String> = if request.name_ok {
            vec![authority(
                request.destination.host(),
                request.destination.port(),
            )]
        } else {
            request
                .checked
                .iter()
                .take(MAX_PINNED)
                .map(ToString::to_string)
                .collect()
        };
        if targets.is_empty() {
            return Err(HopError::Skip(
                "no checked address to send the proxy".into(),
            ));
        }
        let mut last = HopError::Skip("nothing to try".into());
        for target in targets {
            match self.exchange(proxy, request.form, &target).await {
                Ok(connected) => return Ok(connected),
                // The proxy could not reach this address: the next checked one may work. A name
                // is one target, so this is the end for it.
                Err(HopError::Final(ChainError::Refused { status, .. }))
                    if (500..=599).contains(&status) && !request.name_ok =>
                {
                    last = HopError::Final(ChainError::Refused {
                        proxy: proxy.clone(),
                        status,
                        reason: "upstream error".into(),
                    });
                }
                Err(other) => return Err(other),
            }
        }
        Err(last)
    }

    fn memo(&self, proxy: &ProxyAddr) -> Option<Memo> {
        let epoch = self.discovery.epoch();
        self.memo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(proxy)
            .filter(|m| m.epoch == epoch)
            .cloned()
    }

    fn remember(&self, proxy: &ProxyAddr, state: AuthState, basic: Option<String>) {
        let epoch = self.discovery.epoch();
        self.memo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                proxy.clone(),
                Memo {
                    epoch,
                    state,
                    basic,
                },
            );
    }

    fn forget_basic(&self, proxy: &ProxyAddr) {
        if let Some(memo) = self
            .memo
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(proxy)
        {
            memo.basic = None;
        }
    }

    async fn dial(&self, proxy: &ProxyAddr) -> Result<TcpStream, HopError> {
        let connect = TcpStream::connect((proxy.host(), proxy.port()));
        let stream = match tokio::time::timeout(self.config.connect_timeout, connect).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => return Err(HopError::Down(format!("connect failed: {err}"))),
            Err(_) => return Err(HopError::Down("connect timed out".into())),
        };
        if let Err(err) = stream.set_nodelay(true) {
            tracing::debug!(error = %err, "nodelay");
        }
        Ok(stream)
    }

    /// One request to `proxy`, with as many `407` rounds as it takes.
    async fn exchange(
        &self,
        proxy: &ProxyAddr,
        form: Form,
        authority: &str,
    ) -> Result<Connected, HopError> {
        let failed = |why: String| {
            HopError::Final(ChainError::AuthFailed {
                proxy: proxy.clone(),
                why,
            })
        };
        let memo = self.memo(proxy);
        let mut header = memo.as_ref().and_then(|m| m.basic.clone());
        let mut session: Option<Box<dyn AuthSession>> = None;
        let mut preemptive = false;
        if header.is_none()
            && let Some(mut started) = self
                .auth
                .begin(proxy, &[])
                .map_err(|e| failed(e.to_string()))?
        {
            // A scheme that signs in without being asked (Kerberos): the first leg has no challenge.
            if let AuthStep::Authorization(value) =
                started.step(None).map_err(|e| failed(e.to_string()))?
            {
                header = Some(value);
            }
            session = Some(started);
            preemptive = true;
        }
        let mut stream = self.dial(proxy).await?;
        if form == Form::Absolute
            && header.is_none()
            && memo.as_ref().is_some_and(|m| m.state == AuthState::Open)
        {
            // Known to need nothing: no probe round trip.
            return Ok(connected(stream, proxy, authority, None));
        }
        let mut legs = 0;
        loop {
            let head = self
                .round(&mut stream, form, authority, header.as_deref())
                .await?;
            if head.status != 407 {
                return self
                    .finish(proxy, form, authority, stream, &head, header)
                    .await;
            }
            legs += 1;
            if legs > self.config.max_legs {
                return Err(failed(format!("the proxy asked {legs} times")));
            }
            let challenges = head.challenges();
            if challenges.is_empty() {
                return Err(failed("407 without a Proxy-Authenticate header".into()));
            }
            let offered_owned = wire::schemes(&challenges);
            // A preemptive session (Negotiate sent unasked) met a 407: ask again with what the proxy
            // actually offers, so a Basic-only proxy still works on the first request. Keep the
            // preemptive session when nothing else can answer.
            if session.is_none() || preemptive {
                let offered: Vec<&str> = offered_owned.iter().map(String::as_str).collect();
                preemptive = false;
                match self.auth.begin(proxy, &offered) {
                    Ok(Some(started)) => session = Some(started),
                    Ok(None) if session.is_some() => {}
                    Ok(None) => {
                        return Err(HopError::Final(ChainError::AuthRequired {
                            proxy: proxy.clone(),
                            schemes: offered_owned,
                        }));
                    }
                    Err(err) => return Err(failed(err.to_string())),
                }
            }
            let combined = challenges.join(", ");
            let step = match session.as_mut() {
                Some(session) => session.step(Some(&combined)),
                None => return Err(failed("no session".into())),
            };
            match step {
                Ok(AuthStep::Authorization(value)) => header = Some(value),
                Ok(_) => {
                    return Err(failed(
                        "the proxy asked again after authentication was complete".into(),
                    ));
                }
                Err(err) => {
                    self.forget_basic(proxy);
                    return Err(failed(err.to_string()));
                }
            }
            // Same connection for the next leg when the proxy allows it (NTLM needs it); a fresh
            // one otherwise (Basic does not care).
            let reusable = head.keeps_alive()
                && match (form, head.content_length()) {
                    // A HEAD answer has no body, whatever Content-Length says.
                    (Form::Absolute, _) => true,
                    (Form::Tunnel, Some(n)) if n <= MAX_DRAIN => {
                        drain(&mut stream, n, self.config.head_timeout).await
                    }
                    (Form::Tunnel, _) => false,
                };
            if !reusable {
                stream = self.dial(proxy).await?;
            }
        }
    }

    /// One request and its response head, within the head timeout.
    async fn round(
        &self,
        stream: &mut TcpStream,
        form: Form,
        authority: &str,
        header: Option<&str>,
    ) -> Result<ResponseHead, HopError> {
        let request = request_bytes(form, authority, header);
        let exchange = async {
            stream.write_all(&request).await?;
            wire::read_response_head(stream).await
        };
        match tokio::time::timeout(self.config.head_timeout, exchange).await {
            Ok(Ok(head)) => Ok(head),
            Ok(Err(err)) => Err(HopError::Down(format!("no usable answer: {err}"))),
            Err(_) => Err(HopError::Down("no answer in time".into())),
        }
    }

    async fn finish(
        &self,
        proxy: &ProxyAddr,
        form: Form,
        authority: &str,
        mut stream: TcpStream,
        head: &ResponseHead,
        header: Option<String>,
    ) -> Result<Connected, HopError> {
        if form == Form::Tunnel && !(200..300).contains(&head.status) {
            return Err(HopError::Final(ChainError::Refused {
                proxy: proxy.clone(),
                status: head.status,
                reason: head.reason.clone(),
            }));
        }
        let basic = header.clone().filter(|h| is_basic(h));
        match &header {
            // A refusal (`403`) before authentication says nothing about whether credentials
            // are needed: do not remember the proxy as open, probe again next time.
            None if form == Form::Absolute && (400..500).contains(&head.status) => {
                tracing::warn!(%proxy, status = head.status, "authentication probe was refused before a login was asked for");
            }
            None => self.remember(proxy, AuthState::Open, None),
            Some(_) => self.remember(proxy, AuthState::Required, basic.clone()),
        }
        if form == Form::Absolute && !head.keeps_alive() {
            if header.is_some() && basic.is_none() {
                // The probe authenticated this connection and the proxy now closes it: a
                // connection-based scheme cannot carry the request.
                return Err(HopError::Final(ChainError::AuthFailed {
                    proxy: proxy.clone(),
                    why: "the proxy closes the connection after each answer, so connection-based authentication cannot carry a plain-HTTP request".into(),
                }));
            }
            // Basic and "no authentication" carry no connection state: dial again.
            stream = self.dial(proxy).await?;
        }
        Ok(connected(stream, proxy, authority, basic))
    }
}

fn connected(
    stream: TcpStream,
    proxy: &ProxyAddr,
    authority: &str,
    authorization: Option<String>,
) -> Connected {
    Connected {
        stream,
        hop: Hop::Proxy(proxy.clone()),
        addr: None,
        authority: Some(authority.to_owned()),
        authorization: authorization.map(Secret),
    }
}

fn is_basic(header: &str) -> bool {
    header
        .split_once(' ')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
}

/// `host:port`, with brackets around an IPv6 literal.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn request_bytes(form: Form, authority: &str, header: Option<&str>) -> Vec<u8> {
    let mut out = match form {
        Form::Tunnel => format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"),
        // The destination's own port: proxies commonly deny other ports before they authenticate,
        // which would hide the `407` the probe is there to provoke.
        Form::Absolute => {
            let port = authority.rsplit_once(':').map_or("80", |(_, port)| port);
            format!("HEAD http://{PROBE_HOST}:{port}/ HTTP/1.1\r\nHost: {PROBE_HOST}:{port}\r\n")
        }
    };
    out.push_str("Proxy-Connection: keep-alive\r\n");
    if let Some(value) = header {
        out.push_str("Proxy-Authorization: ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Reads and discards `len` bytes. False when the proxy cannot deliver them in time.
async fn drain(stream: &mut TcpStream, len: usize, within: Duration) -> bool {
    let mut left = len;
    let mut sink = [0_u8; 4096];
    let read = async {
        while left > 0 {
            let want = left.min(sink.len());
            let Some(buf) = sink.get_mut(..want) else {
                return false;
            };
            match stream.read(buf).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => left -= n,
            }
        }
        true
    };
    tokio::time::timeout(within, read).await.unwrap_or(false)
}

/// Connects to the first address that answers within `per_address`.
///
/// # Errors
/// The last connect error, or [`io::ErrorKind::NotFound`] for an empty list.
pub async fn connect_first(
    addrs: &[SocketAddr],
    per_address: Duration,
) -> io::Result<(TcpStream, SocketAddr)> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    for addr in addrs {
        match tokio::time::timeout(per_address, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                if let Err(err) = stream.set_nodelay(true) {
                    tracing::debug!(error = %err, "nodelay");
                }
                return Ok((stream, *addr));
            }
            Ok(Err(err)) => last = err,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}
