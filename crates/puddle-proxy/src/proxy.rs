// SPDX-License-Identifier: GPL-3.0-or-later
//! One proxied guest connection: read the request head, decide, connect, splice.
//!
//! The order matters for security: the head is bounded in size and time before anything else;
//! the rules engine decides on the normalised name **before** it is resolved (R-10, EG-8); every
//! resolved address is checked (R-14) and the proxy connects only to an address that passed.
//! Every refusal is an HTTP error response followed by a clean close (a reset could overtake the
//! response, T-111); every failure after the connection is open is passed on as a reset (T-048).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use puddle_agent_proto::host::{GuestStream, HostConfig, StreamHandler};
use puddle_agent_proto::relay::splice;
use puddle_types::{
    BlockReason, ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionReason, Decision,
    EgressRequest, EventSink, Host, HttpRequestLine, NullConnectionLog, PatternKind,
    PendingOutcome, Policy, PolicyError, ProtocolHint, SandboxName, SuffixAllows,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::Instrument;

use puddle_netpolicy::{LocalAccess, LocalCategory, NetPolicy, block_message, normalise_host};

use crate::counted::Counted;
use crate::destination::{AddressCheck, AddressVerdict, Resolver, SystemResolver};
use crate::http::{self, Body, Head, HeadError, RawTarget};
use crate::target::Target;

/// Limits and timeouts. The defaults suit a real guest; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// How long a guest may take to send its whole request head (slow-loris guard). Over it:
    /// `408`.
    pub head_timeout: Duration,
    /// How long resolving an allowed name may take. Over it: `504`.
    pub resolve_timeout: Duration,
    /// How long connecting to one address may take before the next is tried. All failed: `502`.
    pub connect_timeout: Duration,
    /// Proxied connections one sandbox may have open at once. Over it: `503`. Far above what
    /// real tools open (D-2: pnpm, `BuildKit` and `NuGet` peak in the hundreds).
    pub max_streams_per_sandbox: usize,
    /// Agent connections (yamux sessions) one route accepts at once. The agent opens 1 to 64.
    pub max_sessions_per_route: usize,
    /// Per-session limits of the agent protocol.
    pub session: HostConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            head_timeout: Duration::from_secs(30),
            resolve_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            max_streams_per_sandbox: 4096,
            max_sessions_per_route: 128,
            session: HostConfig::default(),
        }
    }
}

impl ProxyConfig {
    /// The default limits with another head timeout.
    #[must_use]
    pub fn with_head_timeout(mut self, timeout: Duration) -> Self {
        self.head_timeout = timeout;
        self
    }

    /// The default limits with another per-sandbox stream cap.
    #[must_use]
    pub fn with_max_streams_per_sandbox(mut self, max: usize) -> Self {
        self.max_streams_per_sandbox = max;
        self
    }

    /// The default limits with another per-route session cap.
    #[must_use]
    pub fn with_max_sessions_per_route(mut self, max: usize) -> Self {
        self.max_sessions_per_route = max;
        self
    }

    /// The default limits with other resolve and connect timeouts.
    #[must_use]
    pub fn with_network_timeouts(mut self, resolve: Duration, connect: Duration) -> Self {
        self.resolve_timeout = resolve;
        self.connect_timeout = connect;
        self
    }

    /// The default limits with other agent-session limits.
    #[must_use]
    pub fn with_session(mut self, session: HostConfig) -> Self {
        self.session = session;
        self
    }
}

/// The egress proxy: one per puddle process, shared by every sandbox's route.
///
/// ```
/// # use std::sync::Arc;
/// # use puddle_proxy::Proxy;
/// # use puddle_types::{Decision, EgressRequest, NullSink, Policy, PolicyError, SuffixAllows};
/// # struct Store;
/// # impl Policy for Store {
/// #     fn decide(&self, _: &EgressRequest, _: SuffixAllows) -> Result<Decision, PolicyError> {
/// #         Err(PolicyError { reason: "demo".into() })
/// #     }
/// # }
/// let proxy = Arc::new(Proxy::new(Arc::new(Store), Arc::new(NullSink)));
/// # let _ = proxy;
/// ```
pub struct Proxy {
    policy: Arc<dyn Policy>,
    resolver: Arc<dyn Resolver>,
    addresses: Arc<dyn AddressCheck>,
    log: Arc<dyn ConnectionLog>,
    pub(crate) sink: Arc<dyn EventSink>,
    pub(crate) config: ProxyConfig,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// A proxy that asks `policy`, resolves with the OS resolver, and reports agent events (OOM
    /// kills) to `sink`. Its address check is a [`NetPolicy`] with every local toggle off and no
    /// registered endpoints: public addresses only. The host program passes its own
    /// [`NetPolicy`] (settings-backed toggles, puddle's endpoint registry) with
    /// [`Self::with_address_check`], and its audit (the store) with
    /// [`Self::with_connection_log`]; until then connections are not recorded.
    #[must_use]
    pub fn new(policy: Arc<dyn Policy>, sink: Arc<dyn EventSink>) -> Self {
        Self {
            policy,
            resolver: Arc::new(SystemResolver),
            addresses: Arc::new(NetPolicy::new(Arc::new(LocalAccess::NONE))),
            log: Arc::new(NullConnectionLog),
            sink,
            config: ProxyConfig::default(),
        }
    }

    /// Uses `resolver` for allowed names.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Uses `check` for resolved addresses.
    #[must_use]
    pub fn with_address_check(mut self, check: Arc<dyn AddressCheck>) -> Self {
        self.addresses = check;
        self
    }

    /// Reports every connection that got as far as a destination to `log` (the store's
    /// `connection` audit records, R-24): one event when it ends, with its decision, the address
    /// connected to and the bytes each way.
    #[must_use]
    pub fn with_connection_log(mut self, log: Arc<dyn ConnectionLog>) -> Self {
        self.log = log;
        self
    }

    /// Uses `config` for limits and timeouts.
    #[must_use]
    pub fn with_config(mut self, config: ProxyConfig) -> Self {
        self.config = config;
        self
    }

    /// The limits in use.
    #[must_use]
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    /// The [`StreamHandler`] for one sandbox's route. `sandbox` comes from the route, never from
    /// the guest (HO-3). Each handler has its own stream cap, so give each route one handler.
    #[must_use]
    pub fn handler(self: &Arc<Self>, sandbox: SandboxName) -> SandboxHandler {
        SandboxHandler {
            proxy: Arc::clone(self),
            streams: Arc::new(Semaphore::new(self.config.max_streams_per_sandbox)),
            sandbox,
        }
    }

    async fn decide(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Decision, PolicyError> {
        if request.protocol == Some(ProtocolHint::Ssh) {
            return Ok(Decision::Blocked {
                reason: BlockReason::SshUnsupported,
            });
        }
        let policy = Arc::clone(&self.policy);
        let request = request.clone();
        // A miss writes a pending row, so the call may block on SQLite.
        tokio::task::spawn_blocking(move || policy.decide(&request, suffix_allows))
            .await
            .unwrap_or_else(|_| {
                Err(PolicyError {
                    reason: "policy task failed".into(),
                })
            })
    }

    /// Hands `event` to the connection log on a blocking thread (it may write to SQLite).
    async fn record(&self, event: ConnectionEvent) {
        let log = Arc::clone(&self.log);
        if tokio::task::spawn_blocking(move || log.record(&event))
            .await
            .is_err()
        {
            tracing::warn!("connection log panicked; record lost");
        }
    }
}

/// Serves the proxied connections of one sandbox. Made by [`Proxy::handler`].
#[derive(Debug, Clone)]
pub struct SandboxHandler {
    proxy: Arc<Proxy>,
    streams: Arc<Semaphore>,
    sandbox: SandboxName,
}

impl SandboxHandler {
    /// The sandbox this handler serves.
    #[must_use]
    pub fn sandbox(&self) -> &SandboxName {
        &self.sandbox
    }
}

impl StreamHandler for SandboxHandler {
    async fn handle(&self, stream: GuestStream) {
        let span = tracing::debug_span!("conn", sandbox = %self.sandbox);
        serve(self, stream).instrument(span).await;
    }
}

/// An error response: status, extra headers, a one-line explanation for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) status: &'static str,
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) message: String,
}

impl Refusal {
    fn new(status: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            message: message.into(),
        }
    }

    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    fn bytes(&self) -> Vec<u8> {
        let body = format!("puddle: {}\n", self.message);
        let mut out = format!(
            "HTTP/1.1 {}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\n",
            self.status,
            body.len()
        );
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("connection: close\r\n\r\n");
        out.push_str(&body);
        out.into_bytes()
    }
}

/// Sends `refusal` and closes the stream cleanly: a refusal is a normal end, and dropping the
/// stream without the shutdown would reset it, which can reach the client before the response.
async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, refusal: &Refusal) {
    let sent = async {
        stream.write_all(&refusal.bytes()).await?;
        stream.shutdown().await
    };
    if let Err(err) = sent.await {
        tracing::debug!(error = %err, "guest went away before the refusal was sent");
    }
}

async fn serve(handler: &SandboxHandler, stream: GuestStream) {
    let proxy = &handler.proxy;
    let (stream, counts) = Counted::new(stream);
    let mut reader = BufReader::new(stream);
    let Ok(_permit) = Arc::clone(&handler.streams).try_acquire_owned() else {
        tracing::warn!(
            limit = proxy.config.max_streams_per_sandbox,
            "connection refused: sandbox over its connection limit"
        );
        let limit = proxy.config.max_streams_per_sandbox;
        let refusal = Refusal::new(
            "503 Service Unavailable",
            format!("too many open connections from this sandbox (limit {limit})"),
        );
        refuse(reader.get_mut(), &refusal).await;
        return;
    };
    let head = match read_request(&mut reader, proxy.config.head_timeout).await {
        Ok(head) => head,
        Err(None) => return,
        Err(Some(refusal)) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    let (target, path, body) = match parse_request(&head) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    let mut request = EgressRequest::new(handler.sandbox.clone(), target.host.clone(), target.port);
    if path.is_some() {
        request = request.with_protocol(ProtocolHint::Http);
    }
    let mut event = relay(proxy, reader, &request, &head, &target, path, body).await;
    event.bytes_up = counts.read();
    event.bytes_down = counts.written();
    proxy.record(event).await;
}

/// Decides, connects and relays one request whose destination is known; returns what the audit
/// records about it (bytes are filled in by the caller once the stream is gone).
async fn relay(
    proxy: &Proxy,
    mut reader: GuestReader,
    request: &EgressRequest,
    head: &Head,
    target: &Target,
    path: Option<String>,
    body: Body,
) -> ConnectionEvent {
    let (admitted, mut event) = admit(proxy, request).await;
    if let Some(path) = &path {
        event.http = Some(HttpRequestLine::new(head.method.as_str(), path));
    }
    let addrs = match admitted {
        Ok(addrs) => addrs,
        Err(refusal) => {
            refuse(reader.get_mut(), &refusal).await;
            return event;
        }
    };
    let (server, addr) = match connect_first(&addrs, proxy.config.connect_timeout).await {
        Ok(connected) => connected,
        Err(err) => {
            tracing::info!(host = %target.host, port = target.port, error = %err, "upstream connect failed");
            let refusal = Refusal::new(
                "502 Bad Gateway",
                format!("could not connect to {}:{}", target.host, target.port),
            );
            refuse(reader.get_mut(), &refusal).await;
            return event;
        }
    };
    tracing::debug!(host = %target.host, port = target.port, %addr, "connected");
    event.resolved_ip = Some(addr.ip());
    match path {
        None => tunnel(reader, server).await,
        Some(path) => forward(reader, server, head, &path, target, body).await,
    }
    event
}

/// The guest side of one proxied stream, counted for the audit.
type GuestReader = BufReader<Counted<GuestStream>>;

/// Reads the head within `limit`. `Err(None)`: the guest closed or failed before a request, so
/// there is no one to answer.
async fn read_request(reader: &mut GuestReader, limit: Duration) -> Result<Head, Option<Refusal>> {
    match tokio::time::timeout(limit, http::read_head(reader)).await {
        Err(_) => Err(Some(Refusal::new(
            "408 Request Timeout",
            format!("request head not received within {}s", limit.as_secs()),
        ))),
        Ok(Err(err)) => {
            tracing::debug!(error = %err, "guest stream failed before a request");
            Err(None)
        }
        Ok(Ok(Err(HeadError::Empty))) => Err(None),
        Ok(Ok(Err(HeadError::TooLarge))) => Err(Some(Refusal::new(
            "431 Request Header Fields Too Large",
            format!("request head over {} KiB", http::MAX_HEAD / 1024),
        ))),
        Ok(Ok(Err(HeadError::Bad(why)))) => Err(Some(Refusal::new("400 Bad Request", why))),
        Ok(Ok(Ok(head))) => Ok(head),
    }
}

/// The normalised target, the origin-form path for a plain-HTTP request, and its body framing.
fn parse_request(head: &Head) -> Result<(Target, Option<String>, Body), Refusal> {
    let RawTarget { host, port, path } =
        http::parse_target(&head.method, &head.uri).map_err(|why| {
            Refusal::new(
                "400 Bad Request",
                format!(
                    "{why}; point the client at this proxy (CONNECT or an absolute http:// URI)"
                ),
            )
        })?;
    let host = normalise_host(&host)
        .map_err(|why| Refusal::new("400 Bad Request", why.to_string()))?
        .into_host();
    let body = if head.is_connect() {
        Body::None
    } else {
        http::body_framing(&head.headers).map_err(|why| Refusal::new("400 Bad Request", why))?
    };
    Ok((Target { host, port }, path, body))
}

/// Decides the request and, if allowed, returns the addresses it may connect to (R-10, R-14),
/// with the audit event for the decision.
pub(crate) async fn admit(
    proxy: &Proxy,
    request: &EgressRequest,
) -> (Result<Vec<SocketAddr>, Refusal>, ConnectionEvent) {
    // Replaced by the first step that decides; a path that forgets to stays fail-closed in the
    // audit too.
    let mut event = ConnectionEvent::new(
        request,
        ConnectionDecision::Blocked,
        ConnectionReason::PolicyUnavailable,
    );
    let admitted = admit_into(proxy, request, &mut event).await;
    (admitted, event)
}

/// Records each decision `admit` takes in `event`.
fn note(
    event: &mut ConnectionEvent,
    request: &EgressRequest,
    decided: &Result<Decision, PolicyError>,
) {
    *event = match decided {
        Ok(decision) => ConnectionEvent::decided(request, decision),
        Err(_) => ConnectionEvent::new(
            request,
            ConnectionDecision::Blocked,
            ConnectionReason::PolicyUnavailable,
        ),
    };
}

/// Marks `event` blocked for `reason`, keeping the rule that allowed the name, if any.
fn note_block(event: &mut ConnectionEvent, reason: BlockReason) {
    event.decision = ConnectionDecision::Blocked;
    event.reason = ConnectionReason::Blocked(reason);
    event.pending_id = None;
}

async fn admit_into(
    proxy: &Proxy,
    request: &EgressRequest,
    event: &mut ConnectionEvent,
) -> Result<Vec<SocketAddr>, Refusal> {
    let host = &request.host;
    let port = request.port;
    // Name stage: a literal or a name that is blocked by itself never reaches the rules, so it
    // never becomes a pending row (R-14).
    let target = puddle_netpolicy::Target::from_host(host.clone());
    if let Some(reason) = proxy
        .addresses
        .check_target(&request.sandbox, &target, port)
    {
        note_block(event, reason);
        return Err(block(request, &[reason]));
    }
    let decided = proxy.decide(request, SuffixAllows::Count).await;
    note(event, request, &decided);
    let pattern = allowed(request, decided)?;
    let addrs = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Name(name) => {
            match tokio::time::timeout(
                proxy.config.resolve_timeout,
                proxy.resolver.resolve(name, port),
            )
            .await
            {
                Err(_) => {
                    return Err(Refusal::new(
                        "504 Gateway Timeout",
                        format!("resolving {host} timed out"),
                    ));
                }
                Ok(Err(err)) => {
                    tracing::info!(%host, error = %err, "resolve failed");
                    return Err(Refusal::new(
                        "502 Bad Gateway",
                        format!("could not resolve {host}"),
                    ));
                }
                Ok(Ok(addrs)) => addrs,
            }
        }
    };
    if addrs.is_empty() {
        return Err(Refusal::new(
            "502 Bad Gateway",
            format!("{host} has no addresses"),
        ));
    }
    let mut usable = Vec::new();
    let mut exact_only = Vec::new();
    let mut categories: Vec<LocalCategory> = Vec::new();
    let mut blocked = Vec::new();
    for addr in addrs {
        match proxy.addresses.check(&request.sandbox, addr) {
            AddressVerdict::Allow => usable.push(addr),
            AddressVerdict::ExactOnly(category) => {
                exact_only.push(addr);
                categories.push(category);
            }
            AddressVerdict::Block(reason) => blocked.push(reason),
            other => {
                tracing::warn!(%addr, verdict = ?other, "unknown address verdict, address dropped");
                blocked.push(BlockReason::LocalAddress);
            }
        }
    }
    if pattern == PatternKind::Exact {
        // An exact allow reaches local addresses whose toggle is on (D-37).
        usable.append(&mut exact_only);
    } else if !exact_only.is_empty() {
        // After a wildcard allow, a local address whose toggle is on needs an exact allow of its
        // own (R-14, D-44): an exact rule for the address itself admits it.
        let (by_ip, rest): (Vec<_>, Vec<_>) = exact_only
            .into_iter()
            .partition(|addr| ip_allowed(proxy, request, *addr));
        usable.extend(by_ip);
        exact_only = rest;
    }
    if usable.is_empty() && !exact_only.is_empty() {
        // Otherwise only an exact allow of the name counts. Asking again without suffix allows
        // writes the pending row for the exact name.
        let again = proxy.decide(request, SuffixAllows::Ignore).await;
        note(event, request, &again);
        if allowed(request, again).map_err(|r| wildcard_note(r, &categories))? != PatternKind::Exact
        {
            note_block(event, BlockReason::LocalAddress);
            return Err(block(request, &[BlockReason::LocalAddress]));
        }
        usable = exact_only;
    }
    if usable.is_empty() {
        if blocked.is_empty() {
            blocked.push(BlockReason::LocalAddress);
        }
        note_block(event, shown_reason(&blocked));
        return Err(block(request, &blocked));
    }
    Ok(usable)
}

/// Whether an exact allow rule for `addr`'s IP applies to `request`'s sandbox (R-14, D-44).
/// Looks only; a miss records nothing. A policy error counts as no match.
fn ip_allowed(proxy: &Proxy, request: &EgressRequest, addr: SocketAddr) -> bool {
    let by_ip = EgressRequest::new(request.sandbox.clone(), Host::Ip(addr.ip()), request.port);
    match proxy.policy.lookup(&by_ip, SuffixAllows::Ignore) {
        Ok(Some(Decision::Allow {
            rule_id,
            pattern: PatternKind::Exact,
        })) => {
            tracing::info!(sandbox = %request.sandbox, host = %request.host, %addr, rule = %rule_id, "local address allowed by its IP rule");
            true
        }
        Ok(_) => false,
        Err(err) => {
            tracing::warn!(%addr, error = %err, "IP rule lookup failed, address not admitted");
            false
        }
    }
}

/// Adds to a pending refusal why the wildcard allow didn't count (D-44).
fn wildcard_note(mut refusal: Refusal, categories: &[LocalCategory]) -> Refusal {
    if let Some(category) = categories.first() {
        refusal.message = format!(
            "{} (it resolves to a {} address, and wildcard rules don't reach local addresses: approve the exact name, add an exact rule for its address, or turn on \"wildcards reach local addresses\")",
            refusal.message,
            category.describe()
        );
    }
    refusal
}

/// The pattern kind of an allow, or the refusal for anything else.
fn allowed(
    request: &EgressRequest,
    decision: Result<Decision, PolicyError>,
) -> Result<PatternKind, Refusal> {
    let host = &request.host;
    let port = request.port;
    let sandbox = &request.sandbox;
    match decision {
        Ok(Decision::Allow { rule_id, pattern }) => {
            tracing::info!(%sandbox, %host, port, rule = %rule_id, "allowed");
            Ok(pattern)
        }
        Ok(Decision::Deny { rule_id, .. }) => {
            tracing::info!(%sandbox, %host, port, rule = %rule_id, "denied by rule");
            Err(Refusal::new(
                "403 Forbidden",
                format!("{host} is denied by a rule (rule {rule_id})"),
            )
            .header("x-puddle-decision", "deny")
            .header("x-puddle-rule", rule_id.to_string()))
        }
        Ok(Decision::Pending(outcome)) => {
            tracing::info!(%sandbox, %host, port, pending = ?outcome.pending_id(), "pending approval");
            let refusal = Refusal::new(
                "403 Forbidden",
                match outcome {
                    PendingOutcome::Suppressed => format!(
                        "{host} is not allowed; too many new requests from this sandbox, so this one wasn't added to the inbox (retry later)"
                    ),
                    _ => format!(
                        "{host} is not allowed yet; approve it in puddle and retry"
                    ),
                },
            )
            .header("x-puddle-decision", "pending");
            Err(match outcome.pending_id() {
                Some(id) => refusal.header("x-puddle-pending", id.to_string()),
                None => refusal,
            })
        }
        Ok(Decision::Blocked { reason }) => Err(block(request, &[reason])),
        Ok(other) => {
            tracing::warn!(%sandbox, %host, port, decision = ?other, "unknown decision, refused");
            Err(
                Refusal::new("403 Forbidden", format!("{host} is not allowed"))
                    .header("x-puddle-decision", "deny"),
            )
        }
        Err(err) => {
            tracing::error!(%sandbox, %host, port, error = %err, "policy unavailable, refused");
            Err(Refusal::new(
                "503 Service Unavailable",
                "the rules could not be checked; the connection was refused",
            ))
        }
    }
}

/// The refusal for a blocked request; `reasons` holds every address's reason (at least one).
/// The header names the first toggle if any (turning it on would help), else the first reason.
fn block(request: &EgressRequest, reasons: &[BlockReason]) -> Refusal {
    let host = &request.host;
    let reason = shown_reason(reasons);
    tracing::info!(sandbox = %request.sandbox, %host, port = request.port, %reason, "blocked");
    Refusal::new(
        "403 Forbidden",
        block_message(host, &request.sandbox, reasons),
    )
    .header("x-puddle-decision", "blocked")
    .header("x-puddle-blocked", reason.code())
}

/// The reason a block names: the first toggle if any (turning it on would help), else the first.
fn shown_reason(reasons: &[BlockReason]) -> BlockReason {
    reasons
        .iter()
        .find(|r| matches!(r, BlockReason::LocalToggle(_)))
        .or_else(|| reasons.first())
        .copied()
        .unwrap_or(BlockReason::LocalAddress)
}

/// Connects to the first address that answers within `per_address`.
async fn connect_first(
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

/// `CONNECT`: answer `200`, pass on bytes the guest sent early, splice. On an error both ends
/// reset (T-048): [`splice`] sets zero linger on the server socket, and the guest stream is dropped
/// without a shutdown.
async fn tunnel(reader: GuestReader, mut server: TcpStream) {
    let early = reader.buffer().to_vec();
    let mut guest = reader.into_inner();
    let opened = async {
        guest
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        server.write_all(&early).await
    };
    if let Err(err) = opened.await {
        tracing::debug!(error = %err, "tunnel failed before the splice");
        abort(&server);
        return;
    }
    match splice(&mut server, &mut guest).await {
        Ok((up, down)) => tracing::debug!(
            bytes_up = up + early.len() as u64,
            bytes_down = down,
            "tunnel closed"
        ),
        Err(err) => tracing::debug!(error = %err, "tunnel aborted"),
    }
}

/// Plain HTTP: one request per connection, `Host` rewritten to the checked target, body framed
/// exactly, so a second request can't ride on the checked connection.
async fn forward(
    mut reader: GuestReader,
    mut server: TcpStream,
    head: &Head,
    path: &str,
    target: &Target,
    body: Body,
) {
    let upstream_head = http::upstream_head(head, path, &target.host_header());
    let result = async {
        server.write_all(upstream_head.as_bytes()).await?;
        forward_one_request(&mut reader, &mut server, body).await
    }
    .await;
    match result {
        Ok(0) => tracing::debug!("request forwarded"),
        Ok(extra) => tracing::debug!(
            discarded_bytes = extra,
            "request forwarded; pipelined bytes discarded"
        ),
        Err(err) => {
            tracing::debug!(error = %err, "plain-HTTP request aborted");
            abort(&server);
            // `reader` is dropped without a shutdown: the guest stream resets.
        }
    }
}

/// Sends the body up while the response comes down (so `Expect: 100-continue` works). Anything
/// the guest sends after the body is never forwarded; returns how many such bytes were buffered.
async fn forward_one_request<C, U>(
    client: &mut BufReader<C>,
    upstream: &mut U,
    body: Body,
) -> io::Result<usize>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut server_in, mut server_out) = tokio::io::split(upstream);
    let leftover = {
        let (guest_in, mut guest_out) = tokio::io::split(&mut *client);
        let mut guest_in = BufReader::new(guest_in);
        {
            let upload = async {
                http::copy_body(&mut guest_in, &mut server_out, body).await?;
                server_out.flush().await
            };
            let download = tokio::io::copy(&mut server_in, &mut guest_out);
            tokio::pin!(download);
            let uploaded_first = tokio::select! {
                up = upload => { up?; true }
                down = &mut download => { down?; false }
            };
            if uploaded_first {
                download.await?;
            }
        }
        guest_out.shutdown().await?;
        guest_in.buffer().len()
    };
    Ok(leftover + client.buffer().len())
}

/// Makes dropping `server` send a reset instead of a clean close.
fn abort(server: &TcpStream) {
    if let Err(err) = server.set_zero_linger() {
        tracing::debug!(error = %err, "zero linger");
    }
}

#[cfg(test)]
mod tests;
