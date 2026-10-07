// SPDX-License-Identifier: GPL-3.0-or-later
//! The image-pull proxy (interim design): the listener puddle's own registry traffic
//! goes through, so image pulls take the same way out as everything else.
//!
//! msb's registry client (run inside puddle by the msb adapter) is given this listener as its
//! proxy, with a per-run token as the URL's userinfo (`http://puddle:<token>@127.0.0.1:<port>`),
//! through the SDK's own setting (`puddle_compute_msb::MsbConfig::with_registry_proxy`),
//! not through `HTTPS_PROXY`: the token is never in the process environment, so no child process
//! inherits it. Then:
//!
//! - **Only puddle gets in.** The listener binds `127.0.0.1` only, and every request must carry
//!   `Proxy-Authorization: Basic` for `puddle:<token>`; anything else is a `407` and the
//!   connection is closed. The token is 256 random bits, compared in constant time, and never
//!   logged (`Debug` and `Display` redact it; the log lines carry host and port only).
//! - **Guests never reach it.** It registers itself in [`PuddleEndpoints`] as
//!   [`EndpointKind::PullProxy`], so the sandbox proxy's guard blocks it.
//! - **No rules, but the guard.** Pulls are puddle's own requests, not a sandbox's, so the rules
//!   engine isn't asked and no pending row is written. The address guard still
//!   applies: puddle's own endpoints (this listener included), cloud metadata, link-local and
//!   special addresses are blocked. Private and loopback addresses are allowed by default, so a
//!   company registry on an internal address and a developer's `localhost:5000` registry work
//!   ([`PullProxy::with_local_access`] changes that).
//! - **Same relay as the sandbox proxy.** `CONNECT` is spliced (TLS stays end to end, so the
//!   registry client verifies the certificate itself: an intercepting company proxy needs its
//!   root passed to the client), and absolute-form `http://` is forwarded once with the proxy
//!   credentials dropped.
//!
//! - **Recorded in the audit.** With a log set ([`PullProxy::with_connection_log`]), every pull
//!   whose destination was parsed ends as one `connection` record with `origin: puddle` and no
//!   sandbox: allowed, refused by the address guard, or failed to connect. It carries the
//!   upstream hop and the bytes, and never a header, credential or query string.
//!
//! Pulls leave through the company proxy route when one is set ([`PullProxy::with_upstream`]),
//! and connect directly otherwise.

use std::fmt::{self, Write as _};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use puddle_netpolicy::{
    AddressClass, EndpointKind, LocalAccess, NetPolicy, PuddleEndpoints, Registration,
};
use puddle_types::{
    BlockReason, ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionReason, Host,
    HttpRequestLine, LocalCategory, NullConnectionLog,
};
use subtle::ConstantTimeEq;
use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tracing::Instrument;

use crate::counted::Counted;
use crate::destination::{Resolver, SystemResolver};
use crate::http::{self, Head};
use crate::proxy::{ProxyConfig, Refusal, forward, parse_request, read_request, refuse, tunnel};
use crate::target::Target;
use crate::upstream::{Admitted, Upstream, connect_out};

/// Random bytes in a token (256 bits).
const TOKEN_BYTES: usize = 32;

/// The user name in the proxy URL. Any other name is refused.
const USER: &str = "puddle";

/// Pause after an accept error, so a broken listener can't spin a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What a pull may reach besides public addresses, unless [`PullProxy::with_local_access`] says
/// otherwise: private networks (a company registry) and loopback (a local registry). puddle's own
/// endpoints stay blocked whatever this says.
#[must_use]
pub fn default_pull_access() -> LocalAccess {
    LocalAccess::NONE
        .with_toggle(LocalCategory::Private, true)
        .with_toggle(LocalCategory::Loopback, true)
}

/// The per-run token of the pull proxy: 32 random bytes as 64 lower-case hex characters.
///
/// `Debug` never shows it and there is no `Display`; [`PullToken::expose`] is the one way to
/// read it.
#[derive(Clone)]
pub struct PullToken(String);

impl PullToken {
    /// A fresh token from the OS random source.
    ///
    /// # Errors
    ///
    /// When the OS has no randomness to give.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
        let text = bytes
            .iter()
            .fold(String::with_capacity(TOKEN_BYTES * 2), |mut text, b| {
                let _ = write!(text, "{b:02x}");
                text
            });
        Ok(Self(text))
    }

    /// The token text.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The `Proxy-Authorization: Basic` credentials a client sends for this token.
    fn basic_credentials(&self) -> String {
        BASE64.encode(format!("{USER}:{}", self.0))
    }
}

impl fmt::Debug for PullToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PullToken(<redacted>)")
    }
}

/// The proxy URL for the registry client, `http://puddle:<token>@127.0.0.1:<port>`.
///
/// `Debug` and `Display` show it with the token replaced by `<redacted>`;
/// [`ProxyUrl::expose`] gives the real URL, to put into the environment.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    url: String,
    addr: SocketAddr,
}

impl ProxyUrl {
    /// The URL with the token, for `HTTPS_PROXY` / `HTTP_PROXY`.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.url
    }

    /// The listener's address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "http://{USER}:<redacted>@{}", self.addr)
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyUrl({self})")
    }
}

/// The image-pull proxy, bound but not serving yet: `127.0.0.1` only, a per-run token
/// every request must carry (`407` otherwise), registered in [`PuddleEndpoints`] so guests never
/// reach it, and the address guard without the rules.
///
/// Bind it early (it uses a std listener, so no async runtime is needed), put
/// [`PullProxy::proxy_url`] into the environment before any thread starts, then
/// [`PullProxy::serve`] it inside the runtime.
pub struct PullProxy {
    listener: std::net::TcpListener,
    addr: SocketAddr,
    token: PullToken,
    guard: NetPolicy,
    access: LocalAccess,
    resolver: Arc<dyn Resolver>,
    config: ProxyConfig,
    upstream: Option<Upstream>,
    log: Arc<dyn ConnectionLog>,
    registration: Registration,
}

impl fmt::Debug for PullProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PullProxy")
            .field("addr", &self.addr)
            .field("token", &self.token)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl PullProxy {
    /// Binds `127.0.0.1` on a free port, makes a fresh token, and registers the listener in
    /// `endpoints` (the registry the sandbox proxy's guard uses), so no guest can reach it.
    ///
    /// # Errors
    ///
    /// When the port can't be bound or the OS has no randomness.
    pub fn bind(endpoints: &PuddleEndpoints) -> io::Result<Self> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let token = PullToken::generate()?;
        let registration = endpoints.register(addr, EndpointKind::PullProxy);
        let access = default_pull_access();
        Ok(Self {
            listener,
            addr,
            token,
            guard: NetPolicy::new(Arc::new(access)).with_endpoints(endpoints.clone()),
            access,
            resolver: Arc::new(SystemResolver),
            config: ProxyConfig::default(),
            upstream: None,
            log: Arc::new(NullConnectionLog),
            registration,
        })
    }

    /// Uses `resolver` for registry names (tests point names at local servers).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Which local address categories pulls may reach. puddle's own endpoints are blocked
    /// whatever this says.
    #[must_use]
    pub fn with_local_access(mut self, access: LocalAccess) -> Self {
        let endpoints = self.guard.endpoints().clone();
        self.guard = NetPolicy::new(Arc::new(access)).with_endpoints(endpoints);
        self.access = access;
        self
    }

    /// Uses `config`'s head timeout, resolve and connect timeouts, and its
    /// `max_streams_per_sandbox` as the cap on open pull connections.
    #[must_use]
    pub fn with_config(mut self, config: ProxyConfig) -> Self {
        self.config = config;
        self
    }

    /// Sends pulls out along the company proxy route. The guard still runs on every
    /// address first, and a `DIRECT` hop connects only to an address that passed.
    #[must_use]
    pub fn with_upstream(mut self, upstream: Upstream) -> Self {
        self.upstream = Some(upstream);
        self
    }

    /// Records every pull in `log`, as a `connection` record with origin `puddle`.
    #[must_use]
    pub fn with_connection_log(mut self, log: Arc<dyn ConnectionLog>) -> Self {
        self.log = log;
        self
    }

    /// Where the listener is bound (always `127.0.0.1`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The URL for the registry client's `HTTPS_PROXY` / `HTTP_PROXY`.
    #[must_use]
    pub fn proxy_url(&self) -> ProxyUrl {
        ProxyUrl {
            url: format!("http://{USER}:{}@{}", self.token.expose(), self.addr),
            addr: self.addr,
        }
    }

    /// The token, for tests and for a client that builds its own header.
    #[must_use]
    pub fn token(&self) -> &PullToken {
        &self.token
    }

    /// Starts accepting. Must be called inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// When the listener can't be handed to tokio.
    pub fn serve(self) -> io::Result<PullRoute> {
        self.listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(self.listener)?;
        let shared = Arc::new(Shared {
            credentials: self.token.basic_credentials(),
            guard: self.guard,
            access: self.access,
            resolver: self.resolver,
            streams: Arc::new(Semaphore::new(self.config.max_streams_per_sandbox)),
            upstream: self.upstream,
            log: self.log,
            config: self.config,
        });
        let task = tokio::spawn(accept_loop(listener, shared));
        Ok(PullRoute {
            addr: self.addr,
            task,
            _registration: self.registration,
        })
    }
}

/// The pull proxy, serving. Dropping it (or [`PullRoute::shutdown`]) stops accepting, resets open
/// connections and removes the listener from the endpoint registry.
#[derive(Debug)]
pub struct PullRoute {
    addr: SocketAddr,
    task: JoinHandle<()>,
    _registration: Registration,
}

impl PullRoute {
    /// Where the listener is bound.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops the listener and waits until its connections are gone.
    pub async fn shutdown(mut self) {
        self.task.abort();
        if let Err(err) = (&mut self.task).await
            && err.is_panic()
        {
            tracing::error!("image-pull proxy task panicked");
        }
    }
}

impl Drop for PullRoute {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Shared {
    /// The base64 credentials of `puddle:<token>`.
    credentials: String,
    guard: NetPolicy,
    access: LocalAccess,
    resolver: Arc<dyn Resolver>,
    streams: Arc<Semaphore>,
    upstream: Option<Upstream>,
    log: Arc<dyn ConnectionLog>,
    config: ProxyConfig,
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let shared = Arc::clone(&shared);
                    let span = tracing::debug_span!("pull", %peer);
                    conns.spawn(async move { serve(&shared, stream).await }.instrument(span));
                }
                Err(err) => {
                    tracing::warn!(error = %err, "image-pull proxy accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
}

/// Whether `head` carries exactly one `Proxy-Authorization: Basic` header with `credentials`.
fn authorised(head: &Head, credentials: &str) -> bool {
    let mut values = head
        .headers
        .iter()
        .filter(|h| http::header_name(h) == "proxy-authorization")
        .map(|h| http::header_value(h));
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let Some((scheme, presented)) = value.split_once(' ') else {
        return false;
    };
    let scheme_ok = scheme.eq_ignore_ascii_case("basic");
    let token_ok: bool = presented
        .trim()
        .as_bytes()
        .ct_eq(credentials.as_bytes())
        .into();
    scheme_ok & token_ok
}

fn unauthorised() -> Refusal {
    Refusal::new(
        "407 Proxy Authentication Required",
        "this is puddle's image-pull proxy; only puddle may use it",
    )
    .header("proxy-authenticate", "Basic realm=\"puddle\"")
}

async fn serve(shared: &Shared, stream: TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(error = %err, "nodelay");
    }
    let (stream, counts) = Counted::new(stream);
    let mut reader = BufReader::new(stream);
    let Ok(_permit) = Arc::clone(&shared.streams).try_acquire_owned() else {
        let limit = shared.config.max_streams_per_sandbox;
        tracing::warn!(
            limit,
            "image-pull connection refused: over the connection limit"
        );
        let refusal = Refusal::new(
            "503 Service Unavailable",
            format!("too many open image-pull connections (limit {limit})"),
        );
        refuse(reader.get_mut(), &refusal).await;
        return;
    };
    let head = match read_request(&mut reader, shared.config.head_timeout).await {
        Ok(head) => head,
        Err(None) => return,
        Err(Some(refusal)) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    if !authorised(&head, &shared.credentials) {
        tracing::warn!("image-pull proxy: request without puddle's credentials refused");
        refuse(reader.get_mut(), &unauthorised()).await;
        return;
    }
    let (target, path, body) = match parse_request(&head) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    let mut event = ConnectionEvent::puddle(
        target.host.clone(),
        target.port,
        ConnectionDecision::Allow,
        ConnectionReason::PuddleRequest,
    );
    if let Some(path) = &path {
        event.http = Some(HttpRequestLine::new(head.method.as_str(), path));
    }
    relay(shared, reader, &head, &target, path, body, &mut event).await;
    event.bytes_up = counts.read();
    event.bytes_down = counts.written();
    tracing::debug!(
        host = %target.host,
        bytes_up = event.bytes_up,
        bytes_down = event.bytes_down,
        "image-pull connection closed"
    );
    let log = Arc::clone(&shared.log);
    if tokio::task::spawn_blocking(move || log.record(&event))
        .await
        .is_err()
    {
        tracing::warn!("connection log panicked; record lost");
    }
}

/// Admits, connects and relays one pull, noting in `event` what happened.
async fn relay(
    shared: &Shared,
    mut reader: BufReader<Counted<TcpStream>>,
    head: &Head,
    target: &Target,
    path: Option<String>,
    body: http::Body,
    event: &mut ConnectionEvent,
) {
    let admitted = match admit(shared, target, event).await {
        Ok(admitted) => admitted,
        Err(refusal) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    let out = match connect_out(
        shared.upstream.as_ref(),
        target,
        path.is_none(),
        &admitted,
        shared.config.connect_timeout,
    )
    .await
    {
        Ok(out) => out,
        Err(refusal) => {
            refuse(reader.get_mut(), &refusal).await;
            return;
        }
    };
    event.resolved_ip = out.addr.map(|addr| addr.ip());
    event.upstream = out.hop.clone();
    tracing::info!(host = %target.host, port = target.port, addr = ?out.addr, hop = ?out.hop, "image-pull connection");
    match path {
        None => {
            tunnel(reader, out.stream).await;
        }
        Some(path) => {
            forward(
                reader,
                out.stream,
                head,
                &path,
                target,
                body,
                out.via.as_ref(),
            )
            .await;
        }
    }
}

/// The verdict on one address a pull would connect to.
fn verdict(guard: &NetPolicy, access: LocalAccess, addr: SocketAddr) -> Result<(), BlockReason> {
    match guard.classify(addr) {
        AddressClass::Public => Ok(()),
        AddressClass::Local { category, .. } if access.is_on(category) => Ok(()),
        AddressClass::Local { category, .. } => Err(BlockReason::LocalToggle(category)),
        // puddle's own endpoints, and any class this version doesn't know.
        _ => Err(BlockReason::PuddleEndpoint),
    }
}

/// The addresses a pull to `target` may connect to: the name stage (`localhost`, metadata
/// names), then every resolved address through [`verdict`].
async fn admit(
    shared: &Shared,
    target: &Target,
    event: &mut ConnectionEvent,
) -> Result<Admitted, Refusal> {
    let host = &target.host;
    let port = target.port;
    let named = puddle_netpolicy::Target::from_host(host.clone()).named_category();
    if let Some(category) = named {
        if !shared.access.is_on(category) {
            return Err(blocked(
                host,
                port,
                &[BlockReason::LocalToggle(category)],
                event,
            ));
        }
        // `localhost:<puddle port>`: refused before any lookup.
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if category == LocalCategory::Loopback
            && matches!(
                shared.guard.classify(loopback),
                AddressClass::PuddleEndpoint(_)
            )
        {
            return Err(blocked(host, port, &[BlockReason::PuddleEndpoint], event));
        }
    }
    let addrs = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Name(name) => {
            match tokio::time::timeout(
                shared.config.resolve_timeout,
                shared.resolver.resolve(name, port),
            )
            .await
            {
                Err(_) => {
                    return left_to_upstream(shared, host, "timed out").ok_or_else(|| {
                        Refusal::new("504 Gateway Timeout", format!("resolving {host} timed out"))
                    });
                }
                Ok(Err(err)) => {
                    tracing::info!(%host, error = %err, "image-pull resolve failed");
                    return left_to_upstream(shared, host, "failed").ok_or_else(|| {
                        Refusal::new("502 Bad Gateway", format!("could not resolve {host}"))
                    });
                }
                Ok(Ok(addrs)) => addrs,
            }
        }
    };
    let resolved = addrs.len();
    let mut usable = Vec::new();
    let mut reasons = Vec::new();
    for addr in addrs {
        match verdict(&shared.guard, shared.access, addr) {
            Ok(()) => usable.push(addr),
            Err(reason) => reasons.push(reason),
        }
    }
    if usable.is_empty() {
        if reasons.is_empty() {
            return Err(Refusal::new(
                "502 Bad Gateway",
                format!("{host} has no addresses"),
            ));
        }
        return Err(blocked(host, port, &reasons, event));
    }
    // A proxy may be told the name only when every address it resolved to passed the guard.
    let name_ok = matches!(host, Host::Ip(_)) || usable.len() == resolved;
    Ok(Admitted::checked(usable, name_ok))
}

/// A registry name this host cannot resolve, when the company proxy may resolve it (networks
/// without external DNS): there is no address to guard, and the name stage already ran.
fn left_to_upstream(shared: &Shared, host: &Host, why: &str) -> Option<Admitted> {
    if shared
        .upstream
        .as_ref()
        .is_some_and(Upstream::resolves_unknown_names)
    {
        tracing::info!(%host, why, "image pull: name not resolved here; the company proxy resolves it");
        Some(Admitted::unresolved())
    } else {
        None
    }
}

/// The refusal for a pull to an address it may not reach.
fn blocked(
    host: &Host,
    port: u16,
    reasons: &[BlockReason],
    event: &mut ConnectionEvent,
) -> Refusal {
    let reason = reasons
        .iter()
        .find(|r| matches!(r, BlockReason::PuddleEndpoint))
        .or_else(|| reasons.first())
        .copied()
        .unwrap_or(BlockReason::LocalAddress);
    event.decision = ConnectionDecision::Blocked;
    event.reason = ConnectionReason::Blocked(reason);
    tracing::info!(%host, port, %reason, "image pull blocked");
    let what = match reason {
        BlockReason::PuddleEndpoint => "one of puddle's own endpoints".to_owned(),
        BlockReason::LocalToggle(category) => format!("a {} address", category.describe()),
        _ => "an address image pulls may not reach".to_owned(),
    };
    Refusal::new(
        "403 Forbidden",
        format!("{host} is {what}; image pulls never go there"),
    )
    .header("x-puddle-decision", "blocked")
    .header("x-puddle-blocked", reason.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(headers: &[&str]) -> Head {
        Head {
            method: "CONNECT".into(),
            uri: "registry.test:443".into(),
            version: "HTTP/1.1".into(),
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
        }
    }

    fn token() -> PullToken {
        PullToken("ab".repeat(TOKEN_BYTES))
    }

    #[test]
    fn a_token_is_64_hex_characters_and_fresh_each_time() {
        let a = PullToken::generate().unwrap();
        let b = PullToken::generate().unwrap();
        assert_eq!(a.expose().len(), 64);
        assert!(
            a.expose()
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_never_shows_the_token() {
        let t = token();
        assert_eq!(format!("{t:?}"), "PullToken(<redacted>)");
        let url = ProxyUrl {
            url: format!("http://puddle:{}@127.0.0.1:9", t.expose()),
            addr: "127.0.0.1:9".parse().unwrap(),
        };
        assert_eq!(url.to_string(), "http://puddle:<redacted>@127.0.0.1:9");
        assert_eq!(
            format!("{url:?}"),
            "ProxyUrl(http://puddle:<redacted>@127.0.0.1:9)"
        );
        assert!(url.expose().contains(t.expose()));
    }

    #[test]
    fn only_the_exact_basic_credentials_are_accepted() {
        let t = token();
        let good = t.basic_credentials();
        let ok = |headers: &[&str]| authorised(&head(headers), &good);
        assert!(ok(&[&format!("Proxy-Authorization: Basic {good}")]));
        assert!(ok(&[&format!("proxy-authorization:   basic {good}  ")]));
        assert!(ok(&[
            "Host: x",
            &format!("PROXY-AUTHORIZATION: BASIC {good}")
        ]));

        assert!(!ok(&[]), "missing");
        assert!(!ok(&["Authorization: Basic x"]), "wrong header");
        let wrong = BASE64.encode(format!("puddle:{}", "cd".repeat(TOKEN_BYTES)));
        assert!(
            !ok(&[&format!("Proxy-Authorization: Basic {wrong}")]),
            "wrong token"
        );
        let user = BASE64.encode(format!("admin:{}", t.expose()));
        assert!(
            !ok(&[&format!("Proxy-Authorization: Basic {user}")]),
            "wrong user"
        );
        assert!(
            !ok(&[&format!("Proxy-Authorization: Bearer {good}")]),
            "scheme"
        );
        assert!(
            !ok(&[&format!("Proxy-Authorization: Basic{good}")]),
            "no space"
        );
        assert!(!ok(&["Proxy-Authorization: Basic"]), "empty");
        assert!(
            !ok(&[&format!("Proxy-Authorization: Basic {}", t.expose())]),
            "raw token, not base64"
        );
        let both = format!("Proxy-Authorization: Basic {good}");
        assert!(!ok(&[&both, &both]), "duplicated header");
        assert!(
            !ok(&[&both, &format!("Proxy-Authorization: Basic {wrong}")]),
            "a second, wrong header"
        );
        assert!(
            !ok(&[&format!("Proxy-Authorization: Basic {good}x")]),
            "suffix"
        );
    }

    #[test]
    fn pulls_reach_public_private_and_loopback_but_not_metadata_link_local_or_puddle() {
        let endpoints = PuddleEndpoints::new();
        let _api = endpoints.register("127.0.0.1:7070".parse().unwrap(), EndpointKind::Api);
        let access = default_pull_access();
        let guard = NetPolicy::new(Arc::new(access)).with_endpoints(endpoints);
        let v = |a: &str| verdict(&guard, access, a.parse().unwrap());
        assert_eq!(v("140.82.121.4:443"), Ok(()));
        assert_eq!(v("10.1.2.3:443"), Ok(()));
        assert_eq!(v("[fd00::1]:443"), Ok(()));
        assert_eq!(v("127.0.0.1:5000"), Ok(()));
        assert_eq!(v("127.0.0.1:7070"), Err(BlockReason::PuddleEndpoint));
        assert_eq!(
            v("169.254.169.254:80"),
            Err(BlockReason::LocalToggle(LocalCategory::Metadata))
        );
        assert_eq!(
            v("168.63.129.16:80"),
            Err(BlockReason::LocalToggle(LocalCategory::Metadata))
        );
        assert_eq!(
            v("169.254.1.1:80"),
            Err(BlockReason::LocalToggle(LocalCategory::LinkLocal))
        );
        assert_eq!(
            v("224.0.0.1:80"),
            Err(BlockReason::LocalToggle(LocalCategory::Special))
        );
        let none = LocalAccess::NONE;
        let strict = NetPolicy::new(Arc::new(none));
        assert_eq!(
            verdict(&strict, none, "10.1.2.3:443".parse().unwrap()),
            Err(BlockReason::LocalToggle(LocalCategory::Private))
        );
    }

    #[test]
    fn a_block_names_puddle_endpoints_first() {
        let host = Host::parse_normalised("localhost").unwrap();
        let mut event = ConnectionEvent::puddle(
            host.clone(),
            1,
            ConnectionDecision::Allow,
            ConnectionReason::PuddleRequest,
        );
        let r = blocked(
            &host,
            1,
            &[
                BlockReason::LocalToggle(LocalCategory::Special),
                BlockReason::PuddleEndpoint,
            ],
            &mut event,
        );
        assert_eq!(
            (event.decision, event.reason),
            (
                ConnectionDecision::Blocked,
                ConnectionReason::Blocked(BlockReason::PuddleEndpoint)
            )
        );
        assert_eq!(r.status, "403 Forbidden");
        assert!(
            r.headers
                .contains(&("x-puddle-blocked", "puddle_endpoint".to_owned()))
        );
        assert!(
            r.message.contains("puddle's own endpoints"),
            "{}",
            r.message
        );
        let r = blocked(
            &host,
            1,
            &[BlockReason::LocalToggle(LocalCategory::Metadata)],
            &mut event,
        );
        assert!(r.message.contains("metadata"), "{}", r.message);
        let r = blocked(&host, 1, &[], &mut event);
        assert!(
            r.headers
                .contains(&("x-puddle-blocked", "local_address".to_owned()))
        );
    }
}
