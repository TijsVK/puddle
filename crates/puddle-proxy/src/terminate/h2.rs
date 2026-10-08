// SPDX-License-Identifier: GPL-3.0-or-later
//! A terminated connection whose guest speaks HTTP/2.
//!
//! Every stream is one request, decided, checked and injected exactly like an HTTP/1.1 request on
//! the strict path: the same checks (`Host`, target, framing), the same [`Injector`] and the same
//! header rules, then sent over the upstream leg, which is an HTTP/2 connection (streams
//! multiplexed) or, for a server that speaks only HTTP/1.1, a small pool of connections. Bodies
//! stream both ways with their trailers, so gRPC works.
//!
//! [`Injector`]: super::Injector

use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use ::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use ::http::{Method, Request, Response, StatusCode, Uri};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use puddle_types::HttpRequestLine;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Notify;
use tokio::time::Sleep;

use super::guest::{ALPN_H2, ALPN_HTTP11};
use super::inject::{InjectContext, InjectDecision, Injection, RequestView};
use super::leg::{self, BoxError, Connected, H1Pool, H2Conn, Lease, UpBody};
use super::request::{self, UpstreamVersion, bad, misdirected};
use super::session::{Context, Outcome};
use super::watch::Watch;
use super::ws;
use crate::proxy::Refusal;

/// Streams a guest may have open at once (RFC 9113 §6.5.2). Real tools open a few dozen; the
/// bar is the hundreds `PX-40` names for connections.
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 256;

/// The largest request header list accepted from the guest (the plain-HTTP path's head limit).
const MAX_REQUEST_HEADER_LIST: u32 = 64 * 1024;

/// Streams the guest reset before the proxy accepted them, tolerated before the connection is
/// ended (rapid reset, CVE-2023-44487).
const MAX_PENDING_ACCEPT_RESETS: usize = 20;

/// Streams the proxy reset because of the guest's protocol errors, tolerated before the
/// connection is ended.
const MAX_LOCAL_ERROR_RESETS: usize = 128;

/// How long a stream may go without a frame in either direction before it is reset. A watch or
/// event stream is quiet for long stretches, so this is far above the body-stall timeout of
/// HTTP/1.1; what catches a dead peer sooner is the ping of the connection.
pub(crate) const STREAM_IDLE: Duration = Duration::from_secs(3600);

/// How often a connection with no stream open is looked at for the keep-alive timeout.
const IDLE_CHECK: Duration = Duration::from_secs(2);

/// What an HTTP/1.1 pool checkout may wait for a free connection.
const POOL_WAIT: Duration = Duration::from_secs(30);

/// A response body or request body as the HTTP/2 server and the upstream clients take it.
type RespBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// The upstream leg of one guest connection.
enum LegState {
    None,
    H2(H2Conn),
    H1(H1Pool),
}

/// Where one stream's request goes.
enum Route {
    H2(hyper::client::conn::http2::SendRequest<UpBody>),
    H1(Lease),
}

impl Route {
    fn version(&self) -> UpstreamVersion {
        match self {
            Self::H2(_) => UpstreamVersion::H2,
            Self::H1(_) => UpstreamVersion::H1,
        }
    }

    /// Nothing was sent on this route: an HTTP/1.1 connection checked out for it is still good.
    fn unused(self) {
        if let Self::H1(mut lease) = self {
            lease.mark_reusable();
        }
    }
}

struct Shared {
    cx: Arc<Context>,
    leg: tokio::sync::Mutex<LegState>,
    /// Why the real server could not be used at the handshake; the first stream gets it.
    deferred: Mutex<Option<Refusal>>,
    outcome: Mutex<Outcome>,
    open_streams: AtomicUsize,
}

impl Shared {
    /// The route for one more request, connecting again when the upstream connection is gone.
    async fn route(&self) -> Result<Route, Refusal> {
        if let Some(refusal) = self
            .deferred
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            return Err(refusal);
        }
        let pool = {
            let mut leg = self.leg.lock().await;
            match &*leg {
                LegState::H2(conn) if !conn.sender.is_closed() => {
                    return Ok(Route::H2(conn.sender.clone()));
                }
                LegState::H1(pool) => Some(pool.clone()),
                _ => {
                    let made = leg::connect(&self.cx, &[ALPN_H2, ALPN_HTTP11]).await?;
                    {
                        let mut outcome =
                            self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
                        if outcome.hop.is_none() && outcome.resolved_ip.is_none() {
                            outcome.hop = made.hop;
                            outcome.resolved_ip = made.ip;
                        }
                    }
                    match made.conn {
                        Connected::H2(conn) => {
                            let sender = conn.sender.clone();
                            *leg = LegState::H2(conn);
                            return Ok(Route::H2(sender));
                        }
                        Connected::H1(conn) => {
                            let pool = H1Pool::new(conn);
                            *leg = LegState::H1(pool.clone());
                            Some(pool)
                        }
                    }
                }
            }
        };
        match pool {
            Some(pool) => pool.checkout(&self.cx, POOL_WAIT).await.map(Route::H1),
            None => Err(bad("no upstream")),
        }
    }
}

/// Counts a stream as open until the guard goes away (with the response body, so a stream that
/// is still sending is not mistaken for an idle connection).
struct StreamGuard(Arc<Shared>);

impl StreamGuard {
    fn new(shared: &Arc<Shared>) -> Self {
        shared.open_streams.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(shared))
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.open_streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves the guest's HTTP/2 connection `io` until it ends; `first` is the verified connection
/// made at the handshake (if it could be made, else `deferred` says why).
pub(crate) async fn serve<IO>(
    cx: Arc<Context>,
    io: IO,
    first: Option<Connected>,
    deferred: Option<Refusal>,
    outcome: Outcome,
) -> Outcome
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = cx.proxy.config;
    let leg = match first {
        Some(Connected::H2(conn)) => LegState::H2(conn),
        Some(Connected::H1(conn)) => LegState::H1(H1Pool::new(conn)),
        None => LegState::None,
    };
    let shared = Arc::new(Shared {
        cx,
        leg: tokio::sync::Mutex::new(leg),
        deferred: Mutex::new(deferred),
        outcome: Mutex::new(outcome),
        open_streams: AtomicUsize::new(0),
    });
    let service = {
        let shared = Arc::clone(&shared);
        service_fn(move |request| handle(Arc::clone(&shared), request))
    };
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .max_frame_size(leg::MAX_FRAME_SIZE)
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_REQUEST_HEADER_LIST)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESETS)
        .max_local_error_reset_streams(MAX_LOCAL_ERROR_RESETS)
        .keep_alive_interval(leg::PING_INTERVAL)
        .keep_alive_timeout(leg::PING_TIMEOUT)
        .enable_connect_protocol();
    let connection =
        builder.serve_connection(TokioIo::new(Watch::new(io, config.head_timeout)), service);
    tokio::pin!(connection);
    let mut idle_since = Some(Instant::now());
    let mut tick = tokio::time::interval(IDLE_CHECK);
    loop {
        tokio::select! {
            result = connection.as_mut() => {
                if let Err(err) = result {
                    tracing::debug!(host = %shared.cx.target.host, error = %err, "guest HTTP/2 connection ended");
                }
                break;
            }
            _ = tick.tick() => {
                if shared.open_streams.load(Ordering::SeqCst) > 0 {
                    idle_since = None;
                } else if idle_since.get_or_insert_with(Instant::now).elapsed() >= config.keepalive_timeout {
                    connection.as_mut().graceful_shutdown();
                    idle_since = Some(Instant::now());
                }
            }
        }
    }
    let mut outcome = shared
        .outcome
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    std::mem::take(&mut *outcome)
}

async fn handle(
    shared: Arc<Shared>,
    request: Request<Incoming>,
) -> Result<Response<RespBody>, Infallible> {
    let guard = StreamGuard::new(&shared);
    Ok(match exchange(&shared, request, guard).await {
        Ok(response) => response,
        Err(refusal) => refusal_response(&refusal),
    })
}

/// A refusal as an HTTP/2 response: the same status, headers and text as the HTTP/1.1 path sends.
fn refusal_response(refusal: &Refusal) -> Response<RespBody> {
    let status = refusal
        .status
        .split(' ')
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let text = format!("puddle: {}\n", refusal.message);
    let mut response = Response::new(
        Full::new(Bytes::from(text))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    for (name, value) in &refusal.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    response
}

/// What the checks learn about a request.
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) method: Method,
    /// Path and query, starting with `/`.
    pub(crate) path: String,
    /// The `:protocol` of an extended `CONNECT` (RFC 8441), if any.
    pub(crate) protocol: Option<hyper::ext::Protocol>,
}

/// Checks an HTTP/2 request the way the strict HTTP/1.1 parser checks one: the request must be
/// for the connection's own host, in origin form, with nothing that only makes sense on an
/// HTTP/1.1 connection.
pub(crate) fn check<B>(
    request: &Request<B>,
    target: &crate::target::Target,
) -> Result<Checked, Refusal> {
    let protocol = request.extensions().get::<hyper::ext::Protocol>().cloned();
    let method = request.method().clone();
    if method == Method::CONNECT && protocol.is_none() {
        return Err(bad("CONNECT inside a tunnel is not supported"));
    }
    if protocol.is_some() && method != Method::CONNECT {
        return Err(bad("a :protocol on a request that is not CONNECT"));
    }
    let headers = request.headers();
    let uri = request.uri();
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return Err(bad("more than one Host header"));
    }
    let host = host
        .map(|value| value.to_str().map_err(|_| bad("malformed Host header")))
        .transpose()?;
    let authority = uri.authority().map(::http::uri::Authority::as_str);
    if authority.is_none() && host.is_none() {
        return Err(bad("missing :authority"));
    }
    for named in authority.into_iter().chain(host) {
        if named.contains('@') {
            return Err(bad("userinfo (user@host) is not allowed"));
        }
        if !request::authority_is(named, target) {
            return Err(misdirected(target));
        }
    }
    match uri.scheme_str() {
        None | Some("https") => {}
        Some(_) => return Err(bad("an absolute http:// target inside an https connection")),
    }
    let path = uri
        .path_and_query()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    if !path.starts_with('/') {
        return Err(bad("the request target must be a path"));
    }
    // Connection-specific fields have no meaning on HTTP/2 and are how a request is smuggled
    // past a proxy that translates it to HTTP/1.1 (RFC 9113 §8.2.2).
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        if headers.contains_key(&name) {
            return Err(bad(format!("the {name} header does not exist in HTTP/2")));
        }
    }
    for value in headers.get_all(header::TE) {
        if !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
            return Err(bad("TE other than trailers does not exist in HTTP/2"));
        }
    }
    let mut lengths = headers.get_all(header::CONTENT_LENGTH).iter().map(|value| {
        value
            .to_str()
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
    });
    if let Some(first) = lengths.next() {
        let Some(first) = first else {
            return Err(bad("invalid Content-Length"));
        };
        if lengths.any(|length| length != Some(first)) {
            return Err(bad("conflicting Content-Length headers"));
        }
    }
    for value in headers.get_all(header::EXPECT) {
        if !value.as_bytes().eq_ignore_ascii_case(b"100-continue") {
            return Err(Refusal::new(
                "417 Expectation Failed",
                "only Expect: 100-continue is supported",
            ));
        }
    }
    Ok(Checked {
        method,
        path,
        protocol,
    })
}

/// The request's header lines for the injector: the same `name: value` lines the HTTP/1.1 head
/// has, with the `Host` the HTTP/2 request names in `:authority`.
fn header_lines(headers: &HeaderMap, host: &str) -> Vec<String> {
    let mut lines = Vec::with_capacity(headers.len() + 1);
    lines.push(format!("host: {host}"));
    for (name, value) in headers {
        if name == header::HOST {
            continue;
        }
        lines.push(format!(
            "{}: {}",
            name.as_str(),
            String::from_utf8_lossy(value.as_bytes())
        ));
    }
    lines
}

async fn exchange(
    shared: &Arc<Shared>,
    mut request: Request<Incoming>,
    guard: StreamGuard,
) -> Result<Response<RespBody>, Refusal> {
    let cx = &shared.cx;
    let checked = check(&request, &cx.target).inspect_err(|refusal| {
        tracing::info!(host = %cx.target.host, status = %refusal.status, "terminated request refused: {}", refusal.message);
    })?;
    {
        let mut outcome = shared
            .outcome
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if outcome.http.is_none() {
            outcome.http = Some(HttpRequestLine::new(checked.method.as_str(), &checked.path));
        }
    }
    tracing::debug!(host = %cx.target.host, method = %checked.method, path = %puddle_types::request_path(&checked.path), "terminated request (h2)");
    if let Some(protocol) = &checked.protocol
        && protocol.as_str() != "websocket"
    {
        return Err(Refusal::new(
            "501 Not Implemented",
            format!("the :protocol {} is not supported", protocol.as_str()),
        ));
    }
    let mut route = shared.route().await?;
    let version = route.version();
    let injection = match decide(shared, &checked, request.headers(), version).await {
        Ok(injection) => injection,
        Err(refusal) => {
            route.unused();
            return Err(refusal);
        }
    };
    let headers =
        request::upstream_headers_h2(request.headers(), &cx.target, injection.as_ref(), version)?;
    record_injection(shared, injection.as_ref());
    if checked.protocol.is_some() {
        let guest_upgrade = hyper::upgrade::on(&mut request);
        return websocket(shared, guest_upgrade, &checked, route, headers, guard).await;
    }
    let head_only = checked.method == Method::HEAD;
    let activity = Arc::new(Activity::new());
    let sent = Arc::new(Sent::default());
    let (_, body) = request.into_parts();
    let injected = injection
        .as_ref()
        .map(|injection| {
            injection
                .headers()
                .iter()
                .map(|header| header.name().clone())
                .collect()
        })
        .unwrap_or_default();
    let body: UpBody = GuestBody::new(body, &activity, &sent, injected).boxed_unsync();
    let upstream_request =
        build_request(cx, version, checked.method, &checked.path, headers, body)?;
    let response = send(shared, &mut route, upstream_request, &sent).await?;
    let lease = match route {
        Route::H1(lease) => Some(lease),
        Route::H2(_) => None,
    };
    Ok(guest_response(
        response, head_only, &activity, &sent, lease, guard,
    ))
}

/// Asks the injector about the request, as the HTTP/1.1 path does: what it may add, or why the
/// request is refused.
async fn decide(
    shared: &Shared,
    checked: &Checked,
    headers: &HeaderMap,
    version: UpstreamVersion,
) -> Result<Option<Injection>, Refusal> {
    let cx = &shared.cx;
    let mut lines = header_lines(headers, &cx.target.host.to_string());
    // A WebSocket over an extended CONNECT reaches an HTTP/1.1 server as a `GET` with `Upgrade`
    // headers; the rules judge what the server will be sent.
    let websocket_over_h1 = checked.protocol.is_some() && version == UpstreamVersion::H1;
    let method = if websocket_over_h1 {
        lines.push("connection: upgrade".to_owned());
        lines.push("upgrade: websocket".to_owned());
        Method::GET.as_str()
    } else {
        checked.method.as_str()
    };
    let context = InjectContext {
        workspace: &cx.workspace,
        host: &cx.target.host,
    };
    let view = RequestView {
        method,
        target: &checked.path,
        headers: &lines,
    };
    match cx.termination.injector().decide(&context, &view).await {
        InjectDecision::Inject(injection) => Ok(Some(injection)),
        InjectDecision::PassThrough => Ok(None),
        InjectDecision::Refuse(refusal) => {
            tracing::info!(host = %cx.target.host, code = refusal.code(), "request refused by the credential rules");
            let status = StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::BAD_GATEWAY);
            let line = format!(
                "{} {}",
                status.as_str(),
                status.canonical_reason().unwrap_or("")
            );
            Err(Refusal::new(line, refusal.message().to_owned())
                .header("x-puddle-blocked", refusal.code()))
        }
    }
}

/// The request for the real server: `:authority` and `:scheme` from the URI on HTTP/2, the
/// origin-form target (the `Host` header is in `headers`) on HTTP/1.1.
fn build_request(
    cx: &Context,
    version: UpstreamVersion,
    method: Method,
    path: &str,
    headers: HeaderMap,
    body: UpBody,
) -> Result<Request<UpBody>, Refusal> {
    let uri = match version {
        UpstreamVersion::H2 => Uri::builder()
            .scheme("https")
            .authority(cx.target.host.to_string())
            .path_and_query(path)
            .build(),
        UpstreamVersion::H1 => path.parse::<Uri>().map_err(Into::into),
    }
    .map_err(|_: ::http::Error| bad("malformed request target"))?;
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .version(match version {
            UpstreamVersion::H2 => ::http::Version::HTTP_2,
            UpstreamVersion::H1 => ::http::Version::HTTP_11,
        });
    if let Some(map) = builder.headers_mut() {
        *map = headers;
    }
    builder.body(body).map_err(|_| bad("malformed request"))
}

/// Sends `request` over `route` and waits for the answer's head: `502` when the request fails,
/// `504` when the server stays silent for the upstream-head timeout after the request is fully
/// sent (`sent`). A streaming call that never finishes sending is held by the idle timeout.
async fn send(
    shared: &Shared,
    route: &mut Route,
    request: Request<UpBody>,
    sent: &Sent,
) -> Result<Response<Incoming>, Refusal> {
    let cx = &shared.cx;
    let timeout = cx.proxy.config.upstream_head_timeout;
    let head_deadline = async {
        sent.wait().await;
        tokio::time::sleep(timeout).await;
    };
    let sending = async {
        match route {
            Route::H2(sender) => Some(sender.send_request(request).await),
            Route::H1(lease) => match lease.sender() {
                Some(sender) => Some(sender.send_request(request).await),
                None => None,
            },
        }
    };
    tokio::select! {
        answered = sending => match answered {
            Some(Ok(response)) => Ok(response),
            Some(Err(err)) => {
                tracing::info!(host = %cx.target.host, error = %err, "upstream request failed");
                Err(Refusal::new(
                    "502 Bad Gateway",
                    format!("the request to {} failed: {}", cx.target.host, short(&err)),
                ))
            }
            None => Err(Refusal::new("502 Bad Gateway", "the upstream connection is gone")),
        },
        () = head_deadline => Err(Refusal::new(
            "504 Gateway Timeout",
            format!("{} did not answer within {}s", cx.target.host, timeout.as_secs()),
        )),
    }
}

/// An extended `CONNECT` for a WebSocket (RFC 8441): to an HTTP/2 server it is passed on as it is;
/// to an HTTP/1.1 server it becomes the `Upgrade` handshake of RFC 6455 with a key of the
/// proxy's own. Either way the answer is a `200` and the two connections become a byte pipe.
async fn websocket(
    shared: &Arc<Shared>,
    guest_upgrade: hyper::upgrade::OnUpgrade,
    checked: &Checked,
    mut route: Route,
    mut headers: HeaderMap,
    guard: StreamGuard,
) -> Result<Response<RespBody>, Refusal> {
    let cx = &shared.cx;
    let version = route.version();
    let mut key = None;
    let method = match version {
        UpstreamVersion::H2 => Method::CONNECT,
        UpstreamVersion::H1 => {
            if !ws::version_ok(&headers) {
                return Err(bad("only Sec-WebSocket-Version 13 is supported"));
            }
            let fresh = ws::new_key().ok_or_else(|| {
                Refusal::new("502 Bad Gateway", "no random bytes for the WebSocket key")
            })?;
            headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            headers.insert(
                HeaderName::from_static("sec-websocket-key"),
                HeaderValue::from_str(&fresh).map_err(|_| bad("key"))?,
            );
            key = Some(fresh);
            Method::GET
        }
    };
    let empty: UpBody = http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut upstream_request = build_request(cx, version, method, &checked.path, headers, empty)?;
    if version == UpstreamVersion::H2
        && let Some(protocol) = &checked.protocol
    {
        upstream_request.extensions_mut().insert(protocol.clone());
    }
    let finished = Sent::default();
    finished.finish();
    let mut response = send(shared, &mut route, upstream_request, &finished).await?;
    let agreed = match version {
        UpstreamVersion::H2 => response.status().is_success(),
        UpstreamVersion::H1 => response.status() == StatusCode::SWITCHING_PROTOCOLS,
    };
    let lease = match route {
        Route::H1(lease) => Some(lease),
        Route::H2(_) => None,
    };
    if !agreed {
        // The server said no: its answer goes to the guest as any other.
        let activity = Arc::new(Activity::new());
        let sent = Arc::new(Sent::default());
        sent.finish();
        return Ok(guest_response(
            response, false, &activity, &sent, lease, guard,
        ));
    }
    if let Some(key) = &key
        && !ws::accept_matches(response.headers(), key)
    {
        return Err(Refusal::new(
            "502 Bad Gateway",
            "the server's WebSocket answer was not valid",
        ));
    }
    let upstream_upgrade = hyper::upgrade::on(&mut response);
    let mut answer = Response::new(
        http_body_util::Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    for (name, value) in ws::answer_headers(response.headers(), false) {
        answer.headers_mut().append(name, value);
    }
    tokio::spawn(async move {
        let _guard = guard;
        let _lease = lease;
        let (guest, upstream) = tokio::join!(guest_upgrade, upstream_upgrade);
        match (guest, upstream) {
            (Ok(guest), Ok(upstream)) => {
                let mut guest = TokioIo::new(guest);
                ws::splice(&mut guest, upstream).await;
            }
            (guest, upstream) => {
                tracing::debug!(guest = ?guest.err(), upstream = ?upstream.err(), "the WebSocket upgrade did not complete");
            }
        }
    });
    Ok(answer)
}

fn record_injection(shared: &Shared, injection: Option<&Injection>) {
    if let Some(injection) = injection {
        let mut outcome = shared
            .outcome
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        outcome.injected = true;
        outcome
            .binding_id
            .get_or_insert_with(|| injection.binding_id().to_owned());
    }
}

fn short(err: &hyper::Error) -> String {
    use std::error::Error as _;
    err.source()
        .map_or_else(|| err.to_string(), ToString::to_string)
}

/// Headers of a response that describe the upstream connection, not the message.
fn is_connection_specific(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The upstream's response, for the HTTP/2 guest: connection-specific headers removed, the body
/// (and its trailers) streamed through.
fn guest_response(
    response: Response<Incoming>,
    head_only: bool,
    activity: &Arc<Activity>,
    sent: &Arc<Sent>,
    lease: Option<Lease>,
    guard: StreamGuard,
) -> Response<RespBody> {
    let (mut parts, body) = response.into_parts();
    let named_in_connection: Vec<String> = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    let mut headers = HeaderMap::with_capacity(parts.headers.len());
    let mut last: Option<HeaderName> = None;
    for (name, value) in std::mem::take(&mut parts.headers) {
        let name = name.or_else(|| last.clone());
        let Some(name) = name else { continue };
        last = Some(name.clone());
        if is_connection_specific(&name) || named_in_connection.iter().any(|t| t == name.as_str()) {
            continue;
        }
        headers.append(name, value);
    }
    parts.headers = headers;
    parts.version = ::http::Version::HTTP_2;
    let body = if head_only {
        // `HEAD` and `304` describe a body they do not carry; an HTTP/2 stream just ends.
        UpstreamBody::empty(lease, sent, guard)
    } else {
        UpstreamBody::new(body, activity, sent, lease, guard)
    };
    Response::from_parts(parts, body.boxed_unsync())
}

// ---------------------------------------------------------------------------------------------
// Bodies

/// When a stream last moved a frame in either direction.
#[derive(Debug)]
pub(crate) struct Activity {
    base: tokio::time::Instant,
    last_ms: AtomicU64,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn quiet_for(&self) -> Duration {
        let now = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// Whether the request body has been read to its end, and the wait for that.
#[derive(Debug, Default)]
pub(crate) struct Sent {
    done: AtomicBool,
    notify: Notify,
}

impl Sent {
    fn finish(&self) {
        self.done.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_done() {
                return;
            }
            notified.await;
        }
    }
}

/// Fires when the stream it watches has moved no frame for the idle time.
struct IdleTimer {
    activity: Arc<Activity>,
    sleep: Pin<Box<Sleep>>,
}

impl IdleTimer {
    fn new(activity: &Arc<Activity>) -> Self {
        Self {
            activity: Arc::clone(activity),
            sleep: Box::pin(tokio::time::sleep(STREAM_IDLE)),
        }
    }

    fn poll_expired(&mut self, cx: &mut TaskContext<'_>) -> Poll<()> {
        loop {
            std::task::ready!(self.sleep.as_mut().poll(cx));
            let quiet = self.activity.quiet_for();
            if quiet >= STREAM_IDLE {
                return Poll::Ready(());
            }
            self.sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + STREAM_IDLE.saturating_sub(quiet));
        }
    }
}

fn timed_out() -> BoxError {
    tracing::info!("an HTTP/2 stream moved no frame for too long and was reset");
    Box::new(io::Error::new(
        io::ErrorKind::TimedOut,
        "the stream was idle for too long",
    ))
}

/// The guest's request body on its way upstream.
///
/// A guest may end a stream with `RST_STREAM(NO_ERROR)` after fewer bytes than its
/// `Content-Length`; the HTTP/2 library reports that as a clean end. Forwarded as it is, the
/// upstream request would be framed as complete with a body shorter than it declared, which is how
/// a server that translates HTTP/2 to HTTP/1.1 behind us gets desynchronised. So the bytes are
/// counted and a body that ends short is an error, which resets the upstream stream.
struct GuestBody {
    inner: Incoming,
    activity: Arc<Activity>,
    sent: Arc<Sent>,
    timer: IdleTimer,
    /// The `Content-Length` the guest declared, if any.
    expected: Option<u64>,
    received: u64,
    /// Headers the proxy sets itself: a guest may not send them in a trailer either.
    injected: Vec<HeaderName>,
}

impl GuestBody {
    fn new(
        inner: Incoming,
        activity: &Arc<Activity>,
        sent: &Arc<Sent>,
        injected: Vec<HeaderName>,
    ) -> Self {
        if inner.is_end_stream() {
            sent.finish();
        }
        activity.touch();
        Self {
            expected: inner.size_hint().exact(),
            received: 0,
            injected,
            inner,
            activity: Arc::clone(activity),
            sent: Arc::clone(sent),
            timer: IdleTimer::new(activity),
        }
    }
}

/// Takes out of a trailer block what must not travel there (RFC 9110 §6.5.1: framing, routing and
/// authentication fields) and what the proxy injected into the head.
fn scrub_trailers(trailers: &mut HeaderMap, injected: &[HeaderName]) {
    let names: Vec<HeaderName> = trailers
        .keys()
        .filter(|name| {
            request::is_proxy_owned(name)
                || matches!(
                    name.as_str(),
                    "authorization"
                        | "cookie"
                        | "content-encoding"
                        | "content-type"
                        | "content-range"
                )
                || injected.contains(name)
        })
        .cloned()
        .collect();
    for name in names {
        trailers.remove(&name);
    }
}

fn body_ended_short() -> BoxError {
    Box::new(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the request body ended before its Content-Length",
    ))
}

impl Body for GuestBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.activity.touch();
                let frame = match frame.into_data() {
                    Ok(data) => {
                        this.received = this.received.saturating_add(data.len() as u64);
                        Frame::data(data)
                    }
                    Err(frame) => match frame.into_trailers() {
                        Ok(mut trailers) => {
                            scrub_trailers(&mut trailers, &this.injected);
                            Frame::trailers(trailers)
                        }
                        Err(frame) => frame,
                    },
                };
                if this.inner.is_end_stream() {
                    this.sent.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err)))),
            Poll::Ready(None) => {
                if this
                    .expected
                    .is_some_and(|expected| expected != this.received)
                {
                    return Poll::Ready(Some(Err(body_ended_short())));
                }
                this.sent.finish();
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.timer.poll_expired(cx).is_ready() {
                    Poll::Ready(Some(Err(timed_out())))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The upstream's response body on its way to the guest. It holds the HTTP/1.1 connection it
/// came over, which goes back to the pool once the body ended cleanly and the request was fully
/// sent.
struct UpstreamBody {
    inner: Option<Incoming>,
    activity: Arc<Activity>,
    sent: Arc<Sent>,
    lease: Option<Lease>,
    timer: IdleTimer,
    _guard: StreamGuard,
}

impl UpstreamBody {
    fn new(
        inner: Incoming,
        activity: &Arc<Activity>,
        sent: &Arc<Sent>,
        lease: Option<Lease>,
        guard: StreamGuard,
    ) -> Self {
        let mut body = Self {
            inner: Some(inner),
            activity: Arc::clone(activity),
            sent: Arc::clone(sent),
            lease,
            timer: IdleTimer::new(activity),
            _guard: guard,
        };
        if body.inner.as_ref().is_some_and(Incoming::is_end_stream) {
            body.finished();
        }
        body
    }

    fn empty(lease: Option<Lease>, sent: &Arc<Sent>, guard: StreamGuard) -> Self {
        let activity = Arc::new(Activity::new());
        let mut body = Self {
            inner: None,
            activity: Arc::clone(&activity),
            sent: Arc::clone(sent),
            lease,
            timer: IdleTimer::new(&activity),
            _guard: guard,
        };
        body.finished();
        body
    }

    /// The response ended: the connection is reusable only if the request ended too.
    fn finished(&mut self) {
        if let Some(mut lease) = self.lease.take()
            && self.sent.is_done()
        {
            lease.mark_reusable();
        }
    }
}

impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                this.activity.touch();
                if this.inner.as_ref().is_some_and(Incoming::is_end_stream) {
                    this.finished();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.lease = None;
                Poll::Ready(Some(Err(Box::new(err))))
            }
            Poll::Ready(None) => {
                this.finished();
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.timer.poll_expired(cx).is_ready() {
                    this.lease = None;
                    Poll::Ready(Some(Err(timed_out())))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.as_ref().is_none_or(Incoming::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Some(inner) => inner.size_hint(),
            None => SizeHint::with_exact(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use puddle_types::Host;

    use super::*;
    use crate::target::Target;

    fn target() -> Target {
        Target {
            host: Host::parse_normalised("bound.test").unwrap(),
            port: 443,
        }
    }

    fn builder() -> ::http::request::Builder {
        Request::builder().uri("https://bound.test/a?b=1")
    }

    fn status(refusal: &Refusal) -> &str {
        refusal.status.split(' ').next().unwrap()
    }

    #[test]
    fn a_request_for_the_connection_host_passes_with_its_path_and_query() {
        let request = builder().body(()).unwrap();
        let checked = check(&request, &target()).unwrap();
        assert_eq!(checked.method, Method::GET);
        assert_eq!(checked.path, "/a?b=1");
        assert!(checked.protocol.is_none());
        // `Host` and `:authority` may both be there if they agree, with or without the port.
        for host in ["bound.test", "Bound.Test:443"] {
            let request = builder().header("host", host).body(()).unwrap();
            assert!(check(&request, &target()).is_ok(), "{host}");
        }
    }

    #[test]
    fn a_request_for_another_host_or_in_another_form_is_refused() {
        for (what, request, code) in [
            (
                "another authority",
                Request::builder()
                    .uri("https://other.test/")
                    .body(())
                    .unwrap(),
                "421",
            ),
            (
                "another port",
                Request::builder()
                    .uri("https://bound.test:8443/")
                    .body(())
                    .unwrap(),
                "421",
            ),
            (
                "a Host that disagrees",
                builder().header("host", "other.test").body(()).unwrap(),
                "421",
            ),
            (
                "two Host headers",
                builder()
                    .header("host", "bound.test")
                    .header("host", "bound.test")
                    .body(())
                    .unwrap(),
                "400",
            ),
            (
                "a Host that is not text",
                builder()
                    .header("host", HeaderValue::from_bytes(b"bound\xff.test").unwrap())
                    .body(())
                    .unwrap(),
                "400",
            ),
            (
                "no authority at all",
                Request::builder().uri("/a").body(()).unwrap(),
                "400",
            ),
            (
                "userinfo",
                Request::builder()
                    .uri("https://user@bound.test/")
                    .body(())
                    .unwrap(),
                "400",
            ),
            (
                "http scheme",
                Request::builder()
                    .uri("http://bound.test/")
                    .body(())
                    .unwrap(),
                "400",
            ),
        ] {
            let refusal = check(&request, &target()).unwrap_err();
            assert_eq!(status(&refusal), code, "{what}: {}", refusal.message);
        }
    }

    #[test]
    fn headers_that_do_not_exist_in_http2_are_refused() {
        for (name, value) in [
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("te", "gzip"),
        ] {
            let request = builder().header(name, value).body(()).unwrap();
            let refusal = check(&request, &target()).unwrap_err();
            assert_eq!(status(&refusal), "400", "{name}");
        }
        let request = builder().header("te", "Trailers").body(()).unwrap();
        assert!(check(&request, &target()).is_ok());
    }

    #[test]
    fn content_length_and_expect_are_checked() {
        for (values, ok) in [
            (vec!["10"], true),
            (vec!["10", "10"], true),
            (vec!["10", "11"], false),
            (vec!["ten"], false),
            (vec!["-1"], false),
        ] {
            let mut request = builder();
            for value in &values {
                request = request.header("content-length", *value);
            }
            let result = check(&request.body(()).unwrap(), &target());
            assert_eq!(result.is_ok(), ok, "{values:?}");
        }
        let request = builder().header("expect", "100-continue").body(()).unwrap();
        assert!(check(&request, &target()).is_ok());
        let request = builder().header("expect", "gimme").body(()).unwrap();
        assert_eq!(status(&check(&request, &target()).unwrap_err()), "417");
    }

    #[test]
    fn connect_is_for_websockets_only() {
        let plain = Request::builder()
            .method("CONNECT")
            .uri("https://bound.test/")
            .body(())
            .unwrap();
        assert_eq!(status(&check(&plain, &target()).unwrap_err()), "400");
        let websocket = Request::builder()
            .method("CONNECT")
            .uri("https://bound.test/chat")
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .body(())
            .unwrap();
        let checked = check(&websocket, &target()).unwrap();
        assert_eq!(
            checked.protocol.as_ref().map(hyper::ext::Protocol::as_str),
            Some("websocket")
        );
        let stray = builder()
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .body(())
            .unwrap();
        assert_eq!(status(&check(&stray, &target()).unwrap_err()), "400");
    }

    #[test]
    fn the_injector_sees_the_lines_of_an_http11_head_with_the_host() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("bound.test"));
        headers.append("cookie", HeaderValue::from_static("a=1"));
        headers.append("cookie", HeaderValue::from_static("b=2"));
        headers.insert("x-bytes", HeaderValue::from_bytes(b"a\xffb").unwrap());
        let lines = header_lines(&headers, "bound.test");
        assert_eq!(lines.first().map(String::as_str), Some("host: bound.test"));
        assert_eq!(lines.iter().filter(|l| l.starts_with("host:")).count(), 1);
        assert_eq!(lines.iter().filter(|l| l.starts_with("cookie:")).count(), 2);
        assert!(lines.iter().any(|l| l.starts_with("x-bytes: a")));
    }

    #[test]
    fn a_refusal_becomes_a_response_with_its_status_headers_and_text() {
        let refusal = Refusal::new("403 Forbidden", "nope").header("x-puddle-blocked", "why");
        let response = refusal_response(&refusal);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["x-puddle-blocked"], "why");
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        let odd = refusal_response(&Refusal::new("garbage", "x"));
        assert_eq!(odd.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn trailers_lose_framing_routing_authentication_and_injected_names() {
        let mut trailers = HeaderMap::new();
        for name in [
            "x-kept",
            "grpc-status",
            "authorization",
            "cookie",
            "host",
            "content-length",
            "transfer-encoding",
            "x-api-key",
        ] {
            trailers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "v".parse().unwrap(),
            );
        }
        scrub_trailers(&mut trailers, &[HeaderName::from_static("x-api-key")]);
        let mut left: Vec<&str> = trailers.keys().map(HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["grpc-status", "x-kept"]);
    }

    #[test]
    fn connection_specific_response_headers_are_dropped() {
        for name in [
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailer",
        ] {
            assert!(
                is_connection_specific(&HeaderName::from_static(name)),
                "{name}"
            );
        }
        assert!(!is_connection_specific(&HeaderName::from_static(
            "content-type"
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stream_with_no_frame_for_the_idle_time_times_out_and_activity_defers_it() {
        let activity = Arc::new(Activity::new());
        let mut timer = IdleTimer::new(&activity);
        let mut cx = TaskContext::from_waker(std::task::Waker::noop());
        assert!(timer.poll_expired(&mut cx).is_pending());
        tokio::time::advance(STREAM_IDLE.saturating_sub(Duration::from_secs(1))).await;
        activity.touch();
        tokio::time::advance(Duration::from_secs(2)).await;
        // The timer's own deadline passed, but a frame moved a moment ago.
        assert!(timer.poll_expired(&mut cx).is_pending());
        tokio::time::advance(STREAM_IDLE + Duration::from_secs(1)).await;
        assert!(timer.poll_expired(&mut cx).is_ready());
    }

    #[tokio::test]
    async fn the_sent_flag_wakes_its_waiters_once_and_stays_set() {
        let sent = Arc::new(Sent::default());
        let waiter = {
            let sent = Arc::clone(&sent);
            tokio::spawn(async move { sent.wait().await })
        };
        tokio::task::yield_now().await;
        assert!(!sent.is_done());
        sent.finish();
        waiter.await.unwrap();
        sent.wait().await;
    }
}
