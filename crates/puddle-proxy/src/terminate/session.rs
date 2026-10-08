// SPDX-License-Identifier: GPL-3.0-or-later
//! One terminated connection, from the `CONNECT` answer to the last response.

use std::io;
use std::pin::pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::client::conn::http1::SendRequest;
use puddle_types::{Host, HttpRequestLine, WorkspaceName};
use puddle_upstream::{TlsClient, TlsConnectError};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use super::body::{Abort, BodyReader, ChannelBody, pump};
use super::guest::{ALPN_HTTP11, Prefixed, Proto, read_hello, server_config};
use super::inject::{Forwarding, InjectContext, Injection, RequestView, Unauthorized};
use super::leg::{self, BoxError, Connected, H1Conn, UpBody};
use super::request::{self, Parsed};
use super::stand_in::Swapped;
use super::{Termination, h2, response, ws};
use crate::http::{self, HeadError};
use crate::proxy::{ClientReader, Proxy, ProxyConfig, Refusal, refuse};
use crate::target::Target;
use crate::upstream::Admitted;

/// The upstream client's read buffer cap, which bounds a response head: heads up to this size are
/// always accepted and heads over twice this size never are (the client library may read a
/// little past the cap in one read, so the line between is not sharp). Real servers send a few
/// KiB.
pub(crate) const MAX_RESPONSE_HEAD: usize = 32 * 1024;

/// Most response header lines accepted from the upstream.
pub(crate) const MAX_RESPONSE_HEADERS: usize = 200;

/// Ends the guest's handshake with the alert for a name that is not the `CONNECT` host. Nothing
/// goes to the real server.
async fn refuse_name<S>(cx: &Context, start: tokio_rustls::StartHandshake<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tracing::info!(host = %cx.target.host, "TLS handshake refused: the client asked for another name");
    let _ = async {
        let (refuse_config, _) =
            server_config(cx.termination.ca(), &cx.target.host, &[ALPN_HTTP11]).ok()?;
        tokio::time::timeout(
            cx.proxy.config.tls_handshake_timeout,
            start.into_stream(refuse_config),
        )
        .await
        .ok()
    }
    .await;
}

/// What a connection did, for the audit record.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent fact the connection record carries"
)]
pub(crate) struct Outcome {
    /// The first request's method and path (no query).
    pub(crate) http: Option<HttpRequestLine>,
    /// Whether any request had a credential injected.
    pub(crate) injected: bool,
    /// The binding that supplied it.
    pub(crate) binding_id: Option<String>,
    /// A secret stand-in went to a host it is not for, and out unchanged.
    pub(crate) placeholder_unbound: bool,
    /// The address first connected to.
    pub(crate) resolved_ip: Option<std::net::IpAddr>,
    /// The company-proxy hop that carried the first connection.
    pub(crate) hop: Option<String>,
    /// The guest asked for a name other than the `CONNECT` host in its TLS handshake.
    pub(crate) sni_mismatch: bool,
    /// The guest's client refused the certificate (it does not trust the workspace's CA).
    pub(crate) certificate_refused: bool,
    /// The code of the first refusal the credential rules gave a request (`x-puddle-blocked`).
    pub(crate) refused: Option<&'static str>,
}

impl Outcome {
    /// Notes what the stand-in swap did to a request: a swapped stand-in counts as an injected
    /// credential (its id is the binding unless a binding already is), an unbound one raises the
    /// flag.
    pub(crate) fn record_stand_ins(&mut self, host: &Host, swapped: &Swapped) {
        if !swapped.unbound.is_empty() {
            tracing::info!(%host, stand_ins = ?swapped.unbound, "a stand-in went to a host it is not for, unchanged");
        }
        if let Some(id) = swapped.swapped.first() {
            self.injected = true;
            self.binding_id.get_or_insert_with(|| id.clone());
        }
        self.placeholder_unbound |= !swapped.unbound.is_empty();
    }
}

/// What a terminated connection runs on.
pub(crate) struct Context {
    pub(crate) proxy: Arc<Proxy>,
    pub(crate) termination: Arc<Termination>,
    pub(crate) tls: TlsClient,
    pub(crate) workspace: WorkspaceName,
    pub(crate) target: Target,
    pub(crate) admitted: Admitted,
}

/// Terminates `reader`'s connection (a `CONNECT` whose head was just read). The guest's
/// `ClientHello` is read first and its name checked; then the real server is connected to, offering
/// the protocols the guest offered, and the guest is offered what the server chose.
pub(crate) async fn run<S>(cx: Arc<Context>, reader: ClientReader<S>) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut outcome = Outcome::default();
    let early = reader.buffer().to_vec();
    let mut stream = reader.into_inner();
    if let Err(err) = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        tracing::debug!(error = %err, "guest went away before the TLS handshake");
        return outcome;
    }
    let config = cx.proxy.config;
    let hello = tokio::time::timeout(
        config.tls_handshake_timeout,
        read_hello(Prefixed::new(stream, early), &cx.target.host),
    )
    .await;
    let (start, hello) = match hello {
        Ok(Ok(read)) => read,
        Ok(Err(err)) => {
            tracing::debug!(host = %cx.target.host, error = %err, "guest TLS hello not read");
            return outcome;
        }
        Err(_) => {
            tracing::debug!(host = %cx.target.host, "guest TLS hello timed out");
            return outcome;
        }
    };
    if !hello.name_matches {
        refuse_name(&cx, start).await;
        outcome.sni_mismatch = true;
        return outcome;
    }
    // Upstream first: what the real server speaks decides what the guest is offered.
    let (first, deferred) = match leg::connect(&cx, &hello.upstream_offer()).await {
        Ok(made) => {
            outcome.hop = made.hop;
            outcome.resolved_ip = made.ip;
            (Some(made.conn), None)
        }
        Err(refusal) => (None, Some(refusal)),
    };
    let guest_proto = match &first {
        Some(conn) => hello.guest_proto(conn.proto()),
        // The real server could not be used: the guest still gets the handshake, and the first
        // request is answered with the reason.
        None if hello.offers_h1 => Proto::H1,
        None => Proto::H2,
    };
    let built = server_config(cx.termination.ca(), &cx.target.host, &[guest_proto.alpn()])
        .inspect_err(
            |err| tracing::error!(error = %err, "could not build the guest TLS configuration"),
        );
    let Ok((server_config, _)) = built else {
        return outcome; // the CA cannot sign for a name it was checked to permit
    };
    let tls = match tokio::time::timeout(
        config.tls_handshake_timeout,
        start.into_stream(server_config),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            if let Some(alert) = super::handshake::rejected_certificate(&err) {
                outcome.certificate_refused = true;
                tracing::info!(workspace = %cx.workspace, host = %cx.target.host, alert, "the client in the workspace did not accept puddle's certificate for this host");
            } else {
                tracing::debug!(host = %cx.target.host, error = %err, "guest TLS handshake failed");
            }
            return outcome;
        }
        Err(_) => {
            tracing::debug!(host = %cx.target.host, "guest TLS handshake timed out");
            return outcome;
        }
    };
    match guest_proto {
        Proto::H2 => h2::serve(cx, tls, first, deferred, outcome).await,
        Proto::H1 => {
            let upstream = match first {
                Some(Connected::H1(conn)) => Some(conn),
                _ => None,
            };
            let (read, write) = tokio::io::split(tls);
            let mut conn = Conn {
                cx: &cx,
                reader: BufReader::new(read),
                writer: write,
                upstream,
                deferred,
                outcome,
                first: true,
            };
            conn.serve().await;
            conn.outcome
        }
    }
}

/// Whether a connection goes on after a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    /// End the connection cleanly (a TLS close).
    Close,
    /// End it without a clean close: the response, if any, is incomplete.
    Abort,
}

struct Conn<'a, R, W> {
    cx: &'a Context,
    reader: BufReader<R>,
    writer: W,
    upstream: Option<H1Conn>,
    /// Why the real server could not be used at the handshake; answered by the first request.
    deferred: Option<Refusal>,
    outcome: Outcome,
    first: bool,
}

impl<R, W> Conn<'_, R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn serve(&mut self) {
        loop {
            match self.one_request().await {
                Flow::Continue => {}
                Flow::Close => {
                    if let Err(err) = self.writer.shutdown().await {
                        tracing::debug!(error = %err, "guest TLS close failed");
                    }
                    return;
                }
                Flow::Abort => return,
            }
        }
    }

    async fn refuse(&mut self, refusal: &Refusal) -> Flow {
        refuse(&mut self.writer, refusal).await;
        Flow::Abort
    }

    /// Waits for the next request's first byte. `false`: the guest closed or went quiet.
    async fn wait_for_request(&mut self) -> bool {
        let wait = if self.first {
            self.cx.proxy.config.head_timeout
        } else {
            self.cx.proxy.config.keepalive_timeout
        };
        matches!(
            tokio::time::timeout(wait, self.reader.fill_buf()).await,
            Ok(Ok(buf)) if !buf.is_empty()
        )
    }

    async fn one_request(&mut self) -> Flow {
        let config = self.cx.proxy.config;
        if !self.wait_for_request().await {
            return Flow::Close;
        }
        let head = match tokio::time::timeout(
            config.head_timeout,
            http::read_head(&mut self.reader),
        )
        .await
        {
            Err(_) => {
                return self
                    .refuse(&Refusal::new(
                        "408 Request Timeout",
                        format!(
                            "request head not received within {}s",
                            config.head_timeout.as_secs()
                        ),
                    ))
                    .await;
            }
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "guest stream failed inside the tunnel");
                return Flow::Abort;
            }
            Ok(Ok(Err(HeadError::Empty))) => return Flow::Close,
            Ok(Ok(Err(HeadError::TooLarge))) => {
                return self
                    .refuse(&Refusal::new(
                        "431 Request Header Fields Too Large",
                        format!("request head over {} KiB", http::MAX_HEAD / 1024),
                    ))
                    .await;
            }
            Ok(Ok(Err(HeadError::Bad(why)))) => {
                return self.refuse(&Refusal::new("400 Bad Request", why)).await;
            }
            Ok(Ok(Ok(head))) => head,
        };
        self.first = false;
        let parsed = match request::parse(&head, &self.cx.target) {
            Ok(parsed) => parsed,
            Err(refusal) => {
                tracing::info!(host = %self.cx.target.host, status = %refusal.status, "terminated request refused: {}", refusal.message);
                return self.refuse(&refusal).await;
            }
        };
        if self.outcome.http.is_none() {
            self.outcome.http = Some(HttpRequestLine::new(parsed.method.as_str(), &parsed.target));
        }
        tracing::debug!(host = %self.cx.target.host, method = %parsed.method, path = %puddle_types::request_path(&parsed.target), "terminated request");
        if let Err(refusal) = self.ensure_upstream().await {
            return self.refuse(&refusal).await;
        }
        let context = InjectContext {
            workspace: &self.cx.workspace,
            host: &self.cx.target.host,
        };
        let injector = self.cx.termination.injector();
        let view = RequestView::new(&parsed.method, &parsed.target, &head.headers);
        let prefetched = match injector.body_wanted(&context, &view) {
            Some(limit) => match self.read_whole_body(&parsed, limit).await {
                Ok(body) => Some(body),
                Err(flow) => return flow,
            },
            None => None,
        };
        let decision = match &prefetched {
            Some(body) => injector.decide(&context, &view.with_body(body)).await,
            None => injector.decide(&context, &view).await,
        };
        let Forwarding {
            injection,
            unauthorized,
        } = match decision.into_forwarding() {
            Ok(forwarding) => forwarding,
            Err(refusal) => {
                tracing::info!(host = %self.cx.target.host, code = refusal.code(), "request refused by the credential rules");
                self.outcome.refused.get_or_insert(refusal.code());
                return self.refuse(&refusal.to_refusal()).await;
            }
        };
        let headers = match request::upstream_headers(&head, &self.cx.target, injection.as_ref()) {
            Ok(headers) => headers,
            Err(refusal) => return self.refuse(&refusal).await,
        };
        let headers = self.add_credentials(headers, injection.as_ref());
        self.exchange(&parsed, headers, unauthorized.as_ref(), prefetched)
            .await
    }

    /// Notes the injected credential for the audit, then swaps the workspace's stand-ins in
    /// `headers` for their real values (the injected headers are left alone).
    fn add_credentials(
        &mut self,
        mut headers: ::http::HeaderMap,
        injection: Option<&Injection>,
    ) -> ::http::HeaderMap {
        if let Some(injection) = injection {
            self.outcome.injected = true;
            self.outcome
                .binding_id
                .get_or_insert_with(|| injection.binding_id().to_owned());
        }
        let host = &self.cx.target.host;
        let swapped = self
            .cx
            .termination
            .stand_ins()
            .swap(&mut headers, host, injection);
        self.outcome.record_stand_ins(host, &swapped);
        headers
    }

    /// Makes sure a verified upstream connection exists.
    async fn ensure_upstream(&mut self) -> Result<(), Refusal> {
        if let Some(refusal) = self.deferred.take() {
            return Err(refusal);
        }
        if let Some(up) = self.upstream.as_mut() {
            // `ready` waits until the connection has settled after the last response, so a
            // connection the server closed (or fed stray bytes) is seen as closed here.
            if up.sender.ready().await.is_ok() {
                return Ok(());
            }
        }
        self.upstream = None;
        self.upstream = Some(
            leg::connect(self.cx, &[ALPN_HTTP11])
                .await?
                .conn
                .into_h1()?,
        );
        Ok(())
    }

    /// Reads the guest's whole request body (at most `limit` bytes) for an injector that decides
    /// on it. `Err` is how the connection goes on: the refusal has been sent.
    async fn read_whole_body(&mut self, parsed: &Parsed, limit: usize) -> Result<Bytes, Flow> {
        let too_large = || {
            Refusal::new(
                "413 Content Too Large",
                format!("this request's body is over {limit} bytes, more than puddle reads to decide on it"),
            )
            .header("x-puddle-blocked", "body_too_large")
        };
        if matches!(parsed.body, http::Body::None | http::Body::Length(0)) {
            return Ok(Bytes::new());
        }
        if matches!(parsed.body, http::Body::Length(n) if n > limit as u64) {
            return Err(self.refuse(&too_large()).await);
        }
        if parsed.expect_continue
            && let Err(err) = self
                .writer
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
        {
            tracing::debug!(error = %err, "guest went away before its body");
            return Err(Flow::Abort);
        }
        let idle = self.cx.proxy.config.body_idle_timeout;
        let mut decoder = BodyReader::new(parsed.body);
        let mut whole = Vec::new();
        loop {
            match tokio::time::timeout(idle, decoder.next(&mut self.reader)).await {
                Ok(Ok(Some(piece))) => {
                    whole.extend_from_slice(&piece);
                    if whole.len() > limit {
                        return Err(self.refuse(&too_large()).await);
                    }
                }
                Ok(Ok(None)) => return Ok(Bytes::from(whole)),
                Ok(Err(err)) => {
                    tracing::info!(host = %self.cx.target.host, error = %err, "request body failed");
                    return Err(self
                        .refuse(&Refusal::new(
                            "400 Bad Request",
                            "the request body could not be read",
                        ))
                        .await);
                }
                Err(_) => {
                    return Err(self
                        .refuse(&Refusal::new(
                            "408 Request Timeout",
                            "the request body did not arrive",
                        ))
                        .await);
                }
            }
        }
    }

    /// Writes `response` to the guest while the guest's read side is polled (see [`keep_reading`]).
    async fn write_response(
        &mut self,
        response: ::http::Response<hyper::body::Incoming>,
        parsed: &Parsed,
        config: ProxyConfig,
    ) -> io::Result<response::Written> {
        tokio::select! {
            written = response::write(
                &mut self.writer,
                response,
                &parsed.method,
                parsed.http11,
                parsed.close,
                config.body_idle_timeout,
            ) => written,
            never = keep_reading(&mut self.reader) => match never {},
        }
    }

    /// The server agreed to the WebSocket upgrade: tells the guest, then pipes the two connections
    /// until either ends. Nothing else is sent on this connection afterwards.
    async fn splice_websocket(
        &mut self,
        response: &mut ::http::Response<hyper::body::Incoming>,
    ) -> Flow {
        let upgraded = hyper::upgrade::on(&mut *response);
        let mut head =
            b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n"
                .to_vec();
        for (name, value) in ws::answer_headers(response.headers(), true) {
            head.extend_from_slice(name.as_str().as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        let host = &self.cx.target.host;
        let piped = async {
            self.writer
                .write_all(&head)
                .await
                .inspect_err(|err| tracing::debug!(error = %err, "guest went away before the WebSocket answer"))
                .ok()?;
            let upgraded = upgraded
                .await
                .inspect_err(|_| tracing::info!(host = %host, "the WebSocket upgrade did not complete"))
                .ok()?;
            // Bytes the guest sent right behind its handshake are still in the reader's buffer.
            let mut guest = tokio::io::join(&mut self.reader, &mut self.writer);
            ws::splice(&mut guest, upgraded).await;
            Some(())
        }
        .await;
        piped.map_or(Flow::Abort, |()| Flow::Close)
    }

    /// Answers the guest with `unauthorized`'s refusal in place of the server's `401`. The server's
    /// answer is left unread, so the upstream connection is not used again.
    async fn replace_unauthorized(&mut self, unauthorized: &Unauthorized) -> Flow {
        let refusal = unauthorized.refusal();
        tracing::info!(host = %self.cx.target.host, code = refusal.code(), "401 replaced: the credential for this request was puddle's to choose");
        self.upstream = None;
        self.outcome.refused.get_or_insert(refusal.code());
        self.refuse(&refusal.to_refusal()).await
    }

    /// Sends `parsed` with `headers` upstream and its response to the guest. A `401` from the
    /// server is replaced by `unauthorized`'s answer when there is one.
    async fn exchange(
        &mut self,
        parsed: &Parsed,
        headers: ::http::HeaderMap,
        unauthorized: Option<&Unauthorized>,
        prefetched: Option<Bytes>,
    ) -> Flow {
        let config = self.cx.proxy.config;
        let Some(upstream) = self.upstream.as_mut() else {
            return Flow::Abort;
        };
        // A body the injector asked for is already read, framing and `Expect` included.
        let (framing, (channel, tx, abort)) = match prefetched {
            Some(body) => (http::Body::None, ChannelBody::prefetched(body)),
            None => (parsed.body, ChannelBody::new(parsed.body)),
        };
        let has_body = !matches!(framing, http::Body::None | http::Body::Length(0));
        let Some(request) = upstream_request(parsed, headers, channel) else {
            return self
                .refuse(&Refusal::new("400 Bad Request", "malformed request"))
                .await;
        };
        if parsed.expect_continue
            && has_body
            && let Err(err) = self
                .writer
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
        {
            tracing::debug!(error = %err, "guest went away before its body");
            return Flow::Abort;
        }
        let (sent, pumped) = send_and_pump(
            &mut upstream.sender,
            &mut self.reader,
            request,
            (framing, tx, abort),
            config,
        )
        .await;
        let body_complete = matches!(pumped, Some(Ok(())));
        let response = match sent {
            Some(Ok(response)) => response,
            Some(Err(err)) => {
                if let Some(Err(why)) = pumped {
                    tracing::info!(host = %self.cx.target.host, error = %why, "request body failed");
                    return self
                        .refuse(&Refusal::new(
                            "400 Bad Request",
                            "the request body could not be read",
                        ))
                        .await;
                }
                tracing::info!(host = %self.cx.target.host, error = %err, "upstream request failed");
                self.upstream = None;
                return self
                    .refuse(&Refusal::new(
                        "502 Bad Gateway",
                        format!(
                            "the request to {} failed: {}",
                            self.cx.target.host,
                            short(&err)
                        ),
                    ))
                    .await;
            }
            None => {
                self.upstream = None;
                return self
                    .refuse(&Refusal::new(
                        "504 Gateway Timeout",
                        format!(
                            "{} did not answer within {}s",
                            self.cx.target.host,
                            config.upstream_head_timeout.as_secs()
                        ),
                    ))
                    .await;
            }
        };
        if response.status() == ::http::StatusCode::UNAUTHORIZED
            && let Some(unauthorized) = unauthorized
        {
            return self.replace_unauthorized(unauthorized).await;
        }
        let mut response = response;
        if parsed.upgrade && response.status() == ::http::StatusCode::SWITCHING_PROTOCOLS {
            return self.splice_websocket(&mut response).await;
        }
        let written = self.write_response(response, parsed, config).await;
        match written {
            Ok(response::Written::KeepOpen) if body_complete || !has_body => Flow::Continue,
            Ok(_) => {
                if !body_complete && has_body {
                    self.upstream = None;
                }
                Flow::Close
            }
            Err(err) => {
                tracing::info!(host = %self.cx.target.host, error = %err, "response aborted");
                self.upstream = None;
                Flow::Abort
            }
        }
    }
}

/// The request to send to an HTTP/1.1 server: the checked `parsed` pieces, the rebuilt `headers`
/// and the guest's body as it is decoded. A WebSocket handshake keeps its `Upgrade` headers.
fn upstream_request(
    parsed: &Parsed,
    mut headers: ::http::HeaderMap,
    body: ChannelBody,
) -> Option<::http::Request<UpBody>> {
    if parsed.upgrade {
        headers.insert(
            ::http::header::CONNECTION,
            ::http::HeaderValue::from_static("upgrade"),
        );
        headers.insert(
            ::http::header::UPGRADE,
            ::http::HeaderValue::from_static("websocket"),
        );
    }
    let body: UpBody = body.map_err(|err| Box::new(err) as BoxError).boxed_unsync();
    let mut builder = ::http::Request::builder()
        .method(parsed.method.as_str())
        .uri(parsed.target.as_str())
        .version(::http::Version::HTTP_11);
    if let Some(map) = builder.headers_mut() {
        *map = headers;
    }
    builder.body(body).ok()
}

/// Polls the guest's read side for as long as it is dropped. A yamux stream only learns that
/// the peer opened its window again by being read, so a writer that is stuck on a full window
/// while nobody reads (the guest is waiting for the response) never wakes: a download of more
/// than one window would stall. Anything the guest does send stays buffered for the next request.
async fn keep_reading<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::convert::Infallible {
    // An empty read is the guest closing its side: the response may still go out.
    let _ = reader.fill_buf().await;
    std::future::pending().await
}

/// Sends `request` while pumping the guest's body into it. `None` as the first answer: the
/// upstream did not answer in time. The second is the pump's result, if it finished.
async fn send_and_pump<R>(
    sender: &mut SendRequest<UpBody>,
    reader: &mut R,
    request: ::http::Request<UpBody>,
    (body, tx, abort): (http::Body, tokio::sync::mpsc::Sender<Bytes>, Abort),
    config: ProxyConfig,
) -> (
    Option<Result<::http::Response<hyper::body::Incoming>, hyper::Error>>,
    Option<io::Result<()>>,
)
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let has_body = !matches!(body, http::Body::None | http::Body::Length(0));
    let sending = sender.send_request(request);
    let mut sending = pin!(sending);
    let pump_fut = async move {
        if has_body {
            pump(reader, body, tx, config.body_idle_timeout).await
        } else {
            drop(tx);
            Ok(())
        }
    };
    let mut pump_fut = pin!(pump_fut);
    let mut pumped: Option<io::Result<()>> = None;
    // The upstream's clock for the response head starts once the whole request is sent.
    let mut deadline =
        (!has_body).then(|| Box::pin(tokio::time::sleep(config.upstream_head_timeout)));
    let sent = loop {
        tokio::select! {
            result = &mut pump_fut, if pumped.is_none() => {
                if result.is_err() {
                    // Never let the upstream mistake a cut-off body for a complete one.
                    abort.abort();
                } else {
                    deadline = Some(Box::pin(tokio::time::sleep(config.upstream_head_timeout)));
                }
                pumped = Some(result);
            }
            result = &mut sending => break Some(result),
            () = async {
                match deadline.as_mut() {
                    Some(sleep) => sleep.await,
                    None => std::future::pending().await,
                }
            } => break None,
        }
    };
    if has_body && !matches!(pumped, Some(Ok(()))) {
        // The response came before the body was in, or the body failed: cut the upload off so
        // the upstream sees a failed request, before the sender goes away.
        abort.abort();
    }
    (sent, pumped)
}

pub(crate) fn short(err: &hyper::Error) -> String {
    use std::error::Error as _;
    err.source()
        .map_or_else(|| err.to_string(), ToString::to_string)
}

pub(crate) fn upstream_tls_refusal(name: &str, err: &TlsConnectError) -> Refusal {
    tracing::info!(host = name, error = %err, "upstream TLS refused");
    let message = match err {
        TlsConnectError::Certificate(reason) => {
            format!("the certificate of {name} was not accepted ({reason}); nothing was sent")
        }
        other => format!("could not set up TLS with {name} ({other})"),
    };
    Refusal::new("502 Bad Gateway", message).header("x-puddle-blocked-by", "upstream-tls")
}
