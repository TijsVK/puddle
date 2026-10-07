// SPDX-License-Identifier: GPL-3.0-or-later
//! One terminated connection, from the `CONNECT` answer to the last response.

use std::io;
use std::pin::pin;
use std::sync::atomic::Ordering;

use hyper::client::conn::http1::{self, SendRequest};
use hyper_util::rt::TokioIo;
use puddle_types::{HttpRequestLine, SandboxName};
use puddle_upstream::{TlsClient, TlsConnectError};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::task::JoinHandle;

use super::body::{Abort, ChannelBody, pump};
use super::guest::{Prefixed, acceptor};
use super::inject::{InjectContext, InjectDecision, RequestView};
use super::request::{self, Parsed};
use super::{Termination, response};
use crate::http::{self, HeadError};
use crate::proxy::{ClientReader, ProxyConfig, Refusal, refuse};
use crate::target::Target;
use crate::upstream::{Admitted, connect_out};

/// The upstream client's read buffer cap, which bounds a response head: heads up to this size are
/// always accepted and heads over twice this size never are (the client library may read a
/// little past the cap in one read, so the line between is not sharp). Real servers send a few
/// KiB.
pub(crate) const MAX_RESPONSE_HEAD: usize = 32 * 1024;

/// Most response header lines accepted from the upstream.
const MAX_RESPONSE_HEADERS: usize = 200;

/// What a connection did, for the audit record.
#[derive(Debug, Default)]
pub(crate) struct Outcome {
    /// The first request's method and path (no query).
    pub(crate) http: Option<HttpRequestLine>,
    /// Whether any request had a credential injected.
    pub(crate) injected: bool,
    /// The binding that supplied it.
    pub(crate) binding_id: Option<String>,
    /// The address first connected to.
    pub(crate) resolved_ip: Option<std::net::IpAddr>,
    /// The company-proxy hop that carried the first connection.
    pub(crate) hop: Option<String>,
    /// The guest asked for a name other than the `CONNECT` host in its TLS handshake.
    pub(crate) sni_mismatch: bool,
}

/// What a terminated connection runs on.
pub(crate) struct Context<'a> {
    pub(crate) proxy: &'a crate::proxy::Proxy,
    pub(crate) termination: &'a Termination,
    pub(crate) tls: &'a TlsClient,
    pub(crate) sandbox: &'a SandboxName,
    pub(crate) target: &'a Target,
    pub(crate) admitted: &'a Admitted,
}

/// Terminates `reader`'s connection (a `CONNECT` whose head was just read). The real server is
/// connected to when the first request arrives.
pub(crate) async fn run<S>(cx: &Context<'_>, reader: ClientReader<S>) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
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
    let (acceptor, mismatch) = match acceptor(cx.termination.ca(), &cx.target.host) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::error!(error = %err, "could not build the guest TLS configuration");
            return outcome;
        }
    };
    let config = cx.proxy.config;
    let accepted = tokio::time::timeout(
        config.tls_handshake_timeout,
        acceptor.accept(Prefixed::new(stream, early)),
    )
    .await;
    let tls = match accepted {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            outcome.sni_mismatch = mismatch.load(Ordering::Relaxed);
            if outcome.sni_mismatch {
                tracing::info!(host = %cx.target.host, "TLS handshake refused: the client asked for another name");
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
    let (read, write) = tokio::io::split(tls);
    let mut conn = Conn {
        cx,
        reader: BufReader::new(read),
        writer: write,
        upstream: None,
        outcome,
        first: true,
    };
    conn.serve().await;
    conn.outcome
}

/// The HTTP client connection to the real server, and its driver task.
struct Upstream {
    sender: SendRequest<ChannelBody>,
    driver: JoinHandle<()>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.driver.abort();
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
    cx: &'a Context<'a>,
    reader: BufReader<R>,
    writer: W,
    upstream: Option<Upstream>,
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
        let parsed = match request::parse(&head, self.cx.target) {
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
        let decision = {
            let context = InjectContext {
                sandbox: self.cx.sandbox,
                host: &self.cx.target.host,
            };
            let view = RequestView {
                method: &parsed.method,
                target: &parsed.target,
                headers: &head.headers,
            };
            self.cx.termination.injector().decide(&context, &view).await
        };
        let injection = match decision {
            InjectDecision::Inject(injection) => Some(injection),
            InjectDecision::PassThrough => None,
            InjectDecision::Refuse(refusal) => {
                tracing::info!(host = %self.cx.target.host, code = refusal.code(), "request refused by the credential rules");
                let status = ::http::StatusCode::from_u16(refusal.status())
                    .unwrap_or(::http::StatusCode::BAD_GATEWAY);
                let line = format!(
                    "{} {}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("")
                );
                return self
                    .refuse(
                        &Refusal::new(line, refusal.message().to_owned())
                            .header("x-puddle-blocked", refusal.code()),
                    )
                    .await;
            }
        };
        let headers = match request::upstream_headers(&head, self.cx.target, injection.as_ref()) {
            Ok(headers) => headers,
            Err(refusal) => return self.refuse(&refusal).await,
        };
        if let Some(injection) = &injection {
            self.outcome.injected = true;
            self.outcome
                .binding_id
                .get_or_insert_with(|| injection.binding_id().to_owned());
        }
        self.exchange(&parsed, headers).await
    }

    /// Makes sure a verified upstream connection exists.
    async fn ensure_upstream(&mut self) -> Result<(), Refusal> {
        if let Some(up) = self.upstream.as_mut() {
            // `ready` waits until the connection has settled after the last response, so a
            // connection the server closed (or fed stray bytes) is seen as closed here.
            if up.sender.ready().await.is_ok() {
                return Ok(());
            }
        }
        self.upstream = None;
        let cx = self.cx;
        let config = cx.proxy.config;
        let out = connect_out(
            cx.proxy.upstream(),
            cx.target,
            true,
            cx.admitted,
            config.connect_timeout,
        )
        .await?;
        if self.outcome.hop.is_none() && self.outcome.resolved_ip.is_none() {
            self.outcome.hop.clone_from(&out.hop);
            self.outcome.resolved_ip = out.addr.map(|addr| addr.ip());
        }
        let name = cx.target.host.to_string();
        let tls = match tokio::time::timeout(
            config.tls_handshake_timeout,
            cx.tls.connect(&name, out.stream),
        )
        .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(err)) => return Err(upstream_tls_refusal(&name, &err)),
            Err(_) => {
                return Err(Refusal::new(
                    "504 Gateway Timeout",
                    format!("the TLS handshake with {name} timed out"),
                )
                .header("x-puddle-blocked-by", "upstream-tls"));
            }
        };
        let (sender, connection) = http1::Builder::new()
            .max_buf_size(MAX_RESPONSE_HEAD)
            .max_headers(MAX_RESPONSE_HEADERS)
            .handshake::<_, ChannelBody>(TokioIo::new(tls))
            .await
            .map_err(|err| {
                tracing::info!(host = %name, error = %err, "HTTP client setup failed");
                Refusal::new("502 Bad Gateway", format!("could not talk HTTP to {name}"))
            })?;
        let driver = tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %err, "upstream connection ended");
            }
        });
        self.upstream = Some(Upstream { sender, driver });
        Ok(())
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

    /// Sends `parsed` with `headers` upstream and its response to the guest.
    async fn exchange(&mut self, parsed: &Parsed, headers: ::http::HeaderMap) -> Flow {
        let config = self.cx.proxy.config;
        let Some(upstream) = self.upstream.as_mut() else {
            return Flow::Abort;
        };
        let (body, tx, abort) = ChannelBody::new(parsed.body);
        let has_body = !matches!(parsed.body, http::Body::None | http::Body::Length(0));
        let mut builder = ::http::Request::builder()
            .method(parsed.method.as_str())
            .uri(parsed.target.as_str())
            .version(::http::Version::HTTP_11);
        if let Some(map) = builder.headers_mut() {
            *map = headers;
        }
        let Ok(request) = builder.body(body) else {
            return self
                .refuse(&Refusal::new("400 Bad Request", "malformed request"))
                .await;
        };
        if parsed.expect_continue
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
            (parsed.body, tx, abort),
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
    sender: &mut SendRequest<ChannelBody>,
    reader: &mut R,
    request: ::http::Request<ChannelBody>,
    (body, tx, abort): (http::Body, tokio::sync::mpsc::Sender<bytes::Bytes>, Abort),
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

fn short(err: &hyper::Error) -> String {
    use std::error::Error as _;
    err.source()
        .map_or_else(|| err.to_string(), ToString::to_string)
}

fn upstream_tls_refusal(name: &str, err: &TlsConnectError) -> Refusal {
    tracing::info!(host = name, error = %err, "upstream TLS refused");
    let message = match err {
        TlsConnectError::Certificate(reason) => {
            format!("the certificate of {name} was not accepted ({reason}); nothing was sent")
        }
        other => format!("could not set up TLS with {name} ({other})"),
    };
    Refusal::new("502 Bad Gateway", message).header("x-puddle-blocked-by", "upstream-tls")
}
