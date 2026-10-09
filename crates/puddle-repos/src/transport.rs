// SPDX-License-Identifier: GPL-3.0-or-later
//! The real route to a Git host: puddle's own connection through the company proxy chain, TLS
//! checked the way the host's own programs check it, then one HTTP/1.1 request.
//!
//! Nothing is guarded the way a workspace's request is: the destination is the credential's own
//! host, chosen by the user. A redirect is never followed, so the token goes to that host and
//! nowhere else, and an answer is read up to [`MAX_BODY`] bytes.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::future::BoxFuture;
use http::header::{ACCEPT, AUTHORIZATION, CONNECTION, HOST, USER_AGENT};
use http::{HeaderValue, Request};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use puddle_types::{
    ConnectionDecision, ConnectionEvent, ConnectionLog, ConnectionReason, Host, HttpRequestLine,
    NullConnectionLog,
};
use puddle_upstream::host::connect;
use puddle_upstream::{Chain, Destination, Form, Scheme, TlsClient, TlsConnectError};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::api::{Api, ApiReply, ApiRequest, MAX_BODY, TransportError};

/// The time one request may take, connection and TLS included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Requests over puddle's own route. Cheap to share.
pub struct HostApi {
    chain: Arc<Chain>,
    tls: TlsClient,
    timeout: Duration,
    log: Arc<dyn ConnectionLog>,
}

impl std::fmt::Debug for HostApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostApi").finish_non_exhaustive()
    }
}

impl HostApi {
    /// Requests that leave through `chain` (the company proxy route) and trust what `tls` trusts.
    #[must_use]
    pub fn new(chain: Arc<Chain>, tls: TlsClient) -> Self {
        Self {
            chain,
            tls,
            timeout: REQUEST_TIMEOUT,
            log: Arc::new(NullConnectionLog),
        }
    }

    /// The same, recording every request in `log` as puddle's own connection (origin `puddle`,
    /// the Git host, and whether it worked), like an image pull.
    #[must_use]
    pub fn with_connection_log(mut self, log: Arc<dyn ConnectionLog>) -> Self {
        self.log = log;
        self
    }

    /// The same with another limit for one request.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn exchange(&self, request: ApiRequest) -> Result<ApiReply, TransportError> {
        let authorization = request
            .authorization
            .header_value()
            .ok_or(TransportError::BadToken)?;
        let (name, port) = split_port(&request.host);
        let destination = Destination::new(Scheme::Https, name, port.unwrap_or(443));
        let connected = connect(&self.chain, &destination, Form::Tunnel)
            .await
            .map_err(|err| TransportError::Unreachable(err.to_string()))?;
        let stream = self
            .tls
            .connect(name, connected.stream)
            .await
            .map_err(|err| match err {
                TlsConnectError::InvalidName(name) => {
                    TransportError::Unreachable(format!("{name:?} is not a valid server name"))
                }
                TlsConnectError::Certificate(why) => TransportError::Tls(why),
                other => TransportError::Unreachable(format!("the TLS handshake failed: {other}")),
            })?;
        send(stream, &request, authorization).await
    }
}

impl Api for HostApi {
    fn get(&self, request: ApiRequest) -> BoxFuture<'_, Result<ApiReply, TransportError>> {
        Box::pin(async move {
            let (host, path) = (request.host.clone(), request.path.clone());
            let result = tokio::time::timeout(self.timeout, self.exchange(request))
                .await
                .unwrap_or(Err(TransportError::Timeout(self.timeout.as_secs().max(1))));
            self.record(&host, &path, &result);
            result
        })
    }
}

impl HostApi {
    /// Writes the request as a `connection` record of puddle's own. A write that fails is the
    /// log's to report; the listing is not affected.
    fn record(&self, host: &str, path: &str, result: &Result<ApiReply, TransportError>) {
        let (name, port) = split_port(host);
        let Ok(name) = Host::parse_normalised(name) else {
            return;
        };
        let (reason, down) = match result {
            Ok(reply) if reply.status < 400 => (ConnectionReason::PuddleRequest, reply.body.len()),
            Ok(reply) => (
                ConnectionReason::PuddleRequestFailed("host_refused"),
                reply.body.len(),
            ),
            Err(err) => (ConnectionReason::PuddleRequestFailed(failure_code(err)), 0),
        };
        let mut event =
            ConnectionEvent::puddle(name, port.unwrap_or(443), ConnectionDecision::Allow, reason);
        event.http = Some(HttpRequestLine::new("GET", path));
        event.bytes_down = down as u64;
        self.log.record(&event);
    }
}

/// The audit code of a request that got no answer.
fn failure_code(err: &TransportError) -> &'static str {
    match err {
        TransportError::Unreachable(_) => "unreachable",
        TransportError::Tls(_) => "tls",
        TransportError::Timeout(_) => "timeout",
        TransportError::TooLarge => "too_large",
        TransportError::Protocol(_) => "protocol",
        TransportError::BadToken => "bad_token",
    }
}

/// `host[:port]` as the name and the port when there is one.
fn split_port(host: &str) -> (&str, Option<u16>) {
    match host.rsplit_once(':') {
        Some((name, port)) => port.parse().map_or((host, None), |p| (name, Some(p))),
        None => (host, None),
    }
}

fn protocol(err: impl std::fmt::Display) -> TransportError {
    TransportError::Protocol(err.to_string())
}

/// One `GET` over `io`, which closes after the answer.
async fn send<T>(
    io: T,
    request: &ApiRequest,
    authorization: HeaderValue,
) -> Result<ApiReply, TransportError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(protocol)?;
    let mut builder = Request::builder()
        .method("GET")
        .uri(&request.path)
        .header(HOST, &request.host)
        .header(USER_AGENT, "puddle")
        .header(ACCEPT, request.accept)
        .header(AUTHORIZATION, authorization)
        .header(CONNECTION, "close");
    for (name, value) in request.headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Empty::<Bytes>::new()).map_err(protocol)?;
    tokio::pin!(connection);
    let answered = async {
        let response = sender.send_request(request).await.map_err(protocol)?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, MAX_BODY)
            .collect()
            .await
            .map_err(|err| {
                if err.is::<http_body_util::LengthLimitError>() {
                    TransportError::TooLarge
                } else {
                    protocol(err)
                }
            })?
            .to_bytes();
        let mut headers = std::collections::BTreeMap::new();
        for (name, value) in &parts.headers {
            if let Ok(value) = value.to_str() {
                headers
                    .entry(name.as_str().to_owned())
                    .or_insert_with(|| value.to_owned());
            }
        }
        Ok(ApiReply {
            status: parts.status.as_u16(),
            headers,
            body: body.to_vec(),
        })
    };
    tokio::pin!(answered);
    tokio::select! {
        biased;
        reply = &mut answered => reply,
        // The connection ends as soon as the answer is handed over, and it can win this race
        // with the answer still in the channel: the answer is read first, and the connection's
        // own error only explains one that did not arrive.
        ended = &mut connection => match answered.await {
            Ok(reply) => Ok(reply),
            Err(err) => Err(ended.map_or_else(protocol, |()| err)),
        },
    }
}
