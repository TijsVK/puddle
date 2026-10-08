// SPDX-License-Identifier: GPL-3.0-or-later
//! The upstream leg of a terminated connection: connecting to the real server with the protocols
//! the guest offered, and the connections it yields.
//!
//! One guest connection owns its upstream connections and never shares them (PX-33): one HTTP/2
//! connection that carries every stream, or HTTP/1.1 connections that carry one request at a time
//! (one for an HTTP/1.1 guest, a small pool for an HTTP/2 guest talking to an HTTP/1.1 server).

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use super::guest::{ALPN_HTTP11, Proto};
use super::session::{Context, MAX_RESPONSE_HEAD, MAX_RESPONSE_HEADERS, upstream_tls_refusal};
use crate::proxy::Refusal;
use crate::upstream::connect_out;

/// An error a body carries from one leg to the other.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body as the upstream clients take it.
pub(crate) type UpBody = UnsyncBoxBody<Bytes, BoxError>;

/// Most upstream HTTP/1.1 connections one HTTP/2 guest connection opens.
pub(crate) const MAX_POOLED: usize = 8;

/// How often an HTTP/2 connection with streams open is pinged, and how long it may stay silent
/// after a ping before it is dropped. A gRPC watch or an event stream is idle by design; the ping
/// is what tells a live peer from a dead one.
pub(crate) const PING_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const PING_TIMEOUT: Duration = Duration::from_secs(20);

/// The largest HTTP/2 frame payload accepted on either leg, announced to the peer. The default,
/// 16 KiB, made a bulk transfer through the proxy several times slower than a pass-through of
/// the same connection: every frame costs a parse and a copy on each leg.
pub(crate) const MAX_FRAME_SIZE: u32 = 64 * 1024;

/// The largest header list accepted from the upstream on HTTP/2 (RFC 9113 §6.5.2).
const MAX_UPSTREAM_HEADER_LIST: u32 = 64 * 1024;

/// An HTTP/1.1 connection to the real server and its driver task.
pub(crate) struct H1Conn {
    pub(crate) sender: http1::SendRequest<UpBody>,
    driver: JoinHandle<()>,
}

impl Drop for H1Conn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// An HTTP/2 connection to the real server. The driver ends by itself once every sender and
/// every stream is gone, so dropping this does not cut streams that are still running.
pub(crate) struct H2Conn {
    pub(crate) sender: http2::SendRequest<UpBody>,
}

/// A verified connection to the real server.
pub(crate) enum Connected {
    H1(H1Conn),
    H2(H2Conn),
}

impl Connected {
    pub(crate) fn proto(&self) -> Proto {
        match self {
            Self::H1(_) => Proto::H1,
            Self::H2(_) => Proto::H2,
        }
    }
}

/// A connection and what the audit learns from making it.
pub(crate) struct Made {
    pub(crate) conn: Connected,
    pub(crate) hop: Option<String>,
    pub(crate) ip: Option<std::net::IpAddr>,
}

/// Connects to the real server for `cx`'s target and verifies it, offering `alpn`. A certificate
/// that is not accepted is a `502` that names the reason; no request byte has been sent.
///
/// # Errors
/// The refusal to give the guest.
pub(crate) async fn connect(cx: &Context, alpn: &[&[u8]]) -> Result<Made, Refusal> {
    let config = cx.proxy.config;
    let out = connect_out(
        cx.proxy.upstream(),
        &cx.target,
        true,
        &cx.admitted,
        config.connect_timeout,
    )
    .await?;
    let hop = out.hop.clone();
    let ip = out.addr.map(|addr| addr.ip());
    let name = cx.target.host.to_string();
    let tls = match tokio::time::timeout(
        config.tls_handshake_timeout,
        cx.tls.connect_alpn(&name, out.stream, alpn),
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
    let proto = Proto::from_alpn(tls.get_ref().1.alpn_protocol());
    let io = TokioIo::new(tls);
    let setup_failed = |err: hyper::Error| {
        tracing::info!(host = %name, error = %err, "HTTP client setup failed");
        Refusal::new("502 Bad Gateway", format!("could not talk HTTP to {name}"))
    };
    let conn = match proto {
        Proto::H1 => {
            let (sender, connection) = http1::Builder::new()
                .max_buf_size(MAX_RESPONSE_HEAD)
                .max_headers(MAX_RESPONSE_HEADERS)
                .handshake::<_, UpBody>(io)
                .await
                .map_err(setup_failed)?;
            let driver = tokio::spawn(async move {
                if let Err(err) = connection.with_upgrades().await {
                    tracing::debug!(error = %err, "upstream connection ended");
                }
            });
            Connected::H1(H1Conn { sender, driver })
        }
        Proto::H2 => {
            let (sender, connection) = http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .adaptive_window(true)
                .max_frame_size(MAX_FRAME_SIZE)
                .keep_alive_interval(PING_INTERVAL)
                .keep_alive_timeout(PING_TIMEOUT)
                .max_header_list_size(MAX_UPSTREAM_HEADER_LIST)
                .handshake::<_, UpBody>(io)
                .await
                .map_err(setup_failed)?;
            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    tracing::debug!(error = %err, "upstream HTTP/2 connection ended");
                }
            });
            Connected::H2(H2Conn { sender })
        }
    };
    Ok(Made { conn, hop, ip })
}

/// The HTTP/1.1 connections an HTTP/2 guest connection uses toward an HTTP/1.1 server: idle ones
/// are kept for the next stream, and at most [`MAX_POOLED`] exist at once.
#[derive(Clone)]
pub(crate) struct H1Pool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    idle: Mutex<Vec<H1Conn>>,
    permits: Arc<Semaphore>,
}

impl H1Pool {
    /// A pool that starts with the already verified `first`.
    pub(crate) fn new(first: H1Conn) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                idle: Mutex::new(vec![first]),
                permits: Arc::new(Semaphore::new(MAX_POOLED)),
            }),
        }
    }

    /// An idle connection, or a new one when fewer than [`MAX_POOLED`] are in use; otherwise
    /// waits (at most `wait`) for one to come back.
    ///
    /// # Errors
    /// No connection could be had: the refusal to give the guest.
    pub(crate) async fn checkout(&self, cx: &Context, wait: Duration) -> Result<Lease, Refusal> {
        let acquired =
            tokio::time::timeout(wait, Arc::clone(&self.inner.permits).acquire_owned()).await;
        let Ok(Ok(permit)) = acquired else {
            return Err(Refusal::new(
                "503 Service Unavailable",
                format!(
                    "all {MAX_POOLED} connections to {} are busy",
                    cx.target.host
                ),
            ));
        };
        loop {
            let idle = self
                .inner
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            let Some(mut conn) = idle else { break };
            // `ready` waits until the connection has settled after its last response, so one the
            // server closed (or fed stray bytes) is seen as closed here.
            if conn.sender.ready().await.is_ok() {
                return Ok(Lease::new(conn, self, permit));
            }
        }
        match connect(cx, &[ALPN_HTTP11]).await?.conn {
            Connected::H1(conn) => Ok(Lease::new(conn, self, permit)),
            Connected::H2(_) => Err(Refusal::new(
                "502 Bad Gateway",
                "the server chose a protocol that was not offered",
            )),
        }
    }
}

/// An HTTP/1.1 connection checked out of a [`H1Pool`]. It goes back only when the exchange ended
/// cleanly ([`Self::reusable`]); otherwise it is dropped, which closes it.
pub(crate) struct Lease {
    conn: Option<H1Conn>,
    pool: Arc<PoolInner>,
    reusable: bool,
    _permit: OwnedSemaphorePermit,
}

impl Lease {
    fn new(conn: H1Conn, pool: &H1Pool, permit: OwnedSemaphorePermit) -> Self {
        Self {
            conn: Some(conn),
            pool: Arc::clone(&pool.inner),
            reusable: false,
            _permit: permit,
        }
    }

    pub(crate) fn sender(&mut self) -> Option<&mut http1::SendRequest<UpBody>> {
        self.conn.as_mut().map(|conn| &mut conn.sender)
    }

    /// The exchange is complete in both directions: the connection may carry another request.
    pub(crate) fn mark_reusable(&mut self) {
        self.reusable = true;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take()
            && self.reusable
            && !conn.sender.is_closed()
        {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(conn);
        }
    }
}
