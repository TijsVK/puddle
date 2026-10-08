// SPDX-License-Identifier: GPL-3.0-or-later
//! The host side of one agent connection: accept the yamux session, serve the control stream,
//! hand every other stream to the proxy.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use puddle_agent_proto::host::{serve_session, GuestStream, HostConfig, StreamHandler};
//! # use puddle_types::{NullSink, WorkspaceName};
//! struct Proxy;
//! impl StreamHandler for Proxy {
//!     async fn handle(&self, stream: GuestStream) {
//!         // read the CONNECT line from `stream`, decide, splice ...
//!         # drop(stream);
//!     }
//! }
//! # async fn f(
//! #     conn: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let workspace = WorkspaceName::new("box")?;
//! serve_session(conn, workspace, Arc::new(NullSink), Arc::new(Proxy), HostConfig::default()).await?;
//! # Ok(()) }
//! ```

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::StreamExt;
use puddle_types::{Event, EventSink, WorkspaceName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_yamux::{Session, StreamHandle};

use crate::control::{self, AgentMessage, MAX_LINE};
use crate::kind::{MAX_PREAMBLE, StreamKind, parse_preamble};
use crate::resolve::{self, ResolveAnswer, ResolveQuery};
use crate::yamux::{VERSION_BYTE, server_config};

/// Name used in [`Event::OomKill`] when the agent couldn't tell which process was killed (its pid
/// is then 0).
pub const UNKNOWN_PROCESS: &str = "unknown";

/// Longest agent version string kept for the log.
const MAX_VERSION_CHARS: usize = 64;

/// Limits for one session. The defaults suit a real guest; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostConfig {
    /// How long a new connection or stream may stay silent before its first byte. A proxied
    /// client sends its request line at once; the agent writes the control preamble at once.
    pub first_byte_timeout: Duration,
    /// Control messages a stream may send in one burst.
    pub control_burst: u32,
    /// Control messages per second a stream may send after its burst. Messages over the limit are
    /// dropped and counted in a warning.
    pub control_per_second: u32,
    /// Name lookups (`resolve` streams) one session may have open at once. Over it, a lookup is
    /// answered [`ResolveAnswer::Unavailable`] without asking the handler.
    pub max_resolves: usize,
    /// How long the handler may take to answer one lookup. Over it: [`ResolveAnswer::Unavailable`].
    pub resolve_timeout: Duration,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            first_byte_timeout: Duration::from_secs(30),
            control_burst: 32,
            control_per_second: 10,
            max_resolves: 64,
            resolve_timeout: Duration::from_secs(15),
        }
    }
}

/// Why a session ended other than cleanly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The connection doesn't start with a yamux frame, so it isn't from `puddle-agent`.
    #[error("not a yamux session: first byte {0:#04x}")]
    NotYamux(u8),
    /// Nothing arrived within [`HostConfig::first_byte_timeout`].
    #[error("no data from the guest within {0:?}")]
    Timeout(Duration),
    /// The connection or the yamux session failed.
    #[error("session i/o: {0}")]
    Io(#[from] io::Error),
}

/// What the host does with a proxied guest connection (one yamux stream that isn't the control
/// stream). The proxy implements it.
pub trait StreamHandler: Send + Sync + 'static {
    /// Serves one connection. Errors are the handler's to log; to pass an abort on, drop the
    /// stream without shutting it down (see [`crate::relay`]).
    fn handle(&self, stream: GuestStream) -> impl Future<Output = ()> + Send;

    /// Answers one name lookup from the guest's stub DNS. The default says
    /// [`ResolveAnswer::Unavailable`]: a handler without a name policy never invents an answer.
    /// The query is untrusted; the handler normalises and checks it.
    fn resolve(&self, query: ResolveQuery) -> impl Future<Output = ResolveAnswer> + Send {
        let _ = query;
        async { ResolveAnswer::Unavailable }
    }
}

/// One proxied guest connection: a yamux stream with its first byte (already read by the host to
/// tell it from the control stream) put back in front.
#[derive(Debug)]
pub struct GuestStream(Prefixed<StreamHandle>);

impl AsyncRead for GuestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// A stream with one already-read byte put back in front of it.
#[derive(Debug)]
struct Prefixed<S> {
    first: Option<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() > 0
            && let Some(b) = self.first.take()
        {
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// State shared by the streams of one session.
struct Shared<H> {
    workspace: WorkspaceName,
    sink: Arc<dyn EventSink>,
    handler: Arc<H>,
    config: HostConfig,
    /// Set while a control stream is open: a session has at most one.
    control_open: AtomicBool,
    /// Lookups in flight on this session.
    resolves: Semaphore,
}

/// Serves one connection from a workspace's agent until it closes. `workspace` is the workspace the
/// route belongs to (the route is the identity): nothing the guest sends can change it.
///
/// Every stream task is owned here and ends when the session does.
///
/// # Errors
///
/// [`SessionError::NotYamux`] for a connection that isn't a yamux session,
/// [`SessionError::Timeout`] if it stays silent, [`SessionError::Io`] if the session fails. A
/// clean close by the guest is `Ok`.
pub async fn serve_session<IO, H>(
    mut io: IO,
    workspace: WorkspaceName,
    sink: Arc<dyn EventSink>,
    handler: Arc<H>,
    config: HostConfig,
) -> Result<(), SessionError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: StreamHandler,
{
    let Some(first) = first_byte(&mut io, config.first_byte_timeout).await? else {
        return Ok(());
    };
    if first != VERSION_BYTE {
        return Err(SessionError::NotYamux(first));
    }
    let shared = Arc::new(Shared {
        workspace,
        sink,
        handler,
        resolves: Semaphore::new(config.max_resolves),
        config,
        control_open: AtomicBool::new(false),
    });
    let mut session = Session::new_server(
        Prefixed {
            first: Some(first),
            inner: io,
        },
        server_config(),
    );
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            inbound = session.next() => match inbound {
                None => return Ok(()),
                Some(Err(err)) => return Err(err.into()),
                Some(Ok(stream)) => {
                    tasks.spawn(serve_stream(stream, Arc::clone(&shared)));
                }
            },
            Some(done) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(err) = done
                    && err.is_panic()
                {
                    tracing::error!(workspace = %shared.workspace, "stream task panicked");
                }
            }
        }
    }
}

/// Reads the first byte within `limit`; `None` at a clean end of stream.
async fn first_byte<R: AsyncRead + Unpin>(
    io: &mut R,
    limit: Duration,
) -> Result<Option<u8>, SessionError> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(limit, io.read(&mut first)).await {
        Err(_) => Err(SessionError::Timeout(limit)),
        Ok(Err(err)) => Err(err.into()),
        Ok(Ok(0)) => Ok(None),
        Ok(Ok(_)) => Ok(Some(first[0])),
    }
}

async fn serve_stream<H: StreamHandler>(mut stream: StreamHandle, shared: Arc<Shared<H>>) {
    let first = match first_byte(&mut stream, shared.config.first_byte_timeout).await {
        Ok(Some(b)) => b,
        Ok(None) => return,
        Err(err) => {
            tracing::debug!(workspace = %shared.workspace, error = %err, "guest stream dropped before its first byte");
            return;
        }
    };
    if first != 0 {
        let stream = GuestStream(Prefixed {
            first: Some(first),
            inner: stream,
        });
        shared.handler.handle(stream).await;
        return;
    }
    let mut reader = BufReader::new(Prefixed {
        first: Some(first),
        inner: stream,
    });
    let mut line = Vec::with_capacity(MAX_PREAMBLE);
    let read = tokio::time::timeout(
        shared.config.first_byte_timeout,
        control::read_line(&mut reader, &mut line, MAX_PREAMBLE),
    )
    .await;
    if !matches!(read, Ok(Ok(true))) {
        tracing::warn!(workspace = %shared.workspace, "stream with an unreadable preamble closed");
        return;
    }
    match parse_preamble(&line) {
        Ok((StreamKind::Control, 1)) => {
            if shared.control_open.swap(true, Ordering::AcqRel) {
                tracing::warn!(workspace = %shared.workspace, "second control stream on one session refused");
                return;
            }
            serve_control(reader, &shared).await;
            shared.control_open.store(false, Ordering::Release);
        }
        Ok((StreamKind::Resolve, 1)) => serve_resolve(reader, &shared).await,
        Ok((kind, version)) => {
            tracing::warn!(workspace = %shared.workspace, kind = kind.name(), version, "stream kind not served by this host, closed");
        }
        Err(err) => {
            tracing::warn!(workspace = %shared.workspace, error = %err, "stream closed");
        }
    }
}

/// Answers one lookup: reads the query line, asks the handler (bounded in number and time), writes
/// the answer line and closes the stream cleanly. The preamble is already read.
async fn serve_resolve<H: StreamHandler>(
    mut reader: BufReader<Prefixed<StreamHandle>>,
    shared: &Shared<H>,
) {
    let workspace = &shared.workspace;
    let query = match tokio::time::timeout(
        shared.config.first_byte_timeout,
        resolve::read_query(&mut reader),
    )
    .await
    {
        Ok(Ok(query)) => query,
        Ok(Err(err)) => {
            tracing::debug!(%workspace, error = %err, "resolve stream with an unreadable query closed");
            return;
        }
        Err(_) => {
            tracing::debug!(%workspace, "resolve stream closed: no query in time");
            return;
        }
    };
    let answer = if let Ok(_permit) = shared.resolves.try_acquire() {
        tokio::time::timeout(shared.config.resolve_timeout, shared.handler.resolve(query))
            .await
            .unwrap_or(ResolveAnswer::Unavailable)
    } else {
        tracing::warn!(%workspace, limit = shared.config.max_resolves, "too many lookups open on one session; answered unavailable");
        ResolveAnswer::Unavailable
    };
    let line = match answer.to_line() {
        Ok(line) => line,
        Err(err) => {
            tracing::warn!(%workspace, error = %err, "resolve answer not sent");
            return;
        }
    };
    let stream = reader.get_mut();
    if stream.write_all(&line).await.is_ok() {
        let _ = stream.shutdown().await;
    }
}

/// Reads control messages until the stream ends or misbehaves. The preamble is already read.
async fn serve_control<H>(mut reader: BufReader<Prefixed<StreamHandle>>, shared: &Shared<H>) {
    let workspace = &shared.workspace;
    let mut limit = RateLimit::new(
        shared.config.control_burst,
        shared.config.control_per_second,
        Instant::now(),
    );
    let mut line = Vec::with_capacity(256);
    loop {
        match control::read_line(&mut reader, &mut line, MAX_LINE).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                tracing::warn!(%workspace, error = %err, "control stream ended");
                return;
            }
        }
        if !limit.allow(Instant::now()) {
            continue;
        }
        if limit.suppressed > 0 {
            tracing::warn!(%workspace, dropped = limit.suppressed, "control messages over the rate limit were dropped");
            limit.suppressed = 0;
        }
        match AgentMessage::from_line(&line) {
            Ok(msg) => on_message(msg, shared),
            Err(err) => tracing::warn!(%workspace, error = %err, "invalid control message ignored"),
        }
    }
}

fn on_message<H>(msg: AgentMessage, shared: &Shared<H>) {
    let workspace = &shared.workspace;
    match msg {
        AgentMessage::Hello {
            agent_version,
            protocol,
        } => {
            let version = clean(&agent_version, MAX_VERSION_CHARS);
            tracing::info!(%workspace, agent_version = %version, protocol, "guest agent connected");
        }
        AgentMessage::OomKill { pid, process } => {
            let event = Event::oom_kill(
                workspace.clone(),
                pid.unwrap_or(0),
                process.as_deref().unwrap_or(UNKNOWN_PROCESS),
            );
            if let Event::OomKill { pid, process, .. } = &event {
                tracing::warn!(%workspace, pid, process = %process, "guest out of memory: process killed");
            }
            shared.sink.emit(event);
        }
        AgentMessage::Unknown => {
            tracing::debug!(%workspace, "unknown control message ignored");
        }
    }
}

/// Cuts `s` to `max` characters and replaces control characters, for guest text in logs.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// A token bucket: `burst` messages at once, then `per_second`.
#[derive(Debug)]
struct RateLimit {
    tokens: f64,
    burst: f64,
    per_second: f64,
    last: Instant,
    /// Messages dropped since the last one that got through.
    suppressed: u64,
}

impl RateLimit {
    fn new(burst: u32, per_second: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            burst: f64::from(burst),
            per_second: f64::from(per_second),
            last: now,
            suppressed: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            self.suppressed += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests;
