// SPDX-License-Identifier: GPL-3.0-or-later
//! Binding, serving and shutting down. Connections are served by hyper directly (not
//! `axum::serve`) so headers have a read timeout and every connection task has an owner.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use puddle_store::{Clock, Store};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, watch};
use tokio::task::{JoinHandle, JoinSet};
use tower_http::timeout::TimeoutLayer;

use crate::auth::{Guard, guard};
use crate::error::ApiError;
use crate::events::EventHub;
use crate::routes::{AppState, api_router};
use crate::settings::SettingsRepo;
use crate::token::{ApiToken, ConnectionInfo};

/// Largest request body (the biggest real one, a settings document, is well under 4 KiB).
const MAX_BODY_BYTES: usize = 64 * 1024;

/// How long a client may take to send a request's headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long shutdown waits for open requests before ending them.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Pause after a failed `accept` (e.g. out of file descriptors) before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How the API listens. There is deliberately no address setting: it binds `127.0.0.1`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ApiConfig {
    /// Port on `127.0.0.1`; 0 (the default) lets the OS pick a free one, which clients learn
    /// from the connection file.
    pub port: u16,
    /// Browser origins besides the API's own that may call it, e.g. the desktop shell's
    /// (`tauri://localhost`). Empty by default. Calls from them still need the token.
    pub extra_origins: Vec<String>,
    /// Longest a non-streaming request may take before it gets a 408.
    pub request_timeout: Duration,
    /// Most connections served at once; further ones are closed at accept.
    pub max_connections: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: 0,
            extra_origins: Vec::new(),
            request_timeout: Duration::from_secs(30),
            max_connections: 256,
        }
    }
}

impl ApiConfig {
    /// The default configuration on a fixed port.
    #[must_use]
    pub fn with_port(port: u16) -> Self {
        Self {
            port,
            ..Self::default()
        }
    }
}

/// What the API serves from.
#[derive(Clone)]
#[non_exhaustive]
pub struct Services {
    /// Rules, pending requests and the audit log.
    pub store: Arc<Store>,
    /// Settings documents.
    pub settings: Arc<dyn SettingsRepo>,
    /// The event hub SSE subscribers read from; give the same hub to whatever emits events.
    pub events: Arc<EventHub>,
    /// The clock consents are stamped with.
    pub clock: Arc<dyn Clock>,
}

impl Services {
    /// Services over these parts.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        settings: Arc<dyn SettingsRepo>,
        events: Arc<EventHub>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            settings,
            events,
            clock,
        }
    }
}

/// Why the API couldn't start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServeError {
    /// The port couldn't be bound.
    #[error("cannot listen on 127.0.0.1:{port}: {source}")]
    Bind {
        /// The requested port.
        port: u16,
        /// What failed.
        source: io::Error,
    },
}

/// A bound, not yet serving API.
pub struct ApiServer {
    listener: TcpListener,
    addr: SocketAddr,
    router: Router,
    token: ApiToken,
    max_connections: usize,
    stop: watch::Sender<bool>,
}

impl ApiServer {
    /// Binds `127.0.0.1:<config.port>` and builds the routes.
    ///
    /// # Errors
    ///
    /// [`ServeError::Bind`] if the port is taken or can't be bound.
    pub async fn bind(
        config: ApiConfig,
        token: ApiToken,
        services: Services,
    ) -> Result<Self, ServeError> {
        let bind_err = |source| ServeError::Bind {
            port: config.port,
            source,
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .await
            .map_err(bind_err)?;
        let addr = listener.local_addr().map_err(bind_err)?;
        let (stop, shutdown) = watch::channel(false);
        let state = AppState {
            store: services.store,
            settings: services.settings,
            settings_lock: Arc::new(Mutex::new(())),
            events: services.events,
            clock: services.clock,
            shutdown,
        };
        let guard_state = Guard::new(token.clone(), addr.port(), &config.extra_origins);
        let router = build_router(state, guard_state, config.request_timeout);
        tracing::info!(%addr, "api listening");
        Ok(Self {
            listener,
            addr,
            router,
            token,
            max_connections: config.max_connections.max(1),
            stop,
        })
    }

    /// The bound address (always `127.0.0.1`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// What a client needs to connect, for [`ConnectionInfo::write`].
    #[must_use]
    pub fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            url: format!("http://{}", self.addr),
            token: self.token.clone(),
        }
    }

    /// Starts serving on a task owned by the returned handle.
    #[must_use]
    pub fn spawn(self) -> RunningApi {
        let Self {
            listener,
            addr,
            router,
            max_connections,
            stop,
            ..
        } = self;
        let shutdown = stop.subscribe();
        let task = tokio::spawn(serve(listener, router, max_connections, shutdown));
        RunningApi { addr, stop, task }
    }
}

/// A serving API. Dropping it without [`RunningApi::shutdown`] aborts the server task.
pub struct RunningApi {
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl RunningApi {
    /// The bound address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting, ends event streams, lets open requests finish (up to 5 s) and returns
    /// when every connection is closed.
    pub async fn shutdown(mut self) {
        // Receivers live in the server task; if it already ended there is nobody to tell.
        let _ = self.stop.send(true);
        if let Err(err) = (&mut self.task).await {
            tracing::error!(error = %err, "api server task failed");
        }
    }
}

impl Drop for RunningApi {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn build_router(state: AppState, guard_state: Guard, request_timeout: Duration) -> Router {
    let (router, _spec) = api_router().split_for_parts();
    router
        .route(
            "/api/openapi.json",
            axum::routing::get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::openapi_json(),
                )
            }),
        )
        .fallback(|| async { ApiError::not_found("no such route") })
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(guard_state, guard))
        .with_state(state)
}

async fn serve(
    listener: TcpListener,
    router: Router,
    max_connections: usize,
    mut shutdown: watch::Receiver<bool>,
) {
    let graceful = GracefulShutdown::new();
    let mut connections = JoinSet::new();
    loop {
        // Reap finished connections so the cap counts open ones only.
        while connections.try_join_next().is_some() {}
        let accepted = tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(error = %err, "api accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() || connections.len() >= max_connections {
            tracing::warn!(open = connections.len(), "api connection refused");
            drop(stream);
            continue;
        }
        let service = TowerToHyperService::new(router.clone());
        let connection = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service);
        let connection = graceful.watch(connection);
        connections.spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %err, "api connection ended with an error");
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("api connections still open after the grace period; closing them");
    }
    connections.shutdown().await;
    tracing::info!("api stopped");
}
