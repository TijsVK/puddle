// SPDX-License-Identifier: GPL-3.0-or-later
//! The host listener on one sandbox's route: accept agent connections and serve
//! each as a yamux session whose proxied streams go to that sandbox's [`SandboxHandler`].
//!
//! The endpoint is the identity: every connection on it belongs to the sandbox the route
//! was created for, whatever the guest says.

use std::sync::Arc;
use std::time::Duration;

use puddle_agent_proto::host::serve_session;
use puddle_ipc::{Endpoint, IpcError, Listener};
use puddle_types::SandboxName;
use tokio::task::{JoinHandle, JoinSet};
use tracing::Instrument;

use crate::proxy::{Proxy, SandboxHandler};

/// Pause after an accept error, so a broken listener can't spin a core.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A route being served. Dropping it (or [`Route::shutdown`]) stops accepting and ends every
/// session on it; open connections are reset.
#[derive(Debug)]
pub struct Route {
    endpoint: Endpoint,
    sandbox: SandboxName,
    task: JoinHandle<()>,
}

impl Route {
    /// The endpoint the sandbox's vsock route points at.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The sandbox this route serves.
    #[must_use]
    pub fn sandbox(&self) -> &SandboxName {
        &self.sandbox
    }

    /// Stops the route and waits until its accept loop and sessions are gone.
    pub async fn shutdown(mut self) {
        self.task.abort();
        if let Err(err) = (&mut self.task).await
            && err.is_panic()
        {
            tracing::error!(sandbox = %self.sandbox, "route task panicked");
        }
    }
}

impl Drop for Route {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Proxy {
    /// Serves `listener` (the route of `sandbox`) until the returned [`Route`] is dropped or shut
    /// down. Must be called inside a tokio runtime.
    #[must_use]
    pub fn serve_route(self: &Arc<Self>, listener: Listener, sandbox: SandboxName) -> Route {
        let endpoint = listener.endpoint().clone();
        let handler = Arc::new(self.handler(sandbox.clone()));
        let span = tracing::info_span!("route", sandbox = %sandbox);
        let task = tokio::spawn(accept_loop(Arc::clone(self), listener, handler).instrument(span));
        Route {
            endpoint,
            sandbox,
            task,
        }
    }
}

async fn accept_loop(proxy: Arc<Proxy>, mut listener: Listener, handler: Arc<SandboxHandler>) {
    let max = proxy.config.max_sessions_per_route;
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) if sessions.len() >= max => {
                    tracing::warn!(limit = max, "agent connection refused: route over its session limit");
                    drop(conn);
                }
                Ok(conn) => {
                    let sandbox = handler.sandbox().clone();
                    let sink = Arc::clone(&proxy.sink);
                    let config = proxy.config.session;
                    let handler = Arc::clone(&handler);
                    sessions.spawn(async move {
                        serve_session(conn, sandbox, sink, handler, config).await
                    });
                }
                Err(IpcError::Closed { .. }) => {
                    tracing::info!("route closed");
                    return;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(done) = sessions.join_next(), if !sessions.is_empty() => match done {
                Ok(Ok(())) => tracing::debug!("agent session ended"),
                Ok(Err(err)) => tracing::info!(error = %err, "agent session failed"),
                Err(err) if err.is_panic() => tracing::error!("agent session panicked"),
                Err(_) => {}
            },
        }
    }
}
