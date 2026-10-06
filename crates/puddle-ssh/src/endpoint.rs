// SPDX-License-Identifier: GPL-3.0-or-later
//! [`SshEndpoint`]: serves SSH to every client of a sandbox's owner-only endpoint.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use puddle_boot::{BootHook, GatedError, GatedSandbox};
use puddle_compute::{Sandbox, SshStream};
use puddle_ipc::{Connection, Endpoint, IpcError, Listener};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, warn};

use crate::refusal::{HELLO, refusal_line};

/// How long the endpoint waits before accepting again after an accept error, so a persistent
/// OS error doesn't spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long writing the hello or a refusal line may take; a client that doesn't read is
/// dropped.
const WRITE_LIMIT: Duration = Duration::from_secs(5);

/// What an [`SshEndpoint`] serves its clients with.
///
/// puddle's implementation is [`GatedSandbox`]: a client is admitted once the sandbox's boot
/// hook has returned 0 (waiting while it boots) and then gets its own SSH connection from the
/// runtime. Tests implement it with other servers.
pub trait SshTarget: Send + Sync + 'static {
    /// What [`SshTarget::serve`] fails with.
    type Error: std::error::Error + Send + Sync + 'static;

    /// The name used in logs (the sandbox's).
    fn label(&self) -> String;

    /// Decides whether a new client is served, waiting while that isn't known yet. `Err` holds
    /// the reason the client is shown.
    fn admit(&self) -> impl Future<Output = Result<(), String>> + Send;

    /// Serves one SSH connection on `stream` until it ends. Must not time out an idle session.
    ///
    /// # Errors
    ///
    /// Whatever ended the session abnormally; it is logged.
    fn serve<S: SshStream>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<S: Sandbox> SshTarget for GatedSandbox<S> {
    type Error = GatedError;

    fn label(&self) -> String {
        self.name().to_string()
    }

    async fn admit(&self) -> Result<(), String> {
        self.gate()
            .wait_ready(BootHook::DEFAULT_READY_WAIT)
            .await
            .map_err(|reason| {
                GatedError::NotReady {
                    sandbox: self.name().to_string(),
                    reason,
                }
                .to_string()
            })
    }

    async fn serve<T: SshStream>(&self, stream: T) -> Result<(), GatedError> {
        // Through the gate again: a stop between `admit` and here refuses instead of serving.
        self.serve_ssh(stream).await
    }
}

/// A sandbox's SSH endpoint: accepts clients on its [`Listener`] and serves each one with its
/// own connection from an [`SshTarget`], until [`SshEndpoint::close`] (or drop).
///
/// A refused client gets one [refusal line](crate::refusal_line) and a close. No session has a
/// timeout. Sessions end when the client or the server ends them, or when the endpoint closes.
#[derive(Debug)]
pub struct SshEndpoint {
    endpoint: Endpoint,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Listener>>,
}

impl SshEndpoint {
    /// Starts serving `listener`'s clients with `target`.
    ///
    /// # Errors
    ///
    /// [`IpcError::NoRuntime`] outside a tokio runtime.
    pub fn start<T: SshTarget>(listener: Listener, target: Arc<T>) -> Result<Self, IpcError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| IpcError::NoRuntime)?;
        let endpoint = listener.endpoint().clone();
        let (stop, stopped) = oneshot::channel();
        let task = handle.spawn(accept_loop(listener, target, stopped));
        Ok(Self {
            endpoint,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// The endpoint clients connect to (`puddle ssh-bridge <endpoint>`).
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Stops accepting, ends every session, and returns once no new client can reach the
    /// endpoint.
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            // An error means the loop already ended (it owns the receiver).
            let _ignored = stop.send(());
        }
        if let Some(task) = self.task.take() {
            match task.await {
                Ok(listener) => listener.close().await,
                Err(e) => warn!(endpoint = %self.endpoint, error = %e, "ssh endpoint task failed"),
            }
        }
    }
}

impl Drop for SshEndpoint {
    /// Ends the accept loop and every session; the endpoint closes as its listener drops.
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn accept_loop<T: SshTarget>(
    mut listener: Listener,
    target: Arc<T>,
    mut stopped: oneshot::Receiver<()>,
) -> Listener {
    let label = target.label();
    let endpoint = listener.endpoint().to_string();
    info!(sandbox = %label, endpoint, "ssh endpoint listening");
    // Owns every session: dropping or shutting it down ends them.
    let mut sessions = JoinSet::new();
    let mut next_id = 0_u64;
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok(conn) => {
                    next_id += 1;
                    sessions.spawn(session(target.clone(), conn, next_id));
                }
                Err(e @ IpcError::Closed { .. }) => {
                    warn!(sandbox = %label, endpoint, error = %e, "ssh endpoint stopped accepting");
                    // Keep the sessions until the endpoint is closed.
                    let _stopped = stopped.await;
                    break;
                }
                Err(e) => {
                    warn!(sandbox = %label, endpoint, error = %e, "ssh endpoint accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
        }
    }
    sessions.shutdown().await;
    info!(sandbox = %label, endpoint, "ssh endpoint closed");
    listener
}

/// One client: admitted and served with its own SSH connection, or refused with a reason.
async fn session<T: SshTarget>(target: Arc<T>, mut conn: Connection, id: u64) {
    let label = target.label();
    let hello = tokio::time::timeout(WRITE_LIMIT, async {
        conn.write_all(HELLO.as_bytes()).await?;
        conn.flush().await
    })
    .await;
    if !matches!(hello, Ok(Ok(()))) {
        info!(sandbox = %label, session = id, "ssh client left before the hello");
        return;
    }
    if let Err(reason) = target.admit().await {
        info!(sandbox = %label, session = id, reason, "ssh client refused");
        let line = refusal_line(&reason);
        let written = tokio::time::timeout(WRITE_LIMIT, async {
            conn.write_all(line.as_bytes()).await?;
            conn.flush().await?;
            conn.shutdown().await
        })
        .await;
        if !matches!(written, Ok(Ok(()))) {
            info!(sandbox = %label, session = id, "ssh client left before reading the refusal");
        }
        // Dropping the connection closes it: the only EOF a Windows pipe has.
        return;
    }
    info!(sandbox = %label, session = id, "ssh session started");
    match target.serve(conn).await {
        Ok(()) => info!(sandbox = %label, session = id, "ssh session ended"),
        Err(e) => {
            warn!(sandbox = %label, session = id, error = %e, "ssh session ended with an error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_outside_a_runtime_is_refused() {
        struct Never;
        impl SshTarget for Never {
            type Error = std::io::Error;
            fn label(&self) -> String {
                "never".into()
            }
            fn admit(&self) -> impl Future<Output = Result<(), String>> {
                std::future::ready(Err("never".into()))
            }
            fn serve<S: SshStream>(
                &self,
                _stream: S,
            ) -> impl Future<Output = Result<(), Self::Error>> {
                std::future::ready(Ok(()))
            }
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let root = puddle_ipc::IpcRoot::new().unwrap();
        let listener = rt.block_on(async { root.listen().unwrap() });
        let err = SshEndpoint::start(listener, Arc::new(Never)).unwrap_err();
        assert!(matches!(err, IpcError::NoRuntime), "{err}");
        // The helper target itself, so it is no dead code.
        assert_eq!(Never.label(), "never");
        rt.block_on(async {
            assert!(Never.admit().await.is_err());
            Never.serve(tokio::io::duplex(1).0).await.unwrap();
        });
    }
}
