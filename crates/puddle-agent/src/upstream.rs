// SPDX-License-Identifier: GPL-3.0-or-later
//! The way to the host: a small pool of yamux sessions, each on its own vsock connection.
//!
//! A vsock route on Windows tops out around 90–128 concurrent streams, far below what a parallel
//! restore or a `docker pull` opens, so one guest connection must not cost one vsock stream.
//! Streams are spread round-robin over [`crate::Config::mux`] sessions; a session that died is
//! redialled on its next use.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_yamux::{Control, Session, StreamHandle};

use crate::config::{Config, Target};

/// A connection to the host before yamux runs on it.
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One live session: its control handle and the task that drives it.
struct Slot {
    control: Control,
    driver: JoinHandle<()>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// The pool of sessions to the host.
pub struct Upstream {
    target: Target,
    vsock_buffer: u64,
    yamux: tokio_yamux::Config,
    slots: Vec<Mutex<Option<Slot>>>,
    next: AtomicUsize,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("target", &self.target)
            .field("sessions", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// A pool for `config` (target, session count, vsock buffer, window). Nothing is dialled
    /// until the first [`Upstream::open`].
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self {
            target: config.target.clone(),
            vsock_buffer: config.vsock_buffer,
            yamux: puddle_agent_proto::yamux::client_config_with_window(config.window),
            slots: (0..config.mux.max(1)).map(|_| Mutex::new(None)).collect(),
            next: AtomicUsize::new(0),
        }
    }

    /// Opens a new stream to the host on the next session, dialling it if it isn't up.
    ///
    /// # Errors
    ///
    /// The dial failing, or the fresh session refusing a stream.
    pub async fn open(&self) -> io::Result<StreamHandle> {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let Some(slot) = self.slots.get(i) else {
            return Err(io::Error::other("no session slots"));
        };
        let mut slot = slot.lock().await;
        if let Some(live) = slot.as_mut() {
            match live.control.open_stream().await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    tracing::info!(session = i, error = ?err, "session to the host dropped, redialling");
                    *slot = None;
                }
            }
        }
        let mut session = Session::new_client(self.dial().await?, self.yamux);
        let mut control = session.control();
        // Driving the session moves its frames; the host never opens streams to us.
        let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
        let stream = control
            .open_stream()
            .await
            .map_err(|e| io::Error::other(format!("yamux open: {e:?}")))?;
        *slot = Some(Slot { control, driver });
        Ok(stream)
    }

    async fn dial(&self) -> io::Result<Pin<Box<dyn Io>>> {
        match &self.target {
            Target::Vsock { cid, port } => {
                let (cid, port, buffer) = (*cid, *port, self.vsock_buffer);
                dial_vsock(cid, port, buffer).await
            }
            Target::Unix(path) => dial_unix(path).await,
        }
    }
}

#[cfg(target_os = "linux")]
async fn dial_vsock(cid: u32, port: u32, buffer: u64) -> io::Result<Pin<Box<dyn Io>>> {
    let std_stream = tokio::task::spawn_blocking(move || crate::vsock::connect(cid, port, buffer))
        .await
        .map_err(io::Error::other)??;
    std_stream.set_nonblocking(true)?;
    Ok(Box::pin(tokio::net::TcpStream::from_std(std_stream)?))
}

#[cfg(not(target_os = "linux"))]
#[expect(clippy::unused_async, reason = "same signature as the Linux version")]
async fn dial_vsock(_cid: u32, _port: u32, _buffer: u64) -> io::Result<Pin<Box<dyn Io>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "vsock needs a Linux guest",
    ))
}

#[cfg(unix)]
async fn dial_unix(path: &std::path::Path) -> io::Result<Pin<Box<dyn Io>>> {
    Ok(Box::pin(tokio::net::UnixStream::connect(path).await?))
}

#[cfg(not(unix))]
#[expect(clippy::unused_async, reason = "same signature as the Unix version")]
async fn dial_unix(_path: &std::path::Path) -> io::Result<Pin<Box<dyn Io>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unix sockets need a Unix guest",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(target: Target) -> Upstream {
        Upstream::new(&Config {
            target,
            mux: 2,
            ..Config::default()
        })
    }

    #[tokio::test]
    async fn an_unreachable_host_is_an_error_on_every_slot() {
        let up = upstream(Target::Unix("/nonexistent/puddle-route.sock".into()));
        assert!(format!("{up:?}").contains("sessions: 2"));
        for _ in 0..3 {
            assert!(up.open().await.is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_vsock_target_nobody_listens_on_is_an_error() {
        // CID 1 is local loopback; nothing listens there.
        let up = upstream(Target::Vsock {
            cid: 1,
            port: 0x7fff_fff1,
        });
        assert!(up.open().await.is_err());
    }
}
