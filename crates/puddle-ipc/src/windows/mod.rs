// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows: named pipes with an owner-only DACL, a first-instance check and a pool of acceptors.

#[expect(
    unsafe_code,
    reason = "Win32 calls for the user's SID and the pipe's security descriptor (T-029 HO-1)"
)]
mod security;

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY};
use windows_sys::Win32::Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};

use crate::name::random_name;
use crate::{CONNECT_BUSY_TIMEOUT, IpcError, PIPE_ACCEPTORS};

/// Every endpoint name starts with this.
const PIPE_PREFIX: &str = r"\\.\pipe\puddle-";

/// Per-instance buffer size hint, from the `PoC` (T-004 throughput).
const PIPE_BUFFER: u32 = 4 * 1024 * 1024;

/// How long [`connect`] waits between tries on a busy pipe.
const BUSY_RETRY: std::time::Duration = std::time::Duration::from_millis(10);

#[derive(Debug, Clone)]
pub(crate) struct Root {
    /// The owner-only security descriptor, as SDDL.
    sddl: Arc<str>,
}

impl Root {
    pub(crate) fn new() -> Result<Self, IpcError> {
        let sid = security::current_user_sid().map_err(|source| IpcError::Root {
            path: PathBuf::from("the current user's SID"),
            source,
        })?;
        Ok(Self {
            sddl: owner_only_sddl(&sid).into(),
        })
    }

    #[expect(
        clippy::unused_self,
        reason = "same interface as the Unix root, whose names live in its directory"
    )]
    pub(crate) fn endpoint_path(&self) -> Result<PathBuf, IpcError> {
        Ok(PathBuf::from(format!(
            "{PIPE_PREFIX}{}",
            random_name::<16>()?
        )))
    }

    pub(crate) fn bind(&self, path: &Path) -> Result<Listener, IpcError> {
        if !path
            .to_str()
            .is_some_and(|p| p.starts_with(PIPE_PREFIX) && p.len() > PIPE_PREFIX.len())
        {
            return Err(IpcError::ForeignEndpoint {
                endpoint: path.to_path_buf(),
                root: PathBuf::from(PIPE_PREFIX),
            });
        }
        // The first instance proves the name is new (HO-2); every later one is created while one
        // of ours still exists, so the name can't change hands in between.
        let first = self
            .create(path, true)
            .map_err(|source| bind_error(path, source))?;
        let mut idle = Vec::with_capacity(PIPE_ACCEPTORS);
        idle.push(first);
        for _ in 1..PIPE_ACCEPTORS {
            idle.push(self.create(path, false).map_err(|source| IpcError::Io {
                op: "create an instance of",
                endpoint: path.to_path_buf(),
                source,
            })?);
        }
        let (tx, rx) = mpsc::channel(PIPE_ACCEPTORS);
        let mut tasks = JoinSet::new();
        for server in idle {
            tasks.spawn(acceptor(
                server,
                self.clone(),
                path.to_path_buf(),
                tx.clone(),
            ));
        }
        Ok(Listener {
            rx,
            tasks,
            path: path.to_path_buf(),
        })
    }

    fn create(&self, path: &Path, first: bool) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .in_buffer_size(PIPE_BUFFER)
            .out_buffer_size(PIPE_BUFFER);
        security::create_pipe(&options, path.as_os_str(), &self.sddl)
    }
}

/// A DACL that grants the user `sid` full access and nobody else anything; `P` blocks
/// inheritance, so no default ACEs (Everyone and anonymous read, T-029 HO-1) come back.
fn owner_only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// `CreateNamedPipe` with `FILE_FLAG_FIRST_PIPE_INSTANCE` fails with access denied when the name
/// exists (or exists with a DACL that keeps us out), and with pipe-busy when it exists at its
/// instance limit. Either way somebody else has the name.
fn bind_error(path: &Path, source: io::Error) -> IpcError {
    match source.raw_os_error().and_then(|c| u32::try_from(c).ok()) {
        Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) => IpcError::NameTaken {
            endpoint: path.to_path_buf(),
        },
        _ => IpcError::Io {
            op: "create",
            endpoint: path.to_path_buf(),
            source,
        },
    }
}

type Accepted = io::Result<NamedPipeServer>;

/// Waits for a client on `server`, hands it over, and arms the next instance; forever, until the
/// listener goes away.
async fn acceptor(
    mut server: NamedPipeServer,
    root: Root,
    path: PathBuf,
    tx: mpsc::Sender<Accepted>,
) {
    loop {
        let connected = server.connect().await;
        // Create the next instance while the current one still holds the name (HO-2).
        let next = match root.create(&path, false) {
            Ok(next) => next,
            Err(err) => {
                // Nothing to do with a send error: the listener is gone.
                let _ = tx.send(Err(err)).await;
                return;
            }
        };
        let current = std::mem::replace(&mut server, next);
        match connected {
            Ok(()) => {
                if tx.send(Ok(current)).await.is_err() {
                    return;
                }
            }
            // The client left before we saw it (e.g. ERROR_NO_DATA): drop that instance.
            Err(err) => tracing::debug!(endpoint = %path.display(), %err, "pipe client vanished"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Listener {
    rx: mpsc::Receiver<Accepted>,
    /// Dropping the set aborts the acceptors, which closes every idle instance once the runtime
    /// gets to them; [`Listener::close`] waits for that.
    tasks: JoinSet<()>,
    path: PathBuf,
}

impl Listener {
    pub(crate) async fn close(mut self) {
        self.rx.close();
        self.tasks.shutdown().await;
        // Instances accepted but never handed out are connected, not listening; close them now.
        while self.rx.try_recv().is_ok() {}
        drain_listening(&self.path);
    }

    pub(crate) async fn accept(&mut self, endpoint: &Path) -> Result<Stream, IpcError> {
        match self.rx.recv().await {
            Some(Ok(server)) => Ok(Stream::Server(server)),
            Some(Err(source)) => Err(IpcError::Io {
                op: "create an instance of",
                endpoint: endpoint.to_path_buf(),
                source,
            }),
            None => Err(IpcError::Closed {
                endpoint: endpoint.to_path_buf(),
            }),
        }
    }
}

pub(crate) async fn connect(path: &Path) -> Result<Stream, IpcError> {
    let deadline = tokio::time::Instant::now() + CONNECT_BUSY_TIMEOUT;
    let mut options = ClientOptions::new();
    // Identification only: the server learns who we are but can't act as us.
    options.security_qos_flags(SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT);
    loop {
        match options.open(path) {
            Ok(client) => return Ok(Stream::Client(client)),
            Err(err) if is_busy(&err) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(IpcError::Busy {
                        endpoint: path.to_path_buf(),
                    });
                }
                tokio::time::sleep(BUSY_RETRY).await;
            }
            Err(err) => return Err(crate::client_error(path, err)),
        }
    }
}

/// An aborted acceptor's instance stays open, and listening, until the I/O driver dequeues its
/// cancelled connect: mio keeps the handle alive for that pending overlapped operation. So
/// connect to each such instance and hang up, until a client finds no listening instance
/// (`NotFound` once every handle is closed, busy while one is still on its way out or a client
/// still holds a connection). Bounded: aborted acceptors create no new instances.
fn drain_listening(path: &Path) {
    let mut options = ClientOptions::new();
    options.security_qos_flags(SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT);
    for _ in 0..=PIPE_ACCEPTORS {
        match options.open(path) {
            Ok(client) => drop(client),
            Err(err) if err.kind() == io::ErrorKind::NotFound || is_busy(&err) => return,
            Err(err) => {
                tracing::debug!(endpoint = %path.display(), %err, "pipe close probe failed");
                return;
            }
        }
    }
    tracing::debug!(endpoint = %path.display(), "pipe still listening after close");
}

fn is_busy(err: &io::Error) -> bool {
    err.raw_os_error().and_then(|c| u32::try_from(c).ok()) == Some(ERROR_PIPE_BUSY)
}

/// A pipe connection: the server end from a [`Listener`], or the client end from [`connect`].
#[derive(Debug)]
pub(crate) enum Stream {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_read(cx, buf),
            Self::Client(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_write(cx, buf),
            Self::Client(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_flush(cx),
            Self::Client(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_shutdown(cx),
            Self::Client(c) => Pin::new(c).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Server(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Client(c) => Pin::new(c).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Server(s) => s.is_write_vectored(),
            Self::Client(c) => c.is_write_vectored(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_grants_only_the_given_sid_and_blocks_inheritance() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn first_instance_failures_mean_the_name_is_taken() {
        let p = Path::new(r"\\.\pipe\puddle-x");
        for code in [ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY] {
            let err = bind_error(
                p,
                io::Error::from_raw_os_error(i32::try_from(code).unwrap()),
            );
            assert!(matches!(err, IpcError::NameTaken { .. }), "{code}: {err}");
        }
        let err = bind_error(p, io::Error::from_raw_os_error(87));
        assert!(matches!(err, IpcError::Io { op: "create", .. }), "{err}");
    }

    #[test]
    fn endpoint_names_have_the_prefix_and_128_random_bits() {
        let p = Root::new().unwrap().endpoint_path().unwrap();
        let s = p.to_str().unwrap();
        let suffix = s.strip_prefix(PIPE_PREFIX).unwrap();
        assert_eq!(suffix.len(), 32, "{s}");
    }

    #[test]
    fn busy_is_recognised_by_its_os_code() {
        let busy = i32::try_from(ERROR_PIPE_BUSY).unwrap();
        assert!(is_busy(&io::Error::from_raw_os_error(busy)));
        assert!(!is_busy(&io::Error::from_raw_os_error(2)));
        assert!(!is_busy(&io::Error::other("x")));
    }
}
