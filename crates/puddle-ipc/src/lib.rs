// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-sandbox host endpoints that only the current user can open.
//!
//! msb connects each guest vsock route to a host endpoint: a named pipe on Windows, a Unix socket
//! elsewhere. puddle gives every sandbox its own endpoint, so the endpoint a connection arrives on
//! *is* the sandbox's identity. This crate makes those endpoints safe to rely on:
//!
//! | Threat | Windows | Linux |
//! |---|---|---|
//! | Another user or a restricted process opens the endpoint | explicit DACL granting the current user's SID only (no Everyone/anonymous read); remote clients rejected | socket file `0600` inside a fresh `0700` directory |
//! | A process creates the name first (squatting) | 128-bit random name; the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`; an existing name is refused ([`IpcError::NameTaken`]); one of puddle's instances exists for as long as the [`Listener`] lives | a fresh directory with a random name that only puddle can write; `bind` fails on an existing path |
//!
//! # Use
//!
//! ```no_run
//! # async fn demo() -> Result<(), puddle_ipc::IpcError> {
//! let root = puddle_ipc::IpcRoot::new()?;
//! let mut listener = root.listen()?;          // bind *before* the VM boots
//! let route_target = listener.endpoint().path(); // goes into the sandbox's vsock route
//! # let _ = route_target;
//! let connection = listener.accept().await?;  // AsyncRead + AsyncWrite
//! # drop(connection);
//! # Ok(()) }
//! ```
//!
//! Clients (msb, or `puddle ssh-bridge`) connect with [`connect`].
//!
//! Endpoints must be bound inside a tokio runtime with I/O enabled. On Windows a [`Listener`]
//! keeps a pool of [`PIPE_ACCEPTORS`] idle pipe instances, so a burst of guest connections
//! doesn't meet `ERROR_PIPE_BUSY` (which msb turns into a reset inside the guest).
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod error;
mod name;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
use windows as sys;

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use error::IpcError;

/// How many idle pipe instances a Windows [`Listener`] keeps ready (taken from the `PoC`, which
/// needed this many for bursts such as a parallel package restore). Unused on Unix, where the
/// kernel's listen backlog plays this role.
pub const PIPE_ACCEPTORS: usize = 32;

/// Where puddle's endpoints live, and the access rule they get.
///
/// On Windows this holds the owner-only security descriptor for the current user. On Unix it
/// owns a fresh `0700` directory that holds the sockets; the directory is removed when the last
/// clone of the root and the last [`Listener`] in it are dropped.
///
/// Cloning is cheap; clones share the same directory.
#[derive(Debug, Clone)]
pub struct IpcRoot {
    inner: sys::Root,
}

impl IpcRoot {
    /// A root in the default place: on Unix a new directory under `$XDG_RUNTIME_DIR` (or the
    /// temp directory when that isn't set); on Windows the named-pipe namespace.
    ///
    /// # Errors
    ///
    /// [`IpcError::Root`] when the directory can't be created or its mode can't be set, or
    /// (Windows) the current user's SID can't be read; [`IpcError::Random`] when the system
    /// random source fails.
    pub fn new() -> Result<Self, IpcError> {
        Ok(Self {
            inner: sys::Root::new()?,
        })
    }

    /// A fresh, unbound endpoint with a random name in this root.
    ///
    /// Callers normally use [`IpcRoot::listen`]; this exists so a caller can see the name before
    /// binding it (tests use it to squat a name).
    ///
    /// # Errors
    ///
    /// [`IpcError::Random`] when the system random source fails.
    pub fn endpoint(&self) -> Result<Endpoint, IpcError> {
        Ok(Endpoint {
            path: self.inner.endpoint_path()?,
        })
    }

    /// Binds `endpoint` with owner-only access.
    ///
    /// # Errors
    ///
    /// - [`IpcError::NameTaken`] when something already exists at that name: nothing is
    ///   bound and the caller must not boot the sandbox against it.
    /// - [`IpcError::ForeignEndpoint`] when `endpoint` was made by another root.
    /// - [`IpcError::NoRuntime`] outside a tokio runtime.
    /// - [`IpcError::Io`] for other OS errors.
    pub fn bind(&self, endpoint: &Endpoint) -> Result<Listener, IpcError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(IpcError::NoRuntime);
        }
        let inner = self.inner.bind(&endpoint.path)?;
        tracing::debug!(endpoint = %endpoint, "endpoint bound");
        Ok(Listener {
            endpoint: endpoint.clone(),
            inner,
        })
    }

    /// Binds a fresh random endpoint: [`IpcRoot::endpoint`] then [`IpcRoot::bind`].
    ///
    /// # Errors
    ///
    /// As [`IpcRoot::endpoint`] and [`IpcRoot::bind`].
    pub fn listen(&self) -> Result<Listener, IpcError> {
        self.bind(&self.endpoint()?)
    }
}

#[cfg(unix)]
impl IpcRoot {
    /// A root in a new private directory under `parent` (which must exist).
    ///
    /// # Errors
    ///
    /// As [`IpcRoot::new`].
    pub fn new_in(parent: &Path) -> Result<Self, IpcError> {
        Ok(Self {
            inner: sys::Root::new_in(parent)?,
        })
    }

    /// The private directory that holds this root's sockets.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.inner.dir()
    }
}

/// The name of one endpoint: a pipe path (`\\.\pipe\puddle-<32 hex>`) on Windows, a socket path
/// (`<root dir>/<16 hex>.sock`) on Unix. This is what goes into the sandbox's vsock route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    path: PathBuf,
}

impl Endpoint {
    /// The path a client opens.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.path.display().fmt(f)
    }
}

/// A bound endpoint that accepts connections.
///
/// Dropping it closes the endpoint: at once on Unix (the socket file is removed too); on Windows
/// once the runtime has cancelled the acceptor tasks. [`Listener::close`] returns only when the
/// endpoint is gone. Connections already accepted stay open either way.
#[derive(Debug)]
pub struct Listener {
    endpoint: Endpoint,
    inner: sys::Listener,
}

impl Listener {
    /// The endpoint this listener is bound to.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Closes the endpoint and returns once no new client can reach it.
    #[cfg_attr(
        unix,
        expect(
            clippy::unused_async,
            reason = "async for the Windows acceptor shutdown"
        )
    )]
    pub async fn close(self) {
        #[cfg(windows)]
        self.inner.close().await;
        #[cfg(unix)]
        drop(self.inner);
    }

    /// Waits for the next client.
    ///
    /// Cancel-safe: dropping the future loses no connection.
    ///
    /// # Errors
    ///
    /// [`IpcError::Io`] when the OS fails to accept or (Windows) to create the next pipe
    /// instance; [`IpcError::Closed`] when the listener can't accept any more.
    pub async fn accept(&mut self) -> Result<Connection, IpcError> {
        self.inner
            .accept(&self.endpoint.path)
            .await
            .map(|inner| Connection { inner })
    }
}

/// One connection on an endpoint, server or client side.
///
/// **No half-close on Windows:** named pipes have none, so `shutdown` there is a no-op and the
/// peer sees EOF only when the connection is dropped. Protocols over an endpoint mark their own
/// end of stream (yamux and SSH do). On Unix `shutdown` half-closes as usual.
#[derive(Debug)]
pub struct Connection {
    inner: sys::Stream,
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Connects to the endpoint at `path` as a client.
///
/// On Windows a busy pipe (every instance taken) is retried for up to
/// [`CONNECT_BUSY_TIMEOUT`]; the client never lets the server impersonate it beyond
/// identification (`SECURITY_IDENTIFICATION`).
///
/// # Errors
///
/// [`IpcError::NotFound`] when nothing listens there, [`IpcError::AccessDenied`] when the
/// endpoint refuses this process, [`IpcError::Busy`] when no pipe instance freed up in time,
/// [`IpcError::NoRuntime`] outside a tokio runtime, [`IpcError::Io`] otherwise.
pub async fn connect(path: &Path) -> Result<Connection, IpcError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(IpcError::NoRuntime);
    }
    sys::connect(path).await.map(|inner| Connection { inner })
}

/// How long [`connect`] retries a Windows pipe whose instances are all busy.
pub const CONNECT_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maps an OS error from a client open to the crate's error.
fn client_error(endpoint: &Path, source: io::Error) -> IpcError {
    match source.kind() {
        io::ErrorKind::NotFound => IpcError::NotFound {
            endpoint: endpoint.to_path_buf(),
        },
        io::ErrorKind::PermissionDenied => IpcError::AccessDenied {
            endpoint: endpoint.to_path_buf(),
        },
        _ => IpcError::Io {
            op: "connect to",
            endpoint: endpoint.to_path_buf(),
            source,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_errors_map_to_specific_variants() {
        let p = Path::new("/x");
        assert!(matches!(
            client_error(p, io::Error::from(io::ErrorKind::NotFound)),
            IpcError::NotFound { .. }
        ));
        assert!(matches!(
            client_error(p, io::Error::from(io::ErrorKind::PermissionDenied)),
            IpcError::AccessDenied { .. }
        ));
        assert!(matches!(
            client_error(p, io::Error::from(io::ErrorKind::BrokenPipe)),
            IpcError::Io {
                op: "connect to",
                ..
            }
        ));
    }

    #[test]
    fn binding_outside_a_runtime_is_refused() {
        let root = IpcRoot::new().unwrap();
        let err = root.listen().unwrap_err();
        assert!(matches!(err, IpcError::NoRuntime), "{err}");
    }

    #[test]
    fn connecting_outside_a_runtime_is_refused() {
        // Polled with no tokio context at all: the guard must answer before any I/O.
        let err = block_on_without_runtime(connect(Path::new("/nonexistent"))).unwrap_err();
        assert!(matches!(err, IpcError::NoRuntime), "{err}");
    }

    /// Polls a future to completion without any tokio context.
    fn block_on_without_runtime<F: Future>(fut: F) -> F::Output {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn endpoint_displays_its_path() {
        let e = Endpoint {
            path: PathBuf::from("/a/b.sock"),
        };
        assert_eq!(e.to_string(), "/a/b.sock");
        assert_eq!(e.path(), Path::new("/a/b.sock"));
    }
}
