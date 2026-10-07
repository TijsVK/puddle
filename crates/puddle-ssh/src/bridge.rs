// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle ssh-bridge`: relays `ssh`'s stdio to a sandbox's SSH endpoint (it is the
//! `ProxyCommand`).
//!
//! Rules, the same on Windows and Unix:
//!
//! | Event | What the bridge does |
//! |---|---|
//! | client input ends (EOF, or a read error) | half-closes the endpoint (Unix; a no-op on a Windows pipe, see below) and **keeps relaying** the server's output |
//! | the server's output ends | flushes and closes the client output, and ends: the session is over, whatever the input still does |
//! | writing to the client fails (`ssh` is gone) | ends; dropping the connection closes it, which the server sees |
//! | writing to the server fails | stops sending; ends once the server's output ends |
//! | the endpoint doesn't say [`HELLO`] within [`HELLO_TIMEOUT`] | [`BridgeError::NoAnswer`]: never wait forever on something that isn't serving |
//! | the endpoint refuses the client | [`BridgeError::Refused`] with the reason, nothing written to the client |
//!
//! Why the server's EOF ends everything: SSH has no transport half-close (the server ends a
//! session by closing), a Windows pipe's EOF is a full close anyway, and `ssh` may keep the
//! bridge's stdin open after the connection is gone.
//!
//! **Windows named pipes can't half-close**: after the client's input ends, the server
//! only learns of it through SSH itself (`DISCONNECT`, channel EOF), never from the stream.
//! Nothing in SSH needs more.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use puddle_ipc::IpcError;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::refusal::{HELLO, Head, read_head};

/// The relay's read size.
const CHUNK: usize = 64 * 1024;

/// How long the bridge waits for the endpoint's [`HELLO`]. puddle sends it as
/// soon as it accepts, before deciding anything, so only a hung or foreign endpoint misses it.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the bridge didn't relay a session to its end.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Nothing listens at the endpoint.
    #[error(
        "no puddle SSH endpoint at {endpoint}: the sandbox is not running, or puddle is not (start it in puddle and connect again)"
    )]
    NotFound {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// The endpoint refused this process.
    #[error(
        "access to the SSH endpoint {endpoint} was denied: only the user running puddle, from an unrestricted process, may connect"
    )]
    AccessDenied {
        /// The endpoint.
        endpoint: PathBuf,
    },
    /// Connecting failed otherwise.
    #[error("could not connect to the SSH endpoint")]
    Connect(#[source] IpcError),
    /// puddle refused to serve this client.
    #[error("{reason}")]
    Refused {
        /// Why, as one printable line.
        reason: String,
    },
    /// The endpoint took the connection but didn't answer.
    #[error(
        "the SSH endpoint did not answer within {waited:?}: puddle may be stuck or the sandbox's endpoint is gone (restart the sandbox in puddle and connect again)"
    )]
    NoAnswer {
        /// How long the bridge waited.
        waited: Duration,
    },
    /// Something other than puddle answered.
    #[error("the SSH endpoint did not answer as puddle does")]
    NotPuddle,
    /// Reading from the endpoint failed mid-session.
    #[error("the connection to the sandbox broke")]
    ServerRead(#[source] io::Error),
}

impl From<IpcError> for BridgeError {
    fn from(e: IpcError) -> Self {
        match e {
            IpcError::NotFound { endpoint } => Self::NotFound { endpoint },
            IpcError::AccessDenied { endpoint } => Self::AccessDenied { endpoint },
            other => Self::Connect(other),
        }
    }
}

/// How a relayed session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEnd {
    /// The server closed the stream (the normal end).
    ServerClosed,
    /// Writing to the client failed: `ssh` went away first.
    ClientGone,
}

/// What a relayed session did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// How it ended.
    pub end: SessionEnd,
    /// Bytes from the client to the server.
    pub sent: u64,
    /// Bytes from the server to the client.
    pub received: u64,
    /// Whether the client's input ended before the session did.
    pub input_ended: bool,
}

/// Connects to the endpoint at `endpoint` and relays `input`/`output` (the bridge's stdin and
/// stdout) through it until the session ends.
///
/// # Errors
///
/// [`BridgeError::NotFound`], [`BridgeError::AccessDenied`] or [`BridgeError::Connect`] when
/// the endpoint can't be opened; otherwise as [`relay`].
pub async fn run<I, O>(endpoint: &Path, input: I, output: O) -> Result<Report, BridgeError>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    run_with(endpoint, input, output, HELLO_TIMEOUT).await
}

/// [`run`] with another wait for the endpoint's hello (tests).
///
/// # Errors
///
/// As [`run`].
pub async fn run_with<I, O>(
    endpoint: &Path,
    input: I,
    output: O,
    hello_timeout: Duration,
) -> Result<Report, BridgeError>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let conn = puddle_ipc::connect(endpoint).await?;
    relay_with(input, output, conn, hello_timeout).await
}

/// Relays `input` to `server` and `server` to `output` by the rules in the [module
/// docs](self), until the server's side ends or the client goes away.
///
/// # Errors
///
/// [`BridgeError::NoAnswer`] or [`BridgeError::NotPuddle`] when the server doesn't start with
/// [`HELLO`]; [`BridgeError::Refused`] when it then refuses;
/// [`BridgeError::ServerRead`] when reading from the server fails.
pub async fn relay<I, O, S>(input: I, output: O, server: S) -> Result<Report, BridgeError>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite,
{
    relay_with(input, output, server, HELLO_TIMEOUT).await
}

/// [`relay`] with another wait for the endpoint's hello (tests).
///
/// # Errors
///
/// As [`relay`].
pub async fn relay_with<I, O, S>(
    input: I,
    mut output: O,
    server: S,
    hello_timeout: Duration,
) -> Result<Report, BridgeError>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite,
{
    let (mut from_server, to_server) = tokio::io::split(server);
    let sent = AtomicU64::new(0);
    let up = pump_up(input, to_server, &sent);
    let down = async {
        read_hello(&mut from_server, hello_timeout).await?;
        match read_head(&mut from_server)
            .await
            .map_err(BridgeError::ServerRead)?
        {
            Head::Refused(reason) => Err(BridgeError::Refused { reason }),
            Head::Pass(head) => pump_down(&head, &mut from_server, &mut output).await,
        }
    };
    tokio::pin!(up, down);
    let mut input_ended = None;
    loop {
        tokio::select! {
            ended = &mut up, if input_ended.is_none() => input_ended = Some(ended),
            d = &mut down => {
                let (end, received) = d?;
                return Ok(Report {
                    end,
                    sent: sent.load(Ordering::Relaxed),
                    received,
                    input_ended: input_ended.unwrap_or(false),
                });
            }
        }
    }
}

/// Reads the endpoint's hello, which no SSH data precedes.
async fn read_hello<R: AsyncRead + Unpin>(
    server: &mut R,
    limit: Duration,
) -> Result<(), BridgeError> {
    let mut hello = [0_u8; HELLO.len()];
    match tokio::time::timeout(limit, server.read_exact(&mut hello)).await {
        Err(_) => Err(BridgeError::NoAnswer { waited: limit }),
        // Closed before a whole hello: whatever answered isn't serving.
        Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Err(BridgeError::NotPuddle),
        Ok(Err(e)) => Err(BridgeError::ServerRead(e)),
        Ok(Ok(_)) if hello == *HELLO.as_bytes() => Ok(()),
        Ok(Ok(_)) => Err(BridgeError::NotPuddle),
    }
}

/// Client to server; returns whether the client's input ended (`false`: the server went away).
async fn pump_up<I, W>(mut input: I, mut server: W, sent: &AtomicU64) -> bool
where
    I: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let n = match input.read(&mut buf).await {
            // A read error on stdin can't be reported to anyone better than the server's EOF.
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let chunk = buf.get(..n).unwrap_or_default();
        if server.write_all(chunk).await.is_err() || server.flush().await.is_err() {
            // The server is gone; its side of the stream ends the session.
            return false;
        }
        sent.fetch_add(n as u64, Ordering::Relaxed);
    }
    // Half-close where the stream has it (Unix). On a Windows pipe this does nothing and the
    // server learns of the end through SSH. An error means the server is gone already.
    let _ignored = server.shutdown().await;
    true
}

async fn pump_down<R, O>(
    head: &[u8],
    server: &mut R,
    output: &mut O,
) -> Result<(SessionEnd, u64), BridgeError>
where
    R: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut received = 0_u64;
    if !head.is_empty() {
        if write_out(output, head).await.is_err() {
            return Ok((SessionEnd::ClientGone, received));
        }
        received += head.len() as u64;
    }
    let mut buf = vec![0_u8; CHUNK];
    loop {
        let n = server
            .read(&mut buf)
            .await
            .map_err(BridgeError::ServerRead)?;
        if n == 0 {
            // Closing the client's input tells `ssh` the connection is gone. If `ssh` left
            // first, there is nobody to tell.
            let _ignored = output.shutdown().await;
            return Ok((SessionEnd::ServerClosed, received));
        }
        if write_out(output, buf.get(..n).unwrap_or_default())
            .await
            .is_err()
        {
            return Ok((SessionEnd::ClientGone, received));
        }
        received += n as u64;
    }
}

async fn write_out<O: AsyncWrite + Unpin>(output: &mut O, bytes: &[u8]) -> io::Result<()> {
    output.write_all(bytes).await?;
    output.flush().await
}

#[cfg(test)]
mod tests;
