// SPDX-License-Identifier: GPL-3.0-or-later
//! The SSH endpoint of a sandbox and the `puddle ssh-bridge` relay (W1, T-114).
//!
//! An IDE or `ssh` reaches a sandbox like this:
//!
//! ```text
//!  ssh / VS Code ──stdio──► puddle ssh-bridge <endpoint> ──pipe/socket──► SshEndpoint ──► serve_ssh
//!   (ProxyCommand)            (bridge::run)                 (puddle-ipc,     (one per      (msb's SSH
//!                                                            owner-only)      sandbox)       server)
//! ```
//!
//! | Piece | What |
//! |---|---|
//! | [`SshEndpoint`] | accepts clients on a sandbox's owner-only [`puddle_ipc::Listener`]; each client gets **its own** SSH connection to the sandbox |
//! | [`SshTarget`] | what a client is served by; puddle's only implementation is [`puddle_boot::GatedSandbox`], so nobody gets SSH before the boot hook returned 0 |
//! | [`bridge`] | the relay between `ssh`'s stdio and the endpoint, and the refusal line it turns into a message |
//!
//! **One SSH connection per client.** msb caps active TCP forwards at 64 per SSH connection
//! (T-071), so connections are never shared: an IDE's forwards don't eat into puddle's own, and
//! puddle's forwards (W5) open their own connection.
//!
//! **No timeouts on a session.** Neither the endpoint nor the bridge ends an idle session; an
//! IDE may sit idle for hours. The runtime's own SSH server must have its inactivity timeout off
//! too (the msb adapter builds it with `disable_inactivity_timeout`).
//!
//! **End of stream.** A Windows named pipe has no half-close (T-105): when `ssh` closes the
//! bridge's stdin the sandbox side can't be told, so the bridge keeps relaying the sandbox's
//! output until the server ends the session (SSH ends it with its own `DISCONNECT`). The
//! session is over when the server's side ends; see [`bridge`] for the exact rules.
#![forbid(unsafe_code)]

pub mod bridge;
mod endpoint;
mod refusal;

pub use endpoint::{SshEndpoint, SshTarget};
pub use refusal::{HELLO, REFUSAL_PREFIX, refusal_line, sanitize_reason};
