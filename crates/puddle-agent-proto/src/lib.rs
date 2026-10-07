// SPDX-License-Identifier: GPL-3.0-or-later
//! The wire protocol between the guest agent (`puddle-agent`) and the host.
//!
//! One sandbox reaches the host over a vsock route (a Unix socket or named pipe on the host).
//! The agent opens a few connections on it, and each carries one **yamux session**. The agent
//! opens every yamux stream; the host never does.
//!
//! | First bytes of a stream | Stream kind | Host side |
//! |---|---|---|
//! | a [`kind`] preamble `\0puddle-control/1\n` | the **control stream**: newline-delimited JSON [`AgentMessage`]s, guest → host only | [`host::serve_session`] turns them into [`puddle_types::Event`]s |
//! | a [`kind`] preamble `\0puddle-resolve/1\n` | one name lookup for the guest's stub DNS ([`resolve`]) | [`host::StreamHandler::resolve`] |
//! | another [`kind`] preamble (`connect`, `ssh-agent`: reserved) or an unknown one | — | closed with a logged reason |
//! | anything else (an HTTP request line) | one proxied guest connection: `CONNECT host:port` or an absolute-form request | handed to the caller's [`host::StreamHandler`] (the proxy) |
//!
//! Both sides use [`yamux::client_config`] / [`yamux::server_config`], and both splice a guest
//! connection with [`relay::splice`], which passes an abort on as a TCP reset instead of a clean
//! close.
//!
//! Everything the guest sends is untrusted: the host bounds line lengths, rate-limits control
//! messages, cleans process names ([`puddle_types::Event::oom_kill`]) and ignores message types it
//! doesn't know.
//!
//! # Features
//!
//! - `testing`: [`testing::AllowAll`], a [`host::StreamHandler`] that serves every `CONNECT`
//!   without a policy, for integration tests of the agent. Never use it in product code.
#![forbid(unsafe_code)]

pub mod control;
pub mod host;
pub mod kind;
pub mod relay;
pub mod resolve;
#[cfg(feature = "testing")]
pub mod testing;
pub mod yamux;

pub use control::AgentMessage;

/// The yamux crate both sides use, so callers name the same types.
pub use tokio_yamux;
