// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest agent (`puddle-agent`): a static binary inside each sandbox (ADR 0005) that
//!
//! - listens for proxy clients (`HTTP(S)_PROXY`) and
//!   carries each connection to puddle's proxy as one yamux stream over vsock ([`serve`],
//!   [`upstream`]);
//! - also listens on the Docker bridge address (`172.17.0.1:3128`) while a bridge owns it, so
//!   containers inside the sandbox reach the same proxy ([`bridge`], T-099);
//! - watches the guest kernel's OOM killer and reports each kill on the control stream
//!   ([`oom`], [`control`]), which the host turns into
//!   [`puddle_types::Event::OomKill`].
//!
//! It also applies merged guest files for the boot hook ([`merge_file`], T-097).
//!
//! The wire protocol is in `puddle-agent-proto`. Settings come from environment variables
//! ([`config`]). The binary's `main` only parses the command line ([`cli`]) and starts an
//! [`Agent`].

pub mod bridge;
pub mod cli;
pub mod config;
pub mod control;
#[cfg(target_os = "linux")]
mod ifaddrs;
pub mod merge_file;
pub mod oom;
pub mod serve;
pub mod upstream;
#[cfg(target_os = "linux")]
mod vsock;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use puddle_agent_proto::AgentMessage;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

pub use config::Config;

/// Reports waiting for the control stream.
const REPORT_QUEUE: usize = 64;

/// A running agent. Its tasks stop when it is dropped.
#[derive(Debug)]
pub struct Agent {
    local_addr: SocketAddr,
    bridge: watch::Receiver<bridge::BridgeState>,
    tasks: JoinSet<()>,
    /// Keeps the control stream open when the OOM watch is off.
    _reports: Option<mpsc::Sender<AgentMessage>>,
}

impl Agent {
    /// Binds the listener and starts the proxy relay, the control stream and (if on) the OOM
    /// watch. The host is dialled on first use.
    ///
    /// # Errors
    ///
    /// Binding the listener failing.
    pub async fn start(config: Config) -> io::Result<Self> {
        Self::start_with_probe(config, bridge::system_probe()).await
    }

    /// [`Agent::start`] with a chosen way of finding the Docker bridge (tests).
    ///
    /// # Errors
    ///
    /// Binding the listener failing.
    pub async fn start_with_probe(
        config: Config,
        probe: Arc<dyn bridge::Probe>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let upstream = Arc::new(upstream::Upstream::new(&config));
        let mut tasks = JoinSet::new();
        tasks.spawn(serve::serve(listener, Arc::clone(&upstream)));
        let (bridge_tx, bridge) = watch::channel(bridge::BridgeState::default());
        match config.bridge {
            // A wildcard listener on the bridge's port already covers the bridge address (and
            // would make the bind fail), so there is nothing to watch for.
            Some(b) if covers(config.listen, b.addr.into()) => {
                tracing::info!(listen = %config.listen, "the proxy listener already covers the docker bridge");
            }
            Some(b) => {
                tasks.spawn(bridge::watch(b, probe, Arc::clone(&upstream), bridge_tx));
            }
            None => {}
        }
        let (tx, rx) = mpsc::channel(REPORT_QUEUE);
        tasks.spawn(control::run(upstream, rx));
        let reports = match config.oom {
            Some(sources) => {
                tasks.spawn(oom::watch(sources, tx));
                None
            }
            None => Some(tx),
        };
        tracing::info!(listen = %local_addr, target = ?config.target, sessions = config.mux, "puddle-agent started");
        Ok(Self {
            local_addr,
            bridge,
            tasks,
            _reports: reports,
        })
    }

    /// The address the proxy listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Where the Docker bridge listener is bound right now, `None` while there is no bridge
    /// (or the listener is off).
    #[must_use]
    pub fn bridge_addr(&self) -> Option<SocketAddr> {
        self.bridge.borrow().addr
    }

    /// Follows the Docker bridge listener: every bind and every close is a new state.
    #[must_use]
    pub fn bridge_state(&self) -> watch::Receiver<bridge::BridgeState> {
        self.bridge.clone()
    }

    /// Runs until the listener stops (it doesn't on its own).
    pub async fn run(mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}

/// Whether a listener on `listen` accepts connections for `addr`.
fn covers(listen: SocketAddr, addr: SocketAddr) -> bool {
    listen.port() == addr.port() && (listen.ip().is_unspecified() || listen.ip() == addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_wildcard_or_equal_listener_covers_the_bridge_address() {
        let bridge: SocketAddr = "172.17.0.1:3128".parse().unwrap();
        assert!(covers("0.0.0.0:3128".parse().unwrap(), bridge));
        assert!(covers("172.17.0.1:3128".parse().unwrap(), bridge));
        assert!(!covers("0.0.0.0:3129".parse().unwrap(), bridge));
        assert!(!covers("127.0.0.1:3128".parse().unwrap(), bridge));
    }
}
