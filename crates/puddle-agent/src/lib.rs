// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest agent (`puddle-agent`): a static binary inside each sandbox (ADR 0005) that
//!
//! - listens for proxy clients (`HTTP(S)_PROXY`) and
//!   carries each connection to puddle's proxy as one yamux stream over vsock ([`serve`],
//!   [`upstream`]);
//! - also listens on the Docker bridge address (`172.17.0.1:3128`) while a bridge owns it, so
//!   containers inside the sandbox reach the same proxy ([`bridge`]);
//! - watches the guest kernel's OOM killer and reports each kill on the control stream
//!   ([`oom`], [`control`]), which the host turns into
//!   [`puddle_types::Event::OomKill`].
//!
//! - answers DNS for tools that ignore the proxy settings, when switched on: a stub on one
//!   address hands out stand-in addresses and asks the host about each name ([`capture`]).
//!
//! It also applies merged guest files for the boot hook ([`merge_file`]).
//!
//! The wire protocol is in `puddle-agent-proto`. Settings come from environment variables
//! ([`config`]). The binary's `main` only parses the command line ([`cli`]) and starts an
//! [`Agent`].

pub mod bridge;
pub mod capture;
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
    stand_ins: Option<capture::table::StandIns>,
    dns: Option<(SocketAddr, SocketAddr)>,
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
        let (stand_ins, dns) = match &config.dns {
            Some(dns_config) => {
                let (table, bound) = start_dns(dns_config, &upstream, &mut tasks).await;
                (Some(table), bound)
            }
            None => (None, None),
        };
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
            stand_ins,
            dns,
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

    /// The stand-in table, `None` while the stub DNS is off. The transparent listener finds the
    /// name behind a redirected connection's original address in it.
    #[must_use]
    pub fn stand_ins(&self) -> Option<capture::table::StandIns> {
        self.stand_ins.clone()
    }

    /// The UDP and TCP addresses the stub DNS bound at start, `None` when it is off or its address
    /// didn't exist yet (it keeps trying).
    #[must_use]
    pub fn dns_addrs(&self) -> Option<(SocketAddr, SocketAddr)> {
        self.dns
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

/// Starts the stub DNS. If its address isn't there yet (the interface is made after the agent
/// starts), a task keeps trying; the table is usable at once.
async fn start_dns(
    config: &config::DnsConfig,
    upstream: &Arc<upstream::Upstream>,
    tasks: &mut JoinSet<()>,
) -> (capture::table::StandIns, Option<(SocketAddr, SocketAddr)>) {
    let table = match &config.table {
        Some(path) => capture::table::StandIns::open(path),
        None => capture::table::StandIns::in_memory(),
    };
    let limits = capture::dns::Limits::default();
    let stub = capture::dns::Stub::new(
        capture::dns::HostAsk::new(Arc::clone(upstream), limits.ask_timeout),
        table.clone(),
        limits,
    );
    let listen = SocketAddr::V4(config.listen);
    match capture::dns::DnsServer::bind(stub.clone(), listen).await {
        Ok(server) => {
            let addrs = (server.udp_addr(), server.tcp_addr());
            tracing::info!(%listen, "stub DNS listening");
            tasks.spawn(server.run());
            (table, Some(addrs))
        }
        Err(err) => {
            tracing::warn!(%listen, error = %err, "stub DNS not bound yet; trying again until it is");
            tasks.spawn(capture::dns::bind_when_ready(stub, listen));
            (table, None)
        }
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
