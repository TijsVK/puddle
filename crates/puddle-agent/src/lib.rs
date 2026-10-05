// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest agent (`puddle-agent`): a static binary inside each sandbox (ADR 0005) that
//!
//! - listens for proxy clients (`HTTP(S)_PROXY`, nested containers via the docker0 gateway) and
//!   carries each connection to puddle's proxy as one yamux stream over vsock ([`serve`],
//!   [`upstream`]);
//! - watches the guest kernel's OOM killer and reports each kill on the control stream
//!   ([`oom`], [`control`]), which the host turns into
//!   [`puddle_types::Event::OomKill`].
//!
//! The wire protocol is in `puddle-agent-proto`. Settings come from environment variables
//! ([`config`]). The binary's `main` only parses the command line ([`cli`]) and starts an
//! [`Agent`].

pub mod cli;
pub mod config;
pub mod control;
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
use tokio::sync::mpsc;
use tokio::task::JoinSet;

pub use config::Config;

/// Reports waiting for the control stream.
const REPORT_QUEUE: usize = 64;

/// A running agent. Its tasks stop when it is dropped.
#[derive(Debug)]
pub struct Agent {
    local_addr: SocketAddr,
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
        let listener = TcpListener::bind(config.listen).await?;
        let local_addr = listener.local_addr()?;
        let upstream = Arc::new(upstream::Upstream::new(&config));
        let mut tasks = JoinSet::new();
        tasks.spawn(serve::serve(listener, Arc::clone(&upstream)));
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
            tasks,
            _reports: reports,
        })
    }

    /// The address the proxy listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs until the listener stops (it doesn't on its own).
    pub async fn run(mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}
