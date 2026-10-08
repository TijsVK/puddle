// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared harness: a host over a Unix socket (yamux server, control stream, allow-all CONNECT
//! endpoint) and an agent pointed at it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use puddle_agent::config::{OomSources, Target};
use puddle_agent::{Agent, Config};
use puddle_agent_proto::host::{HostConfig, serve_session};
use puddle_agent_proto::testing::AllowAll;
use puddle_types::{Event, EventSink, WorkspaceName};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct ChanSink(pub mpsc::UnboundedSender<Event>);

impl EventSink for ChanSink {
    fn emit(&self, event: Event) {
        let _ = self.0.send(event);
    }
}

/// A per-test temp dir, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pa-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn workspace() -> WorkspaceName {
    WorkspaceName::new("agent").unwrap()
}

pub struct Rig {
    pub agent: Agent,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub sink: Arc<dyn EventSink>,
    pub host: JoinHandle<()>,
    pub dir: TempDir,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.host.abort();
    }
}

impl Rig {
    pub fn socket(&self) -> PathBuf {
        self.dir.0.join("route.sock")
    }

    /// Stops the host (every session to the agent dies) and starts a fresh one on the same path.
    pub async fn restart_host(&mut self) {
        self.host.abort();
        let _ = (&mut self.host).await;
        std::fs::remove_file(self.socket()).unwrap();
        self.host = start_host(&self.socket(), Arc::clone(&self.sink));
    }
}

pub fn start_host(socket: &Path, sink: Arc<dyn EventSink>) -> JoinHandle<()> {
    let listener = UnixListener::bind(socket).unwrap();
    tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let sink = Arc::clone(&sink);
            sessions.spawn(async move {
                // A session ends with an error when the agent side goes away mid-frame; fine here.
                let _ = serve_session(
                    conn,
                    workspace(),
                    sink,
                    Arc::new(AllowAll),
                    HostConfig::default(),
                )
                .await;
            });
        }
    })
}

/// Starts a host on a Unix socket and an agent on 127.0.0.1:0 pointed at it.
/// `oom` gets the rig's temp dir and returns the OOM watch sources (or `None` for no watch).
pub async fn rig(tag: &str, oom: impl FnOnce(&Path) -> Option<OomSources>) -> Rig {
    rig_with(tag, oom, |_| {}, Arc::new(NoBridge)).await
}

/// A probe that never finds a bridge.
pub struct NoBridge;

impl puddle_agent::bridge::Probe for NoBridge {
    fn find(&self, _: std::net::Ipv4Addr) -> Option<u32> {
        None
    }
}

/// [`rig`] with a say in the config and the bridge probe.
pub async fn rig_with(
    tag: &str,
    oom: impl FnOnce(&Path) -> Option<OomSources>,
    tweak: impl FnOnce(&mut Config),
    probe: Arc<dyn puddle_agent::bridge::Probe>,
) -> Rig {
    let dir = TempDir::new(tag);
    let oom = oom(&dir.0);
    let socket = dir.0.join("route.sock");
    let (tx, events) = mpsc::unbounded_channel();
    let sink: Arc<dyn EventSink> = Arc::new(ChanSink(tx));
    let host = start_host(&socket, Arc::clone(&sink));
    let mut config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        target: Target::Unix(socket),
        oom,
        ..Config::default()
    };
    tweak(&mut config);
    let agent = Agent::start_with_probe(config, probe).await.unwrap();
    Rig {
        agent,
        events,
        sink,
        host,
        dir,
    }
}

pub async fn next_event(
    rx: &mut mpsc::UnboundedReceiver<Event>,
    within: Duration,
) -> Option<Event> {
    tokio::time::timeout(within, rx.recv()).await.ok().flatten()
}
