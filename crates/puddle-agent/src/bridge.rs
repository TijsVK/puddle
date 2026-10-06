// SPDX-License-Identifier: GPL-3.0-or-later
//! The Docker bridge listener (T-099): nested containers use `172.17.0.1:3128` as their proxy
//! (the boot-time Docker CLI config, T-109), so the agent listens there too, **only while a
//! bridge owns that address**.
//!
//! dockerd can start after boot or restart, so [`watch()`] polls instead of looking once:
//!
//! - no bridge interface owns the address: nothing is bound, and no container-reachable
//!   address is ever listened on;
//! - the bridge appears: bind it (and check again that it is still the same interface);
//! - the bridge goes away: drop the listener and every connection it carried;
//! - the bridge comes back, even between two polls, as a different interface: rebind, because
//!   the old socket belonged to the old one.
//!
//! A connection accepted here is relayed exactly like one on the loopback listener: the same
//! [`crate::upstream::Upstream`], so the same route, the same sandbox and the same host policy
//! and audit. The agent doesn't look at the request.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::BridgeConfig;
use crate::serve;
use crate::upstream::Upstream;

/// An IPv4 address on an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfAddr {
    /// Interface name.
    pub name: String,
    /// Interface index; a re-created interface gets a new one.
    pub index: u32,
    /// The address.
    pub addr: Ipv4Addr,
}

/// Where interface addresses come from (`getifaddrs`, or a fake in tests).
pub trait Interfaces: Send + Sync + 'static {
    /// Every IPv4 address on every interface.
    ///
    /// # Errors
    ///
    /// The listing failing.
    fn ipv4(&self) -> io::Result<Vec<IfAddr>>;
}

/// Finds the interface that owns the bridge address, `None` if there isn't one.
pub trait Probe: Send + Sync + 'static {
    /// The index of the bridge interface that owns `addr`. A different index later means the
    /// bridge was re-created.
    fn find(&self, addr: Ipv4Addr) -> Option<u32>;
}

/// The real probe: an interface counts only when it owns the address **and** is a Linux bridge
/// (`/sys/class/net/<name>/bridge` exists), so a stray `eth0` that happens to carry the address
/// never opens a listener.
#[derive(Debug, Clone)]
pub struct SysProbe<I> {
    interfaces: I,
    sysfs_net: PathBuf,
}

impl<I: Interfaces> SysProbe<I> {
    /// A probe over `interfaces`, reading bridge-ness from `sysfs_net` (`/sys/class/net`).
    pub fn new(interfaces: I, sysfs_net: impl Into<PathBuf>) -> Self {
        Self {
            interfaces,
            sysfs_net: sysfs_net.into(),
        }
    }

    fn is_bridge(&self, name: &str) -> bool {
        // Kernel names never contain a separator; refuse a path trick anyway.
        !name.is_empty()
            && !name.contains(['/', '\0'])
            && name != "."
            && name != ".."
            && self.sysfs_net.join(name).join("bridge").is_dir()
    }
}

impl<I: Interfaces> Probe for SysProbe<I> {
    fn find(&self, addr: Ipv4Addr) -> Option<u32> {
        match self.interfaces.ipv4() {
            Ok(all) => all
                .into_iter()
                .find(|i| i.addr == addr && self.is_bridge(&i.name))
                .map(|i| i.index),
            Err(err) => {
                // Treated as "no bridge": never listen on a guess.
                tracing::warn!(error = %err, "listing interfaces failed");
                None
            }
        }
    }
}

/// The probe the agent uses in the guest.
#[must_use]
pub fn system_probe() -> Arc<dyn Probe> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(SysProbe::new(crate::ifaddrs::Getifaddrs, "/sys/class/net"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(NoBridge)
    }
}

/// A probe that never finds a bridge (non-Linux builds, which have no Docker bridge).
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy)]
struct NoBridge;

#[cfg(not(target_os = "linux"))]
impl Probe for NoBridge {
    fn find(&self, _addr: Ipv4Addr) -> Option<u32> {
        None
    }
}

/// What the watcher is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BridgeState {
    /// Where the bridge listener is bound, `None` while there is no bridge.
    pub addr: Option<SocketAddr>,
    /// How many listeners have been bound so far (a rebind counts), so a waiter can tell
    /// "the same listener" from "a new one on the same port".
    pub binds: u64,
}

/// A bound bridge listener and its connections.
struct Bound {
    index: u32,
    tasks: JoinSet<()>,
}

impl Bound {
    /// Closes the listener and waits until it is really closed, so the same address can be
    /// bound again at once.
    async fn close(mut self) {
        self.tasks.shutdown().await;
    }
}

/// Watches for the bridge and keeps a listener on it while it exists. Runs forever.
pub async fn watch(
    config: BridgeConfig,
    probe: Arc<dyn Probe>,
    upstream: Arc<Upstream>,
    state: watch::Sender<BridgeState>,
) {
    let ip = *config.addr.ip();
    let mut bound: Option<Bound> = None;
    // The interface whose bind already failed, so a persistent failure is logged once.
    let mut failed_for: Option<u32> = None;
    let mut binds = 0u64;
    loop {
        let seen = probe.find(ip);
        if bound.as_ref().map(|b| b.index) != seen
            && let Some(old) = bound.take()
        {
            tracing::info!(index = old.index, now = ?seen, "docker bridge gone or replaced; listener closed");
            old.close().await;
            state.send_replace(BridgeState { addr: None, binds });
        }
        if bound.is_none() {
            match seen {
                Some(index) => match bind(&config, &*probe, index, &upstream).await {
                    Ok((local, listener)) => {
                        binds += 1;
                        failed_for = None;
                        tracing::info!(listen = %local, index, "docker bridge found; listening");
                        bound = Some(listener);
                        state.send_replace(BridgeState {
                            addr: Some(local),
                            binds,
                        });
                    }
                    Err(err) => {
                        if failed_for != Some(index) {
                            tracing::warn!(addr = %config.addr, error = %err, "cannot listen on the docker bridge; retrying");
                            failed_for = Some(index);
                        }
                    }
                },
                None => failed_for = None,
            }
        }
        tokio::time::sleep(config.poll).await;
    }
}

/// Binds the bridge address and starts serving, but only if the probe still reports `index`
/// afterwards (the bridge could have gone between the probe and the bind).
async fn bind(
    config: &BridgeConfig,
    probe: &dyn Probe,
    index: u32,
    upstream: &Arc<Upstream>,
) -> io::Result<(SocketAddr, Bound)> {
    let listener = TcpListener::bind(SocketAddr::V4(config.addr)).await?;
    let local = listener.local_addr()?;
    if probe.find(*config.addr.ip()) != Some(index) {
        return Err(io::Error::other("the bridge changed while binding"));
    }
    let mut tasks = JoinSet::new();
    tasks.spawn(serve::serve(listener, Arc::clone(upstream)));
    Ok((local, Bound { index, tasks }))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(Vec<IfAddr>);

    impl Interfaces for Fake {
        fn ipv4(&self) -> io::Result<Vec<IfAddr>> {
            Ok(self.0.clone())
        }
    }

    struct Broken;

    impl Interfaces for Broken {
        fn ipv4(&self) -> io::Result<Vec<IfAddr>> {
            Err(io::Error::other("netlink says no"))
        }
    }

    fn iface(name: &str, index: u32, addr: [u8; 4]) -> IfAddr {
        IfAddr {
            name: name.to_owned(),
            index,
            addr: Ipv4Addr::from(addr),
        }
    }

    /// A fake `/sys/class/net` where `bridges` have a `bridge` directory and `others` don't.
    fn sysfs(bridges: &[&str], others: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for name in bridges {
            std::fs::create_dir_all(dir.path().join(name).join("bridge")).unwrap();
        }
        for name in others {
            std::fs::create_dir_all(dir.path().join(name)).unwrap();
        }
        dir
    }

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 17, 0, 1);

    #[test]
    fn a_bridge_that_owns_the_address_is_found_by_index() {
        let sys = sysfs(&["docker0"], &["eth0"]);
        let probe = SysProbe::new(
            Fake(vec![
                iface("eth0", 2, [10, 0, 2, 15]),
                iface("docker0", 5, [172, 17, 0, 1]),
            ]),
            sys.path(),
        );
        assert_eq!(probe.find(GATEWAY), Some(5));
    }

    #[test]
    fn a_non_bridge_interface_with_the_address_is_not_a_bridge() {
        let sys = sysfs(&["docker0"], &["eth0", "veth1"]);
        let probe = SysProbe::new(
            Fake(vec![
                iface("eth0", 2, [172, 17, 0, 1]),
                iface("veth1", 9, [172, 17, 0, 1]),
            ]),
            sys.path(),
        );
        assert_eq!(probe.find(GATEWAY), None);
    }

    #[test]
    fn a_bridge_without_the_address_is_not_found() {
        let sys = sysfs(&["docker0", "br-ab12"], &[]);
        let probe = SysProbe::new(
            Fake(vec![
                iface("docker0", 5, [172, 18, 0, 1]),
                iface("br-ab12", 6, [172, 19, 0, 1]),
            ]),
            sys.path(),
        );
        assert_eq!(probe.find(GATEWAY), None);
    }

    #[test]
    fn a_failed_listing_means_no_bridge() {
        let sys = sysfs(&["docker0"], &[]);
        assert_eq!(SysProbe::new(Broken, sys.path()).find(GATEWAY), None);
    }

    #[test]
    fn odd_interface_names_never_reach_the_filesystem() {
        let sys = sysfs(&[], &[]);
        let probe = SysProbe::new(
            Fake(vec![
                iface("", 1, [172, 17, 0, 1]),
                iface("..", 2, [172, 17, 0, 1]),
                iface(".", 3, [172, 17, 0, 1]),
                iface("a/b", 4, [172, 17, 0, 1]),
            ]),
            sys.path(),
        );
        assert_eq!(probe.find(GATEWAY), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_probe_finds_no_bridge_for_loopback() {
        // `lo` owns 127.0.0.1 but is not a bridge.
        assert_eq!(system_probe().find(Ipv4Addr::LOCALHOST), None);
    }
}
