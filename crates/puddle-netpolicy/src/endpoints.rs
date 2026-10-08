// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's own listeners: every puddle listener registers here when it binds, and
//! the guard blocks a workspace from reaching any of them, whatever the loopback toggle or
//! the rules say.

use std::fmt;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

/// What a registered puddle listener is, for the block message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EndpointKind {
    /// The local API.
    Api,
    /// The image-pull proxy.
    PullProxy,
    /// The browser front for VS Code in the browser.
    BrowserFront,
    /// A pinned port forward.
    PinnedForward,
    /// Any other listener.
    Other,
}

impl EndpointKind {
    /// A short description for messages.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Api => "API",
            Self::PullProxy => "image-pull proxy",
            Self::BrowserFront => "browser front",
            Self::PinnedForward => "pinned port forward",
            Self::Other => "listener",
        }
    }
}

impl fmt::Display for EndpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

/// Which addresses land on this host. A seam, so tests don't depend on the machine's interfaces.
pub trait HostAddrs: Send + Sync {
    /// Whether a connection to `ip` reaches this host's own listeners.
    fn is_own(&self, ip: IpAddr) -> bool;
}

/// The real [`HostAddrs`]: loopback and unspecified addresses land here, and so does any
/// address the host can `bind`, which is exactly the set of its own interface addresses (so a
/// listener on `0.0.0.0` reached through the host's LAN address is caught too).
#[derive(Debug, Clone, Copy, Default)]
pub struct OwnAddresses;

impl HostAddrs for OwnAddresses {
    fn is_own(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || ip.is_unspecified() || UdpSocket::bind((ip, 0)).is_ok()
    }
}

#[derive(Debug)]
struct Entry {
    id: u64,
    addr: SocketAddr,
    kind: EndpointKind,
}

#[derive(Debug, Default)]
struct Inner {
    entries: RwLock<Vec<Entry>>,
    next_id: AtomicU64,
}

/// The registry of puddle's own listeners. Cheap to clone; clones share the registry.
///
/// ```
/// use puddle_netpolicy::{EndpointKind, OwnAddresses, PuddleEndpoints};
///
/// let endpoints = PuddleEndpoints::new();
/// let api = endpoints.register("127.0.0.1:7070".parse().unwrap(), EndpointKind::Api);
/// assert_eq!(endpoints.find("127.0.0.1:7070".parse().unwrap(), &OwnAddresses), Some(EndpointKind::Api));
/// drop(api);
/// assert_eq!(endpoints.find("127.0.0.1:7070".parse().unwrap(), &OwnAddresses), None);
/// ```
#[derive(Debug, Clone, Default)]
pub struct PuddleEndpoints {
    inner: Arc<Inner>,
}

/// A listener's registration; dropping it unregisters the listener. Keep it as long as the
/// listener is bound.
#[derive(Debug)]
#[must_use = "dropping the registration unregisters the listener at once"]
pub struct Registration {
    endpoints: PuddleEndpoints,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = self
            .endpoints
            .inner
            .entries
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        entries.retain(|e| e.id != self.id);
    }
}

impl PuddleEndpoints {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a listener bound at `addr` (with its real port, after `bind`).
    pub fn register(&self, addr: SocketAddr, kind: EndpointKind) -> Registration {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Entry { id, addr, kind });
        Registration {
            endpoints: self.clone(),
            id,
        }
    }

    /// The listener a connection to `dest` would reach, if any: same port, and an address that
    /// is the listener's own or lands on this host (loopback, unspecified, one of its interface
    /// addresses, also as IPv4-mapped IPv6). Over-matching a listener bound to one address only
    /// is deliberate: it fails closed.
    #[must_use]
    pub fn find(&self, dest: SocketAddr, host: &dyn HostAddrs) -> Option<EndpointKind> {
        let entries = self
            .inner
            .entries
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let mut same_port = entries.iter().filter(|e| e.addr.port() == dest.port());
        let first = same_port.next()?;
        let ip = unmapped(dest.ip());
        if let Some(e) = std::iter::once(first)
            .chain(same_port)
            .find(|e| unmapped(e.addr.ip()) == ip)
        {
            return Some(e.kind);
        }
        (ip.is_loopback() || ip.is_unspecified() || host.is_own(ip)).then_some(first.kind)
    }

    /// The registered listeners, in registration order.
    #[must_use]
    pub fn list(&self) -> Vec<(SocketAddr, EndpointKind)> {
        self.inner
            .entries
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|e| (e.addr, e.kind))
            .collect()
    }
}

fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Lan;
    impl HostAddrs for Lan {
        fn is_own(&self, ip: IpAddr) -> bool {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip == "192.168.1.10".parse::<IpAddr>().unwrap()
        }
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn any_host_local_address_on_a_registered_port_matches() {
        let endpoints = PuddleEndpoints::new();
        let _api = endpoints.register(sa("127.0.0.1:7070"), EndpointKind::Api);
        for dest in [
            "127.0.0.1:7070",
            "127.0.0.2:7070",
            "[::1]:7070",
            "[::ffff:127.0.0.1]:7070",
            "0.0.0.0:7070",
            "[::]:7070",
            "192.168.1.10:7070",
        ] {
            assert_eq!(
                endpoints.find(sa(dest), &Lan),
                Some(EndpointKind::Api),
                "{dest}"
            );
        }
        for dest in ["192.168.1.11:7070", "127.0.0.1:7071", "8.8.8.8:7070"] {
            assert_eq!(endpoints.find(sa(dest), &Lan), None, "{dest}");
        }
    }

    #[test]
    fn the_listener_s_own_address_matches_even_if_not_host_local() {
        struct Nothing;
        impl HostAddrs for Nothing {
            fn is_own(&self, _: IpAddr) -> bool {
                false
            }
        }
        let endpoints = PuddleEndpoints::new();
        let _a = endpoints.register(sa("10.9.9.9:9000"), EndpointKind::PinnedForward);
        let _b = endpoints.register(sa("10.9.9.8:9000"), EndpointKind::BrowserFront);
        assert_eq!(
            endpoints.find(sa("10.9.9.8:9000"), &Nothing),
            Some(EndpointKind::BrowserFront)
        );
        assert_eq!(endpoints.find(sa("10.9.9.7:9000"), &Nothing), None);
    }

    #[test]
    fn dropping_the_registration_unregisters_only_that_listener() {
        let endpoints = PuddleEndpoints::new();
        let api = endpoints.register(sa("127.0.0.1:7070"), EndpointKind::Api);
        let pull = endpoints
            .clone()
            .register(sa("127.0.0.1:7071"), EndpointKind::PullProxy);
        assert_eq!(endpoints.list().len(), 2);
        drop(api);
        assert_eq!(
            endpoints.list(),
            vec![(sa("127.0.0.1:7071"), EndpointKind::PullProxy)]
        );
        drop(pull);
        assert_eq!(endpoints.list(), Vec::new());
    }

    #[test]
    fn own_addresses_detects_loopback_and_unspecified() {
        for ip in ["127.0.0.1", "0.0.0.0", "::1", "::"] {
            assert!(OwnAddresses.is_own(ip.parse().unwrap()), "{ip}");
        }
        // TEST-NET-1 is never configured on a CI runner.
        assert!(!OwnAddresses.is_own("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn kinds_describe_themselves() {
        for (kind, text) in [
            (EndpointKind::Api, "API"),
            (EndpointKind::PullProxy, "image-pull proxy"),
            (EndpointKind::BrowserFront, "browser front"),
            (EndpointKind::PinnedForward, "pinned port forward"),
            (EndpointKind::Other, "listener"),
        ] {
            assert_eq!(kind.to_string(), text);
        }
    }
}
