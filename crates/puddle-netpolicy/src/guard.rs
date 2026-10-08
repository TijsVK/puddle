// SPDX-License-Identifier: GPL-3.0-or-later
//! The guard: what a workspace may reach, per destination and per resolved address (R-14).

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use puddle_types::{BlockReason, Host, LocalCategory, WorkspaceName};

use crate::{
    AddressClass, HostAddrs, LocalAccess, LocalAccessSource, OwnAddresses, PuddleEndpoints, Target,
    classify_ip,
};

/// What the proxy may do with one resolved address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressVerdict {
    /// Connect if the rules allow the request.
    Allow,
    /// A local address whose toggle is on: connect only after an **exact** allow of the name or
    /// of this address (R-14). After a suffix allow the proxy admits the address if an
    /// exact rule for its IP allows it, and otherwise asks again with `SuffixAllows::Ignore`, so
    /// the request goes pending for the exact name.
    ExactOnly(LocalCategory),
    /// Never connect, whatever the rules say; no pending row.
    Block(BlockReason),
}

/// The destination guard: address classes, the workspace's local toggles and puddle's own
/// endpoints. Cheap to share (`Arc`); every check reads the workspace's current settings.
///
/// ```
/// use std::sync::Arc;
/// use puddle_netpolicy::{AddressVerdict, LocalAccess, NetPolicy};
/// use puddle_types::{BlockReason, LocalCategory, WorkspaceName};
///
/// let guard = NetPolicy::new(Arc::new(LocalAccess::NONE.with_toggle(LocalCategory::Private, true)));
/// let workspace = WorkspaceName::new("box").unwrap();
/// assert_eq!(guard.check_address(&workspace, "8.8.8.8:443".parse().unwrap()), AddressVerdict::Allow);
/// assert_eq!(
///     guard.check_address(&workspace, "10.0.0.1:443".parse().unwrap()),
///     AddressVerdict::ExactOnly(LocalCategory::Private)
/// );
/// assert_eq!(
///     guard.check_address(&workspace, "127.0.0.1:80".parse().unwrap()),
///     AddressVerdict::Block(BlockReason::LocalToggle(LocalCategory::Loopback))
/// );
/// ```
#[derive(Clone)]
pub struct NetPolicy {
    access: Arc<dyn LocalAccessSource>,
    endpoints: PuddleEndpoints,
    host: Arc<dyn HostAddrs>,
}

impl fmt::Debug for NetPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPolicy")
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

impl NetPolicy {
    /// A guard that reads each workspace's toggles from `access`, with an empty endpoint registry
    /// and the host's real addresses ([`OwnAddresses`]).
    #[must_use]
    pub fn new(access: Arc<dyn LocalAccessSource>) -> Self {
        Self {
            access,
            endpoints: PuddleEndpoints::new(),
            host: Arc::new(OwnAddresses),
        }
    }

    /// Uses `endpoints` as the registry of puddle's own listeners.
    #[must_use]
    pub fn with_endpoints(mut self, endpoints: PuddleEndpoints) -> Self {
        self.endpoints = endpoints;
        self
    }

    /// Uses `host` to tell which addresses land on this host.
    #[must_use]
    pub fn with_host_addrs(mut self, host: Arc<dyn HostAddrs>) -> Self {
        self.host = host;
        self
    }

    /// The registry of puddle's own listeners, to register them into.
    #[must_use]
    pub fn endpoints(&self) -> &PuddleEndpoints {
        &self.endpoints
    }

    /// The class of `addr`: one of puddle's own endpoints first (whatever its address class),
    /// then the address's class.
    #[must_use]
    pub fn classify(&self, addr: SocketAddr) -> AddressClass {
        match self.endpoints.find(addr, self.host.as_ref()) {
            Some(kind) => AddressClass::PuddleEndpoint(kind),
            None => classify_ip(addr.ip()),
        }
    }

    /// The verdict on one address `workspace` would connect to.
    #[must_use]
    pub fn check_address(&self, workspace: &WorkspaceName, addr: SocketAddr) -> AddressVerdict {
        verdict(self.classify(addr), self.access.local_access(workspace))
    }

    /// The name stage, before the rules are asked: a destination that is blocked by its literal
    /// address or by its name alone (`localhost`, a metadata name) gets its block reason here,
    /// so it never becomes a pending row (R-14). `None`: ask the rules.
    #[must_use]
    pub fn check_target(
        &self,
        workspace: &WorkspaceName,
        target: &Target,
        port: u16,
    ) -> Option<BlockReason> {
        let access = self.access.local_access(workspace);
        if let Host::Ip(ip) = target.host() {
            return match verdict(self.classify(SocketAddr::new(*ip, port)), access) {
                AddressVerdict::Block(reason) => Some(reason),
                _ => None,
            };
        }
        let category = target.named_category()?;
        // `localhost:<puddle port>`: refuse now rather than after a useless approval.
        let loopback = SocketAddr::from(([127, 0, 0, 1], port));
        if category == LocalCategory::Loopback
            && self.endpoints.find(loopback, self.host.as_ref()).is_some()
        {
            return Some(BlockReason::PuddleEndpoint);
        }
        (!access.is_on(category)).then_some(BlockReason::LocalToggle(category))
    }
}

fn verdict(class: AddressClass, access: LocalAccess) -> AddressVerdict {
    match class {
        AddressClass::Public => AddressVerdict::Allow,
        AddressClass::Local { category, .. } if !access.is_on(category) => {
            AddressVerdict::Block(BlockReason::LocalToggle(category))
        }
        AddressClass::Local { .. } if access.wildcards_reach_local() => AddressVerdict::Allow,
        AddressClass::Local { category, .. } => AddressVerdict::ExactOnly(category),
        // puddle's own endpoints, and any class this version doesn't know: blocked.
        _ => AddressVerdict::Block(BlockReason::PuddleEndpoint),
    }
}

/// The user-facing explanation for a block (the `403` body), naming what would change it.
///
/// ```
/// use puddle_netpolicy::block_message;
/// use puddle_types::{BlockReason, Host, LocalCategory, WorkspaceName};
///
/// let workspace = WorkspaceName::new("box").unwrap();
/// let host = Host::parse_normalised("10.0.0.1").unwrap();
/// let msg = block_message(&host, &workspace, &[BlockReason::LocalToggle(LocalCategory::Private)]);
/// assert!(msg.contains("turn on 'private' (local/private network) globally or for workspace box"));
/// ```
#[must_use]
pub fn block_message(host: &Host, workspace: &WorkspaceName, reasons: &[BlockReason]) -> String {
    let mut toggles: Vec<LocalCategory> = reasons
        .iter()
        .filter_map(|r| match r {
            BlockReason::LocalToggle(c) => Some(*c),
            _ => None,
        })
        .collect();
    toggles.sort_unstable();
    toggles.dedup();
    if toggles.is_empty() {
        return match reasons.first() {
            Some(BlockReason::PuddleEndpoint) => format!(
                "{host} is one of puddle's own endpoints; workspaces never reach them, and no rule or toggle changes this"
            ),
            Some(BlockReason::SshUnsupported) => "SSH is not supported yet, use HTTPS".to_owned(),
            _ => format!("{host} is a local address puddle does not connect to"),
        };
    }
    let what = toggles
        .iter()
        .map(|c| c.describe())
        .collect::<Vec<_>>()
        .join(" or ");
    let switch = toggles
        .iter()
        .map(|c| format!("'{}' ({})", c.key(), c.describe()))
        .collect::<Vec<_>>()
        .join(" or ");
    format!(
        "{host} is {what}, and that toggle is off. To allow it, turn on {switch} globally or for workspace {workspace}; it then still needs an allow rule or an approval. Approving it alone does not change this"
    )
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::{EndpointKind, Registration, normalise_host};

    fn workspace() -> WorkspaceName {
        WorkspaceName::new("box").unwrap()
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    struct Lan;
    impl HostAddrs for Lan {
        fn is_own(&self, ip: IpAddr) -> bool {
            ip == "192.168.1.10".parse::<IpAddr>().unwrap()
        }
    }

    fn guard(access: LocalAccess) -> (NetPolicy, Registration) {
        let g = NetPolicy::new(Arc::new(access)).with_host_addrs(Arc::new(Lan));
        let api = g
            .endpoints()
            .register(sa("127.0.0.1:7070"), EndpointKind::Api);
        (g, api)
    }

    fn all_on() -> LocalAccess {
        LocalCategory::ALL
            .into_iter()
            .fold(LocalAccess::NONE, |a, c| a.with_toggle(c, true))
    }

    #[test]
    fn toggle_off_blocks_naming_the_category() {
        let (g, _api) = guard(LocalAccess::NONE);
        for (addr, c) in [
            ("127.0.0.1:80", LocalCategory::Loopback),
            ("10.1.2.3:80", LocalCategory::Private),
            ("169.254.1.1:80", LocalCategory::LinkLocal),
            ("169.254.169.254:80", LocalCategory::Metadata),
            ("224.0.0.1:80", LocalCategory::Special),
        ] {
            assert_eq!(
                g.check_address(&workspace(), sa(addr)),
                AddressVerdict::Block(BlockReason::LocalToggle(c)),
                "{addr}"
            );
        }
        assert_eq!(
            g.check_address(&workspace(), sa("8.8.8.8:80")),
            AddressVerdict::Allow
        );
    }

    #[test]
    fn toggle_on_permits_exact_allows_only_unless_wildcards_reach_local() {
        let (g, _api) = guard(all_on());
        assert_eq!(
            g.check_address(&workspace(), sa("10.1.2.3:80")),
            AddressVerdict::ExactOnly(LocalCategory::Private)
        );
        let (g, _api) = guard(all_on().with_wildcards_reach_local(true));
        assert_eq!(
            g.check_address(&workspace(), sa("10.1.2.3:80")),
            AddressVerdict::Allow
        );
        // The wildcard setting never replaces a toggle.
        let (g, _api) = guard(LocalAccess::NONE.with_wildcards_reach_local(true));
        assert_eq!(
            g.check_address(&workspace(), sa("10.1.2.3:80")),
            AddressVerdict::Block(BlockReason::LocalToggle(LocalCategory::Private))
        );
    }

    #[test]
    fn puddle_endpoints_are_their_own_class_and_ignore_every_toggle() {
        let (g, _api) = guard(all_on().with_wildcards_reach_local(true));
        for addr in [
            "127.0.0.1:7070",
            "[::1]:7070",
            "192.168.1.10:7070",
            "0.0.0.0:7070",
        ] {
            assert_eq!(
                g.classify(sa(addr)),
                AddressClass::PuddleEndpoint(EndpointKind::Api),
                "{addr}"
            );
            assert_eq!(
                g.check_address(&workspace(), sa(addr)),
                AddressVerdict::Block(BlockReason::PuddleEndpoint),
                "{addr}"
            );
        }
        assert_eq!(
            g.check_address(&workspace(), sa("127.0.0.1:7071")),
            AddressVerdict::Allow
        );
        assert_eq!(
            g.check_address(&workspace(), sa("192.168.1.11:7070")),
            AddressVerdict::Allow
        );
    }

    #[test]
    fn the_name_stage_blocks_literals_and_category_names_before_the_rules() {
        let target = |h: &str| normalise_host(h).unwrap();
        let (off, _a) = guard(LocalAccess::NONE);
        let check = |g: &NetPolicy, h: &str, port| g.check_target(&workspace(), &target(h), port);
        assert_eq!(
            check(&off, "10.0.0.1", 80),
            Some(BlockReason::LocalToggle(LocalCategory::Private))
        );
        assert_eq!(
            check(&off, "localhost", 80),
            Some(BlockReason::LocalToggle(LocalCategory::Loopback))
        );
        assert_eq!(
            check(&off, "metadata.google.internal", 80),
            Some(BlockReason::LocalToggle(LocalCategory::Metadata))
        );
        assert_eq!(check(&off, "example.com", 80), None);
        assert_eq!(check(&off, "8.8.8.8", 80), None);
        let (on, _b) = guard(all_on());
        // Toggle on: the rules decide (an exact allow or an approval).
        assert_eq!(check(&on, "10.0.0.1", 80), None);
        assert_eq!(check(&on, "localhost", 80), None);
        assert_eq!(check(&on, "metadata", 80), None);
        // puddle's own endpoints, by literal or by `localhost`, whatever the toggles.
        assert_eq!(
            check(&on, "127.0.0.1", 7070),
            Some(BlockReason::PuddleEndpoint)
        );
        assert_eq!(
            check(&on, "localhost", 7070),
            Some(BlockReason::PuddleEndpoint)
        );
        assert_eq!(
            check(&on, "foo.localhost", 7070),
            Some(BlockReason::PuddleEndpoint)
        );
        assert_eq!(check(&on, "metadata", 7070), None);
        assert_eq!(
            check(&off, "localhost", 7070),
            Some(BlockReason::PuddleEndpoint)
        );
    }

    #[test]
    fn toggles_are_read_per_workspace_per_call() {
        let per = |s: &WorkspaceName| {
            LocalAccess::NONE.with_toggle(LocalCategory::Loopback, s.as_str() == "dev")
        };
        let g = NetPolicy::new(Arc::new(per));
        let dev = WorkspaceName::new("dev").unwrap();
        assert_eq!(
            g.check_address(&dev, sa("127.0.0.1:3000")),
            AddressVerdict::ExactOnly(LocalCategory::Loopback)
        );
        assert_eq!(
            g.check_address(&workspace(), sa("127.0.0.1:3000")),
            AddressVerdict::Block(BlockReason::LocalToggle(LocalCategory::Loopback))
        );
        assert!(format!("{g:?}").starts_with("NetPolicy"));
    }

    #[test]
    fn block_messages_name_what_would_change_them() {
        let host = Host::parse_normalised("nas.example").unwrap();
        let one = block_message(
            &host,
            &workspace(),
            &[BlockReason::LocalToggle(LocalCategory::Private)],
        );
        assert_eq!(
            one,
            "nas.example is local/private network, and that toggle is off. To allow it, turn on 'private' (local/private network) globally or for workspace box; it then still needs an allow rule or an approval. Approving it alone does not change this"
        );
        let two = block_message(
            &host,
            &workspace(),
            &[
                BlockReason::LocalToggle(LocalCategory::Private),
                BlockReason::PuddleEndpoint,
                BlockReason::LocalToggle(LocalCategory::Loopback),
                BlockReason::LocalToggle(LocalCategory::Private),
            ],
        );
        assert!(
            two.contains("turn on 'loopback' (host loopback) or 'private' (local/private network)"),
            "{two}"
        );
        assert!(
            block_message(&host, &workspace(), &[BlockReason::PuddleEndpoint])
                .contains("puddle's own endpoints")
        );
        assert!(block_message(&host, &workspace(), &[BlockReason::SshUnsupported]).contains("SSH"));
        assert!(
            block_message(&host, &workspace(), &[BlockReason::LocalAddress])
                .contains("local address")
        );
        assert!(block_message(&host, &workspace(), &[]).contains("local address"));
    }
}
