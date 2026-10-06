// SPDX-License-Identifier: GPL-3.0-or-later
//! Which resolved addresses the proxy may connect to (R-14), and how names are resolved.
//!
//! The proxy resolves a name only after a rule allowed it (R-10, T-029 EG-8), checks every
//! address it got, and connects only to an address that passed: it never resolves twice, so a
//! DNS answer can't change between the check and the connect.
//!
//! [`PublicOnly`] is the fail-closed default until T-132 brings address classes and the
//! local-destination toggles: every loopback, private, link-local, metadata, multicast or
//! otherwise special address is blocked, including IPv4 addresses embedded in IPv6 (mapped,
//! NAT64, 6to4, Teredo).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;

use puddle_types::{BlockReason, DomainName, SandboxName};

/// What the proxy may do with one resolved address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressVerdict {
    /// Connect if the request is allowed.
    Allow,
    /// A local address whose toggle is on: connect only if an **exact** rule allowed the name
    /// (R-14); after a suffix allow the proxy asks again with `SuffixAllows::Ignore`.
    ExactOnly,
    /// Never connect, whatever the rules say.
    Block(BlockReason),
}

/// Decides per resolved address (R-14). T-132 implements it with address classes and toggles.
pub trait AddressCheck: Send + Sync {
    /// The verdict for `addr` in `sandbox`.
    fn check(&self, sandbox: &SandboxName, addr: IpAddr) -> AddressVerdict;
}

/// Allows public unicast addresses only; blocks everything else with
/// [`BlockReason::LocalAddress`]. Conservative: an address it doesn't recognise as public is
/// blocked.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicOnly;

impl AddressCheck for PublicOnly {
    fn check(&self, _sandbox: &SandboxName, addr: IpAddr) -> AddressVerdict {
        if is_public(addr) {
            AddressVerdict::Allow
        } else {
            AddressVerdict::Block(BlockReason::LocalAddress)
        }
    }
}

/// Whether `addr` is a public unicast address.
#[must_use]
pub fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => is_public_v4(a),
        IpAddr::V6(a) => is_public_v6(a),
    }
}

fn in4(a: Ipv4Addr, net: u32, bits: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
    a.to_bits() & mask == net & mask
}

fn in6(a: Ipv6Addr, net: u128, bits: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    a.to_bits() & mask == net & mask
}

/// The low 32 bits of an IPv6 address as IPv4.
fn low_v4(a: Ipv6Addr) -> Ipv4Addr {
    Ipv4Addr::from_bits(u32::try_from(a.to_bits() & u128::from(u32::MAX)).unwrap_or(0))
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    !(a.is_unspecified()
        || in4(a, 0, 8) // "this network"
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local() // includes 169.254.169.254 (metadata)
        || in4(a, 0x6440_0000, 10) // CGNAT 100.64/10
        || in4(a, 0xC000_0000, 24) // IETF protocol assignments 192.0.0/24
        || in4(a, 0xC058_6300, 24) // 6to4 relay anycast
        || in4(a, 0xC612_0000, 15) // benchmarking 198.18/15
        || a.is_documentation()
        || a.is_multicast()
        || a.is_broadcast()
        || a.octets()[0] >= 240 // reserved
        || a == Ipv4Addr::new(168, 63, 129, 16)) // Azure wire server (metadata)
}

fn is_public_v6(a: Ipv6Addr) -> bool {
    // Not `to_ipv4()`: that also maps ::1 to 0.0.0.1.
    if let Some(v4) = a.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    if in6(a, 0x0064_ff9b << 96, 96) {
        return is_public_v4(low_v4(a)); // NAT64 well-known prefix
    }
    if in6(a, 0x2002 << 112, 16) || in6(a, 0x2001_0000 << 96, 32) {
        return false; // 6to4 and Teredo need relays a sandbox has no reason to use
    }
    // Global unicast is 2000::/3; everything outside it (loopback, unspecified, ULA, link-local,
    // multicast, IPv4-compatible, fec0::/10, 64:ff9b:1::/48 ...) is not public.
    in6(a, 0x2000 << 112, 3)
        && !in6(a, 0x2001 << 112, 23) // IETF protocol assignments
        && !in6(a, 0x2001_0db8 << 96, 32) // documentation
        && !in6(a, 0x3fff << 112, 20) // documentation (RFC 9637)
        && a != Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254) // AWS metadata (ULA anyway)
}

/// A boxed future, for the object-safe [`Resolver`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a name the rules allowed. Tests fake it; [`SystemResolver`] uses the OS resolver.
pub trait Resolver: Send + Sync {
    /// The addresses of `name`, with `port` filled in.
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>>;
}

/// The OS resolver (`getaddrinfo` on a blocking thread, through tokio).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((name.as_str(), port)).await?;
            Ok(addrs.collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_pass() {
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "140.82.121.4",
            "100.63.255.255",
            "100.128.0.0",
            "2606:4700::1111",
            "2a00:1450:4001:80b::200e",
            "64:ff9b::808:808",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip(a)), "{a}");
        }
    }

    #[test]
    fn local_and_special_addresses_are_blocked() {
        for a in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "169.254.1.1",
            "168.63.129.16",
            "100.64.0.1",
            "192.0.0.1",
            "192.88.99.1",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fd00::1",
            "fd00:ec2::254",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "::127.0.0.1",
            "2002:7f00:1::1",
            "2002:808:808::1",
            "2001::1",
            "2001:db8::1",
            "3fff::1",
            "fec0::1",
            "100::1",
        ] {
            assert!(!is_public(ip(a)), "{a}");
        }
    }

    #[test]
    fn public_only_blocks_with_local_address() {
        let sandbox = SandboxName::new("box").unwrap();
        assert_eq!(
            PublicOnly.check(&sandbox, ip("1.1.1.1")),
            AddressVerdict::Allow
        );
        assert_eq!(
            PublicOnly.check(&sandbox, ip("127.0.0.1")),
            AddressVerdict::Block(BlockReason::LocalAddress)
        );
    }

    #[tokio::test]
    async fn the_system_resolver_resolves_localhost() {
        let name = DomainName::parse_normalised("localhost").unwrap();
        let addrs = SystemResolver.resolve(&name, 8080).await.unwrap();
        assert_ne!(addrs.len(), 0);
        assert!(
            addrs
                .iter()
                .all(|a| a.port() == 8080 && a.ip().is_loopback())
        );
    }
}
