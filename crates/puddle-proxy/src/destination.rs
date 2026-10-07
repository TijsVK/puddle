// SPDX-License-Identifier: GPL-3.0-or-later
//! Which destinations and resolved addresses the proxy may connect to (R-14), and how names are
//! resolved.
//!
//! The proxy resolves a name only after a rule allowed it (R-10), checks every
//! address it got, and connects only to an address that passed: it never resolves twice, so a
//! DNS answer can't change between the check and the connect. The checks are
//! `puddle-netpolicy`'s [`NetPolicy`]: address classes, the sandbox's local-destination toggles
//! and puddle's own endpoints.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub use puddle_netpolicy::AddressVerdict;
use puddle_netpolicy::{NetPolicy, Target};
use puddle_types::{BlockReason, DomainName, Host, SandboxName};

/// Decides per destination and per resolved address (R-14). [`NetPolicy`] is the product
/// implementation; tests use doubles.
pub trait AddressCheck: Send + Sync {
    /// The name stage, before the rules are asked: `Some(reason)` blocks the request without a
    /// pending row. The default checks an IP literal with [`Self::check`] and lets names through.
    fn check_target(
        &self,
        sandbox: &SandboxName,
        target: &Target,
        port: u16,
    ) -> Option<BlockReason> {
        match target.host() {
            Host::Ip(ip) => match self.check(sandbox, SocketAddr::new(*ip, port)) {
                AddressVerdict::Block(reason) => Some(reason),
                _ => None,
            },
            Host::Name(_) => None,
        }
    }

    /// The verdict for connecting `sandbox` to `addr`.
    fn check(&self, sandbox: &SandboxName, addr: SocketAddr) -> AddressVerdict;
}

impl AddressCheck for NetPolicy {
    fn check_target(
        &self,
        sandbox: &SandboxName,
        target: &Target,
        port: u16,
    ) -> Option<BlockReason> {
        NetPolicy::check_target(self, sandbox, target, port)
    }

    fn check(&self, sandbox: &SandboxName, addr: SocketAddr) -> AddressVerdict {
        self.check_address(sandbox, addr)
    }
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
