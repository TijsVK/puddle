// SPDX-License-Identifier: GPL-3.0-or-later
//! Which destinations and resolved addresses the proxy may connect to (R-14), and how names are
//! resolved.
//!
//! The proxy resolves a name only after a rule allowed it (R-10), checks every
//! address it got, and connects only to an address that passed: it never resolves twice, so a
//! DNS answer can't change between the check and the connect. The checks are
//! `puddle-netpolicy`'s [`NetPolicy`]: address classes, the workspace's local-destination toggles
//! and puddle's own endpoints.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

pub use puddle_netpolicy::AddressVerdict;
use puddle_netpolicy::{NetPolicy, Target};
use puddle_types::{BlockReason, DomainName, Host, WorkspaceName};

/// Decides per destination and per resolved address (R-14). [`NetPolicy`] is the product
/// implementation; tests use doubles.
pub trait AddressCheck: Send + Sync {
    /// The name stage, before the rules are asked: `Some(reason)` blocks the request without a
    /// pending row. The default checks an IP literal with [`Self::check`] and lets names through.
    fn check_target(
        &self,
        workspace: &WorkspaceName,
        target: &Target,
        port: u16,
    ) -> Option<BlockReason> {
        match target.host() {
            Host::Ip(ip) => match self.check(workspace, SocketAddr::new(*ip, port)) {
                AddressVerdict::Block(reason) => Some(reason),
                _ => None,
            },
            Host::Name(_) => None,
        }
    }

    /// The verdict for connecting `workspace` to `addr`.
    fn check(&self, workspace: &WorkspaceName, addr: SocketAddr) -> AddressVerdict;
}

impl AddressCheck for NetPolicy {
    fn check_target(
        &self,
        workspace: &WorkspaceName,
        target: &Target,
        port: u16,
    ) -> Option<BlockReason> {
        NetPolicy::check_target(self, workspace, target, port)
    }

    fn check(&self, workspace: &WorkspaceName, addr: SocketAddr) -> AddressVerdict {
        self.check_address(workspace, addr)
    }
}

/// A boxed future, for the object-safe [`Resolver`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a name the rules allowed. Tests fake it; [`SystemResolver`] uses the OS resolver.
pub trait Resolver: Send + Sync {
    /// The addresses of `name`, with `port` filled in.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] when the name does not exist (NXDOMAIN, or no address of the
    /// asked kind); any other error means the lookup itself failed (no resolver answered, the
    /// network is down), which says nothing about the name.
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
            let addrs = tokio::net::lookup_host((name.as_str(), port))
                .await
                .map_err(name_error)?;
            Ok(addrs.collect())
        })
    }
}

/// `err` from `getaddrinfo`, with "the name does not exist" told apart from "the lookup failed":
/// the first becomes [`io::ErrorKind::NotFound`] (the original text kept), the second is passed
/// on. Windows gives the Winsock code. Unix gives only the text of `gai_strerror`, in the
/// process's language, so there a failure is recognised by the English texts that say so, and
/// anything else stays "no such name", as every error was before; a system in another language
/// therefore never has a name that exists refused, and at worst keeps the old answer.
fn name_error(err: io::Error) -> io::Error {
    if lookup_failed(&err) {
        err
    } else {
        tracing::debug!(error = %err, "name lookup error read as no such name");
        io::Error::new(io::ErrorKind::NotFound, err)
    }
}

/// Whether `err` says the lookup itself failed (no resolver answered, the network is down)
/// rather than that the name does not exist.
fn lookup_failed(err: &io::Error) -> bool {
    /// `WSAHOST_NOT_FOUND` and `WSANO_DATA`: the Winsock resolver's own "no such name" answers.
    /// Any other Winsock code (`WSATRY_AGAIN`, `WSANO_RECOVERY`, a network error), and the errno of
    /// `EAI_SYSTEM` on Unix, is a failure.
    const WINSOCK_NO_SUCH_NAME: [i32; 2] = [11001, 11004];
    /// What `gai_strerror` says for `EAI_AGAIN` and `EAI_FAIL` in glibc, musl and the BSDs
    /// (lower case).
    const FAILURE_TEXTS: [&str; 4] = [
        "temporary failure in name resolution",
        "non-recoverable failure in name resolution",
        "try again",
        "system error",
    ];
    if let Some(code) = err.raw_os_error() {
        return !WINSOCK_NO_SUCH_NAME.contains(&code);
    }
    if matches!(
        err.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    ) {
        return true;
    }
    let text = err.to_string().to_ascii_lowercase();
    FAILURE_TEXTS.iter().any(|known| text.contains(known))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_does_not_exist_is_told_apart_from_a_lookup_that_failed() {
        let gai =
            |text: &str| io::Error::other(format!("failed to lookup address information: {text}"));
        for missing in [
            gai("Name or service not known"),
            gai("No address associated with hostname"),
            gai("nodename nor servname provided, or not known"),
            // A system in another language: the text is not recognised, which keeps the answer
            // every error used to get.
            gai("Naam of service onbekend"),
            io::Error::from_raw_os_error(11001),
            io::Error::from_raw_os_error(11004),
        ] {
            let shown = missing.to_string();
            assert_eq!(
                name_error(missing).kind(),
                io::ErrorKind::NotFound,
                "{shown}"
            );
        }
        for failed in [
            gai("Temporary failure in name resolution"),
            gai("Non-recoverable failure in name resolution"),
            gai("Try again"),
            // `EAI_SYSTEM` on Unix, `WSATRY_AGAIN` and `WSAENETDOWN` on Windows.
            io::Error::from_raw_os_error(111),
            io::Error::from_raw_os_error(11002),
            io::Error::from_raw_os_error(10050),
            io::Error::from(io::ErrorKind::TimedOut),
            io::Error::from(io::ErrorKind::NetworkUnreachable),
        ] {
            let shown = failed.to_string();
            assert_ne!(
                name_error(failed).kind(),
                io::ErrorKind::NotFound,
                "{shown}"
            );
        }
        let kept = name_error(gai("Name or service not known")).to_string();
        assert!(kept.contains("Name or service not known"), "{kept}");
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
