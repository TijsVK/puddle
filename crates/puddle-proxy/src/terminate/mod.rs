// SPDX-License-Identifier: GPL-3.0-or-later
//! TLS termination for the hosts a sandbox has a credential for.
//!
//! Almost every connection through the proxy is spliced: the guest and the real server talk TLS
//! to each other and puddle sees only the name. A *bound* host is the exception, so that a
//! credential can be added to the request without ever entering the sandbox. For those hosts, and
//! only those, the proxy is the TLS server the guest sees (with a certificate from the
//! sandbox's own name-constrained CA, `puddle-ca`) and a verifying TLS client to the real server.
//!
//! A connection is terminated only when all of these hold; otherwise it is spliced exactly as
//! before:
//!
//! - the sandbox has a [`Termination`] (a [`TerminationSet`], its CA and an [`Injector`]);
//! - the guest asked for a *name* (an IP literal never matches) in the set;
//! - the port is 443.
//!
//! The rules, the address guard and the IP rules run first and are unchanged: terminating a host
//! never allows it.
//!
//! On a terminated connection:
//!
//! - **Guest leg**: a rustls server offering only `http/1.1`, whose one certificate is the leaf
//!   for the `CONNECT` host. A client that sends another name, an IP address or none gets a TLS
//!   alert and the connection ends with the audit reason `sni_mismatch`; nothing is sent upstream.
//! - **Requests**: read with the strict parser the plain-HTTP path uses, one at a time (a
//!   pipelined request is decided on its own), and rebuilt before they are sent. A request for
//!   another host (`Host`, or an absolute target) is `421`; an ambiguous one is `400`.
//! - **Upstream leg**: one connection per guest connection, never shared, verified against the
//!   platform's roots plus the corporate roots with the host's clock. A certificate that is not
//!   accepted is a `502` that names the reason, and no request byte, and no credential, is sent.
//!   The [`Injector`] is asked only after the connection is verified.
//! - **Responses**: framed by an HTTP client library, then rebuilt for the guest. Redirects are
//!   passed through, never followed.

mod body;
mod guest;
mod inject;
pub(crate) mod request;
mod response;
mod session;
mod set;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use puddle_ca::SandboxCa;
use puddle_types::SandboxName;

pub use inject::{
    HeaderError, InjectContext, InjectDecision, InjectRefusal, InjectedHeader, Injection, Injector,
    NoInjection, RequestView, SecretValue,
};
pub(crate) use session::{Context, run};
pub use set::{PatternError, TerminationSet};

/// Hosts puddle decrypts by default: GitHub and Azure DevOps, for git and Git LFS. Not
/// `api.github.com` (the `gh` CLI and gists would become an exfiltration channel with a
/// credential), nor any package registry.
pub const DEFAULT_TERMINATED_HOSTS: [&str; 3] =
    ["github.com", "dev.azure.com", "*.visualstudio.com"];

/// Why a [`Termination`] could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TerminationError {
    /// The CA's name constraints do not permit a name of the set, so it could never serve it.
    #[error("the certificate authority does not permit {0:?}")]
    NotPermitted(String),
}

/// What terminating one sandbox's bound hosts needs: which hosts, the CA that certifies them for
/// that sandbox alone, and the injector that decides about credentials.
#[derive(Debug)]
pub struct Termination {
    set: TerminationSet,
    ca: Arc<SandboxCa>,
    injector: Arc<dyn Injector>,
}

impl Termination {
    /// Terminates the hosts of `set`, certified by `ca`, with credentials decided by `injector`.
    ///
    /// # Errors
    /// [`TerminationError::NotPermitted`] when the CA's name constraints leave out a name of the
    /// set.
    pub fn new(
        set: TerminationSet,
        ca: Arc<SandboxCa>,
        injector: Arc<dyn Injector>,
    ) -> Result<Self, TerminationError> {
        for name in set.dns_names() {
            if !ca.constraints().permits(&name) {
                return Err(TerminationError::NotPermitted(name));
            }
        }
        Ok(Self { set, ca, injector })
    }

    /// The hosts that are decrypted.
    #[must_use]
    pub fn set(&self) -> &TerminationSet {
        &self.set
    }

    pub(crate) fn ca(&self) -> &Arc<SandboxCa> {
        &self.ca
    }

    pub(crate) fn injector(&self) -> &Arc<dyn Injector> {
        &self.injector
    }
}

/// Where the proxy finds a sandbox's [`Termination`]. Asked once per `CONNECT`; `None` means the
/// sandbox has no credential bound and everything is spliced.
pub trait TerminationSource: Send + Sync + std::fmt::Debug {
    /// The termination of `sandbox`, if it has one.
    fn termination(&self, sandbox: &SandboxName) -> Option<Arc<Termination>>;
}

/// A [`TerminationSource`] the host program updates as sandboxes start, stop and change.
#[derive(Debug, Default)]
pub struct Terminations {
    sandboxes: RwLock<HashMap<SandboxName, Arc<Termination>>>,
}

impl Terminations {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets (or replaces) `sandbox`'s termination. Connections already open keep the old one.
    pub fn insert(&self, sandbox: SandboxName, termination: Termination) {
        self.sandboxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sandbox, Arc::new(termination));
    }

    /// Removes `sandbox`'s termination (its CA is dropped once its connections end).
    pub fn remove(&self, sandbox: &SandboxName) {
        self.sandboxes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(sandbox);
    }
}

impl TerminationSource for Terminations {
    fn termination(&self, sandbox: &SandboxName) -> Option<Arc<Termination>> {
        self.sandboxes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sandbox)
            .cloned()
    }
}
