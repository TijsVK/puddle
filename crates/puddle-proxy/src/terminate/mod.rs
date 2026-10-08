// SPDX-License-Identifier: GPL-3.0-or-later
//! TLS termination for the hosts a workspace has a credential for.
//!
//! Almost every connection through the proxy is spliced: the guest and the real server talk TLS
//! to each other and puddle sees only the name. A *bound* host is the exception, so that a
//! credential can be added to the request without ever entering the workspace. For those hosts, and
//! only those, the proxy is the TLS server the guest sees (with a certificate from the
//! workspace's own name-constrained CA, `puddle-ca`) and a verifying TLS client to the real server.
//!
//! A connection is terminated only when all of these hold; otherwise it is spliced exactly as
//! before:
//!
//! - the workspace has a [`Termination`] (a [`TerminationSet`], its CA and an [`Injector`]);
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
//!   A client that refuses the certificate (it does not trust the workspace's CA) is recorded with
//!   the audit reason `guest_tls_rejected`; the rule's decision stands, since puddle blocked nothing.
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
mod handshake;
mod inject;
pub(crate) mod request;
mod response;
mod session;
mod set;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use puddle_ca::WorkspaceCa;
use puddle_types::WorkspaceName;

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

/// What terminating one workspace's bound hosts needs: which hosts, the CA that certifies them for
/// that workspace alone, and the injector that decides about credentials.
#[derive(Debug)]
pub struct Termination {
    set: TerminationSet,
    ca: Arc<WorkspaceCa>,
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
        ca: Arc<WorkspaceCa>,
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

    pub(crate) fn ca(&self) -> &Arc<WorkspaceCa> {
        &self.ca
    }

    pub(crate) fn injector(&self) -> &Arc<dyn Injector> {
        &self.injector
    }
}

/// Where the proxy finds a workspace's [`Termination`]. Asked once per `CONNECT`; `None` means the
/// workspace has no credential bound and everything is spliced.
pub trait TerminationSource: Send + Sync + std::fmt::Debug {
    /// The termination of `workspace`, if it has one.
    fn termination(&self, workspace: &WorkspaceName) -> Option<Arc<Termination>>;
}

/// A [`TerminationSource`] the host program updates as workspaces start, stop and change.
#[derive(Debug, Default)]
pub struct Terminations {
    workspaces: RwLock<HashMap<WorkspaceName, Arc<Termination>>>,
}

impl Terminations {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets (or replaces) `workspace`'s termination. Connections already open keep the old one.
    pub fn insert(&self, workspace: WorkspaceName, termination: Termination) {
        self.workspaces
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(workspace, Arc::new(termination));
    }

    /// Removes `workspace`'s termination (its CA is dropped once its connections end).
    pub fn remove(&self, workspace: &WorkspaceName) {
        self.workspaces
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(workspace);
    }
}

impl TerminationSource for Terminations {
    fn termination(&self, workspace: &WorkspaceName) -> Option<Arc<Termination>> {
        self.workspaces
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(workspace)
            .cloned()
    }
}
