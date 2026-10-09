// SPDX-License-Identifier: GPL-3.0-or-later
//! TLS termination for the hosts a workspace has a credential for.
//!
//! Almost every connection through the proxy is spliced: the guest and the real server talk TLS
//! to each other and puddle sees only the name. A *bound* host is the exception, so that a
//! credential can be added to the request without ever entering the workspace. For those hosts, and
//! only those, the proxy is the TLS server the guest sees (with a certificate from the
//! workspace's own CA, `puddle-ca`) and a verifying TLS client to the real server.
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
//! - **Order**: the guest's `ClientHello` is read first and its name checked; a client that sends
//!   another name, an IP address or none gets a TLS alert and the connection ends with the audit
//!   reason `sni_mismatch`, and nothing is sent upstream. Then the real server is connected to,
//!   offering the protocols the guest offered (`h2`, `http/1.1`), and the guest is offered what the
//!   server chose. A server that cannot be used (a certificate that is not accepted) does not stop
//!   the guest's handshake: the first request is answered with the reason.
//! - **Guest leg**: a rustls server whose one certificate is the leaf for the `CONNECT` host.
//!   HTTP/1.1 is read with the strict parser the plain-HTTP path uses, one request at a time (a
//!   pipelined request is decided on its own) and rebuilt before it is sent. HTTP/2 is served by
//!   hyper, one request per stream, with the same checks (`Host`/`:authority`, target, framing)
//!   and limits of its own (streams, header list, resets, header-read time).
//!   A client that refuses the certificate (it does not trust the workspace's CA) is recorded with
//!   the audit reason `guest_tls_rejected`; the rule's decision stands, since puddle blocked nothing.
//! - **Requests**: a request for another host (`Host`, `:authority` or an absolute target) is
//!   `421`; an ambiguous one is `400`. The [`Injector`] is asked the same way on both versions.
//! - **Upstream leg**: one connection per guest connection, never shared, verified against the
//!   platform's roots plus the corporate roots with the host's clock. A certificate that is not
//!   accepted is a `502` that names the reason, and no request byte, and no credential, is sent.
//!   The [`Injector`] is asked only after the connection is verified. HTTP/2 to the server carries
//!   every stream of an HTTP/2 guest; an HTTP/2 guest talking to an HTTP/1.1 server uses a small
//!   pool of HTTP/1.1 connections owned by that guest connection.
//! - **Stand-ins**: after the injector has decided, the workspace's [`StandIns`] are swapped for
//!   their real values in the header values of the request, toward the hosts each is for, on both
//!   HTTP versions.
//! - **Responses**: framed by an HTTP client library, then rebuilt for the guest, trailers
//!   included. Redirects are passed through, never followed. A `401` is replaced by the
//!   injector's own refusal when the injector added the request's credential ([`Unauthorized`]);
//!   otherwise it is the server's answer like any other. The HTTP/3 entries of `Alt-Svc` are
//!   removed on both HTTP versions: a workspace has no UDP path, so a client would only try
//!   HTTP/3 and fail.
//! - **WebSocket**: HTTP/1.1 `Upgrade` and HTTP/2 extended `CONNECT` (RFC 8441) are checked and
//!   injected like any request; once the server agrees, the two connections are a byte pipe.

mod alt_svc;
mod body;
mod guest;
mod h2;
mod handshake;
mod inject;
mod leg;
pub(crate) mod request;
mod response;
mod session;
mod set;
mod stand_in;
mod watch;
mod ws;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use puddle_ca::WorkspaceCa;
use puddle_types::WorkspaceName;

pub use inject::{
    HeaderError, InjectContext, InjectDecision, InjectRefusal, InjectedHeader, Injection, Injector,
    NoInjection, RequestView, SecretValue, Unauthorized,
};
pub(crate) use session::{Context, run};
pub use set::{PatternError, TerminationSet};
pub use stand_in::{StandIn, StandInError, StandInOrigin, StandIns, secret_stand_in};

/// Hosts puddle decrypts by default: GitHub and Azure DevOps, for git and Git LFS. Not
/// `api.github.com` (the `gh` CLI and gists would become an exfiltration channel with a
/// credential), nor any package registry.
pub const DEFAULT_TERMINATED_HOSTS: [&str; 3] =
    ["github.com", "dev.azure.com", "*.visualstudio.com"];

/// What terminating one workspace's bound hosts needs: which hosts, the CA that certifies them for
/// that workspace alone, and the injector that decides about credentials.
#[derive(Debug)]
pub struct Termination {
    set: TerminationSet,
    ca: Arc<WorkspaceCa>,
    injector: Arc<dyn Injector>,
    stand_ins: Arc<StandIns>,
}

impl Termination {
    /// Terminates the hosts of `set`, certified by `ca`, with credentials decided by `injector`.
    ///
    /// The CA has no name constraint, so `set` is the only limit on which hosts get a leaf from
    /// it; to change the set while a workspace runs, make a new `Termination` with the same CA
    /// and [`Terminations::insert`] it (connections already open keep the old set; the next one
    /// sees the new).
    #[must_use]
    pub fn new(set: TerminationSet, ca: Arc<WorkspaceCa>, injector: Arc<dyn Injector>) -> Self {
        Self {
            set,
            ca,
            injector,
            stand_ins: Arc::new(StandIns::new()),
        }
    }

    /// Swaps the workspace's `stand_ins` for their real values on terminated requests (see
    /// [`StandIns`]). The registry stays the caller's to change while requests are served. Its
    /// hosts ([`StandIns::hosts`]) must be among the hosts this termination decrypts, or a
    /// connection to them is spliced and nothing is swapped.
    #[must_use]
    pub fn with_stand_ins(mut self, stand_ins: Arc<StandIns>) -> Self {
        self.stand_ins = stand_ins;
        self
    }

    /// The hosts that are decrypted.
    #[must_use]
    pub fn set(&self) -> &TerminationSet {
        &self.set
    }

    /// The CA that certifies every host of the set, for this workspace alone.
    #[must_use]
    pub fn ca(&self) -> &Arc<WorkspaceCa> {
        &self.ca
    }

    pub(crate) fn injector(&self) -> &Arc<dyn Injector> {
        &self.injector
    }

    /// The workspace's stand-ins, as [`Self::with_stand_ins`] was given them.
    #[must_use]
    pub fn stand_ins(&self) -> &Arc<StandIns> {
        &self.stand_ins
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
