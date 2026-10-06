// SPDX-License-Identifier: GPL-3.0-or-later
//! Test doubles (feature `testing`). Never use them in product code: [`AnyAddress`] connects
//! anywhere, [`StaticPolicy`] keeps its rules in memory, and [`CollectingConnectionLog`] keeps
//! the audit in memory.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use puddle_types::{
    ConnectionEvent, ConnectionLog, Decision, DomainName, EgressRequest, Host, PatternKind,
    PendingId, PendingOutcome, Policy, PolicyError, RuleId, SandboxName, SuffixAllows,
};

use crate::destination::{AddressCheck, AddressVerdict, BoxFuture, Resolver};

/// A [`Policy`] with exact-host rules in memory: allowed hosts pass, denied hosts are refused, and
/// anything else becomes a pending item (deduplicated per sandbox, host and port) until
/// [`StaticPolicy::approve`] or [`StaticPolicy::deny`] turns it into a rule.
#[derive(Debug, Default)]
pub struct StaticPolicy {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    rules: HashMap<Host, (RuleId, bool, PatternKind)>,
    pending: Vec<PendingItem>,
    next_id: i64,
    decisions: u64,
    unavailable: bool,
}

/// One request that matched no rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingItem {
    /// Its id.
    pub id: PendingId,
    /// The sandbox it came from.
    pub sandbox: SandboxName,
    /// The host asked for.
    pub host: Host,
    /// The port asked for.
    pub port: u16,
    /// How many times it was asked.
    pub attempts: u32,
    /// Whether it is still waiting.
    pub open: bool,
}

impl StaticPolicy {
    /// No rules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, host: &Host, allow: bool, pattern: PatternKind) -> RuleId {
        let mut state = self.state();
        state.next_id += 1;
        let id = RuleId(state.next_id);
        state.rules.insert(host.clone(), (id, allow, pattern));
        for item in &mut state.pending {
            if item.host == *host {
                item.open = false;
            }
        }
        id
    }

    /// Allows `host` (an exact rule).
    pub fn allow(&self, host: &Host) -> RuleId {
        self.add(host, true, PatternKind::Exact)
    }

    /// Allows `host` as if a suffix rule had matched it.
    pub fn allow_as_suffix(&self, host: &Host) -> RuleId {
        self.add(host, true, PatternKind::Suffix)
    }

    /// Denies `host`.
    pub fn deny_host(&self, host: &Host) -> RuleId {
        self.add(host, false, PatternKind::Exact)
    }

    /// Approves pending item `id`: its host is allowed from now on.
    ///
    /// # Errors
    /// An error naming the id when no open item has it.
    pub fn approve(&self, id: PendingId) -> Result<RuleId, String> {
        self.resolve(id, true)
    }

    /// Denies pending item `id`: its host is denied from now on.
    ///
    /// # Errors
    /// An error naming the id when no open item has it.
    pub fn deny(&self, id: PendingId) -> Result<RuleId, String> {
        self.resolve(id, false)
    }

    fn resolve(&self, id: PendingId, allow: bool) -> Result<RuleId, String> {
        let host = self
            .state()
            .pending
            .iter()
            .find(|p| p.id == id && p.open)
            .map(|p| p.host.clone())
            .ok_or_else(|| format!("no open pending item {id}"))?;
        Ok(self.add(&host, allow, PatternKind::Exact))
    }

    /// Every pending item, open or not, oldest first.
    #[must_use]
    pub fn pending(&self) -> Vec<PendingItem> {
        self.state().pending.clone()
    }

    /// How many times [`Policy::decide`] was called.
    #[must_use]
    pub fn decisions(&self) -> u64 {
        self.state().decisions
    }

    /// Makes every later decision fail (or succeed again).
    pub fn set_unavailable(&self, unavailable: bool) {
        self.state().unavailable = unavailable;
    }
}

impl Policy for StaticPolicy {
    fn decide(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Decision, PolicyError> {
        self.state().decisions += 1;
        if let Some(decision) = self.lookup(request, suffix_allows)? {
            return Ok(decision);
        }
        let mut state = self.state();
        let open = state.pending.iter_mut().find(|p| {
            p.open
                && p.sandbox == request.sandbox
                && p.host == request.host
                && p.port == request.port
        });
        if let Some(item) = open {
            item.attempts += 1;
            return Ok(Decision::Pending(PendingOutcome::Repeat(item.id)));
        }
        state.next_id += 1;
        let id = PendingId(state.next_id);
        state.pending.push(PendingItem {
            id,
            sandbox: request.sandbox.clone(),
            host: request.host.clone(),
            port: request.port,
            attempts: 1,
            open: true,
        });
        Ok(Decision::Pending(PendingOutcome::New(id)))
    }

    fn lookup(
        &self,
        request: &EgressRequest,
        suffix_allows: SuffixAllows,
    ) -> Result<Option<Decision>, PolicyError> {
        let state = self.state();
        if state.unavailable {
            return Err(PolicyError {
                reason: "unavailable for this test".into(),
            });
        }
        Ok(match state.rules.get(&request.host) {
            Some(&(rule_id, true, pattern))
                if pattern == PatternKind::Exact || suffix_allows == SuffixAllows::Count =>
            {
                Some(Decision::Allow { rule_id, pattern })
            }
            Some(&(rule_id, false, pattern)) => Some(Decision::Deny { rule_id, pattern }),
            _ => None,
        })
    }
}

/// A [`ConnectionLog`] that keeps every event in memory.
#[derive(Debug, Default)]
pub struct CollectingConnectionLog {
    events: Mutex<Vec<ConnectionEvent>>,
}

impl CollectingConnectionLog {
    /// Nothing recorded yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The events so far, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<ConnectionEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits up to `limit` until at least `count` events are in, and returns them all. A
    /// connection is recorded when it ends, after the guest has its answer.
    pub async fn wait_for(&self, count: usize, limit: Duration) -> Vec<ConnectionEvent> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let events = self.events();
            if events.len() >= count || tokio::time::Instant::now() >= deadline {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

impl ConnectionLog for CollectingConnectionLog {
    fn record(&self, event: &ConnectionEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
    }
}

/// An [`AddressCheck`] that allows every address, so tests can reach servers on loopback.
#[derive(Debug, Clone, Copy, Default)]
pub struct AnyAddress;

impl AddressCheck for AnyAddress {
    fn check_target(
        &self,
        _sandbox: &SandboxName,
        _target: &puddle_netpolicy::Target,
        _port: u16,
    ) -> Option<puddle_types::BlockReason> {
        None
    }

    fn check(&self, _sandbox: &SandboxName, _addr: SocketAddr) -> AddressVerdict {
        AddressVerdict::Allow
    }
}

/// A [`Resolver`] with fixed answers; unknown names fail like NXDOMAIN.
#[derive(Debug, Default)]
pub struct StaticResolver {
    names: Mutex<HashMap<String, Vec<IpAddr>>>,
}

impl StaticResolver {
    /// No names.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `name` resolve to `addrs`.
    #[must_use]
    pub fn with(self, name: &str, addrs: &[IpAddr]) -> Self {
        self.names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), addrs.to_vec());
        self
    }
}

impl Resolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        name: &'a DomainName,
        port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        let found = self
            .names
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name.as_str())
            .cloned();
        Box::pin(async move {
            found
                .map(|ips| {
                    ips.into_iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect()
                })
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
        })
    }
}

/// What Node 24 `fetch` sends through a proxy for a plain `http://` URL (`NODE_USE_ENV_PROXY=1`,
/// `HTTP_PROXY` set): a `CONNECT host:80` tunnel, not an absolute-form request (T-109, T-098).
/// Captured 2026-10-06 from Node v24.18.0 for
/// `fetch("http://node.fixture.test/some/path?q=canary", { method: "POST", body: "hello" })`.
pub mod node_fetch {
    /// The `CONNECT` head.
    pub const CONNECT: &str = "CONNECT node.fixture.test:80 HTTP/1.1\r\nhost: node.fixture.test\r\nconnection: close\r\nproxy-connection: keep-alive\r\n\r\n";
    /// The bytes Node sends inside the tunnel once it is open: the request and its body.
    pub const TUNNELED: &str = "POST /some/path?q=canary HTTP/1.1\r\nhost: node.fixture.test\r\nconnection: keep-alive\r\ncontent-type: text/plain;charset=UTF-8\r\naccept: */*\r\naccept-language: *\r\nsec-fetch-mode: cors\r\nuser-agent: node\r\naccept-encoding: gzip, deflate\r\ncontent-length: 5\r\n\r\nhello";
}
