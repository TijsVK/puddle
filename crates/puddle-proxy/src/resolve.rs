// SPDX-License-Identifier: GPL-3.0-or-later
//! Name lookups from the guest's stub DNS (the `resolve` stream).
//!
//! Clients that ignore proxy settings resolve a name and connect to the answer, which the guest's
//! network rules redirect to the agent. The stub answers every address query with a stand-in
//! address and asks the host first, so the one thing it must learn is whether the name exists.
//! The host decides with the workspace's rules. An address lookup never writes a pending row: the
//! connect that follows is what produces the deny or pending row. The one exception is `SRV` (below).
//!
//! - **Not allowed** (no rule, or a deny): a stand-in with **no lookup at all**. DNS carries nothing
//!   out, and a guest asking for a million random names causes no resolver traffic.
//! - **Blocked by itself** (a toggle that is off, one of puddle's endpoints): a stand-in too; the
//!   connect says which toggle would allow it.
//! - **Allowed**: the name is resolved once here. An answer means a stand-in; "no such name" means
//!   `NXDOMAIN`, unless the company proxy is in the route and may resolve it where the host can't
//!   (some networks resolve internet names only at the proxy): then a stand-in, and the proxy
//!   decides when the connect arrives.
//! - **`SRV`, `TXT`, `MX`** are looked up for allowed names only; for any other name the answer is
//!   `NODATA`. An `SRV` query for a name **no rule matches** also raises one pending request for
//!   the base name (deduplicated like any other), because a client that starts with `SRV`
//!   (`mongodb+srv://`) would otherwise fail without the user ever seeing it. A denied name raises
//!   nothing, and neither do `TXT` and `MX`. The leading service labels of an `SRV` name (`_mongodb._tcp.`) are not part of what
//!   the rules match: `_mongodb._tcp.db.example.net` is decided as `db.example.net`.
//!
//! The answer to an address query never contains an address of the host's: only the stand-in the
//! guest allocates itself.

use puddle_agent_proto::resolve::{
    MAX_RECORDS, RecordType, ResolveAnswer, ResolveQuery, StandInReason,
};
use puddle_netpolicy::normalise_host;
use puddle_types::{BlockReason, DomainName, EgressRequest, Host, SuffixAllows, WorkspaceName};
use std::net::SocketAddr;

use crate::destination::AddressVerdict;
use crate::proxy::{Proxy, WorkspaceHandler};
use crate::records::{RecordError, valid_fqdn};

/// How long a guest may cache "stand-in" and "the name exists but has nothing of this type".
const POSITIVE_TTL: u32 = 60;
/// How long a guest may cache "no such name".
const NEGATIVE_TTL: u32 = 20;
/// The most leading service labels (`_service._proto.`) set aside before the rules look at a name.
const MAX_SERVICE_LABELS: usize = 3;

impl WorkspaceHandler {
    /// Answers one lookup of this workspace's stub DNS.
    pub(crate) async fn resolve_name(&self, query: ResolveQuery) -> ResolveAnswer {
        let proxy = &self.proxy;
        if !valid_fqdn(&query.name) {
            return ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL };
        }
        let (service, base) = split_service_labels(&query.name);
        let name = match normalise_host(base).map(puddle_netpolicy::Target::into_host) {
            Ok(Host::Name(name)) if service.is_empty() || query.rtype != RecordType::A => name,
            // An address literal, an invalid name, or an address query for a service name: not a
            // name any client connects to.
            _ => return ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL },
        };
        let host = Host::Name(name.clone());
        // A blocked name is not looked up either: it gets the stand-in, and the connect says why.
        let target = puddle_netpolicy::Target::from_host(host.clone());
        if proxy
            .addresses()
            .check_target(&self.workspace, &target, 0)
            .is_some()
        {
            return stand_in_or_no_data(query.rtype, StandInReason::Blocked);
        }
        match allowed(proxy, &self.workspace, &host).await {
            Allowed::No => return stand_in_or_no_data(query.rtype, StandInReason::NotAllowed),
            Allowed::Unmatched => {
                if query.rtype != RecordType::Srv {
                    return stand_in_or_no_data(query.rtype, StandInReason::NotAllowed);
                }
                return self.request_for_srv(host).await;
            }
            Allowed::Unreadable => return ResolveAnswer::Unavailable,
            Allowed::Yes => {}
        }
        // Only a name the rules allow gets here: bound how many lookups one workspace runs at once.
        let Ok(_permit) = self.lookups.try_acquire() else {
            tracing::warn!(workspace = %self.workspace, limit = proxy.config().max_lookups_per_workspace, "too many name lookups at once; answered unavailable");
            return ResolveAnswer::Unavailable;
        };
        match query.rtype {
            RecordType::A => address_answer(proxy, &self.workspace, &name).await,
            rtype => records_answer(proxy, &query.name, rtype).await,
        }
    }
}

impl WorkspaceHandler {
    /// Raises the pending request an `SRV` query for an unmatched name stands for, and answers
    /// `NODATA` (the user has not decided yet). The port is unknown at this point, so it is 0.
    async fn request_for_srv(&self, host: Host) -> ResolveAnswer {
        let request = EgressRequest::new(self.workspace.clone(), host, 0);
        match self.proxy.decide(&request, SuffixAllows::Count).await {
            Ok(_) => ResolveAnswer::NoData { ttl: NEGATIVE_TTL },
            Err(err) => {
                tracing::warn!(workspace = %self.workspace, error = %err, "rules unreadable; name lookup refused");
                ResolveAnswer::Unavailable
            }
        }
    }
}

/// A stand-in for an address query; `NODATA` for a record query (nothing is looked up, and a
/// service record is never invented).
fn stand_in_or_no_data(rtype: RecordType, why: StandInReason) -> ResolveAnswer {
    if rtype == RecordType::A {
        ResolveAnswer::StandIn {
            why,
            ttl: POSITIVE_TTL,
        }
    } else {
        ResolveAnswer::NoData { ttl: POSITIVE_TTL }
    }
}

/// `(service labels, the name the rules decide)`: the leading `_x` labels set aside.
fn split_service_labels(name: &str) -> (Vec<&str>, &str) {
    let mut rest = name;
    let mut service = Vec::new();
    while service.len() < MAX_SERVICE_LABELS
        && let Some((label, tail)) = rest.split_once('.')
        && label.starts_with('_')
    {
        service.push(label);
        rest = tail;
    }
    (service, rest)
}

enum Allowed {
    Yes,
    /// A deny rule matches.
    No,
    /// No rule matches.
    Unmatched,
    Unreadable,
}

/// Whether a rule allows `host` for `workspace`. Asks without recording anything.
async fn allowed(proxy: &Proxy, workspace: &WorkspaceName, host: &Host) -> Allowed {
    let request = EgressRequest::new(workspace.clone(), host.clone(), 0);
    match proxy.look_up_rule(request, SuffixAllows::Count).await {
        Ok(Some(decision)) if decision.is_allow() => Allowed::Yes,
        Ok(Some(_)) => Allowed::No,
        Ok(None) => Allowed::Unmatched,
        Err(err) => {
            tracing::warn!(%workspace, %host, error = %err, "rules unreadable; name lookup refused");
            Allowed::Unreadable
        }
    }
}

/// The answer to an address query for an allowed name: resolve it here, once.
async fn address_answer(
    proxy: &Proxy,
    workspace: &WorkspaceName,
    name: &DomainName,
) -> ResolveAnswer {
    let lookup = tokio::time::timeout(
        proxy.config().lookup_timeout,
        proxy.resolver().resolve(name, 0),
    )
    .await;
    match lookup {
        Ok(Ok(addrs)) if !addrs.is_empty() => ResolveAnswer::StandIn {
            why: why_for(proxy, workspace, &addrs),
            ttl: POSITIVE_TTL,
        },
        Ok(Ok(_) | Err(_)) if proxy.company_proxy_may_resolve() => {
            tracing::info!(%workspace, host = %name, "name not resolved here; the company proxy will resolve it");
            ResolveAnswer::StandIn {
                why: StandInReason::ViaUpstream,
                ttl: POSITIVE_TTL,
            }
        }
        Ok(Ok(_)) => ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL },
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL }
        }
        // The lookup failed; that says nothing about the name, so the guest must not cache
        // "no such name" for it.
        Ok(Err(err)) => {
            tracing::warn!(%workspace, host = %name, error = %err, "name lookup failed; answered unavailable");
            ResolveAnswer::Unavailable
        }
        Err(_) if proxy.company_proxy_may_resolve() => ResolveAnswer::StandIn {
            why: StandInReason::ViaUpstream,
            ttl: POSITIVE_TTL,
        },
        Err(_) => {
            tracing::info!(%workspace, host = %name, "name lookup timed out");
            ResolveAnswer::Unavailable
        }
    }
}

/// `Blocked` when every address of the name is refused by the address guard (the connect says why),
/// else `Resolves`.
fn why_for(proxy: &Proxy, workspace: &WorkspaceName, addrs: &[SocketAddr]) -> StandInReason {
    let all_blocked = addrs.iter().all(|addr| {
        matches!(
            proxy.addresses().check(workspace, *addr),
            AddressVerdict::Block(reason) if !matches!(reason, BlockReason::SshUnsupported)
        )
    });
    if all_blocked {
        StandInReason::Blocked
    } else {
        StandInReason::Resolves
    }
}

/// The answer to a record query for an allowed name.
async fn records_answer(proxy: &Proxy, fqdn: &str, rtype: RecordType) -> ResolveAnswer {
    let found = tokio::time::timeout(
        proxy.config().lookup_timeout,
        proxy.record_resolver().records(fqdn, rtype),
    )
    .await;
    match found {
        Ok(Ok(found)) => {
            let mut records = found.records;
            records.truncate(MAX_RECORDS);
            ResolveAnswer::Records {
                records,
                ttl: u32::try_from(found.ttl.as_secs()).unwrap_or(POSITIVE_TTL),
            }
        }
        Ok(Err(RecordError::NoSuchName)) => ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL },
        Ok(Err(RecordError::NoData)) => ResolveAnswer::NoData { ttl: NEGATIVE_TTL },
        Ok(Err(RecordError::Failed(why))) => {
            tracing::info!(host = %fqdn, error = %why, "record lookup failed");
            ResolveAnswer::Unavailable
        }
        Err(_) => ResolveAnswer::Unavailable,
    }
}

#[cfg(test)]
mod tests;
