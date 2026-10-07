// SPDX-License-Identifier: GPL-3.0-or-later
//! Name lookups from the guest's stub DNS (the `resolve` stream).
//!
//! Clients that ignore proxy settings resolve a name and connect to the answer, which the guest's
//! network rules redirect to the agent. The stub answers every address query with a stand-in
//! address and asks the host first, so the one thing it must learn is whether the name exists.
//! The host decides with the sandbox's rules and never writes a pending row for a lookup: the
//! connect that follows is what produces the deny or pending row.
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
//!   `NODATA`. The leading service labels of an `SRV` name (`_mongodb._tcp.`) are not part of what
//!   the rules match: `_mongodb._tcp.db.example.net` is decided as `db.example.net`.
//!
//! The answer to an address query never contains an address of the host's: only the stand-in the
//! guest allocates itself.

use puddle_agent_proto::resolve::{
    MAX_RECORDS, RecordType, ResolveAnswer, ResolveQuery, StandInReason,
};
use puddle_netpolicy::normalise_host;
use puddle_types::{BlockReason, DomainName, EgressRequest, Host, SandboxName, SuffixAllows};
use std::net::SocketAddr;

use crate::destination::AddressVerdict;
use crate::proxy::{Proxy, SandboxHandler};
use crate::records::{RecordError, valid_fqdn};

/// How long a guest may cache "stand-in" and "the name exists but has nothing of this type".
const POSITIVE_TTL: u32 = 60;
/// How long a guest may cache "no such name".
const NEGATIVE_TTL: u32 = 20;
/// The most leading service labels (`_service._proto.`) set aside before the rules look at a name.
const MAX_SERVICE_LABELS: usize = 3;

impl SandboxHandler {
    /// Answers one lookup of this sandbox's stub DNS.
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
            .check_target(&self.sandbox, &target, 0)
            .is_some()
        {
            return stand_in_or_no_data(query.rtype, StandInReason::Blocked);
        }
        match allowed(proxy, &self.sandbox, &host).await {
            Allowed::No => return stand_in_or_no_data(query.rtype, StandInReason::NotAllowed),
            Allowed::Unreadable => return ResolveAnswer::Unavailable,
            Allowed::Yes => {}
        }
        // Only a name the rules allow gets here: bound how many lookups one sandbox runs at once.
        let Ok(_permit) = self.lookups.try_acquire() else {
            tracing::warn!(sandbox = %self.sandbox, limit = proxy.config().max_lookups_per_sandbox, "too many name lookups at once; answered unavailable");
            return ResolveAnswer::Unavailable;
        };
        match query.rtype {
            RecordType::A => address_answer(proxy, &self.sandbox, &name).await,
            rtype => records_answer(proxy, &query.name, rtype).await,
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
    No,
    Unreadable,
}

/// Whether a rule allows `host` for `sandbox`. Asks without recording anything.
async fn allowed(proxy: &Proxy, sandbox: &SandboxName, host: &Host) -> Allowed {
    let request = EgressRequest::new(sandbox.clone(), host.clone(), 0);
    match proxy.look_up_rule(request, SuffixAllows::Count).await {
        Ok(Some(puddle_types::Decision::Allow { .. })) => Allowed::Yes,
        Ok(_) => Allowed::No,
        Err(err) => {
            tracing::warn!(%sandbox, %host, error = %err, "rules unreadable; name lookup refused");
            Allowed::Unreadable
        }
    }
}

/// The answer to an address query for an allowed name: resolve it here, once.
async fn address_answer(proxy: &Proxy, sandbox: &SandboxName, name: &DomainName) -> ResolveAnswer {
    let lookup = tokio::time::timeout(
        proxy.config().lookup_timeout,
        proxy.resolver().resolve(name, 0),
    )
    .await;
    match lookup {
        Ok(Ok(addrs)) if !addrs.is_empty() => ResolveAnswer::StandIn {
            why: why_for(proxy, sandbox, &addrs),
            ttl: POSITIVE_TTL,
        },
        Ok(Ok(_) | Err(_)) if proxy.company_proxy_may_resolve() => {
            tracing::info!(%sandbox, host = %name, "name not resolved here; the company proxy will resolve it");
            ResolveAnswer::StandIn {
                why: StandInReason::ViaUpstream,
                ttl: POSITIVE_TTL,
            }
        }
        Ok(Ok(_) | Err(_)) => ResolveAnswer::NoSuchName { ttl: NEGATIVE_TTL },
        Err(_) if proxy.company_proxy_may_resolve() => ResolveAnswer::StandIn {
            why: StandInReason::ViaUpstream,
            ttl: POSITIVE_TTL,
        },
        Err(_) => {
            tracing::info!(%sandbox, host = %name, "name lookup timed out");
            ResolveAnswer::Unavailable
        }
    }
}

/// `Blocked` when every address of the name is refused by the address guard (the connect says why),
/// else `Resolves`.
fn why_for(proxy: &Proxy, sandbox: &SandboxName, addrs: &[SocketAddr]) -> StandInReason {
    let all_blocked = addrs.iter().all(|addr| {
        matches!(
            proxy.addresses().check(sandbox, *addr),
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
