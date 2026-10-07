// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's answers to the stub DNS, without an agent: the handler is called directly. The path
//! through a real agent and route is in `puddle-e2e`.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use puddle_agent_proto::resolve::{Record, RecordType, ResolveAnswer, ResolveQuery, StandInReason};
use puddle_netpolicy::{LocalAccess, NetPolicy};
use puddle_types::{
    Decision, DomainName, EgressRequest, Host, NullSink, PatternKind, Policy, PolicyError, RuleId,
    SandboxName, SuffixAllows,
};
use puddle_upstream::{
    Chain, Config, Discovery, FakeOs, Hop, NoAuth, ProxyAddr, ProxyConfig as OsProxyConfig,
};

use crate::destination::{BoxFuture, Resolver};
use crate::testing::{AnyAddress, StaticPolicy, StaticRecords, StaticResolver};
use crate::{Proxy, ProxyConfig, SandboxHandler, Upstream};

fn sandbox() -> SandboxName {
    SandboxName::new("box").unwrap()
}

fn host(h: &str) -> Host {
    Host::parse_normalised(h).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn a(name: &str) -> ResolveQuery {
    ResolveQuery::new(name, RecordType::A)
}

fn company_proxy(resolve_unknown_names: bool) -> Upstream {
    let os = FakeOs::new(OsProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..OsProxyConfig::default()
    });
    os.set_pac(|_| Ok(vec![Hop::Proxy(ProxyAddr::new("127.0.0.1", 1))]));
    Upstream::new(Chain::new(
        Discovery::new(os, Config::default()),
        Arc::new(NoAuth),
    ))
    .with_resolve_via_upstream(resolve_unknown_names)
}

struct Rig {
    policy: Arc<StaticPolicy>,
    resolver: Arc<StaticResolver>,
    records: Arc<StaticRecords>,
    handler: SandboxHandler,
}

fn rig_with(
    resolver: StaticResolver,
    records: StaticRecords,
    build: impl FnOnce(Proxy) -> Proxy,
) -> Rig {
    let policy = Arc::new(StaticPolicy::new());
    let resolver = Arc::new(resolver);
    let records = Arc::new(records);
    let proxy = Proxy::new(policy.clone(), Arc::new(NullSink))
        .with_resolver(resolver.clone())
        .with_record_resolver(records.clone())
        .with_address_check(Arc::new(AnyAddress));
    let proxy = Arc::new(build(proxy));
    Rig {
        policy,
        resolver,
        records,
        handler: proxy.handler(sandbox()),
    }
}

fn rig(resolver: StaticResolver) -> Rig {
    rig_with(resolver, StaticRecords::new(), |p| p)
}

fn stand_in(why: StandInReason) -> ResolveAnswer {
    ResolveAnswer::StandIn { why, ttl: 60 }
}

#[tokio::test]
async fn an_allowed_name_that_resolves_gets_a_stand_in_after_one_lookup() {
    let r = rig(StaticResolver::new().with("example.com", &[ip("93.184.215.14")]));
    r.policy.allow(&host("example.com"));
    assert_eq!(
        r.handler.resolve_name(a("example.com")).await,
        stand_in(StandInReason::Resolves)
    );
    assert_eq!(r.resolver.lookups(), 1);
}

#[tokio::test]
async fn a_wildcard_allow_counts() {
    let r = rig(StaticResolver::new().with("api.example.com", &[ip("93.184.215.14")]));
    r.policy.allow_as_suffix(&host("api.example.com"));
    assert_eq!(
        r.handler.resolve_name(a("api.example.com")).await,
        stand_in(StandInReason::Resolves)
    );
}

#[tokio::test]
async fn an_allowed_name_the_host_cannot_resolve_is_nxdomain_on_a_direct_route() {
    let r = rig(StaticResolver::new());
    r.policy.allow(&host("gone.example"));
    assert_eq!(
        r.handler.resolve_name(a("gone.example")).await,
        ResolveAnswer::NoSuchName { ttl: 20 }
    );
}

#[tokio::test]
async fn an_allowed_name_the_host_cannot_resolve_goes_to_the_company_proxy_when_one_is_in_the_route()
 {
    let r = rig_with(StaticResolver::new(), StaticRecords::new(), |p| {
        p.with_upstream(company_proxy(true))
    });
    r.policy.allow(&host("only-at-the-proxy.example"));
    assert_eq!(
        r.handler.resolve_name(a("only-at-the-proxy.example")).await,
        stand_in(StandInReason::ViaUpstream)
    );
}

#[tokio::test]
async fn with_resolving_at_the_proxy_off_an_unresolvable_name_is_nxdomain_even_behind_a_proxy() {
    let r = rig_with(StaticResolver::new(), StaticRecords::new(), |p| {
        p.with_upstream(company_proxy(false))
    });
    r.policy.allow(&host("only-at-the-proxy.example"));
    assert_eq!(
        r.handler.resolve_name(a("only-at-the-proxy.example")).await,
        ResolveAnswer::NoSuchName { ttl: 20 }
    );
}

#[tokio::test]
async fn a_name_nothing_allows_gets_a_stand_in_with_no_lookup_and_no_pending_row() {
    let r = rig(StaticResolver::new().with("secret.example", &[ip("93.184.215.14")]));
    r.policy.deny_host(&host("denied.example"));
    for name in ["secret.example", "denied.example", "leak-x7f3q.example.net"] {
        assert_eq!(
            r.handler.resolve_name(a(name)).await,
            stand_in(StandInReason::NotAllowed),
            "{name}"
        );
    }
    assert_eq!(r.resolver.lookups(), 0);
    assert_eq!(
        r.policy.decisions(),
        0,
        "a lookup never asks for a decision"
    );
    assert_eq!(r.policy.pending(), vec![]);
}

#[tokio::test]
async fn a_name_nothing_allows_has_no_records_and_no_lookup_for_every_type() {
    let r = rig_with(
        StaticResolver::new(),
        StaticRecords::new().with("x.example", RecordType::Txt, vec![]),
        |p| p,
    );
    for rtype in [RecordType::Srv, RecordType::Txt, RecordType::Mx] {
        assert_eq!(
            r.handler
                .resolve_name(ResolveQuery::new("x.example", rtype))
                .await,
            ResolveAnswer::NoData { ttl: 60 }
        );
    }
    assert_eq!(r.records.lookups(), 0);
}

#[tokio::test]
async fn a_name_blocked_by_itself_gets_a_stand_in_with_no_lookup() {
    let r = rig_with(StaticResolver::new(), StaticRecords::new(), |p| {
        p.with_address_check(Arc::new(NetPolicy::new(Arc::new(LocalAccess::NONE))))
    });
    r.policy.allow(&host("localhost"));
    assert_eq!(
        r.handler.resolve_name(a("localhost")).await,
        stand_in(StandInReason::Blocked)
    );
    assert_eq!(r.resolver.lookups(), 0);
}

#[tokio::test]
async fn a_name_whose_every_address_is_blocked_still_gets_a_stand_in_and_the_connect_says_why() {
    let r = rig_with(
        StaticResolver::new().with("intranet.example", &[ip("10.1.2.3"), ip("127.0.0.1")]),
        StaticRecords::new(),
        |p| p.with_address_check(Arc::new(NetPolicy::new(Arc::new(LocalAccess::NONE)))),
    );
    r.policy.allow(&host("intranet.example"));
    assert_eq!(
        r.handler.resolve_name(a("intranet.example")).await,
        stand_in(StandInReason::Blocked)
    );
}

#[tokio::test]
async fn a_name_with_one_public_address_is_an_ordinary_stand_in() {
    let r = rig_with(
        StaticResolver::new().with("mixed.example", &[ip("10.1.2.3"), ip("93.184.215.14")]),
        StaticRecords::new(),
        |p| p.with_address_check(Arc::new(NetPolicy::new(Arc::new(LocalAccess::NONE)))),
    );
    r.policy.allow(&host("mixed.example"));
    assert_eq!(
        r.handler.resolve_name(a("mixed.example")).await,
        stand_in(StandInReason::Resolves)
    );
}

#[tokio::test]
async fn names_that_are_not_host_names_are_nxdomain_without_a_lookup() {
    let r = rig(StaticResolver::new());
    for name in [
        "",
        "1.2.3.4",
        "esc\u{1b}[2K.example",
        "a b.example",
        "bücher.example",
        "a..b",
        &"a".repeat(300),
        "_dmarc.example.com", // an address query for a service name
    ] {
        assert_eq!(
            r.handler.resolve_name(a(name)).await,
            ResolveAnswer::NoSuchName { ttl: 20 },
            "{name:?}"
        );
    }
    assert_eq!(r.resolver.lookups(), 0);
    assert_eq!(r.policy.decisions(), 0);
}

#[tokio::test]
async fn srv_records_come_back_for_an_allowed_name_decided_without_its_service_labels() {
    let srv = vec![Record::Srv {
        priority: 0,
        weight: 5,
        port: 27017,
        target: "shard0.db.example.net".into(),
    }];
    let r = rig_with(
        StaticResolver::new(),
        StaticRecords::new().with("_mongodb._tcp.db.example.net", RecordType::Srv, srv.clone()),
        |p| p,
    );
    // The rule is for the cluster's name, not for the service name.
    r.policy.allow(&host("db.example.net"));
    assert_eq!(
        r.handler
            .resolve_name(ResolveQuery::new(
                "_mongodb._tcp.db.example.net",
                RecordType::Srv
            ))
            .await,
        ResolveAnswer::Records {
            records: srv,
            ttl: 30
        }
    );
    assert_eq!(
        r.resolver.lookups(),
        0,
        "no address lookup for a record query"
    );
}

#[tokio::test]
async fn txt_and_mx_are_forwarded_and_missing_ones_are_nodata_or_nxdomain() {
    let txt = vec![Record::Txt {
        strings: vec!["authSource=admin".into()],
    }];
    let r = rig_with(
        StaticResolver::new(),
        StaticRecords::new()
            .with("db.example.net", RecordType::Txt, txt.clone())
            .with("db.example.net", RecordType::Mx, vec![]),
        |p| p,
    );
    r.policy.allow(&host("db.example.net"));
    r.policy.allow(&host("nowhere.example.net"));
    assert_eq!(
        r.handler
            .resolve_name(ResolveQuery::new("db.example.net", RecordType::Txt))
            .await,
        ResolveAnswer::Records {
            records: txt,
            ttl: 30
        }
    );
    assert_eq!(
        r.handler
            .resolve_name(ResolveQuery::new("db.example.net", RecordType::Srv))
            .await,
        ResolveAnswer::NoData { ttl: 20 }
    );
    assert_eq!(
        r.handler
            .resolve_name(ResolveQuery::new("nowhere.example.net", RecordType::Txt))
            .await,
        ResolveAnswer::NoSuchName { ttl: 20 }
    );
}

#[tokio::test]
async fn unreadable_rules_make_the_lookup_unavailable_not_allowed() {
    let r = rig(StaticResolver::new().with("example.com", &[ip("93.184.215.14")]));
    r.policy.allow(&host("example.com"));
    r.policy.set_unavailable(true);
    assert_eq!(
        r.handler.resolve_name(a("example.com")).await,
        ResolveAnswer::Unavailable
    );
    assert_eq!(r.resolver.lookups(), 0);
}

/// A resolver that never answers, and counts how many lookups started.
#[derive(Default)]
struct Stuck {
    started: AtomicU64,
}

impl Resolver for Stuck {
    fn resolve<'a>(
        &'a self,
        _name: &'a DomainName,
        _port: u16,
    ) -> BoxFuture<'a, io::Result<Vec<std::net::SocketAddr>>> {
        self.started.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}

fn stuck_rig(
    config: ProxyConfig,
    upstream: Option<Upstream>,
) -> (Arc<StaticPolicy>, Arc<Stuck>, SandboxHandler) {
    let policy = Arc::new(StaticPolicy::new());
    let stuck = Arc::new(Stuck::default());
    let mut proxy = Proxy::new(policy.clone(), Arc::new(NullSink))
        .with_resolver(stuck.clone())
        .with_address_check(Arc::new(AnyAddress))
        .with_config(config);
    if let Some(upstream) = upstream {
        proxy = proxy.with_upstream(upstream);
    }
    (policy, stuck, Arc::new(proxy).handler(sandbox()))
}

#[tokio::test(start_paused = true)]
async fn a_lookup_that_times_out_is_unavailable_or_left_to_the_company_proxy() {
    let config = ProxyConfig::default().with_lookup_limits(Duration::from_secs(1), 32);
    let (policy, _, handler) = stuck_rig(config, None);
    policy.allow(&host("slow.example"));
    assert_eq!(
        handler.resolve_name(a("slow.example")).await,
        ResolveAnswer::Unavailable
    );

    let (policy, _, handler) = stuck_rig(config, Some(company_proxy(true)));
    policy.allow(&host("slow.example"));
    assert_eq!(
        handler.resolve_name(a("slow.example")).await,
        stand_in(StandInReason::ViaUpstream)
    );
}

#[tokio::test(start_paused = true)]
async fn lookups_over_the_per_sandbox_cap_are_unavailable_and_free_their_slot_when_done() {
    let config = ProxyConfig::default().with_lookup_limits(Duration::from_secs(5), 2);
    let (policy, stuck, handler) = stuck_rig(config, None);
    for name in ["a.example", "b.example", "c.example"] {
        policy.allow(&host(name));
    }
    let first = tokio::spawn({
        let handler = handler.clone();
        async move { handler.resolve_name(a("a.example")).await }
    });
    let second = tokio::spawn({
        let handler = handler.clone();
        async move { handler.resolve_name(a("b.example")).await }
    });
    // Let both take their slot.
    while stuck.started.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        handler.resolve_name(a("c.example")).await,
        ResolveAnswer::Unavailable
    );
    assert_eq!(
        stuck.started.load(Ordering::SeqCst),
        2,
        "the third never started a lookup"
    );
    // The two time out and free their slots.
    assert_eq!(first.await.unwrap(), ResolveAnswer::Unavailable);
    assert_eq!(second.await.unwrap(), ResolveAnswer::Unavailable);
    assert_eq!(
        handler.resolve_name(a("c.example")).await,
        ResolveAnswer::Unavailable
    );
    assert_eq!(stuck.started.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_policy_that_only_knows_decide_allows_nothing() {
    // The default `lookup` answers "no rule", so the stub never resolves for such a policy.
    struct DecideOnly;
    impl Policy for DecideOnly {
        fn decide(&self, _: &EgressRequest, _: SuffixAllows) -> Result<Decision, PolicyError> {
            Ok(Decision::Allow {
                rule_id: RuleId(1),
                pattern: PatternKind::Exact,
            })
        }
    }
    let resolver = Arc::new(StaticResolver::new().with("example.com", &[ip("93.184.215.14")]));
    let proxy = Arc::new(
        Proxy::new(Arc::new(DecideOnly), Arc::new(NullSink))
            .with_resolver(resolver.clone())
            .with_address_check(Arc::new(AnyAddress)),
    );
    let handler = proxy.handler(sandbox());
    assert_eq!(
        handler.resolve_name(a("example.com")).await,
        stand_in(StandInReason::NotAllowed)
    );
    assert_eq!(resolver.lookups(), 0);
}

#[test]
fn leading_service_labels_are_set_aside_up_to_three() {
    assert_eq!(
        super::split_service_labels("example.com"),
        (vec![], "example.com")
    );
    assert_eq!(
        super::split_service_labels("_a._b.example.com"),
        (vec!["_a", "_b"], "example.com")
    );
    assert_eq!(
        super::split_service_labels("_a._b._c._d.example.com"),
        (vec!["_a", "_b", "_c"], "_d.example.com")
    );
}
