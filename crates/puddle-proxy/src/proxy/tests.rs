// SPDX-License-Identifier: GPL-3.0-or-later
//! Decision, address and refusal logic without a guest stream. The full path over a route is in
//! `tests/route.rs`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use puddle_types::{NullSink, PendingId, RuleId, RuleSetId};
use tokio::net::TcpListener;

use super::*;
use crate::testing::{AnyAddress, StaticPolicy, StaticResolver};

fn workspace() -> WorkspaceName {
    WorkspaceName::new("box").unwrap()
}

fn host(h: &str) -> Host {
    normalise_host(h).unwrap().into_host()
}

fn request(h: &str) -> EgressRequest {
    EgressRequest::new(workspace(), host(h), 443)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn proxy(policy: Arc<dyn Policy>, resolver: StaticResolver) -> Proxy {
    Proxy::new(policy, Arc::new(NullSink)).with_resolver(Arc::new(resolver))
}

/// The addresses or refusal of [`super::admit`], without its audit event.
async fn admit(proxy: &Proxy, request: &EgressRequest) -> Result<Vec<SocketAddr>, Refusal> {
    super::admit(proxy, request)
        .await
        .0
        .map(|admitted| admitted.addrs)
}

fn header<'a>(refusal: &'a Refusal, name: &str) -> Option<&'a str> {
    refusal
        .headers
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.as_str())
}

/// A policy that answers from a closure and counts calls with each `SuffixAllows` mode.
struct FnPolicy<F> {
    f: F,
    ignore_calls: AtomicU32,
}

impl<F> FnPolicy<F> {
    fn new(f: F) -> Arc<Self> {
        Arc::new(Self {
            f,
            ignore_calls: AtomicU32::new(0),
        })
    }
}

impl<F> Policy for FnPolicy<F>
where
    F: Fn(SuffixAllows) -> Result<Decision, PolicyError> + Send + Sync,
{
    fn decide(&self, _: &EgressRequest, mode: SuffixAllows) -> Result<Decision, PolicyError> {
        if mode == SuffixAllows::Ignore {
            self.ignore_calls.fetch_add(1, Ordering::SeqCst);
        }
        (self.f)(mode)
    }
}

/// Exact-only for 10/8, block for 127/8, allow for the rest.
struct Toggles;

impl AddressCheck for Toggles {
    fn check(&self, _: &WorkspaceName, addr: SocketAddr) -> AddressVerdict {
        match addr.ip() {
            IpAddr::V4(a) if a.octets()[0] == 10 => {
                AddressVerdict::ExactOnly(LocalCategory::Private)
            }
            IpAddr::V4(a) if a.is_loopback() => AddressVerdict::Block(BlockReason::PuddleEndpoint),
            _ => AddressVerdict::Allow,
        }
    }
}

#[tokio::test]
async fn an_allowed_name_is_resolved_and_its_public_addresses_returned() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("example.com"));
    let p = proxy(
        policy,
        StaticResolver::new().with("example.com", &[ip("93.184.215.14"), ip("2606:2800::1")]),
    );
    let addrs = admit(&p, &request("example.com")).await.unwrap();
    assert_eq!(
        addrs,
        vec![
            SocketAddr::new(ip("93.184.215.14"), 443),
            SocketAddr::new(ip("2606:2800::1"), 443)
        ]
    );
}

#[tokio::test]
async fn an_unmatched_name_is_pending_and_never_resolved() {
    let policy = Arc::new(StaticPolicy::new());
    // The resolver knows nothing: if the proxy resolved, the refusal would be a 502.
    let p = proxy(policy.clone(), StaticResolver::new());
    let first = admit(&p, &request("unknown.example")).await.unwrap_err();
    assert_eq!(first.status, "403 Forbidden");
    assert_eq!(header(&first, "x-puddle-decision"), Some("pending"));
    assert_eq!(header(&first, "x-puddle-pending"), Some("1"));
    assert!(
        first.message.contains("approve it in puddle"),
        "{}",
        first.message
    );
    let again = admit(&p, &request("unknown.example")).await.unwrap_err();
    assert_eq!(header(&again, "x-puddle-pending"), Some("1"));
    let items = policy.pending();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].attempts, 2);
    assert_eq!(items[0].workspace, workspace());
}

#[tokio::test]
async fn a_suppressed_request_says_it_was_not_recorded() {
    let p = proxy(
        FnPolicy::new(|_| Ok(Decision::Pending(PendingOutcome::Suppressed))),
        StaticResolver::new(),
    );
    let refusal = admit(&p, &request("a.example")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
    assert_eq!(header(&refusal, "x-puddle-pending"), None);
    assert!(
        refusal.message.contains("wasn't added"),
        "{}",
        refusal.message
    );
}

#[tokio::test]
async fn a_deny_rule_is_a_403_that_names_the_rule() {
    let policy = Arc::new(StaticPolicy::new());
    let rule = policy.deny_host(&host("bad.example"));
    let p = proxy(policy.clone(), StaticResolver::new());
    let refusal = admit(&p, &request("bad.example")).await.unwrap_err();
    assert_eq!(refusal.status, "403 Forbidden");
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("deny"));
    assert_eq!(
        header(&refusal, "x-puddle-rule"),
        Some(rule.to_string().as_str())
    );
    assert_eq!(policy.pending().len(), 0);
}

#[tokio::test]
async fn a_policy_error_fails_closed_with_503() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("example.com"));
    policy.set_unavailable(true);
    let p = proxy(
        policy,
        StaticResolver::new().with("example.com", &[ip("1.1.1.1")]),
    );
    let refusal = admit(&p, &request("example.com")).await.unwrap_err();
    assert_eq!(refusal.status, "503 Service Unavailable");
}

#[tokio::test]
async fn a_rule_set_deny_names_the_rule_and_the_set() {
    let p = proxy(
        FnPolicy::new(|_| {
            Ok(Decision::SetDeny {
                set: RuleSetId::User(2),
                rule_id: RuleId(8),
                pattern: PatternKind::Exact,
            })
        }),
        StaticResolver::new(),
    );
    let refusal = admit(&p, &request("ads.example")).await.unwrap_err();
    assert_eq!(refusal.status, "403 Forbidden");
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("deny"));
    assert_eq!(header(&refusal, "x-puddle-rule"), Some("8"));
    assert_eq!(header(&refusal, "x-puddle-rule-set"), Some("user:2"));
    assert!(
        refusal.message.contains("rule set user:2"),
        "{}",
        refusal.message
    );
}

#[tokio::test]
async fn a_rule_set_allow_reaches_public_addresses_but_counts_as_a_wildcard_for_local_ones() {
    let policy = FnPolicy::new(|mode| {
        Ok(match mode {
            SuffixAllows::Count => Decision::SetAllow {
                set: RuleSetId::System,
                rule_id: None,
                pattern: PatternKind::Exact,
            },
            // Asked again for a local address, the engine drops every set allow (R-42).
            SuffixAllows::Ignore => Decision::Pending(PendingOutcome::New(PendingId(1))),
        })
    });
    let resolver = || {
        StaticResolver::new()
            .with("pub.example", &[ip("8.8.8.8")])
            .with("lan.example", &[ip("10.0.0.5")])
    };
    let p = proxy(policy.clone(), resolver()).with_address_check(Arc::new(Toggles));
    assert_eq!(
        admit(&p, &request("pub.example")).await.unwrap(),
        vec![SocketAddr::new(ip("8.8.8.8"), 443)]
    );
    let refusal = admit(&p, &request("lan.example")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
    assert_eq!(policy.ignore_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_panicking_policy_fails_closed_with_503() {
    let p = proxy(
        FnPolicy::new(|_| panic!("policy bug")),
        StaticResolver::new(),
    );
    let refusal = admit(&p, &request("example.com")).await.unwrap_err();
    assert_eq!(refusal.status, "503 Service Unavailable");
}

#[tokio::test]
async fn ssh_is_blocked_before_the_policy_is_asked() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("github.com"));
    let p = proxy(policy.clone(), StaticResolver::new());
    let req = request("github.com").with_protocol(ProtocolHint::Ssh);
    let refusal = admit(&p, &req).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("blocked"));
    assert_eq!(
        header(&refusal, "x-puddle-blocked"),
        Some("ssh_unsupported")
    );
    assert!(refusal.message.contains("use HTTPS"));
    assert_eq!(policy.decisions(), 0);
    assert_eq!(policy.pending().len(), 0);
}

#[tokio::test]
async fn a_blocked_decision_from_the_policy_is_never_pending() {
    let p = proxy(
        FnPolicy::new(|_| {
            Ok(Decision::Blocked {
                reason: BlockReason::PuddleEndpoint,
            })
        }),
        StaticResolver::new(),
    );
    let refusal = admit(&p, &request("a.example")).await.unwrap_err();
    assert_eq!(
        header(&refusal, "x-puddle-blocked"),
        Some("puddle_endpoint")
    );
    assert_eq!(header(&refusal, "x-puddle-pending"), None);
    assert!(refusal.message.contains("puddle's own endpoints"));
}

#[tokio::test]
async fn local_addresses_of_an_allowed_name_are_blocked_by_default() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("rebind.example"));
    let p = proxy(
        policy,
        StaticResolver::new().with("rebind.example", &[ip("127.0.0.1"), ip("169.254.169.254")]),
    );
    let refusal = admit(&p, &request("rebind.example")).await.unwrap_err();
    assert_eq!(refusal.status, "403 Forbidden");
    assert_eq!(
        header(&refusal, "x-puddle-blocked"),
        Some("toggle:loopback")
    );
    assert!(
        refusal
            .message
            .contains("turn on 'loopback' (host loopback) or 'metadata' (cloud metadata)"),
        "{}",
        refusal.message
    );
}

#[tokio::test]
async fn an_allowed_ip_literal_is_checked_without_resolving() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("10.1.2.3"));
    policy.allow(&host("1.1.1.1"));
    let p = proxy(policy, StaticResolver::new());
    let refusal = admit(&p, &request("10.1.2.3")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-blocked"), Some("toggle:private"));
    let addrs = admit(&p, &request("1.1.1.1")).await.unwrap();
    assert_eq!(addrs, vec![SocketAddr::new(ip("1.1.1.1"), 443)]);
}

#[tokio::test]
async fn local_addresses_are_dropped_when_public_ones_remain() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("mixed.example"));
    let p = proxy(
        policy,
        StaticResolver::new().with("mixed.example", &[ip("10.0.0.1"), ip("8.8.8.8")]),
    );
    let addrs = admit(&p, &request("mixed.example")).await.unwrap();
    assert_eq!(addrs, vec![SocketAddr::new(ip("8.8.8.8"), 443)]);
}

#[tokio::test]
async fn a_block_reason_from_the_address_check_is_passed_on() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("self.example"));
    let p = proxy(
        policy,
        StaticResolver::new().with("self.example", &[ip("127.0.0.1")]),
    )
    .with_address_check(Arc::new(Toggles));
    let refusal = admit(&p, &request("self.example")).await.unwrap_err();
    assert_eq!(
        header(&refusal, "x-puddle-blocked"),
        Some("puddle_endpoint")
    );
}

#[tokio::test]
async fn a_toggled_local_address_needs_an_exact_allow() {
    let resolver = || StaticResolver::new().with("nas.example", &[ip("10.0.0.5")]);
    // Exact allow: connects.
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("nas.example"));
    let p = proxy(policy, resolver()).with_address_check(Arc::new(Toggles));
    assert_eq!(
        admit(&p, &request("nas.example")).await.unwrap(),
        vec![SocketAddr::new(ip("10.0.0.5"), 443)]
    );
    // Suffix allow: asked again with suffix allows ignored, and goes pending for the exact name.
    let policy = Arc::new(StaticPolicy::new());
    policy.allow_as_suffix(&host("nas.example"));
    let p = proxy(policy.clone(), resolver()).with_address_check(Arc::new(Toggles));
    let refusal = admit(&p, &request("nas.example")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
    assert_eq!(policy.pending().len(), 1);
}

#[tokio::test]
async fn a_suffix_allow_reasked_without_suffixes_follows_the_second_answer() {
    let resolver = || StaticResolver::new().with("nas.example", &[ip("10.0.0.5")]);
    let suffix = Decision::Allow {
        rule_id: RuleId(1),
        pattern: PatternKind::Suffix,
    };
    // The second answer is an exact allow: connect.
    let policy = FnPolicy::new(move |mode| {
        Ok(match mode {
            SuffixAllows::Count => suffix,
            SuffixAllows::Ignore => Decision::Allow {
                rule_id: RuleId(2),
                pattern: PatternKind::Exact,
            },
        })
    });
    let p = proxy(policy.clone(), resolver()).with_address_check(Arc::new(Toggles));
    assert_eq!(admit(&p, &request("nas.example")).await.unwrap().len(), 1);
    assert_eq!(policy.ignore_calls.load(Ordering::SeqCst), 1);
    // A (misbehaving) policy answering with a suffix allow again: blocked, not connected.
    let policy = FnPolicy::new(move |_| Ok(suffix));
    let p = proxy(policy, resolver()).with_address_check(Arc::new(Toggles));
    let refusal = admit(&p, &request("nas.example")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-blocked"), Some("local_address"));
}

/// The audit event follows the last decision `admit` took (R-24).
#[tokio::test]
async fn the_audit_event_follows_each_admit_path() {
    let resolver = || StaticResolver::new().with("nas.example", &[ip("10.0.0.5")]);
    let kind = |e: &ConnectionEvent| (e.decision, e.reason, e.rule_id, e.pending_id);

    // Name stage: SSH never reaches the rules.
    let p = proxy(Arc::new(StaticPolicy::new()), resolver());
    let req = request("nas.example").with_protocol(ProtocolHint::Ssh);
    let (_, e) = super::admit(&p, &req).await;
    assert_eq!(
        kind(&e),
        (
            ConnectionDecision::Blocked,
            ConnectionReason::Blocked(BlockReason::SshUnsupported),
            None,
            None
        )
    );
    // Name stage: a literal blocked by the address check.
    let p = proxy(Arc::new(StaticPolicy::new()), resolver());
    let (_, e) = super::admit(&p, &request("127.0.0.1")).await;
    assert_eq!(e.decision, ConnectionDecision::Blocked);
    assert_eq!(e.reason.to_string(), "toggle:loopback");

    // Suffix allow, local address, re-asked: pending for the exact name.
    let policy = Arc::new(StaticPolicy::new());
    policy.allow_as_suffix(&host("nas.example"));
    let p = proxy(policy.clone(), resolver()).with_address_check(Arc::new(Toggles));
    let (_, e) = super::admit(&p, &request("nas.example")).await;
    assert_eq!(
        kind(&e),
        (
            ConnectionDecision::Pending,
            ConnectionReason::NoRule,
            None,
            Some(policy.pending()[0].id)
        )
    );
    // Re-asked and a suffix allow again: blocked, keeping the rule.
    let suffix = Decision::Allow {
        rule_id: RuleId(1),
        pattern: PatternKind::Suffix,
    };
    let p =
        proxy(FnPolicy::new(move |_| Ok(suffix)), resolver()).with_address_check(Arc::new(Toggles));
    let (_, e) = super::admit(&p, &request("nas.example")).await;
    assert_eq!(
        kind(&e),
        (
            ConnectionDecision::Blocked,
            ConnectionReason::Blocked(BlockReason::LocalAddress),
            Some(RuleId(1)),
            None
        )
    );
    // Allowed, then every address blocked by the address check: blocked, keeping the rule.
    let policy = Arc::new(StaticPolicy::new());
    let rule = policy.allow(&host("self.example"));
    let p = proxy(
        policy,
        StaticResolver::new().with("self.example", &[ip("127.0.0.1")]),
    )
    .with_address_check(Arc::new(Toggles));
    let (_, e) = super::admit(&p, &request("self.example")).await;
    assert_eq!(
        kind(&e),
        (
            ConnectionDecision::Blocked,
            ConnectionReason::Blocked(BlockReason::PuddleEndpoint),
            Some(rule),
            None
        )
    );
    // Allowed and admitted: the allow.
    let policy = Arc::new(StaticPolicy::new());
    let rule = policy.allow(&host("nas.example"));
    let p = proxy(policy, resolver()).with_address_check(Arc::new(Toggles));
    let (admitted, e) = super::admit(&p, &request("nas.example")).await;
    assert!(admitted.is_ok());
    assert_eq!(
        kind(&e),
        (
            ConnectionDecision::Allow,
            ConnectionReason::Rule,
            Some(rule),
            None
        )
    );
}

#[tokio::test]
async fn resolve_failures_are_502_and_504() {
    struct Never;
    impl Resolver for Never {
        fn resolve<'a>(
            &'a self,
            _: &'a puddle_types::DomainName,
            _: u16,
        ) -> crate::BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            Box::pin(std::future::pending())
        }
    }
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("gone.example"));
    policy.allow(&host("empty.example"));
    policy.allow(&host("slow.example"));
    let p = proxy(policy, StaticResolver::new().with("empty.example", &[]));
    let refusal = admit(&p, &request("gone.example")).await.unwrap_err();
    assert_eq!(refusal.status, "502 Bad Gateway");
    assert!(refusal.message.contains("could not resolve"));
    let refusal = admit(&p, &request("empty.example")).await.unwrap_err();
    assert_eq!(refusal.status, "502 Bad Gateway");
    assert!(refusal.message.contains("no addresses"));

    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("slow.example"));
    let p = Proxy::new(policy, Arc::new(NullSink))
        .with_resolver(Arc::new(Never))
        .with_config(
            ProxyConfig::default()
                .with_network_timeouts(Duration::from_millis(20), Duration::from_secs(1)),
        );
    let refusal = admit(&p, &request("slow.example")).await.unwrap_err();
    assert_eq!(refusal.status, "504 Gateway Timeout");
}

#[tokio::test]
async fn connect_first_skips_addresses_that_refuse() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good = listener.local_addr().unwrap();
    // A port that was just free: connecting to it is refused.
    let closed = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (_, addr) = connect_first(&[closed, good], Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(addr, good);
    assert!(
        connect_first(&[closed], Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(
        connect_first(&[], Duration::from_secs(5))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn a_refusal_is_a_complete_response_that_closes() {
    let bytes = Refusal::new("403 Forbidden", "x is not allowed")
        .header("x-puddle-decision", "deny")
        .bytes();
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(
        text,
        "HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: 25\r\nx-puddle-decision: deny\r\nconnection: close\r\n\r\npuddle: x is not allowed\n"
    );
}

#[test]
fn config_builders_set_their_field() {
    let c = ProxyConfig::default()
        .with_head_timeout(Duration::from_secs(1))
        .with_max_streams_per_workspace(7)
        .with_max_sessions_per_route(3)
        .with_session(HostConfig {
            control_burst: 1,
            ..HostConfig::default()
        });
    assert_eq!(c.head_timeout, Duration::from_secs(1));
    assert_eq!(c.max_streams_per_workspace, 7);
    assert_eq!(c.max_sessions_per_route, 3);
    assert_eq!(c.session.control_burst, 1);
    let p = Proxy::new(Arc::new(StaticPolicy::new()), Arc::new(NullSink))
        .with_address_check(Arc::new(AnyAddress))
        .with_config(c);
    assert_eq!(p.config().max_streams_per_workspace, 7);
    assert!(format!("{p:?}").contains("max_streams_per_workspace: 7"));
    let handler = Arc::new(p).handler(workspace());
    assert_eq!(handler.workspace(), &workspace());
}

// The real guard (`puddle_netpolicy::NetPolicy`) in the proxy: the local-destination toggles,
// exact-only allows after a wildcard, and puddle's own listeners.

mod guard {
    use std::sync::atomic::AtomicUsize;

    use puddle_netpolicy::{EndpointKind, LocalAccess, NetPolicy, PuddleEndpoints};

    use super::*;

    fn all_on() -> LocalAccess {
        LocalCategory::ALL
            .into_iter()
            .fold(LocalAccess::NONE, |a, c| a.with_toggle(c, true))
    }

    fn guarded(policy: Arc<dyn Policy>, resolver: StaticResolver, access: LocalAccess) -> Proxy {
        proxy(policy, resolver).with_address_check(Arc::new(NetPolicy::new(Arc::new(access))))
    }

    fn blocked(refusal: &Refusal) -> Option<&str> {
        assert_eq!(refusal.status, "403 Forbidden");
        assert_eq!(header(refusal, "x-puddle-pending"), None);
        header(refusal, "x-puddle-blocked")
    }

    #[tokio::test]
    async fn hostile_hg06_local_targets_blocked_with_every_toggle_off() {
        let policy = Arc::new(StaticPolicy::new());
        let resolver = StaticResolver::new()
            .with("ten.nip.example", &[ip("10.0.0.1")])
            .with("lo.nip.example", &[ip("127.0.0.1")])
            .with("imds.nip.example", &[ip("169.254.169.254")]);
        let cases = [
            ("169.254.169.254", "toggle:metadata"),
            ("metadata.google.internal", "toggle:metadata"),
            ("168.63.129.16", "toggle:metadata"),
            ("fd00:ec2::254", "toggle:metadata"),
            ("64:ff9b::a9fe:a9fe", "toggle:metadata"),
            ("169.254.1.1", "toggle:link_local"),
            ("192.168.1.1", "toggle:private"),
            ("100.64.0.1", "toggle:private"),
            ("127.0.0.1", "toggle:loopback"),
            ("localhost", "toggle:loopback"),
            ("::ffff:127.0.0.1", "toggle:loopback"),
            ("ten.nip.example", "toggle:private"),
            ("lo.nip.example", "toggle:loopback"),
            ("imds.nip.example", "toggle:metadata"),
        ];
        // Every destination allowed by a rule: only the guard stands in the way.
        for (h, _) in cases {
            policy.allow(&host(h));
        }
        let p = guarded(policy.clone(), resolver, LocalAccess::NONE);
        for (h, want) in cases {
            let refusal = admit(&p, &request(h)).await.unwrap_err();
            assert_eq!(blocked(&refusal), Some(want), "{h}");
            assert!(
                refusal.message.contains("toggle is off"),
                "{h}: {}",
                refusal.message
            );
        }
        assert_eq!(policy.pending().len(), 0);
        // Literals and category names never reached the rules; the three names did.
        assert_eq!(policy.decisions(), 3);
    }

    /// A resolver that answers public, then loopback, then public, ... (DNS rebinding).
    struct Rebinding(AtomicUsize);

    impl Resolver for Rebinding {
        fn resolve<'a>(
            &'a self,
            _: &'a puddle_types::DomainName,
            port: u16,
        ) -> crate::BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let ip = if n.is_multiple_of(2) {
                ip("93.184.215.14")
            } else {
                ip("127.0.0.1")
            };
            Box::pin(async move { Ok(vec![SocketAddr::new(ip, port)]) })
        }
    }

    #[tokio::test]
    async fn hostile_hg07_rebinding_connects_only_to_checked_addresses() {
        let policy = Arc::new(StaticPolicy::new());
        policy.allow(&host("rebind.example"));
        let resolver = Arc::new(Rebinding(AtomicUsize::new(0)));
        let p = Proxy::new(policy, Arc::new(NullSink))
            .with_resolver(resolver.clone())
            .with_address_check(Arc::new(NetPolicy::new(Arc::new(LocalAccess::NONE))));
        let (mut ok, mut refused) = (0, 0);
        for _ in 0..50 {
            match admit(&p, &request("rebind.example")).await {
                Ok(addrs) => {
                    assert_eq!(addrs, vec![SocketAddr::new(ip("93.184.215.14"), 443)]);
                    ok += 1;
                }
                Err(refusal) => {
                    assert_eq!(blocked(&refusal), Some("toggle:loopback"));
                    refused += 1;
                }
            }
        }
        assert_eq!((ok, refused), (25, 25));
        // One lookup per request: the checked answer is the one connected to.
        assert_eq!(resolver.0.load(Ordering::SeqCst), 50);
    }

    #[tokio::test]
    async fn hostile_hg08_mixed_answer_connects_to_the_public_address_only() {
        let policy = Arc::new(StaticPolicy::new());
        policy.allow(&host("mixed.example"));
        let resolver = StaticResolver::new().with(
            "mixed.example",
            &[
                ip("127.0.0.1"),
                ip("169.254.169.254"),
                ip("8.8.8.8"),
                ip("10.0.0.1"),
            ],
        );
        let p = guarded(policy, resolver, LocalAccess::NONE);
        assert_eq!(
            admit(&p, &request("mixed.example")).await.unwrap(),
            vec![SocketAddr::new(ip("8.8.8.8"), 443)]
        );
    }

    #[tokio::test]
    async fn toggle_on_unlisted_local_destination_goes_to_approval_not_through() {
        let policy = Arc::new(StaticPolicy::new());
        let resolver = StaticResolver::new().with("nas.lan.example", &[ip("192.168.1.20")]);
        let p = guarded(policy.clone(), resolver, all_on());
        for h in [
            "10.1.2.3",
            "fd00::5",
            "nas.lan.example",
            "localhost",
            "127.0.0.1",
        ] {
            let refusal = admit(&p, &request(h)).await.unwrap_err();
            assert_eq!(
                header(&refusal, "x-puddle-decision"),
                Some("pending"),
                "{h}"
            );
        }
        assert_eq!(policy.pending().len(), 5);
    }

    #[tokio::test]
    async fn toggle_on_and_exactly_allowed_local_destination_is_allowed() {
        let policy = Arc::new(StaticPolicy::new());
        for h in ["10.1.2.3", "nas.lan.example", "localhost"] {
            policy.allow(&host(h));
        }
        let resolver = StaticResolver::new()
            .with("nas.lan.example", &[ip("192.168.1.20")])
            .with("localhost", &[ip("127.0.0.1"), ip("::1")]);
        let p = guarded(policy, resolver, all_on());
        assert_eq!(
            admit(&p, &request("10.1.2.3")).await.unwrap(),
            vec![SocketAddr::new(ip("10.1.2.3"), 443)]
        );
        assert_eq!(
            admit(&p, &request("nas.lan.example")).await.unwrap(),
            vec![SocketAddr::new(ip("192.168.1.20"), 443)]
        );
        assert_eq!(admit(&p, &request("localhost")).await.unwrap().len(), 2);
        // The neighbouring address still needs its own allow.
        let refusal = admit(&p, &request("10.1.2.4")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
    }

    #[tokio::test]
    async fn toggle_off_allowed_local_destination_is_blocked_naming_the_toggle() {
        let policy = Arc::new(StaticPolicy::new());
        policy.allow(&host("10.1.2.3"));
        let p = guarded(
            policy,
            StaticResolver::new(),
            all_on().with_toggle(LocalCategory::Private, false),
        );
        let refusal = admit(&p, &request("10.1.2.3")).await.unwrap_err();
        assert_eq!(blocked(&refusal), Some("toggle:private"));
        assert!(
            refusal.message.contains(
                "turn on 'private' (local/private network) globally or for workspace box"
            ),
            "{}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn wildcard_allow_does_not_reach_a_local_address_with_the_setting_off() {
        let policy = Arc::new(StaticPolicy::new());
        // StaticPolicy answers "suffix match" per host, standing in for a `.nip.example` rule.
        for h in ["nas.nip.example", "both.nip.example", "pub.nip.example"] {
            policy.allow_as_suffix(&host(h));
        }
        let resolver = || {
            StaticResolver::new()
                .with("nas.nip.example", &[ip("192.168.1.20")])
                .with("both.nip.example", &[ip("192.168.1.20"), ip("8.8.8.8")])
                .with("pub.nip.example", &[ip("8.8.8.8")])
        };
        let p = guarded(policy.clone(), resolver(), all_on());
        let refusal = admit(&p, &request("nas.nip.example")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
        assert!(
            refusal
                .message
                .contains("wildcard rules don't reach local addresses"),
            "{}",
            refusal.message
        );
        assert_eq!(policy.pending().len(), 1);
        assert_eq!(policy.pending()[0].host, host("nas.nip.example"));
        // Mixed public/local under a wildcard: the public address only.
        assert_eq!(
            admit(&p, &request("both.nip.example")).await.unwrap(),
            vec![SocketAddr::new(ip("8.8.8.8"), 443)]
        );
        // A wildcard to a public address is unchanged.
        assert_eq!(
            admit(&p, &request("pub.nip.example")).await.unwrap().len(),
            1
        );
        // Setting on: the wildcard reaches the local address.
        let p = guarded(
            policy.clone(),
            resolver(),
            all_on().with_wildcards_reach_local(true),
        );
        assert_eq!(
            admit(&p, &request("nas.nip.example")).await.unwrap(),
            vec![SocketAddr::new(ip("192.168.1.20"), 443)]
        );
        // Setting on, toggle off: still blocked; the setting never replaces the toggle.
        let p = guarded(
            policy,
            resolver(),
            LocalAccess::NONE.with_wildcards_reach_local(true),
        );
        let refusal = admit(&p, &request("nas.nip.example")).await.unwrap_err();
        assert_eq!(blocked(&refusal), Some("toggle:private"));
    }

    #[tokio::test]
    async fn exact_ip_rule_admits_the_local_address_of_a_wildcard_name() {
        let policy = Arc::new(StaticPolicy::new());
        for h in [
            "nas.nip.example",
            "both.nip.example",
            "two.nip.example",
            "other.nip.example",
            "denied.nip.example",
        ] {
            policy.allow_as_suffix(&host(h));
        }
        policy.allow(&host("192.168.1.20"));
        let ip_deny = policy.deny_host(&host("192.168.1.30"));
        let resolver = || {
            StaticResolver::new()
                .with("nas.nip.example", &[ip("192.168.1.20")])
                .with("both.nip.example", &[ip("192.168.1.20"), ip("8.8.8.8")])
                .with("two.nip.example", &[ip("192.168.1.20"), ip("192.168.1.21")])
                .with("other.nip.example", &[ip("192.168.1.21")])
                .with("denied.nip.example", &[ip("192.168.1.30")])
        };
        let p = guarded(policy.clone(), resolver(), all_on());
        // The IP rule admits its address: no pending row for the name or the address.
        assert_eq!(
            admit(&p, &request("nas.nip.example")).await.unwrap(),
            vec![SocketAddr::new(ip("192.168.1.20"), 443)]
        );
        assert_eq!(policy.pending().len(), 0);
        // Mixed with a public address: both are used.
        assert_eq!(
            admit(&p, &request("both.nip.example")).await.unwrap(),
            vec![
                SocketAddr::new(ip("8.8.8.8"), 443),
                SocketAddr::new(ip("192.168.1.20"), 443)
            ]
        );
        // Only the address the rule names: its neighbour is dropped.
        assert_eq!(
            admit(&p, &request("two.nip.example")).await.unwrap(),
            vec![SocketAddr::new(ip("192.168.1.20"), 443)]
        );
        assert_eq!(policy.pending().len(), 0);
        // A neighbour with no IP rule goes pending for the name.
        let refusal = admit(&p, &request("other.nip.example")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
        assert!(
            refusal
                .message
                .contains("add an exact rule for its address"),
            "{}",
            refusal.message
        );
        // An address with an IP deny is denied by that rule, with no pending row (R-27).
        let refusal = admit(&p, &request("denied.nip.example")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-decision"), Some("deny"));
        assert_eq!(
            header(&refusal, "x-puddle-rule"),
            Some(ip_deny.to_string().as_str())
        );
        let pending: Vec<Host> = policy.pending().into_iter().map(|p| p.host).collect();
        assert_eq!(pending, vec![host("other.nip.example")]);
        // The IP rule never replaces the toggle.
        let p = guarded(
            policy.clone(),
            resolver(),
            all_on().with_toggle(LocalCategory::Private, false),
        );
        let refusal = admit(&p, &request("nas.nip.example")).await.unwrap_err();
        assert_eq!(blocked(&refusal), Some("toggle:private"));
    }

    /// Suffix-allows every name and records a pending row on `Ignore`; `lookup` fails.
    struct BrokenLookup(StaticPolicy);

    impl Policy for BrokenLookup {
        fn decide(&self, r: &EgressRequest, mode: SuffixAllows) -> Result<Decision, PolicyError> {
            match mode {
                SuffixAllows::Count => Ok(Decision::Allow {
                    rule_id: RuleId(1),
                    pattern: PatternKind::Suffix,
                }),
                SuffixAllows::Ignore => self.0.decide(r, mode),
            }
        }

        fn lookup(
            &self,
            _: &EgressRequest,
            _: SuffixAllows,
        ) -> Result<Option<Decision>, PolicyError> {
            Err(PolicyError {
                reason: "lookup down".into(),
            })
        }
    }

    #[tokio::test]
    async fn failed_or_missing_ip_lookup_admits_nothing() {
        let resolver = || StaticResolver::new().with("nas.nip.example", &[ip("192.168.1.20")]);
        // `lookup` errors: an IP deny can't be ruled out, so the request fails closed (R-27),
        // and nothing goes pending.
        let broken = Arc::new(BrokenLookup(StaticPolicy::new()));
        let p = guarded(broken.clone(), resolver(), all_on());
        let (refusal, event) = super::super::admit(&p, &request("nas.nip.example")).await;
        assert_eq!(refusal.unwrap_err().status, "503 Service Unavailable");
        assert_eq!(event.reason, ConnectionReason::PolicyUnavailable);
        assert_eq!(broken.0.pending().len(), 0);
        // The trait's default `lookup` (no IP rules known): the same.
        let suffix = Decision::Allow {
            rule_id: RuleId(1),
            pattern: PatternKind::Suffix,
        };
        let pending = Decision::Pending(PendingOutcome::New(PendingId(7)));
        let policy = FnPolicy::new(move |mode| {
            Ok(match mode {
                SuffixAllows::Count => suffix,
                SuffixAllows::Ignore => pending,
            })
        });
        let p = guarded(policy.clone(), resolver(), all_on());
        let refusal = admit(&p, &request("nas.nip.example")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-pending"), Some("7"));
        assert_eq!(policy.ignore_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn puddle_endpoints_are_blocked_whatever_the_toggles_and_rules_say() {
        let endpoints = PuddleEndpoints::new();
        let _api = endpoints.register(SocketAddr::new(ip("127.0.0.1"), 443), EndpointKind::Api);
        let policy = Arc::new(StaticPolicy::new());
        for h in ["127.0.0.1", "localhost", "self.example"] {
            policy.allow(&host(h));
        }
        let guard = NetPolicy::new(Arc::new(all_on().with_wildcards_reach_local(true)))
            .with_endpoints(endpoints);
        let p = proxy(
            policy.clone(),
            StaticResolver::new().with("self.example", &[ip("127.0.0.1")]),
        )
        .with_address_check(Arc::new(guard));
        for h in ["127.0.0.1", "localhost", "self.example"] {
            let refusal = admit(&p, &request(h)).await.unwrap_err();
            assert_eq!(blocked(&refusal), Some("puddle_endpoint"), "{h}");
            assert!(refusal.message.contains("puddle's own endpoints"), "{h}");
        }
        assert_eq!(policy.pending().len(), 0);
        // Literal and `localhost` were refused before the rules.
        assert_eq!(policy.decisions(), 1);
    }

    /// R-27: an exact deny of an address wins over every rule for the name.
    mod r27 {
        use std::collections::HashMap;
        use std::sync::atomic::AtomicBool;

        use proptest::prelude::*;

        use super::*;
        use crate::proxy::admit as admit_with_event;

        fn denied_by(refusal: &Refusal) -> Option<&str> {
            assert_eq!(refusal.status, "403 Forbidden", "{}", refusal.message);
            assert_eq!(header(refusal, "x-puddle-decision"), Some("deny"));
            assert_eq!(header(refusal, "x-puddle-pending"), None);
            header(refusal, "x-puddle-rule")
        }

        #[tokio::test]
        async fn r27_ip_deny_beats_an_exact_name_allow_local_or_public() {
            let policy = Arc::new(StaticPolicy::new());
            policy.allow(&host("nas.example"));
            policy.allow(&host("pub.example"));
            let local_deny = policy.deny_host(&host("192.168.1.30"));
            let public_deny = policy.deny_host(&host("8.8.4.4"));
            let resolver = StaticResolver::new()
                .with("nas.example", &[ip("192.168.1.30")])
                .with("pub.example", &[ip("8.8.4.4")]);
            let p = guarded(policy.clone(), resolver, all_on());

            let (admitted, event) = admit_with_event(&p, &request("nas.example")).await;
            let refusal = admitted.unwrap_err();
            assert_eq!(denied_by(&refusal), Some(local_deny.to_string().as_str()));
            assert!(
                refusal.message.contains("192.168.1.30 (rule"),
                "{}",
                refusal.message
            );
            assert_eq!(
                (
                    event.decision,
                    event.reason,
                    event.rule_id,
                    event.pending_id,
                    event.resolved_ip
                ),
                (
                    ConnectionDecision::Deny,
                    ConnectionReason::Rule,
                    Some(local_deny),
                    None,
                    Some(ip("192.168.1.30"))
                )
            );
            let refusal = admit(&p, &request("pub.example")).await.unwrap_err();
            assert_eq!(denied_by(&refusal), Some(public_deny.to_string().as_str()));
            assert_eq!(policy.pending().len(), 0);
        }

        #[tokio::test]
        async fn r27_ip_deny_beats_a_wildcard_allow_even_with_wildcards_reaching_local() {
            let policy = Arc::new(StaticPolicy::new());
            policy.allow_as_suffix(&host("nas.nip.example"));
            policy.allow_as_suffix(&host("pub.nip.example"));
            policy.deny_host(&host("192.168.1.30"));
            policy.deny_host(&host("8.8.4.4"));
            let resolver = || {
                StaticResolver::new()
                    .with("nas.nip.example", &[ip("192.168.1.30")])
                    .with("pub.nip.example", &[ip("8.8.4.4")])
            };
            for access in [all_on(), all_on().with_wildcards_reach_local(true)] {
                let p = guarded(policy.clone(), resolver(), access);
                for h in ["nas.nip.example", "pub.nip.example"] {
                    let refusal = admit(&p, &request(h)).await.unwrap_err();
                    assert!(denied_by(&refusal).is_some(), "{h}");
                }
            }
            assert_eq!(policy.pending().len(), 0);
        }

        #[tokio::test]
        async fn r27_a_mixed_answer_drops_only_the_denied_addresses() {
            let policy = Arc::new(StaticPolicy::new());
            policy.allow(&host("mixed.example"));
            policy.deny_host(&host("1.1.1.1"));
            policy.deny_host(&host("10.0.0.5"));
            let resolver = StaticResolver::new().with(
                "mixed.example",
                &[
                    ip("8.8.8.8"),
                    ip("1.1.1.1"),
                    ip("10.0.0.5"),
                    ip("192.168.1.20"),
                ],
            );
            let p = guarded(policy.clone(), resolver, all_on());
            assert_eq!(
                admit(&p, &request("mixed.example")).await.unwrap(),
                vec![
                    SocketAddr::new(ip("8.8.8.8"), 443),
                    SocketAddr::new(ip("192.168.1.20"), 443)
                ]
            );
            // Denied and toggle-blocked addresses only: the toggle is named, since turning it on
            // reaches an address no rule denies.
            let resolver =
                StaticResolver::new().with("mixed.example", &[ip("10.0.0.5"), ip("192.168.1.20")]);
            let p = guarded(
                policy,
                resolver,
                all_on().with_toggle(LocalCategory::Private, false),
            );
            let refusal = admit(&p, &request("mixed.example")).await.unwrap_err();
            assert_eq!(blocked(&refusal), Some("toggle:private"));
        }

        #[tokio::test]
        async fn r27_approving_the_name_never_reaches_a_denied_address() {
            let policy = Arc::new(StaticPolicy::new());
            let ip_deny = policy.deny_host(&host("192.168.1.30"));
            let p = guarded(
                policy.clone(),
                StaticResolver::new().with("nas.example", &[ip("192.168.1.30")]),
                all_on(),
            );
            // Unknown name: pending for the name, never resolved (R-10).
            let refusal = admit(&p, &request("nas.example")).await.unwrap_err();
            assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
            policy.approve(policy.pending()[0].id).unwrap();
            let refusal = admit(&p, &request("nas.example")).await.unwrap_err();
            assert_eq!(denied_by(&refusal), Some(ip_deny.to_string().as_str()));
            assert_eq!(policy.pending().iter().filter(|p| p.open).count(), 0);
        }

        /// An exact name allow whose IP lookup fails: refused, never connected.
        struct ExactThenBroken;

        impl Policy for ExactThenBroken {
            fn decide(&self, _: &EgressRequest, _: SuffixAllows) -> Result<Decision, PolicyError> {
                Ok(Decision::Allow {
                    rule_id: RuleId(1),
                    pattern: PatternKind::Exact,
                })
            }

            fn lookup(
                &self,
                _: &EgressRequest,
                _: SuffixAllows,
            ) -> Result<Option<Decision>, PolicyError> {
                Err(PolicyError {
                    reason: "lookup down".into(),
                })
            }
        }

        #[tokio::test]
        async fn r27_a_failed_ip_lookup_fails_closed_after_an_exact_allow() {
            let p = proxy(
                Arc::new(ExactThenBroken),
                StaticResolver::new().with("pub.example", &[ip("8.8.8.8")]),
            );
            let refusal = admit(&p, &request("pub.example")).await.unwrap_err();
            assert_eq!(refusal.status, "503 Service Unavailable");
            // An IP literal is decided as itself; no separate lookup.
            assert_eq!(admit(&p, &request("8.8.8.8")).await.unwrap().len(), 1);
        }

        /// Answers the name with generated decisions and each address with its generated IP
        /// rule; flags any decision asked about an IP (the proxy must never ask one for a name).
        struct GenPolicy {
            name: Result<Decision, PolicyError>,
            again: Decision,
            ip_rules: HashMap<IpAddr, Decision>,
            ignore_calls: AtomicU32,
            decided_an_ip: AtomicBool,
        }

        impl Policy for GenPolicy {
            fn decide(
                &self,
                r: &EgressRequest,
                mode: SuffixAllows,
            ) -> Result<Decision, PolicyError> {
                if matches!(r.host, Host::Ip(_)) {
                    self.decided_an_ip.store(true, Ordering::SeqCst);
                }
                match mode {
                    SuffixAllows::Count => self.name.clone(),
                    SuffixAllows::Ignore => {
                        self.ignore_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(self.again)
                    }
                }
            }

            fn lookup(
                &self,
                r: &EgressRequest,
                _: SuffixAllows,
            ) -> Result<Option<Decision>, PolicyError> {
                Ok(match r.host {
                    Host::Ip(addr) => self.ip_rules.get(&addr).copied(),
                    Host::Name(_) => None,
                })
            }
        }

        const POOL: [&str; 10] = [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "10.0.0.5",
            "192.168.1.20",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "fd00::1",
            "::ffff:10.0.0.6",
        ];

        fn decision() -> impl Strategy<Value = Decision> {
            let rule = (1i64..50).prop_map(RuleId);
            let pattern = prop_oneof![Just(PatternKind::Exact), Just(PatternKind::Suffix)];
            prop_oneof![
                (rule.clone(), pattern.clone())
                    .prop_map(|(rule_id, pattern)| Decision::Allow { rule_id, pattern }),
                (rule, pattern).prop_map(|(rule_id, pattern)| Decision::Deny { rule_id, pattern }),
                (1i64..50).prop_map(|id| Decision::Pending(PendingOutcome::New(PendingId(id)))),
                (1i64..50).prop_map(|id| Decision::Pending(PendingOutcome::Repeat(PendingId(id)))),
                Just(Decision::Pending(PendingOutcome::Suppressed)),
                Just(Decision::Blocked {
                    reason: BlockReason::LocalAddress
                }),
            ]
        }

        /// 0: no IP rule, 1: exact allow, 2: exact deny.
        fn ip_rule_kind() -> impl Strategy<Value = u8> {
            prop_oneof![2 => Just(0u8), 1 => Just(1u8), 2 => Just(2u8)]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2000))]

            /// Whatever the name's rules answer (first ask and re-ask), whatever the toggles and
            /// the wildcard setting, and whatever mix of addresses the name resolves to, an
            /// address with an IP deny is never admitted; and when every address is denied, the
            /// refusal is that deny, with no re-ask that could write a pending row.
            #[test]
            fn no_name_rule_reaches_an_ip_denied_address(
                name in prop_oneof![
                    4 => decision().prop_map(Ok),
                    1 => Just(Err(PolicyError { reason: "down".into() })),
                ],
                again in decision(),
                picked in proptest::sample::subsequence(POOL.to_vec(), 1..=POOL.len()),
                kinds in proptest::collection::vec(ip_rule_kind(), POOL.len()),
                toggles in proptest::collection::vec(any::<bool>(), LocalCategory::ALL.len()),
                wildcards_reach_local in any::<bool>(),
            ) {
                let resolved: Vec<IpAddr> = picked.iter().map(|a| ip(a)).collect();
                let mut ip_rules = HashMap::new();
                let mut denied = Vec::new();
                for (index, (addr, kind)) in POOL.iter().zip(&kinds).enumerate() {
                    let rule_id = RuleId(100 + i64::try_from(index).unwrap());
                    let pattern = PatternKind::Exact;
                    match kind {
                        1 => { ip_rules.insert(ip(addr), Decision::Allow { rule_id, pattern }); }
                        2 => {
                            ip_rules.insert(ip(addr), Decision::Deny { rule_id, pattern });
                            denied.push((ip(addr), rule_id));
                        }
                        _ => {}
                    }
                }
                let access = LocalCategory::ALL
                    .into_iter()
                    .zip(&toggles)
                    .fold(LocalAccess::NONE, |a, (c, on)| a.with_toggle(c, *on))
                    .with_wildcards_reach_local(wildcards_reach_local);
                let policy = Arc::new(GenPolicy {
                    name: name.clone(),
                    again,
                    ip_rules,
                    ignore_calls: AtomicU32::new(0),
                    decided_an_ip: AtomicBool::new(false),
                });
                let p = guarded(
                    policy.clone(),
                    StaticResolver::new().with("svc.example", &resolved),
                    access,
                );
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let (admitted, event) =
                    runtime.block_on(admit_with_event(&p, &request("svc.example")));

                prop_assert!(!policy.decided_an_ip.load(Ordering::SeqCst));
                let is_denied = |a: &IpAddr| denied.iter().any(|(d, _)| d == a);
                if let Ok(admitted) = &admitted {
                    for addr in &admitted.addrs {
                        prop_assert!(resolved.contains(&addr.ip()), "{addr} was never resolved");
                        prop_assert!(!is_denied(&addr.ip()), "{addr} is IP-denied but admitted");
                    }
                    // A proxy may be told the name only if nothing it resolves to is
                    // denied or dropped.
                    prop_assert!(
                        !admitted.name_ok || admitted.addrs.len() == resolved.len(),
                        "the name was offered to a proxy although an address was dropped"
                    );
                    prop_assert!(!event.resolved_ip.is_some_and(|a| is_denied(&a)));
                }
                if matches!(name, Ok(Decision::Allow { .. })) && resolved.iter().all(is_denied) {
                    let refusal = admitted.unwrap_err();
                    let rule = header(&refusal, "x-puddle-rule").map(str::to_owned);
                    prop_assert_eq!(header(&refusal, "x-puddle-decision"), Some("deny"));
                    prop_assert!(denied.iter().any(|(_, r)| Some(r.to_string()) == rule));
                    prop_assert_eq!(policy.ignore_calls.load(Ordering::SeqCst), 0);
                    prop_assert_eq!(event.decision, ConnectionDecision::Deny);
                }
            }
        }
    }
}

mod termination {
    use puddle_ca::CaBuilder;

    use super::*;
    use crate::terminate::{NoInjection, Termination, TerminationSet, Terminations};

    fn terminating_proxy() -> Proxy {
        let set = TerminationSet::parse(["github.com", "*.visualstudio.com"]).unwrap();
        let ca = Arc::new(
            CaBuilder::new("test", set.name_constraints().unwrap())
                .build()
                .unwrap(),
        );
        let terminations = Arc::new(Terminations::new());
        terminations.insert(
            workspace(),
            Termination::new(set, ca, Arc::new(NoInjection)).unwrap(),
        );
        proxy(Arc::new(StaticPolicy::new()), StaticResolver::new())
            .with_termination(terminations, puddle_upstream::TlsClient::new([]).unwrap())
    }

    fn at(h: &str, port: u16, workspace: WorkspaceName) -> EgressRequest {
        EgressRequest::new(workspace, host(h), port)
    }

    #[test]
    fn only_a_bound_name_on_443_for_a_workspace_with_a_termination_is_terminated() {
        let proxy = terminating_proxy();
        let terminated =
            |h: &str, port: u16| proxy.terminating(&at(h, port, workspace())).is_some();
        for (h, port) in [
            ("github.com", 443),
            ("dev.visualstudio.com", 443),
            ("a.b.visualstudio.com", 443),
        ] {
            assert!(terminated(h, port), "{h}:{port}");
        }
        for (h, port) in [
            // Another port, plain HTTP and SSH are never decrypted.
            ("github.com", 80),
            ("github.com", 8443),
            ("github.com", 22),
            ("github.com", 444),
            // Names that merely look like bound ones.
            ("api.github.com", 443),
            ("visualstudio.com", 443),
            ("evilgithub.com", 443),
            ("github.com.evil.example", 443),
            ("example.com", 443),
            // An address is never decrypted, even a GitHub one.
            ("140.82.112.3", 443),
            ("::1", 443),
            ("127.0.0.1", 443),
        ] {
            assert!(!terminated(h, port), "{h}:{port}");
        }
        let other = WorkspaceName::new("other").unwrap();
        assert!(proxy.terminating(&at("github.com", 443, other)).is_none());
    }

    #[test]
    fn a_proxy_without_a_termination_never_terminates() {
        let plain = proxy(Arc::new(StaticPolicy::new()), StaticResolver::new());
        assert!(plain.terminating(&request("github.com")).is_none());
    }
}
