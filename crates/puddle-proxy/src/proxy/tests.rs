// SPDX-License-Identifier: GPL-3.0-or-later
//! Decision, address and refusal logic without a guest stream. The full path over a route is in
//! `tests/route.rs`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use puddle_types::{NullSink, PendingId, RuleId};
use tokio::net::TcpListener;

use super::*;
use crate::testing::{AnyAddress, StaticPolicy, StaticResolver};

fn sandbox() -> SandboxName {
    SandboxName::new("box").unwrap()
}

fn host(h: &str) -> Host {
    normalise_host(h).unwrap().into_host()
}

fn request(h: &str) -> EgressRequest {
    EgressRequest::new(sandbox(), host(h), 443)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn proxy(policy: Arc<dyn Policy>, resolver: StaticResolver) -> Proxy {
    Proxy::new(policy, Arc::new(NullSink)).with_resolver(Arc::new(resolver))
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
    fn check(&self, _: &SandboxName, addr: SocketAddr) -> AddressVerdict {
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
    assert_eq!(items[0].sandbox, sandbox());
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
        .with_max_streams_per_sandbox(7)
        .with_max_sessions_per_route(3)
        .with_session(HostConfig {
            control_burst: 1,
            ..HostConfig::default()
        });
    assert_eq!(c.head_timeout, Duration::from_secs(1));
    assert_eq!(c.max_streams_per_sandbox, 7);
    assert_eq!(c.max_sessions_per_route, 3);
    assert_eq!(c.session.control_burst, 1);
    let p = Proxy::new(Arc::new(StaticPolicy::new()), Arc::new(NullSink))
        .with_address_check(Arc::new(AnyAddress))
        .with_config(c);
    assert_eq!(p.config().max_streams_per_sandbox, 7);
    assert!(format!("{p:?}").contains("max_streams_per_sandbox: 7"));
    let handler = Arc::new(p).handler(sandbox());
    assert_eq!(handler.sandbox(), &sandbox());
}

// T-132: the real guard (`puddle_netpolicy::NetPolicy`) in the proxy. Ports of T-005's HG-06 to
// HG-08, T-052's D-37 and T-059's D-44 cases, and D-26.

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
    async fn d37_toggle_on_unlisted_local_destination_goes_to_approval_not_through() {
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
    async fn d37_toggle_on_and_exactly_allowed_local_destination_is_allowed() {
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
    async fn d37_toggle_off_allowed_local_destination_is_blocked_naming_the_toggle() {
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
            refusal
                .message
                .contains("turn on 'private' (local/private network) globally or for sandbox box"),
            "{}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn d44_wildcard_allow_does_not_reach_a_local_address_with_the_setting_off() {
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
    async fn d44_exact_ip_rule_admits_the_local_address_of_a_wildcard_name() {
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
        policy.deny_host(&host("192.168.1.30"));
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
        // A neighbour with no IP rule, or an address with an IP deny, goes pending for the name.
        for h in ["other.nip.example", "denied.nip.example"] {
            let refusal = admit(&p, &request(h)).await.unwrap_err();
            assert_eq!(
                header(&refusal, "x-puddle-decision"),
                Some("pending"),
                "{h}"
            );
            assert!(
                refusal
                    .message
                    .contains("add an exact rule for its address"),
                "{h}: {}",
                refusal.message
            );
        }
        let pending: Vec<Host> = policy.pending().into_iter().map(|p| p.host).collect();
        assert_eq!(
            pending,
            vec![host("other.nip.example"), host("denied.nip.example")]
        );
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
    async fn d44_failed_or_missing_ip_lookup_admits_nothing() {
        let resolver = || StaticResolver::new().with("nas.nip.example", &[ip("192.168.1.20")]);
        // `lookup` errors: the address isn't admitted and the name goes pending.
        let broken = Arc::new(BrokenLookup(StaticPolicy::new()));
        let p = guarded(broken.clone(), resolver(), all_on());
        let refusal = admit(&p, &request("nas.nip.example")).await.unwrap_err();
        assert_eq!(header(&refusal, "x-puddle-decision"), Some("pending"));
        assert_eq!(broken.0.pending().len(), 1);
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
    async fn d26_puddle_endpoints_are_blocked_whatever_the_toggles_and_rules_say() {
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
}
