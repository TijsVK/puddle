// SPDX-License-Identifier: GPL-3.0-or-later
//! Decision, address and refusal logic without a guest stream. The full path over a route is in
//! `tests/route.rs`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use puddle_types::{NullSink, RuleId};
use tokio::net::TcpListener;

use super::*;
use crate::testing::{AnyAddress, StaticPolicy, StaticResolver};

fn sandbox() -> SandboxName {
    SandboxName::new("box").unwrap()
}

fn host(h: &str) -> Host {
    normalise_host(h).unwrap()
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
    fn check(&self, _: &SandboxName, addr: IpAddr) -> AddressVerdict {
        match addr {
            IpAddr::V4(a) if a.octets()[0] == 10 => AddressVerdict::ExactOnly,
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
    assert_eq!(header(&refusal, "x-puddle-blocked"), Some("local_address"));
    assert!(refusal.message.contains("local addresses"));
}

#[tokio::test]
async fn an_allowed_ip_literal_is_checked_without_resolving() {
    let policy = Arc::new(StaticPolicy::new());
    policy.allow(&host("10.1.2.3"));
    policy.allow(&host("1.1.1.1"));
    let p = proxy(policy, StaticResolver::new());
    let refusal = admit(&p, &request("10.1.2.3")).await.unwrap_err();
    assert_eq!(header(&refusal, "x-puddle-blocked"), Some("local_address"));
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
