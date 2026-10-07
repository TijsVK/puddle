// SPDX-License-Identifier: GPL-3.0-or-later
//! L2 end to end, no VM: a DNS client → the guest agent's stub DNS → a `resolve` stream over the
//! sandbox's real endpoint (a Unix socket) → the real proxy with the real SQLite rules engine.
//!
//! The doubles are the host's resolvers (they count their lookups) and the address check.
//! Hostile cases speak to the route directly, without the agent.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "helpers outside #[test] functions fail the test by panicking, and the DNS client reads answers the test knows the shape of"
)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt as _;
use puddle_agent::config::{DnsConfig, Target};
use puddle_agent::{Agent, Config};
use puddle_agent_proto::resolve::{
    self, Record, RecordType, ResolveAnswer, ResolveQuery, StandInReason,
};
use puddle_agent_proto::tokio_yamux::{Control, Session};
use puddle_agent_proto::yamux::client_config;
use puddle_ipc::IpcRoot;
use puddle_proxy::testing::{AnyAddress, StaticRecords, StaticResolver};
use puddle_proxy::{Proxy, ProxyConfig, Route, Upstream};
use puddle_store::{Actor, Effect, Limits, NewRule, Pattern, Scope, Store, SystemClock};
use puddle_types::{NullSink, SandboxName};
use puddle_upstream::{Chain, Config as UpstreamConfig, Discovery, FakeOs, Hop, NoAuth, ProxyAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_SRV: u16 = 33;

fn sandbox() -> SandboxName {
    SandboxName::new("dns").unwrap()
}

/// Counts what the host's resolvers were asked.
struct Counted {
    resolver: Arc<StaticResolver>,
    records: Arc<StaticRecords>,
}

struct Rig {
    store: Arc<Store>,
    counted: Counted,
    agent: Agent,
    route: Route,
    _root: IpcRoot,
}

fn company_proxy() -> Upstream {
    let os = FakeOs::new(puddle_upstream::ProxyConfig {
        pac_url: Some("http://pac.corp/p.pac".into()),
        ..puddle_upstream::ProxyConfig::default()
    });
    os.set_pac(|_| Ok(vec![Hop::Proxy(ProxyAddr::new("127.0.0.1", 1))]));
    Upstream::new(Chain::new(
        Discovery::new(os, UpstreamConfig::default()),
        Arc::new(NoAuth),
    ))
}

#[derive(Default)]
struct Options {
    table: Option<std::path::PathBuf>,
    upstream: Option<Upstream>,
    config: ProxyConfig,
}

async fn rig_with(options: Options) -> Rig {
    let store = Arc::new(Store::open_in_memory(Arc::new(SystemClock), Limits::default()).unwrap());
    let resolver = Arc::new(
        StaticResolver::new()
            .with(
                "api.example.com",
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))],
            )
            .with(
                "wild.example.org",
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 215, 15))],
            ),
    );
    let records = Arc::new(
        StaticRecords::new()
            .with(
                "_mongodb._tcp.db.example.net",
                RecordType::Srv,
                vec![
                    Record::Srv {
                        priority: 0,
                        weight: 1,
                        port: 27017,
                        target: "shard0.db.example.net".into(),
                    },
                    Record::Srv {
                        priority: 0,
                        weight: 1,
                        port: 27017,
                        target: "shard1.db.example.net".into(),
                    },
                ],
            )
            .with(
                "db.example.net",
                RecordType::Txt,
                vec![Record::Txt {
                    strings: vec!["authSource=admin".into()],
                }],
            ),
    );
    let mut proxy = Proxy::new(store.clone(), Arc::new(NullSink))
        .with_connection_log(store.clone())
        .with_resolver(resolver.clone())
        .with_record_resolver(records.clone())
        .with_address_check(Arc::new(AnyAddress))
        .with_config(options.config);
    if let Some(upstream) = options.upstream {
        proxy = proxy.with_upstream(upstream);
    }
    let root = IpcRoot::new().unwrap();
    let route = Arc::new(proxy).serve_route(root.listen().unwrap(), sandbox());
    let config = Config {
        listen: SocketAddr::new(LOCAL, 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        bridge: None,
        dns: Some(DnsConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            table: options.table,
        }),
        ..Config::default()
    };
    let agent = Agent::start(config).await.unwrap();
    Rig {
        store,
        counted: Counted { resolver, records },
        agent,
        route,
        _root: root,
    }
}

async fn rig() -> Rig {
    rig_with(Options::default()).await
}

fn allow(store: &Store, host: &str) {
    store
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sandbox()),
            pattern: Pattern::parse(host).unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
}

fn deny(store: &Store, host: &str) {
    store
        .add_rule(&NewRule {
            scope: Scope::Sandbox(sandbox()),
            pattern: Pattern::parse(host).unwrap(),
            effect: Effect::Deny,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
}

/// What the proxy wrote because of what the guest did: pending requests, and audit lines other
/// than the rules this test set up.
fn footprint(store: &Store) -> (usize, usize) {
    let audit = store
        .audit_lines(0, 100_000)
        .unwrap()
        .into_iter()
        .filter(|(_, line)| !line.contains("\"type\":\"rule_"))
        .count();
    (store.open_pending(None).unwrap().len(), audit)
}

// ---- a minimal DNS client ----

fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        m.push(u8::try_from(label.len()).unwrap());
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0]);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

#[derive(Debug)]
struct Reply {
    rcode: u16,
    answers: u16,
    additional: u16,
    /// The data of the first answer.
    first: Vec<u8>,
}

fn word(m: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes([m[at], m[at + 1]]))
}

fn parse(m: &[u8]) -> Reply {
    let mut at = 12;
    while m[at] != 0 {
        at += 1 + usize::from(m[at]);
    }
    at += 1 + 4;
    let answers = word(m, 6);
    let first = if answers > 0 {
        // Name pointer (2), type, class, ttl (4), rdlength.
        let len = word(m, at + 10);
        m[at + 12..at + 12 + len].to_vec()
    } else {
        Vec::new()
    };
    Reply {
        rcode: u16::try_from(word(m, 2) & 0xF).unwrap(),
        answers: u16::try_from(answers).unwrap(),
        additional: u16::try_from(word(m, 10)).unwrap(),
        first,
    }
}

async fn dns(server: SocketAddr, name: &str, qtype: u16) -> Reply {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for attempt in 0..5 {
        socket
            .send_to(&query(7, name, qtype), server)
            .await
            .unwrap();
        let mut buf = vec![0u8; 2048];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
        {
            return parse(&buf[..n]);
        }
        assert!(attempt < 4, "no answer for {name}");
    }
    unreachable!()
}

fn ip_of(reply: &Reply) -> Ipv4Addr {
    Ipv4Addr::new(
        reply.first[0],
        reply.first[1],
        reply.first[2],
        reply.first[3],
    )
}

// ---- the cases ----

#[tokio::test]
async fn an_allowed_name_gets_a_stand_in_that_maps_back_after_one_lookup_on_the_host() {
    let rig = rig().await;
    allow(&rig.store, "api.example.com");
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let reply = dns(udp, "api.example.com", TYPE_A).await;
    assert_eq!((reply.rcode, reply.answers), (0, 1));
    let ip = ip_of(&reply);
    assert!(puddle_agent::capture::table::in_range(ip), "{ip}");
    let table = rig.agent.stand_ins().unwrap();
    assert_eq!(table.name_for(ip).as_deref(), Some("api.example.com"));
    assert_eq!(rig.counted.resolver.lookups(), 1);
    // Again: the same address, from the stub's cache, so no second lookup.
    assert_eq!(ip_of(&dns(udp, "api.example.com", TYPE_A).await), ip);
    assert_eq!(rig.counted.resolver.lookups(), 1);
    // The lookup wrote nothing: no pending row, no audit line.
    assert_eq!(footprint(&rig.store), (0, 0));
}

#[tokio::test]
async fn a_wildcard_rule_allows_the_names_below_it() {
    let rig = rig().await;
    allow(&rig.store, ".example.org");
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let reply = dns(udp, "wild.example.org", TYPE_A).await;
    assert_eq!((reply.rcode, reply.answers), (0, 1));
    assert_eq!(rig.counted.resolver.lookups(), 1);
}

#[tokio::test]
async fn an_allowed_name_the_host_cannot_resolve_is_nxdomain() {
    let rig = rig().await;
    allow(&rig.store, "missing.example.com");
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    assert_eq!(dns(udp, "missing.example.com", TYPE_A).await.rcode, 3);
    // The AAAA query that follows agrees without asking.
    let asked = rig.counted.resolver.lookups();
    assert_eq!(dns(udp, "missing.example.com", TYPE_AAAA).await.rcode, 3);
    assert_eq!(rig.counted.resolver.lookups(), asked);
}

#[tokio::test]
async fn with_a_company_proxy_in_the_route_an_unresolvable_allowed_name_gets_a_stand_in() {
    let rig = rig_with(Options {
        upstream: Some(company_proxy()),
        ..Options::default()
    })
    .await;
    allow(&rig.store, "only-at-the-proxy.example.com");
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let reply = dns(udp, "only-at-the-proxy.example.com", TYPE_A).await;
    assert_eq!((reply.rcode, reply.answers), (0, 1));
    let table = rig.agent.stand_ins().unwrap();
    assert_eq!(
        table.name_for(ip_of(&reply)).as_deref(),
        Some("only-at-the-proxy.example.com")
    );
}

#[tokio::test]
async fn a_name_nothing_allows_gets_a_stand_in_and_leaves_no_host_lookup_and_no_row() {
    let rig = rig().await;
    deny(&rig.store, "denied.example.com");
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    for name in [
        "unknown.example.net",
        "denied.example.com",
        "api.example.com",
    ] {
        let reply = dns(udp, name, TYPE_A).await;
        assert_eq!((reply.rcode, reply.answers), (0, 1), "{name}");
        // AAAA and TXT of the same name.
        assert_eq!(dns(udp, name, TYPE_AAAA).await.answers, 0);
        assert_eq!(dns(udp, name, TYPE_TXT).await.answers, 0);
    }
    assert_eq!(rig.counted.resolver.lookups(), 0);
    assert_eq!(rig.counted.records.lookups(), 0);
    assert_eq!(footprint(&rig.store), (0, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hundred_thousand_random_denied_names_cause_no_host_lookup_and_no_rows() {
    let rig = Arc::new(rig().await);
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let answered = Arc::new(AtomicU64::new(0));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    for worker in 0..16u32 {
        let answered = Arc::clone(&answered);
        workers.push(tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut buf = vec![0u8; 2048];
            for i in 0..6_250u32 {
                let name = format!(
                    "leak-{worker:x}-{i:x}-{:x}.attacker.example",
                    i.wrapping_mul(2_654_435_761)
                );
                let qtype = [TYPE_A, TYPE_AAAA, TYPE_TXT][usize::try_from(i % 3).unwrap()];
                loop {
                    socket.send_to(&query(1, &name, qtype), udp).await.unwrap();
                    if let Ok(Ok(_)) =
                        tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
                            .await
                    {
                        break;
                    }
                }
                answered.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }
    for w in workers {
        w.await.unwrap();
    }
    assert_eq!(answered.load(Ordering::SeqCst), 100_000);
    assert_eq!(rig.counted.resolver.lookups(), 0);
    assert_eq!(rig.counted.records.lookups(), 0);
    assert_eq!(footprint(&rig.store), (0, 0));
    let table = rig.agent.stand_ins().unwrap();
    assert!(table.len() <= puddle_agent::capture::table::CAPACITY);
    assert!(
        table.len() >= 33_000,
        "the A names each got a stand-in: {}",
        table.len()
    );
}

#[tokio::test]
async fn srv_and_txt_are_forwarded_for_an_allowed_name_with_a_stand_in_for_each_target() {
    let rig = rig().await;
    allow(&rig.store, "db.example.net");
    let (udp, tcp) = rig.agent.dns_addrs().unwrap();
    let srv = dns(udp, "_mongodb._tcp.db.example.net", TYPE_SRV).await;
    assert_eq!((srv.rcode, srv.answers, srv.additional), (0, 2, 2));
    assert_eq!(u16::from_be_bytes([srv.first[4], srv.first[5]]), 27017);
    let txt = dns(udp, "db.example.net", TYPE_TXT).await;
    assert_eq!((txt.rcode, txt.answers), (0, 1));
    assert_eq!(&txt.first[1..], b"authSource=admin");
    // The same over TCP.
    let mut stream = tokio::net::TcpStream::connect(tcp).await.unwrap();
    let q = query(3, "db.example.net", TYPE_TXT);
    stream
        .write_all(&[&u16::try_from(q.len()).unwrap().to_be_bytes()[..], &q].concat())
        .await
        .unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(parse(&answer).answers, 1);
    // The service name is decided as the cluster's name: an unallowed one gets no records.
    let none = dns(udp, "_mongodb._tcp.other.example.net", TYPE_SRV).await;
    assert_eq!((none.rcode, none.answers), (0, 0));
    assert_eq!(footprint(&rig.store), (0, 0));
}

#[tokio::test]
async fn names_that_stay_in_the_sandbox_never_reach_the_host() {
    let rig = rig().await;
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    for name in [
        "printer",
        "box.local",
        "db.default.svc.cluster.local",
        "1.0.0.127.in-addr.arpa",
    ] {
        assert_eq!(dns(udp, name, TYPE_A).await.rcode, 3, "{name}");
    }
    assert_eq!(footprint(&rig.store), (0, 0));
    assert_eq!(rig.counted.resolver.lookups(), 0);
}

#[tokio::test]
async fn a_restarted_agent_keeps_every_address_it_handed_out() {
    let dir = tempfile::tempdir().unwrap();
    let table = dir.path().join("run/dns-table");
    let rig = rig_with(Options {
        table: Some(table.clone()),
        ..Options::default()
    })
    .await;
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let first = ip_of(&dns(udp, "kept.example.com", TYPE_A).await);
    let second = ip_of(&dns(udp, "kept-too.example.com", TYPE_A).await);
    drop(rig);

    let rig = rig_with(Options {
        table: Some(table),
        ..Options::default()
    })
    .await;
    let (udp, _) = rig.agent.dns_addrs().unwrap();
    let stand_ins = rig.agent.stand_ins().unwrap();
    // A client that cached the address before the restart still resolves back to the name.
    assert_eq!(
        stand_ins.name_for(first).as_deref(),
        Some("kept.example.com")
    );
    assert_eq!(
        ip_of(&dns(udp, "kept-too.example.com", TYPE_A).await),
        second
    );
    assert_ne!(ip_of(&dns(udp, "new.example.com", TYPE_A).await), first);
}

// ---- a hostile guest talking to the route itself ----

async fn raw_guest(route: &Route) -> (Control, JoinHandle<()>) {
    let conn = puddle_ipc::connect(route.endpoint().path()).await.unwrap();
    let mut session = Session::new_client(conn, client_config());
    let control = session.control();
    let driver = tokio::spawn(async move { while let Some(Ok(_)) = session.next().await {} });
    (control, driver)
}

#[tokio::test]
async fn a_guest_that_speaks_to_the_route_directly_gets_the_same_answers_and_no_more() {
    let rig = rig().await;
    allow(&rig.store, "api.example.com");
    let (control, driver) = raw_guest(&rig.route).await;
    let ask = |name: &'static str, rtype| {
        let mut control = control.clone();
        async move {
            let stream = control.open_stream().await.unwrap();
            resolve::ask(
                stream,
                &ResolveQuery::new(name, rtype),
                Duration::from_secs(5),
            )
            .await
        }
    };
    assert_eq!(
        ask("api.example.com", RecordType::A).await.unwrap(),
        ResolveAnswer::StandIn {
            why: StandInReason::Resolves,
            ttl: 60
        }
    );
    assert_eq!(
        ask("random-abc.attacker.example", RecordType::A)
            .await
            .unwrap(),
        ResolveAnswer::StandIn {
            why: StandInReason::NotAllowed,
            ttl: 60
        }
    );
    assert!(matches!(
        ask("random-abc.attacker.example", RecordType::Txt)
            .await
            .unwrap(),
        ResolveAnswer::NoData { .. }
    ));
    // Names that are not names, and the sandbox is never the guest's to choose.
    for odd in ["", "1.2.3.4", "a b.example", "\u{1b}[2K.example"] {
        assert!(matches!(
            ask(odd, RecordType::A).await.unwrap(),
            ResolveAnswer::NoSuchName { .. }
        ));
    }
    assert_eq!(
        rig.counted.resolver.lookups(),
        1,
        "only the allowed name was looked up"
    );
    // Garbage on a resolve stream and an over-long line end that stream without an answer, and the
    // session keeps working.
    for bytes in [
        [&b"\0puddle-resolve/1\n"[..], b"{not json}\n"].concat(),
        [&b"\0puddle-resolve/1\n"[..], &vec![b'x'; 4096]].concat(),
    ] {
        let mut stream = control.clone().open_stream().await.unwrap();
        // The host stops reading after the bad line.
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.write_all(&bytes)).await;
        let mut back = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut back)).await;
        assert_eq!(back, Vec::<u8>::new());
    }
    assert!(ask("api.example.com", RecordType::A).await.is_ok());
    assert_eq!(footprint(&rig.store), (0, 0));
    driver.abort();
}

#[tokio::test]
async fn a_guest_that_floods_lookups_of_an_allowed_name_over_a_stuck_resolver_hits_the_caps() {
    // A resolver that never answers: the sandbox's lookup cap (32) and the session cap (64) hold.
    struct Stuck;
    impl puddle_proxy::Resolver for Stuck {
        fn resolve<'a>(
            &'a self,
            _name: &'a puddle_types::DomainName,
            _port: u16,
        ) -> puddle_proxy::BoxFuture<'a, std::io::Result<Vec<SocketAddr>>> {
            Box::pin(std::future::pending())
        }
    }
    let store = Arc::new(Store::open_in_memory(Arc::new(SystemClock), Limits::default()).unwrap());
    allow(&store, ".example.com");
    let proxy = Proxy::new(store.clone(), Arc::new(NullSink))
        .with_resolver(Arc::new(Stuck))
        .with_address_check(Arc::new(AnyAddress))
        .with_config(ProxyConfig::default().with_lookup_limits(Duration::from_secs(2), 32));
    let root = IpcRoot::new().unwrap();
    let route = Arc::new(proxy).serve_route(root.listen().unwrap(), sandbox());
    let (control, driver) = raw_guest(&route).await;
    let mut set = tokio::task::JoinSet::new();
    for i in 0..200 {
        let mut control = control.clone();
        set.spawn(async move {
            let stream = control.open_stream().await.unwrap();
            resolve::ask(
                stream,
                &ResolveQuery::new(format!("n{i}.example.com"), RecordType::A),
                Duration::from_secs(10),
            )
            .await
            .unwrap()
        });
    }
    let mut unavailable = 0;
    while let Some(answer) = set.join_next().await {
        if answer.unwrap() == ResolveAnswer::Unavailable {
            unavailable += 1;
        }
    }
    // All 200 are refused or time out: none hangs the host, and every one gets an answer.
    assert_eq!(unavailable, 200);
    driver.abort();
}
