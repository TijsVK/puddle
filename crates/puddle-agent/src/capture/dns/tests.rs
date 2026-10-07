// SPDX-License-Identifier: GPL-3.0-or-later
use std::sync::atomic::{AtomicUsize, Ordering};

use puddle_agent_proto::resolve::StandInReason;

use super::*;
use crate::capture::table::in_range;
use crate::capture::wire::tests::query_bytes;

const WAIT: Duration = Duration::from_secs(5);

/// What the fake host knows: a function from a query to its answer, counting the asks.
struct Fake<F> {
    f: F,
    asks: AtomicUsize,
}

impl<F> Fake<F> {
    fn new(f: F) -> Self {
        Self {
            f,
            asks: AtomicUsize::new(0),
        }
    }
}

impl<F, Fut> Ask for Arc<Fake<F>>
where
    F: Fn(ResolveQuery) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolveAnswer, ResolveError>> + Send + 'static,
{
    fn ask(
        &self,
        query: ResolveQuery,
    ) -> impl Future<Output = Result<ResolveAnswer, ResolveError>> + Send {
        self.asks.fetch_add(1, Ordering::SeqCst);
        (self.f)(query)
    }
}

fn stand_in() -> ResolveAnswer {
    ResolveAnswer::StandIn {
        why: StandInReason::Resolves,
        ttl: 60,
    }
}

type Handle<F> = Arc<Fake<F>>;

fn stub_with<F, Fut>(f: F, limits: Limits) -> (Stub<Handle<F>>, Handle<F>, StandIns)
where
    F: Fn(ResolveQuery) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolveAnswer, ResolveError>> + Send + 'static,
{
    let fake = Arc::new(Fake::new(f));
    let table = StandIns::in_memory();
    (
        Stub::new(Arc::clone(&fake), table.clone(), limits),
        fake,
        table,
    )
}

type Ready = std::future::Ready<Result<ResolveAnswer, ResolveError>>;
type Fixed = Handle<Box<dyn Fn(ResolveQuery) -> Ready + Send + Sync>>;

/// A host that gives `answer` to every question.
fn answers_with(answer: ResolveAnswer) -> (Stub<Fixed>, Fixed, StandIns) {
    stub_with(
        Box::new(move |_| std::future::ready(Ok(answer.clone())))
            as Box<dyn Fn(ResolveQuery) -> Ready + Send + Sync>,
        Limits::default(),
    )
}

/// A decoded response.
#[derive(Debug)]
struct Response {
    id: u16,
    flags: u16,
    questions: u16,
    answers: Vec<Rr>,
    additional: Vec<Rr>,
    len: usize,
}

#[derive(Debug, Clone)]
struct Rr {
    owner: String,
    rtype: u16,
    ttl: u32,
    rdata: Vec<u8>,
    message: Vec<u8>,
    rdata_at: usize,
}

impl Response {
    fn rcode(&self) -> u16 {
        self.flags & 0xF
    }
    fn truncated(&self) -> bool {
        self.flags & 0x200 != 0
    }
}

fn word(m: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([m[at], m[at + 1]])
}

/// Reads a name at `at` (following pointers); returns it and the offset after it in place.
fn read_name(m: &[u8], mut at: usize) -> (String, usize) {
    let mut name = String::new();
    let mut after = None;
    loop {
        let len = usize::from(m[at]);
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let target = usize::from(word(m, at) & 0x3FFF);
            after.get_or_insert(at + 2);
            at = target;
            continue;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(&m[at + 1..at + 1 + len]).unwrap());
        at += 1 + len;
    }
    (name, after.unwrap_or(at))
}

fn decode(m: &[u8]) -> Response {
    let (qd, an, ar) = (word(m, 4), word(m, 6), word(m, 10));
    let mut at = 12;
    for _ in 0..qd {
        let (_, next) = read_name(m, at);
        at = next + 4;
    }
    let rrs = |n: u16, at: &mut usize| -> Vec<Rr> {
        (0..n)
            .map(|_| {
                let (owner, next) = read_name(m, *at);
                let rtype = word(m, next);
                let ttl = u32::from_be_bytes([m[next + 4], m[next + 5], m[next + 6], m[next + 7]]);
                let rdlen = usize::from(word(m, next + 8));
                let rdata_at = next + 10;
                *at = rdata_at + rdlen;
                Rr {
                    owner,
                    rtype,
                    ttl,
                    rdata: m[rdata_at..rdata_at + rdlen].to_vec(),
                    message: m.to_vec(),
                    rdata_at,
                }
            })
            .collect()
    };
    let answers = rrs(an, &mut at);
    let additional = rrs(ar, &mut at);
    Response {
        id: word(m, 0),
        flags: word(m, 2),
        questions: qd,
        answers,
        additional,
        len: m.len(),
    }
}

impl Rr {
    fn ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3])
    }
    /// The target name of an SRV (after 6 bytes) or MX (after 2) record.
    fn target(&self, skip: usize) -> String {
        read_name(&self.message, self.rdata_at + skip).0
    }
}

async fn ask_stub<A: Ask>(stub: &Stub<A>, name: &str, qtype: u16) -> Response {
    let reply = stub
        .answer(&query_bytes(0x4242, name, qtype, None), true)
        .await
        .expect("an answer");
    let r = decode(&reply);
    assert_eq!(r.id, 0x4242);
    assert_eq!(r.questions, 1);
    r
}

#[tokio::test]
async fn an_address_query_gets_a_stand_in_from_the_range_and_the_same_one_every_time() {
    let (stub, fake, table) = answers_with(stand_in());
    let first = ask_stub(&stub, "api.example.com", TYPE_A).await;
    assert_eq!(first.rcode(), 0);
    assert_eq!(first.answers.len(), 1);
    let ip = first.answers[0].ip();
    assert!(in_range(ip));
    assert_eq!(first.answers[0].ttl, 60);
    assert_eq!(first.answers[0].owner, "api.example.com");
    assert_eq!(table.name_for(ip).as_deref(), Some("api.example.com"));
    let second = ask_stub(&stub, "API.example.com", TYPE_A).await;
    assert_eq!(second.answers[0].ip(), ip);
    let other = ask_stub(&stub, "other.example.com", TYPE_A).await;
    assert_ne!(other.answers[0].ip(), ip);
    assert_eq!(
        fake.asks.load(Ordering::SeqCst),
        2,
        "the second query was cached"
    );
}

#[tokio::test]
async fn a_hundred_parallel_queries_for_one_name_cost_one_lookup() {
    let (stub, fake, _) = stub_with(
        |_| async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(stand_in())
        },
        Limits::default(),
    );
    let mut set = JoinSet::new();
    for _ in 0..100 {
        let stub = stub.clone();
        set.spawn(async move { ask_stub(&stub, "busy.example.com", TYPE_A).await.answers[0].ip() });
    }
    let mut seen = std::collections::HashSet::new();
    while let Some(ip) = set.join_next().await {
        seen.insert(ip.unwrap());
    }
    assert_eq!(seen.len(), 1);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_answer_is_kept_for_the_time_the_host_said_and_asked_again_after() {
    let (stub, fake, _) = stub_with(
        |_| std::future::ready(Ok(ResolveAnswer::NoSuchName { ttl: 20 })),
        Limits::default(),
    );
    assert_eq!(ask_stub(&stub, "gone.example.com", TYPE_A).await.rcode(), 3);
    tokio::time::advance(Duration::from_secs(19)).await;
    assert_eq!(ask_stub(&stub, "gone.example.com", TYPE_A).await.rcode(), 3);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(ask_stub(&stub, "gone.example.com", TYPE_A).await.rcode(), 3);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_stand_in_ttl_given_to_the_guest_is_at_most_a_minute() {
    let (stub, _, _) = answers_with(ResolveAnswer::StandIn {
        why: StandInReason::ViaUpstream,
        ttl: 3600,
    });
    let r = ask_stub(&stub, "long.example.com", TYPE_A).await;
    assert_eq!(r.answers[0].ttl, 60);
    let (stub, _, _) = answers_with(ResolveAnswer::StandIn {
        why: StandInReason::Resolves,
        ttl: 0,
    });
    assert_eq!(
        ask_stub(&stub, "zero.example.com", TYPE_A).await.answers[0].ttl,
        1
    );
}

#[tokio::test]
async fn aaaa_is_nodata_without_asking_and_nxdomain_when_the_name_is_known_missing() {
    let (stub, fake, _) = answers_with(ResolveAnswer::NoSuchName { ttl: 30 });
    let r = ask_stub(&stub, "gone.example.com", 28).await;
    assert_eq!((r.rcode(), r.answers.len()), (0, 0));
    assert_eq!(fake.asks.load(Ordering::SeqCst), 0);
    // Once the A lookup found nothing, the other types agree.
    assert_eq!(ask_stub(&stub, "gone.example.com", TYPE_A).await.rcode(), 3);
    assert_eq!(ask_stub(&stub, "gone.example.com", 28).await.rcode(), 3);
    assert_eq!(ask_stub(&stub, "gone.example.com", 65).await.rcode(), 3);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn names_that_stay_in_the_sandbox_are_nxdomain_without_asking() {
    let (stub, fake, _) = answers_with(stand_in());
    for name in [
        "printer",
        "localhost",
        "host.local",
        "db.default.svc.cluster.local",
        "4.3.2.1.in-addr.arpa",
        "box.internal",
        "1.2.3.4",
    ] {
        for qtype in [TYPE_A, 28, TYPE_SRV, TYPE_TXT, 12] {
            let r = ask_stub(&stub, name, qtype).await;
            assert_eq!(r.rcode(), 3, "{name} type {qtype}");
        }
    }
    assert_eq!(fake.asks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn odd_names_and_foreign_classes_never_reach_the_host() {
    let (stub, fake, _) = answers_with(stand_in());
    let mut odd = query_bytes(1, "abcd.example.com", TYPE_A, None);
    odd[13] = 0x1B;
    let r = decode(&stub.answer(&odd, true).await.unwrap());
    assert_eq!(r.rcode(), 3);
    // A CHAOS-class query.
    let mut chaos = query_bytes(2, "version.bind", 16, None);
    let n = chaos.len();
    chaos[n - 1] = 3;
    let r = decode(&stub.answer(&chaos, true).await.unwrap());
    assert_eq!(r.rcode(), 5);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn garbage_is_dropped_or_answered_with_an_error_and_never_asks() {
    let (stub, fake, _) = answers_with(stand_in());
    assert!(stub.answer(&[1, 2, 3], true).await.is_none());
    let mut response = query_bytes(1, "example.com", TYPE_A, None);
    response[2] |= 0x80;
    assert!(stub.answer(&response, true).await.is_none());
    let mut two = query_bytes(9, "example.com", TYPE_A, None);
    two[5] = 2;
    let r = decode(&stub.answer(&two, true).await.unwrap());
    assert_eq!((r.id, r.rcode()), (9, 1));
    assert_eq!(fake.asks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_host_that_cannot_answer_is_servfail_and_not_remembered() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let (stub, fake, _) = stub_with(
        move |_| {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            std::future::ready(match n {
                0 => Ok(ResolveAnswer::Unavailable),
                1 => Err(ResolveError::NoAnswer),
                2 => Ok(ResolveAnswer::Unknown),
                _ => Ok(stand_in()),
            })
        },
        Limits::default(),
    );
    for _ in 0..3 {
        assert_eq!(
            ask_stub(&stub, "flaky.example.com", TYPE_A).await.rcode(),
            2
        );
    }
    let r = ask_stub(&stub, "flaky.example.com", TYPE_A).await;
    assert_eq!(r.rcode(), 0, "the next try asks again");
    assert_eq!(fake.asks.load(Ordering::SeqCst), 4);
}

#[tokio::test(start_paused = true)]
async fn a_host_that_never_answers_is_servfail_after_the_limit() {
    let (stub, _, _) = stub_with(
        |_| std::future::pending::<Result<ResolveAnswer, ResolveError>>(),
        Limits {
            ask_timeout: Duration::from_secs(2),
            ..Limits::default()
        },
    );
    assert_eq!(ask_stub(&stub, "hang.example.com", TYPE_A).await.rcode(), 2);
}

#[tokio::test(start_paused = true)]
async fn lookups_on_the_host_never_exceed_the_limit_and_queries_that_wait_too_long_fail() {
    struct Slot(Arc<AtomicUsize>);
    impl Drop for Slot {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let (current, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (c, p) = (Arc::clone(&current), Arc::clone(&peak));
    let (stub, _, _) = stub_with(
        move |_| {
            let now = c.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            let slot = Slot(Arc::clone(&c));
            async move {
                let _slot = slot;
                std::future::pending::<Result<ResolveAnswer, ResolveError>>().await
            }
        },
        Limits {
            ask_timeout: Duration::from_secs(2),
            max_asks: 2,
            ..Limits::default()
        },
    );
    let mut set = JoinSet::new();
    for i in 0..5 {
        let stub = stub.clone();
        set.spawn(async move {
            ask_stub(&stub, &format!("n{i}.example.com"), TYPE_A)
                .await
                .rcode()
        });
    }
    while let Some(rcode) = set.join_next().await {
        assert_eq!(rcode.unwrap(), 2);
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_host_answer_of_the_wrong_kind_is_not_passed_on() {
    let (stub, _, _) = answers_with(ResolveAnswer::Records {
        records: vec![],
        ttl: 30,
    });
    assert_eq!(ask_stub(&stub, "x.example.com", TYPE_A).await.rcode(), 2);
    let (stub, _, _) = answers_with(stand_in());
    assert_eq!(ask_stub(&stub, "x.example.com", TYPE_TXT).await.rcode(), 2);
}

#[tokio::test]
async fn srv_records_come_with_a_stand_in_for_each_target() {
    let (stub, fake, table) = answers_with(ResolveAnswer::Records {
        records: vec![
            HostRecord::Srv {
                priority: 0,
                weight: 5,
                port: 27017,
                target: "shard0.db.example.net".into(),
            },
            HostRecord::Srv {
                priority: 0,
                weight: 5,
                port: 27017,
                target: "shard1.db.example.net".into(),
            },
            HostRecord::Srv {
                priority: 1,
                weight: 1,
                port: 27017,
                target: "shard0.db.example.net".into(),
            },
            // Not plain: dropped. A TXT in an SRV answer: dropped. A local target: no stand-in.
            HostRecord::Srv {
                priority: 0,
                weight: 1,
                port: 1,
                target: "bad name.example".into(),
            },
            HostRecord::Txt {
                strings: vec!["x".into()],
            },
            HostRecord::Srv {
                priority: 2,
                weight: 1,
                port: 1,
                target: "single-label".into(),
            },
        ],
        ttl: 30,
    });
    let r = ask_stub(&stub, "_mongodb._tcp.db.example.net", TYPE_SRV).await;
    assert_eq!(r.rcode(), 0);
    assert_eq!(r.answers.len(), 4);
    assert_eq!(r.answers[0].rtype, TYPE_SRV);
    assert_eq!(word(&r.answers[0].rdata, 4), 27017);
    assert_eq!(r.answers[0].target(6), "shard0.db.example.net");
    assert_eq!(r.answers[1].target(6), "shard1.db.example.net");
    assert_eq!(r.answers[3].target(6), "single-label");
    // One stand-in per distinct target that isn't local, in the additional section.
    assert_eq!(r.additional.len(), 2);
    for extra in &r.additional {
        assert_eq!(extra.rtype, TYPE_A);
        assert_eq!(
            table.name_for(extra.ip()).as_deref(),
            Some(extra.owner.as_str())
        );
    }
    // The client's next query for a target is answered with the same stand-in, from the table.
    let a = ask_stub(&stub, "shard1.db.example.net", TYPE_A).await;
    assert_eq!(
        a.rcode(),
        2,
        "the fake host only knows records, so an A lookup fails"
    );
    assert_eq!(
        table.address_for("shard1.db.example.net").unwrap(),
        r.additional[1].ip()
    );
    assert_eq!(fake.asks.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn txt_and_mx_records_are_encoded_and_other_types_in_the_answer_are_dropped() {
    let (stub, _, _) = answers_with(ResolveAnswer::Records {
        records: vec![
            HostRecord::Txt {
                strings: vec!["authSource=admin".into(), "replicaSet=rs0".into()],
            },
            HostRecord::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            },
        ],
        ttl: 30,
    });
    let txt = ask_stub(&stub, "db.example.com", TYPE_TXT).await;
    assert_eq!(txt.answers.len(), 1);
    assert_eq!(txt.answers[0].rdata[0], 16);
    assert!(txt.additional.is_empty());
    let mx = ask_stub(&stub, "db.example.com", TYPE_MX).await;
    assert_eq!(mx.answers.len(), 1);
    assert_eq!(word(&mx.answers[0].rdata, 0), 10);
    assert_eq!(mx.answers[0].target(2), "mx.example.com");
    assert_eq!(mx.additional.len(), 1);
}

#[tokio::test]
async fn nodata_and_nxdomain_for_records_pass_through() {
    let (stub, _, _) = answers_with(ResolveAnswer::NoData { ttl: 20 });
    let r = ask_stub(&stub, "db.example.com", TYPE_SRV).await;
    assert_eq!((r.rcode(), r.answers.len()), (0, 0));
    let (stub, _, _) = answers_with(ResolveAnswer::NoSuchName { ttl: 20 });
    assert_eq!(ask_stub(&stub, "db.example.com", TYPE_TXT).await.rcode(), 3);
    // A record answer whose every record is unusable is NODATA.
    let (stub, _, _) = answers_with(ResolveAnswer::Records {
        records: vec![HostRecord::Txt { strings: vec![] }],
        ttl: 20,
    });
    let r = ask_stub(&stub, "db.example.com", TYPE_SRV).await;
    assert_eq!((r.rcode(), r.answers.len()), (0, 0));
}

#[tokio::test]
async fn the_cache_does_not_grow_past_its_limit() {
    let (stub, fake, _) = stub_with(
        |_| std::future::ready(Ok(stand_in())),
        Limits {
            cache_entries: 8,
            ..Limits::default()
        },
    );
    for i in 0..100 {
        ask_stub(&stub, &format!("n{i}.example.com"), TYPE_A).await;
    }
    assert_eq!(fake.asks.load(Ordering::SeqCst), 100);
    let held = stub.shared.cache.lock().unwrap().map.len();
    assert!(held <= 8, "{held}");
}

#[tokio::test]
async fn when_every_stand_in_is_in_use_the_answer_is_servfail() {
    let table = StandIns::open_with_capacity(None, 1);
    let fake = Arc::new(Fake::new(|_| std::future::ready(Ok(stand_in()))));
    let stub = Stub::new(Arc::clone(&fake), table.clone(), Limits::default());
    let first = ask_stub(&stub, "a.example.com", TYPE_A).await;
    let _held = table.hold(first.answers[0].ip()).unwrap();
    assert_eq!(ask_stub(&stub, "b.example.com", TYPE_A).await.rcode(), 2);
}

// ---- the sockets ----

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn serve<F, Fut>(f: F, limits: Limits) -> (DnsServer, Arc<Fake<F>>)
where
    F: Fn(ResolveQuery) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ResolveAnswer, ResolveError>> + Send + 'static,
{
    let (stub, fake, _) = stub_with(f, limits);
    (DnsServer::bind(stub, loopback()).await.unwrap(), fake)
}

async fn udp_query(server: &DnsServer, message: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(message, server.udp_addr()).await.unwrap();
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

async fn tcp_exchange(stream: &mut tokio::net::TcpStream, message: &[u8]) -> Option<Vec<u8>> {
    let mut framed = u16::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).await.ok()?;
    let mut len = [0u8; 2];
    tokio::time::timeout(WAIT, stream.read_exact(&mut len))
        .await
        .ok()?
        .ok()?;
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut answer).await.ok()?;
    Some(answer)
}

#[tokio::test]
async fn the_server_answers_over_udp_and_over_tcp_on_one_connection() {
    let (server, _) = serve(|_| std::future::ready(Ok(stand_in())), Limits::default()).await;
    let udp = udp_query(
        &server,
        &query_bytes(1, "udp.example.com", TYPE_A, Some(1232)),
    )
    .await
    .unwrap();
    let r = decode(&udp);
    assert_eq!((r.id, r.rcode(), r.answers.len()), (1, 0, 1));
    assert_eq!(r.additional.len(), 1, "the OPT echo");
    let mut tcp = tokio::net::TcpStream::connect(server.tcp_addr())
        .await
        .unwrap();
    for i in 0..3u16 {
        let answer = tcp_exchange(&mut tcp, &query_bytes(i, "tcp.example.com", TYPE_A, None))
            .await
            .unwrap();
        let r = decode(&answer);
        assert_eq!((r.id, r.answers.len()), (i, 1));
    }
    assert_ne!(server.udp_addr().port(), 0);
}

#[tokio::test]
async fn a_large_answer_is_truncated_over_udp_and_whole_over_tcp() {
    let (server, _) = serve(
        |_| {
            std::future::ready(Ok(ResolveAnswer::Records {
                records: vec![HostRecord::Txt {
                    strings: vec!["z".repeat(2000)],
                }],
                ttl: 30,
            }))
        },
        Limits::default(),
    )
    .await;
    let q = query_bytes(5, "big.example.com", TYPE_TXT, None);
    let udp = decode(&udp_query(&server, &q).await.unwrap());
    assert!(udp.truncated());
    assert!(udp.answers.is_empty());
    assert!(udp.len <= 512);
    let mut tcp = tokio::net::TcpStream::connect(server.tcp_addr())
        .await
        .unwrap();
    let whole = decode(&tcp_exchange(&mut tcp, &q).await.unwrap());
    assert!(!whole.truncated());
    assert_eq!(whole.answers.len(), 1);
}

#[tokio::test]
async fn bad_udp_and_tcp_input_gets_an_error_or_nothing_and_the_server_carries_on() {
    let (server, fake) = serve(|_| std::future::ready(Ok(stand_in())), Limits::default()).await;
    assert!(udp_query(&server, &[0xFF; 5]).await.is_none());
    let mut two = query_bytes(3, "example.com", TYPE_A, None);
    two[5] = 2;
    let r = decode(&udp_query(&server, &two).await.unwrap());
    assert_eq!(r.rcode(), 1);
    // TCP: a zero length, an over-long length and a cut message each end the connection.
    for first in [vec![0u8, 0], vec![0xFF, 0xFF], vec![0, 40, 1, 2]] {
        let mut tcp = tokio::net::TcpStream::connect(server.tcp_addr())
            .await
            .unwrap();
        tcp.write_all(&first).await.unwrap();
        if first.len() > 2 {
            tcp.shutdown().await.unwrap();
        }
        let mut sink = Vec::new();
        let read = tokio::time::timeout(WAIT, tcp.read_to_end(&mut sink))
            .await
            .unwrap();
        assert!(read.is_ok() || read.is_err());
        assert_eq!(sink, Vec::<u8>::new());
    }
    let ok = udp_query(&server, &query_bytes(4, "example.com", TYPE_A, None))
        .await
        .unwrap();
    assert_eq!(decode(&ok).answers.len(), 1);
    assert_eq!(fake.asks.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn an_idle_tcp_connection_is_closed() {
    let (server, _) = serve(
        |_| std::future::ready(Ok(stand_in())),
        Limits {
            tcp_idle: Duration::from_secs(3),
            ..Limits::default()
        },
    )
    .await;
    let mut tcp = tokio::net::TcpStream::connect(server.tcp_addr())
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut buf))
        .await
        .expect("the server closes an idle connection");
    assert_eq!(n.unwrap(), 0);
}

#[tokio::test]
async fn tcp_connections_over_the_limit_are_closed() {
    let (server, _) = serve(
        |_| std::future::ready(Ok(stand_in())),
        Limits {
            max_tcp_connections: 2,
            ..Limits::default()
        },
    )
    .await;
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut c = tokio::net::TcpStream::connect(server.tcp_addr())
            .await
            .unwrap();
        assert!(
            tcp_exchange(&mut c, &query_bytes(1, "a.example.com", TYPE_A, None))
                .await
                .is_some()
        );
        held.push(c);
    }
    let mut third = tokio::net::TcpStream::connect(server.tcp_addr())
        .await
        .unwrap();
    assert!(
        tcp_exchange(&mut third, &query_bytes(1, "a.example.com", TYPE_A, None))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn binding_waits_for_an_address_that_is_taken_and_then_serves() {
    let taken = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listen = taken.local_addr().unwrap();
    let (stub, _, _) = answers_with(stand_in());
    assert!(DnsServer::bind(stub.clone(), listen).await.is_err());
    let task = tokio::spawn(bind_when_ready(stub, listen));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(!task.is_finished());
    drop(taken);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // The server needs both UDP and TCP on `listen`: once it is up, a query is answered.
    let mut answered = false;
    for _ in 0..40 {
        socket
            .send_to(&query_bytes(7, "x.example.com", TYPE_A, None), listen)
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            && decode(&buf[..n]).answers.len() == 1
        {
            answered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    task.abort();
    assert!(answered);
}

#[tokio::test]
async fn asking_through_an_unreachable_host_is_an_error_not_a_hang() {
    let upstream = Arc::new(Upstream::new(&crate::Config {
        target: crate::config::Target::Unix("/nonexistent/puddle-route.sock".into()),
        ..crate::Config::default()
    }));
    let ask = HostAsk::new(upstream, Duration::from_secs(2));
    let result = ask
        .ask(ResolveQuery::new("example.com", RecordType::A))
        .await;
    assert!(result.is_err());
}

#[test]
fn only_answers_of_the_asked_kind_are_kept() {
    for (rtype, answer, kept) in [
        (RecordType::A, stand_in(), true),
        (RecordType::A, ResolveAnswer::NoData { ttl: 1 }, true),
        (
            RecordType::A,
            ResolveAnswer::Records {
                records: vec![],
                ttl: 1,
            },
            false,
        ),
        (RecordType::Txt, stand_in(), false),
        (RecordType::Mx, ResolveAnswer::NoSuchName { ttl: 1 }, true),
        (RecordType::Srv, ResolveAnswer::Unknown, false),
    ] {
        let fitted = fit_to(rtype, answer.clone());
        assert_eq!(fitted == answer, kept, "{rtype:?} {answer:?}");
        if !kept {
            assert_eq!(fitted, ResolveAnswer::Unavailable);
        }
    }
}
