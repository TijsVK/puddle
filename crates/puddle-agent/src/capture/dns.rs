// SPDX-License-Identifier: GPL-3.0-or-later
//! The stub DNS server.
//!
//! Tools that ignore the proxy settings resolve a name and connect to the answer. The stub answers
//! every address query for a name the host doesn't rule out with a stand-in address from
//! [`super::table`], and the capture rules send the connection to the agent, which sends the
//! name to the host's proxy like any other client of it.
//!
//! What the stub answers itself, without asking the host:
//!
//! - names that never leave the sandbox ([`names::is_local_only`]): `NXDOMAIN`;
//! - `AAAA` and every other type that isn't forwarded: `NODATA` (so dual-stack clients use the
//!   stand-in at once), or `NXDOMAIN` when the name is already known not to exist;
//! - anything it already learned recently (the cache, for the time the host said).
//!
//! The rest is one lookup on a `resolve` stream ([`puddle_agent_proto::resolve`]); concurrent
//! queries for the same name share one lookup. The host decides with the sandbox's rules, and a
//! name it doesn't allow gets a stand-in without being looked up anywhere.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::FutureExt as _;
use futures_util::future::{BoxFuture, Shared};
use puddle_agent_proto::resolve::{
    self, Record as HostRecord, RecordType, ResolveAnswer, ResolveError, ResolveQuery,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::names;
use super::table::StandIns;
use super::wire::{
    self, CLASS_IN, MAX_QUERY, QueryName, Rcode, Rdata, Record, Reject, TYPE_A, TYPE_MX, TYPE_SRV,
    TYPE_TXT,
};
use crate::upstream::Upstream;

/// Longest time (seconds) a stand-in answer may be cached by the guest.
const GUEST_TTL_CAP: u32 = 60;
/// The range a host-given time to live is kept in for the stub's own cache (seconds).
const CACHE_TTL: (u32, u32) = (1, 300);

/// Limits of the stub. The defaults suit a real guest; tests shorten them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long one lookup on the host may take (and how long a query waits for a free slot).
    pub ask_timeout: Duration,
    /// Lookups on the host in flight at once.
    pub max_asks: usize,
    /// Answers kept (the cache is emptied of expired ones, then cleared, when full).
    pub cache_entries: usize,
    /// UDP queries handled at once; more are dropped (the client retries).
    pub max_udp_queries: usize,
    /// TCP connections open at once; more are closed.
    pub max_tcp_connections: usize,
    /// How long a TCP connection may sit idle.
    pub tcp_idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            ask_timeout: Duration::from_secs(5),
            max_asks: 64,
            cache_entries: 4096,
            max_udp_queries: 256,
            max_tcp_connections: 64,
            tcp_idle: Duration::from_secs(10),
        }
    }
}

/// How the stub asks the host about a name: one lookup per call.
pub trait Ask: Send + Sync + 'static {
    /// Asks the host.
    ///
    /// # Errors
    ///
    /// [`ResolveError`] when there is no answer (stream failed, timed out, bad answer).
    fn ask(
        &self,
        query: ResolveQuery,
    ) -> impl Future<Output = Result<ResolveAnswer, ResolveError>> + Send;
}

/// Asks the host over a fresh `resolve` stream of the agent's sessions.
#[derive(Debug)]
pub struct HostAsk {
    upstream: Arc<Upstream>,
    limit: Duration,
}

impl HostAsk {
    /// Asks through `upstream`, waiting at most `limit` for each answer.
    #[must_use]
    pub fn new(upstream: Arc<Upstream>, limit: Duration) -> Self {
        Self { upstream, limit }
    }
}

impl Ask for HostAsk {
    async fn ask(&self, query: ResolveQuery) -> Result<ResolveAnswer, ResolveError> {
        let stream = tokio::time::timeout(self.limit, self.upstream.open())
            .await
            .map_err(|_| ResolveError::Timeout(self.limit))??;
        resolve::ask(stream, &query, self.limit).await
    }
}

type Key = (String, RecordType);

/// Answers the host gave, kept for the time it said.
#[derive(Debug)]
struct Cache {
    map: HashMap<Key, (ResolveAnswer, Instant)>,
    capacity: usize,
}

impl Cache {
    fn get(&self, key: &Key, now: Instant) -> Option<ResolveAnswer> {
        let (answer, expires) = self.map.get(key)?;
        (now < *expires).then(|| answer.clone())
    }

    fn put(&mut self, key: Key, answer: ResolveAnswer, ttl: u32, now: Instant) {
        if self.map.len() >= self.capacity {
            self.map.retain(|_, (_, expires)| now < *expires);
            if self.map.len() >= self.capacity {
                self.map.clear();
            }
        }
        let ttl = ttl.clamp(CACHE_TTL.0, CACHE_TTL.1);
        self.map
            .insert(key, (answer, now + Duration::from_secs(u64::from(ttl))));
    }
}

type Flight = Shared<BoxFuture<'static, ResolveAnswer>>;

struct State<A> {
    ask: A,
    stand_ins: StandIns,
    cache: Mutex<Cache>,
    inflight: Mutex<HashMap<Key, Flight>>,
    asks: Semaphore,
    limits: Limits,
}

/// The stub's brain: turns a DNS query into a DNS answer. Cheap to clone.
pub struct Stub<A> {
    shared: Arc<State<A>>,
}

impl<A> Clone for Stub<A> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<A: Ask> Stub<A> {
    /// A stub that asks `ask` and hands out addresses from `stand_ins`.
    #[must_use]
    pub fn new(ask: A, stand_ins: StandIns, limits: Limits) -> Self {
        Self {
            shared: Arc::new(State {
                ask,
                stand_ins,
                cache: Mutex::new(Cache {
                    map: HashMap::new(),
                    capacity: limits.cache_entries.max(1),
                }),
                inflight: Mutex::new(HashMap::new()),
                asks: Semaphore::new(limits.max_asks.max(1)),
                limits,
            }),
        }
    }

    /// Answers one DNS message from the guest, or `None` for a message to drop (a response, or
    /// too short to be a query). `udp` limits the answer's size.
    pub async fn answer(&self, message: &[u8], udp: bool) -> Option<Vec<u8>> {
        let query = match wire::parse_query(message) {
            Ok(query) => query,
            Err(Reject::Drop) => return None,
            Err(Reject::Answer {
                id,
                rcode,
                recursion_desired,
            }) => return Some(wire::error_response(id, rcode, recursion_desired)),
        };
        let (rcode, answers, additional) = self.respond(&query).await;
        Some(wire::respond(&query, rcode, &answers, &additional, udp))
    }

    async fn respond(&self, query: &wire::Query) -> (Rcode, Vec<Record>, Vec<Record>) {
        let name = match &query.name {
            QueryName::Plain(name) if names::is_plain(name) || name.is_empty() => name,
            _ => return (Rcode::NxDomain, vec![], vec![]),
        };
        if query.qclass != CLASS_IN {
            return (Rcode::Refused, vec![], vec![]);
        }
        if names::is_local_only(name) {
            return (Rcode::NxDomain, vec![], vec![]);
        }
        match query.qtype {
            TYPE_A => self.address(name).await,
            TYPE_SRV => self.records(name, RecordType::Srv).await,
            TYPE_TXT => self.records(name, RecordType::Txt).await,
            TYPE_MX => self.records(name, RecordType::Mx).await,
            _ => {
                // `AAAA` and the rest: nothing to say about types we don't forward, unless the
                // name is already known not to exist.
                let known_missing = matches!(
                    self.cached(name, RecordType::A),
                    Some(ResolveAnswer::NoSuchName { .. })
                );
                let rcode = if known_missing {
                    Rcode::NxDomain
                } else {
                    Rcode::NoError
                };
                (rcode, vec![], vec![])
            }
        }
    }

    async fn address(&self, name: &str) -> (Rcode, Vec<Record>, Vec<Record>) {
        match self.lookup(name, RecordType::A).await {
            ResolveAnswer::StandIn { ttl, .. } => match self.shared.stand_ins.address_for(name) {
                Ok(ip) => (Rcode::NoError, vec![stand_in_record(None, ip, ttl)], vec![]),
                Err(err) => {
                    tracing::warn!(%name, error = %err, "no stand-in address left");
                    (Rcode::ServFail, vec![], vec![])
                }
            },
            ResolveAnswer::NoSuchName { .. } => (Rcode::NxDomain, vec![], vec![]),
            ResolveAnswer::NoData { .. } => (Rcode::NoError, vec![], vec![]),
            _ => (Rcode::ServFail, vec![], vec![]),
        }
    }

    async fn records(&self, name: &str, rtype: RecordType) -> (Rcode, Vec<Record>, Vec<Record>) {
        match self.lookup(name, rtype).await {
            ResolveAnswer::Records { records, ttl } => {
                let mut answers = Vec::new();
                let mut additional: Vec<Record> = Vec::new();
                for record in records {
                    let Some((data, target)) = convert(rtype, record) else {
                        continue;
                    };
                    answers.push(Record {
                        owner: None,
                        ttl: ttl.min(GUEST_TTL_CAP),
                        data,
                    });
                    // A target gets a stand-in of its own, so the client's next step (connecting
                    // to it) needs no lookup of the name it was just given.
                    let known = additional
                        .iter()
                        .any(|r| r.owner.as_deref() == target.as_deref());
                    if let Some(target) = target
                        && !known
                        && !names::is_local_only(&target)
                        && let Ok(ip) = self.shared.stand_ins.address_for(&target)
                    {
                        additional.push(stand_in_record(Some(target), ip, ttl));
                    }
                }
                if answers.is_empty() {
                    (Rcode::NoError, vec![], vec![])
                } else {
                    (Rcode::NoError, answers, additional)
                }
            }
            ResolveAnswer::NoSuchName { .. } => (Rcode::NxDomain, vec![], vec![]),
            ResolveAnswer::NoData { .. } => (Rcode::NoError, vec![], vec![]),
            _ => (Rcode::ServFail, vec![], vec![]),
        }
    }

    fn cached(&self, name: &str, rtype: RecordType) -> Option<ResolveAnswer> {
        let cache = self
            .shared
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cache.get(&(name.to_owned(), rtype), Instant::now())
    }

    /// What the host says about `name`: from the cache, else from one lookup shared by every
    /// query for the same thing that is in flight.
    async fn lookup(&self, name: &str, rtype: RecordType) -> ResolveAnswer {
        if let Some(hit) = self.cached(name, rtype) {
            return hit;
        }
        let key = (name.to_owned(), rtype);
        let flight = {
            let mut inflight = self
                .shared
                .inflight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            inflight
                .entry(key.clone())
                .or_insert_with(|| {
                    let shared = Arc::clone(&self.shared);
                    let key = key.clone();
                    async move { shared.ask_host(key).await }.boxed().shared()
                })
                .clone()
        };
        let answer = flight.await;
        self.shared
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&key);
        answer
    }
}

impl<A: Ask> State<A> {
    /// One lookup on the host, bounded in number and time. A failure is `Unavailable` and is not
    /// kept.
    async fn ask_host(&self, key: Key) -> ResolveAnswer {
        let limit = self.limits.ask_timeout;
        let Ok(Ok(_slot)) = tokio::time::timeout(limit, self.asks.acquire()).await else {
            tracing::debug!(name = %key.0, "too many lookups waiting; answered unavailable");
            return ResolveAnswer::Unavailable;
        };
        let query = ResolveQuery::new(key.0.clone(), key.1);
        let answer = match tokio::time::timeout(limit, self.ask.ask(query)).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(err)) => {
                tracing::debug!(name = %key.0, error = %err, "lookup on the host failed");
                return ResolveAnswer::Unavailable;
            }
            Err(_) => {
                tracing::debug!(name = %key.0, "lookup on the host timed out");
                return ResolveAnswer::Unavailable;
            }
        };
        let answer = fit_to(key.1, answer);
        let ttl = match &answer {
            ResolveAnswer::StandIn { ttl, .. }
            | ResolveAnswer::NoSuchName { ttl }
            | ResolveAnswer::NoData { ttl }
            | ResolveAnswer::Records { ttl, .. } => *ttl,
            _ => return answer,
        };
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .put(key, answer.clone(), ttl, Instant::now());
        answer
    }
}

/// An answer of a kind the question can't have (a stand-in for a `TXT` query, records for an `A`
/// query) is a failure, not something to pass on.
fn fit_to(rtype: RecordType, answer: ResolveAnswer) -> ResolveAnswer {
    match (rtype, &answer) {
        (
            RecordType::A,
            ResolveAnswer::StandIn { .. }
            | ResolveAnswer::NoSuchName { .. }
            | ResolveAnswer::NoData { .. },
        )
        | (
            RecordType::Srv | RecordType::Txt | RecordType::Mx,
            ResolveAnswer::Records { .. }
            | ResolveAnswer::NoSuchName { .. }
            | ResolveAnswer::NoData { .. },
        ) => answer,
        _ => ResolveAnswer::Unavailable,
    }
}

fn stand_in_record(owner: Option<String>, ip: Ipv4Addr, ttl: u32) -> Record {
    Record {
        owner,
        ttl: ttl.clamp(1, GUEST_TTL_CAP),
        data: Rdata::A(ip),
    }
}

/// A host record as DNS data if it is of the type asked for and its names are plain; the second
/// value is the name the record points at, if any.
fn convert(rtype: RecordType, record: HostRecord) -> Option<(Rdata, Option<String>)> {
    match (rtype, record) {
        (
            RecordType::Srv,
            HostRecord::Srv {
                priority,
                weight,
                port,
                target,
            },
        ) if names::is_plain(&target) => Some((
            Rdata::Srv {
                priority,
                weight,
                port,
                target: target.clone(),
            },
            Some(target),
        )),
        (RecordType::Txt, HostRecord::Txt { strings }) => Some((Rdata::Txt(strings), None)),
        (
            RecordType::Mx,
            HostRecord::Mx {
                preference,
                exchange,
            },
        ) if names::is_plain(&exchange) => Some((
            Rdata::Mx {
                preference,
                exchange: exchange.clone(),
            },
            Some(exchange),
        )),
        _ => None,
    }
}

/// The stub's sockets: UDP and TCP on the same address. Its tasks end when it is dropped.
#[derive(Debug)]
pub struct DnsServer {
    udp: SocketAddr,
    tcp: SocketAddr,
    tasks: JoinSet<()>,
}

impl DnsServer {
    /// Binds `listen` (UDP and TCP) and starts serving `stub`.
    ///
    /// # Errors
    ///
    /// Binding a socket failing, for example because no interface has the address yet.
    pub async fn bind<A: Ask>(stub: Stub<A>, listen: SocketAddr) -> io::Result<Self> {
        let udp = UdpSocket::bind(listen).await?;
        let tcp = TcpListener::bind(listen).await?;
        let (udp_addr, tcp_addr) = (udp.local_addr()?, tcp.local_addr()?);
        let limits = stub.shared.limits;
        let mut tasks = JoinSet::new();
        tasks.spawn(serve_udp(udp, stub.clone(), limits));
        tasks.spawn(serve_tcp(tcp, stub, limits));
        Ok(Self {
            udp: udp_addr,
            tcp: tcp_addr,
            tasks,
        })
    }

    /// The UDP address bound.
    #[must_use]
    pub fn udp_addr(&self) -> SocketAddr {
        self.udp
    }

    /// The TCP address bound.
    #[must_use]
    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp
    }

    /// Runs until a socket task ends (they don't on their own).
    pub async fn run(mut self) {
        while self.tasks.join_next().await.is_some() {}
    }
}

/// How often [`bind_when_ready`] tries.
const BIND_RETRY: Duration = Duration::from_secs(1);

/// Binds `listen` as soon as an interface has the address, then serves. The address is made by
/// the boot sequence, which may run after the agent starts.
pub async fn bind_when_ready<A: Ask>(stub: Stub<A>, listen: SocketAddr) {
    loop {
        tokio::time::sleep(BIND_RETRY).await;
        match DnsServer::bind(stub.clone(), listen).await {
            Ok(server) => {
                tracing::info!(%listen, "stub DNS listening");
                server.run().await;
                return;
            }
            Err(err) => tracing::debug!(%listen, error = %err, "stub DNS still not bound"),
        }
    }
}

async fn serve_udp<A: Ask>(socket: UdpSocket, stub: Stub<A>, limits: Limits) {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(limits.max_udp_queries.max(1)));
    let mut tasks = JoinSet::new();
    let mut buf = vec![0u8; MAX_QUERY];
    loop {
        while tasks.try_join_next().is_some() {}
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(err) => {
                tracing::debug!(error = %err, "udp receive failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("too many queries at once; one dropped");
            continue;
        };
        let message = buf.get(..n).unwrap_or_default().to_vec();
        let (socket, stub) = (Arc::clone(&socket), stub.clone());
        tasks.spawn(async move {
            if let Some(answer) = stub.answer(&message, true).await
                && let Err(err) = socket.send_to(&answer, peer).await
            {
                tracing::debug!(error = %err, "udp answer not sent");
            }
            drop(slot);
        });
    }
}

async fn serve_tcp<A: Ask>(listener: TcpListener, stub: Stub<A>, limits: Limits) {
    let slots = Arc::new(Semaphore::new(limits.max_tcp_connections.max(1)));
    let mut conns = JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::debug!(error = %err, "tcp accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!("too many tcp connections; one closed");
            continue;
        };
        let stub = stub.clone();
        conns.spawn(async move {
            tcp_connection(stream, stub, limits.tcp_idle).await;
            drop(slot);
        });
    }
}

/// Answers length-prefixed queries one after another until the client goes quiet or misbehaves.
async fn tcp_connection<A: Ask>(mut stream: tokio::net::TcpStream, stub: Stub<A>, idle: Duration) {
    loop {
        let mut len = [0u8; 2];
        let read = tokio::time::timeout(idle, stream.read_exact(&mut len)).await;
        if !matches!(read, Ok(Ok(_))) {
            return;
        }
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 || len > MAX_QUERY {
            return;
        }
        let mut message = vec![0u8; len];
        if !matches!(
            tokio::time::timeout(idle, stream.read_exact(&mut message)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(answer) = stub.answer(&message, false).await else {
            return;
        };
        let mut framed = u16::try_from(answer.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
