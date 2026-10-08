// SPDX-License-Identifier: GPL-3.0-or-later
//! A hostile guest tries puddle's own API through the real proxy: the guest agent's CONNECT to the
//! API's address and port is refused with a reason, whatever the loopback toggle and the rules
//! say.
//!
//! Unix only, like the other agent-through-proxy tests: on Windows the agent's refusal path resets
//! the client's connection before the answer can be read. The refusal itself comes from the
//! address guard, which is the same code on every OS, and the registration is tested on both
//! (`puddle-api`'s `endpoints` tests).
//!
//! The doubles are the resolver (no names are resolved here) and nothing else: the address guard is
//! the real `NetPolicy` with every local category switched on and the API registered by
//! `ApiServer::bind`.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use puddle_agent::config::Target;
use puddle_agent::{Agent, Config};
use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, MemorySettings, RunningApi, Services, SettingsRepo,
};
use puddle_ipc::IpcRoot;
use puddle_netpolicy::{LocalAccess, NetPolicy, PuddleEndpoints};
use puddle_proxy::testing::StaticResolver;
use puddle_proxy::{Proxy, Route};
use puddle_store::{Actor, Effect, Limits, ManualClock, NewRule, Pattern, Scope, Store};
use puddle_types::{LocalCategory, NullSink, WorkspaceName};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const NOW: u64 = 1_800_000_000_000;

struct Rig {
    api: RunningApi,
    agent: Agent,
    store: Arc<Store>,
    _route: Route,
    _root: IpcRoot,
}

async fn rig() -> Rig {
    let clock = Arc::new(ManualClock::new(NOW));
    let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
    let endpoints = PuddleEndpoints::new();
    let services = Services::new(
        store.clone(),
        Arc::new(MemorySettings::default()) as Arc<dyn SettingsRepo>,
        Arc::new(EventHub::default()),
        clock,
    )
    .with_endpoints(endpoints.clone());
    let api = ApiServer::bind(
        ApiConfig::default(),
        ApiToken::generate().unwrap(),
        services,
    )
    .await
    .unwrap()
    .spawn();

    // Every local category on, wildcards reaching local: the most permissive guard there is.
    let access = LocalCategory::ALL
        .into_iter()
        .fold(LocalAccess::NONE, |a, c| a.with_toggle(c, true))
        .with_wildcards_reach_local(true);
    let guard = NetPolicy::new(Arc::new(access)).with_endpoints(endpoints);
    let proxy = Arc::new(
        Proxy::new(store.clone(), Arc::new(NullSink))
            .with_resolver(Arc::new(StaticResolver::new()))
            .with_address_check(Arc::new(guard)),
    );
    let root = IpcRoot::new().unwrap();
    let route = proxy.serve_route(
        root.listen().unwrap(),
        WorkspaceName::new("e2e-api").unwrap(),
    );
    let agent = Agent::start(Config {
        listen: SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 0),
        target: Target::Unix(route.endpoint().path().to_path_buf()),
        oom: None,
        ..Config::default()
    })
    .await
    .unwrap();
    Rig {
        api,
        agent,
        store,
        _route: route,
        _root: root,
    }
}

/// The answer to `CONNECT authority` through the agent: status, header lines, and the body.
async fn connect_via(agent: SocketAddr, authority: &str) -> io::Result<(u16, Vec<String>, String)> {
    let mut conn = TcpStream::connect(agent).await?;
    conn.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await?;
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let code = line
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| io::Error::other(format!("bad status line {line:?}")))?;
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await?;
        if h == "\r\n" || h.is_empty() {
            break;
        }
        headers.push(h.trim_end().to_ascii_lowercase());
    }
    let length = headers
        .iter()
        .find_map(|h| h.strip_prefix("content-length: "))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body).await?;
    Ok((code, headers, String::from_utf8_lossy(&body).into_owned()))
}

#[tokio::test]
async fn a_guest_cannot_reach_the_api_even_with_every_local_toggle_on_and_an_allow_rule() {
    let rig = rig().await;
    let port = rig.api.local_addr().port();
    // An exact allow for the literal doesn't help either: puddle's own listeners come first.
    rig.store
        .add_rule(&NewRule {
            scope: Scope::Global,
            pattern: Pattern::parse("127.0.0.1").unwrap(),
            effect: Effect::Allow,
            expires_at: None,
            created_by: Actor::Cli,
        })
        .unwrap();
    for authority in [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::ffff:127.0.0.1]:{port}"),
        format!("0.0.0.0:{port}"),
    ] {
        let (code, headers, body) = connect_via(rig.agent.local_addr(), &authority)
            .await
            .unwrap();
        assert_eq!(code, 403, "{authority}");
        assert!(
            headers.contains(&"x-puddle-blocked: puddle_endpoint".to_owned()),
            "{authority}: {headers:?}"
        );
        assert!(
            !headers.iter().any(|h| h.starts_with("x-puddle-pending")),
            "{authority}: {headers:?}"
        );
        assert!(
            body.contains("puddle's own endpoints"),
            "{authority}: the refusal must say why: {body:?}"
        );
    }
    assert_eq!(rig.store.open_pending(None).unwrap().len(), 0);
}
