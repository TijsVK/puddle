// SPDX-License-Identifier: GPL-3.0-or-later
//! A real API on loopback and a raw HTTP/1.1 client, so tests control every header byte (a
//! normal client would fix up `Host` and refuse odd requests).

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, FakeLauncher, FakeWorkspaces, Launcher,
    MemorySettings, NetworkHealthService, RunningApi, Services, SettingsRepo,
};
use puddle_store::{Limits, ManualClock, Store};
use puddle_types::{EgressRequest, Host, PendingId, SuffixAllows, WorkspaceName};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Epoch ms the test clock starts at.
pub(crate) const START_MS: u64 = 1_700_000_000_000;

/// How long any single network step in a test may take.
pub(crate) const STEP: Duration = Duration::from_secs(10);

pub(crate) struct Api {
    pub(crate) running: RunningApi,
    pub(crate) addr: SocketAddr,
    pub(crate) token: String,
    pub(crate) store: Arc<Store>,
    pub(crate) events: Arc<EventHub>,
    pub(crate) settings: Arc<MemorySettings>,
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) workspaces: FakeWorkspaces,
    pub(crate) launcher: Arc<FakeLauncher>,
}

pub(crate) async fn start() -> Api {
    start_with(ApiConfig::default()).await
}

pub(crate) async fn start_with(config: ApiConfig) -> Api {
    start_inner(config, true, None).await
}

/// An API serving this network-health report.
pub(crate) async fn start_with_network(network: Arc<dyn NetworkHealthService>) -> Api {
    start_inner(ApiConfig::default(), true, Some(network)).await
}

/// An API whose services have no workspaces implementation (what `Services::new` gives).
pub(crate) async fn start_without_workspaces() -> Api {
    start_inner(ApiConfig::default(), false, None).await
}

async fn start_inner(
    config: ApiConfig,
    with_workspaces: bool,
    network: Option<Arc<dyn NetworkHealthService>>,
) -> Api {
    let clock = Arc::new(ManualClock::new(START_MS));
    let events = Arc::new(EventHub::default());
    let store = Arc::new(
        Store::open_in_memory(clock.clone(), Limits::default())
            .unwrap()
            .with_events(events.clone()),
    );
    let settings = Arc::new(MemorySettings::default());
    let launcher = Arc::new(FakeLauncher::new());
    let workspaces = FakeWorkspaces::with_options(
        events.clone(),
        clock.clone(),
        launcher.clone() as Arc<dyn Launcher>,
        Duration::ZERO,
    );
    let token = ApiToken::generate().unwrap();
    let services = Services::new(
        store.clone(),
        settings.clone() as Arc<dyn SettingsRepo>,
        events.clone(),
        clock.clone(),
    );
    let services = if with_workspaces {
        services.with_workspaces(Arc::new(workspaces.clone()))
    } else {
        services
    };
    let services = match network {
        Some(network) => services.with_network_health(network),
        None => services,
    };
    let server = ApiServer::bind(config, token.clone(), services)
        .await
        .unwrap();
    let addr = server.local_addr();
    let running = server.spawn();
    Api {
        running,
        addr,
        token: token.expose().to_owned(),
        store,
        events,
        settings,
        clock,
        workspaces,
        launcher,
    }
}

impl Api {
    pub(crate) fn host(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    /// A well-formed request with the token, our `Host` and `Connection: close`.
    pub(crate) async fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Reply {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
            self.host(),
            self.token
        );
        let body = body.map(Value::to_string).unwrap_or_default();
        if !body.is_empty() || matches!(method, "POST" | "PUT") {
            let _ = write!(
                head,
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
        }
        head.push_str("\r\n");
        head.push_str(&body);
        raw(self.addr, head.as_bytes()).await
    }

    pub(crate) async fn get(&self, path: &str) -> Reply {
        self.send("GET", path, None).await
    }

    /// Makes the workspace ask for `host:443` once, as the proxy would; returns the pending id.
    pub(crate) fn request(&self, workspace: &str, host: &str) -> i64 {
        let decision = self
            .store
            .decide(
                &EgressRequest::new(
                    WorkspaceName::new(workspace).unwrap(),
                    Host::parse_normalised(host).unwrap(),
                    443,
                ),
                SuffixAllows::Count,
            )
            .unwrap();
        match decision {
            puddle_types::Decision::Pending(outcome) => {
                let PendingId(id) = outcome.pending_id().unwrap();
                id
            }
            other => panic!("expected a pending decision, got {other:?}"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl Reply {
    pub(crate) fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `error` code of an error body.
    pub(crate) fn error(&self) -> String {
        self.json()["error"].as_str().unwrap_or_default().to_owned()
    }
}

/// Sends `request` as is and reads the reply until the server closes.
pub(crate) async fn raw(addr: SocketAddr, request: &[u8]) -> Reply {
    let mut stream = tokio::time::timeout(STEP, TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    stream.write_all(request).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(STEP, stream.read_to_end(&mut bytes))
        .await
        .expect("reply within the step timeout")
        .unwrap();
    parse(&bytes)
}

pub(crate) fn parse(bytes: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("no header end in {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap();
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line {status_line:?}"));
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked")
    });
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_owned()
    };
    Reply {
        status,
        headers,
        body,
    }
}

fn dechunk(mut rest: &str) -> String {
    let mut out = String::new();
    while let Some((size, after)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..].trim_start_matches("\r\n");
    }
    out
}
