// SPDX-License-Identifier: GPL-3.0-or-later
//! The real API with the embedded UI on fixed settings and one pending request, for the UI's
//! end-to-end tests (T-170). `serve_ui <port> <connection-file>` listens on `127.0.0.1:<port>`,
//! writes the connection file the way the app does, and serves until it is killed. T-171 replaces
//! it with the full fixture backend (seeded scenarios, scripted events).
#![expect(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a test helper binary: it reports on stdout and a bad start is a panic"
)]

use std::path::PathBuf;
use std::sync::Arc;

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, MemorySettings, Services, SettingsRepo,
};
use puddle_store::{Limits, Store, SystemClock};
use puddle_types::{EgressRequest, Host, SandboxName, SuffixAllows};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args
        .next()
        .and_then(|p| p.parse().ok())
        .expect("usage: serve_ui <port> <connection-file>");
    let file = PathBuf::from(
        args.next()
            .expect("usage: serve_ui <port> <connection-file>"),
    );

    let clock = Arc::new(SystemClock);
    let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
    store
        .decide(
            &EgressRequest::new(
                SandboxName::new("demo").unwrap(),
                Host::parse_normalised("registry.example.org").unwrap(),
                443,
            ),
            SuffixAllows::Count,
        )
        .unwrap();
    let services = Services::new(
        store,
        Arc::new(MemorySettings::default()) as Arc<dyn SettingsRepo>,
        Arc::new(EventHub::default()),
        clock,
    );
    let server = ApiServer::bind(
        ApiConfig::with_port(port),
        ApiToken::generate().unwrap(),
        services,
    )
    .await
    .unwrap();
    server.connection_info().write(&file).unwrap();
    let running = server.spawn();
    println!("serving the UI on {}", running.local_addr());
    std::future::pending::<()>().await;
}
