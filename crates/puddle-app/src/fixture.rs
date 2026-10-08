// SPDX-License-Identifier: GPL-3.0-or-later
//! The fixture backend (until the real host is wired in): the real API router on in-memory services, with
//! one pending request seeded so the inbox has something to show. All data is fictional.

use std::sync::Arc;

use puddle_api::{
    ApiConfig, ApiServer, ApiToken, EventHub, MemorySettings, Services, SettingsRepo,
};
use puddle_store::{Limits, Store, SystemClock};
use puddle_types::{EgressRequest, Host, SuffixAllows, WorkspaceName};

use crate::backend::{Backend, BackendError};

/// Starts the fixture backend on `127.0.0.1:<port>`.
pub(crate) async fn start(port: u16) -> Result<Backend, BackendError> {
    let fixture =
        |what: &str, err: &dyn std::fmt::Display| BackendError::Fixture(format!("{what}: {err}"));
    let clock = Arc::new(SystemClock);
    let store = Arc::new(
        Store::open_in_memory(clock.clone(), Limits::default())
            .map_err(|e| fixture("store", &e))?,
    );
    let workspace = WorkspaceName::new("demo").map_err(|e| fixture("workspace name", &e))?;
    let host = Host::parse_normalised("registry.example.org").map_err(|e| fixture("host", &e))?;
    store
        .decide(
            &EgressRequest::new(workspace, host, 443),
            SuffixAllows::Count,
        )
        .map_err(|e| fixture("seed", &e))?;
    let events = Arc::new(EventHub::default());
    let services = Services::new(
        store,
        Arc::new(MemorySettings::default()) as Arc<dyn SettingsRepo>,
        events.clone(),
        clock,
    );
    let server =
        ApiServer::bind(ApiConfig::with_port(port), ApiToken::generate()?, services).await?;
    let info = server.connection_info();
    Backend::new(info, events, server.spawn())
}
