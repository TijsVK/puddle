// SPDX-License-Identifier: GPL-3.0-or-later
//! The routes. Each handler carries its `#[utoipa::path]`, and [`api_router`] registers routes
//! and spec together (`utoipa-axum`), so the published spec can't drift from what is served.

use std::sync::Arc;

use puddle_store::{Clock, Store};
use tokio::sync::{Mutex, watch};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::events::EventHub;
use crate::settings::SettingsRepo;

mod audit;
mod events;
mod meta;
mod pending;
mod rules;
mod settings;

/// What the handlers share.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<Store>,
    pub(crate) settings: Arc<dyn SettingsRepo>,
    /// Serialises settings read-modify-write cycles.
    pub(crate) settings_lock: Arc<Mutex<()>>,
    pub(crate) events: Arc<EventHub>,
    pub(crate) clock: Arc<dyn Clock>,
    /// Becomes `true` when the server shuts down; ends SSE streams.
    pub(crate) shutdown: watch::Receiver<bool>,
}

/// Every documented route.
pub(crate) fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(meta::health))
        .routes(routes!(events::events))
        .routes(routes!(pending::list_pending))
        .routes(routes!(pending::inbox))
        .routes(routes!(pending::get_pending))
        .routes(routes!(pending::approve))
        .routes(routes!(pending::deny))
        .routes(routes!(pending::suppression))
        .routes(routes!(rules::list_rules, rules::create_rule))
        .routes(routes!(rules::delete_rule))
        .routes(routes!(rules::set_rule_expiry))
        .routes(routes!(audit::audit))
        .routes(routes!(settings::get_global, settings::put_global))
        .routes(routes!(settings::get_sandbox, settings::put_sandbox))
        .routes(routes!(settings::get_consents))
        .routes(routes!(settings::put_consent))
}
