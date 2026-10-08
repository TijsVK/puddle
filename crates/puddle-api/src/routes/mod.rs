// SPDX-License-Identifier: GPL-3.0-or-later
//! The routes. Each handler carries its `#[utoipa::path]`, and [`api_router`] registers routes
//! and spec together (`utoipa-axum`), so the published spec can't drift from what is served.

use std::sync::Arc;

use puddle_store::{Clock, Store};
use tokio::sync::{Mutex, watch};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::credentials::CredentialService;
use crate::events::EventHub;
use crate::network_health::NetworkHealthService;
use crate::settings::SettingsRepo;
use crate::workspaces::WorkspaceService;

mod audit;
mod credentials;
mod events;
mod identities;
mod meta;
mod network_health;
mod pending;
mod rule_sets;
mod rules;
pub(crate) mod settings;
mod workspaces;

/// What the handlers share.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) store: Arc<Store>,
    pub(crate) settings: Arc<dyn SettingsRepo>,
    /// Serialises settings read-modify-write cycles.
    pub(crate) settings_lock: Arc<Mutex<()>>,
    pub(crate) events: Arc<EventHub>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) workspaces: Arc<dyn WorkspaceService>,
    pub(crate) network_health: Arc<dyn NetworkHealthService>,
    pub(crate) credentials: Arc<dyn CredentialService>,
    /// Becomes `true` when the server shuts down; ends SSE streams.
    pub(crate) shutdown: watch::Receiver<bool>,
}

/// Every documented route.
pub(crate) fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(meta::health))
        .routes(routes!(events::events))
        .routes(routes!(network_health::network_health))
        .routes(routes!(pending::list_pending))
        .routes(routes!(pending::inbox))
        .routes(routes!(pending::get_pending))
        .routes(routes!(pending::approve))
        .routes(routes!(pending::deny))
        .routes(routes!(pending::suppression))
        .routes(routes!(rules::list_rules, rules::create_rule))
        .routes(routes!(rules::delete_rule))
        .routes(routes!(rules::set_rule_expiry))
        .routes(routes!(
            rule_sets::list_rule_sets,
            rule_sets::create_rule_set
        ))
        .routes(routes!(
            rule_sets::update_rule_set,
            rule_sets::delete_rule_set
        ))
        .routes(routes!(rule_sets::switch_rule_set))
        .routes(routes!(audit::audit))
        .routes(routes!(settings::get_global, settings::put_global))
        .routes(routes!(
            settings::get_workspace_settings,
            settings::put_workspace_settings
        ))
        .routes(routes!(settings::get_consents))
        .routes(routes!(settings::put_consent))
        .routes(routes!(
            workspaces::list_workspaces,
            workspaces::create_workspace
        ))
        .routes(routes!(
            workspaces::get_workspace,
            workspaces::delete_workspace
        ))
        .routes(routes!(workspaces::start_workspace))
        .routes(routes!(workspaces::stop_workspace))
        .routes(routes!(workspaces::reclaim_workspace))
        .routes(routes!(workspaces::delete_check))
        .routes(routes!(workspaces::attach_workspace))
        .routes(routes!(
            identities::list_identities,
            identities::create_identity
        ))
        .routes(routes!(identities::reorder_identities))
        .routes(routes!(
            identities::get_identity,
            identities::update_identity,
            identities::delete_identity
        ))
        .routes(routes!(identities::set_default_identity))
        .routes(routes!(credentials::found_accounts))
        .routes(routes!(credentials::check_credential))
        .routes(routes!(credentials::store_token))
        .routes(routes!(credentials::forget_token))
        .routes(routes!(credentials::sign_in))
        .routes(routes!(identities::get_workspace_git))
        .routes(routes!(
            identities::set_workspace_identities,
            identities::attach_identity
        ))
        .routes(routes!(identities::detach_identity))
        .routes(routes!(identities::set_git_switches))
        .routes(routes!(identities::add_git_repo))
        .routes(routes!(
            identities::set_git_repo,
            identities::remove_git_repo
        ))
}
