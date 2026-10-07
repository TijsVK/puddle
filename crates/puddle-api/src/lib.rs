// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's local HTTP API axum on `127.0.0.1`, an SSE event stream, and the
//! `OpenAPI` contract the UI and CLI are generated from (ADR 0004).
//!
//! # Security
//!
//! Every request, the spec included, passes three checks before any handler runs, in this
//! order, and each refusal is a JSON [`ApiErrorBody`]:
//!
//! 1. **`Host`** must be `127.0.0.1:<port>` or `localhost:<port>` for the bound port (421
//!    otherwise). This defeats DNS rebinding: a page on `evil.example` that rebinds its name to
//!    `127.0.0.1` still sends `Host: evil.example`.
//! 2. **`Origin`**, when present, must be the API's own origin or one listed in
//!    [`ApiConfig::extra_origins`] (403 otherwise; `null` is refused). There is no CORS: a
//!    cross-origin page gets no preflight answer, so it can't send the token header at all.
//! 3. **`Authorization: Bearer <token>`** must carry the token from the user-only connection
//!    file ([`ConnectionInfo`]), compared in constant time (401 otherwise). The token never goes
//!    into a guest, a mount or a URL.
//!
//! With [`ApiConfig::ui`] set (the default under feature `embedded-ui`) the same origin also
//! serves the single-page app: files outside `/api` need no token, because the page has to load
//! before it can present one, but they keep the `Host` and `Origin` checks and carry a strict
//! `Content-Security-Policy` and no framing.
//!
//! The listener binds `127.0.0.1` only; there is no setting for another address. State changes
//! are `POST`/`PUT`/`DELETE` and the ones with a body accept only `application/json`, so no
//! "simple" cross-site request can reach them.
//!
//! # Use
//!
//! ```no_run
//! # async fn run(services: puddle_api::Services) -> Result<(), Box<dyn std::error::Error>> {
//! use puddle_api::{ApiConfig, ApiServer, ApiToken};
//!
//! let server = ApiServer::bind(ApiConfig::default(), ApiToken::generate()?, services).await?;
//! server.connection_info().write(std::path::Path::new("/run/user/1000/puddle/api.json"))?;
//! let running = server.spawn();
//! // ... later
//! running.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! Events reach SSE subscribers through [`EventHub`], which implements
//! [`puddle_types::EventSink`]: hand the same hub to the components that emit events.
#![forbid(unsafe_code)]

mod auth;
mod error;
mod events;
mod extract;
mod fake_workspaces;
mod openapi;
mod routes;
mod server;
mod settings;
mod token;
mod ui;
pub mod wire;
mod workspaces;

pub use error::{ApiErrorBody, ErrorCode};
pub use events::{DEFAULT_EVENT_BUFFER, EventHub, Lagged};
pub use fake_workspaces::{FakeLauncher, FakeWorkspaces, Unsaved};
pub use openapi::{API_VERSION, openapi, openapi_json};
pub use server::{ApiConfig, ApiServer, RunningApi, ServeError, Services};
pub use settings::{MemorySettings, SettingsRepo, SettingsRepoError};
pub use token::{ApiToken, ConnectionFileError, ConnectionInfo};
#[cfg(feature = "embedded-ui")]
pub use ui::EmbeddedUi;
pub use ui::{UiAssets, UiFile};
pub use workspaces::{
    AttachMode, Attached, DEFAULT_DISK_MIB, DEFAULT_IMAGE, DeleteCheck, LaunchError, Launcher,
    Listing, MAX_REPO_URL_LEN, NewWorkspace, NoWorkspaces, Operation, RepoFindings, RepoUrl,
    WorkspaceError, WorkspaceRecord, WorkspaceService,
};
