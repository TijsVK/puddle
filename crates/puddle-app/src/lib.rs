// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's desktop shell (desktop): a Tauri 2 app that runs the API in-process and shows
//! the single-page app in its main window.
//!
//! # Design
//!
//! * The page is not served by Tauri. The API serves it from `http://127.0.0.1:<port>/` (feature
//!   `embedded-ui` of `puddle-api`), so the page and the API share one origin: no CORS, SSE works,
//!   and a browser tab runs the same code as the window.
//! * The main window (label `main`, [`window::MAIN_LABEL`]) gets the API token from a start-up
//!   script ([`window::init_script`]) and has **no Tauri permissions at all**: the SPA calls no
//!   Tauri API. `capabilities/main.json` names the label with an empty permission list, never
//!   `remote` and never `windows: ["*"]`, and `build.rs` ships an app ACL manifest, so an app
//!   command is refused to everyone until a capability names it. The ACL tests in `tests/acl.rs`
//!   enforce all of this.
//! * The window stays on the API's origin ([`navigation::OriginPolicy`]). Web addresses elsewhere
//!   go to the default browser, called from Rust; everything else is dropped.
//! * Tray, notifications, badges and close behaviour come later: they run in Rust, driven from
//!   [`backend::Backend::events`]. The real backend and the sandbox quit sequence come later.
#![forbid(unsafe_code)]

pub mod backend;
#[cfg(feature = "fixture")]
mod fixture;
pub mod navigation;
pub mod shell;
pub mod window;

pub use shell::{Options, ShellError, context, run, with_plugins};
