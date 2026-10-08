// SPDX-License-Identifier: GPL-3.0-or-later
//! The puddle host process as a library: the one place that wires the store, the proxies, the
//! sandbox runtime, workspaces, shutdown and the API together.
//!
//! `puddle serve` and the desktop app both start it the same way:
//!
//! ```no_run
//! # async fn demo(config: puddle_host::HostConfig) -> Result<(), puddle_host::HostError> {
//! use puddle_host::{Host, HostOptions, MsbFactory, SystemPlatform, prepare};
//!
//! // Synchronous, before the process has a second thread: binds the pull proxy, pins the
//! // environment, checks the runtime, reads the corporate roots.
//! let prepared = prepare(config, &SystemPlatform::new())?;
//! // Asynchronous: store, upstream chain, runtime, reconcile, proxies, workspaces, API.
//! let host = Host::start(prepared, &MsbFactory, HostOptions::default()).await?;
//! println!("{}", host.url());
//! // ... wait for Ctrl-C / the quit sequence ...
//! host.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! The order of both sequences is part of the contract; see [`Step`], [`START_STEPS`] and
//! [`SHUTDOWN_STEPS`].
#![deny(unsafe_code)]

mod boot;
mod config;
mod data_folder;
mod doctor;
mod error;
mod files;
mod host;
mod paths;
mod platform;
mod process_env;
mod settings_read;
mod workspaces;

pub use config::{AGENT_FILE_NAME, ApiSettings, GuestSettings, HostConfig, UpstreamSettings};
pub use error::HostError;
pub use files::FileSettings;
pub use host::{
    Host, HostOptions, HostShutdown, MsbFactory, PREPARE_STEPS, Prepared, RuntimeFactory,
    RuntimeInputs, SHUTDOWN_STEPS, START_STEPS, Step, prepare,
};
pub use paths::HostPaths;
pub use platform::{Platform, SystemPlatform};
pub use workspaces::{HostWorkspaces, NoLauncher};
