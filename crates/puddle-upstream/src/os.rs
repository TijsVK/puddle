// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam to the operating system: what the OS says about proxies, in neutral terms. Discovery
//! only talks to [`OsProxy`], so every decision path is tested with [`crate::FakeOs`]. The
//! Windows implementation (WinINet and WinHTTP, `windows/`) keeps its own field names and syntax
//! inside itself; Unix is the environment ([`crate::EnvOs`]).

use std::sync::Arc;
use std::time::Duration;

use crate::env::{EnvFallback, EnvOs};
use crate::hop::Hop;
use crate::parse::{BypassList, ProxyRules};

/// Where [`ProxyConfig::rules`] came from. For diagnostics and [`crate::RouteSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Origin {
    /// The operating system's own settings.
    #[default]
    System,
    /// `HTTP(S)_PROXY` variables.
    Environment,
}

/// What the OS says about proxies, whatever the OS calls its fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyConfig {
    /// "Find the PAC script by itself" (WPAD) is on.
    pub auto_detect: bool,
    /// A PAC script's address.
    pub pac_url: Option<String>,
    /// Static proxies per scheme.
    pub rules: ProxyRules,
    /// Destinations that skip the static proxies. Not applied to PAC answers: the script decides.
    pub bypass: BypassList,
    /// Where the rules came from.
    pub origin: Origin,
}

/// One PAC / WPAD evaluation to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacQuery {
    /// The PAC script's address, or `None` to find it by WPAD (DHCP, then DNS).
    pub pac_url: Option<String>,
    /// Also try WPAD discovery.
    pub auto_detect: bool,
    /// The URL to ask `FindProxyForURL` about.
    pub url: String,
    /// Give up after this long.
    pub timeout: Duration,
}

/// Why a PAC evaluation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacError {
    /// The PAC script or WPAD could not be found or fetched: true for every destination until the
    /// network changes, so discovery stops asking for a while.
    #[error("proxy auto-config unavailable: {0}")]
    Unavailable(String),
    /// Took longer than the query's timeout.
    #[error("proxy auto-config timed out")]
    Timeout,
    /// Failed for this destination only (script error, bad URL).
    #[error("proxy auto-config failed: {0}")]
    Failed(String),
}

/// The settings could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("reading the system proxy settings failed: {0}")]
pub struct SettingsError(pub String);

/// Called by the OS layer on any proxy or network change. Cheap and non-blocking.
pub type ChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// Keeps a change registration alive; dropping it unregisters.
pub trait WatchGuard: Send + Sync + std::fmt::Debug {}

/// What discovery asks of the operating system. Blocking: discovery calls it from
/// `spawn_blocking`.
pub trait OsProxy: Send + Sync + std::fmt::Debug {
    /// Reads the current settings.
    ///
    /// # Errors
    /// [`SettingsError`] when the OS call fails.
    fn config(&self) -> Result<ProxyConfig, SettingsError>;

    /// Runs the PAC script or WPAD for `query.url` and returns the full hop list, `DIRECT`
    /// included.
    ///
    /// # Errors
    /// [`PacError`], see its variants.
    fn resolve_pac(&self, query: &PacQuery) -> Result<Vec<Hop>, PacError>;

    /// Calls `on_change` whenever proxy settings or the network change, until the guard drops.
    /// `None` when this OS layer cannot watch.
    fn watch(&self, on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>>;
}

/// The OS layer of the current platform: WinHTTP with the environment as a fallback on Windows,
/// the environment alone elsewhere (no PAC, no change notification yet).
#[must_use]
pub fn system_os() -> Arc<dyn OsProxy> {
    #[cfg(windows)]
    {
        Arc::new(EnvFallback::new(
            Arc::new(crate::windows::WinOs::new()),
            EnvOs::from_process(),
        ))
    }
    #[cfg(not(windows))]
    {
        let _ = EnvFallback::new; // the wrapper is Windows' fallback; Unix needs none
        Arc::new(EnvOs::from_process())
    }
}
