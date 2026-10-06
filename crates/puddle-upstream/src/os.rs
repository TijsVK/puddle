// SPDX-License-Identifier: GPL-3.0-or-later
//! The seam to the operating system: what Windows says about proxies. Discovery only talks to
//! [`OsProxy`], so every decision path is tested with [`crate::FakeOs`] and the Windows
//! implementation ([`crate::WinOs`]) stays a thin layer over WinHTTP.

use std::sync::Arc;
use std::time::Duration;

use crate::hop::Hop;

/// The user's proxy settings as WinINet stores them (`WinHttpGetIEProxyConfigForCurrentUser`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsSettings {
    /// "Automatically detect settings" (WPAD) is on.
    pub auto_detect: bool,
    /// `AutoConfigURL`: the PAC script's address.
    pub pac_url: Option<String>,
    /// `ProxyServer` (when `ProxyEnable` is on), in the WinINet syntax.
    pub proxy_server: Option<String>,
    /// `ProxyOverride`.
    pub bypass: Option<String>,
    /// The machine-wide WinHTTP proxy (`netsh winhttp`), proxy list.
    pub machine_proxy: Option<String>,
    /// The machine-wide WinHTTP bypass list.
    pub machine_bypass: Option<String>,
    /// Group policy `ProxySettingsPerUser=0` makes WinINet read the machine's settings instead of
    /// the user's. Reported, not yet followed (diagnostics only).
    pub per_machine_policy: bool,
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
    fn settings(&self) -> Result<OsSettings, SettingsError>;

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

/// An OS layer for platforms without system proxy settings: no settings, no PAC, no watch.
/// Discovery then falls back to the environment variables.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOs;

impl OsProxy for NoOs {
    fn settings(&self) -> Result<OsSettings, SettingsError> {
        Ok(OsSettings::default())
    }

    fn resolve_pac(&self, _query: &PacQuery) -> Result<Vec<Hop>, PacError> {
        Err(PacError::Unavailable(
            "no system proxy support on this platform".into(),
        ))
    }

    fn watch(&self, _on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>> {
        None
    }
}

/// The OS layer of the current platform: WinHTTP on Windows, [`NoOs`] elsewhere.
#[must_use]
pub fn system_os() -> Arc<dyn OsProxy> {
    #[cfg(windows)]
    {
        Arc::new(crate::windows::WinOs::new())
    }
    #[cfg(not(windows))]
    {
        Arc::new(NoOs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_portable_layer_has_no_settings_no_pac_and_no_watch() {
        let os = NoOs;
        assert_eq!(os.settings().unwrap(), OsSettings::default());
        let query = PacQuery {
            pac_url: None,
            auto_detect: true,
            url: "http://x/".into(),
            timeout: Duration::from_secs(1),
        };
        assert!(matches!(
            os.resolve_pac(&query),
            Err(PacError::Unavailable(_))
        ));
        assert!(os.watch(Arc::new(|| {})).is_none());
        let _ = system_os();
    }
}
