// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's typed configuration: everything `puddle serve` and the desktop app decide, in one
//! value, so both start the same host.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use puddle_api::UiAssets;
use puddle_boot::GitIdentity;
use puddle_lifecycle::ShutdownConfig;
use puddle_runtime::{RuntimeLayout, RuntimeVersion};
use puddle_upstream::Credentials;
use puddle_workspace::WorkspaceConfig;

use crate::{HostError, HostPaths};

/// How the API listens and what it serves.
#[derive(Clone)]
#[non_exhaustive]
pub struct ApiSettings {
    /// Port on `127.0.0.1`; 0 lets the OS pick, and clients learn it from the connection file.
    pub port: u16,
    /// Browser origins besides the API's own that may call it (still needing the token).
    pub extra_origins: Vec<String>,
    /// The single-page app to serve; `None` keeps the API's default (the embedded build when
    /// the `embedded-ui` feature is on, nothing otherwise).
    pub ui: Option<Arc<dyn UiAssets>>,
    /// Where to write the connection file (URL and token), if anywhere.
    pub connection_file: Option<PathBuf>,
}

impl std::fmt::Debug for ApiSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiSettings")
            .field("port", &self.port)
            .field("extra_origins", &self.extra_origins)
            .field("ui", &self.ui.as_ref().map(|_| "custom"))
            .field("connection_file", &self.connection_file)
            .finish()
    }
}

/// How puddle reaches the internet through the company's network.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct UpstreamSettings {
    /// Where the proxy setting comes from (the system's by default).
    pub discovery: puddle_upstream::Config,
    /// A Basic user and password for the company proxy, tried after the system sign-in
    /// (Windows SSPI as the logged-on user). Never logged.
    pub basic: Option<Credentials>,
}

/// What goes into every sandbox besides the image.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GuestSettings {
    /// The static guest agent every sandbox mounts read-only.
    pub agent_binary: PathBuf,
    /// The git identity written into every guest (none: git's own prompt applies).
    pub git_identity: Option<GitIdentity>,
    /// Longest the boot hook may run.
    pub boot_timeout: Duration,
}

impl GuestSettings {
    /// Defaults around the agent at `agent_binary`.
    #[must_use]
    pub fn new(agent_binary: impl Into<PathBuf>) -> Self {
        Self {
            agent_binary: agent_binary.into(),
            git_identity: None,
            boot_timeout: puddle_boot::BootHook::DEFAULT_TIMEOUT,
        }
    }
}

/// The host's configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HostConfig {
    /// Where state lives.
    pub paths: HostPaths,
    /// The bundled runtime folder and msb home.
    pub layout: RuntimeLayout,
    /// The runtime version this build accepts (exactly).
    pub expected_runtime: RuntimeVersion,
    /// msb's log level for sandbox runtimes (`None` keeps the adapter's default).
    pub runtime_log_level: Option<String>,
    /// The API.
    pub api: ApiSettings,
    /// The company network.
    pub upstream: UpstreamSettings,
    /// Workspace volumes and the maintenance sandbox.
    pub workspaces: WorkspaceConfig,
    /// How long shutdown waits to trim and stop a sandbox.
    pub shutdown: ShutdownConfig,
    /// How long shutdown lets running workspace operations finish before it stops the VMs.
    pub operations_grace: Duration,
    /// What goes into the guests.
    pub guest: GuestSettings,
}

impl HostConfig {
    /// A configuration over explicit folders.
    #[must_use]
    pub fn new(paths: HostPaths, layout: RuntimeLayout, guest: GuestSettings) -> Self {
        let connection_file = Some(paths.connection_file());
        Self {
            paths,
            layout,
            expected_runtime: RuntimeVersion::built_for(),
            runtime_log_level: None,
            api: ApiSettings {
                port: 0,
                extra_origins: Vec::new(),
                ui: None,
                connection_file,
            },
            upstream: UpstreamSettings::default(),
            workspaces: WorkspaceConfig::default(),
            shutdown: ShutdownConfig::default(),
            operations_grace: Duration::from_secs(20),
            guest,
        }
    }

    /// The installed layout for the current user: the runtime and the guest agent beside
    /// `exe`, state in the per-user data folder.
    ///
    /// # Errors
    ///
    /// [`HostError::DataDir`] without a per-user data folder; [`HostError::Runtime`] when the
    /// folders are not absolute.
    pub fn installed_for_user(exe: &Path) -> Result<Self, HostError> {
        let data = puddle_fs::data_dir().map_err(|e| HostError::DataDir(e.to_string()))?;
        let layout = RuntimeLayout::installed(exe, &data)?;
        let agent = layout.runtime_dir().join(AGENT_FILE_NAME);
        Ok(Self::new(
            HostPaths::new(data),
            layout,
            GuestSettings::new(agent),
        ))
    }
}

/// The guest agent's file name inside the runtime folder.
pub const AGENT_FILE_NAME: &str = "puddle-agent";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_follow_the_data_folder() {
        let layout = RuntimeLayout::new("/rt".into(), "/data/msb".into()).unwrap_or_else(|_| {
            // Relative on this platform: the test only needs some layout.
            RuntimeLayout::new(
                std::env::temp_dir().join("rt"),
                std::env::temp_dir().join("h"),
            )
            .unwrap_or_else(|e| panic!("{e}"))
        });
        let config = HostConfig::new(
            HostPaths::new("/data"),
            layout,
            GuestSettings::new("/rt/puddle-agent"),
        );
        assert_eq!(
            config.api.connection_file.as_deref(),
            Some(Path::new("/data/api.json"))
        );
        assert_eq!(config.api.port, 0);
        assert_eq!(config.expected_runtime, RuntimeVersion::built_for());
        assert!(config.guest.git_identity.is_none());
        assert!(format!("{:?}", config.api).contains("connection_file"));
    }
}
