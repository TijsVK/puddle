// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the host keeps its files, all under one data folder.

use std::path::{Path, PathBuf};

/// The files and folders of one puddle installation, derived from its data folder.
///
/// The msb home (`msb/`) belongs to [`puddle_runtime::RuntimeLayout`]; everything else the host
/// writes is named here so one value says where a run's state lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    data: PathBuf,
}

impl HostPaths {
    /// Paths below `data` (an absolute folder, created on demand).
    #[must_use]
    pub fn new(data: impl Into<PathBuf>) -> Self {
        Self { data: data.into() }
    }

    /// The data folder.
    #[must_use]
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// The SQLite database: rules, pending requests, audit.
    #[must_use]
    pub fn store(&self) -> PathBuf {
        self.data.join("puddle.db")
    }

    /// The settings documents: `global.json` and `sandboxes/<name>.json`.
    #[must_use]
    pub fn settings(&self) -> PathBuf {
        self.data.join("settings")
    }

    /// The workspace book: what puddle knows about each workspace besides its volume.
    #[must_use]
    pub fn workspace_book(&self) -> PathBuf {
        self.data.join("workspaces.json")
    }

    /// The root every sandbox mount source must be inside (msb mounts only from here).
    #[must_use]
    pub fn guest_share(&self) -> PathBuf {
        self.data.join("guest-share")
    }

    /// The API's connection file (URL and token), for the CLI and `npm run dev`.
    #[must_use]
    pub fn connection_file(&self) -> PathBuf {
        self.data.join("api.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_path_is_below_the_data_folder() {
        let paths = HostPaths::new("/data/puddle");
        for path in [
            paths.store(),
            paths.settings(),
            paths.workspace_book(),
            paths.guest_share(),
            paths.connection_file(),
        ] {
            assert!(path.starts_with("/data/puddle"), "{path:?}");
        }
        assert_eq!(paths.data(), Path::new("/data/puddle"));
    }

    #[test]
    fn the_names_are_distinct() {
        let paths = HostPaths::new("/d");
        let all = [
            paths.store(),
            paths.settings(),
            paths.workspace_book(),
            paths.guest_share(),
            paths.connection_file(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
