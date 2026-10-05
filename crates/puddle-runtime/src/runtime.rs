// SPDX-License-Identifier: GPL-3.0-or-later
//! The opened, version-checked bundled runtime.

use std::process::Command;

use crate::version::VersionRefusal;
use crate::{
    DevOverride, RuntimeEnv, RuntimeError, RuntimeLayout, RuntimeVersion, VersionStatus,
    check_version, read_embedded_version,
};

/// A bundled runtime that exists and passed the version check. Only this type hands out the
/// environment, so code can't run msb without the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledRuntime {
    layout: RuntimeLayout,
    status: VersionStatus,
}

impl BundledRuntime {
    /// Opens the runtime in `layout` and checks its embedded version against `expected`
    /// (normally [`RuntimeVersion::built_for`]).
    ///
    /// The binary is only read, never run; `PATH` is never searched.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Missing`], [`RuntimeError::Unreadable`], [`RuntimeError::NoVersion`] or
    /// [`RuntimeError::Mismatch`] (naming both versions), unless `dev` is active for the last two.
    pub fn open(
        layout: RuntimeLayout,
        expected: &RuntimeVersion,
        dev: DevOverride,
    ) -> Result<Self, RuntimeError> {
        if let Some(path) = layout.required_files().into_iter().find(|f| !f.is_file()) {
            return Err(RuntimeError::Missing { path });
        }
        let path = layout.msb_path();
        let found = read_embedded_version(&path).map_err(|reason| RuntimeError::Unreadable {
            path: path.clone(),
            reason,
        })?;
        let status = check_version(expected, found.as_deref(), dev).map_err(|refusal| {
            let expected = expected.to_string();
            match refusal {
                VersionRefusal::NoVersion => RuntimeError::NoVersion {
                    path: path.clone(),
                    expected,
                },
                VersionRefusal::Mismatch(found) => RuntimeError::Mismatch {
                    path: path.clone(),
                    expected,
                    found,
                },
            }
        })?;
        Ok(Self { layout, status })
    }

    /// The layout the runtime was opened from.
    #[must_use]
    pub fn layout(&self) -> &RuntimeLayout {
        &self.layout
    }

    /// How the version check passed; [`VersionStatus::Overridden`] should be logged as a warning.
    #[must_use]
    pub fn status(&self) -> &VersionStatus {
        &self.status
    }

    /// The environment plan against the current process environment.
    #[must_use]
    pub fn env(&self) -> RuntimeEnv {
        RuntimeEnv::plan(&self.layout, std::env::vars_os())
    }

    /// A command that runs the bundled msb by absolute path with the pinned environment (for
    /// `puddle doctor` and diagnostics; the SDK starts msb itself).
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(self.layout.msb_path());
        self.env().apply_to(&mut command);
        command
    }
}
