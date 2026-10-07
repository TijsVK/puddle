// SPDX-License-Identifier: GPL-3.0-or-later
//! What the host asks of the machine before the runtime opens, behind a trait so the start-up
//! order can be tested without touching the process environment or the runtime folder.

use puddle_certs::{CorporateRoots, read_host_stores};
use puddle_runtime::{BundledRuntime, DevOverride, RuntimeEnv, RuntimeLayout, RuntimeVersion};

use crate::HostError;

/// The machine-level steps of [`crate::prepare`], in the order it calls them.
pub trait Platform: Send + Sync {
    /// Pins the process environment: removes every `MSB_*` variable and sets the three puddle
    /// owns. Must run before any other thread starts.
    ///
    /// # Errors
    ///
    /// [`HostError::EnvironmentTooLate`] when other threads already run.
    fn pin_environment(&self, layout: &RuntimeLayout) -> Result<(), HostError>;

    /// Checks the bundled runtime: files present, exactly the version this build expects.
    ///
    /// # Errors
    ///
    /// [`HostError::Runtime`].
    fn check_runtime(
        &self,
        layout: &RuntimeLayout,
        expected: &RuntimeVersion,
    ) -> Result<(), HostError>;

    /// The host's corporate root certificates (admin- and user-added, minus distrusted).
    ///
    /// # Errors
    ///
    /// [`HostError::Roots`] when a store that must be read cannot be.
    fn corporate_roots(&self) -> Result<CorporateRoots, HostError>;
}

/// The real machine.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemPlatform {
    dev: DevOverrideChoice,
}

#[derive(Debug, Clone, Copy, Default)]
enum DevOverrideChoice {
    #[default]
    None,
    FromEnv,
}

impl SystemPlatform {
    /// The real machine; a runtime of another version is always refused.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The real machine, honouring `PUDDLE_DEV_ANY_RUNTIME` in builds that have the
    /// `dev-override` feature of `puddle-runtime`.
    #[must_use]
    pub fn with_dev_override_from_env(mut self) -> Self {
        self.dev = DevOverrideChoice::FromEnv;
        self
    }

    fn dev_override(self) -> DevOverride {
        match self.dev {
            DevOverrideChoice::None => DevOverride::none(),
            DevOverrideChoice::FromEnv => DevOverride::from_env(),
        }
    }
}

impl Platform for SystemPlatform {
    fn pin_environment(&self, layout: &RuntimeLayout) -> Result<(), HostError> {
        let plan = RuntimeEnv::plan(layout, std::env::vars_os());
        crate::process_env::apply(&plan)
    }

    fn check_runtime(
        &self,
        layout: &RuntimeLayout,
        expected: &RuntimeVersion,
    ) -> Result<(), HostError> {
        BundledRuntime::open(layout.clone(), expected, self.dev_override())?;
        Ok(())
    }

    fn corporate_roots(&self) -> Result<CorporateRoots, HostError> {
        let snapshot = read_host_stores().map_err(|e| HostError::Roots(e.to_string()))?;
        Ok(CorporateRoots::select(
            &snapshot,
            std::time::SystemTime::now(),
        ))
    }
}
