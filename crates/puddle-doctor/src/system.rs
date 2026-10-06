// SPDX-License-Identifier: GPL-3.0-or-later
//! The real machine as a [`Probe`].

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use puddle_runtime::{
    BundledRuntime, DevOverride, RUNTIME_DIR_NAME, RuntimeError, RuntimeLayout, RuntimeVersion,
    VersionStatus,
};

use crate::diagnose::Probe;
use crate::facts::{
    AccessDenied, BootFacts, CodeIntegrity, GsaFacts, HypervisorFacts, JobFacts, Os,
    ProcessOutcome, RuntimeFacts, RuntimeState,
};
use crate::{boot, launch, sys};

/// Probes this machine and the bundled runtime in one folder.
#[derive(Debug)]
pub struct SystemProbe {
    runtime_dir: PathBuf,
    expected: RuntimeVersion,
    dev: DevOverride,
    opened: OnceCell<BundledRuntime>,
}

impl SystemProbe {
    /// Probes the runtime in `runtime_dir`, which must be exactly `expected` (unless `dev` is
    /// active in a development build).
    #[must_use]
    pub fn new(runtime_dir: PathBuf, expected: RuntimeVersion, dev: DevOverride) -> Self {
        Self {
            runtime_dir,
            expected,
            dev,
            opened: OnceCell::new(),
        }
    }

    /// Probes the installed runtime: `runtime/` next to `exe` (normally
    /// [`std::env::current_exe`]), the version this build was made for, and the developer
    /// override from the environment.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::NoExeDir`] if `exe` has no parent folder.
    pub fn installed(exe: &Path) -> Result<Self, RuntimeError> {
        let dir = exe.parent().ok_or_else(|| RuntimeError::NoExeDir {
            path: exe.to_path_buf(),
        })?;
        Ok(Self::new(
            dir.join(RUNTIME_DIR_NAME),
            RuntimeVersion::built_for(),
            DevOverride::from_env(),
        ))
    }

    fn layout(&self) -> Result<RuntimeLayout, RuntimeError> {
        // The home is unused here: `--version` doesn't touch it and the test boot brings its own.
        RuntimeLayout::new(self.runtime_dir.clone(), std::env::temp_dir())
    }
}

impl Probe for SystemProbe {
    fn os(&self) -> Os {
        Os::current()
    }

    fn arch(&self) -> String {
        std::env::consts::ARCH.to_owned()
    }

    fn hypervisor(&self) -> HypervisorFacts {
        sys::hypervisor()
    }

    fn code_integrity(&self) -> Option<CodeIntegrity> {
        sys::code_integrity()
    }

    fn runtime(&self) -> RuntimeFacts {
        let msb = self.runtime_dir.join(puddle_runtime::MSB_FILE_NAME);
        let facts = |state| RuntimeFacts {
            dir: self.runtime_dir.clone(),
            msb: msb.clone(),
            expected: self.expected.to_string(),
            state,
        };
        let layout = match self.layout() {
            Ok(layout) => layout,
            Err(e) => return facts(RuntimeState::Unusable(e)),
        };
        if layout.required_files().iter().all(|f| f.is_file())
            && let Err(e) = sys::file_access(&msb)
            && e.kind() == std::io::ErrorKind::PermissionDenied
        {
            return facts(RuntimeState::AccessDenied(AccessDenied {
                path: msb.clone(),
                detail: e.to_string(),
            }));
        }
        match BundledRuntime::open(layout, &self.expected, self.dev) {
            Ok(rt) => {
                let state = match rt.status() {
                    VersionStatus::Overridden { found } => RuntimeState::Ready {
                        version: found.clone().unwrap_or_else(|| "(no version)".into()),
                        overridden: true,
                    },
                    VersionStatus::Exact => RuntimeState::Ready {
                        version: self.expected.to_string(),
                        overridden: false,
                    },
                };
                // Set once: `runtime` runs once per diagnosis.
                let _first = self.opened.set(rt);
                facts(state)
            }
            Err(e) => facts(RuntimeState::Unusable(e)),
        }
    }

    fn launch(&self, limit: Duration) -> ProcessOutcome {
        match self.opened.get() {
            Some(rt) => launch::run(rt.command().arg("--version"), limit),
            None => ProcessOutcome::SpawnFailed {
                os_error: None,
                detail: "the runtime wasn't opened".into(),
            },
        }
    }

    fn boot(&self, limit: Duration) -> BootFacts {
        boot::test_boot(&self.runtime_dir, std::env::consts::ARCH, limit)
    }

    fn job(&self) -> Option<JobFacts> {
        sys::job()
    }

    fn global_secure_access(&self) -> Option<GsaFacts> {
        sys::global_secure_access()
    }
}
