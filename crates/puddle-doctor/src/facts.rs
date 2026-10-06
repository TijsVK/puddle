// SPDX-License-Identifier: GPL-3.0-or-later
//! What a [`crate::Probe`] reports: plain data, no OS handles, so tests can fake every case and
//! [`crate::diagnose`] can turn it into findings on any platform.

use std::path::PathBuf;
use std::time::Duration;

/// The operating system the checks are worded for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Windows: WHP, AppLocker/WDAC, Global Secure Access.
    Windows,
    /// Linux: KVM (developers and CI; puddle ships for Windows).
    Linux,
    /// Anything else: only the portable checks.
    Other,
}

impl Os {
    /// The OS this build runs on.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }

    /// Lower-case name for reports (`windows`, `linux`, `other`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Other => "other",
        }
    }
}

/// The hypervisor API msb uses: WHP on Windows, `/dev/kvm` on Linux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypervisorApi {
    /// Usable: WHP reports a running hypervisor, or `/dev/kvm` opens read-write.
    Ready,
    /// Not installed: `WinHvPlatform.dll` doesn't load (the optional feature is off), or there is
    /// no `/dev/kvm`.
    NotInstalled {
        /// The loader's or the file system's error.
        detail: String,
    },
    /// WHP is installed but no hypervisor runs in this boot session.
    NotRunning,
    /// `/dev/kvm` exists but this user can't open it.
    AccessDenied {
        /// The error.
        detail: String,
    },
    /// The query itself failed in an unexpected way.
    QueryFailed {
        /// What failed.
        detail: String,
    },
    /// No hypervisor API is known for this OS.
    Unsupported,
}

/// Hardware virtualization and hypervisor facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypervisorFacts {
    /// The hypervisor API's state.
    pub api: HypervisorApi,
    /// Whether the firmware has CPU virtualization (VT-x / AMD-V) on; `None` when unknown.
    /// Windows can't read it reliably while its own hypervisor runs, so only trust it when
    /// [`HypervisorApi::Ready`] is not the case.
    pub firmware_virtualization: Option<bool>,
    /// The vendor of a hypervisor this OS runs *under* or *beside* (CPUID leaf `0x40000000`),
    /// e.g. `Microsoft Hv`, `VMwareVMware`, `KVMKVMKVM`; `None` when CPUID reports none.
    pub hypervisor_vendor: Option<String>,
}

/// Windows code integrity state (`NtQuerySystemInformation(SystemCodeIntegrityInformation)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "four independent flags of one Windows bit field"
)]
pub struct CodeIntegrity {
    /// Memory integrity (HVCI) enforces kernel code integrity.
    pub hvci: bool,
    /// App Control for Business (WDAC) enforces a policy for user-mode programs.
    pub user_mode_enforced: bool,
    /// The user-mode policy only audits.
    pub user_mode_audit: bool,
    /// Test signing is on.
    pub test_signing: bool,
}

/// Why the runtime's file can't be opened for running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessDenied {
    /// The file.
    pub path: PathBuf,
    /// The OS error.
    pub detail: String,
}

/// The bundled runtime's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    /// Present, permitted, and exactly the version this build needs.
    Ready {
        /// The version msb embeds.
        version: String,
        /// Accepted only because of the developer override (never in shipped builds).
        overridden: bool,
    },
    /// The file's permissions don't let this user read or run it.
    AccessDenied(AccessDenied),
    /// Missing, unreadable, or another version; the message names the file and both versions.
    Unusable(puddle_runtime::RuntimeError),
}

/// The bundled runtime: where it is and whether it is usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFacts {
    /// The runtime folder.
    pub dir: PathBuf,
    /// The msb executable's path.
    pub msb: PathBuf,
    /// The version this build needs.
    pub expected: String,
    /// Its state.
    pub state: RuntimeState,
}

/// How a run of the bundled msb ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// The process couldn't be created.
    SpawnFailed {
        /// The OS error code (`GetLastError` on Windows, `errno` elsewhere).
        os_error: Option<i32>,
        /// The error's text.
        detail: String,
    },
    /// The process ran and exited.
    Exited {
        /// Its exit code (on Windows an `NTSTATUS` for crashes, as `i32`); `None` when killed by
        /// a signal.
        code: Option<i32>,
        /// The first line of its standard output.
        stdout_first_line: String,
        /// The last lines of its standard error, at most [`crate::TAIL_LINES`].
        stderr_tail: String,
        /// How long it ran.
        elapsed: Duration,
    },
    /// It didn't finish in time and was killed.
    TimedOut {
        /// The time limit.
        after: Duration,
    },
}

/// The test boot: a microVM from a tiny local root file system that runs one probe program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootFacts {
    /// No test program exists for this CPU architecture.
    UnsupportedArch {
        /// The architecture.
        arch: String,
    },
    /// The root file system or msb home couldn't be prepared on the host.
    SetupFailed {
        /// What failed.
        detail: String,
    },
    /// msb ran.
    Ran {
        /// How it ended (the probe exits with [`crate::PROBE_EXIT_CODE`]).
        outcome: ProcessOutcome,
    },
}

/// Whether this process runs in a Windows job object, and what that job allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobFacts {
    /// Child processes may leave the job (`JOB_OBJECT_LIMIT_BREAKAWAY_OK` or silent breakaway).
    pub breakaway_allowed: bool,
}

/// Microsoft Entra Global Secure Access client state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsaFacts {
    /// None of its services exist.
    NotInstalled,
    /// At least one of its services exists.
    Installed {
        /// Whether one of them is running.
        running: bool,
    },
}
