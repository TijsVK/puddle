// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle doctor`: checks what puddle needs on this machine and what can get in its
//! way, and says plainly what is wrong and the exact fix. Dev-focused: no admin rights needed to
//! run it, and no IT-process advice.
//!
//! | Check | How | Typical finding |
//! |---|---|---|
//! | CPU virtualization | `IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)`; `/proc/cpuinfo` | off in UEFI/BIOS |
//! | Hypervisor | `WHvGetCapability(HypervisorPresent)` from System32's `WinHvPlatform.dll`; `/dev/kvm`; CPUID vendor | WHP feature off, not running yet, VM without nested virtualization |
//! | Code integrity | `NtQuerySystemInformation(SystemCodeIntegrityInformation)` | HVCI / App Control state (info) |
//! | Job object | `IsProcessInJob`, `QueryInformationJobObject` | job without breakaway (CI runners; info) |
//! | Bundled runtime | [`puddle_runtime::BundledRuntime::open`], plus opening `msb` for read + execute | missing, wrong version, permissions |
//! | Runtime starts | `msb --version` with a time limit | `AppLocker`, App Control / Smart App Control, antivirus, EDR, missing DLL, timeout |
//! | Test boot | `msb run` of a 132-byte probe program in a tiny root file system ([`boot`]) | can't boot a VM, timeout |
//! | Global Secure Access | its client's services | installed: explains the VM limitation |
//!
//! [`diagnose`] runs the checks against a [`Probe`]: [`SystemProbe`] for the real machine, a fake
//! in tests. The [`Report`] renders as text or as JSON with a [`SCHEMA_VERSION`] (it may be
//! attached to crash reports later).
//!
//! Classification rules for a refused start (who blocked msb):
//!
//! - `ERROR_ACCESS_DISABLED_BY_POLICY` (1260): `AppLocker` or Software Restriction Policies;
//! - `ERROR_SYSTEM_INTEGRITY_*` (4550–4562, 4580–4582), `ERROR_INVALID_IMAGE_HASH` (577),
//!   `STATUS_INVALID_IMAGE_HASH`: App Control for Business (WDAC) or Smart App Control;
//! - `ERROR_VIRUS_INFECTED`/`_DELETED`, `STATUS_VIRUS_INFECTED`: antivirus;
//! - access denied although the file opens for execute: endpoint security (EDR). A deny ACE on
//!   the file is found earlier, by the runtime check, so it is never mistaken for EDR;
//! - access denied while booting inside a job that forbids breakaway: the job, not EDR (hosted CI
//!   runners).

pub mod boot;
mod diagnose;
mod facts;
mod launch;
mod report;
mod sys;
mod system;

pub use diagnose::{Options, PROBE_EXIT_CODE, Probe, diagnose};
pub use facts::{
    AccessDenied, BootFacts, CodeIntegrity, GsaFacts, HypervisorApi, HypervisorFacts, JobFacts, Os,
    ProcessOutcome, RuntimeFacts, RuntimeState,
};
pub use launch::TAIL_LINES;
pub use puddle_runtime::RuntimeError;
pub use report::{Check, CheckId, Finding, Report, SCHEMA_VERSION, Status};
pub use system::SystemProbe;
