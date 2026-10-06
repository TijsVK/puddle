// SPDX-License-Identifier: GPL-3.0-or-later
//! The compute-plane traits ([`puddle_compute::Runtime`], [`puddle_compute::Sandbox`]) over the
//! msb SDK (`microsandbox = "=0.7.7"`, stock until T-117 moves it to the fork tag).
//!
//! Everything above the compute plane codes against the traits; this crate is the only one that
//! talks to the SDK. [`MsbRuntime::open`] takes an [`MsbConfig`] (private msb home, the runtime
//! pair, the guest-share root, SSH keys) and every SDK call runs scoped to that home, so the
//! user's own `~/.microsandbox` is never read or written by these calls.
//!
//! # What the adapter adds on top of the SDK
//!
//! | Contract point | How |
//! |---|---|
//! | Errors are [`puddle_compute::ComputeError`] | [`error::map`]: SDK variants first, messages only where the SDK has no variant |
//! | A handle belongs to one boot (`StaleHandle`) | the handle remembers the VM process id of its boot and compares it on every exec, SSH and stop |
//! | Exit codes exact, signals `-1` | passed through from the SDK (T-028) |
//! | `VolumeInUse` names the holder | puddle looks it up: the running sandbox whose config mounts the volume (msb's own refusal doesn't name it) |
//! | `VolumeNotFound` / `VolumeSizeMismatch` | checked against the volume catalog before the SDK create |
//! | No stale directory after a failed create | a create that fails removes the sandbox directory it left (msb T-039 is unfixed in 0.7.7), so [`puddle_compute::Capabilities::stale_dir_fixed`] is `true` |
//! | Mount sources | every file mount's host path must lie under [`MsbConfig::guest_share`] (T-020 C-7) |
//! | Memory | `--memory` from the spec at create; [`puddle_compute::Runtime::set_memory`] persists a new size for the next start; `--max-memory` is never set |
//!
//! # SDK options
//!
//! [`SDK_OPTIONS`] lists every `SandboxBuilder` option puddle sets and every one it leaves at the
//! SDK default, with the default, for the D-27 escape-hardening review. A unit test keeps it in
//! step with [`spec::builder`].
#![forbid(unsafe_code)]

mod config;
pub mod error;
mod image;
mod runtime;
mod sandbox;
pub mod spec;
mod volume;

pub use config::{MsbConfig, SshConfig};
pub use runtime::MsbRuntime;
pub use sandbox::MsbSandbox;
pub use spec::{SDK_OPTIONS, SdkOption, SdkSetting};

/// The label every sandbox puddle creates carries (value [`OWNER_LABEL_VALUE`]), so a reconcile
/// can tell puddle's sandboxes from a user's own (T-113).
pub const OWNER_LABEL: &str = "dev.puddle.owner";

/// The value of [`OWNER_LABEL`].
pub const OWNER_LABEL_VALUE: &str = "puddle";
