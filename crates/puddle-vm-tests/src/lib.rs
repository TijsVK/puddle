// SPDX-License-Identifier: GPL-3.0-or-later
//! Harness for tests that boot real microVMs through the msb SDK (T-032 tiers K, W and L).
//!
//! Test code only; never a dependency of product crates.
//!
//! # What a VM test gets
//!
//! [`VmEnv::from_env`] sets up one isolated msb world per test process:
//!
//! - a **per-run prefix** ([`RunPrefix`], from `PUDDLE_VM_PREFIX` or generated) that starts every
//!   sandbox name the run creates, so up to three runs can share a host and cleanup only ever
//!   touches its own sandboxes;
//! - a **private msb home** under `PUDDLE_VM_ROOT` (default: the temp dir) named after the prefix,
//!   holding msb's database, image cache, logs and a `config.json` that points at the runtime
//!   pair. The user's own `~/.microsandbox` is never read or written;
//! - the **runtime pair** (`msb` + `libkrunfw`) from `PUDDLE_VM_RUNTIME_DIR` ([`RuntimePair`]),
//!   the flat layout of msb's release archive. Ambient `MSB_*` variables are refused, because
//!   they would silently override the explicit pair (D-19);
//! - an SDK backend scoped to the test ([`VmEnv::scope`]): SDK calls inside the scope use the
//!   private home, without touching process-wide state.
//!
//! # Conventions
//!
//! - VM test functions (or their test binaries) are named `vm_*`. nextest runs them only under
//!   `--profile vm`, one at a time, and never retries them (`.config/nextest.toml`, T-032).
//! - Laptop-only tests (tier L: real client OS, mains power, corporate network) are named
//!   `vm_laptop_*`; the CI jobs skip them, `ci/windows-e2e.ps1` runs them.
//! - Sandbox names come from [`VmEnv::sandbox_name`]; images from the constants below.
//!
//! # Running
//!
//! ```text
//! PUDDLE_VM_RUNTIME_DIR=/path/to/msb-0.7.7 cargo nextest run -p puddle-vm-tests --profile vm
//! ```
//!
//! The `vm-linux` and `vm-windows` workflows fetch and verify the runtime with
//! `ci/fetch-msb.sh` and run exactly that.
#![forbid(unsafe_code)]

mod env;
mod error;
mod prefix;
mod runtime;

pub use env::{Settings, VmEnv, within};
pub use error::HarnessError;
pub use prefix::RunPrefix;
pub use runtime::{AMBIENT_MSB_VARS, RuntimePair, refuse_ambient_msb_vars};

/// The stock devcontainer image every VM tier boots first (T-028, T-041).
pub const DEBIAN_DEVCONTAINER: &str = "mcr.microsoft.com/devcontainers/base:debian";

/// Environment variable naming the directory that holds `msb` and `libkrunfw`.
pub const RUNTIME_DIR_VAR: &str = "PUDDLE_VM_RUNTIME_DIR";

/// Environment variable with the run prefix; generated when unset.
pub const PREFIX_VAR: &str = "PUDDLE_VM_PREFIX";

/// Environment variable with the directory private msb homes go under; the temp dir when unset.
pub const ROOT_VAR: &str = "PUDDLE_VM_ROOT";

/// Label every harness-created sandbox carries, with the run prefix as its value.
pub const RUN_LABEL: &str = "puddle-vm-run";
