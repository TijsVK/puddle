// SPDX-License-Identifier: GPL-3.0-or-later
//! The msb runtime puddle ships with (D-19): where it lives, the environment that makes the SDK use
//! it and nothing else, and the check that it is exactly the version this build was made for.
//!
//! puddle never uses a user's own msb. At startup it:
//!
//! 1. builds a [`RuntimeLayout`]: the bundled runtime folder (next to `puddle.exe`) and puddle's
//!    private `MSB_HOME`, so images and volumes never mix with a user's own msb;
//! 2. opens the runtime with [`BundledRuntime::open`], which refuses a missing `msb` binary or one
//!    whose embedded version isn't exactly [`BUILT_FOR`] (both versions named in the error);
//! 3. pins the environment with [`RuntimeEnv`]: removes **every** `MSB_*` variable the user set
//!    (incl. `MSB_LIBKRUNFW_PATH`, `MSB_AGENTD_PATH`, `MSB_BACKEND`), then sets `MSB_PATH`,
//!    `MSB_HOME` and `MSB_CONFIG_PATH`. Apply it to the process before any thread starts
//!    ([`RuntimeEnv::apply_to_process`]) or to a child [`std::process::Command`].
//!
//! | Item | What |
//! |---|---|
//! | [`BUILT_FOR`], [`RuntimeVersion`] | the pinned `<release>-puddle.N` and its parser |
//! | [`read_embedded_version`] | the version msb embeds in its binary (`.msbver`), read without running it |
//! | [`check_version`], [`VersionStatus`], [`DevOverride`] | the exact-match rule and the dev-only escape hatch |
//! | [`RuntimeLayout`], [`RuntimeEnv`], [`BundledRuntime`] | paths, environment, the opened runtime |
//! | [`RuntimeError`] | every way the runtime can be unusable |
//!
//! # Features
//!
//! - `dev-override`: honours `PUDDLE_DEV_ANY_RUNTIME=1` ([`DevOverride`]). Off by default; a
//!   release build with it on doesn't compile, and a test fails if any workspace crate enables it.

mod env;
mod error;
mod layout;
mod msbver;
mod runtime;
mod version;

pub use env::{RuntimeEnv, is_msb_variable};
pub use error::RuntimeError;
pub use layout::{LIBKRUNFW_FILE_NAME, MSB_FILE_NAME, RUNTIME_DIR_NAME, RuntimeLayout};
pub use msbver::{MAX_VERSION_BYTES, VERSION_SECTION, read_embedded_version};
pub use runtime::BundledRuntime;
pub use version::{
    BUILT_FOR, DEV_OVERRIDE_COMPILED, DEV_OVERRIDE_VAR, DevOverride, ParseVersionError,
    RuntimeVersion, VersionRefusal, VersionStatus, check_version,
};

#[cfg(all(feature = "dev-override", not(debug_assertions)))]
compile_error!(
    "the `dev-override` feature is for development builds only; release builds must refuse a runtime of another version"
);
