// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared types for puddle's crates: identifiers, wire types and errors that cross crate
//! boundaries. Keep this crate small and free of I/O, so every other crate can depend on it.
//!
//! (The W1 breakdown, T-081, calls this crate `puddle-core`.)
//!
//! | Item | What |
//! |---|---|
//! | [`SandboxName`], [`WorkspaceId`], [`VolumeName`], [`ImageRef`] | validated names; sandbox, workspace and volume names are DNS labels |
//! | [`GuestPath`], [`GuestFile`], [`GuestEnv`] | what providers put into a guest; the boot hook applies them |
//! | [`MemoryMib`] | guest memory size: 256 MiB to 1 TiB, default 8 GiB (the setting is in `puddle-settings`) |
//! | [`SandboxStatus`], [`Event`], [`EventSink`] | sandbox states and the user-facing event stream (incl. [`Event::OomKill`]) |
//! | [`Host`], [`DomainName`] | a normalised egress destination (the proxy normalises, everyone else validates) |
//! | [`EgressRequest`], [`Decision`], [`Policy`] | what the proxy asks the rules engine and what it gets back |
//! | [`ValidationError`] | the one error every checked constructor returns |
//!
//! Every checked type validates in its constructor *and* when deserialised, so a value of the
//! type is always valid. Names are compared and hashed as plain strings.
#![forbid(unsafe_code)]

mod error;
mod event;
mod guest;
mod host;
mod memory;
mod name;
mod policy;

pub use error::ValidationError;
pub use event::{CollectingSink, Event, EventSink, NullSink, SandboxStatus};
pub use guest::{GuestEnv, GuestFile, GuestPath};
pub use host::{DomainName, Host, MAX_LABEL_LEN, MAX_NAME_LEN};
pub use memory::MemoryMib;
pub use name::{
    ImageRef, RESERVED_SANDBOX_NAMES, SandboxName, VolumeName, WORKSPACE_VOLUME_PREFIX, WorkspaceId,
};

pub use policy::{
    BlockReason, Decision, EgressRequest, PatternKind, PendingId, PendingOutcome, Policy,
    PolicyError, ProtocolHint, RuleId, SuffixAllows,
};

/// puddle's version, from the workspace manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The line a puddle binary prints for `--version`: the program name and puddle's version.
///
/// ```
/// assert_eq!(puddle_types::version_line("puddle"), format!("puddle {}", puddle_types::VERSION));
/// ```
#[must_use]
pub fn version_line(program: &str) -> String {
    format!("{program} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, "0.0.0");
    }

    #[test]
    fn version_line_names_program_then_version() {
        assert_eq!(version_line("puddle-agent"), "puddle-agent 0.0.0");
    }
}
