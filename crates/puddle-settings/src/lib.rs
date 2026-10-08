// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's settings model: the global settings, per-workspace overrides, the consent
//! store, and how a stored document is versioned, migrated and read back. No storage and no API:
//! a store keeps the documents ([`GlobalSettings::to_document`] gives a JSON value), the API
//! serves them.
//!
//! | Item | What |
//! |---|---|
//! | [`GlobalSettings`] | one per user: defaults for every workspace, VS Code server options, consents |
//! | [`WorkspaceSettings`] | one per workspace: its overrides |
//! | [`WorkspaceLayer`], [`LocalToggles`] | the settings a workspace has, each optional; used for both levels |
//! | [`Effective`], [`Resolved`], [`Source`] | the value a workspace gets and which level it came from |
//! | [`Consent`], [`Consents`], [`ConsentKind`], [`TermsVersion`], [`UnixMillis`] | what the user agreed to or declined, when, and to which version of the terms |
//! | [`UiPrefs`] | the window's theme, notification and close preferences |
//! | [`ReconnectionGrace`], [`ClipboardRead`], [`ServerChoice`], [`ThemeChoice`], [`DensityChoice`], [`CloseBehaviour`] | value types for single settings |
//! | [`Loaded`], [`SettingsError`] | the result of reading a document |
//!
//! # Resolution
//!
//! Every per-workspace setting has three levels: the workspace's override, the global value, and
//! puddle's built-in default. A level that is unset (`None`, absent in the document) passes on to
//! the next one, so a user who never touched a setting follows puddle's default even when a later
//! version changes it. [`resolve`] is the only place that applies this rule.
//!
//! ```
//! use puddle_settings::{GlobalSettings, WorkspaceSettings, Source, resolve};
//! use puddle_types::MemoryMib;
//!
//! let mut global = GlobalSettings::default();
//! global.workspace_defaults.memory = Some(MemoryMib::new(4096).unwrap());
//! let mut big = WorkspaceSettings::default();
//! big.overrides.memory = Some(MemoryMib::new(16 * 1024).unwrap());
//!
//! assert_eq!(resolve(&global, Some(&big)).memory.value.get(), 16 * 1024);
//! assert_eq!(resolve(&global, None).memory.value.get(), 4096);
//! assert_eq!(resolve(&GlobalSettings::default(), None).memory.source, Source::Default);
//! ```
//!
//! # Documents, versions and unknown fields
//!
//! Each document kind carries `schema_version` (currently [`GLOBAL_SCHEMA_VERSION`] and
//! [`WORKSPACE_SCHEMA_VERSION`]). Reading one ([`GlobalSettings::from_document`]):
//!
//! - **Missing version** means version 1, so `{}` is a valid document with every value unset.
//! - **Older version**: migrations run in order, one step per version; [`Loaded::migrated_from`]
//!   says it happened, so the caller can write the upgraded document back.
//! - **Newer version** (written by a newer puddle): refused with [`SettingsError::NewerSchema`].
//!   A version bump means a field changed meaning, so guessing would be wrong.
//! - **Unknown fields** are kept, not dropped and not rejected: they come back out of
//!   `to_document` unchanged, and [`Loaded::unknown_fields`] lists them for a warning. So an
//!   additive field (new, optional, absent means "as before") needs no version bump, and an
//!   older puddle that reads and rewrites a newer document of the same version keeps it.
//! - **Invalid values** (a memory size out of range, an unknown enum value) fail the whole
//!   document with [`SettingsError::Invalid`]; nothing is half-applied.
//!
//! Changing a field's type or meaning, renaming it, or adding an enum variant that older
//! versions would reject needs a version bump and a migration (see `migrate.rs`).
#![forbid(unsafe_code)]

mod consent;
mod document;
mod global;
mod layer;
mod migrate;
mod resolve;
mod values;
mod workspace;

pub use consent::{Consent, ConsentKind, Consents, TermsVersion, UnixMillis};
pub use document::{Loaded, SettingsError};
pub use global::{GLOBAL_SCHEMA_VERSION, GlobalSettings, UiPrefs, VsCodeServer};
pub use layer::{LocalToggles, WorkspaceLayer};
pub use resolve::{Effective, EffectiveToggles, Resolved, Source, resolve};
pub use values::{
    ClipboardRead, CloseBehaviour, DensityChoice, ReconnectionGrace, ServerChoice, ThemeChoice,
};
pub use workspace::{WORKSPACE_SCHEMA_VERSION, WorkspaceSettings};
