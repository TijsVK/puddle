// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading and writing settings documents: version check, migrations, unknown fields.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::migrate::{self, Migration, VERSION_KEY};

/// A document that failed to load. Nothing of it is applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsError {
    /// The document isn't a JSON object.
    #[error("{kind} settings must be an object")]
    NotAnObject {
        /// The document kind (`global`, `sandbox`).
        kind: &'static str,
    },
    /// `schema_version` isn't a whole number from 1 up.
    #[error("{kind} settings have an invalid schema version {found}")]
    InvalidVersion {
        /// The document kind.
        kind: &'static str,
        /// The value found (truncated).
        found: String,
    },
    /// The document was written by a newer puddle in a shape this version doesn't know.
    #[error(
        "{kind} settings have schema version {found}, written by a newer puddle; this version reads up to {supported}"
    )]
    NewerSchema {
        /// The document kind.
        kind: &'static str,
        /// The document's version.
        found: u32,
        /// The newest version this build reads.
        supported: u32,
    },
    /// A migration step failed.
    #[error("cannot migrate {kind} settings from schema version {from}: {reason}")]
    Migration {
        /// The document kind.
        kind: &'static str,
        /// The version the failing step starts from.
        from: u32,
        /// What went wrong.
        reason: String,
    },
    /// A value is invalid (out of range, wrong type, unknown enum value).
    #[error("invalid {kind} settings: {reason}")]
    Invalid {
        /// The document kind.
        kind: &'static str,
        /// What went wrong, from the value's own validation.
        reason: String,
    },
}

/// A document read by `from_document`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct Loaded<T> {
    /// The settings, in the current shape.
    pub settings: T,
    /// The version the document was stored in, if older than the current one: the caller
    /// should store the upgraded document (`to_document`) so the migration runs once.
    pub migrated_from: Option<u32>,
    /// Fields this version doesn't know, as dotted paths (`sandbox_defaults.cpus`). They are kept
    /// and written back unchanged; the caller logs them at `warn`.
    pub unknown_fields: Vec<String>,
}

/// What every document kind provides to the shared reader and writer.
pub(crate) trait Document: Serialize + DeserializeOwned {
    const KIND: &'static str;
    const VERSION: u32;
    const MIGRATIONS: &'static [Migration];

    fn collect_unknown(&self, out: &mut Vec<String>);
}

pub(crate) fn load<T: Document>(doc: Value) -> Result<Loaded<T>, SettingsError> {
    let (map, found) = migrate::upgrade(T::KIND, doc, T::VERSION, T::MIGRATIONS)?;
    let settings: T =
        serde_json::from_value(Value::Object(map)).map_err(|e| SettingsError::Invalid {
            kind: T::KIND,
            reason: e.to_string(),
        })?;
    let mut unknown_fields = Vec::new();
    settings.collect_unknown(&mut unknown_fields);
    Ok(Loaded {
        settings,
        migrated_from: (found < T::VERSION).then_some(found),
        unknown_fields,
    })
}

pub(crate) fn store<T: Document>(settings: &T) -> Value {
    #[expect(
        clippy::expect_used,
        reason = "settings types have string keys only and serialise to a JSON object"
    )]
    let mut value = serde_json::to_value(settings).expect("settings serialise to JSON");
    if let Value::Object(map) = &mut value {
        map.insert(VERSION_KEY.to_owned(), Value::from(T::VERSION));
    }
    value
}

pub(crate) fn push_unknown(prefix: &str, extra: &BTreeMap<String, Value>, out: &mut Vec<String>) {
    out.extend(extra.keys().map(|k| format!("{prefix}{k}")));
}
