// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-workspace settings document: one per workspace, holding its overrides.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{self, Document};
use crate::migrate::{self, Migration};
use crate::{Loaded, SettingsError, WorkspaceLayer};

/// The current shape of [`WorkspaceSettings`] documents.
pub const WORKSPACE_SCHEMA_VERSION: u32 = 1;

/// One workspace's settings. The workspace it belongs to is the store's key, not part of the
/// document, so renaming or importing a workspace doesn't rewrite it.
///
/// Settings that exist only per workspace (never as a global default, like "dangerous"
/// settings) go next to [`WorkspaceSettings::overrides`].
///
/// ```
/// use puddle_settings::WorkspaceSettings;
/// use serde_json::json;
///
/// let s = WorkspaceSettings::from_document(json!({"overrides": {"zoom_hotkeys": false}}))
///     .unwrap()
///     .settings;
/// assert_eq!(s.overrides.zoom_hotkeys, Some(false));
/// assert_eq!(s.to_document(), json!({"schema_version": 1, "overrides": {"zoom_hotkeys": false}}));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    /// This workspace's overrides of the global defaults; unset ones inherit.
    #[serde(default, skip_serializing_if = "WorkspaceLayer::is_empty")]
    pub overrides: WorkspaceLayer,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl WorkspaceSettings {
    /// Reads a stored document: checks its version, migrates it, keeps unknown fields.
    ///
    /// # Errors
    ///
    /// When the document isn't an object, has a bad or newer `schema_version`, a migration
    /// fails, or a value is invalid. See the crate docs for the rules.
    pub fn from_document(doc: Value) -> Result<Loaded<Self>, SettingsError> {
        document::load(doc)
    }

    /// The document to store: the current `schema_version`, set values only, unknown fields
    /// as they were read.
    #[must_use]
    pub fn to_document(&self) -> Value {
        document::store(self)
    }
}

impl Document for WorkspaceSettings {
    const KIND: &'static str = "workspace";
    const VERSION: u32 = WORKSPACE_SCHEMA_VERSION;
    const MIGRATIONS: &'static [Migration] = migrate::WORKSPACE;

    fn collect_unknown(&self, out: &mut Vec<String>) {
        document::push_unknown("", &self.extra, out);
        self.overrides.collect_unknown("overrides.", out);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unknown_fields_are_listed_with_their_path() {
        let loaded = WorkspaceSettings::from_document(json!({
            "dangerous": { "reach_puddle_endpoints": true },
            "overrides": { "local_toggles": { "vpn": false } }
        }))
        .unwrap();
        assert_eq!(
            loaded.unknown_fields,
            ["dangerous", "overrides.local_toggles.vpn"]
        );
        assert_eq!(
            loaded.settings.to_document()["dangerous"]["reach_puddle_endpoints"],
            true
        );
    }

    #[test]
    fn errors_name_the_document_kind() {
        let err = WorkspaceSettings::from_document(json!([])).unwrap_err();
        assert_eq!(err, SettingsError::NotAnObject { kind: "workspace" });
        let err =
            WorkspaceSettings::from_document(json!({"overrides":{"zoom_hotkeys":1}})).unwrap_err();
        assert!(
            matches!(
                err,
                SettingsError::Invalid {
                    kind: "workspace",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_document_without_overrides_is_version_only() {
        assert_eq!(
            WorkspaceSettings::default().to_document(),
            json!({"schema_version": 1})
        );
    }
}
