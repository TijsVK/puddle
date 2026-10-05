// SPDX-License-Identifier: GPL-3.0-or-later
//! The global settings document: one per user.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{self, Document};
use crate::migrate::{self, Migration};
use crate::{Consents, Loaded, SandboxLayer, SettingsError};

/// The current shape of [`GlobalSettings`] documents.
pub const GLOBAL_SCHEMA_VERSION: u32 = 1;

/// puddle's settings for this user: defaults for every sandbox, options that only exist
/// globally, and the consents.
///
/// ```
/// use puddle_settings::GlobalSettings;
/// use serde_json::json;
///
/// let loaded = GlobalSettings::from_document(json!({
///     "schema_version": 1,
///     "sandbox_defaults": { "memory": 4096, "local_toggles": { "private": true } },
///     "consents": { "telemetry": { "state": "declined", "at": 1, "terms_version": "t1" } },
/// })).unwrap();
/// assert_eq!(loaded.settings.sandbox_defaults.memory.unwrap().get(), 4096);
/// assert!(loaded.unknown_fields.is_empty());
///
/// let doc = loaded.settings.to_document();
/// assert_eq!(doc["schema_version"], 1);
/// assert_eq!(GlobalSettings::from_document(doc).unwrap().settings, loaded.settings);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GlobalSettings {
    /// The value every sandbox gets unless it overrides it. Unset values fall back to puddle's
    /// built-in defaults.
    #[serde(default, skip_serializing_if = "SandboxLayer::is_empty")]
    pub sandbox_defaults: SandboxLayer,
    /// Options for Microsoft's VS Code server (global only).
    #[serde(default, skip_serializing_if = "VsCodeServer::is_empty")]
    pub vscode_server: VsCodeServer,
    /// What the user agreed to or declined (per user, never per sandbox).
    #[serde(default, skip_serializing_if = "Consents::is_empty")]
    pub consents: Consents,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl GlobalSettings {
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

impl Document for GlobalSettings {
    const KIND: &'static str = "global";
    const VERSION: u32 = GLOBAL_SCHEMA_VERSION;
    const MIGRATIONS: &'static [Migration] = migrate::GLOBAL;

    fn collect_unknown(&self, out: &mut Vec<String>) {
        document::push_unknown("", &self.extra, out);
        self.sandbox_defaults
            .collect_unknown("sandbox_defaults.", out);
        document::push_unknown("vscode_server.", &self.vscode_server.extra, out);
        self.consents.collect_unknown("consents.", out);
    }
}

/// Options for Microsoft's VS Code server once the user enabled it (D-40). Whether it is
/// enabled at all is [`Consents::vscode_server`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VsCodeServer {
    /// Let the server send Microsoft its telemetry: the checkbox in the enable popup, default
    /// off (unchecked passes `--disable-telemetry`, D-40 (6)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<bool>,
    /// Update the server automatically when no window is connected; default on (D-43 (6)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_update: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl VsCodeServer {
    /// puddle's default for [`VsCodeServer::telemetry`].
    pub const DEFAULT_TELEMETRY: bool = false;
    /// puddle's default for [`VsCodeServer::auto_update`].
    pub const DEFAULT_AUTO_UPDATE: bool = true;

    /// Whether the server's telemetry is on.
    #[must_use]
    pub fn telemetry(&self) -> bool {
        self.telemetry.unwrap_or(Self::DEFAULT_TELEMETRY)
    }

    /// Whether the server updates itself.
    #[must_use]
    pub fn auto_update(&self) -> bool {
        self.auto_update.unwrap_or(Self::DEFAULT_AUTO_UPDATE)
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl Consents {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Consent, ConsentKind, TermsVersion, UnixMillis};

    #[test]
    fn empty_object_is_all_defaults_and_writes_back_as_version_only() {
        let loaded = GlobalSettings::from_document(json!({})).unwrap();
        assert_eq!(loaded.settings, GlobalSettings::default());
        assert_eq!(loaded.migrated_from, None);
        assert_eq!(
            loaded.settings.to_document(),
            json!({ "schema_version": 1 })
        );
    }

    #[test]
    fn vscode_server_defaults() {
        let v = VsCodeServer::default();
        assert!(!v.telemetry());
        assert!(v.auto_update());
        let loaded = GlobalSettings::from_document(
            json!({"vscode_server":{"telemetry":true,"auto_update":false}}),
        )
        .unwrap();
        assert!(loaded.settings.vscode_server.telemetry());
        assert!(!loaded.settings.vscode_server.auto_update());
    }

    #[test]
    fn unknown_fields_at_every_level_are_listed_and_written_back() {
        let doc = json!({
            "schema_version": 1,
            "rule_sets": ["trackers"],
            "sandbox_defaults": { "cpus": 2, "local_toggles": { "vpn": true } },
            "vscode_server": { "channel": "insiders" },
            "consents": {
                "usage_survey": { "state": "granted" },
                "telemetry": { "state": "not_asked" }
            }
        });
        let loaded = GlobalSettings::from_document(doc.clone()).unwrap();
        assert_eq!(
            loaded.unknown_fields,
            [
                "rule_sets",
                "sandbox_defaults.cpus",
                "sandbox_defaults.local_toggles.vpn",
                "vscode_server.channel",
                "consents.usage_survey",
            ]
        );
        let mut want = doc;
        // A not-asked consent is the default, so it isn't written out.
        want["consents"]
            .as_object_mut()
            .unwrap()
            .remove("telemetry");
        assert_eq!(loaded.settings.to_document(), want);
    }

    #[test]
    fn errors_name_the_document_kind() {
        let err =
            GlobalSettings::from_document(json!({"sandbox_defaults":{"memory":1}})).unwrap_err();
        assert!(matches!(err, SettingsError::Invalid { kind: "global", .. }));
        assert!(err.to_string().contains("invalid memory size"), "{err}");
        let err = GlobalSettings::from_document(json!({"schema_version":2})).unwrap_err();
        assert!(matches!(
            err,
            SettingsError::NewerSchema {
                kind: "global",
                found: 2,
                supported: 1
            }
        ));
    }

    #[test]
    fn consents_round_trip() {
        let mut g = GlobalSettings::default();
        g.consents.set(
            ConsentKind::VsCodeServer,
            Consent::Granted {
                at: UnixMillis(42),
                terms_version: TermsVersion::new("https://example.test/terms").unwrap(),
            },
        );
        let doc = g.to_document();
        assert_eq!(doc["consents"]["vscode_server"]["state"], "granted");
        assert_eq!(GlobalSettings::from_document(doc).unwrap().settings, g);
    }
}
