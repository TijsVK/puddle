// SPDX-License-Identifier: GPL-3.0-or-later
//! The global settings document: one per user.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{self, Document};
use crate::migrate::{self, Migration};
use crate::{
    CloseBehaviour, Consents, DensityChoice, FirstRun, Loaded, ServerChoice, SettingsError,
    ThemeChoice, WorkspaceLayer,
};

/// The current shape of [`GlobalSettings`] documents.
pub const GLOBAL_SCHEMA_VERSION: u32 = 2;

/// puddle's settings for this user: defaults for every workspace, options that only exist
/// globally, and the consents.
///
/// ```
/// use puddle_settings::GlobalSettings;
/// use serde_json::json;
///
/// let loaded = GlobalSettings::from_document(json!({
///     "schema_version": 2,
///     "workspace_defaults": { "memory": 4096, "local_toggles": { "private": true } },
///     "consents": { "telemetry": { "state": "declined", "at": 1, "terms_version": "t1" } },
/// })).unwrap();
/// assert_eq!(loaded.settings.workspace_defaults.memory.unwrap().get(), 4096);
/// assert!(loaded.unknown_fields.is_empty());
///
/// let doc = loaded.settings.to_document();
/// assert_eq!(doc["schema_version"], 2);
/// assert_eq!(GlobalSettings::from_document(doc).unwrap().settings, loaded.settings);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GlobalSettings {
    /// The value every workspace gets unless it overrides it. Unset values fall back to puddle's
    /// built-in defaults.
    #[serde(default, skip_serializing_if = "WorkspaceLayer::is_empty")]
    pub workspace_defaults: WorkspaceLayer,
    /// Options for Microsoft's VS Code server (global only).
    #[serde(default, skip_serializing_if = "VsCodeServer::is_empty")]
    pub vscode_server: VsCodeServer,
    /// How puddle's own window looks and behaves (global only).
    #[serde(default, skip_serializing_if = "UiPrefs::is_empty")]
    pub ui: UiPrefs,
    /// What the user agreed to or declined (per user, never per workspace).
    #[serde(default, skip_serializing_if = "Consents::is_empty")]
    pub consents: Consents,
    /// Whether the first-run flow has been through (per user).
    #[serde(default, skip_serializing_if = "FirstRun::is_empty")]
    pub first_run: FirstRun,
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
        self.workspace_defaults
            .collect_unknown("workspace_defaults.", out);
        document::push_unknown("vscode_server.", &self.vscode_server.extra, out);
        document::push_unknown("ui.", &self.ui.extra, out);
        self.consents.collect_unknown("consents.", out);
        document::push_unknown("first_run.", &self.first_run.extra, out);
    }
}

/// Options for Microsoft's VS Code server once the user enabled it. Whether it is
/// enabled at all is [`Consents::vscode_server`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VsCodeServer {
    /// Which server browser VS Code runs; default the bundled code-server. Choosing Microsoft's
    /// needs a granted [`Consents::vscode_server`], which the API checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerChoice>,
    /// Let the server send Microsoft its telemetry: the checkbox in the enable popup, default
    /// off (unchecked passes `--disable-telemetry`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<bool>,
    /// Update the server automatically when no window is connected; default on.
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

    /// The server in use.
    #[must_use]
    pub fn server(&self) -> ServerChoice {
        self.server.unwrap_or_default()
    }

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

/// Preferences for puddle's own window. They are stored here so they follow the user; the
/// desktop shell reads the notification and close settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UiPrefs {
    /// Light, dark or follow the system; default follow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<ThemeChoice>,
    /// Comfortable or compact spacing for the whole app; default comfortable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub density: Option<DensityChoice>,
    /// Show a system notification for a new request; default on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<bool>,
    /// Play the system sound with a notification; default off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sound: Option<bool>,
    /// What closing the window does while a workspace runs; default keep running in the tray.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_behaviour: Option<CloseBehaviour>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl UiPrefs {
    /// puddle's default for [`UiPrefs::notifications`].
    pub const DEFAULT_NOTIFICATIONS: bool = true;
    /// puddle's default for [`UiPrefs::sound`].
    pub const DEFAULT_SOUND: bool = false;

    /// The theme in use.
    #[must_use]
    pub fn theme(&self) -> ThemeChoice {
        self.theme.unwrap_or_default()
    }

    /// The density in use.
    #[must_use]
    pub fn density(&self) -> DensityChoice {
        self.density.unwrap_or_default()
    }

    /// Whether a new request raises a system notification.
    #[must_use]
    pub fn notifications(&self) -> bool {
        self.notifications.unwrap_or(Self::DEFAULT_NOTIFICATIONS)
    }

    /// Whether a notification plays the system sound.
    #[must_use]
    pub fn sound(&self) -> bool {
        self.sound.unwrap_or(Self::DEFAULT_SOUND)
    }

    /// What closing the window does.
    #[must_use]
    pub fn close_behaviour(&self) -> CloseBehaviour {
        self.close_behaviour.unwrap_or_default()
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
        assert_eq!(loaded.migrated_from, Some(1), "no version means version 1");
        assert_eq!(
            loaded.settings.to_document(),
            json!({ "schema_version": 2 })
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
    fn ui_prefs_and_server_choice_default_and_round_trip() {
        let loaded = GlobalSettings::from_document(json!({})).unwrap();
        assert_eq!(
            loaded.settings.vscode_server.server(),
            ServerChoice::CodeServer
        );
        let ui = &loaded.settings.ui;
        assert_eq!(ui.theme(), ThemeChoice::System);
        assert_eq!(ui.density(), DensityChoice::Comfortable);
        assert!(ui.notifications());
        assert!(!ui.sound());
        assert_eq!(ui.close_behaviour(), CloseBehaviour::Tray);

        let doc = json!({
            "schema_version": 2,
            "vscode_server": { "server": "microsoft" },
            "ui": { "theme": "dark", "density": "compact", "notifications": false, "sound": true, "close_behaviour": "quit" },
        });
        let loaded = GlobalSettings::from_document(doc.clone()).unwrap();
        assert_eq!(loaded.unknown_fields, Vec::<String>::new());
        assert_eq!(
            loaded.settings.vscode_server.server(),
            ServerChoice::Microsoft
        );
        assert_eq!(loaded.settings.ui.theme(), ThemeChoice::Dark);
        assert_eq!(loaded.settings.ui.density(), DensityChoice::Compact);
        assert!(!loaded.settings.ui.notifications());
        assert!(loaded.settings.ui.sound());
        assert_eq!(loaded.settings.ui.close_behaviour(), CloseBehaviour::Quit);
        assert_eq!(loaded.settings.to_document(), doc);
    }

    #[test]
    fn a_document_from_before_these_fields_loads_unchanged_and_ui_unknowns_are_kept() {
        let old = json!({ "schema_version": 2, "vscode_server": { "telemetry": true } });
        let loaded = GlobalSettings::from_document(old.clone()).unwrap();
        assert_eq!(loaded.migrated_from, None);
        assert_eq!(loaded.settings.to_document(), old);

        let newer = json!({ "schema_version": 2, "ui": { "font_scale": 2, "theme": "light" } });
        let loaded = GlobalSettings::from_document(newer.clone()).unwrap();
        assert_eq!(loaded.unknown_fields, ["ui.font_scale"]);
        assert_eq!(loaded.settings.to_document(), newer);
    }

    #[test]
    fn an_invalid_choice_fails_the_document() {
        let err = GlobalSettings::from_document(json!({"ui":{"theme":"purple"}})).unwrap_err();
        assert!(matches!(err, SettingsError::Invalid { kind: "global", .. }));
    }

    #[test]
    fn unknown_fields_at_every_level_are_listed_and_written_back() {
        let doc = json!({
            "schema_version": 2,
            "rule_sets": ["trackers"],
            "workspace_defaults": { "cpus": 2, "local_toggles": { "vpn": true } },
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
                "workspace_defaults.cpus",
                "workspace_defaults.local_toggles.vpn",
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
    fn a_version_1_document_keeps_its_defaults_under_the_new_name() {
        let old = json!({
            "schema_version": 1,
            "sandbox_defaults": { "memory": 4096, "local_toggles": { "private": true } },
            "ui": { "theme": "dark" },
        });
        let loaded = GlobalSettings::from_document(old).unwrap();
        assert_eq!(loaded.migrated_from, Some(1));
        assert_eq!(loaded.unknown_fields, Vec::<String>::new());
        assert_eq!(
            loaded.settings.workspace_defaults.memory.unwrap().get(),
            4096
        );
        let doc = loaded.settings.to_document();
        assert_eq!(doc["schema_version"], 2);
        assert_eq!(doc["workspace_defaults"]["memory"], 4096);
        assert_eq!(doc["ui"]["theme"], "dark");
        assert!(doc.get("sandbox_defaults").is_none(), "{doc}");
        // Written back, it loads as it is.
        assert_eq!(
            GlobalSettings::from_document(doc).unwrap().migrated_from,
            None
        );
    }

    #[test]
    fn a_document_with_both_names_keeps_the_new_one_and_the_old_as_unknown() {
        let both = json!({
            "schema_version": 1,
            "sandbox_defaults": { "memory": 1024 },
            "workspace_defaults": { "memory": 4096 },
        });
        let loaded = GlobalSettings::from_document(both).unwrap();
        assert_eq!(
            loaded.settings.workspace_defaults.memory.unwrap().get(),
            4096
        );
        assert_eq!(loaded.unknown_fields, ["sandbox_defaults"]);
    }

    #[test]
    fn errors_name_the_document_kind() {
        let err =
            GlobalSettings::from_document(json!({"workspace_defaults":{"memory":1}})).unwrap_err();
        assert!(matches!(err, SettingsError::Invalid { kind: "global", .. }));
        assert!(err.to_string().contains("invalid memory size"), "{err}");
        let err = GlobalSettings::from_document(json!({"schema_version":3})).unwrap_err();
        assert!(matches!(
            err,
            SettingsError::NewerSchema {
                kind: "global",
                found: 3,
                supported: 2
            }
        ));
    }

    #[test]
    fn first_run_defaults_to_not_completed_and_round_trips() {
        let loaded = GlobalSettings::from_document(json!({})).unwrap();
        assert!(!loaded.settings.first_run.is_completed());
        assert_eq!(
            loaded.settings.to_document(),
            json!({ "schema_version": 2 }),
            "an unset flow is not written"
        );

        let doc =
            json!({ "schema_version": 2, "first_run": { "completed_at": 1_700_000_000_000_u64 } });
        let loaded = GlobalSettings::from_document(doc.clone()).unwrap();
        assert!(loaded.settings.first_run.is_completed());
        assert_eq!(
            loaded.settings.first_run.completed_at,
            Some(UnixMillis(1_700_000_000_000))
        );
        assert_eq!(loaded.settings.to_document(), doc);
    }

    #[test]
    fn first_run_keeps_fields_it_does_not_know() {
        let doc = json!({ "schema_version": 2, "first_run": { "completed_at": 5, "tour": "v2" } });
        let loaded = GlobalSettings::from_document(doc.clone()).unwrap();
        assert_eq!(loaded.unknown_fields, ["first_run.tour"]);
        assert_eq!(loaded.settings.to_document(), doc);
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
