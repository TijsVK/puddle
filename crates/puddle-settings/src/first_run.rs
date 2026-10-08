// SPDX-License-Identifier: GPL-3.0-or-later
//! Whether the first-run flow has been through, kept with the user's other settings so a reinstall
//! of the app does not ask again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::UnixMillis;

/// The first-run flow's one fact: when the user finished or skipped it.
///
/// ```
/// use puddle_settings::GlobalSettings;
/// use serde_json::json;
///
/// assert!(!GlobalSettings::default().first_run.is_completed());
/// let done = GlobalSettings::from_document(json!({ "first_run": { "completed_at": 7 } })).unwrap();
/// assert!(done.settings.first_run.is_completed());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FirstRun {
    /// When the flow was finished or skipped; unset while it still has to run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<UnixMillis>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl FirstRun {
    /// Whether the flow has been finished or skipped.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.completed_at.is_some()
    }

    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}
