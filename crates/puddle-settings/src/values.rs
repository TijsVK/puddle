// SPDX-License-Identifier: GPL-3.0-or-later
//! Value types for single settings. Like `puddle-types`, each validates in its constructor and
//! when deserialised.

use std::fmt;
use std::time::Duration;

use puddle_types::ValidationError;
use serde::{Deserialize, Serialize};

/// How long browser VS Code keeps a session's extension host after its window disconnected
/// (`--reconnection-grace-time`), in whole seconds.
///
/// ```
/// use puddle_settings::ReconnectionGrace;
/// assert_eq!(ReconnectionGrace::default().secs(), 300);
/// assert!(ReconnectionGrace::new(5).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ReconnectionGrace(u32);

impl ReconnectionGrace {
    /// Shortest accepted grace: 30 s, so a page reload or a short network drop survives.
    pub const MIN: ReconnectionGrace = ReconnectionGrace(30);
    /// Longest accepted grace: one day.
    pub const MAX: ReconnectionGrace = ReconnectionGrace(24 * 60 * 60);
    /// puddle's default: 300 s.
    pub const DEFAULT: ReconnectionGrace = ReconnectionGrace(300);

    /// Checks `secs` and wraps it.
    ///
    /// # Errors
    ///
    /// When `secs` is outside [`ReconnectionGrace::MIN`]..=[`ReconnectionGrace::MAX`].
    pub fn new(secs: u32) -> Result<Self, ValidationError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&secs) {
            Ok(Self(secs))
        } else {
            Err(ValidationError::new(
                "reconnection grace",
                &format!("{secs} s"),
                format_args!("must be between {} and {} s", Self::MIN.0, Self::MAX.0),
            ))
        }
    }

    /// The grace in seconds, as passed to the server.
    #[must_use]
    pub fn secs(self) -> u32 {
        self.0
    }

    /// The grace as a [`Duration`].
    #[must_use]
    pub fn duration(self) -> Duration {
        Duration::from_secs(u64::from(self.0))
    }
}

impl Default for ReconnectionGrace {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for ReconnectionGrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} s", self.0)
    }
}

impl TryFrom<u32> for ReconnectionGrace {
    type Error = ValidationError;

    fn try_from(secs: u32) -> Result<Self, Self::Error> {
        Self::new(secs)
    }
}

impl From<ReconnectionGrace> for u32 {
    fn from(g: ReconnectionGrace) -> u32 {
        g.0
    }
}

/// What happens when a page in a sandbox window reads the clipboard programmatically.
///
/// The default asks once per sandbox; the answer is stored as that sandbox's override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardRead {
    /// Show puddle's prompt.
    #[default]
    Ask,
    /// Allow without a prompt.
    Allow,
    /// Refuse without a prompt.
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_bounds_are_inclusive() {
        assert_eq!(ReconnectionGrace::new(30).unwrap(), ReconnectionGrace::MIN);
        assert_eq!(
            ReconnectionGrace::new(86_400).unwrap(),
            ReconnectionGrace::MAX
        );
        assert!(ReconnectionGrace::new(29).is_err());
        let err = ReconnectionGrace::new(86_401).unwrap_err();
        assert!(err.to_string().contains("between 30 and 86400 s"), "{err}");
    }

    #[test]
    fn grace_display_and_conversions() {
        let g = ReconnectionGrace::DEFAULT;
        assert_eq!(g.to_string(), "300 s");
        assert_eq!(g.duration(), Duration::from_secs(300));
        assert_eq!(u32::from(g), 300);
        assert_eq!(ReconnectionGrace::try_from(60).unwrap().secs(), 60);
    }

    #[test]
    fn grace_validates_when_deserialised() {
        assert_eq!(
            serde_json::from_str::<ReconnectionGrace>("120")
                .unwrap()
                .secs(),
            120
        );
        assert!(serde_json::from_str::<ReconnectionGrace>("0").is_err());
        assert_eq!(
            serde_json::to_string(&ReconnectionGrace::MIN).unwrap(),
            "30"
        );
    }

    #[test]
    fn clipboard_read_is_snake_case_and_defaults_to_ask() {
        assert_eq!(ClipboardRead::default(), ClipboardRead::Ask);
        assert_eq!(
            serde_json::to_string(&ClipboardRead::Allow).unwrap(),
            r#""allow""#
        );
        assert_eq!(
            serde_json::from_str::<ClipboardRead>(r#""deny""#).unwrap(),
            ClipboardRead::Deny
        );
        assert!(serde_json::from_str::<ClipboardRead>(r#""Deny""#).is_err());
    }
}
