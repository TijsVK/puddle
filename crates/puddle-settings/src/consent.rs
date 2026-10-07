// SPDX-License-Identifier: GPL-3.0-or-later
//! The consent store: one record per thing puddle asks the user's permission for. Telemetry and
//! crash reports (strictly opt-in) and Microsoft's VS Code server (the enable popup,
//! consent recorded per user) share this one type, so there is one store, not two.

use std::collections::BTreeMap;
use std::fmt;

use puddle_types::ValidationError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A point in time as milliseconds since the Unix epoch (UTC), as the store's clock gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixMillis(pub u64);

/// Which version of the terms (or of puddle's consent text) the user saw, e.g. `2026-10-05`
/// or a licence URL. 1 to [`TermsVersion::MAX_LEN`] visible ASCII characters, no spaces.
///
/// ```
/// use puddle_settings::TermsVersion;
/// assert_eq!(TermsVersion::new("2026-10-05").unwrap().as_str(), "2026-10-05");
/// assert!(TermsVersion::new("").is_err());
/// assert!(TermsVersion::new("v 1").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TermsVersion(String);

impl TermsVersion {
    /// Longest accepted version string (long enough for a licence URL).
    pub const MAX_LEN: usize = 256;

    /// Checks `version` and wraps it.
    ///
    /// # Errors
    ///
    /// When `version` is empty, longer than [`TermsVersion::MAX_LEN`], or has a character that
    /// isn't visible ASCII.
    pub fn new(version: &str) -> Result<Self, ValidationError> {
        let reason = if version.is_empty() {
            Some("must not be empty")
        } else if version.len() > Self::MAX_LEN {
            Some("is too long")
        } else if !version.bytes().all(|b| b.is_ascii_graphic()) {
            Some("may only contain visible ASCII characters")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(ValidationError::new("terms version", version, reason)),
            None => Ok(Self(version.to_owned())),
        }
    }

    /// The version as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TermsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for TermsVersion {
    type Error = ValidationError;

    fn try_from(version: String) -> Result<Self, Self::Error> {
        Self::new(&version)
    }
}

impl From<TermsVersion> for String {
    fn from(v: TermsVersion) -> String {
        v.0
    }
}

/// The user's answer to one consent question.
///
/// Stored as an object tagged by `state`: `{"state":"not_asked"}`,
/// `{"state":"granted","at":…,"terms_version":"…"}`, `{"state":"declined",…}`.
///
/// ```
/// use puddle_settings::{Consent, TermsVersion, UnixMillis};
/// let v1 = TermsVersion::new("v1").unwrap();
/// let v2 = TermsVersion::new("v2").unwrap();
/// let granted = Consent::Granted { at: UnixMillis(1), terms_version: v1.clone() };
/// assert!(granted.allows(&v1));
/// assert!(!granted.allows(&v2));      // the terms changed: not covered any more
/// assert!(granted.should_ask(&v2));   // so ask again
/// assert!(Consent::NotAsked.should_ask(&v1));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Consent {
    /// The question was never put to the user: nothing is allowed, and the first-run flow asks.
    #[default]
    NotAsked,
    /// The user agreed, at `at`, to the terms in `terms_version`.
    Granted {
        /// When the user agreed.
        at: UnixMillis,
        /// The terms (or consent text) the user agreed to.
        terms_version: TermsVersion,
    },
    /// The user declined, at `at`, the terms in `terms_version`.
    Declined {
        /// When the user declined.
        at: UnixMillis,
        /// The terms (or consent text) the user was shown.
        terms_version: TermsVersion,
    },
}

impl Consent {
    /// Whether the user agreed to exactly `current` terms. Anything else (not asked, declined,
    /// agreed to other terms) allows nothing: consent fails closed.
    #[must_use]
    pub fn allows(&self, current: &TermsVersion) -> bool {
        matches!(self, Self::Granted { terms_version, .. } if terms_version == current)
    }

    /// Whether puddle should put the question to the user: never asked, or agreed to terms
    /// that have since changed. A decline is respected; puddle doesn't ask again on its own
    /// (the user can still change it in the settings).
    #[must_use]
    pub fn should_ask(&self, current: &TermsVersion) -> bool {
        match self {
            Self::NotAsked => true,
            Self::Granted { terms_version, .. } => terms_version != current,
            Self::Declined { .. } => false,
        }
    }
}

/// What a consent is for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentKind {
    /// puddle's own usage telemetry.
    Telemetry,
    /// Sending puddle's crash reports.
    CrashReports,
    /// Downloading and running Microsoft's VS Code server under its licence terms.
    #[serde(rename = "vscode_server")]
    VsCodeServer,
}

impl ConsentKind {
    /// Every kind, in a fixed order.
    pub const ALL: [ConsentKind; 3] = [Self::Telemetry, Self::CrashReports, Self::VsCodeServer];
}

/// Every consent, one field per [`ConsentKind`]. Part of [`crate::GlobalSettings`]: consent is
/// per user, never per sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Consents {
    /// puddle's own usage telemetry.
    #[serde(default, skip_serializing_if = "is_not_asked")]
    pub telemetry: Consent,
    /// Sending crash reports.
    #[serde(default, skip_serializing_if = "is_not_asked")]
    pub crash_reports: Consent,
    /// Microsoft's VS Code server.
    #[serde(default, skip_serializing_if = "is_not_asked")]
    pub vscode_server: Consent,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl Consents {
    /// The record for `kind`.
    #[must_use]
    pub fn get(&self, kind: ConsentKind) -> &Consent {
        match kind {
            ConsentKind::Telemetry => &self.telemetry,
            ConsentKind::CrashReports => &self.crash_reports,
            ConsentKind::VsCodeServer => &self.vscode_server,
        }
    }

    /// Records `consent` for `kind`; returns the record it replaces.
    pub fn set(&mut self, kind: ConsentKind, consent: Consent) -> Consent {
        let slot = match kind {
            ConsentKind::Telemetry => &mut self.telemetry,
            ConsentKind::CrashReports => &mut self.crash_reports,
            ConsentKind::VsCodeServer => &mut self.vscode_server,
        };
        std::mem::replace(slot, consent)
    }

    pub(crate) fn collect_unknown(&self, prefix: &str, out: &mut Vec<String>) {
        crate::document::push_unknown(prefix, &self.extra, out);
    }
}

fn is_not_asked(c: &Consent) -> bool {
    matches!(c, Consent::NotAsked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> TermsVersion {
        TermsVersion::new(s).unwrap()
    }

    #[test]
    fn terms_version_rules() {
        assert!(TermsVersion::new(&"x".repeat(256)).is_ok());
        let long = TermsVersion::new(&"x".repeat(257)).unwrap_err();
        assert_eq!(long.reason(), "is too long");
        assert_eq!(
            TermsVersion::new("a\u{e9}").unwrap_err().reason(),
            "may only contain visible ASCII characters"
        );
        assert_eq!(
            TermsVersion::new("").unwrap_err().reason(),
            "must not be empty"
        );
        assert_eq!(v("https://x/terms").to_string(), "https://x/terms");
        assert_eq!(String::from(v("v1")), "v1");
        assert!(serde_json::from_str::<TermsVersion>(r#""a b""#).is_err());
    }

    #[test]
    fn consent_wire_shape_is_tagged_by_state() {
        let g = Consent::Granted {
            at: UnixMillis(1_700_000_000_000),
            terms_version: v("v1"),
        };
        assert_eq!(
            serde_json::to_string(&g).unwrap(),
            r#"{"state":"granted","at":1700000000000,"terms_version":"v1"}"#
        );
        assert_eq!(
            serde_json::to_string(&Consent::NotAsked).unwrap(),
            r#"{"state":"not_asked"}"#
        );
        let d: Consent =
            serde_json::from_str(r#"{"state":"declined","at":5,"terms_version":"v1"}"#).unwrap();
        assert_eq!(
            d,
            Consent::Declined {
                at: UnixMillis(5),
                terms_version: v("v1")
            }
        );
        assert!(serde_json::from_str::<Consent>(r#"{"state":"granted","at":5}"#).is_err());
        assert!(serde_json::from_str::<Consent>(r#"{"state":"revoked"}"#).is_err());
    }

    #[test]
    fn only_a_grant_of_the_current_terms_allows() {
        let cur = v("v2");
        assert!(!Consent::NotAsked.allows(&cur));
        let declined = Consent::Declined {
            at: UnixMillis(1),
            terms_version: cur.clone(),
        };
        assert!(!declined.allows(&cur));
        assert!(!declined.should_ask(&cur));
        assert!(!declined.should_ask(&v("v3")));
        let granted = Consent::Granted {
            at: UnixMillis(1),
            terms_version: cur.clone(),
        };
        assert!(granted.allows(&cur));
        assert!(!granted.should_ask(&cur));
    }

    #[test]
    fn consents_get_and_set_each_kind() {
        let mut c = Consents::default();
        for kind in ConsentKind::ALL {
            assert_eq!(c.get(kind), &Consent::NotAsked);
            let rec = Consent::Granted {
                at: UnixMillis(7),
                terms_version: v("v1"),
            };
            assert_eq!(c.set(kind, rec.clone()), Consent::NotAsked);
            assert_eq!(c.get(kind), &rec);
        }
        assert_eq!(
            serde_json::to_string(&ConsentKind::VsCodeServer).unwrap(),
            r#""vscode_server""#
        );
    }

    #[test]
    fn not_asked_consents_are_left_out_of_the_document() {
        let mut c = Consents::default();
        assert_eq!(serde_json::to_string(&c).unwrap(), "{}");
        c.set(
            ConsentKind::Telemetry,
            Consent::Declined {
                at: UnixMillis(3),
                terms_version: v("t1"),
            },
        );
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"telemetry":{"state":"declined","at":3,"terms_version":"t1"}}"#
        );
    }
}
