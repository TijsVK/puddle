// SPDX-License-Identifier: GPL-3.0-or-later
//! Local-destination categories: the address classes a user can switch on per sandbox.
//!
//! One enum for every crate: `puddle-netpolicy` classifies addresses into it, `puddle-settings`
//! stores one toggle per category under [`LocalCategory::key`], the proxy's block reason and the
//! audit's `toggle:<key>` name it. The keys are stored format: renaming one needs a settings
//! migration.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ValidationError;

/// A class of local destination with its own toggle. Everything outside these is public.
///
/// A toggle only *permits* its category; each destination still needs an allow rule or an
/// approval. puddle's own endpoints are not a category: no toggle reaches them.
///
/// Non-exhaustive: a "company network" category may follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub enum LocalCategory {
    /// The host itself: `127.0.0.0/8`, `::1`, the unspecified addresses `0.0.0.0` and `::`
    /// (connecting to them reaches the host's own listeners), `localhost` and `*.localhost`.
    Loopback,
    /// Local and private networks: RFC 1918, CGNAT `100.64.0.0/10`, unique-local `fc00::/7`.
    Private,
    /// Link-local `169.254.0.0/16` and `fe80::/10`, apart from the metadata addresses in them.
    LinkLocal,
    /// Cloud instance metadata and credential endpoints (`169.254.169.254`, Azure's
    /// `168.63.129.16`, `metadata.google.internal`, ...).
    Metadata,
    /// Addresses with no business being a TCP destination: multicast, broadcast, reserved,
    /// documentation, benchmarking, "this network", IPv6 outside `2000::/3`, and transition
    /// prefixes (6to4, Teredo, IPv4-compatible) that embed a public address.
    Special,
}

impl LocalCategory {
    /// Every category, in a fixed order (the order block messages list them in).
    pub const ALL: [Self; 5] = [
        Self::Loopback,
        Self::Private,
        Self::LinkLocal,
        Self::Metadata,
        Self::Special,
    ];

    /// The toggle's key: in settings documents, the API, and the audit's `toggle:<key>`.
    ///
    /// ```
    /// use puddle_types::LocalCategory;
    /// assert_eq!(LocalCategory::LinkLocal.key(), "link_local");
    /// assert_eq!("link_local".parse(), Ok(LocalCategory::LinkLocal));
    /// ```
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::Metadata => "metadata",
            Self::Special => "special",
        }
    }

    /// A short description for messages and the UI.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Loopback => "host loopback",
            Self::Private => "local/private network",
            Self::LinkLocal => "link-local",
            Self::Metadata => "cloud metadata",
            Self::Special => "special-use address",
        }
    }

    /// The audit `reason` for a request this category's toggle blocked (R-24).
    #[must_use]
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::Loopback => "toggle:loopback",
            Self::Private => "toggle:private",
            Self::LinkLocal => "toggle:link_local",
            Self::Metadata => "toggle:metadata",
            Self::Special => "toggle:special",
        }
    }
}

impl fmt::Display for LocalCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

impl FromStr for LocalCategory {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.key() == s)
            .ok_or_else(|| ValidationError::new("local category", s, "is not a known category"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_the_stored_names() {
        let keys: Vec<_> = LocalCategory::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(
            keys,
            ["loopback", "private", "link_local", "metadata", "special"]
        );
    }

    #[test]
    fn serde_display_parse_and_audit_agree_with_the_key() {
        for c in LocalCategory::ALL {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.key())
            );
            assert_eq!(
                serde_json::from_str::<LocalCategory>(&format!("\"{}\"", c.key())).unwrap(),
                c
            );
            assert_eq!(c.to_string(), c.key());
            assert_eq!(c.key().parse::<LocalCategory>().unwrap(), c);
            assert_eq!(c.audit_reason(), format!("toggle:{}", c.key()));
            assert_ne!(c.describe(), "");
        }
    }

    #[test]
    fn unknown_keys_are_refused() {
        let err = "vpn".parse::<LocalCategory>().unwrap_err();
        assert_eq!(err.what(), "local category");
        assert!("Loopback".parse::<LocalCategory>().is_err());
        assert!(serde_json::from_str::<LocalCategory>("\"lan\"").is_err());
    }
}
