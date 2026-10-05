// SPDX-License-Identifier: GPL-3.0-or-later
//! The settings every sandbox has, each optional. The same type holds the global defaults
//! ([`crate::GlobalSettings::sandbox_defaults`]) and one sandbox's overrides
//! ([`crate::SandboxSettings::overrides`]); `None` means "not set here, ask the next level".

use std::collections::BTreeMap;

use puddle_types::MemoryMib;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ClipboardRead, ReconnectionGrace};

/// The per-sandbox settings, each optional. A setting added here gets a global default and a
/// per-sandbox override at once, and [`crate::resolve`] must learn it (its exhaustive
/// destructuring fails to compile until it does).
///
/// ```
/// use puddle_settings::SandboxLayer;
/// use puddle_types::MemoryMib;
/// let mut layer = SandboxLayer::default();
/// layer.memory = Some(MemoryMib::new(2048).unwrap());
/// layer.local_toggles.private = Some(true);
/// assert!(!layer.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SandboxLayer {
    /// Guest memory, msb's `--memory` (D-47 (1)); applies at the sandbox's next start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryMib>,
    /// Local-destination toggles, one per address category (D-1, D-37).
    #[serde(default, skip_serializing_if = "LocalToggles::is_empty")]
    pub local_toggles: LocalToggles,
    /// Whether a wildcard or suffix allow may match a name that resolves to a local address
    /// (D-44).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wildcards_reach_local: Option<bool>,
    /// Browser VS Code's reconnection grace (D-43 (1)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnection_grace: Option<ReconnectionGrace>,
    /// Zoom hotkeys in sandbox windows (D-46 (1)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zoom_hotkeys: Option<bool>,
    /// Programmatic clipboard reads in sandbox windows (D-46 (2)).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard_read: Option<ClipboardRead>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl SandboxLayer {
    /// Whether no setting is set at this level (unknown fields count as set, so they are kept).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub(crate) fn collect_unknown(&self, prefix: &str, out: &mut Vec<String>) {
        crate::document::push_unknown(prefix, &self.extra, out);
        self.local_toggles
            .collect_unknown(&format!("{prefix}local_toggles."), out);
    }
}

/// One toggle per local-destination category (D-1). A toggle only *permits* its category: the
/// allowlist still decides each destination (D-37). puddle's default for each is off.
///
/// The category names follow T-005's classifier; T-132 owns the classifier itself.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LocalToggles {
    /// Host loopback (`127.0.0.0/8`, `::1`, `localhost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loopback: Option<bool>,
    /// Private networks (RFC 1918, unique-local IPv6, CGNAT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    /// Link-local addresses (`169.254.0.0/16` except metadata, `fe80::/10`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_local: Option<bool>,
    /// Cloud metadata endpoints (`169.254.169.254` and their names).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<bool>,
    /// Other special-purpose ranges (multicast, documentation, reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub special: Option<bool>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl LocalToggles {
    /// Whether no toggle is set at this level (unknown fields count as set, so they are kept).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn collect_unknown(&self, prefix: &str, out: &mut Vec<String>) {
        crate::document::push_unknown(prefix, &self.extra, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_layer_serialises_to_an_empty_object() {
        assert_eq!(
            serde_json::to_string(&SandboxLayer::default()).unwrap(),
            "{}"
        );
        assert!(SandboxLayer::default().is_empty());
    }

    #[test]
    fn set_values_use_the_documented_names() {
        let l = SandboxLayer {
            memory: Some(MemoryMib::new(1024).unwrap()),
            local_toggles: LocalToggles {
                metadata: Some(false),
                ..LocalToggles::default()
            },
            wildcards_reach_local: Some(true),
            reconnection_grace: Some(ReconnectionGrace::new(60).unwrap()),
            zoom_hotkeys: Some(false),
            clipboard_read: Some(ClipboardRead::Deny),
            extra: BTreeMap::new(),
        };
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"memory":1024,"local_toggles":{"metadata":false},"wildcards_reach_local":true,"reconnection_grace":60,"zoom_hotkeys":false,"clipboard_read":"deny"}"#
        );
        assert_eq!(
            serde_json::from_str::<SandboxLayer>(&serde_json::to_string(&l).unwrap()).unwrap(),
            l
        );
    }

    #[test]
    fn null_means_unset() {
        let l: SandboxLayer =
            serde_json::from_str(r#"{"memory":null,"local_toggles":{"private":null}}"#).unwrap();
        assert!(l.is_empty());
    }

    #[test]
    fn invalid_values_are_rejected_through_the_flattened_map() {
        assert!(serde_json::from_str::<SandboxLayer>(r#"{"memory":1}"#).is_err());
        assert!(serde_json::from_str::<SandboxLayer>(r#"{"memory":"8192"}"#).is_err());
        assert!(
            serde_json::from_str::<SandboxLayer>(r#"{"local_toggles":{"private":"yes"}}"#).is_err()
        );
        assert!(serde_json::from_str::<SandboxLayer>(r#"{"clipboard_read":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<SandboxLayer>(r#"{"reconnection_grace":-1}"#).is_err());
    }

    #[test]
    fn unknown_fields_are_kept_and_listed() {
        let l: SandboxLayer = serde_json::from_str(
            r#"{"cpus":4,"local_toggles":{"private":true,"vpn":true},"memory":2048}"#,
        )
        .unwrap();
        assert_eq!(l.memory.unwrap().get(), 2048);
        assert_eq!(l.local_toggles.private, Some(true));
        assert!(!l.is_empty());
        let mut unknown = Vec::new();
        l.collect_unknown("sandbox_defaults.", &mut unknown);
        assert_eq!(
            unknown,
            [
                "sandbox_defaults.cpus",
                "sandbox_defaults.local_toggles.vpn"
            ]
        );
        let back = serde_json::to_value(&l).unwrap();
        assert_eq!(back["cpus"], 4);
        assert_eq!(back["local_toggles"]["vpn"], true);
    }

    #[test]
    fn a_layer_with_only_unknown_toggles_is_not_empty() {
        let l: SandboxLayer = serde_json::from_str(r#"{"local_toggles":{"vpn":true}}"#).unwrap();
        assert!(!l.local_toggles.is_empty());
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"local_toggles":{"vpn":true}}"#
        );
    }
}
