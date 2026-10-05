// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest memory setting: one default for every sandbox plus per-sandbox overrides.
//!
//! The value becomes msb's `--memory` at create; a change applies at the sandbox's next start.
//! puddle never sets `--max-memory` (T-106).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{SandboxName, ValidationError};

/// Guest memory in MiB, within [`MemoryMib::MIN`]..=[`MemoryMib::MAX`].
///
/// ```
/// use puddle_types::MemoryMib;
/// assert_eq!(MemoryMib::default(), MemoryMib::DEFAULT);
/// assert_eq!(MemoryMib::DEFAULT.get(), 8192);
/// assert!(MemoryMib::new(100).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct MemoryMib(u32);

impl MemoryMib {
    /// Smallest accepted size: 256 MiB.
    pub const MIN: MemoryMib = MemoryMib(256);
    /// Largest accepted size: 1 TiB.
    pub const MAX: MemoryMib = MemoryMib(1024 * 1024);
    /// The default for every sandbox: 8 GiB.
    pub const DEFAULT: MemoryMib = MemoryMib(8 * 1024);

    /// Checks `mib` and wraps it.
    ///
    /// # Errors
    ///
    /// When `mib` is outside [`MemoryMib::MIN`]..=[`MemoryMib::MAX`].
    pub fn new(mib: u32) -> Result<Self, ValidationError> {
        if (Self::MIN.0..=Self::MAX.0).contains(&mib) {
            Ok(Self(mib))
        } else {
            Err(ValidationError::new(
                "memory size",
                &format!("{mib} MiB"),
                format_args!("must be between {} and {} MiB", Self::MIN.0, Self::MAX.0),
            ))
        }
    }

    /// The size in MiB.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl Default for MemoryMib {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for MemoryMib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} MiB", self.0)
    }
}

impl TryFrom<u32> for MemoryMib {
    type Error = ValidationError;

    fn try_from(mib: u32) -> Result<Self, Self::Error> {
        Self::new(mib)
    }
}

impl From<MemoryMib> for u32 {
    fn from(m: MemoryMib) -> u32 {
        m.0
    }
}

/// The memory setting: a default for all sandboxes and optional per-sandbox overrides.
///
/// ```
/// use puddle_types::{MemoryMib, MemorySetting, SandboxName};
/// let big = SandboxName::new("big").unwrap();
/// let mut s = MemorySetting::default();
/// s.set_override(big.clone(), MemoryMib::new(16 * 1024).unwrap());
/// assert_eq!(s.for_sandbox(&big).get(), 16 * 1024);
/// assert_eq!(s.for_sandbox(&SandboxName::new("small").unwrap()), MemoryMib::DEFAULT);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySetting {
    /// The size used by every sandbox without an override.
    pub default: MemoryMib,
    /// Per-sandbox sizes that replace [`MemorySetting::default`].
    #[serde(default)]
    pub overrides: BTreeMap<SandboxName, MemoryMib>,
}

impl MemorySetting {
    /// The size `sandbox` gets at its next create or start.
    #[must_use]
    pub fn for_sandbox(&self, sandbox: &SandboxName) -> MemoryMib {
        self.overrides.get(sandbox).copied().unwrap_or(self.default)
    }

    /// Gives `sandbox` its own size; returns the override it replaces.
    pub fn set_override(&mut self, sandbox: SandboxName, mib: MemoryMib) -> Option<MemoryMib> {
        self.overrides.insert(sandbox, mib)
    }

    /// Makes `sandbox` use the default again; returns the removed override.
    pub fn clear_override(&mut self, sandbox: &SandboxName) -> Option<MemoryMib> {
        self.overrides.remove(sandbox)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_are_inclusive() {
        assert_eq!(MemoryMib::new(256).unwrap(), MemoryMib::MIN);
        assert_eq!(MemoryMib::new(1024 * 1024).unwrap(), MemoryMib::MAX);
        assert!(MemoryMib::new(255).is_err());
        let err = MemoryMib::new(1024 * 1024 + 1).unwrap_err();
        assert!(
            err.to_string().contains("between 256 and 1048576 MiB"),
            "{err}"
        );
    }

    #[test]
    fn display_and_conversions() {
        assert_eq!(MemoryMib::DEFAULT.to_string(), "8192 MiB");
        assert_eq!(u32::from(MemoryMib::MIN), 256);
        assert_eq!(MemoryMib::try_from(512).unwrap().get(), 512);
    }

    #[test]
    fn overrides_replace_and_clear() {
        let n = SandboxName::new("a").unwrap();
        let mut s = MemorySetting::default();
        assert_eq!(s.for_sandbox(&n), MemoryMib::DEFAULT);
        assert_eq!(s.set_override(n.clone(), MemoryMib::MIN), None);
        assert_eq!(
            s.set_override(n.clone(), MemoryMib::MAX),
            Some(MemoryMib::MIN)
        );
        assert_eq!(s.for_sandbox(&n), MemoryMib::MAX);
        assert_eq!(s.clear_override(&n), Some(MemoryMib::MAX));
        assert_eq!(s.for_sandbox(&n), MemoryMib::DEFAULT);
    }

    #[test]
    fn serde_round_trip_and_validation() {
        let mut s = MemorySetting::default();
        s.set_override(SandboxName::new("a").unwrap(), MemoryMib::MIN);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"default":8192,"overrides":{"a":256}}"#);
        assert_eq!(serde_json::from_str::<MemorySetting>(&json).unwrap(), s);
        let only_default: MemorySetting = serde_json::from_str(r#"{"default":4096}"#).unwrap();
        assert!(only_default.overrides.is_empty());
        assert!(serde_json::from_str::<MemorySetting>(r#"{"default":1}"#).is_err());
        assert!(
            serde_json::from_str::<MemorySetting>(r#"{"default":4096,"overrides":{"Bad":512}}"#)
                .is_err()
        );
    }
}
