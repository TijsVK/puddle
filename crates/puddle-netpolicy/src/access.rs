// SPDX-License-Identifier: GPL-3.0-or-later
//! The local-destination settings one sandbox runs with: a toggle per category and
//! whether wildcard allows reach local addresses.

use puddle_settings::Effective;
use puddle_types::{LocalCategory, SandboxName};

/// One sandbox's local-destination settings, resolved (sandbox override over global over
/// default). [`LocalAccess::NONE`] is puddle's default: every toggle off, wildcards don't reach
/// local addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LocalAccess {
    on: u8,
    wildcards_reach_local: bool,
}

fn bit(category: LocalCategory) -> u8 {
    LocalCategory::ALL
        .iter()
        .position(|c| *c == category)
        .map_or(0, |i| 1 << i)
}

impl LocalAccess {
    /// Every toggle off, wildcards don't reach local addresses.
    pub const NONE: Self = Self {
        on: 0,
        wildcards_reach_local: false,
    };

    /// The values from resolved settings.
    #[must_use]
    pub fn from_effective(effective: &Effective) -> Self {
        LocalCategory::ALL.into_iter().fold(
            Self::NONE.with_wildcards_reach_local(effective.wildcards_reach_local.value),
            |access, c| access.with_toggle(c, effective.local_toggles.get(c).value),
        )
    }

    /// The same with `category`'s toggle set to `on`.
    #[must_use]
    pub fn with_toggle(mut self, category: LocalCategory, on: bool) -> Self {
        if on {
            self.on |= bit(category);
        } else {
            self.on &= !bit(category);
        }
        self
    }

    /// The same with "wildcards reach local addresses" set to `on`.
    #[must_use]
    pub fn with_wildcards_reach_local(mut self, on: bool) -> Self {
        self.wildcards_reach_local = on;
        self
    }

    /// Whether `category`'s toggle is on.
    #[must_use]
    pub fn is_on(self, category: LocalCategory) -> bool {
        bit(category) != 0 && self.on & bit(category) != 0
    }

    /// Whether a wildcard (suffix) allow may reach a local address whose toggle is on.
    #[must_use]
    pub fn wildcards_reach_local(self) -> bool {
        self.wildcards_reach_local
    }
}

/// Where the guard gets each sandbox's [`LocalAccess`], read per request so a settings change
/// applies to the next connection. The host program implements it over the settings store; a
/// fixed [`LocalAccess`] applies to every sandbox, and so does a closure.
pub trait LocalAccessSource: Send + Sync {
    /// The settings `sandbox` runs with now.
    fn local_access(&self, sandbox: &SandboxName) -> LocalAccess;
}

impl LocalAccessSource for LocalAccess {
    fn local_access(&self, _sandbox: &SandboxName) -> LocalAccess {
        *self
    }
}

impl<F> LocalAccessSource for F
where
    F: Fn(&SandboxName) -> LocalAccess + Send + Sync,
{
    fn local_access(&self, sandbox: &SandboxName) -> LocalAccess {
        self(sandbox)
    }
}

#[cfg(test)]
mod tests {
    use puddle_settings::{GlobalSettings, SandboxSettings, resolve};

    use super::*;

    #[test]
    fn none_is_the_default_and_everything_off() {
        assert_eq!(LocalAccess::default(), LocalAccess::NONE);
        for c in LocalCategory::ALL {
            assert!(!LocalAccess::NONE.is_on(c));
        }
        assert!(!LocalAccess::NONE.wildcards_reach_local());
    }

    #[test]
    fn toggles_are_independent() {
        for c in LocalCategory::ALL {
            let a = LocalAccess::NONE.with_toggle(c, true);
            for other in LocalCategory::ALL {
                assert_eq!(a.is_on(other), other == c, "{c} vs {other}");
            }
            assert_eq!(a.with_toggle(c, false), LocalAccess::NONE);
        }
    }

    #[test]
    fn from_effective_follows_the_resolved_settings() {
        assert_eq!(
            LocalAccess::from_effective(&Effective::DEFAULTS),
            LocalAccess::NONE
        );
        let mut g = GlobalSettings::default();
        g.sandbox_defaults.local_toggles.private = Some(true);
        g.sandbox_defaults.local_toggles.metadata = Some(true);
        g.sandbox_defaults.wildcards_reach_local = Some(true);
        let mut s = SandboxSettings::default();
        s.overrides.local_toggles.metadata = Some(false);
        let a = LocalAccess::from_effective(&resolve(&g, Some(&s)));
        assert!(a.is_on(LocalCategory::Private));
        assert!(!a.is_on(LocalCategory::Metadata));
        assert!(!a.is_on(LocalCategory::Loopback));
        assert!(a.wildcards_reach_local());
    }

    #[test]
    fn sources_fixed_and_per_sandbox() {
        let sandbox = SandboxName::new("box").unwrap();
        let fixed = LocalAccess::NONE.with_toggle(LocalCategory::Loopback, true);
        assert_eq!(fixed.local_access(&sandbox), fixed);
        let per = |s: &SandboxName| {
            LocalAccess::NONE.with_toggle(LocalCategory::Private, s.as_str() == "box")
        };
        assert!(per.local_access(&sandbox).is_on(LocalCategory::Private));
        let other = SandboxName::new("other").unwrap();
        assert!(!per.local_access(&other).is_on(LocalCategory::Private));
    }
}
