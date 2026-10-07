// SPDX-License-Identifier: GPL-3.0-or-later
//! Which hosts a sandbox's proxy decrypts.

use std::collections::BTreeSet;

use puddle_netpolicy::normalise_host;
use puddle_types::Host;

/// The hosts whose TLS a sandbox's proxy terminates: exact names (`github.com`) and
/// every-name-below patterns (`*.visualstudio.com`). Anything else is spliced untouched.
///
/// A pattern covers names *below* its suffix, never the suffix itself, and needs at least two
/// labels (`*.com` is refused): the set is what the per-sandbox certificate authority is allowed
/// to certify, so a wide pattern would widen what puddle can impersonate.
///
/// ```
/// use puddle_proxy::TerminationSet;
/// use puddle_types::Host;
///
/// let set = TerminationSet::parse(["github.com", "*.visualstudio.com"]).unwrap();
/// assert!(set.contains(&Host::parse_normalised("github.com").unwrap()));
/// assert!(set.contains(&Host::parse_normalised("org.visualstudio.com").unwrap()));
/// assert!(!set.contains(&Host::parse_normalised("visualstudio.com").unwrap()));
/// assert!(!set.contains(&Host::parse_normalised("api.github.com").unwrap()));
/// assert!(!set.contains(&Host::parse_normalised("140.82.112.3").unwrap()));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TerminationSet {
    exact: BTreeSet<String>,
    below: BTreeSet<String>,
}

/// Why a pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PatternError {
    /// Not a DNS name (an IP literal is refused too: certificates here are for names).
    #[error("{0:?} is not a host name")]
    NotAName(String),
    /// A `*.` pattern whose suffix has fewer than two labels.
    #[error("{0:?} is too wide: a pattern needs at least two labels after `*.`")]
    TooWide(String),
}

impl TerminationSet {
    /// An empty set: nothing is decrypted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A set from patterns (`github.com`, `*.visualstudio.com`).
    ///
    /// # Errors
    /// [`PatternError`] for the first pattern that is not a name or is too wide.
    pub fn parse<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Result<Self, PatternError> {
        let mut set = Self::new();
        for pattern in patterns {
            set.insert(pattern)?;
        }
        Ok(set)
    }

    /// Adds one pattern.
    ///
    /// # Errors
    /// As [`Self::parse`].
    pub fn insert(&mut self, pattern: &str) -> Result<(), PatternError> {
        let (below, name) = match pattern.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let host = normalise_host(name)
            .map_err(|_| PatternError::NotAName(pattern.to_owned()))?
            .into_host();
        let Host::Name(name) = host else {
            return Err(PatternError::NotAName(pattern.to_owned()));
        };
        let name = name.to_string();
        if below {
            if name.split('.').count() < 2 {
                return Err(PatternError::TooWide(pattern.to_owned()));
            }
            self.below.insert(name);
        } else {
            self.exact.insert(name);
        }
        Ok(())
    }

    /// Whether `host` is decrypted. An IP literal never is.
    #[must_use]
    pub fn contains(&self, host: &Host) -> bool {
        let Host::Name(name) = host else {
            return false;
        };
        let name = name.to_string();
        if self.exact.contains(&name) {
            return true;
        }
        // Every proper suffix after a dot: `a.b.example.com` -> `b.example.com`, `example.com`.
        name.match_indices('.').any(|(at, _)| {
            name.get(at + 1..)
                .is_some_and(|rest| self.below.contains(rest))
        })
    }

    /// Whether the set has no pattern.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.below.is_empty()
    }

    /// The name constraints for the sandbox's certificate authority: exactly this set (a name
    /// and everything below it, per pattern), no IP addresses.
    ///
    /// # Errors
    /// [`puddle_ca::CaError`] when the set is empty (a CA needs at least one name).
    pub fn name_constraints(&self) -> Result<puddle_ca::NameConstraints, puddle_ca::CaError> {
        self.dns_names()
            .iter()
            .try_fold(puddle_ca::NameConstraints::new(), |constraints, name| {
                constraints.permit_dns(name)
            })
    }

    /// The names a certificate authority must permit for this set: each exact name, and the
    /// suffix of each pattern (X.509 name constraints cover a name and everything below it).
    #[must_use]
    pub fn dns_names(&self) -> Vec<String> {
        self.exact
            .iter()
            .chain(self.below.iter())
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(text: &str) -> Host {
        Host::parse_normalised(text).unwrap()
    }

    #[test]
    fn patterns_cover_exactly_what_they_say() {
        let set =
            TerminationSet::parse(["github.com", "*.visualstudio.com", "dev.azure.com"]).unwrap();
        for yes in [
            "github.com",
            "dev.azure.com",
            "a.visualstudio.com",
            "a.b.visualstudio.com",
        ] {
            assert!(set.contains(&host(yes)), "{yes}");
        }
        for no in [
            "visualstudio.com",
            "api.github.com",
            "evilgithub.com",
            "github.com.evil.example",
            "notvisualstudio.com",
            "azure.com",
            "140.82.112.3",
            "::1",
        ] {
            assert!(!set.contains(&host(no)), "{no}");
        }
    }

    #[test]
    fn bad_patterns_are_refused() {
        for bad in [
            "",
            "140.82.112.3",
            "*.com",
            "*.",
            "*",
            "a b.example",
            "https://github.com",
        ] {
            assert!(TerminationSet::parse([bad]).is_err(), "{bad:?}");
        }
        assert_eq!(
            TerminationSet::parse(["*.com"]),
            Err(PatternError::TooWide("*.com".into()))
        );
    }

    #[test]
    fn patterns_are_normalised_and_listed_for_the_ca() {
        let set =
            TerminationSet::parse(["GitHub.com", "*.VisualStudio.com", "github.com"]).unwrap();
        assert_eq!(set.dns_names(), ["github.com", "visualstudio.com"]);
        assert!(!set.is_empty());
        assert!(TerminationSet::new().is_empty());
        assert!(!TerminationSet::new().contains(&host("github.com")));
    }
}
