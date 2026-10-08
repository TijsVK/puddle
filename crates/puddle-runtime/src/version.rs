// SPDX-License-Identifier: GPL-3.0-or-later
//! The pinned runtime version and the exact-match rule (refuse a runtime puddle wasn't built
//! for; an override for dev builds only).

use std::fmt;
use std::str::FromStr;

/// The msb fork version this build of puddle runs, as `<release>-puddle.<N>` (fork tag
/// `v<release>-puddle.N`). It is the Cargo package version the fork's `msb` embeds in its
/// `.msbver` section, so the fork sets its workspace version to this string when it tags.
///
/// Not written here: the build script takes it from the msb SDK's package version in the workspace
/// `Cargo.lock`, which comes from the fork tag in the root `Cargo.toml` (and fails the build if
/// the two disagree). So the SDK and the runtime it expects can't drift apart.
pub const BUILT_FOR: &str = env!("PUDDLE_MSB_BUILT_FOR");

/// The environment variable that, in builds with the `dev-override` feature, makes puddle accept a
/// runtime of any version (value `1`).
pub const DEV_OVERRIDE_VAR: &str = "PUDDLE_DEV_ANY_RUNTIME";

/// Whether this build contains the dev override at all. `false` in every shipped build.
pub const DEV_OVERRIDE_COMPILED: bool = cfg!(feature = "dev-override");

/// A fork runtime version: an upstream msb release plus the fork's revision on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuntimeVersion {
    major: u64,
    minor: u64,
    patch: u64,
    puddle: u32,
}

impl RuntimeVersion {
    /// The version this build was made for ([`BUILT_FOR`]).
    ///
    /// # Panics
    ///
    /// Never: a unit test parses [`BUILT_FOR`].
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "BUILT_FOR is a constant that a unit test parses"
    )]
    pub fn built_for() -> Self {
        BUILT_FOR
            .parse()
            .expect("BUILT_FOR is a valid <release>-puddle.N version")
    }

    /// The upstream msb release, `MAJOR.MINOR.PATCH` (the fork's base tag without the `v`).
    #[must_use]
    pub fn release(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// The fork revision `N` on that release (≥ 1).
    #[must_use]
    pub fn puddle_revision(&self) -> u32 {
        self.puddle
    }

    /// The fork's git tag for this version, `v<release>-puddle.N`.
    #[must_use]
    pub fn fork_tag(&self) -> String {
        format!("v{self}")
    }

    /// Upstream's git tag for the release, `v<release>`.
    #[must_use]
    pub fn upstream_tag(&self) -> String {
        format!("v{}", self.release())
    }
}

impl fmt::Display for RuntimeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}-puddle.{}",
            self.major, self.minor, self.patch, self.puddle
        )
    }
}

/// Why a string isn't a `<release>-puddle.N` version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a <release>-puddle.N runtime version: {value:?}")]
pub struct ParseVersionError {
    value: String,
}

impl FromStr for RuntimeVersion {
    type Err = ParseVersionError;

    /// Parses `MAJOR.MINOR.PATCH-puddle.N`: decimal numbers without leading zeros (semver), `N` ≥ 1,
    /// no build metadata, nothing else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let fail = || ParseVersionError {
            value: printable(s),
        };
        let (release, puddle) = s.split_once("-puddle.").ok_or_else(fail)?;
        let mut parts = release.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(fail());
        };
        let puddle: u32 = number(puddle).ok_or_else(fail)?;
        if puddle == 0 {
            return Err(fail());
        }
        Ok(Self {
            major: number(major).ok_or_else(fail)?,
            minor: number(minor).ok_or_else(fail)?,
            patch: number(patch).ok_or_else(fail)?,
            puddle,
        })
    }
}

/// A semver numeric identifier: ASCII digits, no leading zero unless it is `0`.
fn number<T: FromStr>(s: &str) -> Option<T> {
    let digits = !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let leading_zero = s.len() > 1 && s.starts_with('0');
    if digits && !leading_zero {
        s.parse().ok()
    } else {
        None
    }
}

/// `s` made safe to print: control and non-ASCII characters escaped, cut to 64 characters.
pub(crate) fn printable(s: &str) -> String {
    let escaped: String = s.escape_default().collect();
    if escaped.chars().count() > 64 {
        let mut cut: String = escaped.chars().take(61).collect();
        cut.push_str("...");
        cut
    } else {
        escaped
    }
}

/// Whether the developer asked to accept any runtime version. Only builds with the `dev-override`
/// feature honour it ([`DEV_OVERRIDE_COMPILED`]); everywhere else it is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DevOverride {
    requested: bool,
}

impl DevOverride {
    /// No override: the default, and what every shipped build behaves like.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// An explicit request (tests, or a caller with its own setting).
    #[must_use]
    pub fn requested() -> Self {
        Self { requested: true }
    }

    /// Reads [`DEV_OVERRIDE_VAR`] from the process environment: requested only when it is `1`.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            requested: std::env::var_os(DEV_OVERRIDE_VAR).is_some_and(|v| v == "1"),
        }
    }

    /// Whether the override is in force: requested *and* compiled in.
    #[must_use]
    pub fn active(self) -> bool {
        self.requested && DEV_OVERRIDE_COMPILED
    }
}

/// How the bundled runtime passed the version check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionStatus {
    /// Exactly the version this build was made for.
    Exact,
    /// Another version (or none), accepted only because the dev override is active. Callers log
    /// this as a warning.
    Overridden {
        /// What the binary says (`None`: no version section), printable, at most 64 characters.
        found: Option<String>,
    },
}

/// Why [`check_version`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionRefusal {
    /// The binary has no embedded version.
    NoVersion,
    /// The binary is another version; the printable found value.
    Mismatch(String),
}

/// The exact-match rule: `found` (the binary's embedded version, `None` when it has none) must be
/// exactly `expected`, byte for byte. A newer or older release, another fork revision, or plain
/// upstream `0.7.7` are all refused, unless `dev` is active.
///
/// # Errors
///
/// [`VersionRefusal`] when the versions differ and the override isn't active.
pub fn check_version(
    expected: &RuntimeVersion,
    found: Option<&str>,
    dev: DevOverride,
) -> Result<VersionStatus, VersionRefusal> {
    let exact = found.is_some_and(|f| f == expected.to_string());
    if exact {
        return Ok(VersionStatus::Exact);
    }
    if dev.active() {
        return Ok(VersionStatus::Overridden {
            found: found.map(printable),
        });
    }
    Err(match found {
        None => VersionRefusal::NoVersion,
        Some(f) => VersionRefusal::Mismatch(printable(f)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_for_is_a_valid_fork_version() {
        let v = RuntimeVersion::built_for();
        assert_eq!(v.to_string(), BUILT_FOR);
        assert_eq!(v.fork_tag(), format!("v{BUILT_FOR}"));
        assert!(v.puddle_revision() >= 1);
    }

    #[test]
    fn parses_and_round_trips() {
        let v: RuntimeVersion = "0.7.7-puddle.14".parse().unwrap();
        assert_eq!(v.release(), "0.7.7");
        assert_eq!(v.puddle_revision(), 14);
        assert_eq!(v.to_string(), "0.7.7-puddle.14");
        assert_eq!(v.fork_tag(), "v0.7.7-puddle.14");
        assert_eq!(v.upstream_tag(), "v0.7.7");
        let big: RuntimeVersion = "10.20.30-puddle.1".parse().unwrap();
        assert_eq!(big.release(), "10.20.30");
    }

    #[test]
    fn rejects_everything_but_release_dash_puddle_n() {
        for bad in [
            "",
            "0.7.7",
            "v0.7.7-puddle.1",
            "0.7-puddle.1",
            "0.7.7.1-puddle.1",
            "0.7.7-puddle.0",
            "0.7.7-puddle.01",
            "00.7.7-puddle.1",
            "0.07.7-puddle.1",
            "0.7.7-puddle.",
            "0.7.7-puddle.1+build",
            "0.7.7-puddle.1 ",
            " 0.7.7-puddle.1",
            "0.7.7-Puddle.1",
            "0.7.7-rc.1",
            "0.7.x-puddle.1",
            "0.7.7-puddle.-1",
            "0.7.7-puddle.1.2",
            "0.7.7-puddle.99999999999",
            "+1.7.7-puddle.1",
        ] {
            assert!(bad.parse::<RuntimeVersion>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parse_error_echoes_a_printable_value() {
        let err = "bad\u{1b}[31m".parse::<RuntimeVersion>().unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains('\u{1b}'), "{msg}");
        assert!(msg.contains("\\u{1b}"), "{msg}");
    }

    #[test]
    fn printable_cuts_long_values() {
        let long = "9".repeat(500);
        let p = printable(&long);
        assert_eq!(p.chars().count(), 64);
        assert!(p.ends_with("..."));
        assert_eq!(printable("0.7.7"), "0.7.7");
    }

    #[test]
    fn exact_version_passes() {
        let v: RuntimeVersion = "0.7.7-puddle.2".parse().unwrap();
        assert_eq!(
            check_version(&v, Some("0.7.7-puddle.2"), DevOverride::none()),
            Ok(VersionStatus::Exact)
        );
        // The override never changes an exact match.
        assert_eq!(
            check_version(&v, Some("0.7.7-puddle.2"), DevOverride::requested()),
            Ok(VersionStatus::Exact)
        );
    }

    #[test]
    fn any_other_version_is_refused() {
        let v: RuntimeVersion = "0.7.7-puddle.2".parse().unwrap();
        for other in [
            "0.7.7",
            "0.7.7-puddle.1",
            "0.7.7-puddle.3",
            "0.7.6-puddle.2",
            "0.8.0-puddle.2",
            "0.7.7-puddle.2+x",
            "0.7.7-puddle.2\n",
        ] {
            assert_eq!(
                check_version(&v, Some(other), DevOverride::none()),
                Err(VersionRefusal::Mismatch(printable(other))),
                "{other:?}"
            );
        }
        assert_eq!(
            check_version(&v, None, DevOverride::none()),
            Err(VersionRefusal::NoVersion)
        );
    }

    #[test]
    fn dev_override_only_works_when_compiled_in() {
        let v: RuntimeVersion = "0.7.7-puddle.2".parse().unwrap();
        let got = check_version(&v, Some("0.7.8"), DevOverride::requested());
        if DEV_OVERRIDE_COMPILED {
            assert_eq!(
                got,
                Ok(VersionStatus::Overridden {
                    found: Some("0.7.8".into())
                })
            );
            assert_eq!(
                check_version(&v, None, DevOverride::requested()),
                Ok(VersionStatus::Overridden { found: None })
            );
        } else {
            assert_eq!(got, Err(VersionRefusal::Mismatch("0.7.8".into())));
        }
        assert!(!DevOverride::none().active());
        assert_eq!(DevOverride::requested().active(), DEV_OVERRIDE_COMPILED);
    }
}
