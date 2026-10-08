// SPDX-License-Identifier: GPL-3.0-or-later
//! The rule sets that ship with puddle, and the hosts puddle allows because of the user's own
//! setup ("System managed"), as data (`docs/spec/rules.md` §7).
//!
//! Both only ever allow (R-36): puddle ships no deny list. Their entries are checked by the tests
//! below (R-4, no duplicates) and loaded into memory; nothing is copied into the database, so an
//! update of puddle updates them.

use std::fmt;

use crate::pattern::Pattern;

/// One entry of a built-in set or of a System managed reason: a pattern as the user would type
/// it (`example.com`, `*.example.com`) and what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogueEntry {
    /// The pattern.
    pub pattern: &'static str,
    /// What the host is for, in a few words.
    pub note: &'static str,
}

/// `entry!("example.com", "what for")`: a catalogue entry (a macro, so the data has no code of
/// its own to cover).
macro_rules! entry {
    ($pattern:expr, $note:expr $(,)?) => {
        CatalogueEntry {
            pattern: $pattern,
            note: $note,
        }
    };
}

/// A rule set that ships with puddle. Read-only; on or off like any set (R-37).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInSet {
    /// Stable id, `[a-z0-9-]+`; the wire id is `builtin:<slug>`.
    pub slug: &'static str,
    /// Display name.
    pub name: &'static str,
    /// One sentence on what the set is for.
    pub description: &'static str,
    /// Whether the set is on where the user never switched it. Every built-in set ships off
    /// (R-1: a fresh install has decided nothing).
    pub default_on: bool,
    /// The hosts it allows.
    pub entries: &'static [CatalogueEntry],
}

/// The built-in sets, in display order.
pub const BUILT_IN_SETS: &[BuiltInSet] = &[
    BuiltInSet {
        slug: "package-registries",
        name: "Package registries",
        description: "The public registries of npm, Yarn, PyPI, crates.io, Go modules, Maven Central, NuGet and RubyGems.",
        default_on: false,
        entries: &[
            entry!("registry.npmjs.org", "npm"),
            entry!("registry.yarnpkg.com", "Yarn"),
            entry!("pypi.org", "PyPI index"),
            entry!("files.pythonhosted.org", "PyPI downloads"),
            entry!("crates.io", "crates.io"),
            entry!("index.crates.io", "crates.io index"),
            entry!("static.crates.io", "crates.io downloads"),
            entry!("proxy.golang.org", "Go module proxy"),
            entry!("sum.golang.org", "Go checksum database"),
            entry!("repo.maven.apache.org", "Maven Central"),
            entry!("repo1.maven.org", "Maven Central"),
            entry!("api.nuget.org", "NuGet"),
            entry!("rubygems.org", "RubyGems"),
            entry!("index.rubygems.org", "RubyGems index"),
        ],
    },
    BuiltInSet {
        slug: "debian-ubuntu",
        name: "Debian and Ubuntu packages",
        description: "The Debian and Ubuntu package archives, for apt.",
        default_on: false,
        entries: &[
            entry!("deb.debian.org", "Debian archive"),
            entry!("security.debian.org", "Debian security updates"),
            entry!("archive.ubuntu.com", "Ubuntu archive"),
            entry!("*.archive.ubuntu.com", "Ubuntu country mirrors"),
            entry!("security.ubuntu.com", "Ubuntu security updates"),
            entry!("ports.ubuntu.com", "Ubuntu archive for other architectures"),
        ],
    },
    BuiltInSet {
        slug: "github",
        name: "GitHub",
        description: "github.com, its API, and the hosts that serve repository archives, raw files and release downloads.",
        default_on: false,
        entries: &[
            entry!("github.com", "GitHub"),
            entry!("api.github.com", "GitHub API"),
            entry!("codeload.github.com", "repository archives"),
            entry!("raw.githubusercontent.com", "raw files"),
            entry!("objects.githubusercontent.com", "downloads"),
            entry!("release-assets.githubusercontent.com", "release downloads"),
        ],
    },
];

/// The built-in set with this slug.
#[must_use]
pub fn built_in(slug: &str) -> Option<&'static BuiltInSet> {
    BUILT_IN_SETS.iter().find(|set| set.slug == slug)
}

/// Why puddle allows a System managed host: a choice the user made (R-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SystemReason {
    /// The browser editor runs Microsoft's VS Code server (a global choice the user consented
    /// to): puddle downloads it from Microsoft, and its extensions come from the Marketplace.
    MicrosoftServer,
    /// The browser editor runs the bundled code-server: its extensions come from Open VSX.
    CodeServer,
    /// Direct SSH is on for the workspace: desktop VS Code's Remote-SSH installs Microsoft's
    /// server and its extensions in it.
    DirectSsh,
}

const MICROSOFT_HOSTS: &[CatalogueEntry] = &[
    entry!(
        "update.code.visualstudio.com",
        "VS Code server downloads and updates",
    ),
    entry!(
        "vscode.download.prss.microsoft.com",
        "VS Code server downloads",
    ),
    entry!("marketplace.visualstudio.com", "Visual Studio Marketplace"),
    entry!("*.gallery.vsassets.io", "Marketplace extension files"),
    entry!("*.gallerycdn.vsassets.io", "Marketplace extension files"),
];

const OPEN_VSX_HOSTS: &[CatalogueEntry] = &[
    entry!("open-vsx.org", "Open VSX extensions"),
    entry!("openvsx.eclipsecontent.org", "Open VSX extension files"),
];

impl SystemReason {
    /// Every reason.
    pub const ALL: [Self; 3] = [Self::MicrosoftServer, Self::CodeServer, Self::DirectSsh];

    /// The stored and wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MicrosoftServer => "microsoft_server",
            Self::CodeServer => "code_server",
            Self::DirectSsh => "direct_ssh",
        }
    }

    /// The reason with this name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == text)
    }

    /// The reason in words, as the Rules screen shows it.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::MicrosoftServer => {
                "You chose Microsoft's VS Code server for the browser editor: puddle downloads it from Microsoft, and its extensions come from the Visual Studio Marketplace."
            }
            Self::CodeServer => {
                "The browser editor runs the bundled code-server: its extensions come from Open VSX."
            }
            Self::DirectSsh => {
                "Direct SSH is on for this workspace: desktop VS Code installs Microsoft's VS Code server and its extensions there."
            }
        }
    }

    /// The hosts this reason allows.
    #[must_use]
    pub fn hosts(self) -> &'static [CatalogueEntry] {
        match self {
            Self::MicrosoftServer | Self::DirectSsh => MICROSOFT_HOSTS,
            Self::CodeServer => OPEN_VSX_HOSTS,
        }
    }
}

impl fmt::Display for SystemReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `entries` as patterns. The catalogue is checked by tests, so a pattern that doesn't parse is
/// a build-time bug; it is skipped (and logged) rather than taking the store down.
pub(crate) fn patterns(entries: &'static [CatalogueEntry]) -> Vec<Pattern> {
    entries
        .iter()
        .filter_map(|entry| match Pattern::parse(entry.pattern) {
            Ok(pattern) => Some(pattern),
            Err(err) => {
                tracing::error!(pattern = entry.pattern, error = %err, "bad catalogue entry skipped");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn every_list() -> Vec<(&'static str, &'static [CatalogueEntry])> {
        let mut lists: Vec<_> = BUILT_IN_SETS.iter().map(|s| (s.slug, s.entries)).collect();
        lists.extend(SystemReason::ALL.map(|r| (r.as_str(), r.hosts())));
        lists
    }

    #[test]
    fn r36_every_catalogue_pattern_passes_r04_and_none_repeats() {
        for (list, entries) in every_list() {
            assert!(!entries.is_empty(), "{list} is empty");
            let mut seen = HashSet::new();
            for entry in entries {
                let pattern = Pattern::parse(entry.pattern)
                    .unwrap_or_else(|e| panic!("{list}: {}: {e}", entry.pattern));
                assert!(
                    seen.insert(pattern.to_string()),
                    "{list}: {} twice",
                    entry.pattern
                );
                assert_ne!(entry.note, "");
            }
            assert_eq!(patterns(entries).len(), entries.len());
        }
    }

    #[test]
    fn a_bad_catalogue_entry_is_skipped_not_fatal() {
        static BAD: [CatalogueEntry; 2] = [
            CatalogueEntry {
                pattern: "*.com",
                note: "a public suffix",
            },
            CatalogueEntry {
                pattern: "ok.example",
                note: "fine",
            },
        ];
        let kept: Vec<String> = patterns(&BAD).iter().map(ToString::to_string).collect();
        assert_eq!(kept, ["ok.example"]);
    }

    #[test]
    fn r01_built_in_sets_ship_off_with_unique_slugs() {
        let mut slugs = HashSet::new();
        for set in BUILT_IN_SETS {
            assert!(!set.default_on, "{} ships on", set.slug);
            assert!(slugs.insert(set.slug));
            assert!(
                set.slug
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{}",
                set.slug
            );
            assert!(!set.name.is_empty() && !set.description.is_empty());
            assert_eq!(built_in(set.slug), Some(set));
        }
        assert_eq!(built_in("nope"), None);
    }

    #[test]
    fn r41_system_reasons_round_trip_and_explain_themselves() {
        for reason in SystemReason::ALL {
            assert_eq!(SystemReason::parse(reason.as_str()), Some(reason));
            assert_eq!(reason.to_string(), reason.as_str());
            assert!(reason.describe().ends_with('.'));
        }
        assert_eq!(SystemReason::parse("vscode"), None);
        // Microsoft's hosts only for Microsoft's server; Open VSX only for code-server.
        let has = |r: SystemReason, host: &str| r.hosts().iter().any(|e| e.pattern == host);
        assert!(has(
            SystemReason::MicrosoftServer,
            "update.code.visualstudio.com"
        ));
        assert!(has(SystemReason::DirectSsh, "marketplace.visualstudio.com"));
        assert!(!has(
            SystemReason::CodeServer,
            "marketplace.visualstudio.com"
        ));
        assert!(has(SystemReason::CodeServer, "open-vsx.org"));
        assert!(!has(SystemReason::MicrosoftServer, "open-vsx.org"));
    }
}
