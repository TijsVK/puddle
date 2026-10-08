// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated names that end up as an argument or a line of a tool's input.
//!
//! A name that reaches a child process is checked first, so it cannot be an option (`-x`), carry a
//! newline into the Git credential protocol or a space into an argument list.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A value was not accepted as a name for a source.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a valid {what}")]
pub struct NameError {
    what: &'static str,
}

macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, $what:literal, $ok:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Checks `value` and wraps it.
            ///
            /// # Errors
            /// [`NameError`] when it is empty, too long, starts with `-` or has a character a
            /// tool argument or credential line must not carry.
            pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
                let value = value.into();
                let check: fn(&str) -> bool = $ok;
                if value.is_empty() || value.len() > 256 || value.starts_with('-') || !check(&value) {
                    return Err(NameError { what: $what });
                }
                Ok(Self(value))
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;
            fn try_from(value: String) -> Result<Self, NameError> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

fn account_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'))
}

fn host_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'))
        && !s.starts_with('.')
}

fn path_chars(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '%' | '@' | '+' | '/')
    }) && !s.starts_with('/')
        && !s.ends_with('/')
        && s.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn id_chars(s: &str) -> bool {
    s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

name_type!(
    /// An account name on a Git host or Azure DevOps (`TijsVK`, `me@example.com`).
    AccountName, "account name", account_chars
);
name_type!(
    /// A Git host name (`github.com`, `dev.azure.com`), with an optional port.
    HostName, "host name", host_chars
);
name_type!(
    /// The path of a repository URL without the host (`org`, `org/project/_git/repo`): it selects
    /// the credential, so it is never empty.
    UrlPath, "URL path", path_chars
);
name_type!(
    /// The id a pasted token is stored under (`puddle:credential:<id>`).
    StoredId, "stored credential id", id_chars
);
name_type!(
    /// An organisation on a host (an Azure DevOps organisation).
    OrgName, "organisation name", account_chars
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_names() {
        assert!(AccountName::new("TijsVK").is_ok());
        assert!(AccountName::new("me+x@example.com").is_ok());
        assert!(HostName::new("github.example.com:8443").is_ok());
        assert!(UrlPath::new("org/project/_git/repo").is_ok());
        assert!(StoredId::new("a1-b_2").is_ok());
    }

    #[test]
    fn rejects_options_lines_and_odd_paths() {
        for bad in ["", "-x", "a b", "a\nb", "a\0b", "a;b", "a$b", "$(x)"] {
            assert!(AccountName::new(bad).is_err(), "{bad:?}");
        }
        assert!(AccountName::new("a".repeat(257)).is_err());
        assert!(HostName::new(".x").is_err());
        assert!(HostName::new("a/b").is_err());
        for bad in [
            "/a", "a/", "a//b", "a/../b", "a/./b", "a\nb", "a b", "a?x=1",
        ] {
            assert!(UrlPath::new(bad).is_err(), "{bad:?}");
        }
        assert!(StoredId::new("a".repeat(65)).is_err());
        assert!(StoredId::new("a:b").is_err());
    }

    #[test]
    fn serde_validates() {
        let ok: AccountName = serde_json::from_str("\"abc\"").unwrap();
        assert_eq!(ok.to_string(), "abc");
        assert_eq!(serde_json::to_string(&ok).unwrap(), "\"abc\"");
        assert!(serde_json::from_str::<AccountName>("\"-x\"").is_err());
    }

    #[test]
    fn error_names_the_kind() {
        assert_eq!(
            AccountName::new("").unwrap_err().to_string(),
            "not a valid account name"
        );
    }
}
