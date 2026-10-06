// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated names: sandboxes, workspaces, volumes and image references.
//!
//! Sandbox, workspace and volume names are DNS labels (RFC 1123: `a-z`, `0-9`, `-`, 1–63
//! characters, starting and ending with a letter or digit). That is stricter than msb's own rule
//! (it also allows upper case, `.` and `_`), so every puddle name is a valid msb name, and a name
//! can also be used as a host label (`<name>.localhost`) and in a pipe or file name unchanged.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ValidationError;

/// Longest DNS label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Prefix of a workspace's volume name: workspace `abc` keeps its files in volume `ws-abc`
/// (ADR 0006).
pub const WORKSPACE_VOLUME_PREFIX: &str = "ws-";

/// Sandbox names puddle refuses because the desktop shell uses them as host names
/// (`tauri.localhost`, `ipc.localhost`, `asset.localhost`).
pub const RESERVED_SANDBOX_NAMES: [&str; 3] = ["tauri", "ipc", "asset"];

/// Checks `value` against the DNS-label rule with at most `max_len` characters.
fn check_label(what: &'static str, value: &str, max_len: usize) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::new(what, value, "must not be empty"));
    }
    if value.len() > max_len {
        return Err(ValidationError::new(
            what,
            value,
            format_args!("must be at most {max_len} characters"),
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ValidationError::new(
            what,
            value,
            "may only contain a-z, 0-9 and '-'",
        ));
    }
    let edge_ok = |b: Option<u8>| b.is_some_and(|b| b != b'-');
    if !edge_ok(value.bytes().next()) || !edge_ok(value.bytes().last()) {
        return Err(ValidationError::new(
            what,
            value,
            "must start and end with a letter or digit",
        ));
    }
    Ok(())
}

/// Implements the string plumbing shared by the validated name types: `as_str`, `Display`,
/// `AsRef<str>`, `FromStr`, `TryFrom<String>`, `TryFrom<&str>` and `From<Name> for String`.
macro_rules! string_newtype {
    ($ty:ident) => {
        impl $ty {
            /// The name as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $ty {
            type Err = ValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl TryFrom<String> for $ty {
            type Error = ValidationError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(&s)
            }
        }

        impl TryFrom<&str> for $ty {
            type Error = ValidationError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl From<$ty> for String {
            fn from(n: $ty) -> String {
                n.0
            }
        }
    };
}

/// A sandbox's name: a DNS label that isn't one of [`RESERVED_SANDBOX_NAMES`].
///
/// ```
/// use puddle_types::SandboxName;
/// assert!(SandboxName::new("my-project").is_ok());
/// assert!(SandboxName::new("My_Project").is_err()); // upper case and '_'
/// assert!(SandboxName::new("tauri").is_err()); // reserved
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[cfg_attr(
    feature = "openapi",
    derive(utoipa::ToSchema),
    schema(
        value_type = String,
        min_length = 1,
        max_length = 63,
        pattern = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
        example = "my-project",
        description = "A sandbox's name: a DNS label (`a-z`, `0-9`, `-`, no leading or trailing `-`), \
                       not `tauri`, `ipc` or `asset`."
    )
)]
pub struct SandboxName(String);

impl SandboxName {
    /// Checks `name` and wraps it.
    ///
    /// # Errors
    ///
    /// When `name` isn't a DNS label (empty, longer than 63, characters other than `a-z`, `0-9`
    /// and `-`, or a leading/trailing `-`) or is reserved.
    pub fn new(name: &str) -> Result<Self, ValidationError> {
        check_label("sandbox name", name, MAX_LABEL_LEN)?;
        if RESERVED_SANDBOX_NAMES.contains(&name) {
            return Err(ValidationError::new(
                "sandbox name",
                name,
                "is reserved for the desktop shell",
            ));
        }
        Ok(Self(name.to_owned()))
    }
}

string_newtype!(SandboxName);

/// A workspace's identifier: a DNS label of at most 60 characters, so its volume name
/// (`ws-<id>`, see [`WorkspaceId::volume_name`]) is a DNS label too.
///
/// ```
/// use puddle_types::WorkspaceId;
/// let id = WorkspaceId::new("acme-api").unwrap();
/// assert_eq!(id.volume_name().as_str(), "ws-acme-api");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkspaceId(String);

impl WorkspaceId {
    /// Longest workspace id: 63 minus the length of [`WORKSPACE_VOLUME_PREFIX`].
    pub const MAX_LEN: usize = MAX_LABEL_LEN - WORKSPACE_VOLUME_PREFIX.len();

    /// Checks `id` and wraps it.
    ///
    /// # Errors
    ///
    /// When `id` isn't a DNS label of at most [`WorkspaceId::MAX_LEN`] characters.
    pub fn new(id: &str) -> Result<Self, ValidationError> {
        check_label("workspace id", id, Self::MAX_LEN)?;
        Ok(Self(id.to_owned()))
    }

    /// The name of the disk volume that holds this workspace's files: `ws-<id>` (ADR 0006).
    #[must_use]
    pub fn volume_name(&self) -> VolumeName {
        VolumeName(format!("{WORKSPACE_VOLUME_PREFIX}{}", self.0))
    }
}

string_newtype!(WorkspaceId);

/// A named disk volume's name: a DNS label.
///
/// ```
/// use puddle_types::{VolumeName, WorkspaceId};
/// let v = VolumeName::new("ws-acme-api").unwrap();
/// assert_eq!(v.workspace_id(), Some(WorkspaceId::new("acme-api").unwrap()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VolumeName(String);

impl VolumeName {
    /// Checks `name` and wraps it.
    ///
    /// # Errors
    ///
    /// When `name` isn't a DNS label.
    pub fn new(name: &str) -> Result<Self, ValidationError> {
        check_label("volume name", name, MAX_LABEL_LEN)?;
        Ok(Self(name.to_owned()))
    }

    /// The workspace this volume belongs to, if its name has the `ws-` prefix.
    #[must_use]
    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        self.0
            .strip_prefix(WORKSPACE_VOLUME_PREFIX)
            .and_then(|id| WorkspaceId::new(id).ok())
    }
}

string_newtype!(VolumeName);

/// An OCI image reference as the user wrote it (`mcr.microsoft.com/devcontainers/base:debian`).
///
/// Only checked for shape (non-empty, at most 512 characters, printable ASCII without spaces);
/// the runtime resolves and rejects references it can't pull.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageRef(String);

impl ImageRef {
    /// Longest accepted reference.
    pub const MAX_LEN: usize = 512;

    /// Checks `reference` and wraps it.
    ///
    /// # Errors
    ///
    /// When `reference` is empty, too long, or contains whitespace or non-printable characters.
    pub fn new(reference: &str) -> Result<Self, ValidationError> {
        if reference.is_empty() {
            return Err(ValidationError::new(
                "image reference",
                reference,
                "must not be empty",
            ));
        }
        if reference.len() > Self::MAX_LEN {
            return Err(ValidationError::new(
                "image reference",
                reference,
                format_args!("must be at most {} characters", Self::MAX_LEN),
            ));
        }
        if !reference.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ValidationError::new(
                "image reference",
                reference,
                "may only contain printable ASCII without spaces",
            ));
        }
        Ok(Self(reference.to_owned()))
    }
}

string_newtype!(ImageRef);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "openapi")]
    proptest::proptest! {
        /// The pattern published in the API schema accepts only names `SandboxName::new` accepts
        /// (the reserved names aside, which a pattern can't express).
        #[test]
        fn openapi_pattern_agrees_with_the_constructor(
            name in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
        ) {
            use utoipa::PartialSchema;
            let schema = serde_json::to_value(SandboxName::schema()).unwrap();
            proptest::prop_assert_eq!(&schema["pattern"], "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$");
            proptest::prop_assert_eq!(&schema["maxLength"], 63);
            let reserved = RESERVED_SANDBOX_NAMES.contains(&name.as_str());
            proptest::prop_assert_eq!(SandboxName::new(&name).is_ok(), !reserved);
        }
    }

    #[test]
    fn sandbox_name_accepts_dns_labels() {
        for ok in ["a", "0", "my-project", "a-1-b", &"x".repeat(63)] {
            assert_eq!(SandboxName::new(ok).unwrap().as_str(), ok);
        }
    }

    #[test]
    fn sandbox_name_rejects_non_labels_with_a_reason() {
        let cases = [
            ("", "must not be empty"),
            (&*"x".repeat(64), "at most 63"),
            ("Foo", "a-z, 0-9"),
            ("a_b", "a-z, 0-9"),
            ("a.b", "a-z, 0-9"),
            ("a b", "a-z, 0-9"),
            ("é", "a-z, 0-9"),
            ("-a", "start and end"),
            ("a-", "start and end"),
            ("-", "start and end"),
        ];
        for (bad, reason) in cases {
            let err = SandboxName::new(bad).unwrap_err();
            assert!(err.reason().contains(reason), "{bad:?}: {err}");
            assert_eq!(err.what(), "sandbox name");
        }
    }

    #[test]
    fn reserved_sandbox_names_are_refused() {
        for reserved in RESERVED_SANDBOX_NAMES {
            let err = SandboxName::new(reserved).unwrap_err();
            assert!(err.reason().contains("reserved"), "{err}");
        }
        assert!(SandboxName::new("tauri-app").is_ok());
    }

    #[test]
    fn workspace_id_leaves_room_for_the_volume_prefix() {
        let longest = "w".repeat(WorkspaceId::MAX_LEN);
        let id = WorkspaceId::new(&longest).unwrap();
        assert_eq!(id.volume_name().as_str().len(), 63);
        assert!(VolumeName::new(id.volume_name().as_str()).is_ok());
        assert!(WorkspaceId::new(&"w".repeat(WorkspaceId::MAX_LEN + 1)).is_err());
    }

    #[test]
    fn volume_name_maps_back_to_its_workspace() {
        let id = WorkspaceId::new("acme").unwrap();
        assert_eq!(id.volume_name().workspace_id(), Some(id));
        assert_eq!(VolumeName::new("other").unwrap().workspace_id(), None);
        assert_eq!(
            VolumeName::new("ws-").ok(),
            None,
            "trailing '-' isn't a label"
        );
        assert!(VolumeName::new("Bad").is_err());
    }

    #[test]
    fn image_ref_checks_shape_only() {
        assert!(ImageRef::new("mcr.microsoft.com/devcontainers/base:debian").is_ok());
        assert!(ImageRef::new("alpine@sha256:0123").is_ok());
        assert!(ImageRef::new("").is_err());
        assert!(ImageRef::new("a b").is_err());
        assert!(ImageRef::new("a\nb").is_err());
        assert!(ImageRef::new(&"a".repeat(513)).is_err());
    }

    #[test]
    fn string_conversions_round_trip() {
        let n: SandboxName = "box".parse().unwrap();
        assert_eq!(n.to_string(), "box");
        assert_eq!(AsRef::<str>::as_ref(&n), "box");
        assert_eq!(String::from(n.clone()), "box");
        assert_eq!(SandboxName::try_from("box").unwrap(), n);
        assert_eq!(SandboxName::try_from(String::from("box")).unwrap(), n);
        let w: WorkspaceId = "w".parse().unwrap();
        assert_eq!(w.to_string(), "w");
        let v: VolumeName = "v".parse().unwrap();
        assert_eq!(v.as_str(), "v");
        let i: ImageRef = "alpine".parse().unwrap();
        assert_eq!(i.as_str(), "alpine");
    }

    #[test]
    fn serde_validates_on_the_way_in() {
        let n: SandboxName = serde_json::from_str(r#""box""#).unwrap();
        assert_eq!(serde_json::to_string(&n).unwrap(), r#""box""#);
        assert!(serde_json::from_str::<SandboxName>(r#""Box""#).is_err());
        assert!(serde_json::from_str::<SandboxName>(r#""ipc""#).is_err());
        assert!(serde_json::from_str::<WorkspaceId>(r#""-""#).is_err());
        assert!(serde_json::from_str::<VolumeName>(r#""""#).is_err());
        assert!(serde_json::from_str::<ImageRef>(r#""a b""#).is_err());
    }
}
