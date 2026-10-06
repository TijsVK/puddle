// SPDX-License-Identifier: GPL-3.0-or-later
//! What puddle puts into a guest: paths, files and environment variables.
//!
//! Providers (proxy config, corporate roots, the per-sandbox CA) produce [`GuestFile`]s and
//! [`GuestEnv`]; the boot hook applies them as a list and holds no provider logic itself.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ValidationError;
use crate::merge::MergeSpec;

/// Longest accepted guest path (Linux `PATH_MAX`).
const MAX_PATH_LEN: usize = 4096;

/// An absolute, normalised path inside the guest (always `/`-separated, whatever the host OS).
///
/// Normalised means: starts with `/`, no empty, `.` or `..` components, no trailing `/` (except
/// the root itself), no NUL. So two `GuestPath`s name the same file exactly when they are equal,
/// and a path can't climb out of a mount with `..`.
///
/// ```
/// use puddle_types::GuestPath;
/// let p = GuestPath::new("/workspaces/acme/src").unwrap();
/// assert!(p.is_within(&GuestPath::new("/workspaces/acme").unwrap()));
/// assert!(GuestPath::new("/workspaces/../etc").is_err());
/// assert!(GuestPath::new("relative").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GuestPath(String);

impl GuestPath {
    /// Checks `path` and wraps it.
    ///
    /// # Errors
    ///
    /// When `path` is relative, not normalised (empty, `.` or `..` components, trailing `/`),
    /// contains NUL, or is longer than 4096 bytes.
    pub fn new(path: &str) -> Result<Self, ValidationError> {
        const WHAT: &str = "guest path";
        if !path.starts_with('/') {
            return Err(ValidationError::new(WHAT, path, "must be absolute"));
        }
        if path.len() > MAX_PATH_LEN {
            return Err(ValidationError::new(
                WHAT,
                path,
                format_args!("must be at most {MAX_PATH_LEN} bytes"),
            ));
        }
        if path.contains('\0') {
            return Err(ValidationError::new(WHAT, path, "must not contain NUL"));
        }
        if path != "/" {
            for component in path.split('/').skip(1) {
                if component.is_empty() || component == "." || component == ".." {
                    return Err(ValidationError::new(
                        WHAT,
                        path,
                        "must be normalised (no empty, '.' or '..' components, no trailing '/')",
                    ));
                }
            }
        }
        Ok(Self(path.to_owned()))
    }

    /// The path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this path is `dir` itself or lies below it (component-wise, so `/ab` is not within
    /// `/a`).
    #[must_use]
    pub fn is_within(&self, dir: &GuestPath) -> bool {
        self.relative_to(dir).is_some()
    }

    /// This path relative to `dir` (`""` for `dir` itself), or `None` if it isn't within `dir`.
    #[must_use]
    pub fn relative_to(&self, dir: &GuestPath) -> Option<&str> {
        if dir.0 == "/" {
            return Some(self.0.trim_start_matches('/'));
        }
        let rest = self.0.strip_prefix(dir.0.as_str())?;
        if rest.is_empty() {
            Some("")
        } else {
            rest.strip_prefix('/')
        }
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for GuestPath {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl TryFrom<&str> for GuestPath {
    type Error = ValidationError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<GuestPath> for String {
    fn from(p: GuestPath) -> String {
        p.0
    }
}

/// A file the boot hook writes into the guest: path, contents, permission bits and how it is
/// applied ([`ApplyKind`]).
///
/// Contents are public material only (configs, CA certificates). Never put a secret in a
/// `GuestFile`: it is logged in `Debug` and copied into the guest's root disk.
///
/// ```
/// use puddle_types::{GuestFile, GuestPath};
/// let f = GuestFile::new(GuestPath::new("/etc/profile.d/01-puddle-env.sh").unwrap(), b"export A=1\n".to_vec())
///     .with_mode(0o644)
///     .unwrap();
/// assert_eq!(f.mode(), 0o644);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestFile {
    path: GuestPath,
    contents: Vec<u8>,
    mode: u32,
    #[serde(default)]
    apply: ApplyKind,
}

/// How the boot hook applies a [`GuestFile`] (T-020 C-4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ApplyKind {
    /// puddle owns the whole file: written atomically at every boot, replacing what is there,
    /// and deleted when no provider lists it any more.
    #[default]
    Replace,
    /// The file is the user's; puddle owns only the keys in the spec (T-097). They are set at
    /// every boot and removed when no provider lists the file any more; everything else stays.
    /// A file that can't be parsed is left alone. The file's mode applies when puddle creates it.
    Merge(MergeSpec),
}

impl GuestFile {
    /// Default permission bits: `0o644`.
    pub const DEFAULT_MODE: u32 = 0o644;

    /// A file at `path` with `contents` and mode [`GuestFile::DEFAULT_MODE`].
    #[must_use]
    pub fn new(path: GuestPath, contents: Vec<u8>) -> Self {
        Self {
            path,
            contents,
            mode: Self::DEFAULT_MODE,
            apply: ApplyKind::Replace,
        }
    }

    /// A merged file at `path`: puddle owns only the keys in `spec` (see [`ApplyKind::Merge`]).
    /// [`GuestFile::contents`] is the file as puddle writes it when none exists.
    ///
    /// ```
    /// use puddle_types::{ApplyKind, GuestFile, GuestPath, MergeEntry, MergeFormat, MergeSpec};
    /// let spec = MergeSpec::new(MergeFormat::Json, vec![MergeEntry::json(&["a"], &serde_json::json!(1))]).unwrap();
    /// let f = GuestFile::merged(GuestPath::new("/root/.docker/config.json").unwrap(), spec);
    /// assert_eq!(f.contents(), b"{\n\t\"a\": 1\n}\n");
    /// assert!(matches!(f.apply(), ApplyKind::Merge(_)));
    /// ```
    #[must_use]
    pub fn merged(path: GuestPath, spec: MergeSpec) -> Self {
        Self {
            path,
            contents: spec.fresh(),
            mode: Self::DEFAULT_MODE,
            apply: ApplyKind::Merge(spec),
        }
    }

    /// The same file with permission bits `mode`.
    ///
    /// # Errors
    ///
    /// When `mode` has bits outside `0o7777`.
    pub fn with_mode(mut self, mode: u32) -> Result<Self, ValidationError> {
        if mode & !0o7777 != 0 {
            return Err(ValidationError::new(
                "file mode",
                &format!("{mode:o}"),
                "must be within 0o7777",
            ));
        }
        self.mode = mode;
        Ok(self)
    }

    /// Where the file goes in the guest.
    #[must_use]
    pub fn path(&self) -> &GuestPath {
        &self.path
    }

    /// The file's contents.
    #[must_use]
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    /// The file's permission bits.
    #[must_use]
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// How the boot hook applies the file.
    #[must_use]
    pub fn apply(&self) -> &ApplyKind {
        &self.apply
    }
}

/// Environment variables for the guest, by name. Later [`GuestEnv::set`]s and
/// [`GuestEnv::extend`]s win.
///
/// Names follow POSIX shell rules (`[A-Za-z_][A-Za-z0-9_]*`), values may be anything but NUL.
/// Case matters: `HTTP_PROXY` and `http_proxy` are separate variables (both are set, T-030).
///
/// ```
/// use puddle_types::GuestEnv;
/// let mut env = GuestEnv::new();
/// env.set("HTTPS_PROXY", "http://127.0.0.1:3128").unwrap();
/// env.set("https_proxy", "http://127.0.0.1:3128").unwrap();
/// assert_eq!(env.get("HTTPS_PROXY"), Some("http://127.0.0.1:3128"));
/// assert_eq!(env.len(), 2);
/// assert!(env.set("BAD-NAME", "x").is_err());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<String, String>",
    into = "BTreeMap<String, String>"
)]
pub struct GuestEnv(BTreeMap<String, String>);

impl GuestEnv {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `name` to `value`, replacing an earlier value.
    ///
    /// # Errors
    ///
    /// When `name` isn't a shell variable name or `value` contains NUL.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), ValidationError> {
        check_env_name(name)?;
        if value.contains('\0') {
            return Err(ValidationError::new(
                "environment value",
                name,
                "must not contain NUL",
            ));
        }
        self.0.insert(name.to_owned(), value.to_owned());
        Ok(())
    }

    /// The value of `name`, if set.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// Adds every variable of `other`; `other` wins on equal names.
    pub fn extend(&mut self, other: &GuestEnv) {
        self.0
            .extend(other.0.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// The variables, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// How many variables are set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no variable is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn check_env_name(name: &str) -> Result<(), ValidationError> {
    let mut bytes = name.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
    if !first_ok || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(ValidationError::new(
            "environment variable name",
            name,
            "must match [A-Za-z_][A-Za-z0-9_]*",
        ));
    }
    Ok(())
}

impl TryFrom<BTreeMap<String, String>> for GuestEnv {
    type Error = ValidationError;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        let mut env = GuestEnv::new();
        for (k, v) in &map {
            env.set(k, v)?;
        }
        Ok(env)
    }
}

impl From<GuestEnv> for BTreeMap<String, String> {
    fn from(env: GuestEnv) -> Self {
        env.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> GuestPath {
        GuestPath::new(s).unwrap()
    }

    #[test]
    fn guest_path_accepts_normalised_absolute_paths() {
        for ok in [
            "/",
            "/a",
            "/a/b.c",
            "/.hidden",
            "/a/..b",
            "/workspaces/acme",
        ] {
            assert_eq!(p(ok).as_str(), ok);
            assert_eq!(p(ok).to_string(), ok);
        }
    }

    #[test]
    fn guest_path_rejects_everything_else() {
        let cases = [
            ("", "absolute"),
            ("a/b", "absolute"),
            ("/a/", "normalised"),
            ("//a", "normalised"),
            ("/a//b", "normalised"),
            ("/a/./b", "normalised"),
            ("/a/../b", "normalised"),
            ("/..", "normalised"),
            ("/a\0b", "NUL"),
        ];
        for (bad, reason) in cases {
            let err = GuestPath::new(bad).unwrap_err();
            assert!(err.reason().contains(reason), "{bad:?}: {err}");
        }
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(GuestPath::new(&long).unwrap_err().reason().contains("4096"));
    }

    #[test]
    fn within_is_component_wise() {
        assert!(p("/a/b").is_within(&p("/a")));
        assert!(p("/a").is_within(&p("/a")));
        assert!(p("/a").is_within(&p("/")));
        assert!(!p("/ab").is_within(&p("/a")));
        assert!(!p("/a").is_within(&p("/a/b")));
        assert_eq!(p("/a/b/c").relative_to(&p("/a")), Some("b/c"));
        assert_eq!(p("/a").relative_to(&p("/a")), Some(""));
        assert_eq!(p("/a/b").relative_to(&p("/")), Some("a/b"));
        assert_eq!(p("/").relative_to(&p("/")), Some(""));
    }

    #[test]
    fn guest_path_conversions() {
        assert_eq!(GuestPath::try_from("/x").unwrap(), p("/x"));
        assert_eq!(GuestPath::try_from(String::from("/x")).unwrap(), p("/x"));
        assert_eq!(String::from(p("/x")), "/x");
        assert!(serde_json::from_str::<GuestPath>(r#""/a/../b""#).is_err());
        assert_eq!(serde_json::to_string(&p("/x")).unwrap(), r#""/x""#);
    }

    #[test]
    fn guest_file_defaults_and_mode_check() {
        let f = GuestFile::new(p("/etc/x"), b"hi".to_vec());
        assert_eq!(f.mode(), GuestFile::DEFAULT_MODE);
        assert_eq!(f.path(), &p("/etc/x"));
        assert_eq!(f.contents(), b"hi");
        assert_eq!(f.clone().with_mode(0o4755).unwrap().mode(), 0o4755);
        let err = f.with_mode(0o10000).unwrap_err();
        assert_eq!(err.what(), "file mode");
    }

    #[test]
    fn guest_env_names_and_values_are_checked() {
        let mut env = GuestEnv::new();
        assert!(env.is_empty());
        for ok in ["A", "_", "a_1", "NODE_EXTRA_CA_CERTS"] {
            env.set(ok, "v").unwrap();
        }
        for bad in ["", "1A", "A-B", "A B", "Ä"] {
            assert!(env.set(bad, "v").is_err(), "{bad:?}");
        }
        assert!(env.set("A", "nul\0").is_err());
        assert_eq!(env.len(), 4);
    }

    #[test]
    fn guest_env_later_values_win() {
        let mut a = GuestEnv::new();
        a.set("X", "1").unwrap();
        a.set("Y", "1").unwrap();
        let mut b = GuestEnv::new();
        b.set("X", "2").unwrap();
        a.extend(&b);
        assert_eq!(a.get("X"), Some("2"));
        assert_eq!(a.get("Y"), Some("1"));
        assert_eq!(a.get("Z"), None);
        let pairs: Vec<_> = a.iter().collect();
        assert_eq!(pairs, [("X", "2"), ("Y", "1")]);
    }

    #[test]
    fn guest_env_serde_validates() {
        let env: GuestEnv = serde_json::from_str(r#"{"A":"1"}"#).unwrap();
        assert_eq!(env.get("A"), Some("1"));
        assert_eq!(serde_json::to_string(&env).unwrap(), r#"{"A":"1"}"#);
        assert!(serde_json::from_str::<GuestEnv>(r#"{"A-B":"1"}"#).is_err());
    }
}
