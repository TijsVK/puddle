// SPDX-License-Identifier: GPL-3.0-or-later
//! Merged guest files: puddle owns only some keys of a file that otherwise belongs to the user.
//!
//! A [`MergeSpec`] names the keys puddle owns and their values. Applying it to the file in the
//! guest sets those keys and keeps everything else, byte for byte: the file is edited in place
//! (only the owned values are rewritten or inserted), not parsed and re-serialised. Removing the
//! keys again (when no provider lists the file any more) deletes exactly them. A file that can't
//! be parsed is never touched: the caller leaves it and logs the [`MergeRefusal`].
//!
//! Two formats exist: [`MergeFormat::Json`] (the Docker CLI's `config.json`, whose `auths` from
//! `docker login` must survive a restart) and [`MergeFormat::Jsonc`] (VS Code's Machine
//! `settings.json`, which may hold comments and trailing commas). Other formats (INI, TOML) are a
//! new [`MergeFormat`] variant with its own engine; keys are paths of strings in every format,
//! values are text in the format's own syntax.
//!
//! The engine is pure (no I/O): `puddle-agent merge-file` runs it in the guest, so the host never
//! parses a file the guest wrote.
//!
//! ```
//! use puddle_types::{MergeEntry, MergeFormat, MergeSpec, Merged};
//! let spec = MergeSpec::new(
//!     MergeFormat::Json,
//!     vec![MergeEntry::json(&["proxies", "default"], &serde_json::json!({"httpProxy": "http://p:1"}))],
//! )
//! .unwrap();
//! let user = br#"{"auths": {"r.example": {"auth": "x"}}}"#;
//! let Merged::Write(out) = spec.apply(Some(user), &[]).unwrap() else { panic!() };
//! let out = String::from_utf8(out).unwrap();
//! assert_eq!(out, r#"{"auths": {"r.example": {"auth": "x"}}, "proxies": {"default":{"httpProxy":"http://p:1"}}}"#);
//! assert_eq!(spec.apply(Some(out.as_bytes()), &[]).unwrap(), Merged::Unchanged);
//! ```

use serde::{Deserialize, Serialize};

use crate::ValidationError;

mod json;
mod jsonc;
mod sshconfig;

/// Largest file the engine reads (4 MiB). A larger one is left alone.
pub const MAX_MERGE_FILE: usize = 4 << 20;

/// The syntax of a merged file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MergeFormat {
    /// Strict JSON (RFC 8259) with an object at the top level.
    Json,
    /// JSON with `//` and `/* */` comments and trailing commas, as VS Code reads its settings.
    /// An object at the top level; the user's comments stay where they are. Values in a
    /// [`MergeEntry`] are plain JSON.
    Jsonc,
    /// OpenSSH's `ssh_config`: puddle owns one `Include <pattern>` line (key path `["Include"]`,
    /// the value is the pattern), added at the top when no `Include` before the first `Host` or
    /// `Match` reads that pattern. The rest of the file keeps its bytes.
    SshConfig,
}

/// One key puddle owns, as a path from the top level (`["proxies", "default"]`), and its value
/// in the format's syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeEntry {
    key: Vec<String>,
    value: String,
}

impl MergeEntry {
    /// A JSON entry: `key` set to `value`.
    #[must_use]
    pub fn json(key: &[&str], value: &serde_json::Value) -> Self {
        Self {
            key: key.iter().map(|k| (*k).to_owned()).collect(),
            value: value.to_string(),
        }
    }

    /// The `Include` line of an `ssh_config` ([`MergeFormat::SshConfig`]): `pattern` is what it
    /// includes, such as `/etc/ssh/ssh_config.d/*.conf`.
    #[must_use]
    pub fn ssh_include(pattern: &str) -> Self {
        Self {
            key: vec!["Include".to_owned()],
            value: pattern.to_owned(),
        }
    }

    /// The key path.
    #[must_use]
    pub fn key(&self) -> &[String] {
        &self.key
    }

    /// The value, in the format's syntax.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// The keys puddle owns in one file, and their values. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSpec", into = "RawSpec")]
pub struct MergeSpec {
    format: MergeFormat,
    entries: Vec<MergeEntry>,
}

#[derive(Serialize, Deserialize)]
struct RawSpec {
    format: MergeFormat,
    entries: Vec<MergeEntry>,
}

impl TryFrom<RawSpec> for MergeSpec {
    type Error = ValidationError;

    fn try_from(raw: RawSpec) -> Result<Self, Self::Error> {
        Self::new(raw.format, raw.entries)
    }
}

impl From<MergeSpec> for RawSpec {
    fn from(spec: MergeSpec) -> Self {
        Self {
            format: spec.format,
            entries: spec.entries,
        }
    }
}

/// What applying (or removing) a spec does to the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Merged {
    /// The file already says this: leave it as it is (not even rewritten).
    Unchanged,
    /// Write these bytes (the whole new file).
    Write(Vec<u8>),
}

/// The result of [`unmerge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmerged {
    /// What to do with the file.
    pub merged: Merged,
    /// Whether the top-level object is empty afterwards (the caller may delete a file puddle
    /// created).
    pub empty: bool,
}

/// Why a file is left as it is. The messages never quote the file's contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MergeRefusal {
    /// The file is larger than [`MAX_MERGE_FILE`].
    #[error("the file is larger than {MAX_MERGE_FILE} bytes")]
    TooLarge,
    /// The file doesn't parse in the format.
    #[error("the file is not valid {format}: {reason}")]
    Syntax {
        /// The format's name.
        format: &'static str,
        /// The parser's message (position only, no content).
        reason: String,
    },
    /// The top level isn't an object.
    #[error("the top level of the file is not an object")]
    NotAnObject,
    /// A key on an owned path holds something other than an object.
    #[error("{key} in the file is not an object, so puddle's keys can't go below it")]
    Conflict {
        /// The key path, joined with `.`.
        key: String,
    },
    /// A key on an owned path appears more than once in its object.
    #[error("{key} appears more than once in the file")]
    DuplicateKey {
        /// The key path, joined with `.`.
        key: String,
    },
    /// The file contains a NUL byte, so it isn't a text configuration file.
    #[error("the file contains a NUL byte")]
    NulByte,
    /// The engine's self-check failed (a bug); the file is left alone.
    #[error("the merged file failed puddle's consistency check")]
    Inconsistent,
}

impl MergeSpec {
    /// Checks and wraps the entries.
    ///
    /// # Errors
    ///
    /// When there are no entries, a key path is empty, one key path is equal to or a prefix of
    /// another, or a value isn't valid in the format.
    pub fn new(format: MergeFormat, entries: Vec<MergeEntry>) -> Result<Self, ValidationError> {
        const WHAT: &str = "merge spec";
        if entries.is_empty() {
            return Err(ValidationError::new(WHAT, "", "must own at least one key"));
        }
        for (i, e) in entries.iter().enumerate() {
            let shown = display_key(&e.key);
            if e.key.is_empty() {
                return Err(ValidationError::new(WHAT, "", "a key path is empty"));
            }
            if entries
                .iter()
                .skip(i + 1)
                .any(|o| o.key.starts_with(&e.key) || e.key.starts_with(&o.key))
            {
                return Err(ValidationError::new(
                    WHAT,
                    &shown,
                    "overlaps another owned key",
                ));
            }
            match format {
                MergeFormat::Json | MergeFormat::Jsonc => {
                    if serde_json::from_str::<serde_json::Value>(&e.value).is_err() {
                        return Err(ValidationError::new(WHAT, &shown, "value is not JSON"));
                    }
                }
                MergeFormat::SshConfig => {
                    if e.key != [sshconfig::KEY] {
                        return Err(ValidationError::new(WHAT, &shown, "only Include is owned"));
                    }
                    if e.value.is_empty()
                        || e.value
                            .chars()
                            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '#')
                    {
                        return Err(ValidationError::new(
                            WHAT,
                            &shown,
                            "the pattern must be one word without quotes or #",
                        ));
                    }
                }
            }
        }
        Ok(Self { format, entries })
    }

    /// The format.
    #[must_use]
    pub fn format(&self) -> MergeFormat {
        self.format
    }

    /// The owned keys and their values, in order.
    #[must_use]
    pub fn entries(&self) -> &[MergeEntry] {
        &self.entries
    }

    /// The owned key paths.
    #[must_use]
    pub fn keys(&self) -> Vec<Vec<String>> {
        self.entries.iter().map(|e| e.key.clone()).collect()
    }

    /// The file as puddle writes it when none exists.
    #[must_use]
    pub fn fresh(&self) -> Vec<u8> {
        match self.apply(None, &[]) {
            Ok(Merged::Write(bytes)) => bytes,
            // `new` checked every value, so applying to an empty file can't be refused.
            Ok(Merged::Unchanged) | Err(_) => Vec::new(),
        }
    }

    /// Applies the spec to `existing` (`None`: no file, or an empty one): removes the keys in
    /// `previous` (what puddle owned at the last boot) that this spec no longer owns, then sets
    /// every owned key. Everything else in the file keeps its bytes.
    ///
    /// # Errors
    ///
    /// A [`MergeRefusal`] when the file can't be merged; the caller leaves it as it is.
    pub fn apply(
        &self,
        existing: Option<&[u8]>,
        previous: &[Vec<String>],
    ) -> Result<Merged, MergeRefusal> {
        if self.format == MergeFormat::SshConfig {
            return sshconfig::apply(existing, &self.entries).map(|out| {
                if existing == Some(out.as_bytes()) {
                    Merged::Unchanged
                } else {
                    Merged::Write(out.into_bytes())
                }
            });
        }
        let owned = self.keys();
        let dropped: Vec<&[String]> = previous
            .iter()
            .filter(|k| !owned.contains(k))
            .map(Vec::as_slice)
            .collect();
        let original = text(existing)?;
        let dialect = dialect(self.format);
        json::apply(dialect, original.as_deref(), &dropped, &self.entries).map(|out| match out {
            Some(t) if original.as_deref() != Some(t.as_str()) => Merged::Write(t.into_bytes()),
            _ => Merged::Unchanged,
        })
    }
}

/// Removes the owned `keys` from `existing`, and every object on their paths that is left empty.
///
/// # Errors
///
/// A [`MergeRefusal`] when the file can't be edited; the caller leaves it as it is.
pub fn unmerge(
    format: MergeFormat,
    existing: &[u8],
    keys: &[Vec<String>],
) -> Result<Unmerged, MergeRefusal> {
    if format == MergeFormat::SshConfig {
        return sshconfig::unmerge(existing);
    }
    let Some(original) = text(Some(existing))? else {
        return Ok(Unmerged {
            merged: Merged::Unchanged,
            empty: true,
        });
    };
    let keys: Vec<&[String]> = keys.iter().map(Vec::as_slice).collect();
    let (out, empty) = json::unmerge(dialect(format), &original, &keys)?;
    let merged = if out == original {
        Merged::Unchanged
    } else {
        Merged::Write(out.into_bytes())
    };
    Ok(Unmerged { merged, empty })
}

/// The engine's dialect for a format.
fn dialect(format: MergeFormat) -> json::Dialect {
    match format {
        MergeFormat::Json => json::Dialect::Strict,
        MergeFormat::Jsonc => json::Dialect::Comments,
        MergeFormat::SshConfig => unreachable!("ssh_config has its own engine"),
    }
}

/// The file as text; `None` for no file or only whitespace.
fn text(existing: Option<&[u8]>) -> Result<Option<String>, MergeRefusal> {
    let Some(bytes) = existing else {
        return Ok(None);
    };
    if bytes.len() > MAX_MERGE_FILE {
        return Err(MergeRefusal::TooLarge);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| MergeRefusal::Syntax {
        format: "UTF-8",
        reason: "invalid byte sequence".to_owned(),
    })?;
    Ok((!s.trim().is_empty()).then(|| s.to_owned()))
}

fn display_key(key: &[String]) -> String {
    key.join(".")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(entries: Vec<MergeEntry>) -> MergeSpec {
        MergeSpec::new(MergeFormat::Json, entries).unwrap()
    }

    #[test]
    fn spec_refuses_empty_overlapping_and_invalid_entries() {
        let err = |entries| {
            MergeSpec::new(MergeFormat::Json, entries)
                .unwrap_err()
                .to_string()
        };
        assert!(err(vec![]).contains("at least one key"));
        assert!(err(vec![MergeEntry::json(&[], &json!(1))]).contains("key path is empty"));
        assert!(
            err(vec![
                MergeEntry::json(&["a", "b"], &json!(1)),
                MergeEntry::json(&["a"], &json!(1)),
            ])
            .contains("\"a.b\": overlaps")
        );
        assert!(
            err(vec![
                MergeEntry::json(&["a"], &json!(1)),
                MergeEntry::json(&["a"], &json!(2)),
            ])
            .contains("overlaps")
        );
        let bad = MergeEntry {
            key: vec!["a".into()],
            value: "{".into(),
        };
        assert!(err(vec![bad]).contains("not JSON"));
        // Siblings and keys that only share a string prefix are fine.
        spec(vec![
            MergeEntry::json(&["a", "b"], &json!(1)),
            MergeEntry::json(&["a", "c"], &json!(1)),
            MergeEntry::json(&["ab"], &json!(1)),
        ]);
    }

    #[test]
    fn spec_round_trips_through_serde_and_validates_on_the_way_in() {
        let s = spec(vec![MergeEntry::json(&["k"], &json!({"x": [1, 2]}))]);
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(
            text,
            r#"{"format":"json","entries":[{"key":["k"],"value":"{\"x\":[1,2]}"}]}"#
        );
        assert_eq!(serde_json::from_str::<MergeSpec>(&text).unwrap(), s);
        assert!(serde_json::from_str::<MergeSpec>(r#"{"format":"json","entries":[]}"#).is_err());
        assert_eq!(s.format(), MergeFormat::Json);
        assert_eq!(s.entries()[0].key(), ["k"]);
        assert_eq!(s.entries()[0].value(), r#"{"x":[1,2]}"#);
    }

    #[test]
    fn fresh_file_is_tab_indented_like_the_docker_cli_writes_it() {
        let s = spec(vec![MergeEntry::json(
            &["proxies", "default"],
            &json!({"httpProxy": "http://172.17.0.1:3128", "noProxy": "localhost"}),
        )]);
        assert_eq!(
            String::from_utf8(s.fresh()).unwrap(),
            "{\n\t\"proxies\": {\n\t\t\"default\": {\n\t\t\t\"httpProxy\": \"http://172.17.0.1:3128\",\n\t\t\t\"noProxy\": \"localhost\"\n\t\t}\n\t}\n}\n"
        );
        // An empty or whitespace-only file counts as no file.
        assert_eq!(
            s.apply(Some(b" \n"), &[]).unwrap(),
            Merged::Write(s.fresh())
        );
    }

    #[test]
    fn unreadable_files_are_refused_with_a_reason_and_no_content() {
        let s = spec(vec![MergeEntry::json(&["a"], &json!(1))]);
        let big = vec![b' '; MAX_MERGE_FILE + 1];
        assert_eq!(s.apply(Some(&big), &[]), Err(MergeRefusal::TooLarge));
        let e = s.apply(Some(b"\xff{}"), &[]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the file is not valid UTF-8: invalid byte sequence"
        );
        let e = s.apply(Some(b"{\"secret-token\": "), &[]).unwrap_err();
        assert!(matches!(e, MergeRefusal::Syntax { format: "JSON", .. }));
        assert!(!e.to_string().contains("secret-token"), "{e}");
        assert_eq!(s.apply(Some(b"[1]"), &[]), Err(MergeRefusal::NotAnObject));
        assert_eq!(
            unmerge(MergeFormat::Json, b"nope", &[vec!["a".into()]]).unwrap_err(),
            MergeRefusal::Syntax {
                format: "JSON",
                reason: "expected ident at line 1 column 2".into()
            }
        );
    }

    #[test]
    fn unmerge_of_an_empty_file_is_a_no_op() {
        let u = unmerge(MergeFormat::Json, b"", &[vec!["a".into()]]).unwrap();
        assert_eq!(u.merged, Merged::Unchanged);
        assert!(u.empty);
    }
}
