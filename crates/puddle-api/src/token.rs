// SPDX-License-Identifier: GPL-3.0-or-later
//! The API's bearer token, and the user-only connection file that hands it (with the URL) to the
//! CLI and the UI.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Random bytes in a token (256 bits).
const TOKEN_BYTES: usize = 32;

/// Largest connection file read back; a real one is under 200 bytes.
const MAX_FILE_BYTES: u64 = 4096;

/// Version of the connection file's format.
const FILE_VERSION: u32 = 1;

/// The API's bearer token: 32 random bytes as 64 lower-case hex characters.
///
/// `Debug` never shows the value and there is no `Display`; [`ApiToken::expose`] is the one way
/// to read it, for the connection file and for clients that send it.
#[derive(Clone)]
pub struct ApiToken(String);

impl ApiToken {
    /// A fresh token from the OS random source.
    ///
    /// # Errors
    ///
    /// [`ConnectionFileError::Random`] if the OS has no randomness to give.
    pub fn generate() -> Result<Self, ConnectionFileError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|err| ConnectionFileError::Random(err.to_string()))?;
        Ok(Self(hex(&bytes)))
    }

    /// Whether `presented` is this token, compared in constant time. A different length is
    /// refused at once (the length isn't secret).
    #[must_use]
    pub fn matches(&self, presented: &[u8]) -> bool {
        self.0.as_bytes().ct_eq(presented).into()
    }

    /// The token text, to write into the connection file or send in a request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn parse(text: String) -> Result<Self, String> {
        let well_formed = text.len() == TOKEN_BYTES * 2
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if well_formed {
            Ok(Self(text))
        } else {
            Err("token is not 64 lower-case hex characters".to_owned())
        }
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 0xf] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// Where the API listens and the token it wants: what a client needs to connect.
///
/// The server writes it with [`ConnectionInfo::write`] after binding; the CLI and UI read it
/// with [`ConnectionInfo::read`]. On Unix the file is created `0600` (its directory `0700` when
/// puddle creates it) and a file readable by others is refused when read back. On Windows it
/// inherits the ACL of its directory, so it belongs in the user's profile (`%LOCALAPPDATA%`),
/// which only the user, administrators and `SYSTEM` can read.
#[derive(Clone)]
pub struct ConnectionInfo {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    /// The bearer token.
    pub token: ApiToken,
}

impl fmt::Debug for ConnectionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionInfo")
            .field("url", &self.url)
            .field("token", &self.token)
            .finish()
    }
}

/// The file's JSON shape.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    version: u32,
    url: String,
    token: String,
}

impl ConnectionInfo {
    /// Writes the file atomically (a temporary file in the same directory, then a rename), so a
    /// reader never sees half a token. Creates the directory if needed.
    ///
    /// # Errors
    ///
    /// [`ConnectionFileError::Io`] if the directory or file can't be created or written.
    pub fn write(&self, path: &Path) -> Result<(), ConnectionFileError> {
        let io_err = |source| ConnectionFileError::Io {
            path: path.to_owned(),
            source,
        };
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        platform::create_private_dir(dir).map_err(io_err)?;
        let body = serde_json::to_vec(&FileFormat {
            version: FILE_VERSION,
            url: self.url.clone(),
            token: self.token.expose().to_owned(),
        })
        .map_err(|err| io_err(io::Error::other(err)))?;
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(|err| ConnectionFileError::Random(err.to_string()))?;
        let file_name = path
            .file_name()
            .map_or_else(|| "api.json".into(), |n| n.to_string_lossy().into_owned());
        let tmp = dir.join(format!(".{file_name}.{}.tmp", hex(&suffix)));
        let result = (|| {
            let mut file = platform::create_private_file(&tmp)?;
            file.write_all(&body)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        if let Err(err) = result {
            // Best effort: the temporary file holds the token, so don't leave it behind.
            let _ = fs::remove_file(&tmp);
            return Err(io_err(err));
        }
        Ok(())
    }

    /// Reads a file written by [`ConnectionInfo::write`].
    ///
    /// # Errors
    ///
    /// [`ConnectionFileError::Io`] if it can't be read, [`ConnectionFileError::Permissions`] if
    /// others may read it (Unix), [`ConnectionFileError::Format`] if it isn't a connection file
    /// of this version.
    pub fn read(path: &Path) -> Result<Self, ConnectionFileError> {
        let io_err = |source| ConnectionFileError::Io {
            path: path.to_owned(),
            source,
        };
        let file = fs::File::open(path).map_err(io_err)?;
        let meta = file.metadata().map_err(io_err)?;
        platform::check_private(&meta).map_err(|mode| ConnectionFileError::Permissions {
            path: path.to_owned(),
            mode,
        })?;
        let mut text = String::new();
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(io_err)?;
        let format_err = |reason: String| ConnectionFileError::Format {
            path: path.to_owned(),
            reason,
        };
        if text.len() > usize::try_from(MAX_FILE_BYTES).unwrap_or(usize::MAX) {
            return Err(format_err("file is too large".to_owned()));
        }
        let parsed: FileFormat = serde_json::from_str(&text).map_err(|err| {
            // serde_json's message can quote the input; keep only where it failed.
            format_err(format!(
                "not a connection file (line {}, column {})",
                err.line(),
                err.column()
            ))
        })?;
        if parsed.version != FILE_VERSION {
            return Err(format_err(format!(
                "version {} is not supported (this puddle reads {FILE_VERSION})",
                parsed.version
            )));
        }
        Ok(Self {
            url: parsed.url,
            token: ApiToken::parse(parsed.token).map_err(format_err)?,
        })
    }
}

/// Why the connection file couldn't be written or read. Never contains the token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionFileError {
    /// The OS random source failed.
    #[error("cannot generate a random token: {0}")]
    Random(String),
    /// A file-system call failed.
    #[error("connection file {}: {source}", path.display())]
    Io {
        /// The connection file.
        path: PathBuf,
        /// What failed.
        source: io::Error,
    },
    /// The file may be read by other users.
    #[error(
        "connection file {} is readable by other users (mode {mode:o}); it must be 0600",
        path.display()
    )]
    Permissions {
        /// The connection file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The file isn't a connection file this puddle understands.
    #[error("connection file {}: {reason}", path.display())]
    Format {
        /// The connection file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
}

#[cfg(unix)]
mod platform {
    use std::fs::{self, DirBuilder, File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            return Ok(());
        }
        DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }

    pub(super) fn create_private_file(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    pub(super) fn check_private(meta: &fs::Metadata) -> Result<(), u32> {
        let mode = meta.permissions().mode() & 0o777;
        let group_or_other = mode & 0o077;
        if group_or_other == 0 {
            Ok(())
        } else {
            Err(mode)
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::Path;

    pub(super) fn create_private_dir(dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)
    }

    pub(super) fn create_private_file(path: &Path) -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(path)
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "same signature as the Unix check; the ACL comes from the directory (see ConnectionInfo)"
    )]
    pub(super) fn check_private(_meta: &fs::Metadata) -> Result<(), u32> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex_and_redacted() {
        let a = ApiToken::generate().unwrap();
        let b = ApiToken::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
        assert_eq!(a.expose().len(), 64);
        assert!(ApiToken::parse(a.expose().to_owned()).is_ok());
        assert_eq!(format!("{a:?}"), "ApiToken(<redacted>)");
        let info = ConnectionInfo {
            url: "http://127.0.0.1:1".into(),
            token: a.clone(),
        };
        assert!(!format!("{info:?}").contains(a.expose()));
    }

    #[test]
    fn matches_only_the_exact_token() {
        let t = ApiToken::generate().unwrap();
        assert!(t.matches(t.expose().as_bytes()));
        assert!(!t.matches(t.expose().to_uppercase().as_bytes()));
        assert!(!t.matches(&t.expose().as_bytes()[..63]));
        assert!(!t.matches(b""));
        let mut longer = t.expose().to_owned();
        longer.push('0');
        assert!(!t.matches(longer.as_bytes()));
    }

    #[test]
    fn hex_encodes_every_nibble() {
        assert_eq!(hex(&[0x00, 0x9f, 0xff, 0x10]), "009fff10");
    }

    #[test]
    fn parse_rejects_malformed_tokens() {
        for bad in ["", "abc", &"g".repeat(64), &"A".repeat(64), &"a".repeat(65)] {
            assert!(ApiToken::parse(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn write_then_read_round_trips_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("api.json");
        let first = ConnectionInfo {
            url: "http://127.0.0.1:1".into(),
            token: ApiToken::generate().unwrap(),
        };
        first.write(&path).unwrap();
        let second = ConnectionInfo {
            url: "http://127.0.0.1:2".into(),
            token: ApiToken::generate().unwrap(),
        };
        second.write(&path).unwrap();
        let back = ConnectionInfo::read(&path).unwrap();
        assert_eq!(back.url, second.url);
        assert_eq!(back.token.expose(), second.token.expose());
        // Only the file itself is left: no temporary files.
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["api.json"]);
    }

    #[cfg(unix)]
    #[test]
    fn file_and_new_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new").join("api.json");
        ConnectionInfo {
            url: "http://127.0.0.1:1".into(),
            token: ApiToken::generate().unwrap(),
        }
        .write(&path)
        .unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.json");
        let token = ApiToken::generate().unwrap();
        ConnectionInfo {
            url: "http://127.0.0.1:1".into(),
            token: token.clone(),
        }
        .write(&path)
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = ConnectionInfo::read(&path).unwrap_err();
        assert!(
            matches!(err, ConnectionFileError::Permissions { mode: 0o644, .. }),
            "{err}"
        );
        assert!(!err.to_string().contains(token.expose()));
    }

    #[test]
    fn malformed_files_are_refused_without_quoting_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.json");
        let secretish = "x".repeat(64);
        for (body, want) in [
            (
                format!("{{\"token\":\"{secretish}\""),
                "not a connection file",
            ),
            (
                format!(r#"{{"version":2,"url":"u","token":"{}"}}"#, "a".repeat(64)),
                "version 2 is not supported",
            ),
            (
                format!(r#"{{"version":1,"url":"u","token":"{secretish}"}}"#),
                "64 lower-case hex",
            ),
            (" ".repeat(5000), "too large"),
        ] {
            fs::write(&path, &body).unwrap();
            set_private(&path);
            let err = ConnectionInfo::read(&path).unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
            assert!(!err.contains(&secretish), "{err}");
        }
        let missing = ConnectionInfo::read(&dir.path().join("nope.json")).unwrap_err();
        assert!(matches!(missing, ConnectionFileError::Io { .. }));
    }

    #[test]
    fn write_into_an_unwritable_place_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        fs::write(&blocker, b"").unwrap();
        let info = ConnectionInfo {
            url: "http://127.0.0.1:1".into(),
            token: ApiToken::generate().unwrap(),
        };
        // The "directory" is a file: creating it fails.
        let err = info.write(&blocker.join("api.json")).unwrap_err();
        assert!(matches!(err, ConnectionFileError::Io { .. }), "{err}");
        // The target is a directory: the rename fails and the temporary file is removed.
        let target = dir.path().join("taken");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"").unwrap();
        assert!(info.write(&target).is_err());
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[cfg(unix)]
    fn set_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(windows)]
    fn set_private(_path: &Path) {}
}
