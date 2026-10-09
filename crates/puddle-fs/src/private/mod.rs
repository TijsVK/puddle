// SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-only files and folders: the one place that knows how each OS says "only this user".
//!
//! | OS | Folder | File | [`check`] |
//! |---|---|---|---|
//! | Unix | new folders `0700` | `0600`, created exclusively | refuses a file with any group or other bit |
//! | Windows | new folders get a protected ACL with one entry, full control for the current user, which their children inherit | the same ACL, set when the file is created | refuses any ACL that is missing or has an entry for another account or a non-allow entry |
//!
//! Every caller (the API's connection file today; settings, consent and CA key files later) gets
//! the same behaviour through this one module.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
compile_error!("puddle-fs supports unix and windows hosts");

/// Creates `dir` and its missing parents, owner-only. An existing folder is left as it is.
///
/// # Errors
///
/// Any file-system error.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    platform::create_dir(dir)
}

/// Creates `path` owner-only, failing if it exists (so a file someone else pre-created, or a
/// symlink, is never written through).
///
/// # Errors
///
/// Any file-system error, including `AlreadyExists`.
pub fn create_file(path: &Path) -> io::Result<File> {
    platform::create_file(path)
}

/// How a file is open to others, as [`check`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exposed {
    /// Unix permission bits with a group or other bit set.
    Mode(u32),
    /// A Windows access list that isn't the current user's alone, and why.
    Acl(String),
}

impl fmt::Display for Exposed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode(mode) => write!(f, "mode {mode:o}; it must be 0600"),
            Self::Acl(why) => write!(f, "{why}; it must be accessible to its owner only"),
        }
    }
}

/// Why [`check`] failed.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    /// The file's permissions couldn't be read.
    #[error("can't read the file's permissions: {0}")]
    Io(#[from] io::Error),
    /// Others may read it.
    #[error("readable by other users ({0})")]
    Exposed(Exposed),
}

/// Whether the open file `file` is owner-only.
///
/// # Errors
///
/// [`CheckError::Exposed`] if others may read it, [`CheckError::Io`] if its permissions can't be
/// read.
pub fn check(file: &File) -> Result<(), CheckError> {
    platform::check(file)
}

/// Makes the existing folder `dir` owner-only, creating it (owner-only) if it is missing.
///
/// Returns what was wrong before the fix, or `None` if the folder was already owner-only or has
/// just been created. On Unix it clears the group and other bits; on Windows it replaces the
/// folder's access list with the one-entry protected list, which the folder's existing children
/// inherit. It checks the result and fails if the folder is still exposed, so a caller can
/// refuse to run rather than run with wider permissions.
///
/// # Errors
///
/// Any file-system error (including not owning the folder), or `InvalidInput` if `dir` is not a
/// folder.
pub fn tighten_dir(dir: &Path) -> io::Result<Option<Exposed>> {
    if !dir.exists() {
        create_dir(dir)?;
        return Ok(None);
    }
    platform::tighten_dir(dir)
}

/// Makes the existing file `path` owner-only, like [`tighten_dir`]. A missing file is not an
/// error and returns `None`, and neither is one that disappears while it is being looked at (a
/// database's `-wal` file goes when its last connection closes); a file that isn't a regular
/// file (a symlink, a folder) is refused.
///
/// # Errors
///
/// Any file-system error, or `InvalidInput` if `path` is not a regular file.
pub fn tighten_file(path: &Path) -> io::Result<Option<Exposed>> {
    match platform::tighten_file(path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        other => other,
    }
}

/// Writes `body` to `path` owner-only and atomically: a temporary owner-only file in the same
/// folder, synced, then renamed over `path`, so a reader never sees half of it. Creates the
/// folder if needed. The temporary file is removed on failure.
///
/// # Errors
///
/// Any file-system error, or the OS random source failing (it names the temporary file).
pub fn write_atomic(path: &Path, body: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_dir(dir)?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|err| io::Error::other(err.to_string()))?;
    let file_name = path
        .file_name()
        .map_or_else(|| "private".into(), |n| n.to_string_lossy().into_owned());
    let tmp = dir.join(format!(".{file_name}.{}.tmp", hex(&suffix)));
    let result = (|| {
        let mut file = create_file(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        // Best effort: the temporary file may hold a secret, so don't leave it behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_creates_folders_replaces_and_leaves_no_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("secret.json");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["secret.json"]);
        check(&File::open(&path).unwrap()).unwrap();
    }

    #[test]
    fn write_atomic_cleans_up_when_the_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        // A folder at the target makes the rename fail after the temporary file was written.
        let path = dir.path().join("target");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("keep"), b"x").unwrap();
        assert!(write_atomic(&path, b"secret").is_err());
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["target"]);
    }

    #[test]
    fn create_file_refuses_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        drop(create_file(&path).unwrap());
        assert_eq!(
            create_file(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn create_dir_keeps_an_existing_folder() {
        let dir = tempfile::tempdir().unwrap();
        create_dir(dir.path()).unwrap();
        create_dir(&dir.path().join("a").join("b")).unwrap();
        assert!(dir.path().join("a").join("b").is_dir());
    }

    #[test]
    fn tighten_creates_a_missing_folder_and_skips_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("new");
        assert_eq!(tighten_dir(&sub).unwrap(), None);
        assert!(sub.is_dir());
        assert_eq!(tighten_file(&sub.join("absent")).unwrap(), None);
    }

    #[test]
    fn a_file_that_goes_away_while_it_is_tightened_is_skipped() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        // SQLite deletes its `-wal` file when its last connection closes, which can happen between
        // the moment the file is seen and the moment it is opened.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("puddle.db-wal");
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    drop(create_file(&path));
                    let _ = fs::remove_file(&path);
                }
            });
            // Stop the churn before judging, so a failure ends the test instead of hanging it.
            // Only `NotFound` is judged: Windows answers "access denied" for a file in the middle of
            // being deleted, which is a different error.
            let deadline = Instant::now() + Duration::from_millis(500);
            let mut first_error = None;
            while first_error.is_none() && Instant::now() < deadline {
                first_error = tighten_file(&path)
                    .err()
                    .filter(|err| err.kind() == io::ErrorKind::NotFound);
            }
            stop.store(true, Ordering::Relaxed);
            assert!(first_error.is_none(), "{first_error:?}");
        });
    }

    #[test]
    fn tighten_leaves_an_owner_only_folder_and_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("own");
        create_dir(&sub).unwrap();
        let file = sub.join("f");
        drop(create_file(&file).unwrap());
        assert_eq!(tighten_dir(&sub).unwrap(), None);
        assert_eq!(tighten_file(&file).unwrap(), None);
    }

    #[test]
    fn tighten_refuses_a_file_where_a_folder_is_expected_and_the_reverse() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            tighten_dir(&file).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            tighten_file(dir.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn hex_is_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x9f, 0xff, 0x10]), "009fff10");
    }
}
