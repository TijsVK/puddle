// SPDX-License-Identifier: GPL-3.0-or-later
//! Owner-only files and folders: the one place that knows how each OS says "only this user".
//!
//! | OS | Folder | File | [`check`] |
//! |---|---|---|---|
//! | Unix | new folders `0700` | `0600`, created exclusively | refuses a file with any group or other bit |
//! | Windows | inherits the parent's ACL (the user's profile: user, administrators, `SYSTEM`) | same | accepts (an explicit ACL, and the check with it, belongs in `windows.rs`) |
//!
//! The Windows half is deliberately a stub with the Unix behaviour's shape, so adding the ACL
//! changes one file and every caller (the API's connection file today; settings, consent and CA
//! key files later) gets the ACL.

use std::fs::{self, File, Metadata};
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

/// Whether `meta` (of a file the caller just opened) is owner-only.
///
/// # Errors
///
/// `Err(mode)` with the permission bits (`0` where the OS has none) if others may read it.
pub fn check(meta: &Metadata) -> Result<(), u32> {
    platform::check(meta)
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
        check(&fs::metadata(&path).unwrap()).unwrap();
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
    fn hex_is_two_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x9f, 0xff, 0x10]), "009fff10");
    }
}
