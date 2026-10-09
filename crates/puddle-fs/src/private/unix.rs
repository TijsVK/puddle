// SPDX-License-Identifier: GPL-3.0-or-later
//! Unix: modes `0700` for folders puddle creates, `0600` for files.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::{CheckError, Exposed};

pub(super) fn create_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

pub(super) fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub(super) fn check(file: &File) -> Result<(), CheckError> {
    let mode = file.metadata()?.permissions().mode() & 0o777;
    // No group or other bit: the low six bits are clear.
    if mode.trailing_zeros() >= 6 {
        Ok(())
    } else {
        Err(CheckError::Exposed(Exposed::Mode(mode)))
    }
}

pub(super) fn tighten_dir(dir: &Path) -> io::Result<Option<Exposed>> {
    let meta = fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a folder"));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode.trailing_zeros() >= 6 {
        return Ok(None);
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let now = fs::metadata(dir)?.permissions().mode() & 0o777;
    if now & 0o077 != 0 {
        return Err(io::Error::other(format!("the mode is still {now:o}")));
    }
    Ok(Some(Exposed::Mode(mode)))
}

pub(super) fn tighten_file(path: &Path) -> io::Result<Option<Exposed>> {
    // A missing file is `NotFound` here and at every later step; the caller reads it as "nothing
    // to tighten".
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let file = File::open(path)?;
    match check(&file) {
        Ok(()) => Ok(None),
        Err(CheckError::Io(err)) => Err(err),
        Err(CheckError::Exposed(was)) => {
            // Through the open handle, so a swap of the path after the check changes nothing.
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            check(&file).map_err(io::Error::other)?;
            Ok(Some(was))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn new_folders_and_files_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("new").join("deeper");
        create_dir(&sub).unwrap();
        assert_eq!(mode(&sub), 0o700);
        let file = sub.join("f");
        drop(create_file(&file).unwrap());
        assert_eq!(mode(&file), 0o600);
    }

    #[test]
    fn an_existing_folder_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        create_dir(dir.path()).unwrap();
        assert_eq!(mode(dir.path()), 0o755);
    }

    #[test]
    fn check_refuses_group_and_other_bits() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, b"x").unwrap();
        for (bits, ok) in [(0o600, true), (0o400, true), (0o640, false), (0o604, false)] {
            fs::set_permissions(&file, fs::Permissions::from_mode(bits)).unwrap();
            let got = check(&File::open(&file).unwrap());
            assert_eq!(got.is_ok(), ok, "{bits:o}");
            if !ok {
                assert!(
                    matches!(got, Err(CheckError::Exposed(Exposed::Mode(m))) if m == bits),
                    "{got:?}"
                );
            }
        }
    }

    #[test]
    fn a_too_open_folder_is_tightened_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(tighten_dir(dir.path()).unwrap(), Some(Exposed::Mode(0o755)));
        assert_eq!(mode(dir.path()), 0o700);
        assert_eq!(tighten_dir(dir.path()).unwrap(), None);
    }

    #[test]
    fn a_too_open_file_is_tightened_and_a_symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("puddle.db");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(tighten_file(&file).unwrap(), Some(Exposed::Mode(0o664)));
        assert_eq!(mode(&file), 0o600);
        assert_eq!(fs::read(&file).unwrap(), b"x");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(
            tighten_file(&link).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_folder_that_cannot_be_read_is_an_error_not_a_silent_pass() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            tighten_dir(&dir.path().join("gone")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
