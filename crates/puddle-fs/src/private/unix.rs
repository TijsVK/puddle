// SPDX-License-Identifier: GPL-3.0-or-later
//! Unix: modes `0700` for folders puddle creates, `0600` for files.

use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

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

pub(super) fn check(meta: &Metadata) -> Result<(), u32> {
    let mode = meta.permissions().mode() & 0o777;
    // No group or other bit: the low six bits are clear.
    if mode.trailing_zeros() >= 6 {
        Ok(())
    } else {
        Err(mode)
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
            let got = check(&fs::metadata(&file).unwrap());
            assert_eq!(got.is_ok(), ok, "{bits:o}");
            if !ok {
                assert_eq!(got, Err(bits));
            }
        }
    }
}
