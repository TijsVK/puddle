// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows: files and folders inherit the ACL of their parent. In the user's profile
//! (`%LOCALAPPDATA%`, see [`crate::data_dir`]) that is the user, administrators and `SYSTEM`.
//!
//! T-093 replaces these with an explicit owner-only ACL (the descriptor code is
//! `puddle-ipc/src/windows/security.rs`) and makes [`check`] read it back. Nothing here sets an
//! ACL yet, so behaviour is what `puddle-api` did before this module existed.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

pub(super) fn create_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

pub(super) fn create_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix check; T-093 reads the ACL here"
)]
pub(super) fn check(_meta: &Metadata) -> Result<(), u32> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_are_created_exclusively_and_checks_pass_until_t093() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a").join("b");
        create_dir(&sub).unwrap();
        let file = sub.join("f");
        drop(create_file(&file).unwrap());
        assert!(create_file(&file).is_err());
        assert_eq!(check(&fs::metadata(&file).unwrap()), Ok(()));
    }
}
