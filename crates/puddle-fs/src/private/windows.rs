// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows: an explicit ACL with one entry, full control for the current user's SID, and
//! protected from inheritance, so neither the parent's entries (administrators, `SYSTEM`) nor
//! Everyone come back. It is set when the file or folder is created, so there is no window with
//! the inherited ACL. Folders carry inheritable entries, so files created inside by other means
//! are owner-only too.

use std::fs::File;
use std::io;
use std::path::Path;

use super::{CheckError, Exposed};
use crate::win;

pub(super) fn create_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    // Missing ancestors, outermost first, each created with the owner-only ACL.
    let mut missing: Vec<&Path> = dir.ancestors().take_while(|p| !p.is_dir()).collect();
    missing.retain(|p| !p.as_os_str().is_empty());
    for path in missing.into_iter().rev() {
        match win::create_owner_only_dir(path) {
            Ok(()) => {}
            // Someone else created it meanwhile; fine if it is a folder now.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

pub(super) fn create_file(path: &Path) -> io::Result<File> {
    win::create_owner_only_file(path)
}

pub(super) fn check(file: &File) -> Result<(), CheckError> {
    win::dacl_is_owner_only(file)?.map_err(|why| CheckError::Exposed(Exposed::Acl(why)))
}

#[cfg(test)]
mod tests {
    //! The ACL as the OS reports it, and other principals trying to open the file.

    use std::fmt::Write as _;
    use std::fs::{self, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::process::Command;

    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS};

    use super::*;
    use crate::win::testing::{
        assert_access_denied, assert_owner_only_dacl, logon_local_user, open_impersonating,
        open_restricted,
    };
    use crate::win::wide_nul;

    #[test]
    fn a_new_file_has_one_protected_ace_for_the_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        drop(create_file(&path).unwrap());
        let file = File::open(&path).unwrap();
        assert_owner_only_dacl(&file, FILE_ALL_ACCESS);
        check(&file).unwrap();
    }

    #[test]
    fn a_new_folder_has_the_owner_ace_and_so_do_its_missing_parents() {
        let dir = tempfile::tempdir().unwrap();
        let leaf = dir.path().join("a").join("b");
        create_dir(&leaf).unwrap();
        for folder in [dir.path().join("a"), leaf.clone()] {
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(&folder)
                .unwrap();
            assert_owner_only_dacl(&handle, FILE_ALL_ACCESS);
        }
        // An existing folder keeps the ACL it has (the temporary folder inherits from the profile).
        create_dir(dir.path()).unwrap();
        // A file created in an owner-only folder by other means gets the owner-only entry too.
        let inner = leaf.join("plain");
        fs::write(&inner, b"x").unwrap();
        check(&File::open(&inner).unwrap()).unwrap();
    }

    #[test]
    fn check_refuses_a_file_with_an_inherited_acl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        fs::write(&path, b"x").unwrap();
        let err = check(&File::open(&path).unwrap()).unwrap_err();
        assert!(matches!(err, CheckError::Exposed(Exposed::Acl(_))), "{err}");
    }

    #[test]
    fn a_restricted_token_without_the_user_sid_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        drop(create_file(&path).unwrap());
        assert_access_denied(open_restricted(&path, GENERIC_READ | GENERIC_WRITE, false));
        assert_access_denied(open_restricted(&path, GENERIC_READ, false));
    }

    #[test]
    fn the_same_restricted_token_with_the_user_sid_gets_in() {
        // Positive control: the refusal above comes from the ACL, not from the token setup.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        drop(create_file(&path).unwrap());
        open_restricted(&path, GENERIC_READ | GENERIC_WRITE, true).unwrap();
    }

    /// A throwaway local account, deleted on drop.
    struct LocalUser {
        name: String,
        password: String,
    }

    impl LocalUser {
        /// `None` when the runner doesn't let this process create accounts.
        fn create() -> Option<Self> {
            let mut random = [0u8; 6];
            getrandom::fill(&mut random).unwrap();
            let tag = random.iter().fold(String::new(), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            });
            let user = Self {
                name: format!("pdl{tag}"),
                password: format!("Pd!{tag}aZ9"),
            };
            let made = Command::new("net")
                .args(["user", &user.name, &user.password, "/add"])
                .output()
                .ok()?;
            made.status.success().then_some(user)
        }
    }

    impl Drop for LocalUser {
        fn drop(&mut self) {
            let _ = Command::new("net")
                .args(["user", &self.name, "/delete"])
                .output();
        }
    }

    #[test]
    fn another_local_user_is_refused_when_the_runner_lets_us_make_one() {
        let Some(user) = LocalUser::create() else {
            eprintln!("skipped: this process can't create local accounts");
            return;
        };
        let Some(token) = logon_local_user(&user.name, &user.password) else {
            eprintln!("skipped: the new account can't log on");
            return;
        };
        // The folder must be one the new account can walk into, or every open fails for that
        // reason alone: the public profile.
        let Some(public) = std::env::var_os("PUBLIC") else {
            eprintln!("skipped: no PUBLIC folder");
            return;
        };
        let dir = tempfile::Builder::new()
            .prefix("puddle-fs-")
            .tempdir_in(public)
            .unwrap();
        let plain = dir.path().join("plain");
        fs::write(&plain, b"x").unwrap();
        let private = dir.path().join("private");
        drop(create_file(&private).unwrap());

        // Control: the account can read an ordinary file there.
        if open_impersonating(&token, &wide_nul(plain.as_os_str()), GENERIC_READ).is_err() {
            eprintln!("skipped: the new account can't read the control file either");
            return;
        }
        assert_access_denied(open_impersonating(
            &token,
            &wide_nul(private.as_os_str()),
            GENERIC_READ,
        ));
        assert_access_denied(open_impersonating(
            &token,
            &wide_nul(private.as_os_str()),
            GENERIC_WRITE,
        ));
    }
}
