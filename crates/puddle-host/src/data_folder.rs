// SPDX-License-Identifier: GPL-3.0-or-later
//! The data folder and the database in it are owner-only, also on an install made before they
//! were: start-up fixes what it can and refuses to run when it can't.

use std::io;
use std::path::{Path, PathBuf};

use puddle_fs::private::{self, Exposed};

use crate::{HostError, HostPaths};

/// Makes the data folder, `puddle.db` and the database's `-wal` and `-shm` files owner-only,
/// creating the folder and the database file owner-only when they are missing. An existing
/// folder or file that others can reach is tightened, and one line is logged naming what was
/// changed.
///
/// # Errors
///
/// [`HostError::State`] when something can't be made owner-only (for example a folder another
/// account owns): puddle does not run with wider permissions.
pub(crate) fn make_owner_only(paths: &HostPaths) -> Result<(), HostError> {
    let mut changed = Vec::new();
    let data = paths.data();
    note(&mut changed, data, private::tighten_dir(data))?;
    // Creating the database file here, owner-only, means SQLite never makes it with the
    // default permissions; its `-wal` and `-shm` files copy the database's.
    let store = paths.store();
    match private::create_file(&store) {
        Ok(file) => drop(file),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            note(&mut changed, &store, private::tighten_file(&store))?;
        }
        Err(err) => return Err(refuse(&store, &err)),
    }
    for suffix in ["-wal", "-shm"] {
        let mut side = store.clone().into_os_string();
        side.push(suffix);
        let side = PathBuf::from(side);
        note(&mut changed, &side, private::tighten_file(&side))?;
    }
    if !changed.is_empty() {
        tracing::warn!(
            changed = %changed.join("; "),
            "made puddle's data folder owner-only (access for other accounts removed)"
        );
    }
    Ok(())
}

fn note(
    changed: &mut Vec<String>,
    path: &Path,
    result: io::Result<Option<Exposed>>,
) -> Result<(), HostError> {
    match result {
        Ok(None) => Ok(()),
        Ok(Some(was)) => {
            changed.push(format!("{} was {}", path.display(), describe(&was)));
            Ok(())
        }
        Err(err) => Err(refuse(path, &err)),
    }
}

fn describe(was: &Exposed) -> String {
    match was {
        Exposed::Mode(mode) => format!("open to other accounts (mode {mode:o})"),
        Exposed::Acl(why) => format!("open to other accounts ({why})"),
    }
}

fn refuse(path: &Path, err: &io::Error) -> HostError {
    HostError::State {
        what: "the data folder",
        reason: format!(
            "{} must be accessible to your account only, and puddle could not make it so: \
             {err}. puddle will not run with wider permissions; fix the folder's permissions \
             (or its owner) and start puddle again",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use puddle_store::{Limits, Store, SystemClock};

    use super::*;

    fn is_owner_only(path: &Path) -> bool {
        private::check(&fs::File::open(path).unwrap()).is_ok()
    }

    #[test]
    fn a_new_install_gets_an_owner_only_folder_and_database_file() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostPaths::new(root.path().join("a").join("puddle"));
        make_owner_only(&paths).unwrap();
        assert!(is_owner_only(&paths.store()));
        assert_eq!(private::tighten_dir(paths.data()).unwrap(), None);
    }

    #[test]
    fn the_database_opens_on_the_pre_made_file_and_its_side_files_stay_private() {
        let root = tempfile::tempdir().unwrap();
        let paths = HostPaths::new(root.path().join("puddle"));
        make_owner_only(&paths).unwrap();
        let store = Store::open(&paths.store(), Arc::new(SystemClock), Limits::default()).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let mut name = paths.store().into_os_string();
            name.push(suffix);
            let name = PathBuf::from(name);
            // SQLite in WAL mode keeps both side files while a connection is open.
            assert!(is_owner_only(&name), "{}", name.display());
        }
        drop(store);
        // A second start on the now-populated folder changes nothing.
        make_owner_only(&paths).unwrap();
    }

    #[test]
    fn an_existing_open_install_is_fixed_and_its_data_is_kept() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("puddle");
        fs::create_dir(&data).unwrap();
        let paths = HostPaths::new(&data);
        for name in ["puddle.db", "puddle.db-wal", "puddle.db-shm"] {
            fs::write(data.join(name), name).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
            for name in ["puddle.db", "puddle.db-wal", "puddle.db-shm"] {
                fs::set_permissions(data.join(name), fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        // On Windows the folder under the temporary location inherits the profile's list.
        assert!(!is_owner_only(&paths.store()));
        make_owner_only(&paths).unwrap();
        for name in ["puddle.db", "puddle.db-wal", "puddle.db-shm"] {
            assert!(is_owner_only(&data.join(name)), "{name}");
            assert_eq!(fs::read_to_string(data.join(name)).unwrap(), name);
        }
        assert_eq!(private::tighten_dir(&data).unwrap(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&data).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn something_that_cannot_be_fixed_stops_the_start_with_a_clear_message() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("puddle");
        fs::create_dir(&data).unwrap();
        // A folder where the database file should be: it can't be tightened as a file.
        fs::create_dir(data.join("puddle.db")).unwrap();
        let err = make_owner_only(&HostPaths::new(&data))
            .unwrap_err()
            .to_string();
        assert!(err.contains("puddle.db"), "{err}");
        assert!(err.contains("will not run with wider permissions"), "{err}");

        // A file where the data folder should be.
        let file = root.path().join("not-a-folder");
        fs::write(&file, b"x").unwrap();
        let err = make_owner_only(&HostPaths::new(&file))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not-a-folder"), "{err}");
    }

    #[test]
    fn the_log_line_describes_both_kinds_of_exposure() {
        assert!(describe(&Exposed::Mode(0o755)).contains("mode 755"));
        assert!(describe(&Exposed::Acl("entry 1".into())).contains("entry 1"));
    }
}
