// SPDX-License-Identifier: GPL-3.0-or-later
//! One puddle host process per data folder.
//!
//! [`DataLock::acquire`] takes an exclusive advisory lock on a file in the data folder. The
//! operating system releases it when the holder exits for any reason, a crash or a kill
//! included, so a lock file left behind never blocks the next start (`flock` on Unix,
//! `LockFileEx` on Windows, both through [`File::try_lock`] in the standard library).
//!
//! The lock file stays empty because Windows locks are mandatory: a second process cannot read
//! a locked file. Who holds the lock is written to a second file, the holder note, which is
//! only a hint for the refusal message: it is written after the lock is taken and read only
//! when the lock is refused. In the instant between a new holder taking the lock and writing
//! its note, a refused process names the previous holder's process or none.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use crate::private;

/// The lock file's name in the data folder.
const LOCK_FILE: &str = "host.lock";
/// The holder note's name in the data folder.
const HOLDER_FILE: &str = "host.holder";

/// Why the data folder could not be locked.
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// Another process holds the lock.
    #[error("{}", held_message(.dir, *.holder))]
    Held {
        /// The data folder.
        dir: PathBuf,
        /// The holder's process ID, when its note could be read.
        holder: Option<u32>,
    },
    /// The folder or the lock file could not be opened.
    #[error("cannot lock {path}: {source}")]
    Io {
        /// The file or folder.
        path: PathBuf,
        /// What went wrong.
        source: io::Error,
    },
}

fn held_message(dir: &Path, holder: Option<u32>) -> String {
    let who = holder.map_or_else(
        || "another puddle process".to_owned(),
        |pid| format!("another puddle process (process ID {pid})"),
    );
    format!(
        "{who} is already using the data folder {}; quit it first (a second one would stop \
         the first one's sandboxes)",
        dir.display()
    )
}

/// The exclusive hold on a data folder; released when dropped or when the process ends.
#[derive(Debug)]
pub struct DataLock {
    // Held for its lock: closing the file releases it.
    _file: File,
}

impl DataLock {
    /// Locks the data folder `dir` (created owner-only if missing) for this process.
    ///
    /// # Errors
    ///
    /// [`LockError::Held`] when another process holds it, [`LockError::Io`] when the folder or
    /// the lock file cannot be opened.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        let io_err = |path: &Path| {
            let path = path.to_path_buf();
            move |source| LockError::Io { path, source }
        };
        private::create_dir(dir).map_err(io_err(dir))?;
        let lock_path = dir.join(LOCK_FILE);
        let file = open_lock_file(&lock_path).map_err(io_err(&lock_path))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LockError::Held {
                    dir: dir.to_path_buf(),
                    holder: read_holder(&dir.join(HOLDER_FILE)),
                });
            }
            Err(TryLockError::Error(source)) => {
                return Err(LockError::Io {
                    path: lock_path,
                    source,
                });
            }
        }
        // Only a hint for the next refusal, so a failure to write it never fails the start.
        let note = format!("{}\n", std::process::id());
        let _ = private::write_atomic(&dir.join(HOLDER_FILE), note.as_bytes());
        Ok(Self { _file: file })
    }
}

/// Opens the lock file, creating it owner-only the first time.
fn open_lock_file(path: &Path) -> io::Result<File> {
    match private::create_file(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            OpenOptions::new().read(true).write(true).open(path)
        }
        Err(e) => Err(e),
    }
}

fn read_holder(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_lock_on_the_same_folder_is_refused_until_the_first_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = DataLock::acquire(dir.path()).unwrap();
        let err = DataLock::acquire(dir.path()).unwrap_err();
        // Same process here, so the note names this one.
        assert!(
            matches!(&err, LockError::Held { holder, .. } if *holder == Some(std::process::id())),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains(&format!("process ID {}", std::process::id())),
            "{err}"
        );
        drop(first);
        drop(DataLock::acquire(dir.path()).unwrap());
    }

    #[test]
    fn different_folders_do_not_block_each_other() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let _a = DataLock::acquire(a.path()).unwrap();
        let _b = DataLock::acquire(b.path()).unwrap();
    }

    #[test]
    fn a_missing_folder_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("new").join("puddle");
        let _lock = DataLock::acquire(&data).unwrap();
        assert!(data.join(LOCK_FILE).is_file());
    }

    #[test]
    fn a_leftover_lock_file_and_note_do_not_block_and_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCK_FILE), b"").unwrap();
        std::fs::write(dir.path().join(HOLDER_FILE), b"4000000\n").unwrap();
        let _lock = DataLock::acquire(dir.path()).unwrap();
        assert_eq!(
            read_holder(&dir.path().join(HOLDER_FILE)),
            Some(std::process::id())
        );
    }

    #[test]
    fn a_refusal_without_a_readable_note_names_no_process() {
        let dir = tempfile::tempdir().unwrap();
        let _first = DataLock::acquire(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join(HOLDER_FILE)).unwrap();
        let err = DataLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::Held { holder: None, .. }), "{err}");
        assert!(
            err.to_string().contains("another puddle process is"),
            "{err}"
        );
    }

    #[test]
    fn a_data_folder_that_is_a_file_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        let err = DataLock::acquire(&file).unwrap_err();
        assert!(matches!(err, LockError::Io { .. }), "{err}");
        assert!(err.to_string().contains("cannot lock"), "{err}");
    }

    #[test]
    fn a_lock_path_that_cannot_be_opened_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        // A folder where the lock file should be: it exists, and opening it for writing fails.
        std::fs::create_dir(dir.path().join(LOCK_FILE)).unwrap();
        let err = DataLock::acquire(dir.path()).unwrap_err();
        assert!(matches!(err, LockError::Io { .. }), "{err}");
    }
}
