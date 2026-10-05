// SPDX-License-Identifier: GPL-3.0-or-later
//! Unix: sockets mode `0600` inside a fresh directory mode `0700`.
//!
//! The directory is the real barrier: it is created by puddle under a random name (`mkdir` fails
//! on an existing path and never follows a symlink in the last component), so no other user can
//! reach, replace or pre-create anything in it. The socket's own mode is defence in depth.

use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::IpcError;
use crate::name::random_name;

/// The longest socket path Linux and macOS accept (`sun_path` minus the trailing NUL).
#[cfg(target_os = "linux")]
pub(crate) const MAX_SOCKET_PATH: usize = 107;
#[cfg(not(target_os = "linux"))]
pub(crate) const MAX_SOCKET_PATH: usize = 103;

const DIR_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;

pub(crate) type Stream = UnixStream;

#[derive(Debug, Clone)]
pub(crate) struct Root {
    dir: Arc<RootDir>,
}

/// Owns the directory; removes it (if empty) when the last root clone and listener are gone.
#[derive(Debug)]
struct RootDir {
    path: PathBuf,
}

impl Drop for RootDir {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_dir(&self.path) {
            tracing::debug!(dir = %self.path.display(), %err, "ipc root not removed");
        }
    }
}

impl Root {
    pub(crate) fn new() -> Result<Self, IpcError> {
        Self::new_in(&default_parent())
    }

    pub(crate) fn new_in(parent: &Path) -> Result<Self, IpcError> {
        let path = parent.join(format!("puddle-{}", random_name::<8>()?));
        let root_err = |source| IpcError::Root {
            path: path.clone(),
            source,
        };
        DirBuilder::new()
            .mode(DIR_MODE)
            .create(&path)
            .map_err(root_err)?;
        // From here on the directory is ours; dropping `dir` removes it on any later error.
        let dir = RootDir { path: path.clone() };
        // The umask can only remove bits from 0700; set it exactly anyway, then check.
        fs::set_permissions(&path, Permissions::from_mode(DIR_MODE)).map_err(root_err)?;
        check_mode(&path, DIR_MODE, true).map_err(root_err)?;
        Ok(Self { dir: Arc::new(dir) })
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir.path
    }

    pub(crate) fn endpoint_path(&self) -> Result<PathBuf, IpcError> {
        Ok(self.dir.path.join(format!("{}.sock", random_name::<8>()?)))
    }

    pub(crate) fn bind(&self, path: &Path) -> Result<Listener, IpcError> {
        if path.parent() != Some(self.dir.path.as_path()) {
            return Err(IpcError::ForeignEndpoint {
                endpoint: path.to_path_buf(),
                root: self.dir.path.clone(),
            });
        }
        check_length(path)?;
        let io_err = |op, source| IpcError::Io {
            op,
            endpoint: path.to_path_buf(),
            source,
        };
        let std_listener = std::os::unix::net::UnixListener::bind(path).map_err(|source| {
            if source.kind() == io::ErrorKind::AddrInUse {
                IpcError::NameTaken {
                    endpoint: path.to_path_buf(),
                }
            } else {
                io_err("bind", source)
            }
        })?;
        // From here on the socket file is ours; dropping `file` removes it on any later error.
        let file = SocketFile {
            path: path.to_path_buf(),
            _root: Arc::clone(&self.dir),
        };
        fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE))
            .map_err(|source| io_err("set the mode of", source))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|source| io_err("configure", source))?;
        let listener =
            UnixListener::from_std(std_listener).map_err(|source| io_err("register", source))?;
        Ok(Listener {
            listener,
            _file: file,
        })
    }
}

/// Where [`Root::new`] puts its directory: `$XDG_RUNTIME_DIR` (per-user, `0700`, tmpfs) when set
/// to an absolute path, else the temp directory.
fn default_parent() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(std::env::temp_dir)
}

fn check_length(path: &Path) -> Result<(), IpcError> {
    let len = path.as_os_str().len();
    if len > MAX_SOCKET_PATH {
        return Err(IpcError::PathTooLong {
            path: path.to_path_buf(),
            len,
            max: MAX_SOCKET_PATH,
        });
    }
    Ok(())
}

/// Checks that `path` (not followed if a symlink) has exactly `mode` and is a directory or not.
fn check_mode(path: &Path, mode: u32, want_dir: bool) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    let actual = meta.permissions().mode() & 0o7777;
    if meta.is_dir() != want_dir || actual != mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "expected mode {mode:o}, found {actual:o} (dir: {})",
                meta.is_dir()
            ),
        ));
    }
    Ok(())
}

/// Removes the socket file when the listener goes.
#[derive(Debug)]
struct SocketFile {
    path: PathBuf,
    /// Keeps the directory alive while the socket is in it.
    _root: Arc<RootDir>,
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path) {
            tracing::debug!(endpoint = %self.path.display(), %err, "socket file not removed");
        }
    }
}

#[derive(Debug)]
pub(crate) struct Listener {
    listener: UnixListener,
    // Declared after `listener`, so the socket closes before its file is removed.
    _file: SocketFile,
}

impl Listener {
    pub(crate) async fn accept(&mut self, endpoint: &Path) -> Result<Stream, IpcError> {
        self.listener
            .accept()
            .await
            .map(|(stream, _addr)| stream)
            .map_err(|source| IpcError::Io {
                op: "accept on",
                endpoint: endpoint.to_path_buf(),
                source,
            })
    }
}

pub(crate) async fn connect(path: &Path) -> Result<Stream, IpcError> {
    UnixStream::connect(path)
        .await
        .map_err(|source| crate::client_error(path, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_paths_are_refused_before_bind() {
        let long = PathBuf::from(format!("/{}", "a".repeat(MAX_SOCKET_PATH)));
        let err = check_length(&long).unwrap_err();
        assert!(matches!(err, IpcError::PathTooLong { len, .. } if len == MAX_SOCKET_PATH + 1));
        let ok = PathBuf::from(format!("/{}", "a".repeat(MAX_SOCKET_PATH - 1)));
        check_length(&ok).unwrap();
    }

    #[test]
    fn default_parent_is_an_existing_absolute_dir() {
        let p = default_parent();
        assert!(p.is_absolute() && p.is_dir(), "{}", p.display());
    }

    #[test]
    fn check_mode_rejects_wrong_mode_and_wrong_kind() {
        let root = Root::new_in(&std::env::temp_dir()).unwrap();
        check_mode(root.dir(), DIR_MODE, true).unwrap();
        assert!(check_mode(root.dir(), 0o755, true).is_err());
        assert!(check_mode(root.dir(), DIR_MODE, false).is_err());
    }

    #[test]
    fn a_root_in_a_missing_parent_fails_with_the_path() {
        let parent =
            std::env::temp_dir().join(format!("puddle-missing-{}", random_name::<8>().unwrap()));
        let err = Root::new_in(&parent).unwrap_err();
        match err {
            IpcError::Root { path, source } => {
                assert!(path.starts_with(&parent));
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("unexpected {other}"),
        }
    }
}
