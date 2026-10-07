// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's per-user data folder.

use std::path::{Path, PathBuf};

/// The folder's name inside the OS's per-user data location.
const APP_DIR_NAME: &str = "puddle";

/// Why there is no data folder.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataDirError {
    /// The OS reports no per-user data location (no home folder).
    #[error(
        "cannot find the per-user data folder: the OS reports no home or local app data folder"
    )]
    NoBase,
    /// The location isn't absolute (a relative `XDG_DATA_HOME` is ignored by `dirs`, so this is a
    /// guard for other platforms): msb would resolve it against whatever the working directory is.
    #[error("the per-user data folder must be absolute: {path}")]
    Relative {
        /// The offending path.
        path: PathBuf,
    },
}

/// puddle's per-user data folder for this OS (see the crate documentation for the table). The
/// folder isn't created.
///
/// # Errors
///
/// [`DataDirError::NoBase`] without a home folder, [`DataDirError::Relative`] if the OS gave a
/// relative path.
pub fn data_dir() -> Result<PathBuf, DataDirError> {
    data_dir_in(dirs::data_local_dir().as_deref())
}

/// [`data_dir`] from an explicit per-user data location (`None` when the OS has none); the
/// testable half.
///
/// # Errors
///
/// As [`data_dir`].
pub fn data_dir_in(base: Option<&Path>) -> Result<PathBuf, DataDirError> {
    let base = base.ok_or(DataDirError::NoBase)?;
    if !base.is_absolute() {
        return Err(DataDirError::Relative {
            path: base.to_path_buf(),
        });
    }
    Ok(base.join(APP_DIR_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folder_is_puddle_inside_the_base() {
        let base = std::env::temp_dir();
        assert_eq!(data_dir_in(Some(&base)).unwrap(), base.join("puddle"));
    }

    #[test]
    fn no_base_and_relative_bases_are_refused() {
        assert_eq!(data_dir_in(None), Err(DataDirError::NoBase));
        assert_eq!(
            data_dir_in(Some(Path::new("data"))),
            Err(DataDirError::Relative {
                path: "data".into()
            })
        );
        assert!(DataDirError::NoBase.to_string().contains("home"));
    }

    #[test]
    fn the_real_folder_is_absolute_and_named_puddle() {
        // CI runners and developer machines all have a home folder.
        let dir = data_dir().unwrap();
        assert!(dir.is_absolute(), "{}", dir.display());
        assert_eq!(dir.file_name().unwrap(), "puddle");
    }

    #[cfg(windows)]
    #[test]
    fn windows_uses_local_app_data() {
        let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set on Windows");
        assert_eq!(data_dir().unwrap(), Path::new(&local).join("puddle"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_uses_xdg_data_home_or_the_home_folder() {
        let want = match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
            Some(xdg) if xdg.is_absolute() => xdg,
            _ => PathBuf::from(std::env::var_os("HOME").expect("HOME is set")).join(".local/share"),
        };
        assert_eq!(data_dir().unwrap(), want.join("puddle"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support() {
        let home = PathBuf::from(std::env::var_os("HOME").expect("HOME is set"));
        assert_eq!(
            data_dir().unwrap(),
            home.join("Library/Application Support/puddle")
        );
    }
}
