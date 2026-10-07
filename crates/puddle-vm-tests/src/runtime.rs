// SPDX-License-Identifier: GPL-3.0-or-later
//! The msb runtime pair the VM tests run on, and the ambient settings that must not leak in.

use std::path::{Path, PathBuf};

use puddle_runtime::HostOs;

use crate::error::HarnessError;

/// msb environment variables that would override the harness's explicit runtime pair or home.
pub const AMBIENT_MSB_VARS: [&str; 5] = [
    "MSB_PATH",
    "MSB_LIBKRUNFW_PATH",
    "MSB_AGENTD_PATH",
    "MSB_HOME",
    "MSB_CONFIG_PATH",
];

/// Fails when any of [`AMBIENT_MSB_VARS`] is set according to `lookup`.
///
/// # Errors
///
/// [`HarnessError::AmbientMsbVar`] naming the first variable that is set.
pub fn refuse_ambient_msb_vars(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), HarnessError> {
    match AMBIENT_MSB_VARS
        .into_iter()
        .find(|var| lookup(var).is_some())
    {
        Some(var) => Err(HarnessError::AmbientMsbVar { var }),
        None => Ok(()),
    }
}

/// The `msb` executable and the `libkrunfw` library it was released with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePair {
    /// `msb` (`msb.exe` on Windows).
    pub msb: PathBuf,
    /// `libkrunfw.so*`, `libkrunfw.dll` or `libkrunfw.dylib`.
    pub libkrunfw: PathBuf,
}

impl RuntimePair {
    /// Finds the pair for this OS in `dir` (msb's release archive layout: both files at the top).
    ///
    /// # Errors
    ///
    /// [`HarnessError::RuntimeIncomplete`] when a file is missing, [`HarnessError::Io`] when the
    /// directory can't be read, [`HarnessError::UnsupportedOs`] on an OS msb doesn't ship for.
    pub fn find_in(dir: &Path) -> Result<Self, HarnessError> {
        Self::find_for_os(dir, std::env::consts::OS)
    }

    fn find_for_os(dir: &Path, os: &'static str) -> Result<Self, HarnessError> {
        let Some(host) = HostOs::from_target_os(os) else {
            return Err(HarnessError::UnsupportedOs { os });
        };
        let files = host.runtime_files();
        let (msb_name, library_prefix) = (files.msb, files.libkrunfw_prefix);
        let msb = dir.join(msb_name);
        if !msb.is_file() {
            return Err(HarnessError::RuntimeIncomplete {
                dir: dir.to_owned(),
                missing: msb_name,
            });
        }
        let entries = std::fs::read_dir(dir).map_err(|e| HarnessError::io("read", dir, e))?;
        // Linux ships the versioned file (`libkrunfw.so.5.6.1`); take the shortest match so a
        // plain `libkrunfw.so` symlink wins when both exist.
        let libkrunfw = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(library_prefix))
            })
            .min_by_key(|path| path.as_os_str().len())
            .ok_or_else(|| HarnessError::RuntimeIncomplete {
                dir: dir.to_owned(),
                missing: "libkrunfw",
            })?;
        Ok(Self { msb, libkrunfw })
    }

    /// The msb `config.json` that pins this pair: the SDK reads runtime paths from it.
    #[must_use]
    pub fn config_json(&self) -> String {
        serde_json::json!({
            "version": 1,
            "paths": { "msb": self.msb, "libkrunfw": self.libkrunfw },
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::tests::TempDir;

    /// The file names of `os`'s runtime: msb, and the firmware's prefix.
    fn names(os: HostOs) -> (&'static str, &'static str) {
        let files = os.runtime_files();
        (files.msb, files.libkrunfw_prefix)
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    #[test]
    fn ambient_vars_are_refused_by_name() {
        assert!(refuse_ambient_msb_vars(|_| None).is_ok());
        let err = refuse_ambient_msb_vars(|var| (var == "MSB_HOME").then(String::new)).unwrap_err();
        assert!(matches!(
            err,
            HarnessError::AmbientMsbVar { var: "MSB_HOME" }
        ));
        for var in AMBIENT_MSB_VARS {
            let err = refuse_ambient_msb_vars(|v| (v == var).then(|| "x".to_owned())).unwrap_err();
            assert!(err.to_string().starts_with(var));
        }
    }

    #[test]
    fn finds_the_linux_release_layout() {
        let dir = TempDir::new("rt-linux");
        touch(dir.path(), names(HostOs::Linux).0);
        touch(dir.path(), "libkrunfw.so.5.6.1");
        let pair = RuntimePair::find_for_os(dir.path(), "linux").unwrap();
        assert_eq!(pair.msb, dir.path().join(names(HostOs::Linux).0));
        assert_eq!(pair.libkrunfw, dir.path().join("libkrunfw.so.5.6.1"));
    }

    #[test]
    fn prefers_the_shortest_library_name() {
        let dir = TempDir::new("rt-short");
        touch(dir.path(), names(HostOs::Linux).0);
        touch(dir.path(), "libkrunfw.so.5.6.1");
        touch(dir.path(), names(HostOs::Linux).1);
        let pair = RuntimePair::find_for_os(dir.path(), "linux").unwrap();
        assert_eq!(pair.libkrunfw, dir.path().join(names(HostOs::Linux).1));
    }

    #[test]
    fn finds_the_windows_and_macos_layouts() {
        let dir = TempDir::new("rt-win");
        let (msb, firmware) = names(HostOs::Windows);
        touch(dir.path(), msb);
        touch(dir.path(), firmware);
        let pair = RuntimePair::find_for_os(dir.path(), "windows").unwrap();
        assert_eq!(pair.libkrunfw, dir.path().join(firmware));
        let mac = TempDir::new("rt-mac");
        touch(mac.path(), names(HostOs::MacOs).0);
        touch(mac.path(), &format!("{}dylib", names(HostOs::MacOs).1));
        assert!(RuntimePair::find_for_os(mac.path(), "macos").is_ok());
    }

    #[test]
    fn names_the_missing_half() {
        let dir = TempDir::new("rt-missing");
        let err = RuntimePair::find_for_os(dir.path(), "linux").unwrap_err();
        assert!(matches!(
            err,
            HarnessError::RuntimeIncomplete { missing: "msb", .. }
        ));
        touch(dir.path(), names(HostOs::Linux).0);
        touch(dir.path(), names(HostOs::Windows).1);
        let err = RuntimePair::find_for_os(dir.path(), "linux").unwrap_err();
        assert!(matches!(
            err,
            HarnessError::RuntimeIncomplete {
                missing: "libkrunfw",
                ..
            }
        ));
    }

    #[test]
    fn a_directory_named_like_the_library_does_not_count() {
        let dir = TempDir::new("rt-dir");
        touch(dir.path(), names(HostOs::Linux).0);
        std::fs::create_dir(dir.path().join(names(HostOs::Linux).1)).unwrap();
        assert!(RuntimePair::find_for_os(dir.path(), "linux").is_err());
    }

    #[test]
    fn unsupported_os_is_named() {
        let dir = TempDir::new("rt-os");
        let err = RuntimePair::find_for_os(dir.path(), "freebsd").unwrap_err();
        assert_eq!(err.to_string(), "msb has no runtime for this OS (freebsd)");
    }

    #[test]
    fn the_host_os_is_supported() {
        let dir = TempDir::new("rt-host");
        let err = RuntimePair::find_in(dir.path()).unwrap_err();
        assert!(
            matches!(err, HarnessError::RuntimeIncomplete { .. }),
            "{err}"
        );
    }

    #[test]
    fn config_pins_both_paths_at_version_1() {
        let pair = RuntimePair {
            msb: PathBuf::from("/rt/msb"),
            libkrunfw: PathBuf::from("/rt/libkrunfw.so.5"),
        };
        let value: serde_json::Value = serde_json::from_str(&pair.config_json()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["paths"]["msb"], "/rt/msb");
        assert_eq!(value["paths"]["libkrunfw"], "/rt/libkrunfw.so.5");
    }
}
