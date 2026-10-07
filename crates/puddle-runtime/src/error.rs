// SPDX-License-Identifier: GPL-3.0-or-later
//! Every way the bundled runtime can be unusable.

use std::path::PathBuf;

/// Why puddle can't use its bundled runtime. Each message names the file and, for version
/// problems, both versions, so `puddle doctor` (T-115) can show it as is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// A path that must be absolute isn't (the SDK would resolve it against the working directory).
    #[error("runtime path must be absolute: {path}")]
    RelativePath {
        /// The offending path.
        path: PathBuf,
    },
    /// The executable puddle was started as has no parent directory.
    #[error("cannot find the folder of the puddle executable {path}")]
    NoExeDir {
        /// The executable path.
        path: PathBuf,
    },
    /// The OS has no per-user data folder to put puddle's msb home in.
    #[error("cannot place puddle's msb home: {reason}")]
    NoDataDir {
        /// Why ([`puddle_fs::DataDirError`]).
        reason: String,
    },
    /// The `msb` binary isn't where the install put it.
    #[error("bundled runtime is missing: {path} does not exist; reinstall puddle")]
    Missing {
        /// Where the binary should be.
        path: PathBuf,
    },
    /// The binary exists but its version can't be read (not an executable, unreadable, malformed
    /// version section).
    #[error("cannot read the version of the bundled runtime {path}: {reason}")]
    Unreadable {
        /// The binary.
        path: PathBuf,
        /// What went wrong.
        reason: String,
    },
    /// The binary has no embedded version at all (a pre-0.7.6 msb, or not msb).
    #[error("bundled runtime {path} has no embedded version; this puddle needs msb {expected}")]
    NoVersion {
        /// The binary.
        path: PathBuf,
        /// What this build needs.
        expected: String,
    },
    /// The binary is another version than the one this build was made for.
    #[error("bundled runtime {path} is msb {found}, but this puddle needs exactly msb {expected}")]
    Mismatch {
        /// The binary.
        path: PathBuf,
        /// What this build needs ([`crate::BUILT_FOR`]).
        expected: String,
        /// What the binary says, made printable and cut to 64 characters.
        found: String,
    },
}
