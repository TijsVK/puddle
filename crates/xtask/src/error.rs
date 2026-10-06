// SPDX-License-Identifier: GPL-3.0-or-later
//! The one error type of the xtask commands.

use std::path::PathBuf;

/// Why an xtask command failed. Messages name the file, tool or package involved.
#[derive(Debug, thiserror::Error)]
pub enum XtaskError {
    /// Bad command line.
    #[error("{0}\n\n{usage}", usage = crate::USAGE)]
    Usage(String),
    /// A file system operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done, with the path.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// An external tool (cargo, cargo-about, gh, git) failed or couldn't start.
    #[error("`{command}` failed: {detail}")]
    Tool {
        /// The command line, without secrets (none are passed).
        command: String,
        /// Exit status and the end of its stderr, or why it couldn't start.
        detail: String,
    },
    /// Input that should be machine-made didn't parse.
    #[error("cannot parse {what}: {reason}")]
    Parse {
        /// What was parsed (file or tool output).
        what: String,
        /// Why not.
        reason: String,
    },
    /// A downloaded file doesn't match its published checksum.
    #[error("checksum mismatch for {file}: {list} says {expected}, the file is {actual}")]
    Checksum {
        /// The file.
        file: String,
        /// The checksum list it was checked against.
        list: String,
        /// The published SHA-256.
        expected: String,
        /// The file's SHA-256.
        actual: String,
    },
    /// A file has no entry in its release's checksum list.
    #[error("{file} has no entry in {list}")]
    NotListed {
        /// The file.
        file: String,
        /// The checksum list.
        list: String,
    },
    /// The downloaded msb isn't the version the runtime folder is being built for.
    #[error("downloaded msb is version {found}, but the runtime folder is for {expected}")]
    Version {
        /// The version expected (the fork tag without its `v`).
        expected: String,
        /// What the binary embeds (`none` when it has no version section).
        found: String,
    },
    /// Some dependencies have no licence entry in the generated notices.
    #[error("no licence entry in the {tree} notices for: {}", .packages.join(", "))]
    MissingLicence {
        /// Which tree (puddle, msb).
        tree: String,
        /// `name version` of each package without an entry.
        packages: Vec<String>,
    },
    /// A committed generated file differs from what the generator makes now.
    #[error("{} is stale: run `cargo xtask openapi` and commit the result", .0.display())]
    Stale(PathBuf),
    /// The output folder already has content.
    #[error("output folder {0} exists and is not empty; remove it or pick another --out")]
    OutputExists(PathBuf),
}

impl XtaskError {
    /// An [`XtaskError::Io`] with context.
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// An [`XtaskError::Parse`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers hand over the error they got from map_err"
    )]
    pub(crate) fn parse(what: impl Into<String>, reason: impl ToString) -> Self {
        Self::Parse {
            what: what.into(),
            reason: reason.to_string(),
        }
    }
}

/// The xtask result type.
pub type Result<T> = std::result::Result<T, XtaskError>;
