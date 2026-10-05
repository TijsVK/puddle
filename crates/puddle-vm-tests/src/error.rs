// SPDX-License-Identifier: GPL-3.0-or-later
//! Errors the harness reports before or around a VM test.

use std::path::PathBuf;
use std::time::Duration;

/// Why the harness couldn't set up, run or clean up a VM test.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// A required environment variable is missing.
    #[error("{var} is not set: {hint}")]
    MissingVar {
        /// The variable.
        var: &'static str,
        /// What to set it to.
        hint: &'static str,
    },
    /// An msb variable is set in the environment and would override the harness's runtime pair.
    #[error(
        "{var} is set in the environment; unset it so the VM tests use their own runtime and home"
    )]
    AmbientMsbVar {
        /// The variable.
        var: &'static str,
    },
    /// The run prefix isn't usable as the start of a sandbox name.
    #[error(
        "invalid run prefix {value:?}: use 1-{max} lowercase letters, digits or '-', starting with a letter"
    )]
    InvalidPrefix {
        /// The rejected value, cut to 64 characters.
        value: String,
        /// The length limit.
        max: usize,
    },
    /// A prefixed sandbox name isn't a valid puddle sandbox name.
    #[error("invalid sandbox name for tag {tag:?}: {reason}")]
    InvalidName {
        /// The tag the test asked for, cut to 64 characters.
        tag: String,
        /// Why the name was rejected.
        reason: String,
    },
    /// The runtime directory lacks `msb` or `libkrunfw`.
    #[error("runtime directory {dir} has no {missing}")]
    RuntimeIncomplete {
        /// The directory searched.
        dir: PathBuf,
        /// The file that wasn't found.
        missing: &'static str,
    },
    /// The harness runs on an OS msb doesn't support.
    #[error("msb has no runtime for this OS ({os})")]
    UnsupportedOs {
        /// `std::env::consts::OS`.
        os: &'static str,
    },
    /// A filesystem step failed.
    #[error("{action} {path}: {source}")]
    Io {
        /// What the harness was doing.
        action: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// An SDK call failed.
    #[error("msb SDK: {0}")]
    Sdk(#[from] microsandbox::MicrosandboxError),
    /// A step took longer than its budget.
    #[error("{what} took longer than {limit:?}")]
    Timeout {
        /// The step.
        what: &'static str,
        /// Its budget.
        limit: Duration,
    },
}

impl HarnessError {
    pub(crate) fn io(
        action: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            action,
            path: path.into(),
            source,
        }
    }
}

/// Cuts a rejected value for an error message, so a hostile or huge value can't flood a log.
pub(crate) fn clip(value: &str) -> String {
    value.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_values_and_cuts_long_ones() {
        assert_eq!(clip("abc"), "abc");
        assert_eq!(clip(&"x".repeat(100)).len(), 64);
    }

    #[test]
    fn messages_name_what_to_fix() {
        let missing = HarnessError::MissingVar {
            var: "PUDDLE_VM_RUNTIME_DIR",
            hint: "a directory with msb and libkrunfw",
        };
        assert_eq!(
            missing.to_string(),
            "PUDDLE_VM_RUNTIME_DIR is not set: a directory with msb and libkrunfw"
        );
        let ambient = HarnessError::AmbientMsbVar { var: "MSB_HOME" };
        assert!(ambient.to_string().starts_with("MSB_HOME is set"));
        let timeout = HarnessError::Timeout {
            what: "create",
            limit: Duration::from_secs(3),
        };
        assert_eq!(timeout.to_string(), "create took longer than 3s");
        let io = HarnessError::io("create", "/x", std::io::Error::other("boom"));
        assert_eq!(io.to_string(), "create /x: boom");
    }
}
