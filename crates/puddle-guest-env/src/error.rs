// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's error type.

/// Why the proxy config can't be built. Messages name the offending input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A `NO_PROXY` entry is not a host name, a `.suffix` or an IP address.
    #[error("invalid NO_PROXY entry {entry:?}: {reason}")]
    NoProxyEntry {
        /// The rejected entry.
        entry: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A value taken from the image's `ENV` can't be passed on (it contains NUL).
    #[error("the image's {name} can't be passed on: {reason}")]
    ImageEnv {
        /// The variable.
        name: String,
        /// Why.
        reason: String,
    },
    /// A file path built from the settings is not a valid guest path (too long).
    #[error("invalid guest file path: {reason}")]
    GuestPath {
        /// Why.
        reason: String,
    },
}
