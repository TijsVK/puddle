// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's error type.

/// What went wrong creating a CA or issuing a leaf. Messages name hosts, never key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// A builder setting is out of range.
    #[error("invalid CA setting {setting}: {reason}")]
    InvalidSetting {
        /// The setting.
        setting: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The host is not a plain DNS name (an IP address, a wildcard and a port are refused).
    #[error("invalid host {host:?}")]
    InvalidHost {
        /// The rejected host.
        host: String,
    },
    /// The CA certificate has expired; a new CA is needed.
    #[error("the CA certificate has expired")]
    Expired,
    /// Key generation or signing failed.
    #[error("certificate generation failed")]
    Generate(#[source] rcgen::Error),
    /// rustls refused the generated key.
    #[error("loading the leaf key failed")]
    LoadKey(#[source] rustls::Error),
}
