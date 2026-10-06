// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's error type.

/// What went wrong creating a CA or issuing a leaf. Messages name hosts and constraints, never
/// key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaError {
    /// A name constraint is not a valid DNS name or IP prefix.
    #[error("invalid name constraint {value:?}: {reason}")]
    InvalidConstraint {
        /// The rejected input.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A CA must permit at least one name; an unconstrained CA is never built.
    #[error("a CA needs at least one permitted name")]
    NoPermittedNames,
    /// A builder setting is out of range.
    #[error("invalid CA setting {setting}: {reason}")]
    InvalidSetting {
        /// The setting.
        setting: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The host is not a valid DNS name or IP address.
    #[error("invalid host {host:?}")]
    InvalidHost {
        /// The rejected host.
        host: String,
    },
    /// The host is outside the CA's name constraints.
    #[error("host {host} is outside the CA's name constraints")]
    NotPermitted {
        /// The refused host.
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
