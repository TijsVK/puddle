// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's per-workspace certificate authority and its leaf certificate cache.
//!
//! The proxy terminates TLS only for hosts with a credential binding. For those hosts it presents
//! a leaf certificate issued by a CA that belongs to one workspace and lives only in the host
//! process's memory (nothing is shared between workspaces).
//!
//! - [`NameConstraints`] says which names a CA may certify. It is a builder input, so the proxy
//!   CA (the workspace's bound hosts) and a later localhost-only dev CA share
//!   [`CaBuilder`]. The constraints go into the CA certificate as a critical RFC 5280 extension,
//!   so a client rejects a leaf for any other name even if one were ever signed.
//! - [`WorkspaceCa`] holds the CA key. It has no way to export, clone or serialise it; leaves come
//!   out as [`rustls::sign::CertifiedKey`], whose key is a signing object, not bytes.
//! - [`CaCertificate`] is the public half, and [`TrustBundle`] turns a list of them into the
//!   [`GuestFile`](puddle_types::GuestFile)s the boot hook writes into the guest trust store.

#![forbid(unsafe_code)]

mod authority;
mod bundle;
mod constraints;
mod error;

pub use authority::{CaBuilder, WorkspaceCa};
pub use bundle::{CaCertificate, GUEST_BUNDLE_PATH, TrustBundle};
pub use constraints::NameConstraints;
pub use error::CaError;
