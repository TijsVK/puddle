// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's per-workspace certificate authority and its leaf certificate cache.
//!
//! The proxy terminates TLS only for the hosts a workspace has a credential, secret or capture
//! profile for (its decrypt set). For those hosts it presents a leaf certificate issued by a CA
//! that belongs to one workspace and lives only in the host process's memory (nothing is shared
//! between workspaces).
//!
//! - [`CaBuilder`] makes the CA. It carries no name constraint: the decrypt set changes while the
//!   workspace runs and the guest only learns the CA at boot, so a constraint would make a new
//!   host wait for a restart. The CA is `CA:TRUE` with a path length of 0 and signs for DNS names
//!   only. The caller decides which hosts are decrypted before it asks for a leaf.
//! - [`WorkspaceCa`] holds the CA key. It has no way to export, clone or serialise it; leaves come
//!   out as [`rustls::sign::CertifiedKey`], whose key is a signing object, not bytes.
//! - [`CaCertificate`] is the public half, and [`TrustBundle`] turns a list of them into the
//!   [`GuestFile`](puddle_types::GuestFile)s the boot hook writes into the guest trust store.

#![forbid(unsafe_code)]

mod authority;
mod bundle;
mod error;
mod name;

pub use authority::{CaBuilder, WorkspaceCa};
pub use bundle::{CaCertificate, GUEST_BUNDLE_PATH, TrustBundle};
pub use error::CaError;
