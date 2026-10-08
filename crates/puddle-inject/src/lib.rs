// SPDX-License-Identifier: GPL-3.0-or-later
//! puddle's credential injector for Git hosts (`docs/arch/spec/credentials.md` §6 to §8).
//!
//! One [`GitInjector`] serves one workspace. For each request on a host puddle decrypts it reads
//! which repository the path names and what the request asks of it (module `git_path`), applies the
//! workspace's push and pull lists, and, when the request carries no `Authorization` of its own,
//! adds the credential of the identity that covers the repository's owner. It holds no secret:
//! the identities and the table come from [`GitSettings`] (the store, read for each request), the
//! secret from a [`CredentialSource`] (the secrets cache) at the moment it is needed.
//!
//! The transport (TLS, framing, which host a connection is for) is `puddle-proxy`'s; this crate
//! only answers the proxy's [`puddle_proxy::Injector`] questions.

#![forbid(unsafe_code)]

mod git_path;
mod header;
mod injector;
mod source;
#[cfg(feature = "testing")]
pub mod testing;

pub use injector::GitInjector;
pub use source::{CredentialSource, GitSettings, SettingsError, StoreSettings};
