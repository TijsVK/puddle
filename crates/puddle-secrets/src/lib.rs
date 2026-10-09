// SPDX-License-Identifier: GPL-3.0-or-later
//! Where puddle gets a secret on the host.
//!
//! Three sources behind one interface, [`Fetch`]:
//!
//! - **`gh`**: the token of a named, signed-in GitHub CLI account.
//! - **Git credential**: one HTTPS URL with its path, asked of Git Credential Manager (or whatever
//!   credential helper Git is set up with) through `git credential fill`.
//! - **Stored**: a token the user pasted, kept in the OS credential store under puddle's own name.
//!
//! The list is closed ([`SourceSpec`]): no variant carries a command line, and every name that
//! reaches a child process is validated first. No source ever opens a sign-in window: tools run
//! with every prompt off and a time limit, and a source that needs a login answers
//! [`SourceError::NotSignedIn`], which the caller turns into a clear refusal and a "Sign in"
//! notice. [`SecretCache`] keeps values in memory with an expiry; [`discover`] lists the signed-in
//! accounts (names only) from a fixed list of commands.
//!
//! A [`Credential`] is a value an identity owns: a source says nothing about how many credentials a
//! workspace has. The same [`Fetch`] call serves the proxy's injection and host-side API calls.
//! Signing in is the user's click and nothing else ([`SignIns`]): `gh auth login --web`, or Git Credential
//! Manager allowed to open its own window. Another source (the Azure CLI) is one more [`SourceSpec`] variant and one more arm in
//! [`Sources`].

#![forbid(unsafe_code)]

mod cache;
mod chunked;
mod discovery;
mod error;
mod keyring_store;
mod name;
mod run;
mod secret;
mod signin;
mod sources;
mod spec;
mod store;

pub use cache::{SecretCache, SignInNeeded, Ttl, Ttls};
pub use chunked::{CHUNK_UNITS, ChunkedStore};
pub use discovery::{DiscoveredAccount, Discovery, Listing, discover};
pub use error::{Refusal, SourceError, Tool};
pub use keyring_store::{KeyringStore, keyring_available};
pub use name::{AccountName, HostName, NameError, OrgName, StoredId, UrlPath};
pub use run::ToolPaths;
pub use secret::Secret;
pub use signin::{SignInError, SignInStart, SignIns};
pub use sources::{Credential, Fetch, Fetched, Sources, pasted_token};
pub use spec::{SourceSpec, TokenScope};
pub use store::{MemoryStore, SecretStore, StoreError};
