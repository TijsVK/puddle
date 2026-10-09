// SPDX-License-Identifier: GPL-3.0-or-later
//! Which repositories an identity's credentials reach, and who a credential's account is.
//!
//! The host asks the Git host's own API with the token a [`Secrets`] source gives it: GitHub's
//! `GET /user/repos` (paged; a fine-grained token lists only what it was granted) and Azure
//! DevOps' organisation-wide repository list for each organisation a credential names. The
//! request leaves through puddle's own company-proxy route ([`HostApi`]); the token goes to that
//! host and nowhere else, and nothing here reaches a workspace.
//!
//! [`Repos`] keeps the lists in memory, one per credential:
//!
//! - a list is read when a screen asks for it, never on a timer, and counts as current for ten
//!   minutes; a refresh reads again unless the list was read moments ago;
//! - one read per credential at a time, however many screens ask;
//! - a host that limits requests (GitHub's primary and secondary limits, Azure DevOps' `429`) is
//!   left alone until it allows, with the wait doubling on each repeat, and nothing is sent while
//!   it waits;
//! - a list that could not be refreshed is served from the last good read, marked stale with the
//!   reason (and when asking again is allowed); a list that cannot be read by design (a host that
//!   is neither GitHub nor Azure DevOps, an Azure DevOps credential that names no organisation)
//!   says so instead of being empty.
//!
//! The tests of this crate run on scripted answers ([`FakeApi`], feature `testing`) shaped like
//! the hosts' documented ones; the route is tested once against a local TLS server and a fake
//! company proxy.

#![forbid(unsafe_code)]

mod api;
mod azure;
mod engine;
mod exchange;
#[cfg(any(test, feature = "testing"))]
mod fake;
mod github;
mod limits;
pub mod listing;
mod model;
mod transport;

pub use api::{Api, ApiReply, ApiRequest, Authorization, MAX_BODY, TransportError};
pub use engine::{Config, Freshness, ProfileRead, Read, Repos, Secrets};
#[cfg(any(test, feature = "testing"))]
pub use fake::{FakeApi, Seen};
pub use model::{
    ListState, Note, NoteKind, Problem, ProblemKind, Profile, Repository, Role, SourceList,
    Visibility,
};
pub use transport::HostApi;
