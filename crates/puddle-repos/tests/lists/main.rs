// SPDX-License-Identifier: GPL-3.0-or-later
//! The lists and profiles of `puddle-repos` over scripted host answers shaped like the ones
//! GitHub and Azure DevOps document (`tests/data`), and the route to a host over a local TLS
//! server and a fake company proxy.
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] fns run only in tests; a panic is how a test fails"
)]

mod azure;
mod cache;
mod common;
mod github;
mod profile;
mod route;
