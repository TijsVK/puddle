// SPDX-License-Identifier: GPL-3.0-or-later
//! Captured logins: a login made inside a workspace keeps its real tokens on the host.
//!
//! A tool that logs in inside a workspace (`claude` and `/login`, `gh auth login`,
//! `copilot login`) ends with a call to the service's token endpoint, which answers with the
//! tokens the tool then stores on the workspace's disk, where anything running in the workspace
//! can read them. With capture on, puddle's proxy reads that one answer ([`Logins`] is its
//! [`puddle_proxy::ExchangeRewriter`]): the real tokens go to the operating system's credential
//! store, and the tool is given stand-ins that look like them ([`stand_in_for`]). The proxy swaps
//! a stand-in for the real token in requests to the service's hosts and nowhere else (the
//! registry of [`puddle_proxy::StandIns`], which secrets share), and when the tool refreshes, the
//! stand-in of its refresh token is swapped for the real one in that one field of the request.
//!
//! Which services are captured, where their tokens come back and which hosts take them is data:
//! [`builtin`]. The workspace's capture setting, the credential store and the user's notices are
//! the host's: they are given to [`Logins::new`].

#![forbid(unsafe_code)]

mod logins;
mod profile;
mod shape;
#[cfg(test)]
mod tests;
mod vault;

pub use logins::{ForgetError, Kept, LoginNotices, Logins, Problem};
pub use profile::{CLAUDE, Endpoint, Field, GITHUB, Profile, Role, Scope, builtin};
pub use shape::{ShapeError, stand_in_for};
