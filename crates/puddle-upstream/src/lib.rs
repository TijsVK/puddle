// SPDX-License-Identifier: GPL-3.0-or-later
//! The company proxy in front of puddle (MWE plan W2, T-026 section 2a).
//!
//! Many networks only let a machine out through an HTTP proxy, chosen per URL by a PAC script or
//! WPAD, and some proxies demand Windows sign-in. This crate holds the host side of that:
//!
//! - [`discovery`]: which [`Route`] a request takes, from the Windows proxy settings (WinINet,
//!   WinHTTP's PAC and WPAD engine, machine-wide WinHTTP, group policy) or the `HTTP(S)_PROXY`
//!   variables, cached per network epoch and invalidated on a debounced OS change notification
//!   (T-134).
//! - Authentication to the proxy (SSPI Negotiate) is T-135's `sspi` module in this crate. Its seam
//!   is [`ProxyAddr`]: a hop names a proxy by host and port only, so T-135 derives the
//!   `HTTP/<host>` service name from it and holds any credentials itself.
//!
//! [`Discovery`] never fails: when it cannot learn a route it answers "direct", and says why in
//! [`Decision::source`]. The caller connects hop by hop and calls [`Discovery::report_failure`]
//! for a proxy that did not answer.
//!
//! ```
//! use puddle_upstream::{Destination, Scheme};
//! let dest = Destination::new(Scheme::Https, "github.com", 443);
//! assert_eq!(dest.pac_url(), "https://github.com/");
//! ```
#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod discovery;
mod env;
#[cfg(any(test, feature = "testing"))]
mod fake;
mod hop;
mod os;
mod parse;
#[cfg(windows)]
mod windows;

pub use discovery::{Config, Decision, Discovery, ManualProxy, Mode, RouteSource, Watching};
pub use env::EnvProxy;
#[cfg(any(test, feature = "testing"))]
pub use fake::FakeOs;
pub use hop::{Destination, Hop, ParseError, ProxyAddr, Route, Scheme};
pub use os::{
    ChangeCallback, NoOs, OsProxy, OsSettings, PacError, PacQuery, SettingsError, WatchGuard,
    system_os,
};
pub use parse::{BypassList, PacAnswer, ProxyServer, parse_pac_answer};
#[cfg(windows)]
pub use windows::WinOs;
