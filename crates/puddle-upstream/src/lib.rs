// SPDX-License-Identifier: GPL-3.0-or-later
//! The company proxy in front of puddle (MWE plan W2, T-026 section 2a).
//!
//! Many networks only let a machine out through an HTTP proxy, chosen per URL by a PAC script or
//! WPAD, and some proxies demand Windows sign-in. This crate holds the host side of that:
//!
//! - [`discovery`]: which [`Route`] a request takes, from what an [`OsProxy`] reports (a
//!   neutral [`ProxyConfig`]: PAC or WPAD, static proxies per scheme, a bypass list), cached per
//!   network epoch and invalidated on a debounced OS change notification (T-134). On Windows the
//!   [`OsProxy`] is WinINet and WinHTTP's PAC and WPAD engine, machine-wide WinHTTP and group
//!   policy, with the `HTTP(S)_PROXY` variables behind them; on Unix it is the variables alone
//!   ([`EnvOs`], T-148 L-2). WinINet's field names and syntax stay inside `windows/`.
//! - [`ProxyAuth`]: the seam for authenticating to the proxy (T-135: Windows SSPI Negotiate, later
//!   GSSAPI on Linux). [`NoAuth`] until then. A hop names a proxy by [`ProxyAddr`] (host and
//!   port) only, so an implementation derives the `HTTP/<host>` service name from it and holds
//!   any credentials itself.
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

mod auth;
pub mod discovery;
mod env;
#[cfg(any(test, feature = "testing"))]
mod fake;
mod hop;
mod os;
mod parse;
#[cfg(windows)]
mod windows;

pub use auth::{AuthError, AuthSession, AuthStep, NoAuth, ProxyAuth, system_auth};
pub use discovery::{Config, Decision, Discovery, ManualProxy, Mode, RouteSource, Watching};
pub use env::{EnvFallback, EnvOs};
#[cfg(any(test, feature = "testing"))]
pub use fake::FakeOs;
pub use hop::{Destination, Hop, ParseError, ProxyAddr, Route, Scheme};
pub use os::{
    ChangeCallback, Origin, OsProxy, PacError, PacQuery, ProxyConfig, SettingsError, WatchGuard,
    system_os,
};
pub use parse::{BypassList, PacAnswer, ProxyRules, parse_pac_answer};
#[cfg(windows)]
pub use windows::WinOs;
