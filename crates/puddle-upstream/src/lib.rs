// SPDX-License-Identifier: GPL-3.0-or-later
//! The company proxy in front of puddle.
//!
//! Many networks only let a machine out through an HTTP proxy, chosen per URL by a PAC script or
//! WPAD, and some proxies demand Windows sign-in. This crate holds the host side of that:
//!
//! - [`discovery`]: which [`Route`] a request takes, from what an [`OsProxy`] reports (a
//!   neutral [`ProxyConfig`]: PAC or WPAD, static proxies per scheme, a bypass list), cached per
//!   network epoch and invalidated on a debounced OS change notification. On Windows the
//!   [`OsProxy`] is WinINet and WinHTTP's PAC and WPAD engine, machine-wide WinHTTP and group
//!   policy, with the `HTTP(S)_PROXY` variables behind them; on Unix it is the variables alone
//!   ([`EnvOs`]). WinINet's field names and syntax stay inside `windows/`.
//! - [`ProxyAuth`]: the seam for authenticating to the proxy. On Windows, [`system_auth`] signs
//!   in with SSPI Negotiate and NTLM as the logged-on user ([`NegotiateAuth`] over SSPI, never a
//!   password prompt); elsewhere it is [`NoAuth`] until a GSSAPI [`TokenSource`] exists. A hop names a proxy by [`ProxyAddr`] (host and
//!   port) only, so an implementation derives the `HTTP/<host>` service name from it and holds
//!   any credentials itself.
//!
//! - [`Chain`]: connects along the route: `DIRECT` only to addresses the caller's guard
//!   passed, `CONNECT` and absolute-form through proxies, fallback to the next hop when one is
//!   unreachable, and the `407` loop on one connection with [`ProxyAuth`] ([`BasicAuth`] from
//!   configured credentials; SSPI is [`NegotiateAuth`]). [`host::connect`] is the same for
//!   puddle's own requests.
//! - [`TlsClient`]: TLS on top of such a connection, verified by the platform's verifier plus
//!   the corporate roots ([`tls_connect`]).
//!
//! [`Discovery`] never fails: when it cannot learn a route it answers "direct", and says why in
//! [`Decision::source`]; a setting it cannot use, or changes it cannot see, are listed in
//! [`ProxyHealth::problems`] and logged, never dropped without a word. The caller connects hop by hop and calls [`Discovery::report_failure`]
//! for a proxy that did not answer.
//!
//! ```
//! use puddle_upstream::{Destination, Scheme};
//! let dest = Destination::new(Scheme::Https, "github.com", 443);
//! assert_eq!(dest.pac_url(), "https://github.com/");
//! ```
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod auth;
mod basic;
mod chain;
pub mod discovery;
mod env;
#[cfg(any(test, feature = "testing"))]
mod fake;
#[cfg(any(test, feature = "testing"))]
mod fake_proxy;
mod health;
mod hop;
pub mod host;
mod negotiate;
mod os;
mod parse;
mod redact;
mod signin;
mod tls;
#[cfg(windows)]
mod windows;
mod wire;

pub use auth::{AuthError, AuthSession, AuthStep, NoAuth, ProxyAuth, system_auth};
pub use basic::{AuthList, BasicAuth, Credentials};
pub use chain::{Chain, ChainConfig, ChainError, Connected, Form, Request, Secret, connect_first};
pub use discovery::{Config, Decision, Discovery, ManualProxy, Mode, RouteSource, Watching};
pub use env::{EnvFallback, EnvOs};
#[cfg(any(test, feature = "testing"))]
pub use fake::FakeOs;
#[cfg(any(test, feature = "testing"))]
pub use fake_proxy::{Behaviour, FakeProxy, Seen};
pub use health::{
    DeadProxy, Detected, MAX_ROUTE_SAMPLES, ModeKind, ProxyHealth, ProxyProblem, ProxyProblemKind,
    RouteSample,
};
pub use hop::{Destination, Hop, ParseError, ProxyAddr, Route, Scheme};
pub use negotiate::{Leg, NegotiateAuth, Package, SecurityContext, TokenSource};
pub use os::{
    ChangeCallback, Origin, OsProxy, PacError, PacQuery, ProblemCallback, ProxyConfig,
    SettingsError, WatchGuard, system_os,
};
pub use parse::{BypassList, PacAnswer, ProxyRules, parse_pac_answer};
pub use redact::{redact_text, redact_url};
pub use signin::{SignIn, SignInOutcome};
pub use tls::{RejectedRoot, TlsClient, TlsConnectError, TlsSetupError, tls_connect};
#[cfg(windows)]
pub use windows::WinOs;
