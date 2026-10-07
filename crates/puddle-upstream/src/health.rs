// SPDX-License-Identifier: GPL-3.0-or-later
//! What discovery reports about itself for the network-health page. Plain data: the API turns it
//! into JSON, so nothing here can leak more than its fields hold, and no field holds a credential
//! ([`ProxyAddr`] cannot carry one, the PAC address is cleaned, no script text is kept).

use std::time::{Duration, SystemTime};

use crate::discovery::RouteSource;
use crate::hop::{Destination, ProxyAddr, Route};

/// How many routes a report lists at most.
pub const MAX_ROUTE_SAMPLES: usize = 100;

/// Where discovery gets its settings, as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModeKind {
    /// The operating system, then the environment.
    System,
    /// No proxy, by puddle's setting.
    Direct,
    /// A proxy typed into puddle's settings.
    Manual,
}

/// What discovery found out about the proxy setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Detected {
    /// A PAC script address is configured.
    Pac,
    /// Automatic detection (WPAD) is on, with no PAC address.
    Wpad,
    /// A fixed proxy in the system settings, or in puddle's.
    Static,
    /// A fixed proxy from `HTTP(S)_PROXY`.
    Env,
    /// No proxy anywhere.
    Direct,
}

/// A proxy that did not answer and is tried last for a while.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadProxy {
    /// The proxy.
    pub proxy: ProxyAddr,
    /// How long until it is tried in order again (or the network changes).
    pub retry_in: Duration,
}

/// One route discovery decided in this epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSample {
    /// Where it was going.
    pub destination: Destination,
    /// The hops, in order.
    pub route: Route,
    /// Which rule produced it.
    pub source: RouteSource,
}

/// A snapshot of proxy discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHealth {
    /// Where the setting comes from.
    pub mode: ModeKind,
    /// What discovery found.
    pub detected: Detected,
    /// Automatic detection (WPAD) is on.
    pub auto_detect: bool,
    /// The PAC script's address without user info, query or fragment. Never the script.
    pub pac_url: Option<String>,
    /// Whether the PAC or WPAD answered in this epoch (`None`: not asked yet, or none in use).
    pub pac_reachable: Option<bool>,
    /// The proxy for plain HTTP, from static settings.
    pub http_proxy: Option<ProxyAddr>,
    /// The proxy for HTTPS, from static settings.
    pub https_proxy: Option<ProxyAddr>,
    /// How many bypass entries the static settings have.
    pub bypass_entries: usize,
    /// Why the system settings could not be read, cleaned.
    pub settings_error: Option<String>,
    /// The network epoch number; it grows whenever the OS reports a change.
    pub epoch: u64,
    /// When the current epoch began, once the network has changed at least once since start.
    pub changed_at: Option<SystemTime>,
    /// Proxies marked unreachable.
    pub dead: Vec<DeadProxy>,
    /// Routes decided so far in this epoch, sorted by host (at most [`MAX_ROUTE_SAMPLES`]).
    pub routes: Vec<RouteSample>,
}
