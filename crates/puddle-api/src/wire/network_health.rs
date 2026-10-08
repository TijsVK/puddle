// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire types of the network-health report.
//!
//! Safe to show by construction: proxies are `host:port` (no user info), the PAC address has no
//! user info, query or fragment, the PAC script itself is never included, sign-in results name a
//! scheme word and a short cleaned message but never a token or a header value, and certificate
//! subjects are display names only (no key material).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Where puddle gets its proxy setting from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Follow the operating system, then the `HTTP(S)_PROXY` variables.
    System,
    /// Never use a proxy (puddle's setting).
    Direct,
    /// A proxy typed into puddle's settings.
    Manual,
}

/// What puddle found out about the proxy setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDetected {
    /// A PAC script address is configured.
    Pac,
    /// Automatic detection (WPAD) is on and no PAC address is set.
    Wpad,
    /// A fixed proxy in the system settings (or puddle's manual setting).
    Static,
    /// A fixed proxy from the `HTTP(S)_PROXY` variables.
    Env,
    /// No proxy anywhere.
    Direct,
}

/// Whether the PAC script or WPAD answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PacState {
    /// No PAC address and no automatic detection.
    NotUsed,
    /// Configured, not asked yet since the network last changed.
    NotAsked,
    /// It has answered.
    Answering,
    /// It could not be fetched; puddle uses the other settings and asks again later.
    Unreachable,
}

/// A proxy that did not answer and is tried last for a while.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DeadProxy {
    /// `host:port`.
    pub proxy: String,
    /// Seconds until it is tried in its normal order again, if the network does not change first.
    pub retry_in_secs: u64,
}

/// What kind of trouble a [`ProxyProblem`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProblemKind {
    /// A proxy setting puddle cannot use (a SOCKS proxy, a malformed entry, a list with nothing
    /// usable in it). What it covers goes direct, or through the entries that are fine.
    UnusableSetting,
    /// puddle cannot, or can no longer, see changes of the proxy settings or the network, so its
    /// routes stay as they are until it restarts.
    ChangesNotNoticed,
    /// A kind this version of the API does not know; the detail says what it is.
    Other,
}

/// One thing in the proxy setup that does not work as the user set it up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyProblem {
    /// What kind of trouble.
    pub kind: ProxyProblemKind,
    /// Which setting or part, and why, as a sentence fragment; contains no credential.
    pub detail: String,
}

/// The proxy setup puddle sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyReport {
    /// Where the setting comes from.
    pub mode: ProxyMode,
    /// What was found.
    pub detected: ProxyDetected,
    /// Automatic detection (WPAD) is on.
    pub auto_detect: bool,
    /// The PAC script's address, without user info, query or fragment; `null` when none.
    #[schema(required = true)]
    pub pac_url: Option<String>,
    /// Whether the PAC or WPAD answered.
    pub pac_state: PacState,
    /// The fixed proxy for plain HTTP (`host:port`), or `null`.
    #[schema(required = true)]
    pub http_proxy: Option<String>,
    /// The fixed proxy for HTTPS (`host:port`), or `null`.
    #[schema(required = true)]
    pub https_proxy: Option<String>,
    /// How many destinations the fixed settings exempt (the bypass list's length).
    pub bypass_entries: u32,
    /// Why the system settings, or a part of them, could not be read; `null` when they could.
    #[schema(required = true)]
    pub settings_error: Option<String>,
    /// What in the setup does not work as set, one entry each; empty when all does.
    pub problems: Vec<ProxyProblem>,
    /// The network epoch; it grows each time a network or settings change is noticed.
    pub epoch: u64,
    /// Epoch ms when the last change was noticed; `null` when none since puddle started.
    #[schema(required = true)]
    pub last_change_at: Option<u64>,
    /// Proxies marked unreachable.
    pub dead_proxies: Vec<DeadProxy>,
}

/// How a sign-in to a proxy ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SignInResult {
    /// The proxy asked, and puddle answered.
    SignedIn,
    /// The proxy let the request through without asking.
    NotRequired,
    /// The proxy refused the credentials or the token.
    Failed,
    /// The proxy asks for something puddle cannot give (a scheme it does not speak, or a
    /// password nobody configured).
    Unsupported,
}

/// The latest sign-in attempt to one proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignInAttempt {
    /// `host:port`.
    pub proxy: String,
    /// The scheme sent (`Negotiate`, `NTLM`, `Basic`); `null` when none was.
    #[schema(required = true)]
    pub scheme: Option<String>,
    /// How it ended.
    pub result: SignInResult,
    /// More, in words; `null` when there is nothing to add.
    #[schema(required = true)]
    pub detail: Option<String>,
    /// Epoch ms.
    pub at: u64,
}

/// How puddle signs in to the company proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignInReport {
    /// The schemes puddle can answer a proxy with, lower case (`negotiate`, `ntlm`, `basic`).
    /// Empty: puddle can not sign in to a proxy on this system.
    pub methods: Vec<String>,
    /// The latest attempt per proxy, newest first.
    pub attempts: Vec<SignInAttempt>,
}

/// A certificate kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A trust anchor.
    Root,
    /// An intermediate issued by a synced root.
    Intermediate,
}

/// A certificate copied into workspaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SyncedRoot {
    /// The subject's common name, when it has one. Comes from a certificate: escape it.
    #[schema(required = true)]
    pub subject: Option<String>,
    /// SHA-256 of the certificate, lower-case hex.
    pub fingerprint: String,
    /// Root or intermediate.
    pub kind: RootKind,
    /// Expiry, epoch ms.
    pub not_after: i64,
    /// The stores it was found in (`LocalMachine\Root\.GroupPolicy`).
    pub sources: Vec<String>,
}

/// A certificate in the host's stores that workspaces do not get.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SkippedRoot {
    /// The subject's common name, when readable.
    #[schema(required = true)]
    pub subject: Option<String>,
    /// SHA-256 of the certificate, lower-case hex.
    pub fingerprint: String,
    /// Why, in words.
    pub reason: String,
}

/// The company roots puddle copied into workspaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RootsReport {
    /// Whether the host's certificate stores have been read (false until the first sync, and
    /// on systems where puddle has no store to read).
    pub synced: bool,
    /// Epoch ms of the last read; `null` when none.
    #[schema(required = true)]
    pub synced_at: Option<u64>,
    /// How many trust anchors workspaces get.
    pub roots: u32,
    /// How many intermediates workspaces get.
    pub intermediates: u32,
    /// What workspaces get.
    pub certificates: Vec<SyncedRoot>,
    /// What was left out.
    pub skipped: Vec<SkippedRoot>,
    /// Stores that could not be read, with the system's reason.
    pub unreadable_stores: Vec<String>,
    /// Company certificates puddle's own TLS checks could not use (the checks that guard a
    /// workspace's credentials on the way out): a server that chains to one fails with an unknown
    /// issuer. Workspaces still get them; this is only about what puddle itself verifies.
    pub left_out_of_tls: Vec<SkippedRoot>,
}

/// Image pulls and the pull proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PullProxyReport {
    /// Image pulls go through puddle's pull proxy (where the rules and the guard apply).
    pub active: bool,
    /// The pull proxy reaches the internet through the company proxy setup above.
    pub via_upstream: bool,
}

/// How a route was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    /// The destination is this machine.
    Loopback,
    /// puddle's setting is "no proxy".
    Disabled,
    /// puddle's own proxy setting.
    Manual,
    /// A PAC script or WPAD answered.
    Pac,
    /// A PAC answered with entries puddle cannot use (SOCKS, HTTPS proxy): direct instead.
    PacUnsupported,
    /// The system's fixed proxy.
    System,
    /// `HTTP(S)_PROXY`.
    Env,
    /// A bypass list exempted the destination.
    Bypass,
    /// No proxy configured anywhere.
    NoProxy,
}

/// The route puddle chose for one destination in this network epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteDecision {
    /// `http` or `https`.
    pub scheme: String,
    /// The host, from a guest request: escape it.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The hops in order: `PROXY host:port` or `DIRECT`.
    pub hops: Vec<String>,
    /// How it was chosen.
    pub source: RouteSource,
}

/// `GET /api/network-health`: everything puddle knows about how it reaches the internet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkHealth {
    /// Epoch ms the report was made.
    pub generated_at: u64,
    /// The proxy setup.
    pub proxy: ProxyReport,
    /// Signing in to the proxy.
    pub sign_in: SignInReport,
    /// Company roots copied into workspaces.
    pub roots: RootsReport,
    /// Image pulls.
    pub pull_proxy: PullProxyReport,
    /// Routes chosen so far in this network epoch, sorted by host (at most 100).
    pub routes: Vec<RouteDecision>,
}

impl NetworkHealth {
    /// A healthy machine with no proxy and no company roots: what the fake starts with.
    #[must_use]
    pub fn direct(now_ms: u64) -> Self {
        Self {
            generated_at: now_ms,
            proxy: ProxyReport {
                mode: ProxyMode::System,
                detected: ProxyDetected::Direct,
                auto_detect: false,
                pac_url: None,
                pac_state: PacState::NotUsed,
                http_proxy: None,
                https_proxy: None,
                bypass_entries: 0,
                settings_error: None,
                problems: Vec::new(),
                epoch: 0,
                last_change_at: None,
                dead_proxies: Vec::new(),
            },
            sign_in: SignInReport {
                methods: Vec::new(),
                attempts: Vec::new(),
            },
            roots: RootsReport {
                synced: false,
                synced_at: None,
                roots: 0,
                intermediates: 0,
                certificates: Vec::new(),
                skipped: Vec::new(),
                unreadable_stores: Vec::new(),
                left_out_of_tls: Vec::new(),
            },
            pull_proxy: PullProxyReport {
                active: false,
                via_upstream: false,
            },
            routes: Vec::new(),
        }
    }
}
