// SPDX-License-Identifier: GPL-3.0-or-later
//! Proxy discovery: which route a request takes to leave the machine.
//!
//! Order for [`Mode::System`] (T-026 section 2a): a loopback destination goes direct; then what
//! the [`OsProxy`] reports: a PAC script or WPAD evaluated per URL, else the static proxies with
//! their bypass list; else direct. On Windows the OS layer is the user's WinINet settings as
//! WinHTTP reads them (PAC and WPAD by Windows' own engine), then the machine-wide WinHTTP proxy,
//! then the `HTTP(S)_PROXY` variables; on Unix it is the variables alone. A PAC that answers
//! (even `DIRECT`) is final; a PAC that fails falls through to the static proxies.
//!
//! Decisions are cached per destination for one *network epoch*. The epoch ends when the OS says
//! the proxy settings or the network changed (debounced, because a VPN or security client can flap
//! the setting many times a second) or when [`Discovery::bump_epoch`] is called. A PAC or WPAD
//! that is unreachable is remembered for the whole epoch (retried after
//! [`Config::pac_retry`]), so a network without WPAD costs one failed lookup, not one per
//! connection. A proxy reported dead through [`Discovery::report_failure`] moves to the back of
//! every route for [`Config::bad_proxy_ttl`], so one dead hop does not cost every connection its
//! connect timeout.
//!
//! reqwest's and hyper's own system-proxy support reads only HKCU `ProxyServer`: no PAC, WPAD,
//! machine proxy or policy. Nothing in puddle uses it for routing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use tokio::sync::{Notify, OnceCell, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::hop::{Destination, Hop, ProxyAddr, Route};
use crate::os::{Origin, OsProxy, PacError, PacQuery, ProxyConfig, WatchGuard};
use crate::parse::{BypassList, ProxyRules};

/// Where the proxy setting comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Mode {
    /// Follow the operating system, then the environment (the default).
    #[default]
    System,
    /// Never use a proxy.
    Direct,
    /// puddle's own setting, ignoring the system.
    Manual(ManualProxy),
}

/// A proxy chosen in puddle's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualProxy {
    /// Proxy list: `host:port` for every scheme, or `http=h:p;https=h:p`.
    pub proxy_server: String,
    /// Bypass list: `;` separated names, `*` wildcards, `<local>` ([`BypassList::parse`]).
    pub bypass: String,
}

/// Tunables. The defaults are the product's.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the setting comes from.
    pub mode: Mode,
    /// Quiet time after the last OS change notification before the epoch ends.
    pub debounce: Duration,
    /// How long a proxy reported dead stays at the back of routes.
    pub bad_proxy_ttl: Duration,
    /// Longest a PAC or WPAD evaluation may take.
    pub pac_timeout: Duration,
    /// How long an unreachable PAC or WPAD is not asked again within an epoch.
    pub pac_retry: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::System,
            debounce: Duration::from_secs(2),
            bad_proxy_ttl: Duration::from_secs(300),
            pac_timeout: Duration::from_secs(15),
            pac_retry: Duration::from_secs(60),
        }
    }
}

/// Which rule produced a route. For logs, the audit and the network-health page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteSource {
    /// The destination is this machine.
    Loopback,
    /// [`Mode::Direct`].
    Disabled,
    /// [`Mode::Manual`].
    Manual,
    /// A PAC script or WPAD answered.
    Pac,
    /// A PAC answered with entries puddle cannot use only (SOCKS, HTTPS proxy): direct instead.
    PacUnsupported,
    /// The operating system's static proxy.
    System,
    /// `HTTP(S)_PROXY`.
    Env,
    /// A bypass list exempted the destination.
    Bypass,
    /// No proxy configured anywhere.
    NoProxy,
}

/// The answer to "how do I reach this destination".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The hops to try, in order.
    pub route: Route,
    /// Which rule produced it.
    pub source: RouteSource,
    /// The network epoch it was made in.
    pub epoch: u64,
}

type Resolved = (Route, RouteSource);

#[derive(Debug)]
struct Epoch {
    number: u64,
    config: OnceCell<ProxyConfig>,
    routes: Mutex<HashMap<Destination, Arc<OnceCell<Resolved>>>>,
    pac_down_until: Mutex<Option<Instant>>,
    bad: Mutex<HashMap<ProxyAddr, Instant>>,
}

impl Epoch {
    fn new(number: u64) -> Arc<Self> {
        Arc::new(Self {
            number,
            config: OnceCell::new(),
            routes: Mutex::default(),
            pac_down_until: Mutex::new(None),
            bad: Mutex::default(),
        })
    }
}

/// Proxy discovery. Cheap to share: wrap in an [`Arc`].
#[derive(Debug)]
pub struct Discovery {
    os: Arc<dyn OsProxy>,
    config: Config,
    current: RwLock<Arc<Epoch>>,
    counter: AtomicU64,
    epochs: watch::Sender<u64>,
}

impl Discovery {
    /// Discovery over `os`.
    #[must_use]
    pub fn new(os: Arc<dyn OsProxy>, config: Config) -> Arc<Self> {
        let (epochs, _) = watch::channel(0);
        Arc::new(Self {
            os,
            config,
            current: RwLock::new(Epoch::new(0)),
            counter: AtomicU64::new(0),
            epochs,
        })
    }

    /// Discovery for this machine: the OS layer of the platform and the default configuration.
    #[must_use]
    pub fn system() -> Arc<Self> {
        Self::new(crate::os::system_os(), Config::default())
    }

    /// The current network epoch number.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch_state().number
    }

    /// A receiver that sees the epoch number whenever a new epoch starts. Holders of long-lived
    /// connections use it to re-route.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.epochs.subscribe()
    }

    /// Ends the epoch now: forgets every cached decision, the PAC-unavailable memory and the
    /// dead-proxy list, and re-reads the settings on next use.
    pub fn bump_epoch(&self) {
        let number = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Epoch::new(number);
        self.epochs.send_replace(number);
        tracing::info!(
            epoch = number,
            "network epoch changed; proxy decisions forgotten"
        );
    }

    /// Records that connecting through `proxy` failed. Until [`Config::bad_proxy_ttl`] passes or
    /// the epoch ends, routes list it after the working hops (it is never removed: it may be the
    /// only way out).
    pub fn report_failure(&self, proxy: &ProxyAddr) {
        let epoch = self.epoch_state();
        epoch
            .bad
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(proxy.clone(), Instant::now() + self.config.bad_proxy_ttl);
        tracing::warn!(proxy = %proxy, "upstream proxy marked unreachable");
    }

    /// Starts listening to the OS for proxy and network changes: after `debounce` of quiet, the
    /// epoch ends. Must run inside a tokio runtime. Returns `None` when the OS layer cannot watch;
    /// call [`Discovery::bump_epoch`] from another signal then. Dropping the handle stops it.
    #[must_use]
    pub fn watch(self: &Arc<Self>) -> Option<Watching> {
        let notify = Arc::new(Notify::new());
        let signal = Arc::clone(&notify);
        let guard = self.os.watch(Arc::new(move || signal.notify_one()))?;
        let this = Arc::downgrade(self);
        let debounce = self.config.debounce;
        let task = tokio::spawn(async move {
            loop {
                notify.notified().await;
                // Each further change restarts the quiet period.
                while tokio::time::timeout(debounce, notify.notified())
                    .await
                    .is_ok()
                {}
                let Some(discovery) = this.upgrade() else {
                    return;
                };
                discovery.bump_epoch();
            }
        });
        Some(Watching {
            task,
            _guard: guard,
        })
    }

    /// Decides the route for `dest`. Never fails: when nothing can be learned, the route is direct.
    pub async fn route(&self, dest: &Destination) -> Decision {
        let epoch = self.epoch_state();
        let (route, source) = if dest.is_loopback() {
            (Route::direct(), RouteSource::Loopback)
        } else {
            match &self.config.mode {
                Mode::Direct => (Route::direct(), RouteSource::Disabled),
                Mode::Manual(manual) => manual_route(manual, dest),
                Mode::System => self.system_route(&epoch, dest).await,
            }
        };
        let now = Instant::now();
        let route = route.demote(|proxy| {
            epoch
                .bad
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(proxy)
                .is_some_and(|until| *until > now)
        });
        tracing::debug!(host = dest.host(), port = dest.port(), route = %route, source = ?source, epoch = epoch.number, "route decided");
        Decision {
            route,
            source,
            epoch: epoch.number,
        }
    }

    fn epoch_state(&self) -> Arc<Epoch> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    async fn system_route(&self, epoch: &Arc<Epoch>, dest: &Destination) -> Resolved {
        let cell = {
            let mut routes = epoch.routes.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(routes.entry(dest.clone()).or_default())
        };
        // Concurrent connections to one destination share a single lookup. An answer that must
        // not outlive the PAC outage (`Err`) is returned but not stored.
        match cell
            .get_or_try_init(|| self.resolve_system(epoch, dest))
            .await
        {
            Ok(resolved) => resolved.clone(),
            Err(resolved) => resolved,
        }
    }

    async fn resolve_system(
        &self,
        epoch: &Arc<Epoch>,
        dest: &Destination,
    ) -> Result<Resolved, Resolved> {
        let settings = epoch
            .config
            .get_or_init(|| async {
                let os = Arc::clone(&self.os);
                match tokio::task::spawn_blocking(move || os.config()).await {
                    Ok(Ok(config)) => config,
                    Ok(Err(err)) => {
                        tracing::warn!(error = %err, "system proxy settings unreadable; going direct");
                        ProxyConfig::default()
                    }
                    Err(err) => {
                        tracing::error!(error = %err, "settings task failed");
                        ProxyConfig::default()
                    }
                }
            })
            .await;
        let mut degraded = false;
        if settings.pac_url.is_some() || settings.auto_detect {
            match self.pac(epoch, settings, dest).await {
                PacOutcome::Answer(resolved) => return Ok(resolved),
                PacOutcome::Failed => {}
                PacOutcome::Unavailable => degraded = true,
            }
        }
        let resolved = Self::static_route(settings, dest);
        if degraded {
            Err(resolved)
        } else {
            Ok(resolved)
        }
    }

    async fn pac(
        &self,
        epoch: &Arc<Epoch>,
        settings: &ProxyConfig,
        dest: &Destination,
    ) -> PacOutcome {
        let now = Instant::now();
        if epoch
            .pac_down_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|until| until > now)
        {
            return PacOutcome::Unavailable;
        }
        let query = PacQuery {
            pac_url: settings.pac_url.clone(),
            auto_detect: settings.auto_detect,
            url: dest.pac_url(),
            timeout: self.config.pac_timeout,
        };
        let os = Arc::clone(&self.os);
        let work = tokio::task::spawn_blocking(move || os.resolve_pac(&query));
        let result = match tokio::time::timeout(self.config.pac_timeout, work).await {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => Err(PacError::Failed(err.to_string())),
            Err(_) => Err(PacError::Timeout),
        };
        match result {
            Ok(hops) => {
                if let Some(route) = Route::new(hops) {
                    PacOutcome::Answer((route, RouteSource::Pac))
                } else {
                    tracing::warn!(
                        host = dest.host(),
                        "PAC answer had no usable entry; going direct"
                    );
                    PacOutcome::Answer((Route::direct(), RouteSource::PacUnsupported))
                }
            }
            Err(err @ (PacError::Unavailable(_) | PacError::Timeout)) => {
                tracing::warn!(error = %err, retry_secs = self.config.pac_retry.as_secs(), "PAC/WPAD unavailable; using the other settings");
                *epoch
                    .pac_down_until
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) =
                    Some(Instant::now() + self.config.pac_retry);
                PacOutcome::Unavailable
            }
            Err(err) => {
                tracing::warn!(host = dest.host(), error = %err, "PAC failed for this destination");
                PacOutcome::Failed
            }
        }
    }

    fn static_route(settings: &ProxyConfig, dest: &Destination) -> Resolved {
        let source = match settings.origin {
            Origin::Environment => RouteSource::Env,
            _ => RouteSource::System,
        };
        match settings.rules.for_scheme(dest.scheme()) {
            _ if settings.rules.is_empty() => (Route::direct(), RouteSource::NoProxy),
            _ if settings.bypass.matches(dest) => (Route::direct(), RouteSource::Bypass),
            Some(proxy) => (Route::via(proxy.clone()), source),
            None => (Route::direct(), source),
        }
    }
}

enum PacOutcome {
    Answer(Resolved),
    Failed,
    Unavailable,
}

fn manual_route(manual: &ManualProxy, dest: &Destination) -> Resolved {
    let rules = ProxyRules::parse(&manual.proxy_server);
    if BypassList::parse(&manual.bypass).matches(dest) {
        return (Route::direct(), RouteSource::Bypass);
    }
    match rules.for_scheme(dest.scheme()) {
        Some(proxy) => (Route::via(proxy.clone()), RouteSource::Manual),
        None => (Route::direct(), RouteSource::Manual),
    }
}

/// A running change listener ([`Discovery::watch`]). Dropping it stops the listener.
#[derive(Debug)]
pub struct Watching {
    task: JoinHandle<()>,
    _guard: Box<dyn WatchGuard>,
}

impl Drop for Watching {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Hop {
    /// The proxy of this hop, if it is one.
    #[must_use]
    pub fn proxy(&self) -> Option<&ProxyAddr> {
        match self {
            Self::Proxy(proxy) => Some(proxy),
            Self::Direct => None,
        }
    }
}
