// SPDX-License-Identifier: GPL-3.0-or-later
//! The network-health report the API serves: the [`NetworkHealthService`] trait the route calls,
//! [`HostNetworkHealth`] that builds the report from the live pieces (proxy discovery, the
//! sign-in chain, the synced company roots, the pull proxy), and [`FakeNetworkHealth`] for tests
//! and the UI fixture.
//!
//! Everything in the report is safe to show (see [`crate::wire::NetworkHealth`]). The one place
//! text from outside enters it passes through [`puddle_upstream::redact_text`] or
//! [`puddle_upstream::redact_url`] first.

use std::sync::{Arc, Mutex, PoisonError, RwLock};

use futures_util::future::BoxFuture;
use puddle_certs::{CertKind, CorporateRoots};
use puddle_store::Clock;
use puddle_types::{Event, EventSink};
use puddle_upstream::{
    Chain, DeadProxy as UpstreamDead, Detected, Discovery, ModeKind, ProxyHealth,
    ProxyProblem as UpstreamProblem, ProxyProblemKind as UpstreamKind, RouteSample, SignIn,
    SignInOutcome, redact_text,
};
use tokio::task::JoinHandle;

use crate::wire::{
    DeadProxy, NetworkHealth, PacState, ProxyDetected, ProxyMode, ProxyProblem, ProxyProblemKind,
    ProxyReport, PullProxyReport, RootKind, RootsReport, RouteDecision, RouteSource, SignInAttempt,
    SignInReport, SignInResult, SkippedRoot, SyncedRoot,
};

/// Why a report could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkHealthError {
    /// The service is not wired in this build or state (503).
    #[error("{0}")]
    Unavailable(String),
}

/// Makes the network-health report.
pub trait NetworkHealthService: Send + Sync {
    /// The report now.
    fn report(&self) -> BoxFuture<'_, Result<NetworkHealth, NetworkHealthError>>;
}

/// The service when none is wired in: every call says so.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNetworkHealth;

impl NetworkHealthService for NoNetworkHealth {
    fn report(&self) -> BoxFuture<'_, Result<NetworkHealth, NetworkHealthError>> {
        Box::pin(async {
            Err(NetworkHealthError::Unavailable(
                "the network-health report is not available in this build yet".into(),
            ))
        })
    }
}

/// What the synced-roots part of the report is made from.
#[derive(Debug, Clone)]
struct RootsState {
    roots: Arc<CorporateRoots>,
    at_ms: u64,
}

/// The real report, over the pieces that know. Cheap to share.
pub struct HostNetworkHealth {
    discovery: Arc<Discovery>,
    chain: Option<Arc<Chain>>,
    clock: Arc<dyn Clock>,
    roots: RwLock<Option<RootsState>>,
    /// Company certificates puddle's own TLS client could not use.
    left_out_of_tls: RwLock<Vec<SkippedRoot>>,
    pull: RwLock<PullProxyReport>,
}

impl std::fmt::Debug for HostNetworkHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostNetworkHealth").finish_non_exhaustive()
    }
}

impl HostNetworkHealth {
    /// A report over `discovery`, stamped by `clock`. Sign-in results appear once
    /// [`HostNetworkHealth::with_chain`] is given the chain that connects.
    #[must_use]
    pub fn new(discovery: Arc<Discovery>, clock: Arc<dyn Clock>) -> Self {
        Self {
            discovery,
            chain: None,
            clock,
            roots: RwLock::new(None),
            left_out_of_tls: RwLock::new(Vec::new()),
            pull: RwLock::new(PullProxyReport {
                active: false,
                via_upstream: false,
            }),
        }
    }

    /// Reports the sign-ins of `chain`.
    #[must_use]
    pub fn with_chain(mut self, chain: Arc<Chain>) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Records the company roots that were just read from the host's stores.
    pub fn set_roots(&self, roots: Arc<CorporateRoots>) {
        let at_ms = self.clock.now_ms();
        *self.roots.write().unwrap_or_else(PoisonError::into_inner) =
            Some(RootsState { roots, at_ms });
    }

    /// Records the company certificates the host's own TLS client left out (it could not use them),
    /// named from `roots` where they are the ones synced into workspaces.
    pub fn set_tls_left_out(
        &self,
        rejected: &[puddle_upstream::RejectedRoot],
        roots: &CorporateRoots,
    ) {
        let left_out = rejected
            .iter()
            .map(|root| {
                let fingerprint = puddle_certs::Fingerprint::of(root.der.as_ref());
                let subject = roots
                    .certificates()
                    .iter()
                    .find(|cert| cert.fingerprint() == fingerprint)
                    .and_then(|cert| cert.subject_cn());
                SkippedRoot {
                    subject: subject.map(redact_text),
                    fingerprint: fingerprint.to_string(),
                    reason: redact_text(&root.reason),
                }
            })
            .collect();
        *self
            .left_out_of_tls
            .write()
            .unwrap_or_else(PoisonError::into_inner) = left_out;
    }

    /// Records whether image pulls go through the pull proxy, and whether that proxy leaves
    /// through the company proxy.
    pub fn set_pull_proxy(&self, active: bool, via_upstream: bool) {
        *self.pull.write().unwrap_or_else(PoisonError::into_inner) = PullProxyReport {
            active,
            via_upstream: active && via_upstream,
        };
    }

    fn build(&self, proxy: &ProxyHealth) -> NetworkHealth {
        let now = self.clock.now_ms();
        let (methods, attempts) = self.chain.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |chain| (chain.auth_methods(), chain.sign_ins()),
        );
        NetworkHealth {
            generated_at: now,
            proxy: proxy_report(proxy),
            sign_in: SignInReport {
                methods: methods.into_iter().map(str::to_owned).collect(),
                attempts: attempts.iter().map(attempt).collect(),
            },
            roots: roots_report(
                self.roots
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref(),
                self.left_out_of_tls
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ),
            pull_proxy: self
                .pull
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            routes: proxy.routes.iter().map(route).collect(),
        }
    }
}

impl NetworkHealthService for HostNetworkHealth {
    fn report(&self) -> BoxFuture<'_, Result<NetworkHealth, NetworkHealthError>> {
        Box::pin(async move { Ok(self.build(&self.discovery.health().await)) })
    }
}

/// Sends [`Event::NetworkChanged`] whenever `discovery` starts a new network epoch, until it is
/// dropped. Spawns on the current tokio runtime.
pub fn forward_network_changes(discovery: &Discovery, sink: Arc<dyn EventSink>) -> JoinHandle<()> {
    let mut epochs = discovery.subscribe();
    tokio::spawn(async move {
        while epochs.changed().await.is_ok() {
            let epoch = *epochs.borrow_and_update();
            sink.emit(Event::NetworkChanged { epoch });
        }
    })
}

fn millis(time: std::time::SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn proxy_report(health: &ProxyHealth) -> ProxyReport {
    ProxyReport {
        mode: match health.mode {
            ModeKind::Direct => ProxyMode::Direct,
            ModeKind::Manual => ProxyMode::Manual,
            _ => ProxyMode::System,
        },
        detected: match health.detected {
            Detected::Pac => ProxyDetected::Pac,
            Detected::Wpad => ProxyDetected::Wpad,
            Detected::Static => ProxyDetected::Static,
            Detected::Env => ProxyDetected::Env,
            _ => ProxyDetected::Direct,
        },
        auto_detect: health.auto_detect,
        pac_url: health.pac_url.clone(),
        pac_state: match (health.detected, health.pac_reachable) {
            (_, Some(false)) => PacState::Unreachable,
            (_, Some(true)) => PacState::Answering,
            (Detected::Pac | Detected::Wpad, None) => PacState::NotAsked,
            _ if health.auto_detect => PacState::NotAsked,
            _ => PacState::NotUsed,
        },
        http_proxy: health.http_proxy.as_ref().map(ToString::to_string),
        https_proxy: health.https_proxy.as_ref().map(ToString::to_string),
        bypass_entries: u32::try_from(health.bypass_entries).unwrap_or(u32::MAX),
        settings_error: health.settings_error.clone(),
        problems: health.problems.iter().map(problem).collect(),
        epoch: health.epoch,
        last_change_at: health.changed_at.map(millis),
        dead_proxies: health.dead.iter().map(dead).collect(),
    }
}

fn problem(problem: &UpstreamProblem) -> ProxyProblem {
    ProxyProblem {
        kind: match problem.kind {
            UpstreamKind::UnusableSetting => ProxyProblemKind::UnusableSetting,
            UpstreamKind::ChangesNotNoticed => ProxyProblemKind::ChangesNotNoticed,
            _ => ProxyProblemKind::Other,
        },
        detail: problem.detail.clone(),
    }
}

fn dead(dead: &UpstreamDead) -> DeadProxy {
    DeadProxy {
        proxy: dead.proxy.to_string(),
        retry_in_secs: dead.retry_in.as_secs(),
    }
}

fn attempt(sign_in: &SignIn) -> SignInAttempt {
    SignInAttempt {
        proxy: sign_in.proxy.to_string(),
        scheme: sign_in.scheme.clone(),
        result: match sign_in.outcome {
            SignInOutcome::SignedIn => SignInResult::SignedIn,
            SignInOutcome::NotRequired => SignInResult::NotRequired,
            SignInOutcome::Unsupported => SignInResult::Unsupported,
            _ => SignInResult::Failed,
        },
        detail: sign_in.detail.clone(),
        at: millis(sign_in.at),
    }
}

fn route(sample: &RouteSample) -> RouteDecision {
    use puddle_upstream::RouteSource as Source;
    RouteDecision {
        scheme: sample.destination.scheme().as_str().to_owned(),
        host: sample.destination.host().to_owned(),
        port: sample.destination.port(),
        hops: sample
            .route
            .hops()
            .iter()
            .map(ToString::to_string)
            .collect(),
        source: match sample.source {
            Source::Loopback => RouteSource::Loopback,
            Source::Disabled => RouteSource::Disabled,
            Source::Manual => RouteSource::Manual,
            Source::Pac => RouteSource::Pac,
            Source::PacUnsupported => RouteSource::PacUnsupported,
            Source::System => RouteSource::System,
            Source::Env => RouteSource::Env,
            Source::Bypass => RouteSource::Bypass,
            _ => RouteSource::NoProxy,
        },
    }
}

fn roots_report(state: Option<&RootsState>, left_out_of_tls: Vec<SkippedRoot>) -> RootsReport {
    let Some(state) = state else {
        return RootsReport {
            synced: false,
            synced_at: None,
            roots: 0,
            intermediates: 0,
            certificates: Vec::new(),
            skipped: Vec::new(),
            unreadable_stores: Vec::new(),
            left_out_of_tls,
        };
    };
    let certificates: Vec<SyncedRoot> = state
        .roots
        .certificates()
        .iter()
        .map(|cert| SyncedRoot {
            subject: cert.subject_cn().map(redact_text),
            fingerprint: cert.fingerprint().to_string(),
            kind: match cert.kind() {
                CertKind::Root => RootKind::Root,
                _ => RootKind::Intermediate,
            },
            not_after: cert.not_after_unix().saturating_mul(1000),
            sources: cert.sources().iter().map(ToString::to_string).collect(),
        })
        .collect();
    let count = |kind| {
        u32::try_from(certificates.iter().filter(|c| c.kind == kind).count()).unwrap_or(u32::MAX)
    };
    RootsReport {
        synced: true,
        synced_at: Some(state.at_ms),
        roots: count(RootKind::Root),
        intermediates: count(RootKind::Intermediate),
        certificates,
        skipped: state
            .roots
            .skipped()
            .iter()
            .map(|skipped| SkippedRoot {
                subject: skipped.subject_cn.as_deref().map(redact_text),
                fingerprint: skipped.fingerprint.to_string(),
                reason: skipped.reason.to_string(),
            })
            .collect(),
        unreadable_stores: state
            .roots
            .unreadable_stores()
            .iter()
            .map(|store| format!("{}: {}", store.source, redact_text(&store.reason)))
            .collect(),
        left_out_of_tls,
    }
}

/// An in-memory [`NetworkHealthService`] for tests and the UI fixture: it serves the report it
/// was given, stamped with the clock's time, and [`FakeNetworkHealth::set`] replaces it.
pub struct FakeNetworkHealth {
    report: Mutex<NetworkHealth>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for FakeNetworkHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeNetworkHealth").finish_non_exhaustive()
    }
}

impl FakeNetworkHealth {
    /// Serves a machine with no proxy until [`FakeNetworkHealth::set`] says otherwise.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        let report = NetworkHealth::direct(clock.now_ms());
        Self {
            report: Mutex::new(report),
            clock,
        }
    }

    /// Serves `report` from now on.
    pub fn set(&self, report: NetworkHealth) {
        *self.report.lock().unwrap_or_else(PoisonError::into_inner) = report;
    }
}

impl NetworkHealthService for FakeNetworkHealth {
    fn report(&self) -> BoxFuture<'_, Result<NetworkHealth, NetworkHealthError>> {
        Box::pin(async move {
            let mut report = self
                .report
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            report.generated_at = self.clock.now_ms();
            Ok(report)
        })
    }
}
