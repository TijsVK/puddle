// SPDX-License-Identifier: GPL-3.0-or-later
//! [`FakeOs`]: scripted OS proxy answers for tests (feature `testing`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::hop::Hop;
use crate::os::{
    ChangeCallback, OsProxy, PacError, PacQuery, ProblemCallback, ProxyConfig, SettingsError,
    WatchGuard,
};

type PacFn = dyn Fn(&PacQuery) -> Result<Vec<Hop>, PacError> + Send + Sync;

/// A scripted [`OsProxy`]: config and the PAC function are set by the test, calls are counted,
/// and [`FakeOs::fire_change`] plays a network change.
pub struct FakeOs {
    config: Mutex<Result<ProxyConfig, SettingsError>>,
    pac: Mutex<Arc<PacFn>>,
    callback: Arc<Mutex<Callbacks>>,
    config_calls: AtomicUsize,
    pac_calls: AtomicUsize,
    can_watch: bool,
    /// Why `watch` fails, told to the problem callback; `None`: it fails without a word (an OS
    /// layer that cannot watch by nature).
    watch_failure: Option<String>,
}

/// What a live watch registered.
#[derive(Default)]
struct Callbacks {
    on_change: Option<ChangeCallback>,
    on_problem: Option<ProblemCallback>,
}

impl std::fmt::Debug for FakeOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeOs").finish_non_exhaustive()
    }
}

impl FakeOs {
    /// A fake that reports `config` and answers every PAC query with `DIRECT`.
    #[must_use]
    pub fn new(config: ProxyConfig) -> Arc<Self> {
        Arc::new(Self::build(config, true))
    }

    fn build(config: ProxyConfig, can_watch: bool) -> Self {
        Self {
            config: Mutex::new(Ok(config)),
            pac: Mutex::new(Arc::new(|_| Ok(vec![Hop::Direct]))),
            callback: Arc::default(),
            config_calls: AtomicUsize::new(0),
            pac_calls: AtomicUsize::new(0),
            can_watch,
            watch_failure: None,
        }
    }

    /// Like [`FakeOs::new`], but `watch` is unsupported.
    #[must_use]
    pub fn without_watch(config: ProxyConfig) -> Arc<Self> {
        Arc::new(Self::build(config, false))
    }

    /// Like [`FakeOs::without_watch`], but `watch` tells the problem callback `why` first, as an OS
    /// layer does that tried to register for changes and failed.
    #[must_use]
    pub fn failing_watch(config: ProxyConfig, why: &str) -> Arc<Self> {
        let mut os = Self::build(config, false);
        os.watch_failure = Some(why.to_owned());
        Arc::new(os)
    }

    /// Replaces the config.
    pub fn set_config(&self, config: ProxyConfig) {
        *self.config.lock().unwrap_or_else(PoisonError::into_inner) = Ok(config);
    }

    /// Makes `config()` fail.
    pub fn fail_config(&self, message: &str) {
        *self.config.lock().unwrap_or_else(PoisonError::into_inner) =
            Err(SettingsError(message.into()));
    }

    /// Sets the PAC function.
    pub fn set_pac(
        &self,
        pac: impl Fn(&PacQuery) -> Result<Vec<Hop>, PacError> + Send + Sync + 'static,
    ) {
        *self.pac.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(pac);
    }

    /// Plays an OS change notification. Returns false when nobody is watching.
    pub fn fire_change(&self) -> bool {
        let callback = self
            .callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_change
            .clone();
        callback.map(|cb| cb()).is_some()
    }

    /// Plays a watcher that stopped working (`why`). Returns false when nobody is watching.
    pub fn fire_watch_problem(&self, why: &str) -> bool {
        let callback = self
            .callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_problem
            .clone();
        callback.map(|cb| cb(why.to_owned())).is_some()
    }

    /// How often `config()` was called.
    #[must_use]
    pub fn config_calls(&self) -> usize {
        self.config_calls.load(Ordering::SeqCst)
    }

    /// How often `resolve_pac()` was called.
    #[must_use]
    pub fn pac_calls(&self) -> usize {
        self.pac_calls.load(Ordering::SeqCst)
    }

    /// True while a watch guard is alive.
    #[must_use]
    pub fn is_watched(&self) -> bool {
        self.callback
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .on_change
            .is_some()
    }
}

struct FakeGuard(Arc<Mutex<Callbacks>>);

impl std::fmt::Debug for FakeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeGuard")
    }
}

impl WatchGuard for FakeGuard {}

impl Drop for FakeGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Callbacks::default();
    }
}

impl OsProxy for FakeOs {
    fn config(&self) -> Result<ProxyConfig, SettingsError> {
        self.config_calls.fetch_add(1, Ordering::SeqCst);
        self.config
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn resolve_pac(&self, query: &PacQuery) -> Result<Vec<Hop>, PacError> {
        self.pac_calls.fetch_add(1, Ordering::SeqCst);
        let pac = self
            .pac
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        pac(query)
    }

    fn watch(
        &self,
        on_change: ChangeCallback,
        on_problem: ProblemCallback,
    ) -> Option<Box<dyn WatchGuard>> {
        if !self.can_watch {
            if let Some(why) = &self.watch_failure {
                on_problem(why.clone());
            }
            return None;
        }
        *self.callback.lock().unwrap_or_else(PoisonError::into_inner) = Callbacks {
            on_change: Some(on_change),
            on_problem: Some(on_problem),
        };
        Some(Box::new(FakeGuard(Arc::clone(&self.callback))))
    }
}
