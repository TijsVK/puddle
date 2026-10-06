// SPDX-License-Identifier: GPL-3.0-or-later
//! [`FakeOs`]: scripted OS proxy answers for tests (feature `testing`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::hop::Hop;
use crate::os::{
    ChangeCallback, OsProxy, PacError, PacQuery, ProxyConfig, SettingsError, WatchGuard,
};

type PacFn = dyn Fn(&PacQuery) -> Result<Vec<Hop>, PacError> + Send + Sync;

/// A scripted [`OsProxy`]: config and the PAC function are set by the test, calls are counted,
/// and [`FakeOs::fire_change`] plays a network change.
pub struct FakeOs {
    config: Mutex<Result<ProxyConfig, SettingsError>>,
    pac: Mutex<Arc<PacFn>>,
    callback: Arc<Mutex<Option<ChangeCallback>>>,
    config_calls: AtomicUsize,
    pac_calls: AtomicUsize,
    can_watch: bool,
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
        }
    }

    /// Like [`FakeOs::new`], but `watch` is unsupported.
    #[must_use]
    pub fn without_watch(config: ProxyConfig) -> Arc<Self> {
        Arc::new(Self::build(config, false))
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
            .clone();
        callback.map(|cb| cb()).is_some()
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
            .is_some()
    }
}

struct FakeGuard(Arc<Mutex<Option<ChangeCallback>>>);

impl std::fmt::Debug for FakeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FakeGuard")
    }
}

impl WatchGuard for FakeGuard {}

impl Drop for FakeGuard {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
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

    fn watch(&self, on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>> {
        if !self.can_watch {
            return None;
        }
        *self.callback.lock().unwrap_or_else(PoisonError::into_inner) = Some(on_change);
        Some(Box::new(FakeGuard(Arc::clone(&self.callback))))
    }
}
