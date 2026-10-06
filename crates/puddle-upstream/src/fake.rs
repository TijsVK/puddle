// SPDX-License-Identifier: GPL-3.0-or-later
//! [`FakeOs`]: scripted OS proxy answers for tests (feature `testing`).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::hop::Hop;
use crate::os::{
    ChangeCallback, OsProxy, OsSettings, PacError, PacQuery, SettingsError, WatchGuard,
};

type PacFn = dyn Fn(&PacQuery) -> Result<Vec<Hop>, PacError> + Send + Sync;

/// A scripted [`OsProxy`]: settings and the PAC function are set by the test, calls are counted,
/// and [`FakeOs::fire_change`] plays a network change.
pub struct FakeOs {
    settings: Mutex<Result<OsSettings, SettingsError>>,
    pac: Mutex<Arc<PacFn>>,
    callback: Arc<Mutex<Option<ChangeCallback>>>,
    settings_calls: AtomicUsize,
    pac_calls: AtomicUsize,
    can_watch: bool,
}

impl std::fmt::Debug for FakeOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeOs").finish_non_exhaustive()
    }
}

impl FakeOs {
    /// A fake that reports `settings` and answers every PAC query with `DIRECT`.
    #[must_use]
    pub fn new(settings: OsSettings) -> Arc<Self> {
        Arc::new(Self::build(settings, true))
    }

    fn build(settings: OsSettings, can_watch: bool) -> Self {
        Self {
            settings: Mutex::new(Ok(settings)),
            pac: Mutex::new(Arc::new(|_| Ok(vec![Hop::Direct]))),
            callback: Arc::default(),
            settings_calls: AtomicUsize::new(0),
            pac_calls: AtomicUsize::new(0),
            can_watch,
        }
    }

    /// Like [`FakeOs::new`], but `watch` is unsupported.
    #[must_use]
    pub fn without_watch(settings: OsSettings) -> Arc<Self> {
        Arc::new(Self::build(settings, false))
    }

    /// Replaces the settings.
    pub fn set_settings(&self, settings: OsSettings) {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) = Ok(settings);
    }

    /// Makes `settings()` fail.
    pub fn fail_settings(&self, message: &str) {
        *self.settings.lock().unwrap_or_else(PoisonError::into_inner) =
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

    /// How often `settings()` was called.
    #[must_use]
    pub fn settings_calls(&self) -> usize {
        self.settings_calls.load(Ordering::SeqCst)
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
    fn settings(&self) -> Result<OsSettings, SettingsError> {
        self.settings_calls.fetch_add(1, Ordering::SeqCst);
        self.settings
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
