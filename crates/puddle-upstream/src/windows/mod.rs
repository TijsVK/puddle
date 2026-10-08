// SPDX-License-Identifier: GPL-3.0-or-later
//! The Windows implementation of [`OsProxy`]: WinHTTP for settings and PAC/WPAD evaluation, the
//! registry for change notification. This module and its children are the crate's only unsafe
//! code; each raw resource is owned by a guard that releases it.
#![expect(
    unsafe_code,
    reason = "FFI to WinHTTP and the registry; each block is small and commented"
)]

mod pac;
mod settings;
mod sspi;
mod watch;

pub(crate) use sspi::SspiSource;

use crate::hop::Hop;
use crate::os::{
    ChangeCallback, OsProxy, PacError, PacQuery, ProblemCallback, ProxyConfig, SettingsError,
    WatchGuard,
};

/// WinHTTP and registry backed [`OsProxy`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WinOs;

impl WinOs {
    /// The Windows OS layer. Stateless: every call asks Windows.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OsProxy for WinOs {
    fn config(&self) -> Result<ProxyConfig, SettingsError> {
        settings::read()
    }

    fn resolve_pac(&self, query: &PacQuery) -> Result<Vec<Hop>, PacError> {
        pac::resolve(query)
    }

    fn watch(
        &self,
        on_change: ChangeCallback,
        on_problem: ProblemCallback,
    ) -> Option<Box<dyn WatchGuard>> {
        watch::start(on_change, &on_problem)
    }
}

/// A UTF-16, NUL-terminated copy of `text`.
pub(crate) fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copies a NUL-terminated UTF-16 string, `None` for null or empty.
///
/// # Safety
/// `ptr` is null or points at a readable NUL-terminated UTF-16 string.
pub(crate) unsafe fn read_wide(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: the caller promises a terminated string, so every index up to the NUL is readable.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) });
    (!text.is_empty()).then_some(text)
}
