// SPDX-License-Identifier: GPL-3.0-or-later
//! Where the API keeps settings documents. The API reads and writes raw documents and does the
//! versioning itself (`puddle-settings`: migrate, keep unknown fields, refuse newer), so a store
//! only has to keep JSON values.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use puddle_types::SandboxName;
use serde_json::Value;

/// Storage for the two settings document kinds. Calls may block (files, `SQLite`); the API runs
/// them on a blocking thread.
pub trait SettingsRepo: Send + Sync {
    /// The global document, or `None` if none was ever written.
    ///
    /// # Errors
    ///
    /// [`SettingsRepoError`] if the storage fails.
    fn load_global(&self) -> Result<Option<Value>, SettingsRepoError>;

    /// Replaces the global document.
    ///
    /// # Errors
    ///
    /// [`SettingsRepoError`] if the storage fails.
    fn save_global(&self, document: Value) -> Result<(), SettingsRepoError>;

    /// One sandbox's document, or `None` if it has none.
    ///
    /// # Errors
    ///
    /// [`SettingsRepoError`] if the storage fails.
    fn load_sandbox(&self, sandbox: &SandboxName) -> Result<Option<Value>, SettingsRepoError>;

    /// Replaces one sandbox's document.
    ///
    /// # Errors
    ///
    /// [`SettingsRepoError`] if the storage fails.
    fn save_sandbox(&self, sandbox: &SandboxName, document: Value)
    -> Result<(), SettingsRepoError>;
}

/// A settings storage failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("settings storage failed: {reason}")]
pub struct SettingsRepoError {
    reason: String,
}

impl SettingsRepoError {
    /// An error with this reason (no secrets: it is logged).
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Settings kept in memory, for tests and until the storage row lands.
#[derive(Debug, Default)]
pub struct MemorySettings {
    global: Mutex<Option<Value>>,
    sandboxes: Mutex<BTreeMap<SandboxName, Value>>,
}

impl SettingsRepo for MemorySettings {
    fn load_global(&self) -> Result<Option<Value>, SettingsRepoError> {
        Ok(self
            .global
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    fn save_global(&self, document: Value) -> Result<(), SettingsRepoError> {
        *self.global.lock().unwrap_or_else(PoisonError::into_inner) = Some(document);
        Ok(())
    }

    fn load_sandbox(&self, sandbox: &SandboxName) -> Result<Option<Value>, SettingsRepoError> {
        Ok(self
            .sandboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sandbox)
            .cloned())
    }

    fn save_sandbox(
        &self,
        sandbox: &SandboxName,
        document: Value,
    ) -> Result<(), SettingsRepoError> {
        self.sandboxes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sandbox.clone(), document);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn memory_settings_keep_what_was_saved() {
        let repo = MemorySettings::default();
        let a = SandboxName::new("a").unwrap();
        assert_eq!(repo.load_global().unwrap(), None);
        assert_eq!(repo.load_sandbox(&a).unwrap(), None);
        repo.save_global(json!({"schema_version": 1})).unwrap();
        repo.save_sandbox(&a, json!({"overrides": {}})).unwrap();
        assert_eq!(
            repo.load_global().unwrap(),
            Some(json!({"schema_version": 1}))
        );
        assert_eq!(
            repo.load_sandbox(&a).unwrap(),
            Some(json!({"overrides": {}}))
        );
        assert_eq!(
            SettingsRepoError::new("disk full").to_string(),
            "settings storage failed: disk full"
        );
    }
}
