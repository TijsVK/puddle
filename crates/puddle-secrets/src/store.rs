// SPDX-License-Identifier: GPL-3.0-or-later
//! Where a pasted token is kept: the seam over the OS credential store.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::name::StoredId;
use crate::secret::Secret;

/// The store did not do what was asked. Carries no detail: a store's own message could quote a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the OS credential store failed")]
pub struct StoreError;

/// A place for pasted tokens, addressed by [`StoredId`]. Blocking: callers run it off the async
/// threads. The product implementation is [`KeyringStore`](crate::KeyringStore); tests use
/// [`MemoryStore`].
pub trait SecretStore: Send + Sync {
    /// The token under `id`, or `None` when there is none.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be reached.
    fn get(&self, id: &StoredId) -> Result<Option<Secret>, StoreError>;

    /// Stores `secret` under `id`, replacing any earlier one.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be reached or refuses.
    fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), StoreError>;

    /// Removes the token under `id`; a missing one is fine.
    ///
    /// # Errors
    /// [`StoreError`] when the store cannot be reached.
    fn delete(&self, id: &StoredId) -> Result<(), StoreError>;
}

/// A store in memory: nothing persists, nothing leaves the process.
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, String>>,
    broken: Mutex<bool>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every later call fail, to test the unavailable-store path.
    pub fn break_it(&self) {
        *self.broken.lock().unwrap_or_else(PoisonError::into_inner) = true;
    }

    /// The ids held, sorted: for tests that look for what a caller left behind.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let mut ids: Vec<String> = entries.keys().cloned().collect();
        ids.sort();
        ids
    }

    fn check(&self) -> Result<(), StoreError> {
        if *self.broken.lock().unwrap_or_else(PoisonError::into_inner) {
            return Err(StoreError);
        }
        Ok(())
    }
}

impl SecretStore for MemoryStore {
    fn get(&self, id: &StoredId) -> Result<Option<Secret>, StoreError> {
        self.check()?;
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(entries.get(id.as_str()).map(|v| Secret::new(v.clone())))
    }

    fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), StoreError> {
        self.check()?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.insert(id.as_str().to_owned(), secret.expose().to_owned());
        Ok(())
    }

    fn delete(&self, id: &StoredId) -> Result<(), StoreError> {
        self.check()?;
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        entries.remove(id.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryStore::new();
        let id = StoredId::new("a").unwrap();
        assert!(store.get(&id).unwrap().is_none());
        store.set(&id, &Secret::new("v1".into())).unwrap();
        store.set(&id, &Secret::new("v2".into())).unwrap();
        assert_eq!(store.get(&id).unwrap().unwrap().expose(), "v2");
        store.delete(&id).unwrap();
        store.delete(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
        store.break_it();
        assert_eq!(store.get(&id).err(), Some(StoreError));
        assert_eq!(store.set(&id, &Secret::new("x".into())), Err(StoreError));
        assert_eq!(store.delete(&id), Err(StoreError));
    }
}
