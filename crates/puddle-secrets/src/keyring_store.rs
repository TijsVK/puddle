// SPDX-License-Identifier: GPL-3.0-or-later
//! The OS credential store through the `keyring` crate: Credential Manager on Windows, Keychain
//! on macOS, the Secret Service on Linux.

use crate::name::StoredId;
use crate::secret::Secret;
use crate::store::{SecretStore, StoreError};

/// Service name every puddle entry is filed under; the entry's user is `credential:<id>`.
const SERVICE: &str = "puddle";

/// The platform's credential store, under puddle's own name.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringStore;

fn entry(id: &StoredId) -> Result<keyring::Entry, StoreError> {
    keyring::Entry::new(SERVICE, &format!("credential:{id}")).map_err(|_| StoreError)
}

impl SecretStore for KeyringStore {
    fn get(&self, id: &StoredId) -> Result<Option<Secret>, StoreError> {
        match entry(id)?.get_password() {
            Ok(value) => Ok(Some(Secret::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(StoreError),
        }
    }

    fn set(&self, id: &StoredId, secret: &Secret) -> Result<(), StoreError> {
        entry(id)?
            .set_password(secret.expose())
            .map_err(|_| StoreError)
    }

    fn delete(&self, id: &StoredId) -> Result<(), StoreError> {
        match entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(StoreError),
        }
    }
}

/// Whether the platform store can be used at all (a Linux host with no Secret Service cannot).
#[must_use]
pub fn keyring_available() -> bool {
    keyring::Entry::store_status().is_ok()
}
