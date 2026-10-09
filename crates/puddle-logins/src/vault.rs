// SPDX-License-Identifier: GPL-3.0-or-later
//! Where a workspace's real tokens are kept: one entry in the operating system's credential store
//! for each of the workspace's token slots.
//!
//! The slots of a workspace are a closed, small set (each profile's roles), so an entry's name is
//! worked out from the workspace, the profile and the role, and no index is needed to find the
//! entries of a workspace, to list them or to delete them with it. An entry holds the stand-in
//! the workspace was given and the real token; the stand-in is not a secret (the workspace has
//! it) but is kept beside the token so the pair survives a restart of the workspace, whose disk
//! still holds the stand-in.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use puddle_secrets::{Secret, SecretStore, StoredId};
use puddle_types::WorkspaceName;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::profile::{Profile, Role};

/// The version of what an entry holds; a version this build does not know is left alone.
const ENTRY_VERSION: u8 = 1;

/// How long the host waits for the credential store (a locked Secret Service can ask the user to
/// unlock it and wait for the answer).
pub(crate) const STORE_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an entry could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum VaultError {
    /// The store did not answer, or refused.
    #[error("the operating system's credential store did not answer")]
    Unavailable,
    /// The entry is not one this build wrote.
    #[error("a saved login could not be understood")]
    Damaged,
}

/// What one entry holds.
#[derive(Deserialize)]
struct Entry {
    v: u8,
    stand_in: String,
    real: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.real.zeroize();
    }
}

#[derive(Serialize)]
struct EntryRef<'a> {
    v: u8,
    stand_in: &'a str,
    real: &'a str,
}

/// A saved pair: the stand-in the workspace holds and the real token behind it.
pub(crate) struct Saved {
    pub(crate) stand_in: String,
    pub(crate) real: Zeroizing<String>,
}

/// The credential store, with puddle's own entry names.
#[derive(Clone)]
pub(crate) struct Vault {
    store: Arc<dyn SecretStore>,
    workspace: String,
}

impl Vault {
    pub(crate) fn new(store: Arc<dyn SecretStore>, workspace: &WorkspaceName) -> Self {
        Self {
            store,
            workspace: workspace.to_string(),
        }
    }

    fn id(&self, profile: &Profile, role: Role) -> Option<StoredId> {
        slot_id(&self.workspace, profile.id, role)
    }

    /// The saved pair of `profile`'s `role`, or `None` when there is none. Blocking.
    pub(crate) fn read(&self, profile: &Profile, role: Role) -> Result<Option<Saved>, VaultError> {
        let id = self.id(profile, role).ok_or(VaultError::Damaged)?;
        let Some(secret) = self.store.get(&id).map_err(|_| VaultError::Unavailable)? else {
            return Ok(None);
        };
        let entry: Entry =
            serde_json::from_str(secret.expose()).map_err(|_| VaultError::Damaged)?;
        if entry.v != ENTRY_VERSION {
            return Err(VaultError::Damaged);
        }
        Ok(Some(Saved {
            stand_in: entry.stand_in.clone(),
            real: Zeroizing::new(entry.real.clone()),
        }))
    }

    /// Saves the pair of `profile`'s `role`, replacing the earlier one. Blocking.
    pub(crate) fn write(
        &self,
        profile: &Profile,
        role: Role,
        stand_in: &str,
        real: &str,
    ) -> Result<(), VaultError> {
        let id = self.id(profile, role).ok_or(VaultError::Damaged)?;
        let text = Zeroizing::new(
            serde_json::to_string(&EntryRef {
                v: ENTRY_VERSION,
                stand_in,
                real,
            })
            .map_err(|_| VaultError::Damaged)?,
        );
        self.store
            .set(&id, &Secret::new((*text).clone()))
            .map_err(|_| VaultError::Unavailable)
    }

    /// Deletes the pair of `profile`'s `role`; one that is not there is fine. Blocking.
    pub(crate) fn delete(&self, profile: &Profile, role: Role) -> Result<(), VaultError> {
        let id = self.id(profile, role).ok_or(VaultError::Damaged)?;
        self.store.delete(&id).map_err(|_| VaultError::Unavailable)
    }
}

/// The name of the entry for one slot: `login-<16 hex of the workspace's hash>-<profile>-<role>`.
/// The workspace is hashed because its name and the rest may not fit the store's 64 characters.
pub(crate) fn slot_id(workspace: &str, profile: &str, role: Role) -> Option<StoredId> {
    let digest = Sha256::digest(workspace.as_bytes());
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        let _ = write!(hex, "{byte:02x}");
    }
    StoredId::new(format!("login-{hex}-{profile}-{}", role.key())).ok()
}

#[cfg(test)]
mod tests {
    use puddle_secrets::MemoryStore;

    use super::*;
    use crate::profile::{CLAUDE, GITHUB};

    fn workspace(name: &str) -> WorkspaceName {
        WorkspaceName::new(name).unwrap()
    }

    fn vault(store: &Arc<MemoryStore>, name: &str) -> Vault {
        Vault::new(Arc::clone(store) as Arc<dyn SecretStore>, &workspace(name))
    }

    #[test]
    fn a_pair_round_trips_and_a_missing_one_is_none() {
        let store = Arc::new(MemoryStore::new());
        let v = vault(&store, "alpha");
        assert!(v.read(&GITHUB, Role::Access).unwrap().is_none());
        v.write(&GITHUB, Role::Access, "gho_standin", "gho_CANARY-real")
            .unwrap();
        let saved = v.read(&GITHUB, Role::Access).unwrap().unwrap();
        assert_eq!(saved.stand_in, "gho_standin");
        assert_eq!(&*saved.real, "gho_CANARY-real");
        v.write(&GITHUB, Role::Access, "gho_standin", "gho_CANARY-newer")
            .unwrap();
        assert_eq!(
            &*v.read(&GITHUB, Role::Access).unwrap().unwrap().real,
            "gho_CANARY-newer"
        );
        v.delete(&GITHUB, Role::Access).unwrap();
        v.delete(&GITHUB, Role::Access).unwrap();
        assert!(v.read(&GITHUB, Role::Access).unwrap().is_none());
    }

    #[test]
    fn each_workspace_profile_and_role_has_an_entry_of_its_own() {
        let store = Arc::new(MemoryStore::new());
        let (a, b) = (vault(&store, "alpha"), vault(&store, "beta"));
        a.write(&GITHUB, Role::Access, "s1", "r1").unwrap();
        assert!(b.read(&GITHUB, Role::Access).unwrap().is_none());
        assert!(a.read(&GITHUB, Role::Refresh).unwrap().is_none());
        assert!(a.read(&CLAUDE, Role::Access).unwrap().is_none());
        b.write(&GITHUB, Role::Access, "s2", "r2").unwrap();
        assert_eq!(
            a.read(&GITHUB, Role::Access).unwrap().unwrap().stand_in,
            "s1"
        );
    }

    #[test]
    fn entry_names_fit_the_store_for_the_longest_workspace_name() {
        let long = "a".repeat(63);
        for profile in crate::profile::builtin() {
            for role in profile.roles() {
                let id = slot_id(&long, profile.id, role).unwrap();
                assert!(id.as_str().len() <= 64, "{id}");
                assert!(id.as_str().starts_with("login-"));
            }
        }
        assert_ne!(
            slot_id("alpha", "github", Role::Access),
            slot_id("alphb", "github", Role::Access)
        );
    }

    #[test]
    fn an_unavailable_store_is_an_error_and_a_damaged_entry_is_another() {
        let store = Arc::new(MemoryStore::new());
        let v = vault(&store, "alpha");
        let id = slot_id("alpha", "github", Role::Access).unwrap();
        store.set(&id, &Secret::new("not json".into())).unwrap();
        assert_eq!(
            v.read(&GITHUB, Role::Access).err(),
            Some(VaultError::Damaged)
        );
        store
            .set(
                &id,
                &Secret::new(r#"{"v":9,"stand_in":"a","real":"b"}"#.into()),
            )
            .unwrap();
        assert_eq!(
            v.read(&GITHUB, Role::Access).err(),
            Some(VaultError::Damaged)
        );
        store.break_it();
        assert_eq!(
            v.read(&GITHUB, Role::Access).err(),
            Some(VaultError::Unavailable)
        );
        assert_eq!(
            v.write(&GITHUB, Role::Access, "s", "r"),
            Err(VaultError::Unavailable)
        );
        assert_eq!(
            v.delete(&GITHUB, Role::Access),
            Err(VaultError::Unavailable)
        );
    }
}
