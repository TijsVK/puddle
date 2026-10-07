// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's small state files: the settings documents and the workspace book.
//!
//! Both are JSON written atomically and owner-only ([`puddle_fs::private::write_atomic`]). A
//! missing file is a fresh install; one that exists but cannot be read or parsed is an error, so
//! a damaged file is never mistaken for an empty one.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use puddle_api::{SettingsRepo, SettingsRepoError};
use puddle_types::{SandboxName, WorkspaceId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::HostError;

/// Reads `path` as JSON, `None` when it does not exist.
fn read_json(path: &Path) -> Result<Option<Value>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("{} is not valid JSON: {e}", path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let body = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    puddle_fs::private::write_atomic(path, &body)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Settings documents as files: `global.json` and `sandboxes/<name>.json` in one folder.
///
/// The API versions and validates the documents; this only keeps them. Sandbox names are
/// validated DNS labels, so a name is always a safe file name. Reads are served from memory after
/// the first one (the proxy asks for a sandbox's settings on every new connection); saves write
/// the file first and the memory second, and this process is the file's only writer.
#[derive(Debug)]
pub struct FileSettings {
    dir: PathBuf,
    cache: Mutex<Cache>,
}

#[derive(Debug, Default)]
struct Cache {
    global: Option<Value>,
    global_read: bool,
    sandboxes: BTreeMap<SandboxName, Option<Value>>,
}

impl FileSettings {
    /// Settings kept in `dir` (created when first written).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cache: Mutex::new(Cache::default()),
        }
    }

    fn global_path(&self) -> PathBuf {
        self.dir.join("global.json")
    }

    fn sandbox_path(&self, sandbox: &SandboxName) -> PathBuf {
        self.dir.join("sandboxes").join(format!("{sandbox}.json"))
    }

    fn cache(&self) -> MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SettingsRepo for FileSettings {
    fn load_global(&self) -> Result<Option<Value>, SettingsRepoError> {
        let mut cache = self.cache();
        if cache.global_read {
            return Ok(cache.global.clone());
        }
        let loaded = read_json(&self.global_path()).map_err(SettingsRepoError::new)?;
        cache.global.clone_from(&loaded);
        cache.global_read = true;
        Ok(loaded)
    }

    fn save_global(&self, document: Value) -> Result<(), SettingsRepoError> {
        let mut cache = self.cache();
        write_json(&self.global_path(), &document).map_err(SettingsRepoError::new)?;
        cache.global = Some(document);
        cache.global_read = true;
        Ok(())
    }

    fn load_sandbox(&self, sandbox: &SandboxName) -> Result<Option<Value>, SettingsRepoError> {
        let mut cache = self.cache();
        if let Some(cached) = cache.sandboxes.get(sandbox) {
            return Ok(cached.clone());
        }
        let loaded = read_json(&self.sandbox_path(sandbox)).map_err(SettingsRepoError::new)?;
        cache.sandboxes.insert(sandbox.clone(), loaded.clone());
        Ok(loaded)
    }

    fn save_sandbox(
        &self,
        sandbox: &SandboxName,
        document: Value,
    ) -> Result<(), SettingsRepoError> {
        let mut cache = self.cache();
        write_json(&self.sandbox_path(sandbox), &document).map_err(SettingsRepoError::new)?;
        cache.sandboxes.insert(sandbox.clone(), Some(document));
        Ok(())
    }
}

/// What the book keeps for one workspace; its volume and sandbox live in the runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Stored {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) repo_url: String,
    pub(crate) image: String,
    pub(crate) memory_mib: u32,
    pub(crate) created_at: u64,
    pub(crate) disk_size_mib: u64,
    pub(crate) first_connect_notice_due: bool,
    /// Set from the moment a create starts until it finishes. A record still marked after a
    /// restart is an interrupted create: its volume is an orphan for reconcile to remove.
    #[serde(default)]
    pub(crate) creating: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BookFile {
    version: u32,
    workspaces: Vec<Stored>,
}

const BOOK_VERSION: u32 = 1;

/// The workspace book: a JSON file with one entry per workspace.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceBook {
    path: PathBuf,
}

impl WorkspaceBook {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn error(reason: String) -> HostError {
        HostError::State {
            what: "the workspace list",
            reason,
        }
    }

    /// Every stored workspace; none when there is no book yet.
    pub(crate) fn load(&self) -> Result<Vec<Stored>, HostError> {
        let Some(value) = read_json(&self.path).map_err(Self::error)? else {
            return Ok(Vec::new());
        };
        let file: BookFile = serde_json::from_value(value).map_err(|e| {
            Self::error(format!(
                "{} is not a workspace list: {e}",
                self.path.display()
            ))
        })?;
        if file.version > BOOK_VERSION {
            return Err(Self::error(format!(
                "{} was written by a newer puddle (version {})",
                self.path.display(),
                file.version
            )));
        }
        for stored in &file.workspaces {
            WorkspaceId::new(&stored.id)
                .map_err(|e| Self::error(format!("workspace {:?}: {e}", stored.id)))?;
            SandboxName::new(&stored.name)
                .map_err(|e| Self::error(format!("workspace {:?}: {e}", stored.id)))?;
        }
        Ok(file.workspaces)
    }

    pub(crate) fn save(&self, workspaces: Vec<Stored>) -> Result<(), HostError> {
        let file = BookFile {
            version: BOOK_VERSION,
            workspaces,
        };
        let value = serde_json::to_value(&file).map_err(|e| Self::error(e.to_string()))?;
        write_json(&self.path, &value).map_err(Self::error)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn stored(id: &str) -> Stored {
        Stored {
            id: id.to_owned(),
            name: id.to_owned(),
            repo_url: "https://example.org/a/b".to_owned(),
            image: "alpine:3".to_owned(),
            memory_mib: 1024,
            created_at: 7,
            disk_size_mib: 2048,
            first_connect_notice_due: true,
            creating: false,
        }
    }

    #[test]
    fn settings_round_trip_and_a_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let repo = FileSettings::new(dir.path().join("settings"));
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
        // A second instance over the same folder sees the same documents.
        let again = FileSettings::new(dir.path().join("settings"));
        assert_eq!(
            again.load_global().unwrap(),
            Some(json!({"schema_version": 1}))
        );
    }

    #[test]
    fn a_damaged_settings_file_is_an_error_not_an_empty_document() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("global.json"), b"{ nope").unwrap();
        let err = FileSettings::new(dir.path()).load_global().unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "{err}");
    }

    #[test]
    fn a_settings_folder_that_is_a_file_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("settings");
        std::fs::write(&blocker, b"x").unwrap();
        let err = FileSettings::new(&blocker)
            .save_global(json!({}))
            .unwrap_err();
        assert!(err.to_string().contains("cannot write"), "{err}");
    }

    #[test]
    fn the_book_round_trips_and_a_missing_book_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let book = WorkspaceBook::new(dir.path().join("workspaces.json"));
        assert_eq!(book.load().unwrap(), Vec::new());
        book.save(vec![stored("a"), stored("b")]).unwrap();
        assert_eq!(book.load().unwrap(), vec![stored("a"), stored("b")]);
    }

    #[test]
    fn a_damaged_or_newer_book_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");
        let book = WorkspaceBook::new(&path);
        std::fs::write(&path, b"[1,2").unwrap();
        assert!(
            book.load()
                .unwrap_err()
                .to_string()
                .contains("not valid JSON")
        );
        std::fs::write(&path, b"{\"nope\": true}").unwrap();
        assert!(
            book.load()
                .unwrap_err()
                .to_string()
                .contains("not a workspace list")
        );
        std::fs::write(&path, br#"{"version": 99, "workspaces": []}"#).unwrap();
        assert!(
            book.load()
                .unwrap_err()
                .to_string()
                .contains("newer puddle")
        );
        let bad = json!({"version": 1, "workspaces": [{
            "id": "Not A Name", "name": "x", "repo_url": "u", "image": "i", "memory_mib": 1,
            "created_at": 0, "disk_size_mib": 1, "first_connect_notice_due": false
        }]});
        std::fs::write(&path, bad.to_string()).unwrap();
        assert!(book.load().is_err());
    }

    #[test]
    fn an_old_entry_without_the_creating_flag_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("workspaces.json");
        let entry = json!({"version": 1, "workspaces": [{
            "id": "a", "name": "a", "repo_url": "u", "image": "i", "memory_mib": 512,
            "created_at": 1, "disk_size_mib": 64, "first_connect_notice_due": false
        }]});
        std::fs::write(&path, entry.to_string()).unwrap();
        let loaded = WorkspaceBook::new(&path).load().unwrap();
        assert!(!loaded.first().unwrap().creating);
    }
}
