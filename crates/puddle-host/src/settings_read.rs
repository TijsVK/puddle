// SPDX-License-Identifier: GPL-3.0-or-later
//! Reading the settings documents for the host's own decisions (direct SSH, local destinations,
//! the default memory). A missing document is a fresh install and means the defaults; one that
//! exists but cannot be read or understood is an `Err` naming what is wrong, so each caller picks
//! fail-closed, refuse or report instead of treating damage as "nothing set".

use puddle_api::SettingsRepo;
use puddle_settings::{GlobalSettings, WorkspaceSettings};
use puddle_types::WorkspaceName;
use serde_json::json;

/// The global settings; the defaults when none were ever saved.
pub(crate) fn global(repo: &dyn SettingsRepo) -> Result<GlobalSettings, String> {
    let doc = repo
        .load_global()
        .map_err(|e| format!("the global settings cannot be read: {e}"))?
        .unwrap_or_else(|| json!({}));
    GlobalSettings::from_document(doc)
        .map(|loaded| loaded.settings)
        .map_err(|e| format!("the global settings are not valid: {e}"))
}

/// One workspace's own settings; empty when it has none.
pub(crate) fn workspace(
    repo: &dyn SettingsRepo,
    name: &WorkspaceName,
) -> Result<WorkspaceSettings, String> {
    let doc = repo
        .load_workspace(name)
        .map_err(|e| format!("the settings of workspace {name} cannot be read: {e}"))?
        .unwrap_or_else(|| json!({}));
    WorkspaceSettings::from_document(doc)
        .map(|loaded| loaded.settings)
        .map_err(|e| format!("the settings of workspace {name} are not valid: {e}"))
}

#[cfg(test)]
mod tests {
    use puddle_api::{MemorySettings, SettingsRepoError};
    use serde_json::{Value, json};

    use super::*;

    /// A repo whose reads fail, like a file that cannot be read.
    struct Unreadable;

    impl SettingsRepo for Unreadable {
        fn load_global(&self) -> Result<Option<Value>, SettingsRepoError> {
            Err(SettingsRepoError::new(
                "/data/global.json is not valid JSON",
            ))
        }
        fn save_global(&self, _: Value) -> Result<(), SettingsRepoError> {
            Ok(())
        }
        fn load_workspace(&self, _: &WorkspaceName) -> Result<Option<Value>, SettingsRepoError> {
            Err(SettingsRepoError::new(
                "/data/workspaces/a.json is not valid JSON",
            ))
        }
        fn save_workspace(&self, _: &WorkspaceName, _: Value) -> Result<(), SettingsRepoError> {
            Ok(())
        }
    }

    fn a() -> WorkspaceName {
        WorkspaceName::new("a").unwrap()
    }

    #[test]
    fn the_unreadable_repo_still_accepts_saves() {
        Unreadable.save_global(json!({})).unwrap();
        Unreadable.save_workspace(&a(), json!({})).unwrap();
    }

    #[test]
    fn a_missing_document_is_the_defaults() {
        let repo = MemorySettings::default();
        assert_eq!(global(&repo).unwrap(), GlobalSettings::default());
        assert!(workspace(&repo, &a()).is_ok());
    }

    #[test]
    fn an_unreadable_document_names_the_file() {
        let g = global(&Unreadable).unwrap_err();
        assert!(g.contains("global settings cannot be read"), "{g}");
        assert!(g.contains("/data/global.json"), "{g}");
        let w = workspace(&Unreadable, &a()).unwrap_err();
        assert!(w.contains("workspace a cannot be read"), "{w}");
        assert!(w.contains("/data/workspaces/a.json"), "{w}");
    }

    #[test]
    fn a_document_that_is_not_settings_is_an_error_not_the_defaults() {
        let repo = MemorySettings::default();
        repo.save_global(json!("text")).unwrap();
        repo.save_workspace(&a(), json!([1])).unwrap();
        assert!(global(&repo).unwrap_err().contains("not valid"));
        assert!(workspace(&repo, &a()).unwrap_err().contains("not valid"));
    }
}
