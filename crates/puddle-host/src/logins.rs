// SPDX-License-Identifier: GPL-3.0-or-later
//! The host's side of captured logins: one [`Logins`] for each start of a workspace's sandbox, the
//! credential store its real tokens are kept in, and the notice that goes to the user when a
//! login cannot be captured.
//!
//! The capture itself is the `puddle-logins` crate's, and the swap is the proxy's. What belongs
//! here is the wiring: whether the workspace has capture on (its setting, read when it starts),
//! the registry of stand-ins the workspace's termination swaps from (shared with everything else
//! that makes stand-ins), the hosts the workspace decrypts for its logins, and the deletion of
//! the real tokens with the workspace.

use std::sync::Arc;

use puddle_logins::{LoginNotices, Logins, Problem, Profile, builtin};
use puddle_proxy::StandIns;
use puddle_secrets::SecretStore;
use puddle_settings::resolve;
use puddle_types::{Event, EventSink, LoginProblemKind, WorkspaceName};

use crate::settings_read;

/// Turns what `puddle-logins` reports into the event the user's screens show a notice for.
struct EventNotices {
    events: Arc<dyn EventSink>,
}

impl LoginNotices for EventNotices {
    fn problem(&self, workspace: &WorkspaceName, profile: &Profile, problem: Problem) {
        self.events.emit(Event::LoginProblem {
            workspace: workspace.clone(),
            service: profile.name.to_owned(),
            kind: kind_of(problem),
        });
    }
}

/// The wire name of a problem. A problem this version does not know is the most general one,
/// which still says the login is not protected.
fn kind_of(problem: Problem) -> LoginProblemKind {
    match problem {
        Problem::StoreUnavailable => LoginProblemKind::StoreUnavailable,
        Problem::UnusableToken => LoginProblemKind::UnusableToken,
        Problem::BoundToken => LoginProblemKind::BoundToken,
        Problem::Unreadable => LoginProblemKind::Unreadable,
        // `UnexpectedAnswer` and any problem a later version adds.
        _ => LoginProblemKind::UnexpectedAnswer,
    }
}

/// What makes a workspace's [`Logins`].
#[derive(Clone)]
pub(crate) struct LoginKeeper {
    /// Where the real tokens are kept: the operating system's credential store.
    store: Arc<dyn SecretStore>,
    events: Arc<dyn EventSink>,
}

impl LoginKeeper {
    pub(crate) fn new(store: Arc<dyn SecretStore>, events: Arc<dyn EventSink>) -> Self {
        Self { store, events }
    }

    /// The captured logins of `workspace` for this start, swapping from `registry`. With
    /// `enabled` false nothing is captured and nothing is decrypted for logins.
    pub(crate) fn logins(
        &self,
        workspace: &WorkspaceName,
        enabled: bool,
        registry: Arc<StandIns>,
    ) -> Logins {
        Logins::new(
            workspace.clone(),
            enabled,
            builtin(),
            registry,
            Arc::clone(&self.store),
            Arc::new(EventNotices {
                events: Arc::clone(&self.events),
            }),
        )
    }

    /// Deletes every token kept for a deleted `workspace`. The workspace is gone either way: a
    /// token that stays behind is unreachable (nothing names it any more) and is only logged.
    pub(crate) async fn delete_workspace(&self, workspace: &WorkspaceName) {
        let (store, name) = (Arc::clone(&self.store), workspace.clone());
        let failed =
            tokio::task::spawn_blocking(move || Logins::delete_workspace(&store, &name, builtin()))
                .await
                .unwrap_or(usize::MAX);
        if failed > 0 {
            tracing::warn!(%workspace, failed, "a deleted workspace's saved logins could not be removed from the credential store");
        }
    }
}

/// Whether `workspace` captures logins: its own setting, else the global one, else on. Settings
/// that cannot be read count as on (the safer reading: puddle keeps the token), with the reason
/// logged.
pub(crate) fn capture_enabled(
    settings: &dyn puddle_api::SettingsRepo,
    workspace: &WorkspaceName,
) -> bool {
    let read = || -> Result<bool, String> {
        let global = settings_read::global(settings)?;
        let own = settings_read::workspace(settings, workspace)?;
        Ok(resolve(&global, Some(&own)).capture_logins.value)
    };
    read().unwrap_or_else(|reason| {
        tracing::warn!(%workspace, %reason, "login capture stays on: the settings cannot be read");
        true
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use puddle_api::{MemorySettings, SettingsRepo};
    use puddle_secrets::MemoryStore;
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct Events(Mutex<Vec<Event>>);

    impl EventSink for Events {
        fn emit(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    fn workspace(name: &str) -> WorkspaceName {
        WorkspaceName::new(name).unwrap()
    }

    #[test]
    fn each_problem_becomes_the_event_that_names_it_with_the_service_as_the_user_knows_it() {
        let events = Arc::new(Events::default());
        let notices = EventNotices {
            events: events.clone(),
        };
        let all = [
            (
                Problem::StoreUnavailable,
                LoginProblemKind::StoreUnavailable,
            ),
            (
                Problem::UnexpectedAnswer,
                LoginProblemKind::UnexpectedAnswer,
            ),
            (Problem::UnusableToken, LoginProblemKind::UnusableToken),
            (Problem::BoundToken, LoginProblemKind::BoundToken),
            (Problem::Unreadable, LoginProblemKind::Unreadable),
        ];
        for (problem, _) in all {
            notices.problem(&workspace("alpha"), &builtin()[0], problem);
        }
        let sent = events.0.lock().unwrap();
        for ((_, kind), event) in all.iter().zip(sent.iter()) {
            assert_eq!(
                *event,
                Event::LoginProblem {
                    workspace: workspace("alpha"),
                    service: "Claude Code".into(),
                    kind: *kind,
                }
            );
        }
        assert_eq!(sent.len(), 5);
    }

    #[tokio::test]
    async fn a_workspace_gets_logins_over_its_own_registry_and_capture_decides_what_it_decrypts() {
        let store = Arc::new(MemoryStore::new());
        let events = Arc::new(Events::default());
        let keeper = LoginKeeper::new(store, events.clone());
        let registry = Arc::new(StandIns::new());
        let on = keeper.logins(&workspace("alpha"), true, Arc::clone(&registry));
        assert!(!on.hosts().is_empty());
        let off = keeper.logins(&workspace("alpha"), false, registry);
        assert!(off.hosts().is_empty());
        // Nothing is kept, so loading says nothing.
        on.load().await;
        assert!(events.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_a_workspace_with_a_credential_store_that_refuses_is_only_logged() {
        let store = Arc::new(MemoryStore::new());
        let keeper = LoginKeeper::new(store.clone(), Arc::new(Events::default()));
        keeper.delete_workspace(&workspace("alpha")).await;
        store.break_it();
        keeper.delete_workspace(&workspace("alpha")).await;
    }

    #[test]
    fn capture_is_on_unless_the_workspace_or_the_global_setting_turns_it_off() {
        let repo = MemorySettings::default();
        let ws = workspace("alpha");
        assert!(capture_enabled(&repo, &ws));
        repo.save_global(json!({"workspace_defaults": {"capture_logins": false}}))
            .unwrap();
        assert!(!capture_enabled(&repo, &ws));
        repo.save_workspace(&ws, json!({"overrides": {"capture_logins": true}}))
            .unwrap();
        assert!(capture_enabled(&repo, &ws));
        assert!(!capture_enabled(&repo, &workspace("beta")));
    }

    #[test]
    fn settings_that_cannot_be_read_leave_capture_on() {
        let repo = MemorySettings::default();
        repo.save_global(json!("not settings")).unwrap();
        assert!(capture_enabled(&repo, &workspace("alpha")));
    }
}
