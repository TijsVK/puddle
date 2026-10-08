// SPDX-License-Identifier: GPL-3.0-or-later
//! Following the events of the store for changes to a workspace's Git settings, so that a change
//! applies to the running workspace at once.

use std::future::Future;

use puddle_store::WorkspaceGit;
use puddle_types::{Event, WorkspaceName};
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tokio::task::{JoinHandle, JoinSet};

/// What a running workspace does with a change to its Git settings.
pub(crate) trait GitChanges: Clone + Send + Sync + 'static {
    /// Recomputes what the workspace decrypts, which is quick and must not wait for anything. The
    /// settings when the workspace runs, else `None`.
    fn decrypt_changed(&self, workspace: &WorkspaceName) -> Option<WorkspaceGit>;

    /// Brings the commit authors in the workspace's guest in line with `git`, which can take as
    /// long as the guest needs to answer.
    fn rewrite_authors(
        &self,
        workspace: WorkspaceName,
        git: WorkspaceGit,
    ) -> impl Future<Output = ()> + Send;

    /// Looks at every running workspace again, after events were missed.
    fn all_git_changed(&self) -> impl Future<Output = ()> + Send;
}

/// Applies each [`Event::WorkspaceGitChanged`] of `events` to `service` until the task is
/// aborted. The decrypt set follows in the order the changes arrive; the guest rewrites run on
/// their own, so a guest that is slow to answer delays only itself.
pub(crate) fn follow<G: GitChanges>(mut events: Receiver<Event>, service: G) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rewrites = JoinSet::new();
        loop {
            tokio::select! {
                event = events.recv() => match event {
                    Ok(Event::WorkspaceGitChanged { workspace }) => {
                        if let Some(git) = service.decrypt_changed(&workspace) {
                            let service = service.clone();
                            rewrites.spawn(async move {
                                service.rewrite_authors(workspace, git).await;
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => service.all_git_changed().await,
                    Err(RecvError::Closed) => break,
                },
                Some(_) = rewrites.join_next() => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use puddle_api::EventHub;
    use puddle_types::EventSink;

    use super::*;

    #[derive(Clone, Default)]
    struct Fake {
        calls: Arc<Mutex<Vec<String>>>,
        running: Arc<Mutex<Vec<String>>>,
    }

    impl GitChanges for Fake {
        fn decrypt_changed(&self, workspace: &WorkspaceName) -> Option<WorkspaceGit> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("decrypt {workspace}"));
            self.running
                .lock()
                .unwrap()
                .contains(&workspace.to_string())
                .then(WorkspaceGit::unconfigured)
        }

        async fn rewrite_authors(&self, workspace: WorkspaceName, _: WorkspaceGit) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("rewrite {workspace}"));
        }

        async fn all_git_changed(&self) {
            self.calls.lock().unwrap().push("all".to_owned());
        }
    }

    async fn calls_after(fake: &Fake, want: usize) -> Vec<String> {
        for _ in 0..500 {
            if fake.calls.lock().unwrap().len() >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut calls = fake.calls.lock().unwrap().clone();
        calls.sort();
        calls
    }

    fn changed(name: &str) -> Event {
        Event::WorkspaceGitChanged {
            workspace: WorkspaceName::new(name).unwrap(),
        }
    }

    #[tokio::test]
    async fn a_change_to_a_running_workspace_recomputes_its_decrypt_set_and_rewrites_its_authors() {
        let hub = EventHub::default();
        let fake = Fake::default();
        fake.running.lock().unwrap().push("alpha".to_owned());
        let task = follow(hub.subscribe(), fake.clone());
        hub.emit(Event::RulesChanged {});
        hub.emit(changed("alpha"));
        hub.emit(changed("beta"));
        // beta does not run: its set is looked at (it has none) and nothing is rewritten.
        assert_eq!(
            calls_after(&fake, 3).await,
            ["decrypt alpha", "decrypt beta", "rewrite alpha"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn missed_events_make_every_running_workspace_be_looked_at_again() {
        // A hub that holds one event: sending three before the task runs makes it lag.
        let hub = EventHub::new(1);
        let fake = Fake::default();
        let task = follow(hub.subscribe(), fake.clone());
        for name in ["a", "b", "c"] {
            hub.emit(changed(name));
        }
        assert!(calls_after(&fake, 1).await.contains(&"all".to_owned()));
        task.abort();
    }

    #[tokio::test]
    async fn the_task_ends_when_the_hub_is_gone() {
        let hub = EventHub::default();
        let task = follow(hub.subscribe(), Fake::default());
        drop(hub);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
