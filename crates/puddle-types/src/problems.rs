// SPDX-License-Identifier: GPL-3.0-or-later
//! Background problems the user should hear about: something puddle does on its own (a sweep, a
//! clean-up, a start-up step) failed, and nobody asked for it, so no request can carry the error.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{Event, EventSink, WorkspaceName};

/// One background problem, as `GET /api/problems` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Problem {
    /// Names the problem; raising it again replaces the old one, and it ends with
    /// [`Problems::clear`].
    pub key: String,
    /// The workspace it is about, or `null` when it is about puddle.
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub workspace: Option<WorkspaceName>,
    /// What went wrong, in one line. It can quote tool output: escape it when rendering.
    pub title: String,
    /// What puddle did about it and what the user can do. It can quote tool output: escape it
    /// when rendering.
    pub detail: String,
}

impl Problem {
    /// A problem about puddle.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            workspace: None,
            title: title.into(),
            detail: detail.into(),
        }
    }

    /// The same problem, about `workspace`.
    #[must_use]
    pub fn about(mut self, workspace: WorkspaceName) -> Self {
        self.workspace = Some(workspace);
        self
    }
}

/// The problems that stand now. A client reads them with `GET /api/problems` and rereads on
/// [`Event::ProblemsChanged`], so one that came before the client connected is not missed.
pub struct Problems {
    open: Mutex<BTreeMap<String, Problem>>,
    events: Arc<dyn EventSink>,
}

impl std::fmt::Debug for Problems {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Problems").finish_non_exhaustive()
    }
}

impl Problems {
    /// An empty list that announces its changes to `events`.
    #[must_use]
    pub fn new(events: Arc<dyn EventSink>) -> Self {
        Self {
            open: Mutex::default(),
            events,
        }
    }

    /// Raises `problem`, replacing one with the same key, and logs it. Announces a change only
    /// when the list differs, so a problem that repeats every minute is not announced every
    /// minute.
    pub fn raise(&self, problem: Problem) {
        tracing::warn!(key = %problem.key, title = %problem.title, detail = %problem.detail, "problem raised");
        let changed = {
            let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
            let changed = open.get(&problem.key) != Some(&problem);
            if changed {
                open.insert(problem.key.clone(), problem);
            }
            changed
        };
        if changed {
            self.events.emit(Event::ProblemsChanged {});
        }
    }

    /// Ends the problem `key` (its cause went away); does nothing when there is none.
    pub fn clear(&self, key: &str) {
        let removed = self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key)
            .is_some();
        if removed {
            self.events.emit(Event::ProblemsChanged {});
        }
    }

    /// Ends every problem whose key starts with `prefix` (for example all of a workspace's).
    pub fn clear_prefix(&self, prefix: &str) {
        let removed = {
            let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
            let before = open.len();
            open.retain(|key, _| !key.starts_with(prefix));
            open.len() != before
        };
        if removed {
            self.events.emit(Event::ProblemsChanged {});
        }
    }

    /// The problems that stand, ordered by key.
    #[must_use]
    pub fn list(&self) -> Vec<Problem> {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CollectingSink;

    fn problems() -> (Arc<CollectingSink>, Problems) {
        let sink = Arc::new(CollectingSink::default());
        (sink.clone(), Problems::new(sink))
    }

    #[test]
    fn a_problem_is_listed_until_it_is_cleared_and_each_change_is_announced_once() {
        let (sink, problems) = problems();
        let first = Problem::new("sweep", "The sweep failed", "It tries again in a minute.");
        problems.raise(first.clone());
        problems.raise(first.clone());
        assert_eq!(problems.list(), [first]);
        assert_eq!(sink.take(), [Event::ProblemsChanged {}]);
        problems.raise(Problem::new("sweep", "The sweep failed", "Disk full."));
        assert_eq!(sink.take(), [Event::ProblemsChanged {}]);
        problems.clear("sweep");
        problems.clear("sweep");
        assert_eq!(problems.list().len(), 0);
        assert_eq!(sink.take(), [Event::ProblemsChanged {}]);
    }

    #[test]
    fn clearing_by_prefix_ends_only_the_matching_problems() {
        let (_, problems) = problems();
        let box_name = WorkspaceName::new("box").unwrap();
        problems.raise(Problem::new("git-locks:box", "a", "b").about(box_name.clone()));
        problems.raise(Problem::new("git-locks:other", "a", "b"));
        problems.clear_prefix("git-locks:box");
        let keys: Vec<_> = problems.list().into_iter().map(|p| p.key).collect();
        assert_eq!(keys, ["git-locks:other"]);
        assert!(format!("{problems:?}").starts_with("Problems"));
    }
}
