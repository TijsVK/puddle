// SPDX-License-Identifier: GPL-3.0-or-later
//! The background sweeper (`docs/spec/rules.md` §4): one pass at start, then one per period.

use std::sync::Arc;
use std::time::Duration;

use puddle_types::{NullSink, Problem, Problems};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::store::Store;

/// How often the sweeper runs by default (R-19).
pub const DEFAULT_SWEEP_PERIOD: Duration = Duration::from_secs(60);

/// The key of the problem a failed sweep raises.
pub const SWEEP_PROBLEM: &str = "sweeper";

fn sweep_problem(reason: &str) -> Problem {
    Problem::new(
        SWEEP_PROBLEM,
        "puddle could not tidy up its rules and activity log",
        format!(
            "{reason}. Rules that expired keep applying, and the activity log is not trimmed or \
             completed, until it works; puddle tries again every minute. A full disk is the usual \
             cause: free some space."
        ),
    )
}

/// A running sweeper. Its owner ends it with [`Sweeper::shutdown`]; dropping the handle also
/// stops it after the current pass.
#[derive(Debug)]
pub struct Sweeper {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Sweeper {
    /// Starts sweeping `store` every `period` on the current tokio runtime. Each pass runs on a
    /// blocking thread; a failed pass is logged and retried next period.
    #[must_use]
    pub fn spawn(store: Arc<Store>, period: Duration) -> Self {
        Self::spawn_reporting(store, period, Arc::new(Problems::new(Arc::new(NullSink))))
    }

    /// Like [`Sweeper::spawn`], and a failed pass raises the problem [`SWEEP_PROBLEM`] in
    /// `problems`, which the next pass that works ends.
    #[must_use]
    pub fn spawn_reporting(store: Arc<Store>, period: Duration, problems: Arc<Problems>) -> Self {
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let pass = Arc::clone(&store);
                // A pass that failed and a pass that panicked are the same to the user.
                let pass = tokio::task::spawn_blocking(move || pass.sweep())
                    .await
                    .map_err(|err| err.to_string())
                    .and_then(|swept| swept.map_err(|err| err.to_string()));
                match pass {
                    Ok(report) => {
                        tracing::debug!(?report, "sweep done");
                        problems.clear(SWEEP_PROBLEM);
                    }
                    Err(reason) => problems.raise(sweep_problem(&reason)),
                }
                tokio::select! {
                    () = tokio::time::sleep(period) => {}
                    _ = &mut stopped => break,
                }
            }
        });
        Self { stop, task }
    }

    /// Stops the sweeper and waits for its current pass to finish.
    pub async fn shutdown(self) {
        // The task may already have ended; then there is no one to tell.
        let _ = self.stop.send(());
        if let Err(err) = self.task.await {
            tracing::warn!(%err, "sweeper ended abnormally");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::{Actor, Effect, Limits, NewRule, Pattern, Scope};

    /// A rule that has expired, so the next pass has to write a `rule_expired` record.
    fn store_with_an_expired_rule() -> Arc<Store> {
        let clock = Arc::new(ManualClock::new(1_000_000));
        let store = Arc::new(Store::open_in_memory(clock.clone(), Limits::default()).unwrap());
        store
            .add_rule(&NewRule {
                scope: Scope::Global,
                pattern: Pattern::parse("old.example").unwrap(),
                effect: Effect::Allow,
                expires_at: Some(1_000_100),
                created_by: Actor::Cli,
            })
            .unwrap();
        clock.advance(1_000);
        store
    }

    async fn until(what: &str, mut done: impl FnMut() -> bool) {
        for _ in 0..500 {
            if done() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(done(), "timed out waiting for {what}");
    }

    #[tokio::test]
    async fn a_sweep_that_cannot_write_is_a_problem_until_one_works() {
        let store = store_with_an_expired_rule();
        store.fail_audit_writes("rule_expired");
        let problems = Arc::new(Problems::new(Arc::new(NullSink)));
        let sweeper =
            Sweeper::spawn_reporting(store.clone(), Duration::from_millis(20), problems.clone());
        until("the sweep problem", || !problems.list().is_empty()).await;
        let problem = problems.list().remove(0);
        assert_eq!(problem.key, SWEEP_PROBLEM);
        assert!(problem.detail.contains("disk full"), "{problem:?}");
        assert!(problem.detail.contains("free some space"), "{problem:?}");
        store.audit_writes_work_again();
        until("the problem to end", || problems.list().is_empty()).await;
        sweeper.shutdown().await;
        assert_eq!(store.rules().len(), 0, "the rule was removed in the end");
    }
}
