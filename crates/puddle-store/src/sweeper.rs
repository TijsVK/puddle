// SPDX-License-Identifier: GPL-3.0-or-later
//! The background sweeper (`docs/spec/rules.md` §4): one pass at start, then one per period.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::store::Store;

/// How often the sweeper runs by default (R-19).
pub const DEFAULT_SWEEP_PERIOD: Duration = Duration::from_secs(60);

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
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let pass = Arc::clone(&store);
                match tokio::task::spawn_blocking(move || pass.sweep()).await {
                    Ok(Ok(report)) => tracing::debug!(?report, "sweep done"),
                    Ok(Err(err)) => tracing::warn!(%err, "sweep failed"),
                    Err(err) => tracing::warn!(%err, "sweep task failed"),
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
