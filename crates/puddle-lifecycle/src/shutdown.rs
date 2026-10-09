// SPDX-License-Identifier: GPL-3.0-or-later
//! The sandboxes puddle runs, and stopping all of them when puddle exits.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use puddle_compute::{ComputeError, Runtime, Sandbox};
use puddle_types::{GuestPath, SandboxName, WorkspaceStatus};
use tokio::task::JoinSet;

use crate::trim::{TrimOutcome, trim_request};

/// Time limits for one sandbox's trim and stop, at shutdown and in [`crate::reconcile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownConfig {
    /// How long `fstrim` may run before the stop goes ahead anyway.
    pub trim_timeout: Duration,
    /// How long a stop may take before puddle gives up on it and reports
    /// [`StopOutcome::TimedOut`]. The msb adapter itself kills a VM that doesn't stop
    /// gracefully within 30 s, so this is a backstop.
    pub stop_timeout: Duration,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            trim_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(45),
        }
    }
}

/// What happened to one sandbox at shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceOutcome {
    /// The sandbox.
    pub sandbox: SandboxName,
    /// The trim before the stop.
    pub trim: TrimOutcome,
    /// The stop.
    pub stop: StopOutcome,
}

/// How a stop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopOutcome {
    /// The runtime stopped it (or it was already down).
    Stopped,
    /// It did not shut down in time and the runtime ended it by force: it is down, but what the
    /// guest had not yet written to disk may be lost.
    Forced,
    /// The runtime refused or failed.
    Failed(ComputeError),
    /// No answer within [`ShutdownConfig::stop_timeout`]. Dropping the owning handle afterwards
    /// still ends the VM.
    TimedOut,
    /// The task that stops it panicked, so it is not known whether the stop was clean. The
    /// task's handle was dropped, which ends the VM without a stop.
    Panicked,
}

impl StopOutcome {
    /// Why the stop did not work, or `None` when it did.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        match self {
            Self::Stopped => None,
            Self::Forced => Some(
                "it did not shut down in time and was ended by force; files it had not written \
                 yet may be missing"
                    .to_owned(),
            ),
            Self::Failed(e) => Some(e.to_string()),
            Self::TimedOut => Some("no answer to the stop".to_owned()),
            Self::Panicked => Some("the task that stops it panicked".to_owned()),
        }
    }
}

/// What [`Lifecycle::shutdown`] did, one entry per sandbox in name order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Per sandbox.
    pub sandboxes: Vec<WorkspaceOutcome>,
}

impl ShutdownReport {
    /// Whether every sandbox stopped cleanly (none was ended by force, failed or timed out).
    #[must_use]
    pub fn all_stopped(&self) -> bool {
        self.sandboxes
            .iter()
            .all(|s| s.stop == StopOutcome::Stopped)
    }

    /// Each sandbox whose disk was not trimmed before the stop, with the reason. The stop went
    /// ahead; the disk file stays larger than its data until a later trim.
    #[must_use]
    pub fn untrimmed(&self) -> Vec<(&SandboxName, String)> {
        self.sandboxes
            .iter()
            .filter_map(|s| Some((&s.sandbox, s.trim.problem()?)))
            .collect()
    }

    /// Each sandbox that was not stopped cleanly, with the reason.
    #[must_use]
    pub fn unstopped(&self) -> Vec<(&SandboxName, String)> {
        self.sandboxes
            .iter()
            .filter_map(|s| Some((&s.sandbox, s.stop.problem()?)))
            .collect()
    }
}

struct Managed<S> {
    handle: S,
    trim: Vec<GuestPath>,
}

struct State<S> {
    sandboxes: BTreeMap<SandboxName, Managed<S>>,
    closed: bool,
}

/// The owning handles of the sandboxes puddle runs. Each one is trimmed and stopped by
/// [`Lifecycle::shutdown`]; until then dropping the `Lifecycle` (or puddle dying) ends the VMs
/// without a stop.
pub struct Lifecycle<R: Runtime> {
    runtime: R,
    config: ShutdownConfig,
    state: Mutex<State<R::Sandbox>>,
}

impl<R: Runtime> std::fmt::Debug for Lifecycle<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lifecycle")
            .field("config", &self.config)
            .field("managed", &self.managed())
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> Lifecycle<R> {
    /// A lifecycle over `runtime` with no sandboxes yet.
    pub fn new(runtime: R, config: ShutdownConfig) -> Self {
        Self {
            runtime,
            config,
            state: Mutex::new(State {
                sandboxes: BTreeMap::new(),
                closed: false,
            }),
        }
    }

    /// The runtime.
    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    /// The time limits.
    pub fn config(&self) -> &ShutdownConfig {
        &self.config
    }

    fn lock(&self) -> MutexGuard<'_, State<R::Sandbox>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes over `handle` (from [`Runtime::create`] or [`Runtime::start`]) until shutdown. At
    /// shutdown `fstrim` runs on `trim` (the workspace mount, say), or on every mounted
    /// filesystem when `trim` is empty. A handle for the same name replaces the older one, which
    /// is returned (dropping it may end the VM if it was an owning handle of an older boot).
    ///
    /// # Errors
    ///
    /// Gives `handle` back once [`Lifecycle::shutdown`] has started; the caller stops or drops
    /// it.
    pub fn manage(
        &self,
        handle: R::Sandbox,
        trim: Vec<GuestPath>,
    ) -> Result<Option<R::Sandbox>, R::Sandbox> {
        let mut state = self.lock();
        if state.closed {
            return Err(handle);
        }
        let name = handle.name().clone();
        Ok(state
            .sandboxes
            .insert(name, Managed { handle, trim })
            .map(|old| old.handle))
    }

    /// Gives back the handle of `name` (an explicit stop or remove by the user), or `None`.
    pub fn release(&self, name: &SandboxName) -> Option<R::Sandbox> {
        self.lock().sandboxes.remove(name).map(|m| m.handle)
    }

    /// The managed sandboxes, in name order.
    pub fn managed(&self) -> Vec<SandboxName> {
        self.lock().sandboxes.keys().cloned().collect()
    }

    /// Trims and stops every managed sandbox, all at once, and refuses new ones from now on.
    /// Never fails as a whole: each sandbox's outcome is in the report. A second call finds
    /// nothing left to stop.
    pub async fn shutdown(&self) -> ShutdownReport {
        let sandboxes = {
            let mut state = self.lock();
            state.closed = true;
            std::mem::take(&mut state.sandboxes)
        };
        tracing::info!(count = sandboxes.len(), "shutdown: stopping every sandbox");
        let mut tasks = JoinSet::new();
        let mut names = BTreeMap::new();
        for (name, managed) in sandboxes {
            let config = self.config.clone();
            let task_name = name.clone();
            let task = tasks.spawn(async move {
                let (trim, stop) = trim_and_stop(&managed.handle, &managed.trim, &config).await;
                WorkspaceOutcome {
                    sandbox: task_name,
                    trim,
                    stop,
                }
            });
            names.insert(task.id(), name);
        }
        let mut report = ShutdownReport::default();
        while let Some(joined) = tasks.join_next_with_id().await {
            match joined {
                Ok((_, outcome)) => report.sandboxes.push(outcome),
                // A panicking stop dropped its handle, which ends the VM. It is reported under
                // its name as not stopped, so the exit says so.
                Err(e) => {
                    tracing::error!(error = %e, "shutdown: a stop task failed");
                    if let Some(sandbox) = names.remove(&e.id()) {
                        report.sandboxes.push(WorkspaceOutcome {
                            sandbox,
                            trim: TrimOutcome::Error("the stop task panicked".to_owned()),
                            stop: StopOutcome::Panicked,
                        });
                    }
                }
            }
        }
        report.sandboxes.sort_by(|a, b| a.sandbox.cmp(&b.sandbox));
        report
    }
}

/// `fstrim` (when the sandbox runs), then stop, each within its time limit. Shared by shutdown
/// and by reconcile's orphan stop.
pub(crate) async fn trim_and_stop<S: Sandbox>(
    sandbox: &S,
    paths: &[GuestPath],
    config: &ShutdownConfig,
) -> (TrimOutcome, StopOutcome) {
    let name = sandbox.name().clone();
    let trim = match sandbox.status().await {
        Ok(WorkspaceStatus::Running) => {
            let request = trim_request(paths, config.trim_timeout);
            // The exec has its own timeout; the outer one also covers a runtime that hangs.
            match tokio::time::timeout(config.trim_timeout, sandbox.exec(request)).await {
                Ok(Ok(out)) => TrimOutcome::from_output(&out),
                Ok(Err(e)) => TrimOutcome::Error(e.to_string()),
                Err(_) => TrimOutcome::Error(format!("no answer within {:?}", config.trim_timeout)),
            }
        }
        Ok(_) => TrimOutcome::NotRunning,
        Err(e) => TrimOutcome::Error(e.to_string()),
    };
    match &trim {
        TrimOutcome::Trimmed | TrimOutcome::NotRunning => {
            tracing::debug!(sandbox = %name, ?trim, "trim before stop");
        }
        _ => tracing::warn!(sandbox = %name, ?trim, "trim before stop failed; stopping anyway"),
    }
    let stop = match tokio::time::timeout(config.stop_timeout, sandbox.stop()).await {
        Ok(Ok(())) if sandbox.stopped_by_force() => StopOutcome::Forced,
        Ok(Ok(())) => StopOutcome::Stopped,
        Ok(Err(e)) => StopOutcome::Failed(e),
        Err(_) => StopOutcome::TimedOut,
    };
    match &stop {
        StopOutcome::Stopped => tracing::info!(sandbox = %name, "sandbox stopped"),
        StopOutcome::Forced => tracing::error!(sandbox = %name, "sandbox ended by force"),
        StopOutcome::Failed(e) => tracing::error!(sandbox = %name, error = %e, "stop failed"),
        StopOutcome::TimedOut => {
            tracing::error!(sandbox = %name, timeout = ?config.stop_timeout, "stop timed out");
        }
        // Only `Lifecycle::shutdown` makes this one, when the task that ran this function died.
        StopOutcome::Panicked => {}
    }
    (trim, stop)
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use puddle_compute::{ExecOutput, ExecRequest, SshStream};

    use super::*;

    /// A sandbox whose exec and stop never answer (a hung runtime).
    struct Hung(SandboxName);

    impl Sandbox for Hung {
        fn name(&self) -> &SandboxName {
            &self.0
        }

        fn owns_lifecycle(&self) -> bool {
            true
        }

        fn status(&self) -> impl Future<Output = Result<WorkspaceStatus, ComputeError>> + Send {
            std::future::ready(Ok(WorkspaceStatus::Running))
        }

        fn stop(&self) -> impl Future<Output = Result<(), ComputeError>> + Send {
            std::future::pending()
        }

        fn exec(
            &self,
            _request: ExecRequest,
        ) -> impl Future<Output = Result<ExecOutput, ComputeError>> + Send {
            std::future::pending()
        }

        fn serve_ssh<S: SshStream>(
            &self,
            _stream: S,
        ) -> impl Future<Output = Result<(), ComputeError>> + Send {
            std::future::pending()
        }
    }

    #[test]
    fn every_way_a_stop_goes_wrong_has_a_reason_and_a_clean_stop_has_none() {
        let failed = ComputeError::Runtime {
            op: "stop",
            message: "stuck".to_owned(),
        };
        assert_eq!(StopOutcome::Stopped.problem(), None);
        assert!(
            StopOutcome::Failed(failed)
                .problem()
                .unwrap()
                .contains("stuck")
        );
        assert!(
            StopOutcome::TimedOut
                .problem()
                .unwrap()
                .contains("no answer")
        );
        assert!(StopOutcome::Forced.problem().unwrap().contains("by force"));
        assert!(
            StopOutcome::Panicked
                .problem()
                .unwrap()
                .contains("panicked")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_trim_and_stop_time_out_in_order() {
        let config = ShutdownConfig {
            trim_timeout: Duration::from_secs(3),
            stop_timeout: Duration::from_secs(5),
        };
        let hung = Hung(SandboxName::new("hung").unwrap());
        let start = tokio::time::Instant::now();
        let (trim, stop) = trim_and_stop(&hung, &[], &config).await;
        assert!(matches!(trim, TrimOutcome::Error(ref e) if e.contains("no answer")));
        assert_eq!(stop, StopOutcome::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_secs(8));
        assert!(hung.owns_lifecycle());
        // A runtime that does not say counts as not forced.
        assert!(!hung.stopped_by_force());
    }
}
