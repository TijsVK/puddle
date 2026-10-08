// SPDX-License-Identifier: GPL-3.0-or-later
//! The readiness gate: no SSH and no exec for anyone until the boot hook has returned 0.
//!
//! ```text
//!          create/start/adopt                hook exits 0
//!   Down ──────────────────────► Booting ──────────────────► Ready
//!    ▲                              │                          │
//!    │                              │ hook fails               │ stop
//!    │                              ▼                          │
//!    └────────── stop ─────────  Failed(stderr) ◄──────────────┘ (next boot: Booting again)
//! ```
//!
//! Callers that arrive while the sandbox is `Booting` wait (up to a limit), so an IDE that
//! connects during the ~1 s hook just sees a slower first connect. `Down` and `Failed` refuse at
//! once; `Failed` carries the hook's stderr so the user sees why.

use std::sync::Arc;
use std::time::Duration;

use puddle_compute::{ComputeError, ExecOutput, ExecRequest, Sandbox, SshStream};
use puddle_types::{SandboxName, WorkspaceStatus};
use tokio::sync::{Mutex, MutexGuard, watch};

use crate::hook::{BootFailure, BootReport};

/// Where a sandbox is in its boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateState {
    /// Not running (never booted, stopped, or the boot never got going).
    Down,
    /// Created or started; the boot hook hasn't finished.
    Booting,
    /// The hook returned 0: SSH and exec are served.
    Ready,
    /// The hook failed; the sandbox was stopped.
    Failed(BootFailure),
}

/// Why a gated call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotReady {
    /// The sandbox isn't running.
    #[error("workspace is not running")]
    Down,
    /// The boot hook failed.
    #[error("workspace failed to boot: {0}")]
    Failed(BootFailure),
    /// Still booting after the wait limit.
    #[error("workspace is still booting after {waited:?}")]
    Timeout {
        /// How long the call waited.
        waited: Duration,
    },
}

/// The readiness gate of one sandbox. It outlives boots: create it once per sandbox and pass it
/// to every [`crate::BootHook`] call for that sandbox. Clones share the state.
#[derive(Debug, Clone)]
pub struct Gate {
    state: Arc<watch::Sender<GateState>>,
    boot: Arc<Mutex<()>>,
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

impl Gate {
    /// A gate in [`GateState::Down`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(watch::Sender::new(GateState::Down)),
            boot: Arc::new(Mutex::new(())),
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> GateState {
        self.state.borrow().clone()
    }

    /// Returns once the sandbox is [`GateState::Ready`]; waits up to `limit` while it is
    /// booting.
    ///
    /// # Errors
    ///
    /// [`NotReady::Down`] or [`NotReady::Failed`] at once; [`NotReady::Timeout`] when it is
    /// still booting after `limit`.
    pub async fn wait_ready(&self, limit: Duration) -> Result<(), NotReady> {
        let mut rx = self.state.subscribe();
        let settled =
            tokio::time::timeout(limit, rx.wait_for(|s| !matches!(s, GateState::Booting))).await;
        match settled {
            Err(_) => Err(NotReady::Timeout { waited: limit }),
            // The sender lives in `self`, so the channel can't close while we wait.
            Ok(Err(_)) => Err(NotReady::Down),
            Ok(Ok(state)) => match &*state {
                GateState::Ready => Ok(()),
                GateState::Failed(f) => Err(NotReady::Failed(f.clone())),
                GateState::Down | GateState::Booting => Err(NotReady::Down),
            },
        }
    }

    /// Closes the gate ([`GateState::Down`]), e.g. when puddle finds the VM gone.
    pub fn close(&self) {
        self.set(GateState::Down);
    }

    pub(crate) fn set(&self, state: GateState) {
        self.state.send_replace(state);
    }

    /// Serialises boots of one sandbox, so two hook runs never overlap.
    pub(crate) async fn lock_boot(&self) -> MutexGuard<'_, ()> {
        self.boot.lock().await
    }
}

/// A gated call failed: refused by the gate, or by the runtime.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatedError {
    /// The gate refused it.
    #[error("workspace {sandbox:?}: {reason}")]
    NotReady {
        /// The sandbox.
        sandbox: String,
        /// Why.
        reason: NotReady,
    },
    /// The runtime failed it.
    #[error(transparent)]
    Compute(#[from] ComputeError),
}

/// A booted sandbox whose exec and SSH go through its [`Gate`]. This is the handle the rest of
/// puddle (SSH endpoint, API) uses; only puddle's own maintenance goes around the gate.
#[derive(Debug)]
pub struct GatedSandbox<S> {
    inner: S,
    gate: Gate,
    ready_wait: Duration,
    report: BootReport,
}

impl<S: Sandbox> GatedSandbox<S> {
    pub(crate) fn new(inner: S, gate: Gate, ready_wait: Duration, report: BootReport) -> Self {
        Self {
            inner,
            gate,
            ready_wait,
            report,
        }
    }

    /// The sandbox's name.
    #[must_use]
    pub fn name(&self) -> &SandboxName {
        self.inner.name()
    }

    /// Its gate.
    #[must_use]
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// What the hook reported for this boot.
    #[must_use]
    pub fn boot_report(&self) -> &BootReport {
        &self.report
    }

    async fn pass(&self) -> Result<(), GatedError> {
        self.gate
            .wait_ready(self.ready_wait)
            .await
            .map_err(|reason| GatedError::NotReady {
                sandbox: self.name().to_string(),
                reason,
            })
    }

    /// Runs a command once the gate is open.
    ///
    /// # Errors
    ///
    /// [`GatedError::NotReady`]; [`GatedError::Compute`] from [`Sandbox::exec`].
    pub async fn exec(&self, request: ExecRequest) -> Result<ExecOutput, GatedError> {
        self.pass().await?;
        Ok(self.inner.exec(request).await?)
    }

    /// Serves one SSH connection once the gate is open.
    ///
    /// # Errors
    ///
    /// [`GatedError::NotReady`]; [`GatedError::Compute`] from [`Sandbox::serve_ssh`].
    pub async fn serve_ssh<T: SshStream>(&self, stream: T) -> Result<(), GatedError> {
        self.pass().await?;
        Ok(self.inner.serve_ssh(stream).await?)
    }

    /// The sandbox's state (not gated).
    ///
    /// # Errors
    ///
    /// From [`Sandbox::status`].
    pub async fn status(&self) -> Result<WorkspaceStatus, ComputeError> {
        self.inner.status().await
    }

    /// Closes the gate, then stops the VM.
    ///
    /// # Errors
    ///
    /// From [`Sandbox::stop`].
    pub async fn stop(&self) -> Result<(), ComputeError> {
        self.gate.close();
        self.inner.stop().await
    }

    /// The handle without the gate, for puddle's own maintenance only (`fstrim` before a stop).
    /// Never hand it to a user-facing path.
    #[must_use]
    pub fn ungated(&self) -> &S {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn down_and_failed_refuse_at_once_ready_passes() {
        let gate = Gate::default();
        assert_eq!(gate.state(), GateState::Down);
        let long = Duration::from_secs(60);
        assert_eq!(gate.wait_ready(long).await, Err(NotReady::Down));
        let failure = BootFailure::Exited {
            code: 1,
            stderr: "puddle-boot: error: x".into(),
        };
        gate.set(GateState::Failed(failure.clone()));
        assert_eq!(
            gate.wait_ready(long).await,
            Err(NotReady::Failed(failure.clone()))
        );
        gate.set(GateState::Ready);
        assert_eq!(gate.wait_ready(long).await, Ok(()));
        gate.close();
        assert_eq!(gate.state(), GateState::Down);
    }

    #[tokio::test(start_paused = true)]
    async fn booting_waits_until_settled_or_times_out() {
        let gate = Gate::new();
        gate.set(GateState::Booting);
        let limit = Duration::from_secs(5);
        assert_eq!(
            gate.wait_ready(limit).await,
            Err(NotReady::Timeout { waited: limit })
        );
        let waiter = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.wait_ready(limit).await })
        };
        tokio::task::yield_now().await;
        gate.set(GateState::Ready);
        assert_eq!(waiter.await.unwrap(), Ok(()));
    }

    #[test]
    fn refusals_read_well() {
        assert_eq!(NotReady::Down.to_string(), "workspace is not running");
        let e = GatedError::NotReady {
            sandbox: "a".into(),
            reason: NotReady::Timeout {
                waited: Duration::from_secs(2),
            },
        };
        assert_eq!(
            e.to_string(),
            r#"workspace "a": workspace is still booting after 2s"#
        );
    }
}
