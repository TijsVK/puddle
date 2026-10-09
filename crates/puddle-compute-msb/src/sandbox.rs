// SPDX-License-Identifier: GPL-3.0-or-later
//! [`MsbSandbox`]: one sandbox handle, bound to one boot.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use microsandbox::sandbox::SandboxHandle;
use microsandbox::{MicrosandboxError, Sandbox as SdkSandbox};
use puddle_compute::{ComputeError, ExecOutput, ExecRequest, Sandbox, SshStream};
use puddle_types::{SandboxName, WorkspaceStatus};

use crate::error::{map, runtime};
use crate::runtime::{MsbRuntime, status};

/// How long [`Sandbox::stop`] waits for a graceful shutdown before killing the VM.
pub(crate) const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Slack on top of an exec's own timeout before the adapter gives up waiting for the SDK.
const EXEC_GRACE: Duration = Duration::from_secs(30);

/// Which boot a handle belongs to: the VM process id msb recorded for it.
pub(crate) fn boot_id(record: &SandboxHandle) -> Option<i32> {
    record.local().and_then(|l| l.pid)
}

/// A handle to one msb sandbox. Handles from [`puddle_compute::Runtime::create`] and
/// [`puddle_compute::Runtime::start`] own the VM (dropping them kills it); handles from
/// [`puddle_compute::Runtime::get`] don't. A handle belongs to the boot it was made for: after a
/// restart, exec, SSH and stop through it fail with [`ComputeError::StaleHandle`].
pub struct MsbSandbox {
    runtime: MsbRuntime,
    name: SandboxName,
    sdk: SdkSandbox,
    boot: Option<i32>,
    /// Set when a stop ended the VM by force.
    forced: AtomicBool,
}

impl std::fmt::Debug for MsbSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsbSandbox")
            .field("name", &self.name)
            .field("boot", &self.boot)
            .field("owns_lifecycle", &self.sdk.owns_lifecycle())
            .finish_non_exhaustive()
    }
}

/// An exec that couldn't start, as the shell would report it: 127 for a missing program, 126 for
/// one that can't run. Anything else stays an error.
fn spawn_failure(failure: &microsandbox::protocol::exec::ExecFailed) -> Option<ExecOutput> {
    use microsandbox::protocol::exec::ExecFailureKind;
    let code = match failure.kind {
        ExecFailureKind::NotFound => 127,
        ExecFailureKind::PermissionDenied | ExecFailureKind::NotExecutable => 126,
        _ => return None,
    };
    Some(ExecOutput::new(
        code,
        Vec::new(),
        format!("{}\n", failure.message).into_bytes(),
    ))
}

impl MsbSandbox {
    pub(crate) fn new(
        runtime: MsbRuntime,
        name: SandboxName,
        sdk: SdkSandbox,
        boot: Option<i32>,
    ) -> Self {
        Self {
            runtime,
            name,
            sdk,
            boot,
            forced: AtomicBool::new(false),
        }
    }

    /// The current record, checked to be this handle's boot and running.
    async fn this_boot(&self, op: &'static str) -> Result<SandboxHandle, ComputeError> {
        let record = self
            .runtime
            .record(self.name.as_str())
            .await?
            .ok_or_else(|| ComputeError::NotFound {
                sandbox: self.name.to_string(),
            })?;
        let current = status(record.status_snapshot());
        if current != WorkspaceStatus::Running {
            return Err(ComputeError::InvalidState {
                sandbox: self.name.to_string(),
                op,
                status: current,
            });
        }
        if boot_id(&record) != self.boot {
            return Err(ComputeError::StaleHandle {
                sandbox: self.name.to_string(),
            });
        }
        Ok(record)
    }
}

// Every method boxes its future: the SDK's futures are large, and callers nest them (the
// contract suite overflowed a test thread's stack with them inline).
impl Sandbox for MsbSandbox {
    fn stopped_by_force(&self) -> bool {
        self.forced.load(Ordering::Relaxed)
    }

    fn name(&self) -> &SandboxName {
        &self.name
    }

    fn owns_lifecycle(&self) -> bool {
        self.sdk.owns_lifecycle()
    }

    fn status(&self) -> impl Future<Output = Result<WorkspaceStatus, ComputeError>> + Send {
        Box::pin(async move {
            let record = self
                .runtime
                .record(self.name.as_str())
                .await?
                .ok_or_else(|| ComputeError::NotFound {
                    sandbox: self.name.to_string(),
                })?;
            Ok(status(record.status_snapshot()))
        })
    }

    fn stop(&self) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            let record = self
                .runtime
                .record(self.name.as_str())
                .await?
                .ok_or_else(|| ComputeError::NotFound {
                    sandbox: self.name.to_string(),
                })?;
            if status(record.status_snapshot()).is_down() {
                return Ok(());
            }
            if boot_id(&record) != self.boot {
                return Err(ComputeError::StaleHandle {
                    sandbox: self.name.to_string(),
                });
            }
            match self
                .runtime
                .sdk(self.sdk.stop_with_timeout(STOP_TIMEOUT))
                .await
            {
                Ok(()) => Ok(()),
                Err(
                    e @ (MicrosandboxError::StopTimeout { .. }
                    | MicrosandboxError::SandboxStopTimedOut { .. }),
                ) => {
                    tracing::warn!(sandbox = %self.name, error = %e, "graceful stop timed out; killing the VM");
                    self.runtime
                        .sdk(self.sdk.kill())
                        .await
                        .map_err(|e| map("kill", self.name.as_str(), e))?;
                    // Down, but not shut down: the caller can ask and tell the user.
                    self.forced.store(true, Ordering::Relaxed);
                    Ok(())
                }
                Err(e) => Err(map("stop", self.name.as_str(), e)),
            }
        })
    }

    fn exec(
        &self,
        request: ExecRequest,
    ) -> impl Future<Output = Result<ExecOutput, ComputeError>> + Send {
        Box::pin(async move {
            self.this_boot("exec").await?;
            let ExecRequest {
                program,
                args,
                env,
                cwd,
                user,
                stdin,
                timeout,
            } = request;
            let env: Vec<(String, String)> = env
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            let call = self.sdk.exec_with(program.clone(), move |mut e| {
                e = e.args(args).envs(env).timeout(timeout).tty(false);
                if let Some(cwd) = cwd {
                    e = e.cwd(cwd.as_str());
                }
                if let Some(user) = user {
                    e = e.user(user);
                }
                if stdin.is_empty() {
                    e.stdin_null()
                } else {
                    e.stdin_bytes(stdin)
                }
            });
            let timed_out = || ComputeError::ExecTimeout {
                sandbox: self.name.to_string(),
                program: program.clone(),
                timeout,
            };
            let Ok(result) =
                tokio::time::timeout(timeout + EXEC_GRACE, self.runtime.sdk(call)).await
            else {
                return Err(timed_out());
            };
            match result {
                Ok(output) => Ok(ExecOutput::new(
                    output.status().code,
                    output.stdout_bytes().to_vec(),
                    output.stderr_bytes().to_vec(),
                )),
                Err(MicrosandboxError::ExecTimeout(_)) => Err(timed_out()),
                Err(MicrosandboxError::ExecFailed(failure)) => {
                    spawn_failure(&failure).ok_or_else(|| runtime("exec", &failure.message))
                }
                Err(e) => Err(map("exec", self.name.as_str(), e)),
            }
        })
    }

    fn serve_ssh<S: SshStream>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            self.this_boot("serve ssh for").await?;
            let ssh = self.runtime.config().ssh.clone();
            let server = self
                .runtime
                .sdk(self.sdk.ssh().server_with(move |mut o| {
                    for key in ssh.authorized_keys {
                        o = o.authorized_key(key);
                    }
                    match ssh.inactivity_timeout {
                        Some(t) => o.inactivity_timeout(t),
                        None => o.disable_inactivity_timeout(),
                    }
                }))
                .await
                .map_err(|e| runtime("serve ssh", &e))?;
            self.runtime
                .sdk(server.serve_connection(stream))
                .await
                .map_err(|e| runtime("serve ssh", &e))
        })
    }
}

#[cfg(test)]
mod tests {
    use microsandbox::protocol::exec::{ExecFailed, ExecFailureKind};

    use super::*;

    fn failed(kind: ExecFailureKind) -> ExecFailed {
        ExecFailed {
            kind,
            errno: Some(2),
            errno_name: Some("ENOENT".into()),
            message: "nope: not found".into(),
            stage: Some("execvp".into()),
        }
    }

    #[test]
    fn spawn_failures_read_like_a_shell() {
        let out = spawn_failure(&failed(ExecFailureKind::NotFound)).unwrap();
        assert_eq!(out.status.code, 127);
        assert_eq!(out.stderr_text(), "nope: not found\n");
        for kind in [
            ExecFailureKind::PermissionDenied,
            ExecFailureKind::NotExecutable,
        ] {
            assert_eq!(spawn_failure(&failed(kind)).unwrap().status.code, 126);
        }
        for kind in [
            ExecFailureKind::BadCwd,
            ExecFailureKind::BadArgs,
            ExecFailureKind::ResourceLimit,
            ExecFailureKind::UserSetupFailed,
        ] {
            assert!(spawn_failure(&failed(kind)).is_none());
        }
    }
}
