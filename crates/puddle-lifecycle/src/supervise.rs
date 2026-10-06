// SPDX-License-Identifier: GPL-3.0-or-later
//! The front/worker split on Windows (see the crate docs): the user's console never reaches
//! the VMs.

use crate::LifecycleError;

/// The environment variable that marks the worker process (value `worker`). Set by the front;
/// never set it by hand.
pub const ROLE_VAR: &str = "PUDDLE_LIFECYCLE_ROLE";

/// Which process this is, from [`supervise`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The front: the worker has exited with `exit_code`; exit with it.
    Front {
        /// The worker's exit code (1 if it has none, e.g. it was killed).
        exit_code: i32,
    },
    /// The worker: run puddle. [`crate::wait_for_shutdown`] resolves on the front's request.
    Worker,
}

/// On Windows, unless this already is the worker: puts this process in the kill-on-close job
/// ([`crate::job`]), starts itself again (same arguments, [`ROLE_VAR`] set) as the worker with a
/// hidden console of its own and stdin as the control pipe, relays the worker's stdout and
/// stderr, turns console events into a shutdown request, and returns [`Role::Front`] when the
/// worker exits. On a console close the front also lifts the job's kill-on-close, so the
/// worker can finish stopping the VMs after Windows ends the front (about 5 s); the worker's
/// owning handles still end any VM it doesn't stop.
///
/// Elsewhere it returns [`Role::Worker`] at once (msb's parent watchdog ends the VMs if puddle
/// dies; `SIGINT`/`SIGTERM`/`SIGHUP` reach puddle through [`crate::wait_for_shutdown`]).
///
/// Only long-running commands use it: the worker's stdin is the control pipe, not the user's.
///
/// # Errors
///
/// Windows: the job can't be set up, or the worker can't be started or waited for.
pub fn supervise() -> Result<Role, LifecycleError> {
    #[cfg(windows)]
    {
        if is_worker() {
            return Ok(Role::Worker);
        }
        crate::windows::front::run()
    }
    #[cfg(not(windows))]
    {
        Ok(Role::Worker)
    }
}

/// Whether this process is the worker under a front.
#[cfg_attr(
    not(windows),
    expect(dead_code, reason = "the worker exists on Windows only")
)]
pub(crate) fn is_worker() -> bool {
    std::env::var_os(ROLE_VAR).is_some_and(|v| v == "worker")
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn outside_windows_every_process_is_the_worker() {
        assert_eq!(supervise().unwrap(), Role::Worker);
    }
}
