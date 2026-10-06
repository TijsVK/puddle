// SPDX-License-Identifier: GPL-3.0-or-later
//! The kill-on-close job object puddle and every process it starts run in (Windows).
//!
//! [`contain_this_process`] creates one job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, puts the
//! current process in it, and keeps the only handle until the process ends. Children inherit
//! the job, msb's VMM processes included (the SDK starts them without
//! `CREATE_BREAKAWAY_FROM_JOB` and adds them to a nested per-sandbox job of its own), and the
//! job doesn't allow breakaway. When puddle ends in any way, `TerminateProcess` included, the
//! handle closes and Windows kills everything left in the job.
//!
//! This is the one place to add job limits (UI restrictions, a process count) for the D-27
//! escape review (T-020 F-7). On Linux it does nothing: msb's parent watchdog stops the VMs.

use crate::LifecycleError;

/// What [`contain_this_process`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// This process is now in puddle's kill-on-close job (or already was).
    Contained,
    /// Not Windows: nothing to do.
    NotNeeded,
}

/// Puts this process in puddle's kill-on-close job (see the module docs). Call it once, before
/// starting any child process; later calls do nothing.
///
/// # Errors
///
/// [`LifecycleError::Job`] when the job can't be created or this process can't join it.
pub fn contain_this_process() -> Result<Containment, LifecycleError> {
    #[cfg(windows)]
    {
        crate::windows::job::contain_this_process().map(|()| Containment::Contained)
    }
    #[cfg(not(windows))]
    {
        Ok(Containment::NotNeeded)
    }
}

/// Lets the processes in the job outlive its handle: the front calls it on a console close, so
/// the worker can finish stopping the VMs after Windows ends the front.
#[cfg(windows)]
pub(crate) fn release_kill_on_close() -> Result<(), LifecycleError> {
    crate::windows::job::release_kill_on_close()
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn outside_windows_there_is_no_job() {
        assert_eq!(contain_this_process().unwrap(), Containment::NotNeeded);
    }
}
