// SPDX-License-Identifier: GPL-3.0-or-later
//! Changing the process environment, which is only sound before a second thread exists.
//!
//! The msb SDK takes its paths from the process environment, and puddle removes the user's own
//! `MSB_*` variables so none of them redirect it. Setting variables while another thread reads
//! them is undefined behaviour on Unix, so this refuses to run once another thread exists.
//! Windows' environment calls are thread-safe, so no check is made there.

use puddle_runtime::RuntimeEnv;

use crate::HostError;

/// How many threads this process runs, where the OS tells us cheaply.
#[cfg(target_os = "linux")]
fn thread_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/task")
        .ok()
        .map(Iterator::count)
}

#[cfg(not(target_os = "linux"))]
fn thread_count() -> Option<usize> {
    None
}

/// Applies `plan` to this process.
///
/// # Errors
///
/// [`HostError::EnvironmentTooLate`] when the process already has more than one thread.
#[expect(
    unsafe_code,
    reason = "changing the process environment; guarded by the single-thread check"
)]
pub(crate) fn apply(plan: &RuntimeEnv) -> Result<(), HostError> {
    if thread_count().is_some_and(|n| n > 1) {
        return Err(HostError::EnvironmentTooLate);
    }
    // SAFETY: on Linux the check above saw a single thread; elsewhere the platform's environment
    // calls are thread-safe (Windows) or puddle does not run (macOS is unsupported).
    unsafe { plan.apply_to_process() };
    Ok(())
}
