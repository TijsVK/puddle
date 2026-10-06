// SPDX-License-Identifier: GPL-3.0-or-later
//! Errors of the process-level parts (job object, front/worker split). Runtime failures during
//! shutdown and reconcile are reported per sandbox in the reports, not as errors.

/// A process-level step failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LifecycleError {
    /// A job-object call failed.
    #[error("job object: {op} failed")]
    Job {
        /// The call.
        op: &'static str,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// Starting or watching the worker process failed.
    #[error("worker process: {op} failed")]
    Worker {
        /// What was being done.
        op: &'static str,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}
