// SPDX-License-Identifier: GPL-3.0-or-later
//! Why the host did not start.

use std::path::PathBuf;

/// A failed start. Messages are for the user: lower case, no trailing period, and the next step
/// where there is one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// The per-user data folder could not be found.
    #[error("cannot find puddle's data folder: {0}")]
    DataDir(String),
    /// The bundled runtime is missing, unreadable or of another version.
    #[error("{0}; `puddle doctor` explains the fix")]
    Runtime(#[from] puddle_runtime::RuntimeError),
    /// Another thread already runs, so the process environment cannot be changed safely.
    #[error("the process environment must be set before any other thread starts")]
    EnvironmentTooLate,
    /// The guest agent binary that every sandbox mounts is missing.
    #[error("the guest agent {path} is missing; build it with ci/build-agent.sh")]
    AgentMissing {
        /// Where it was expected.
        path: PathBuf,
    },
    /// The image-pull proxy could not listen.
    #[error("cannot start the image-pull proxy: {0}")]
    PullProxy(std::io::Error),
    /// The host's corporate root certificates could not be read.
    #[error("cannot read the host's certificate stores: {0}")]
    Roots(String),
    /// The runtime could not be opened.
    #[error("cannot open the sandbox runtime: {0}")]
    Compute(#[from] puddle_compute::ComputeError),
    /// The store could not be opened.
    #[error("cannot open the database: {0}")]
    Store(#[from] puddle_store::StoreError),
    /// A state file could not be read or written.
    #[error("{what}: {reason}")]
    State {
        /// Which file.
        what: &'static str,
        /// What went wrong, with the path.
        reason: String,
    },
    /// Cleaning up after an earlier run failed.
    #[error("cannot reconcile with the runtime: {0}")]
    Reconcile(String),
    /// The API could not start.
    #[error(transparent)]
    Api(#[from] puddle_api::ServeError),
    /// The API token or connection file failed.
    #[error(transparent)]
    Connection(#[from] puddle_api::ConnectionFileError),
    /// A file the guest needs could not be written under the guest-share root.
    #[error("cannot prepare the files sandboxes mount: {0}")]
    GuestFiles(String),
}
