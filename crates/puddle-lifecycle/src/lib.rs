// SPDX-License-Identifier: GPL-3.0-or-later
//! Shutdown and reconcile: puddle's VMs live and die with puddle.
//!
//! - **Shutdown.** [`Lifecycle`] holds the owning handle of every sandbox puddle runs. When puddle
//!   exits, [`Lifecycle::shutdown`] runs `fstrim` in each one (ADR 0006: msb mounts volumes without
//!   `discard`) and then stops it, so msb records it `Stopped`, not `Crashed`.
//! - **Shutdown triggers.** [`wait_for_shutdown`] resolves on Ctrl-C, Ctrl-Break, a closed
//!   console, logoff, system shutdown, `SIGINT`, `SIGTERM` or `SIGHUP`.
//! - **Hard kills.** On Windows every process puddle starts, msb's VMM processes included, runs in
//!   one kill-on-close job object ([`job`]): if puddle is killed (`TerminateProcess`, a crash), the
//!   job's last handle closes and Windows kills the VMs with it. This job is the one place where
//!   later hardening adds job limits. On Linux msb's own parent watchdog does the
//!   same.
//! - **Reconcile.** After a hard kill the records are wrong (`Running` for a VM that is gone, or
//!   `Crashed`). [`reconcile`] runs at start: it stops VMs a previous puddle left running, removes
//!   records, stale directories and orphaned `ws-*` volumes puddle no longer knows, and **never
//!   touches anything puddle didn't create** (a foreign name). Leftover maintenance sandboxes
//!   (`m--*`) always go; [`adopt_workspaces`] then rebuilds the workspace holders.
//!
//! # Windows consoles: why puddle runs as two processes
//!
//! msb starts each VMM as a child of puddle that shares puddle's console and installs no console
//! handler. A Ctrl-C or a closed console window therefore reaches every VMM directly and kills it
//! before puddle can stop it (`Crashed`). [`supervise`] avoids that: the process the user started
//! (the *front*) creates the job, then starts itself again as the *worker* with
//! `CREATE_NO_WINDOW`, so the worker and its VMMs get a hidden console of their own that no
//! keypress or window close reaches. The front relays the worker's output and turns console
//! events into a shutdown request on the worker's stdin.
//!
//! ```no_run
//! # fn run_puddle() -> i32 { 0 }
//! match puddle_lifecycle::supervise() {
//!     Ok(puddle_lifecycle::Role::Front { exit_code }) => std::process::exit(exit_code),
//!     Ok(puddle_lifecycle::Role::Worker) => std::process::exit(run_puddle()),
//!     Err(e) => panic!("{e}"),
//! }
//! ```
//!
//! Inside `run_puddle`: [`reconcile`] and [`adopt_workspaces`] first, then create or start
//! sandboxes and hand their owning handles to [`Lifecycle::manage`], then
//! `wait_for_shutdown().await` and [`Lifecycle::shutdown`].
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod error;
pub mod job;
mod reconcile;
mod shutdown;
mod signal;
mod supervise;
mod trim;
#[cfg(windows)]
mod windows;

pub use error::LifecycleError;
pub use reconcile::{Failure, Inventory, ReconcileReport, adopt_workspaces, reconcile};
pub use shutdown::{Lifecycle, ShutdownConfig, ShutdownReport, StopOutcome, WorkspaceOutcome};
pub use signal::{ShutdownCause, ShutdownSignals, wait_for_shutdown};
pub use supervise::{ROLE_VAR, Role, supervise};
pub use trim::{TrimOutcome, trim_request};
