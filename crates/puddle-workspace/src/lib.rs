// SPDX-License-Identifier: GPL-3.0-or-later
//! Workspace volume lifecycle (W1, T-112; ADR 0006, D-10).
//!
//! Each workspace is a named msb disk volume `ws-<id>` (ext4), mounted at `/workspaces/<id>`.
//! The volume outlives its sandboxes: rebuilding a sandbox reattaches it. Code gets in by
//! cloning inside the guest, into a subdirectory (the volume root also holds puddle's `.puddle`).
//!
//! | Need | Call |
//! |---|---|
//! | create or reuse the volume, attach it to a new sandbox | [`Workspaces::create`], or [`Workspaces::prepare`] → [`Attachment`] around your own create (the boot hook) |
//! | one writer: refuse a second attach naming the holder | built into `prepare`: [`WorkspaceError::InUse`] |
//! | a failed create leaves nothing (record, stale dir, new volume) | [`Attachment::abort`] |
//! | paths in the guest, the clone command | [`Layout`], [`checkout_name`] |
//! | `fstrim` before stop; "reclaim space" | [`Workspaces::stop`], [`Workspaces::reclaim_space`] |
//! | delete after listing unsaved work, with explicit confirmation | [`Workspaces::check_delete`] → [`DeleteReport::confirm`] → [`Workspaces::delete`] |
//! | reconcile after a restart (T-113) | [`Workspaces::adopt`], [`is_maintenance_name`] |
//!
//! A workspace no sandbox runs with is checked or trimmed in a short-lived maintenance sandbox
//! (`m--<id>`, [`WorkspaceConfig::maintenance_image`]) that is removed again afterwards.
//!
//! ```
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//! use puddle_compute::fake::FakeRuntime;
//! use puddle_compute::{Runtime, SandboxSpec};
//! use puddle_types::{ImageRef, SandboxName, WorkspaceId};
//! use puddle_workspace::{WorkspaceError, Workspaces};
//!
//! let rt = FakeRuntime::new();
//! let workspaces = Workspaces::default();
//! let id = WorkspaceId::new("acme").unwrap();
//! let image = ImageRef::new(FakeRuntime::DEBIAN).unwrap();
//! let spec = |n: &str| SandboxSpec::new(SandboxName::new(n).unwrap(), image.clone());
//!
//! let _first = workspaces.create(&rt, &id, spec("one"), None).await.unwrap();
//! let refused = workspaces.create(&rt, &id, spec("two"), None).await.unwrap_err();
//! assert_eq!(refused.to_string(), r#"workspace "acme" is in use by sandbox "one""#);
//! assert!(matches!(refused, WorkspaceError::InUse { .. }));
//! # });
//! ```
#![forbid(unsafe_code)]

mod check;
mod error;
mod layout;
mod registry;
mod trim;
mod workspaces;

pub use check::{
    CHECK_TIMEOUT, DELETE_CHECK_SH, DeleteConfirmation, DeleteReport, Findings, Listing, MAX_ITEMS,
    MAX_REPOS, RepoReport,
};
pub use error::WorkspaceError;
pub use layout::{
    FALLBACK_CHECKOUT, LOST_AND_FOUND, Layout, PUDDLE_DIR, WORKSPACES_ROOT, checkout_name,
};
pub use registry::{HoldKind, Holder};
pub use trim::{TRIM_TIMEOUT, TrimReport};
pub use workspaces::{
    Attachment, Deleted, MAINTENANCE_PREFIX, StopReport, WorkspaceConfig, Workspaces,
    is_maintenance_name,
};
