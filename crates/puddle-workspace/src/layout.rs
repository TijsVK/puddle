// SPDX-License-Identifier: GPL-3.0-or-later
//! Where a workspace lives in the guest: the volume's mount point, the checkouts below it and
//! Puddle's own directory beside them.
//!
//! ```text
//! /workspaces/<id>/            the volume root (ext4); never cloned into, it holds .puddle
//!   ├── lost+found/            only if mkfs made one (msb 0.7.7's doesn't); ignored
//!   ├── .puddle/               Puddle-owned (code-server data, a later ~/.vscode-server); the
//!   │                          delete check ignores it
//!   └── <repo>/                a git checkout (one or more), what the IDE opens
//! ```

use std::time::Duration;

use puddle_compute::ExecRequest;
use puddle_types::{CheckoutDir, GuestPath, WorkspaceId};

use crate::WorkspaceError;

/// Where every workspace volume is mounted: `/workspaces/<id>` (ADR 0006).
pub const WORKSPACES_ROOT: &str = "/workspaces";

/// Puddle's own directory on the volume, beside the checkouts.
pub const PUDDLE_DIR: &str = ".puddle";

/// ext4's recovery directory; ignored at the volume root (msb 0.7.7's mkfs doesn't make one).
pub const LOST_AND_FOUND: &str = CheckoutDir::LOST_AND_FOUND;

/// How long a `sync` may take (a clone of a large repository leaves a lot to write).
pub(crate) const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

/// A workspace's paths in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    mount: GuestPath,
}

impl Layout {
    /// The layout of workspace `id`.
    ///
    /// # Errors
    ///
    /// Never in practice: a [`WorkspaceId`] is a DNS label, so the path is always valid. The
    /// error is [`WorkspaceError::Layout`].
    pub fn new(id: &WorkspaceId) -> Result<Self, WorkspaceError> {
        let mount = guest(&format!("{WORKSPACES_ROOT}/{id}"))?;
        Ok(Self { mount })
    }

    /// The volume's mount point, `/workspaces/<id>`.
    #[must_use]
    pub fn mount(&self) -> &GuestPath {
        &self.mount
    }

    /// Puddle's own directory, `/workspaces/<id>/.puddle`.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn puddle_dir(&self) -> Result<GuestPath, WorkspaceError> {
        self.child(PUDDLE_DIR)
    }

    /// The checkout directory `dir`, `/workspaces/<id>/<dir>`.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout: a [`CheckoutDir`] is one plain
    /// segment).
    pub fn checkout(&self, dir: &CheckoutDir) -> Result<GuestPath, WorkspaceError> {
        self.child(dir.as_str())
    }

    /// The command that creates Puddle's directory (owner-only), run as root after every boot
    /// of a sandbox with this workspace. Idempotent.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn prepare_request(&self) -> Result<ExecRequest, WorkspaceError> {
        let dir = self.puddle_dir()?;
        Ok(ExecRequest::new("mkdir", ["-p", "-m", "0700", dir.as_str()]).as_user("root"))
    }

    /// `git clone -- <url> /workspaces/<id>/<dir>`. Without a shell, so the URL is one argument
    /// whatever it contains; `--` keeps a URL that starts with `-` from being read as an option.
    /// Run it as the session user, with the proxy env.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn clone_request(
        &self,
        url: &str,
        dir: &CheckoutDir,
    ) -> Result<ExecRequest, WorkspaceError> {
        let dir = self.checkout(dir)?;
        Ok(ExecRequest::new(
            "git",
            ["clone", "--", url, dir.as_str()].map(str::to_owned),
        ))
    }

    /// `sync`, as root: flushes everything the guest has cached to the volume. Directory entries
    /// aren't covered by `core.fsync=committed` until the first fsync, so a VMM kill within
    /// seconds of a fresh clone or `git init` can lose the whole repository without it.
    #[must_use]
    pub fn sync_request() -> ExecRequest {
        ExecRequest::new("sync", Vec::<String>::new())
            .as_user("root")
            .with_timeout(SYNC_TIMEOUT)
    }

    fn child(&self, name: &str) -> Result<GuestPath, WorkspaceError> {
        guest(&format!("{}/{name}", self.mount))
    }
}

fn guest(path: &str) -> Result<GuestPath, WorkspaceError> {
    GuestPath::new(path).map_err(|e| WorkspaceError::Layout {
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        Layout::new(&WorkspaceId::new("acme").unwrap()).unwrap()
    }

    #[test]
    fn paths_sit_under_the_mount_point() {
        let l = layout();
        assert_eq!(l.mount().as_str(), "/workspaces/acme");
        assert_eq!(l.puddle_dir().unwrap().as_str(), "/workspaces/acme/.puddle");
        assert_eq!(
            l.checkout(&CheckoutDir::new("api").unwrap())
                .unwrap()
                .as_str(),
            "/workspaces/acme/api"
        );
    }

    #[test]
    fn clone_request_passes_the_url_as_one_argument_after_double_dash() {
        let dir = CheckoutDir::new("api").unwrap();
        let r = layout()
            .clone_request("-u evil https://h/acme/api.git", &dir)
            .unwrap();
        assert_eq!(r.program, "git");
        assert_eq!(
            r.args,
            [
                "clone",
                "--",
                "-u evil https://h/acme/api.git",
                "/workspaces/acme/api"
            ]
        );
        assert_eq!(r.user, None);
    }

    #[test]
    fn sync_request_flushes_everything_as_root() {
        let r = Layout::sync_request();
        assert_eq!(r.program, "sync");
        assert_eq!(r.args, Vec::<String>::new());
        assert_eq!(r.user.as_deref(), Some("root"));
        assert_eq!(r.timeout, SYNC_TIMEOUT);
    }

    #[test]
    fn prepare_request_makes_an_owner_only_puddle_dir_as_root() {
        let r = layout().prepare_request().unwrap();
        assert_eq!(r.program, "mkdir");
        assert_eq!(r.args, ["-p", "-m", "0700", "/workspaces/acme/.puddle"]);
        assert_eq!(r.user.as_deref(), Some("root"));
    }
}
