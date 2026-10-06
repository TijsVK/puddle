// SPDX-License-Identifier: GPL-3.0-or-later
//! Where a workspace lives in the guest: the volume's mount point, the checkouts below it and
//! puddle's own directory beside them (T-020 seams for T-112).
//!
//! ```text
//! /workspaces/<id>/            the volume root (ext4); never cloned into, it holds .puddle
//!   ├── lost+found/            only if mkfs made one (msb 0.7.7's doesn't); ignored
//!   ├── .puddle/               puddle-owned (code-server data, a later ~/.vscode-server); the
//!   │                          delete check ignores it
//!   └── <repo>/                a git checkout (one or more), what the IDE opens
//! ```

use puddle_compute::ExecRequest;
use puddle_types::{GuestPath, WorkspaceId};

use crate::WorkspaceError;

/// Where every workspace volume is mounted: `/workspaces/<id>` (ADR 0006).
pub const WORKSPACES_ROOT: &str = "/workspaces";

/// puddle's own directory on the volume, beside the checkouts.
pub const PUDDLE_DIR: &str = ".puddle";

/// ext4's recovery directory; ignored at the volume root (msb 0.7.7's mkfs doesn't make one).
pub const LOST_AND_FOUND: &str = "lost+found";

/// The checkout directory name used when a clone URL doesn't give a usable one.
pub const FALLBACK_CHECKOUT: &str = "src";

/// Longest checkout directory name taken from a URL.
const MAX_CHECKOUT_LEN: usize = 100;

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

    /// puddle's own directory, `/workspaces/<id>/.puddle`.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn puddle_dir(&self) -> Result<GuestPath, WorkspaceError> {
        self.child(PUDDLE_DIR)
    }

    /// The checkout directory `name` (see [`checkout_name`]), `/workspaces/<id>/<name>`.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] when `name` isn't a usable checkout name (empty, `.`/`..`, a
    /// `/`, a leading `.` or `-`, or one of the reserved names).
    pub fn checkout(&self, name: &str) -> Result<GuestPath, WorkspaceError> {
        if !is_checkout_name(name) {
            return Err(WorkspaceError::Layout {
                reason: format!("{name:?} is not a usable checkout directory name"),
            });
        }
        self.child(name)
    }

    /// The command that creates puddle's directory (owner-only), run as root after every boot
    /// of a sandbox with this workspace. Idempotent.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn prepare_request(&self) -> Result<ExecRequest, WorkspaceError> {
        let dir = self.puddle_dir()?;
        Ok(ExecRequest::new("mkdir", ["-p", "-m", "0700", dir.as_str()]).as_user("root"))
    }

    /// `git clone -- <url> /workspaces/<id>/<name>`, the name from [`checkout_name`]. Without a
    /// shell, so the URL is one argument whatever it contains; `--` keeps a URL that starts
    /// with `-` from being read as an option. Run it as the session user, with the proxy env.
    ///
    /// # Errors
    ///
    /// [`WorkspaceError::Layout`] (never for a valid layout).
    pub fn clone_request(&self, url: &str) -> Result<ExecRequest, WorkspaceError> {
        let dir = self.checkout(&checkout_name(url))?;
        Ok(ExecRequest::new(
            "git",
            ["clone", "--", url, dir.as_str()].map(str::to_owned),
        ))
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

/// Whether `name` can be a checkout directory directly under the volume root.
fn is_checkout_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CHECKOUT_LEN
        && !name.starts_with(['.', '-'])
        && name != LOST_AND_FOUND
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The checkout directory for a clone URL: the last path segment without `.git`, as git would
/// name it, if that is a plain name (ASCII letters, digits, `.`, `_`, `-`, not starting with `.`
/// or `-`); otherwise [`FALLBACK_CHECKOUT`].
///
/// ```
/// use puddle_workspace::checkout_name;
/// assert_eq!(checkout_name("https://github.com/acme/api.git"), "api");
/// assert_eq!(checkout_name("git@github.com:acme/web"), "web");
/// assert_eq!(checkout_name("https://example.org/"), "example.org");
/// assert_eq!(checkout_name("https://h/x/..git"), "src");
/// ```
#[must_use]
pub fn checkout_name(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let last = trimmed.rsplit(['/', ':']).next().unwrap_or_default();
    let name = last.strip_suffix(".git").unwrap_or(last);
    if is_checkout_name(name) {
        name.to_owned()
    } else {
        FALLBACK_CHECKOUT.to_owned()
    }
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
        assert_eq!(l.checkout("api").unwrap().as_str(), "/workspaces/acme/api");
    }

    #[test]
    fn reserved_and_odd_checkout_names_are_refused() {
        let l = layout();
        for bad in [
            "",
            ".",
            "..",
            ".puddle",
            "lost+found",
            "a/b",
            "-x",
            "a b",
            "é",
            &"x".repeat(101),
        ] {
            assert!(l.checkout(bad).is_err(), "{bad:?} accepted");
        }
        assert!(l.checkout(&"x".repeat(100)).is_ok());
    }

    #[test]
    fn checkout_names_follow_git_or_fall_back() {
        let cases = [
            ("https://github.com/acme/api.git", "api"),
            ("https://github.com/acme/api", "api"),
            ("https://github.com/acme/api/", "api"),
            ("git@github.com:acme/web.git", "web"),
            ("git@github.com:web.git", "web"),
            ("https://dev.azure.com/o/p/_git/My.Repo", "My.Repo"),
            ("https://h/x/.hidden", "src"),
            ("https://h/x/-opt", "src"),
            ("https://h/x/a%20b", "src"),
            ("", "src"),
            ("/", "src"),
            ("https://h/x/.git", "src"),
            ("https://h/x/lost+found", "src"),
        ];
        for (url, want) in cases {
            assert_eq!(checkout_name(url), want, "{url}");
        }
    }

    #[test]
    fn clone_request_passes_the_url_as_one_argument_after_double_dash() {
        let r = layout()
            .clone_request("-u evil https://h/acme/api.git")
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
    fn prepare_request_makes_an_owner_only_puddle_dir_as_root() {
        let r = layout().prepare_request().unwrap();
        assert_eq!(r.program, "mkdir");
        assert_eq!(r.args, ["-p", "-m", "0700", "/workspaces/acme/.puddle"]);
        assert_eq!(r.user.as_deref(), Some("root"));
    }
}
