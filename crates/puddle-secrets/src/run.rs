// SPDX-License-Identifier: GPL-3.0-or-later
//! Running the fixed invocations: resolved paths, no console window, never a prompt.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::error::{SourceError, Tool};

/// How long a tool may take before it counts as stuck (most likely on a sign-in window).
pub(crate) const TOOL_TIMEOUT: Duration = Duration::from_secs(10);

/// Where `gh` and `git` are, resolved once. A missing one stays `None` and every source that needs
/// it answers [`SourceError::ToolMissing`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolPaths {
    gh: Option<PathBuf>,
    git: Option<PathBuf>,
}

impl ToolPaths {
    /// Paths given directly (tests, or a setting).
    #[must_use]
    pub fn new(gh: Option<PathBuf>, git: Option<PathBuf>) -> Self {
        Self { gh, git }
    }

    /// Looks `gh` and `git` up in the process's `PATH`.
    #[must_use]
    pub fn resolve() -> Self {
        Self::from_search_path(std::env::var_os("PATH").as_deref().unwrap_or_default())
    }

    /// Looks `gh` and `git` up in `search_path` (a `PATH`-style list). Relative entries are skipped,
    /// so the working directory is never searched; on Windows only `.exe` files count, never a
    /// `.cmd` or `.bat` script.
    #[must_use]
    pub fn from_search_path(search_path: &OsStr) -> Self {
        Self {
            gh: find("gh", search_path),
            git: find("git", search_path),
        }
    }

    pub(crate) fn get(&self, tool: Tool) -> Result<&Path, SourceError> {
        let path = match tool {
            Tool::Gh => &self.gh,
            Tool::Git => &self.git,
        };
        path.as_deref().ok_or(SourceError::ToolMissing(tool))
    }
}

fn find(name: &str, search_path: &OsStr) -> Option<PathBuf> {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    std::env::split_paths(search_path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(&file))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// What a finished tool left behind.
pub(crate) struct Output {
    pub(crate) success: bool,
    /// Standard output; wiped on drop because it may hold a token.
    pub(crate) stdout: Zeroizing<Vec<u8>>,
}

/// Runs `program` with fixed `args`, `stdin` and the prompt-suppressing environment. Never inherits
/// a console, a terminal or a prompt. Standard error is discarded.
pub(crate) async fn run(
    tool: Tool,
    program: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<Output, SourceError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(std::env::temp_dir())
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        // Git and Git Credential Manager: no terminal prompt, no GUI prompt, no askpass program.
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("SSH_ASKPASS", "")
        // gh: no prompt, and a token in the environment must not stand in for the named account.
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_ENTERPRISE_TOKEN")
        .env_remove("GITHUB_ENTERPRISE_TOKEN");
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: a console tool must not flash a window on the user's desktop.
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|err| {
        tracing::debug!(tool = tool.name(), kind = ?err.kind(), "could not start the tool");
        SourceError::ToolMissing(tool)
    })?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A tool that exits before reading its input is not an error here: its status says so.
        let _ = pipe.write_all(bytes).await;
    }
    let out = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(_)) => return Err(SourceError::ToolMissing(tool)),
        Err(_) => return Err(SourceError::Timeout(tool)),
    };
    Ok(Output {
        success: out.status.success(),
        stdout: Zeroizing::new(out.stdout),
    })
}
