// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared by the tests that run `git` (or scripts that do) on the host.
//!
//! Under a git hook (the pre-push gates run the tests) git exports `GIT_DIR`, `GIT_INDEX_FILE`
//! and friends. Every `git` the tests spawn would then act on puddle's own repository whatever
//! its working directory is: `git init --bare` in a temp dir rewrites that repository's
//! `core.bare`. [`command`] and [`git_command`] drop every inherited `GIT_*` variable.
#![allow(dead_code, reason = "each test binary uses a part of this module")]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::ffi::OsString;
use std::process::Command;

/// Set in the child run of [`assert_hook_env_leaves_the_repository_alone`].
const CHILD_MARKER: &str = "PUDDLE_TEST_HOOK_ENV_CHILD";

/// `program` with every `GIT_*` variable in `inherited` removed.
pub(crate) fn command_without(
    program: &str,
    inherited: impl IntoIterator<Item = OsString>,
) -> Command {
    let mut cmd = Command::new(program);
    for key in inherited {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

/// `program` without the caller's `GIT_*` variables.
pub(crate) fn command(program: &str) -> Command {
    command_without(program, std::env::vars_os().map(|(key, _)| key))
}

/// `git` without the caller's `GIT_*` variables.
pub(crate) fn git_command() -> Command {
    command("git")
}

/// True in the child run, where the regression test itself must not recurse.
pub(crate) fn is_hook_env_child() -> bool {
    std::env::var_os(CHILD_MARKER).is_some()
}

/// Regression for the leak: runs this very test binary again (every test but `skip`) with the
/// variables a git hook exports, pointing at a throwaway repository, and asserts the child
/// passed and left that repository's config as it was.
pub(crate) fn assert_hook_env_leaves_the_repository_alone(skip: &str) {
    let outer = tempfile::tempdir().unwrap();
    let outer_git = outer.path().join("outer.git");
    let init = git_command()
        .args(["init", "-q"])
        .arg(&outer_git)
        .output()
        .unwrap();
    assert!(init.status.success());
    let config = outer_git.join(".git/config");
    let before = std::fs::read_to_string(&config).unwrap();

    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--test-threads=1", "--skip", skip])
        .env(CHILD_MARKER, "1")
        .env("GIT_DIR", outer_git.join(".git"))
        .env("GIT_INDEX_FILE", outer_git.join(".git/index"))
        .env("GIT_WORK_TREE", outer.path().join("worktree"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the tests failed under a hook's git environment:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let after = std::fs::read_to_string(&config).unwrap();
    assert_eq!(before, after, "a test changed the surrounding repository");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_git_variables_are_removed() {
        let cmd = command_without(
            "git",
            ["GIT_DIR", "GIT_INDEX_FILE", "PATH", "GIT_CONFIG_COUNT"].map(OsString::from),
        );
        let mut removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        removed.sort();
        assert_eq!(removed, ["GIT_CONFIG_COUNT", "GIT_DIR", "GIT_INDEX_FILE"]);
    }
}
