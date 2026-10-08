// SPDX-License-Identifier: GPL-3.0-or-later
//! xtask's `git` ignores the repository variables a git hook exports: with `GIT_DIR` pointing at
//! another repository, `git init --bare` run through [`xtask::tools::git_command`] must create the
//! new repository and leave the one `GIT_DIR` names alone (unstripped, it re-initialises that one
//! and sets `core.bare = true`).
#![expect(
    clippy::unwrap_used,
    reason = "a failed step fails the test by panicking"
)]

use std::path::PathBuf;
use std::process::Command;

const CHILD: &str = "PUDDLE_TEST_GIT_ENV_CHILD";

fn plain_git(args: &[&str]) {
    let out = xtask::tools::git_command().args(args).output().unwrap();
    assert!(out.status.success(), "git {args:?}");
}

#[test]
fn a_hooks_repository_variables_do_not_reach_git() {
    if let Some(target) = std::env::var_os(CHILD) {
        // The child: GIT_DIR names the victim; the new repository must be created elsewhere.
        let out = xtask::tools::git_command()
            .args(["init", "-q", "--bare"])
            .arg(PathBuf::from(target))
            .output()
            .unwrap();
        assert!(out.status.success());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    let bare = dir.path().join("created.git");
    plain_git(&["init", "-q", victim.to_str().unwrap()]);
    let config = victim.join(".git/config");
    let before = std::fs::read_to_string(&config).unwrap();

    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "a_hooks_repository_variables_do_not_reach_git"])
        .env(CHILD, &bare)
        .env("GIT_DIR", victim.join(".git"))
        .env("GIT_INDEX_FILE", victim.join(".git/index"))
        .env("GIT_WORK_TREE", &victim)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        bare.join("HEAD").is_file(),
        "the bare repository was not created"
    );
    assert_eq!(before, std::fs::read_to_string(&config).unwrap());
}
