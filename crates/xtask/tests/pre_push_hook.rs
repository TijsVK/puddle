// SPDX-License-Identifier: GPL-3.0-or-later
//! The pre-push hook hands the gates a clean git environment: git exports `GIT_DIR` and the
//! other repository variables to hooks, and every git command or test below would then act on
//! puddle's own repository instead of its working directory. Unix only: the stub gate script is made
//! executable with `chmod`; the hook itself is plain `sh`, which Git for Windows also runs.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "a failed step fails the test by panicking"
)]

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
}

#[test]
fn the_gates_start_without_the_repository_variables_a_hook_exports() {
    let hook = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.githooks/pre-push");
    let repo = tempfile::tempdir().unwrap();
    let dir = repo.path();
    git(dir, &["init", "-q"]);
    std::fs::create_dir_all(dir.join("scripts")).unwrap();
    std::fs::write(
        dir.join("scripts/check.sh"),
        "#!/bin/sh\nenv | grep '^GIT_' || true\npwd\n",
    )
    .unwrap();
    Command::new("chmod")
        .arg("+x")
        .arg(dir.join("scripts/check.sh"))
        .status()
        .unwrap();

    // What git sets for a hook: the repository, its index, the checkout.
    let out = Command::new("sh")
        .arg(&hook)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GIT_DIR", dir.join(".git"))
        .env("GIT_INDEX_FILE", dir.join(".git/index"))
        .env("GIT_WORK_TREE", dir)
        .env("GIT_PREFIX", "")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains("GIT_"), "the gates inherited: {stdout}");
    assert_eq!(
        Path::new(stdout.trim()).canonicalize().unwrap(),
        dir.canonicalize().unwrap(),
        "the gates run from the repository's top level"
    );
}
