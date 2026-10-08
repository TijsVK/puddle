// SPDX-License-Identifier: GPL-3.0-or-later
//! The real `guest/delete-check.sh` under dash and bash, against real git repositories in a
//! temp dir that plays the volume root, driven through [`Workspaces::check_delete`] on the fake
//! (its exec handler runs the script on the host). Needs `git` on the host.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use puddle_compute::fake::{ExecContext, FakeRuntime};
use puddle_compute::{DiskSize, ExecOutput, ExecRequest, Runtime, VolumeSpec};
use puddle_types::WorkspaceId;
use puddle_workspace::{DELETE_CHECK_SH, DeleteReport, Workspaces};

mod common;
use common::command;

/// Shells the script must work under (the guest's `/bin/sh` is dash on Debian).
fn shells() -> Vec<&'static str> {
    ["dash", "bash"]
        .into_iter()
        .filter(|s| {
            Command::new("sh")
                .args(["-c", &format!("command -v {s}")])
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .collect()
}

/// Git for the fixture repositories, with auto maintenance off: newer git starts
/// `git maintenance run --auto` detached after a commit, which would still be working in the
/// repository while the script under test reads it.
fn git(dir: &Path, args: &[&str]) {
    let out = command("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.org")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.org")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A volume root with: ext4's `lost+found`, puddle's `.puddle`, a checkout with every kind of
/// unsaved work, a clean checkout, a repo without commits, and a stray file.
fn volume(root: &Path) -> PathBuf {
    let remote = root.join("remote.git");
    std::fs::create_dir(&remote).unwrap();
    git(&remote, &["init", "-q", "--bare", "-b", "main"]);
    let vol = root.join("vol");
    std::fs::create_dir_all(vol.join("lost+found")).unwrap();
    std::fs::create_dir_all(vol.join(".puddle/code-server")).unwrap();
    std::fs::write(vol.join("notes.txt"), "loose\n").unwrap();

    let seed = root.join("seed");
    std::fs::create_dir(&seed).unwrap();
    git(&seed, &["init", "-q", "-b", "main"]);
    std::fs::write(seed.join("a.txt"), "a\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "first"]);
    git(
        &seed,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&seed, &["push", "-q", "origin", "main"]);

    git(&vol, &["clone", "-q", remote.to_str().unwrap(), "web"]);
    git(&vol, &["clone", "-q", remote.to_str().unwrap(), "api"]);
    let api = vol.join("api");
    std::fs::write(api.join("a.txt"), "changed\n").unwrap();
    git(&api, &["stash", "-q"]);
    std::fs::write(api.join("b.txt"), "b\n").unwrap();
    git(&api, &["add", "b.txt"]);
    git(&api, &["commit", "-qm", "local only"]);
    std::fs::write(api.join("a.txt"), "edited\n").unwrap();
    std::fs::write(api.join("new.txt"), "untracked\n").unwrap();
    // A hostile repo config: the check must not run it.
    let pwned = root.join("pwned");
    git(
        &api,
        &[
            "config",
            "core.fsmonitor",
            &format!("touch {}; false", pwned.display()),
        ],
    );

    let fresh = vol.join("fresh");
    std::fs::create_dir(&fresh).unwrap();
    git(&fresh, &["init", "-q"]);
    std::fs::write(fresh.join("x"), "x\n").unwrap();
    vol
}

/// Runs the check script with `shell` on `host_root` whenever the fake is asked to.
fn run_on_host(rt: &FakeRuntime, shell: &'static str, host_root: PathBuf) {
    rt.on_exec(move |_: &mut ExecContext<'_>, r: &ExecRequest| {
        if r.program != "sh" || r.args.get(1).map(String::as_str) != Some(DELETE_CHECK_SH) {
            return None;
        }
        assert_eq!(r.args.get(3).map(String::as_str), Some("/workspaces/acme"));
        // A blocking call in the fake's handler: fine for a test, the script takes milliseconds.
        let out = command(shell)
            .args(["-c", DELETE_CHECK_SH, "puddle-delete-check"])
            .arg(&host_root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        Some(ExecOutput::new(
            out.status.code().unwrap_or(-1),
            out.stdout,
            out.stderr,
        ))
    });
}

async fn check(shell: &'static str, root: &Path) -> DeleteReport {
    let rt = FakeRuntime::new();
    run_on_host(&rt, shell, root.to_path_buf());
    let id = WorkspaceId::new("acme").unwrap();
    rt.create_volume(VolumeSpec {
        name: id.volume_name(),
        size: DiskSize::gib(1),
    })
    .await
    .unwrap();
    Workspaces::default().check_delete(&rt, &id).await.unwrap()
}

#[tokio::test]
async fn the_script_finds_every_kind_of_unsaved_work() {
    let shells = shells();
    assert!(!shells.is_empty(), "neither dash nor bash found");
    for shell in shells {
        let tmp = tempfile::tempdir().unwrap();
        let vol = volume(tmp.path());
        let report = check(shell, &vol).await;
        let f = &report.findings;
        let dirs: Vec<&str> = f.repos.iter().map(|r| r.dir.as_str()).collect();
        assert_eq!(
            dirs,
            ["api", "fresh", "web"],
            "{shell}: lost+found and .puddle skipped"
        );
        let api = &f.repos[0];
        let mut uncommitted = api.uncommitted.items.clone();
        uncommitted.sort();
        assert_eq!(uncommitted, [" M a.txt", "?? new.txt"], "{shell}");
        assert_eq!(api.unpushed.items.len(), 1, "{shell}");
        assert!(api.unpushed.items[0].ends_with(" local only"), "{shell}");
        assert_eq!(api.stashes.items.len(), 1, "{shell}");
        assert!(
            api.stashes.items[0].starts_with("stash@{0}: WIP on main"),
            "{shell}"
        );
        let fresh = &f.repos[1];
        assert_eq!(fresh.uncommitted.items, ["?? x"], "{shell}");
        assert!(
            fresh.unpushed.is_empty() && fresh.stashes.is_empty(),
            "{shell}"
        );
        assert!(f.repos[2].is_clean(), "{shell}: a fresh clone is clean");
        assert_eq!(f.other.items, ["notes.txt"], "{shell}");
        assert!(f.errors.is_empty(), "{shell}: {:?}", f.errors);
        assert!(!report.is_clean());
        assert!(
            !tmp.path().join("pwned").exists(),
            "{shell}: the repo's fsmonitor ran"
        );
    }
}

#[tokio::test]
async fn an_empty_volume_and_a_repo_without_remote_are_judged_right() {
    for shell in shells() {
        let tmp = tempfile::tempdir().unwrap();
        let vol = tmp.path().join("vol");
        std::fs::create_dir_all(vol.join("lost+found")).unwrap();
        assert!(check(shell, &vol).await.is_clean(), "{shell}");

        // Every commit of a repo without a remote is unsaved; so are commits on other branches.
        let solo = vol.join("solo");
        std::fs::create_dir(&solo).unwrap();
        git(&solo, &["init", "-q", "-b", "main"]);
        std::fs::write(solo.join("a"), "a\n").unwrap();
        git(&solo, &["add", "a"]);
        git(&solo, &["commit", "-qm", "one"]);
        git(&solo, &["checkout", "-q", "-b", "side"]);
        std::fs::write(solo.join("b"), "b\n").unwrap();
        git(&solo, &["add", "b"]);
        git(&solo, &["commit", "-qm", "two"]);
        git(&solo, &["checkout", "-q", "--detach", "main"]);
        let report = check(shell, &vol).await;
        let solo = &report.findings.repos[0];
        assert_eq!(solo.unpushed.total(), 2, "{shell}: {:?}", solo.unpushed);
        assert!(solo.uncommitted.is_empty(), "{shell}");
    }
}

#[tokio::test]
async fn long_lists_are_capped_and_counted() {
    for shell in shells() {
        let tmp = tempfile::tempdir().unwrap();
        let vol = tmp.path().join("vol");
        let repo = vol.join("big");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        for i in 0..250 {
            std::fs::write(repo.join(format!("f{i}")), "x").unwrap();
            std::fs::write(vol.join(format!("loose{i}")), "x").unwrap();
        }
        let report = check(shell, &vol).await;
        let big = &report.findings.repos[0];
        assert_eq!(big.uncommitted.items.len(), 200, "{shell}");
        assert_eq!(big.uncommitted.total(), 250, "{shell}");
        assert_eq!(report.findings.other.items.len(), 200, "{shell}");
        assert_eq!(report.findings.other.total(), 250, "{shell}");
    }
}

#[tokio::test]
async fn odd_top_level_names_cannot_break_the_output() {
    for shell in shells() {
        let tmp = tempfile::tempdir().unwrap();
        let vol = tmp.path().join("vol");
        std::fs::create_dir_all(&vol).unwrap();
        std::fs::write(vol.join("tab\there"), "x").unwrap();
        std::fs::write(vol.join("new\nline"), "x").unwrap();
        std::fs::write(vol.join(".hidden"), "x").unwrap();
        std::fs::write(vol.join("..dots"), "x").unwrap();
        let report = check(shell, &vol).await;
        let mut other = report.findings.other.items.clone();
        other.sort();
        assert_eq!(
            other,
            ["..dots", ".hidden", "new?line", "tab?here"],
            "{shell}"
        );
    }
}

#[tokio::test]
async fn a_missing_volume_root_fails_closed() {
    for shell in shells() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = FakeRuntime::new();
        run_on_host(&rt, shell, tmp.path().join("missing"));
        let id = WorkspaceId::new("acme").unwrap();
        rt.create_volume(VolumeSpec {
            name: id.volume_name(),
            size: DiskSize::gib(1),
        })
        .await
        .unwrap();
        let err = Workspaces::default()
            .check_delete(&rt, &id)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot enter"), "{shell}: {err}");
    }
}

/// The fixtures must not touch the repository a git hook points `GIT_DIR` at: `git init --bare`
/// there turns that repository bare.
#[test]
fn fixtures_leave_the_repository_of_a_git_hook_alone() {
    if common::is_hook_env_child() {
        return;
    }
    common::assert_hook_env_leaves_the_repository_alone(
        "fixtures_leave_the_repository_of_a_git_hook_alone",
    );
}
