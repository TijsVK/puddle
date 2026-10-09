// SPDX-License-Identifier: GPL-3.0-or-later
//! The real `guest/clear-locks.sh` under dash and bash, against real git repositories in a temp
//! dir that plays the volume root, driven through [`Workspaces::clear_stale_locks`] on the fake
//! (its exec handler runs the script on the host). A fake proc dir stands in for `/proc`. Needs
//! `git` on the host.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions fail the test by panicking"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use puddle_compute::fake::{ExecContext, FakeRuntime};
use puddle_compute::{ExecOutput, ExecRequest, SandboxSpec};
use puddle_types::{ImageRef, SandboxName, WorkspaceId};
use puddle_workspace::{CLEAR_LOCKS_SH, LockReport, Workspaces};

mod common;
use common::command;

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

/// Git for the fixture repositories, with background maintenance off: newer git starts a
/// detached `git maintenance run --auto` after a commit (and an auto gc can do the same), which
/// creates and deletes `.git/objects/maintenance.lock` after the commit has returned, so a test
/// that lists the locks could catch it between the two (seen with git 2.55).
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    command("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "maintenance.auto")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_CONFIG_KEY_1", "gc.auto")
        .env("GIT_CONFIG_VALUE_1", "0")
        .env("GIT_AUTHOR_NAME", "T")
        .env("GIT_AUTHOR_EMAIL", "t@example.org")
        .env("GIT_COMMITTER_NAME", "T")
        .env("GIT_COMMITTER_EMAIL", "t@example.org")
        .output()
        .unwrap()
}

fn git_ok(dir: &Path, args: &[&str]) {
    let out = git(dir, args);
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Fixture {
    _tmp: tempfile::TempDir,
    vol: PathBuf,
    proc_dir: PathBuf,
}

/// A volume with: `api` (stale locks of several kinds, one nested), `web` (clean), `.puddle`
/// with a lock-named file, `lost+found`, a symlinked `.git`, a plain dir with a lock-named file,
/// and a hostile lock path with a newline. Plus an empty fake proc dir.
fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let vol = tmp.path().join("vol");
    let proc_dir = tmp.path().join("proc");
    std::fs::create_dir_all(&vol).unwrap();
    std::fs::create_dir_all(proc_dir.join("1")).unwrap();
    std::fs::write(proc_dir.join("1/comm"), "init\n").unwrap();
    std::fs::create_dir_all(proc_dir.join("2")).unwrap();
    std::fs::write(proc_dir.join("2/comm"), "bash\n").unwrap();
    std::fs::create_dir_all(proc_dir.join("net")).unwrap();
    for repo in ["api", "web"] {
        std::fs::create_dir(vol.join(repo)).unwrap();
        git_ok(&vol.join(repo), &["init", "-q", "-b", "main"]);
        std::fs::write(vol.join(repo).join("a.txt"), "a\n").unwrap();
        git_ok(&vol.join(repo), &["add", "."]);
        git_ok(&vol.join(repo), &["commit", "-qm", "first"]);
    }
    let api = vol.join("api/.git");
    for lock in [
        "index.lock",
        "HEAD.lock",
        "packed-refs.lock",
        "refs/heads/main.lock",
    ] {
        std::fs::write(api.join(lock), "").unwrap();
    }
    std::fs::create_dir_all(api.join("modules/sub/refs/heads")).unwrap();
    std::fs::write(api.join("modules/sub/index.lock"), "").unwrap();
    std::fs::write(api.join("refs/heads/odd\nname\t.lock"), "").unwrap();
    // Things that must survive.
    std::fs::write(api.join("keep.lockfile"), "x").unwrap();
    std::fs::write(vol.join("api/work.lock"), "user file").unwrap();
    std::fs::create_dir_all(vol.join(".puddle/code-server")).unwrap();
    std::fs::write(vol.join(".puddle/x.lock"), "").unwrap();
    std::fs::create_dir_all(vol.join("lost+found")).unwrap();
    std::fs::create_dir_all(vol.join("plain/.git")).unwrap();
    std::fs::write(vol.join("plain/.git/index.lock"), "").unwrap();
    // `plain` has a .git dir but isn't a repo: still a checkout dir, locks go. A symlinked .git is skipped.
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("index.lock"), "").unwrap();
    std::fs::create_dir(vol.join("linked")).unwrap();
    std::os::unix::fs::symlink(&outside, vol.join("linked/.git")).unwrap();
    std::os::unix::fs::symlink(&outside, vol.join("linkdir")).unwrap();
    Fixture {
        _tmp: tmp,
        vol,
        proc_dir,
    }
}

async fn run(shell: &'static str, fx: &Fixture) -> LockReport {
    let rt = FakeRuntime::new();
    let vol = fx.vol.clone();
    let proc_dir = fx.proc_dir.clone();
    rt.on_exec(move |_: &mut ExecContext<'_>, r: &ExecRequest| {
        if r.program != "sh" || r.args.get(1).map(String::as_str) != Some(CLEAR_LOCKS_SH) {
            return None;
        }
        assert_eq!(r.args.get(3).map(String::as_str), Some("/workspaces/acme"));
        let out = command(shell)
            .args(["-c", CLEAR_LOCKS_SH, "puddle-clear-locks"])
            .arg(&vol)
            .arg(&proc_dir)
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
    let id = WorkspaceId::new("acme").unwrap();
    let spec = SandboxSpec::new(
        SandboxName::new("box").unwrap(),
        ImageRef::new(FakeRuntime::DEBIAN).unwrap(),
    );
    let w = Workspaces::default();
    let sb = w.create(&rt, &id, spec, None).await.unwrap();
    w.clear_stale_locks(&sb, &id).await.unwrap()
}

fn locks_under(root: &Path) -> Vec<String> {
    let out = command("find")
        .arg(root)
        .args(["-name", "*.lock", "-print0"])
        .output()
        .unwrap();
    let mut v: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|l| !l.is_empty())
        .map(|l| l.strip_prefix(root.to_str().unwrap()).unwrap().to_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn stale_locks_in_checkouts_are_removed_and_nothing_else() {
    for shell in shells() {
        let fx = fixture();
        let report = run(shell, &fx).await;
        assert!(!report.skipped_busy, "{shell}");
        assert!(report.errors.is_empty(), "{shell}: {:?}", report.errors);
        let mut removed = report.removed.clone();
        removed.sort();
        assert_eq!(
            removed,
            [
                "api/.git/HEAD.lock",
                "api/.git/index.lock",
                "api/.git/modules/sub/index.lock",
                "api/.git/packed-refs.lock",
                "api/.git/refs/heads/main.lock",
                "api/.git/refs/heads/odd?name?.lock",
                "plain/.git/index.lock",
            ],
            "{shell}"
        );
        // Left alone: user files, .puddle, a symlinked .git's target.
        assert_eq!(
            locks_under(&fx.vol),
            ["/.puddle/x.lock", "/api/work.lock"],
            "{shell}"
        );
        assert!(fx.vol.join("api/.git/keep.lockfile").exists(), "{shell}");
        assert!(
            fx.vol.parent().unwrap().join("outside/index.lock").exists(),
            "{shell}: followed a symlink out of the volume"
        );
    }
}

#[tokio::test]
async fn git_works_again_after_the_locks_are_cleared() {
    for shell in shells() {
        let fx = fixture();
        let api = fx.vol.join("api");
        assert!(
            !git(&api, &["commit", "--allow-empty", "-qm", "x"])
                .status
                .success()
        );
        run(shell, &fx).await;
        std::fs::write(api.join("b.txt"), "b\n").unwrap();
        git_ok(&api, &["add", "b.txt"]);
        git_ok(&api, &["commit", "-qm", "after the crash"]);
        git_ok(&api, &["fsck", "--full"]);
    }
}

#[tokio::test]
async fn nothing_is_removed_while_a_git_process_runs() {
    for shell in shells() {
        for comm in ["git", "git-remote-http", "git-credential-store"] {
            let fx = fixture();
            std::fs::create_dir_all(fx.proc_dir.join("77")).unwrap();
            std::fs::write(fx.proc_dir.join("77/comm"), format!("{comm}\n")).unwrap();
            let before = locks_under(&fx.vol);
            let report = run(shell, &fx).await;
            assert!(report.skipped_busy, "{shell} {comm}");
            assert_eq!(report.removed_count(), 0);
            assert_eq!(
                locks_under(&fx.vol),
                before,
                "{shell} {comm}: removed locks"
            );
        }
    }
}

#[tokio::test]
async fn processes_that_only_look_like_git_do_not_block() {
    for shell in shells() {
        let fx = fixture();
        for (pid, comm) in [("80", "gitk-helper"), ("81", "digit"), ("82", "my-git")] {
            std::fs::create_dir_all(fx.proc_dir.join(pid)).unwrap();
            std::fs::write(fx.proc_dir.join(pid).join("comm"), format!("{comm}\n")).unwrap();
        }
        assert!(!run(shell, &fx).await.skipped_busy, "{shell}");
    }
}

#[tokio::test]
async fn an_empty_volume_and_a_second_run_are_fine() {
    for shell in shells() {
        let fx = fixture();
        run(shell, &fx).await;
        let again = run(shell, &fx).await;
        assert_eq!(again.removed_count(), 0, "{shell}");
        assert_eq!(again.errors, Vec::<String>::new());
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
