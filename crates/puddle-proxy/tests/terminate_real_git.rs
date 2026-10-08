// SPDX-License-Identifier: GPL-3.0-or-later
//! Real `git` against the proxy and the real injector: the messages a refusal carries are what
//! the person at the terminal reads, and a request git sends with its own header behaves as it
//! would without puddle.
//!
//! Needs `git` on the path; without it the tests skip unless `PUDDLE_TOOLS_REQUIRED` is set (CI
//! sets it). Unix only: `git` on Windows verifies certificates with its own TLS backend, and the
//! Windows tier runs real `git` end to end.
#![cfg(unix)]
#![expect(
    clippy::print_stderr,
    clippy::unwrap_used,
    reason = "a skipped test says so; helpers outside #[test] functions fail the test by panicking"
)]
mod git_support;
mod terminate_support;

use std::path::Path;
use std::process::Stdio;

use git_support::{GitRig, PERSONAL, SHA, WORK, token_basic};
use terminate_support::{Guest, LOCAL};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;

/// What a `git` run printed.
struct Ran {
    ok: bool,
    stdout: String,
    stderr: String,
}

struct Git {
    t: GitRig,
    home: tempfile::TempDir,
    port: u16,
    _bridge: JoinHandle<()>,
    _guest: Guest,
}

fn git_available() -> bool {
    let found = std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok();
    if !found {
        assert!(
            std::env::var_os("PUDDLE_TOOLS_REQUIRED").is_none(),
            "PUDDLE_TOOLS_REQUIRED is set but git is not on the path"
        );
        eprintln!("skipped: git not found");
    }
    found
}

/// A loopback port that is a Git client's HTTP proxy: every connection becomes a stream into the
/// guest's route, as the guest agent relays the proxy port.
async fn proxy_port(guest: &Guest) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind((LOCAL, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut control = guest.control.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let Ok(mut stream) = control.open_stream().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
            });
        }
    });
    (port, task)
}

impl Git {
    async fn new() -> Option<Self> {
        if !git_available() {
            return None;
        }
        let t = GitRig::new().await;
        let guest = t.rig.guest().await;
        let (port, bridge) = proxy_port(&guest).await;
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("ca.pem"), t.rig.ca.certificate().pem()).unwrap();
        std::fs::write(home.path().join("gitconfig"), "").unwrap();
        let this = Self {
            t,
            home,
            port,
            _bridge: bridge,
            _guest: guest,
        };
        // A repository with one commit, to push from.
        for args in [
            &["init", "-q", "-b", "main", "repo"][..],
            &[
                "-C",
                "repo",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.org",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
        ] {
            assert!(this.run(args).await.ok, "{args:?}");
        }
        Some(this)
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        // Under a git hook git exports `GIT_DIR` and friends; none of it is for this repository.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.home.path().join("gitconfig"))
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GCM_INTERACTIVE", "never")
            .stdin(Stdio::null());
        command
    }

    async fn run(&self, args: &[&str]) -> Ran {
        let ca: &Path = &self.home.path().join("ca.pem");
        let output = self
            .command()
            .args([
                "-c",
                &format!("http.proxy=http://127.0.0.1:{}", self.port),
                "-c",
                &format!("http.sslCAInfo={}", ca.display()),
                "-c",
                "credential.helper=",
            ])
            .args(args)
            .output()
            .await
            .unwrap();
        Ran {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

#[tokio::test]
async fn a_fetch_from_a_covered_repository_works_and_git_sends_no_authorization_of_its_own() {
    let Some(git) = Git::new().await else { return };
    let ran = git
        .run(&["ls-remote", "https://bound.test/acme/web.git"])
        .await;
    assert!(ran.ok, "{}", ran.stderr);
    assert!(
        ran.stdout.contains(SHA) && ran.stdout.contains("refs/heads/main"),
        "{}",
        ran.stdout
    );
    let seen = git.t.server.recorded();
    assert_eq!(
        seen.len(),
        1,
        "git needed one request, not a 401 and a retry"
    );
    assert_eq!(seen[0].headers_named("authorization"), [token_basic(WORK)]);
    // Another owner gets the other identity's credential.
    let ran = git
        .run(&["ls-remote", "https://bound.test/someone/else.git"])
        .await;
    assert!(ran.ok, "{}", ran.stderr);
    assert_eq!(
        git.t.server.recorded()[1].headers_named("authorization"),
        [token_basic(PERSONAL)]
    );
}

#[tokio::test]
async fn a_refused_push_is_readable_in_git_s_own_output_and_nothing_is_sent() {
    let Some(git) = Git::new().await else { return };
    let ran = git
        .run(&[
            "-C",
            "repo",
            "push",
            "--dry-run",
            "https://bound.test/acme/other.git",
            "HEAD:refs/heads/x",
        ])
        .await;
    assert!(!ran.ok);
    assert!(
        ran.stderr.contains(
            "remote: puddle: push to bound.test/acme/other is not on this workspace's push list; add it, or turn off \"Only push to listed repos\" on the workspace's Git tab"
        ),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains("403"), "{}", ran.stderr);
    assert!(git.t.server.recorded().is_empty());
    // The repository on the list goes through as far as a dry run goes.
    let ran = git
        .run(&[
            "-C",
            "repo",
            "push",
            "--dry-run",
            "https://bound.test/acme/web.git",
            "HEAD:refs/heads/x",
        ])
        .await;
    assert!(ran.ok, "{}", ran.stderr);
    let seen = git.t.server.recorded();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers_named("authorization"), [token_basic(WORK)]);
}

#[tokio::test]
async fn a_refused_fetch_is_readable_when_the_pull_list_is_on() {
    let Some(git) = Git::new().await else { return };
    git.t.world.switches(true, true);
    let ran = git
        .run(&["ls-remote", "https://bound.test/someone/else.git"])
        .await;
    assert!(!ran.ok);
    assert!(
        ran.stderr.contains(
            "remote: puddle: pull from bound.test/someone/else is not on this workspace's pull list; add it, or turn off \"Only pull from listed repos\" on the workspace's Git tab"
        ),
        "{}",
        ran.stderr
    );
    assert!(git.t.server.recorded().is_empty());
}

#[tokio::test]
async fn a_repository_no_identity_covers_works_with_the_token_git_has_and_fails_as_it_would_without_one()
 {
    let Some(git) = Git::new().await else { return };
    for identity in git.t.world.store.identities().unwrap() {
        git.t
            .world
            .store
            .detach_identity(&git.t.world.workspace, identity.id)
            .unwrap();
    }
    // Without a token: git's own error for a private repository, no word from puddle.
    let ran = git
        .run(&["ls-remote", "https://bound.test/acme/private.git"])
        .await;
    assert!(!ran.ok);
    assert!(!ran.stderr.contains("puddle"), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("terminal prompts disabled"),
        "{}",
        ran.stderr
    );
    // With the token in the address, which git sends only after the host's 401 (a credential
    // helper or `.netrc` is the same): that 401 has to reach git.
    let ran = git
        .run(&[
            "ls-remote",
            &format!("https://x-access-token:{WORK}@bound.test/acme/private.git"),
        ])
        .await;
    assert!(ran.ok, "{}", ran.stderr);
    let seen = git.t.server.recorded();
    assert_eq!(seen.len(), 3, "the first run's 401, then 401 and a retry");
    assert_eq!(seen[1].header("authorization"), None);
    assert_eq!(seen[2].headers_named("authorization"), [token_basic(WORK)]);
}

#[tokio::test]
async fn git_s_own_header_goes_out_as_it_is_and_a_401_to_it_is_what_git_would_have_seen_anyway() {
    let Some(git) = Git::new().await else { return };
    // The workspace's own token for a private repository the host accepts it for.
    let ran = git
        .run(&[
            "-c",
            "http.extraHeader=Authorization: Bearer mine",
            "ls-remote",
            "https://bound.test/acme/private.git",
        ])
        .await;
    assert!(ran.ok, "{}", ran.stderr);
    let seen = git.t.server.recorded();
    assert_eq!(seen[0].headers_named("authorization"), ["Bearer mine"]);
    assert!(!format!("{seen:?}").contains(WORK));
    // One the host rejects: git's own error, with no word from puddle.
    let ran = git
        .run(&[
            "-c",
            "http.extraHeader=Authorization: Bearer other",
            "ls-remote",
            "https://bound.test/acme/private.git",
        ])
        .await;
    assert!(!ran.ok);
    assert!(!ran.stderr.contains("puddle"), "{}", ran.stderr);
    assert!(
        ran.stderr.contains("terminal prompts disabled") || ran.stderr.contains("401"),
        "{}",
        ran.stderr
    );
    assert_eq!(
        git.t.server.recorded()[1].headers_named("authorization"),
        ["Bearer other"]
    );
}
