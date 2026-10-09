// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration test: the built agent binary's command line.
#![expect(
    clippy::unwrap_used,
    reason = "a helper outside #[test] fns, only in tests"
)]

use std::process::Command;

fn agent(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_puddle-agent"))
        .args(args)
        .env("PUDDLE_AGENT_LISTEN", "nonsense")
        .output()
        .unwrap()
}

#[test]
fn prints_version_line() {
    let out = agent(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim_end(),
        format!("puddle-agent {}", puddle_types::VERSION)
    );
}

#[test]
fn bad_arguments_and_settings_exit_2() {
    for args in [&["--nope"][..], &["connect", "host"], &[]] {
        let out = agent(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_ne!(out.stderr, b"");
    }
}

#[test]
fn a_listener_that_cannot_bind_stops_the_agent_with_a_logged_error() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_puddle-agent"))
        .env(
            "PUDDLE_AGENT_LISTEN",
            taken.local_addr().unwrap().to_string(),
        )
        .env("PUDDLE_AGENT_TARGET", "unix:///nonexistent/puddle.sock")
        .env("PUDDLE_AGENT_OOM", "0")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("puddle-agent stopped"), "{stderr}");
}
