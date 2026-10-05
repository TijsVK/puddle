// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests: run the built `puddle` binary as a user would.
#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] fns fail the test by panicking"
)]

use std::process::Command;

fn puddle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_puddle"))
        .args(args)
        .output()
        .expect("the puddle binary runs")
}

#[test]
fn version_prints_name_and_version() {
    let out = puddle(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim_end(),
        format!("puddle {}", puddle_types::VERSION)
    );
}

#[test]
fn help_prints_usage() {
    let out = puddle(&["--help"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .starts_with("usage: puddle")
    );
}

#[test]
fn unknown_argument_exits_2_with_usage_on_stderr() {
    let out = puddle(&["--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(String::from_utf8(out.stdout).unwrap(), "");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("unknown argument: --bogus"), "{stderr}");
    assert!(stderr.contains("usage: puddle"), "{stderr}");
}
