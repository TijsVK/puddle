// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle doctor` run as a user would, from a folder without the bundled runtime: the report
//! names the missing runtime, the exit code says something must be fixed, and the test boot is
//! never attempted. A real runtime is checked by `vm_doctor` (puddle-vm-tests).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns fail the test by panicking"
)]

use std::path::Path;
use std::process::{Command, Output};

/// Copies the built `puddle` into `dir` (no `runtime/` beside it) and runs it there.
fn puddle_in(dir: &Path, args: &[&str]) -> Output {
    let exe = dir.join(if cfg!(windows) {
        "puddle.exe"
    } else {
        "puddle"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_puddle"), &exe).unwrap();
    Command::new(&exe).args(args).output().unwrap()
}

#[test]
fn json_names_the_missing_runtime_and_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let out = puddle_in(dir.path(), &["doctor", "--json"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["puddle_version"], puddle_types::VERSION);
    assert_eq!(v["ok"], false);
    let checks = v["checks"].as_array().unwrap();
    let by_id = |id: &str| checks.iter().find(|c| c["id"] == id).unwrap();
    assert_eq!(by_id("runtime")["finding"], "runtime_missing");
    let fix = by_id("runtime")["fix"].as_str().unwrap();
    assert!(
        fix.contains(&*dir.path().join("runtime").to_string_lossy()),
        "{fix}"
    );
    assert_eq!(by_id("launch")["status"], "skipped");
    assert_eq!(by_id("test_boot")["status"], "skipped");
}

#[test]
fn text_report_has_the_fix_line() {
    let dir = tempfile::tempdir().unwrap();
    let out = puddle_in(dir.path(), &["doctor", "--no-boot"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("puddle doctor (puddle "), "{text}");
    assert!(text.contains("FAIL  Bundled runtime"), "{text}");
    assert!(text.contains("fix:  Reinstall puddle"), "{text}");
    assert!(
        text.contains("to fix before puddle can run sandboxes"),
        "{text}"
    );
}

#[test]
fn unknown_doctor_flag_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = puddle_in(dir.path(), &["doctor", "--fix"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("unknown argument: --fix")
    );
}
