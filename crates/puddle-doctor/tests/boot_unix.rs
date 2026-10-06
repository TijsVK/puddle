// SPDX-License-Identifier: GPL-3.0-or-later
//! The test boot's process handling against fake `msb` scripts: the real VM boot is a VM test
//! (`vm_doctor.rs`).
#![cfg(unix)]
#![cfg_attr(
    unix,
    expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test helpers outside #[test] fns fail the test by panicking"
    )
)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use puddle_doctor::boot::test_boot;
use puddle_doctor::{BootFacts, PROBE_EXIT_CODE, ProcessOutcome};

/// A runtime folder whose `msb` is `script`.
fn runtime(script: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let msb = dir.path().join("msb");
    std::fs::write(&msb, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&msb, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn exit_code(facts: &BootFacts) -> Option<i32> {
    match facts {
        BootFacts::Ran {
            outcome: ProcessOutcome::Exited { code, .. },
            ..
        } => *code,
        other => panic!("unexpected {other:?}"),
    }
}

const LIMIT: Duration = Duration::from_secs(20);

#[test]
fn msb_runs_the_probe_in_a_rootfs_with_a_private_home() {
    // Checks what msb is given, then runs the probe the way the guest would.
    let dir = runtime(
        r#"[ "$1" = run ] && [ "$3" = --no-stdin ] && [ "$4" = -- ] && [ "$5" = /probe ] || exit 9
case "$MSB_HOME" in */home) ;; *) exit 8 ;; esac
[ -z "$MSB_USER_SET" ] || exit 7
[ "$(cut -d: -f1,3,7 "$2/etc/passwd")" = root:0:/probe ] || exit 6
exec "$2/probe""#,
    );
    let facts = test_boot(dir.path(), "x86_64", LIMIT);
    let expected = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some(PROBE_EXIT_CODE)
    } else {
        // The probe is a Linux x86-64 program; elsewhere exec fails after the checks passed.
        exit_code(&facts)
    };
    assert_eq!(exit_code(&facts), expected, "{facts:?}");
    assert!(matches!(facts, BootFacts::Ran { retried: false, .. }));
}

#[test]
fn losing_the_boot_race_is_retried_once() {
    let marker = tempfile::tempdir().unwrap();
    let m = marker.path().join("first");
    let dir = runtime(&format!(
        r#"if [ ! -e "{m}" ]; then : > "{m}"; echo "error: sandbox process exited (exit code: 0) before agent relay became available" >&2; exit 1; fi
exit 42"#,
        m = m.display()
    ));
    let facts = test_boot(dir.path(), "x86_64", LIMIT);
    assert_eq!(exit_code(&facts), Some(PROBE_EXIT_CODE));
    assert!(matches!(facts, BootFacts::Ran { retried: true, .. }));
}

#[test]
fn losing_it_twice_reports_the_failure() {
    let dir = runtime(
        r#"echo "error: sandbox process exited (exit code: 0) before agent relay became available" >&2; exit 1"#,
    );
    let facts = test_boot(dir.path(), "x86_64", LIMIT);
    assert_eq!(exit_code(&facts), Some(1));
    assert!(matches!(facts, BootFacts::Ran { retried: true, .. }));
}

#[test]
fn other_failures_are_not_retried() {
    let dir = runtime("echo 'error: something else' >&2; exit 1");
    let facts = test_boot(dir.path(), "x86_64", LIMIT);
    let BootFacts::Ran {
        outcome: ProcessOutcome::Exited { stderr_tail, .. },
        retried,
    } = facts
    else {
        panic!("unexpected {facts:?}");
    };
    assert_eq!(stderr_tail, "error: something else");
    assert!(!retried);
}

#[test]
fn a_hanging_boot_times_out() {
    let dir = runtime("sleep 30");
    let facts = test_boot(dir.path(), "x86_64", Duration::from_millis(500));
    assert!(matches!(
        facts,
        BootFacts::Ran {
            outcome: ProcessOutcome::TimedOut { .. },
            retried: false
        }
    ));
}

#[test]
fn a_relative_runtime_dir_is_a_setup_failure() {
    assert!(matches!(
        test_boot(Path::new("relative/runtime"), "x86_64", LIMIT),
        BootFacts::SetupFailed { .. }
    ));
}
