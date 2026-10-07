// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle doctor` on a real host with the real runtime (tiers K and W): all green with
//! the runtime CI installed, including a test boot, in under 30 s; and a missing runtime, another
//! version and a runtime file this user may not run (a deny ACE on Windows, no execute bit on
//! Linux) each give their own finding on the real probes. Runs only under `--profile vm`.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] fns fail the test by panicking; the report goes to the test log"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use puddle_doctor::{CheckId, Finding, Options, Report, Status, SystemProbe, diagnose};
use puddle_runtime::{
    DevOverride, LIBKRUNFW_FILE_NAME, MSB_FILE_NAME, RUNTIME_DIR_NAME, RuntimeVersion,
};
use puddle_vm_tests::{RuntimePair, Settings};

/// The acceptance bar for a whole run.
const BAR: Duration = Duration::from_secs(30);

/// The firmware file name msb 0.7.7 looks for beside itself on Linux
/// (`microsandbox_utils::libkrunfw_filename("linux")`); puddle's runtime layout only defines
/// Windows's, and CI installs it as `libkrunfw.so.5` for the SDK's explicit config.
const LINUX_LIBKRUNFW: &str = "libkrunfw.so.5.6.1";

/// The runtime pair CI installed (`PUDDLE_VM_RUNTIME_DIR`).
fn ci_runtime() -> RuntimePair {
    let settings = Settings::from_lookup(|var| std::env::var(var).ok()).expect("VM settings");
    RuntimePair::find_in(&settings.runtime_dir).expect("runtime pair")
}

/// A puddle-style runtime folder in `root` with a copy (never a link: the permission test
/// changes the file) of CI's pair, laid out as puddle ships it.
fn runtime_copy(root: &Path) -> PathBuf {
    let pair = ci_runtime();
    let dir = root.join(RUNTIME_DIR_NAME);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(&pair.msb, dir.join(MSB_FILE_NAME)).unwrap();
    // msb pairs itself with the firmware beside it, under the name it was released with.
    let firmware = if cfg!(windows) {
        LIBKRUNFW_FILE_NAME
    } else {
        LINUX_LIBKRUNFW
    };
    std::fs::copy(&pair.libkrunfw, dir.join(firmware)).unwrap();
    dir
}

fn run(dir: PathBuf, expected: RuntimeVersion, options: &Options) -> Report {
    let probe = SystemProbe::new(dir, expected, DevOverride::none());
    let report = diagnose(&probe, options, "vm-test");
    eprintln!("{}", report.to_text());
    report
}

fn status(report: &Report, id: CheckId) -> Status {
    report.check(id).map_or(Status::Skipped, |c| c.status)
}

fn finding(report: &Report, id: CheckId) -> Option<Finding> {
    report.check(id).and_then(|c| c.finding)
}

#[test]
fn vm_doctor_is_all_green_with_a_test_boot_under_30_s() {
    let root = tempfile::tempdir().unwrap();
    let dir = runtime_copy(root.path());
    let report = run(dir, RuntimeVersion::built_for(), &Options::default());
    for id in [
        CheckId::Hypervisor,
        CheckId::Runtime,
        CheckId::Launch,
        CheckId::TestBoot,
    ] {
        assert_eq!(status(&report, id), Status::Ok, "{id:?}");
    }
    assert!(
        report
            .checks
            .iter()
            .all(|c| matches!(c.status, Status::Ok | Status::Info)),
        "every check ok or info"
    );
    assert!(report.ok);
    assert!(
        Duration::from_millis(report.elapsed_ms) < BAR,
        "{} ms",
        report.elapsed_ms
    );
}

/// msb's boot race is fixed in the fork, so the doctor's test boot has no retry: every one
/// of 20 boots in a row must pass on its own.
#[test]
fn vm_test_boot_passes_20_in_a_row_without_a_retry() {
    let root = tempfile::tempdir().unwrap();
    let dir = runtime_copy(root.path());
    for round in 1..=20 {
        let facts = puddle_doctor::boot::test_boot(&dir, "x86_64", BAR);
        let ok = matches!(
            &facts,
            puddle_doctor::BootFacts::Ran {
                outcome: puddle_doctor::ProcessOutcome::Exited {
                    code: Some(puddle_doctor::PROBE_EXIT_CODE),
                    ..
                }
            }
        );
        assert!(ok, "boot {round} of 20: {facts:?}");
    }
}

#[test]
fn vm_doctor_names_a_missing_runtime() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join(RUNTIME_DIR_NAME);
    std::fs::create_dir_all(&dir).unwrap();
    let report = run(dir, RuntimeVersion::built_for(), &Options::default());
    assert_eq!(status(&report, CheckId::Hypervisor), Status::Ok);
    assert_eq!(
        finding(&report, CheckId::Runtime),
        Some(Finding::RuntimeMissing)
    );
    assert_eq!(status(&report, CheckId::Launch), Status::Skipped);
    assert_eq!(status(&report, CheckId::TestBoot), Status::Skipped);
    assert!(!report.ok);
}

#[test]
fn vm_doctor_names_both_versions_on_a_mismatch() {
    let root = tempfile::tempdir().unwrap();
    let dir = runtime_copy(root.path());
    let built = RuntimeVersion::built_for();
    let other: RuntimeVersion =
        format!("{}-puddle.{}", built.release(), built.puddle_revision() + 1)
            .parse()
            .unwrap();
    let report = run(dir, other, &Options::default());
    assert_eq!(
        finding(&report, CheckId::Runtime),
        Some(Finding::RuntimeVersionMismatch)
    );
    let summary = &report.check(CheckId::Runtime).unwrap().summary;
    assert!(summary.contains(&other.to_string()), "{summary}");
    assert!(summary.contains(&built.to_string()), "{summary}");
    assert_eq!(status(&report, CheckId::TestBoot), Status::Skipped);
}

#[test]
fn vm_doctor_reports_a_runtime_this_user_may_not_run() {
    let root = tempfile::tempdir().unwrap();
    let dir = runtime_copy(root.path());
    let msb = dir.join(MSB_FILE_NAME);
    let _restore = deny_run(&msb);
    let report = run(dir, RuntimeVersion::built_for(), &Options::default());
    let runtime = report.check(CheckId::Runtime).unwrap();
    assert_eq!(
        runtime.finding,
        Some(Finding::RuntimePermissions),
        "{runtime:?}"
    );
    let fix = runtime.fix.as_deref().unwrap();
    assert!(fix.contains(&*msb.to_string_lossy()), "{fix}");
    assert_eq!(status(&report, CheckId::Launch), Status::Skipped);
}

/// Undoes [`deny_run`] on drop, so the temp dir can be removed.
struct Restore {
    #[cfg(windows)]
    path: PathBuf,
    #[cfg(windows)]
    sid: String,
}

impl Drop for Restore {
    fn drop(&mut self) {
        #[cfg(windows)]
        icacls(&self.path, &["/remove:d", &format!("*{}", self.sid)]);
    }
}

/// Takes away this user's right to run `path`: a deny ACE for read + execute.
#[cfg(windows)]
fn deny_run(path: &Path) -> Restore {
    let sid = current_user_sid();
    icacls(path, &["/deny", &format!("*{sid}:(RX)")]);
    Restore {
        path: path.to_owned(),
        sid,
    }
}

/// Takes away the execute bits of `path`.
#[cfg(unix)]
fn deny_run(path: &Path) -> Restore {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    Restore {}
}

#[cfg(windows)]
fn icacls(path: &Path, args: &[&str]) {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    eprintln!(
        "icacls {args:?}: {}",
        String::from_utf8_lossy(&out.stdout).trim()
    );
    assert!(out.status.success(), "icacls {args:?}: {out:?}");
}

/// This user's SID: the `S-1-...` field of `whoami /user`.
#[cfg(windows)]
fn current_user_sid() -> String {
    let out = std::process::Command::new("whoami")
        .arg("/user")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    text.split_whitespace()
        .rev()
        .find(|field| field.starts_with("S-1-"))
        .expect("a SID in the output of whoami /user")
        .to_owned()
}
