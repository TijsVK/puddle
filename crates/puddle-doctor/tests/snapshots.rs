// SPDX-License-Identifier: GPL-3.0-or-later
//! Every finding, worded exactly: the report for each faked machine is compared with a file in
//! `tests/snapshots/` (text, then JSON). After a deliberate wording change, regenerate with
//! `PUDDLE_UPDATE_SNAPSHOTS=1 cargo nextest run -p puddle-doctor --test snapshots` and review
//! the diff.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] fns fail the test by panicking"
)]

use std::cell::Cell;
use std::path::PathBuf;
use std::time::Duration;

use puddle_doctor::{
    AccessDenied, BootFacts, CheckId, CodeIntegrity, Finding, GsaFacts, HypervisorApi,
    HypervisorFacts, JobFacts, Options, Os, Probe, ProcessOutcome, Report, RuntimeFacts,
    RuntimeState, Status, diagnose,
};
use puddle_runtime::RuntimeError;

const DIR: &str = r"C:\Users\dev\AppData\Local\Programs\puddle\runtime";
const MSB: &str = r"C:\Users\dev\AppData\Local\Programs\puddle\runtime\msb.exe";
/// The runtime folder of the non-Windows machines (a Linux package puts it next to the program).
const UNIX_DIR: &str = "/opt/puddle/runtime";
const UNIX_MSB: &str = "/opt/puddle/runtime/msb";
const EXPECTED: &str = "0.7.7-puddle.2";

/// A machine described by its facts; counts the calls that cost time.
#[derive(Clone)]
struct Fake {
    os: Os,
    hv: HypervisorFacts,
    ci: Option<CodeIntegrity>,
    runtime: RuntimeState,
    launch: ProcessOutcome,
    boot: BootFacts,
    job: Option<JobFacts>,
    gsa: Option<GsaFacts>,
    launches: Cell<u32>,
    boots: Cell<u32>,
}

fn exited(code: i32, stdout: &str, stderr: &str, ms: u64) -> ProcessOutcome {
    ProcessOutcome::Exited {
        code: Some(code),
        stdout_first_line: stdout.into(),
        stderr_tail: stderr.into(),
        elapsed: Duration::from_millis(ms),
    }
}

fn booted() -> BootFacts {
    BootFacts::Ran {
        outcome: exited(42, "", "", 1130),
    }
}

fn status(code: u32) -> i32 {
    i32::from_ne_bytes(code.to_ne_bytes())
}

/// A healthy Windows laptop.
fn windows() -> Fake {
    Fake {
        os: Os::Windows,
        hv: HypervisorFacts {
            api: HypervisorApi::Ready,
            firmware_virtualization: Some(true),
            hypervisor_vendor: Some("Microsoft Hv".into()),
        },
        ci: Some(CodeIntegrity {
            hvci: true,
            user_mode_enforced: false,
            user_mode_audit: false,
            test_signing: false,
        }),
        runtime: RuntimeState::Ready {
            version: EXPECTED.into(),
            overridden: false,
        },
        launch: exited(0, "msb 0.7.7-puddle.2", "", 85),
        boot: booted(),
        job: None,
        gsa: Some(GsaFacts::NotInstalled),
        launches: Cell::new(0),
        boots: Cell::new(0),
    }
}

fn linux() -> Fake {
    Fake {
        os: Os::Linux,
        hv: HypervisorFacts {
            api: HypervisorApi::Ready,
            firmware_virtualization: Some(true),
            hypervisor_vendor: None,
        },
        ci: None,
        gsa: None,
        ..windows()
    }
}

impl Probe for Fake {
    fn os(&self) -> Os {
        self.os
    }
    fn arch(&self) -> String {
        "x86_64".into()
    }
    fn hypervisor(&self) -> HypervisorFacts {
        self.hv.clone()
    }
    fn code_integrity(&self) -> Option<CodeIntegrity> {
        self.ci
    }
    fn runtime(&self) -> RuntimeFacts {
        let (dir, msb) = if self.os == Os::Windows {
            (DIR, MSB)
        } else {
            (UNIX_DIR, UNIX_MSB)
        };
        RuntimeFacts {
            dir: PathBuf::from(dir),
            msb: PathBuf::from(msb),
            expected: EXPECTED.into(),
            state: self.runtime.clone(),
        }
    }
    fn launch(&self, _limit: Duration) -> ProcessOutcome {
        self.launches.set(self.launches.get() + 1);
        self.launch.clone()
    }
    fn boot(&self, limit: Duration) -> BootFacts {
        assert!(limit >= Duration::from_secs(5) && limit <= Duration::from_secs(25));
        self.boots.set(self.boots.get() + 1);
        self.boot.clone()
    }
    fn job(&self) -> Option<JobFacts> {
        self.job
    }
    fn global_secure_access(&self) -> Option<GsaFacts> {
        self.gsa
    }
}

fn run(fake: &Fake, options: &Options) -> Report {
    let mut report = diagnose(fake, options, "0.1.0");
    report.elapsed_ms = 1234;
    report
}

/// Compares (or with `PUDDLE_UPDATE_SNAPSHOTS=1`, writes) `tests/snapshots/<name>.snap`.
fn snapshot(name: &str, report: &Report) {
    let actual = format!("{}\n---\n{}\n", report.to_text(), report.to_json());
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.snap"));
    if std::env::var_os("PUDDLE_UPDATE_SNAPSHOTS").is_some_and(|v| v == "1") {
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e}; run with PUDDLE_UPDATE_SNAPSHOTS=1",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert!(
        expected == actual,
        "snapshot {name} differs; run with PUDDLE_UPDATE_SNAPSHOTS=1 and review.\n--- expected\n{expected}\n--- actual\n{actual}"
    );
}

fn finding(report: &Report, id: CheckId) -> Option<Finding> {
    report.check(id).and_then(|c| c.finding)
}

fn check(name: &str, fake: &Fake, id: CheckId, expected: Option<Finding>) -> Report {
    let report = run(fake, &Options::default());
    snapshot(name, &report);
    assert_eq!(finding(&report, id), expected, "{name}");
    report
}

#[test]
fn windows_all_green() {
    let fake = windows();
    let r = check("windows_all_green", &fake, CheckId::TestBoot, None);
    assert!(r.ok);
    assert!(
        r.checks
            .iter()
            .all(|c| matches!(c.status, Status::Ok | Status::Info))
    );
    assert_eq!((fake.launches.get(), fake.boots.get()), (1, 1));
}

#[test]
fn windows_whp_not_enabled() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::NotInstalled {
                detail:
                    "WinHvPlatform.dll: The specified module could not be found. (os error 126)"
                        .into(),
            },
            firmware_virtualization: Some(true),
            hypervisor_vendor: None,
        },
        // msb links WinHvPlatform.dll, so it can't start either.
        launch: exited(status(0xC000_0135), "", "", 30),
        ..windows()
    };
    let r = check(
        "windows_whp_not_enabled",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::WhpNotEnabled),
    );
    assert_eq!(finding(&r, CheckId::Launch), Some(Finding::DllMissing));
    assert_eq!(fake.boots.get(), 0);
}

#[test]
fn windows_firmware_virtualization_off() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::NotRunning,
            firmware_virtualization: Some(false),
            hypervisor_vendor: None,
        },
        ..windows()
    };
    let r = check(
        "windows_firmware_off",
        &fake,
        CheckId::Virtualization,
        Some(Finding::FirmwareVirtualizationOff),
    );
    assert_eq!(
        finding(&r, CheckId::Hypervisor),
        Some(Finding::FirmwareVirtualizationOff)
    );
}

#[test]
fn windows_hypervisor_not_running() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::NotRunning,
            firmware_virtualization: Some(true),
            hypervisor_vendor: None,
        },
        ..windows()
    };
    check(
        "windows_hypervisor_not_running",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::HypervisorNotRunning),
    );
}

#[test]
fn windows_in_a_vm_without_nested_virtualization() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::NotRunning,
            firmware_virtualization: Some(false),
            hypervisor_vendor: Some("VMwareVMware".into()),
        },
        ..windows()
    };
    let r = check(
        "windows_vm_without_nesting",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::NestedVirtualizationOff),
    );
    assert_eq!(
        r.check(CheckId::Virtualization).unwrap().status,
        Status::Info
    );
}

#[test]
fn windows_hypervisor_query_failed() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::QueryFailed {
                detail: "WHvGetCapability failed: HRESULT 0x80070005".into(),
            },
            firmware_virtualization: None,
            hypervisor_vendor: None,
        },
        ..windows()
    };
    check(
        "windows_hypervisor_query_failed",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::HypervisorQueryFailed),
    );
}

#[test]
fn windows_runtime_missing() {
    let fake = Fake {
        runtime: RuntimeState::Unusable(RuntimeError::Missing { path: MSB.into() }),
        ..windows()
    };
    check(
        "windows_runtime_missing",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimeMissing),
    );
    assert_eq!((fake.launches.get(), fake.boots.get()), (0, 0));
}

#[test]
fn windows_runtime_version_mismatch() {
    let fake = Fake {
        runtime: RuntimeState::Unusable(RuntimeError::Mismatch {
            path: MSB.into(),
            expected: EXPECTED.into(),
            found: "0.7.7".into(),
        }),
        ..windows()
    };
    check(
        "windows_runtime_version_mismatch",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimeVersionMismatch),
    );
    let no_version = Fake {
        runtime: RuntimeState::Unusable(RuntimeError::NoVersion {
            path: MSB.into(),
            expected: EXPECTED.into(),
        }),
        ..windows()
    };
    let r = run(&no_version, &Options::default());
    assert_eq!(
        finding(&r, CheckId::Runtime),
        Some(Finding::RuntimeVersionMismatch)
    );
}

#[test]
fn windows_runtime_unreadable() {
    let fake = Fake {
        runtime: RuntimeState::Unusable(RuntimeError::Unreadable {
            path: MSB.into(),
            reason: "not an executable".into(),
        }),
        ..windows()
    };
    check(
        "windows_runtime_unreadable",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimeUnreadable),
    );
}

#[test]
fn windows_runtime_permissions() {
    let fake = Fake {
        runtime: RuntimeState::AccessDenied(AccessDenied {
            path: MSB.into(),
            detail: "Access is denied. (os error 5)".into(),
        }),
        ..windows()
    };
    check(
        "windows_runtime_permissions",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimePermissions),
    );
}

#[test]
fn windows_runtime_dev_override_warns() {
    let fake = Fake {
        runtime: RuntimeState::Ready {
            version: "0.7.8".into(),
            overridden: true,
        },
        ..windows()
    };
    let r = check(
        "windows_runtime_overridden",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimeOverridden),
    );
    assert!(r.ok);
}

fn spawn_failed(os_error: i32, detail: &str) -> ProcessOutcome {
    ProcessOutcome::SpawnFailed {
        os_error: Some(os_error),
        detail: format!("{detail} (os error {os_error})"),
    }
}

#[test]
fn windows_blocked_by_applocker() {
    let fake = Fake {
        launch: spawn_failed(
            1260,
            "This program is blocked by group policy. For more information, contact your system administrator.",
        ),
        ..windows()
    };
    check(
        "windows_applocker",
        &fake,
        CheckId::Launch,
        Some(Finding::BlockedByAppLocker),
    );
    assert_eq!(fake.boots.get(), 0);
}

#[test]
fn windows_blocked_by_app_control() {
    let fake = Fake {
        ci: Some(CodeIntegrity {
            hvci: true,
            user_mode_enforced: true,
            user_mode_audit: false,
            test_signing: false,
        }),
        launch: spawn_failed(
            4551,
            "Your organization used Device Guard to block this app. Contact your support person for more info.",
        ),
        ..windows()
    };
    check(
        "windows_app_control",
        &fake,
        CheckId::Launch,
        Some(Finding::BlockedByAppControl),
    );
}

#[test]
fn windows_blocked_by_smart_app_control() {
    let fake = Fake {
        launch: spawn_failed(4580, "An Application Control policy has blocked this file."),
        ..windows()
    };
    check(
        "windows_smart_app_control",
        &fake,
        CheckId::Launch,
        Some(Finding::BlockedByAppControl),
    );
}

#[test]
fn windows_blocked_by_antivirus() {
    let fake = Fake {
        launch: spawn_failed(
            225,
            "Operation did not complete successfully because the file contains a virus or potentially unwanted software.",
        ),
        ..windows()
    };
    check(
        "windows_antivirus",
        &fake,
        CheckId::Launch,
        Some(Finding::BlockedByAntivirus),
    );
}

#[test]
fn windows_process_creation_denied_is_edr() {
    let fake = Fake {
        launch: spawn_failed(5, "Access is denied."),
        ..windows()
    };
    check(
        "windows_edr",
        &fake,
        CheckId::Launch,
        Some(Finding::ProcessCreationDenied),
    );
}

#[test]
fn windows_launch_failed_otherwise() {
    let fake = Fake {
        launch: spawn_failed(193, "%1 is not a valid Win32 application."),
        ..windows()
    };
    check(
        "windows_launch_failed",
        &fake,
        CheckId::Launch,
        Some(Finding::LaunchFailed),
    );
}

#[test]
fn windows_launch_crashed() {
    let fake = Fake {
        launch: exited(status(0xC000_0005), "", "", 40),
        ..windows()
    };
    check(
        "windows_launch_crashed",
        &fake,
        CheckId::Launch,
        Some(Finding::LaunchExited),
    );
}

#[test]
fn windows_launch_timed_out() {
    let fake = Fake {
        launch: ProcessOutcome::TimedOut {
            after: Duration::from_secs(10),
        },
        ..windows()
    };
    check(
        "windows_launch_timeout",
        &fake,
        CheckId::Launch,
        Some(Finding::LaunchTimedOut),
    );
    assert_eq!(fake.boots.get(), 0);
}

#[test]
fn windows_boot_failed() {
    let fake = Fake {
        boot: BootFacts::Ran {
            outcome: exited(
                1,
                "",
                "error: failed to start sandbox\n  → sandbox process exited (exit code: 0) before agent relay became available",
                10_400,
            ),
        },
        ..windows()
    };
    check(
        "windows_boot_failed",
        &fake,
        CheckId::TestBoot,
        Some(Finding::BootFailed),
    );
}

#[test]
fn windows_boot_timed_out() {
    let fake = Fake {
        boot: BootFacts::Ran {
            outcome: ProcessOutcome::TimedOut {
                after: Duration::from_secs(25),
            },
        },
        ..windows()
    };
    check(
        "windows_boot_timeout",
        &fake,
        CheckId::TestBoot,
        Some(Finding::BootTimedOut),
    );
}

const DENIED: &str = "error: io error: Access is denied. (os error 5)";

#[test]
fn windows_boot_denied_in_a_closed_job_is_the_job_not_edr() {
    let fake = Fake {
        job: Some(JobFacts {
            breakaway_allowed: false,
        }),
        boot: BootFacts::Ran {
            outcome: exited(1, "", DENIED, 900),
        },
        ..windows()
    };
    let r = check(
        "windows_boot_job",
        &fake,
        CheckId::TestBoot,
        Some(Finding::BootBlockedByJob),
    );
    assert_eq!(
        finding(&r, CheckId::JobObject),
        Some(Finding::JobWithoutBreakaway)
    );
    // The same refusal outside such a job points at endpoint security.
    for job in [
        None,
        Some(JobFacts {
            breakaway_allowed: true,
        }),
    ] {
        let fake = Fake {
            job,
            ..fake.clone()
        };
        let r = run(&fake, &Options::default());
        assert_eq!(
            finding(&r, CheckId::TestBoot),
            Some(Finding::ProcessCreationDenied)
        );
        assert!(r.check(CheckId::JobObject).is_none());
    }
}

#[test]
fn windows_boot_spawn_refused() {
    let fake = Fake {
        boot: BootFacts::Ran {
            outcome: spawn_failed(1260, "This program is blocked by group policy."),
        },
        ..windows()
    };
    let r = run(&fake, &Options::default());
    assert_eq!(
        finding(&r, CheckId::TestBoot),
        Some(Finding::BlockedByAppLocker)
    );
    let fake = Fake {
        boot: BootFacts::Ran {
            outcome: spawn_failed(1450, "Insufficient system resources exist."),
        },
        ..windows()
    };
    let r = run(&fake, &Options::default());
    assert_eq!(finding(&r, CheckId::TestBoot), Some(Finding::BootFailed));
}

#[test]
fn windows_boot_setup_failed() {
    let fake = Fake {
        boot: BootFacts::SetupFailed {
            detail: r"temp dir: Access is denied. (os error 5)".into(),
        },
        ..windows()
    };
    check(
        "windows_boot_setup_failed",
        &fake,
        CheckId::TestBoot,
        Some(Finding::BootSetupFailed),
    );
}

#[test]
fn windows_gsa_installed_warns_and_explains() {
    let fake = Fake {
        gsa: Some(GsaFacts::Installed { running: true }),
        ci: Some(CodeIntegrity {
            hvci: false,
            user_mode_enforced: false,
            user_mode_audit: true,
            test_signing: true,
        }),
        ..windows()
    };
    let r = check(
        "windows_gsa_installed",
        &fake,
        CheckId::GlobalSecureAccess,
        Some(Finding::GlobalSecureAccessInstalled),
    );
    assert!(r.ok, "a warning doesn't fail the report");
    let stopped = Fake {
        gsa: Some(GsaFacts::Installed { running: false }),
        ..windows()
    };
    let r = run(&stopped, &Options::default());
    assert!(
        r.check(CheckId::GlobalSecureAccess)
            .unwrap()
            .summary
            .contains("not running")
    );
}

#[test]
fn no_boot_skips_the_test_boot() {
    let fake = windows();
    let r = run(
        &fake,
        &Options {
            boot: false,
            ..Options::default()
        },
    );
    snapshot("windows_no_boot", &r);
    assert_eq!(r.check(CheckId::TestBoot).unwrap().status, Status::Skipped);
    assert_eq!(fake.boots.get(), 0);
}

#[test]
fn no_time_left_skips_the_test_boot() {
    let fake = windows();
    let r = run(
        &fake,
        &Options {
            budget: Duration::from_secs(1),
            ..Options::default()
        },
    );
    assert_eq!(
        r.check(CheckId::TestBoot).unwrap().summary,
        "not checked: out of time"
    );
    assert_eq!(fake.boots.get(), 0);
}

#[test]
fn unsupported_arch_skips_the_test_boot() {
    let fake = Fake {
        boot: BootFacts::UnsupportedArch {
            arch: "aarch64".into(),
        },
        ..windows()
    };
    let r = run(&fake, &Options::default());
    let c = r.check(CheckId::TestBoot).unwrap();
    assert_eq!(c.status, Status::Skipped);
    assert!(c.summary.contains("aarch64"));
}

#[test]
fn linux_all_green() {
    let r = check("linux_all_green", &linux(), CheckId::Hypervisor, None);
    assert!(r.check(CheckId::CodeIntegrity).is_none());
    assert!(r.check(CheckId::GlobalSecureAccess).is_none());
}

#[test]
fn linux_kvm_missing() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::NotInstalled {
                detail: "/dev/kvm: No such file or directory (os error 2)".into(),
            },
            firmware_virtualization: Some(false),
            hypervisor_vendor: Some("Microsoft Hv".into()),
        },
        ..linux()
    };
    check(
        "linux_kvm_missing",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::KvmMissing),
    );
}

#[test]
fn linux_kvm_access_denied() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::AccessDenied {
                detail: "/dev/kvm: Permission denied (os error 13)".into(),
            },
            firmware_virtualization: Some(true),
            hypervisor_vendor: None,
        },
        launch: spawn_failed(13, "Permission denied"),
        ..linux()
    };
    let r = check(
        "linux_kvm_access_denied",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::KvmAccessDenied),
    );
    assert_eq!(
        finding(&r, CheckId::Launch),
        Some(Finding::RuntimePermissions)
    );
}

#[test]
fn linux_query_failed_and_killed_by_signal() {
    let fake = Fake {
        hv: HypervisorFacts {
            api: HypervisorApi::QueryFailed {
                detail: "/dev/kvm: Is a directory (os error 21)".into(),
            },
            firmware_virtualization: None,
            hypervisor_vendor: None,
        },
        launch: ProcessOutcome::Exited {
            code: None,
            stdout_first_line: String::new(),
            stderr_tail: String::new(),
            elapsed: Duration::from_millis(5),
        },
        ..linux()
    };
    let r = check(
        "linux_query_failed",
        &fake,
        CheckId::Launch,
        Some(Finding::LaunchExited),
    );
    assert!(
        r.check(CheckId::Launch)
            .unwrap()
            .summary
            .contains("killed by a signal")
    );
}

#[test]
fn linux_boot_killed_by_signal_and_odd_exit() {
    for code in [None, Some(3)] {
        let fake = Fake {
            boot: BootFacts::Ran {
                outcome: ProcessOutcome::Exited {
                    code,
                    stdout_first_line: String::new(),
                    stderr_tail: "boom".into(),
                    elapsed: Duration::from_millis(5),
                },
            },
            ..linux()
        };
        let r = run(&fake, &Options::default());
        assert_eq!(finding(&r, CheckId::TestBoot), Some(Finding::BootFailed));
    }
}

#[test]
fn linux_runtime_permissions_say_chmod() {
    let fake = Fake {
        runtime: RuntimeState::AccessDenied(AccessDenied {
            path: "/opt/puddle/runtime/msb".into(),
            detail: "not executable".into(),
        }),
        ..linux()
    };
    let r = check(
        "linux_runtime_permissions",
        &fake,
        CheckId::Runtime,
        Some(Finding::RuntimePermissions),
    );
    let fix = r.check(CheckId::Runtime).unwrap().fix.clone().unwrap();
    assert!(fix.contains("chmod a+rx"), "{fix}");
    assert!(!fix.contains("icacls"), "{fix}");
}

#[test]
fn linux_boot_without_firmware_is_an_incomplete_runtime() {
    // What the fork's msb says when no libkrunfw.so.<version> sits beside it (K run 37429055402).
    let fake = Fake {
        boot: BootFacts::Ran {
            outcome: exited(
                1,
                "",
                "error: microsandbox runtime installation is incomplete: /opt/puddle/runtime/msb\nhas no matching libkrunfw",
                40,
            ),
        },
        ..linux()
    };
    check(
        "linux_boot_runtime_incomplete",
        &fake,
        CheckId::TestBoot,
        Some(Finding::RuntimeMissing),
    );
}

#[test]
fn other_os_has_no_hypervisor_support() {
    let fake = Fake {
        os: Os::Other,
        hv: HypervisorFacts {
            api: HypervisorApi::Unsupported,
            firmware_virtualization: None,
            hypervisor_vendor: None,
        },
        ci: None,
        gsa: None,
        ..windows()
    };
    check(
        "other_unsupported",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::UnsupportedOs),
    );
}

#[test]
fn macos_is_not_supported_yet() {
    let fake = Fake {
        os: Os::MacOs,
        hv: HypervisorFacts {
            api: HypervisorApi::Unsupported,
            firmware_virtualization: None,
            hypervisor_vendor: None,
        },
        ..linux()
    };
    let r = check(
        "macos_unsupported",
        &fake,
        CheckId::Hypervisor,
        Some(Finding::UnsupportedOs),
    );
    let hypervisor = r.check(CheckId::Hypervisor).unwrap();
    assert!(hypervisor.summary.contains("macOS yet"), "{hypervisor:?}");
    assert_eq!(r.os, "macos");
    assert!(!r.ok);
}

#[test]
fn json_schema_is_versioned_and_stable() {
    let r = run(&windows(), &Options::default());
    let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
    assert_eq!(v["schema_version"], 1);
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "virtualization",
            "hypervisor",
            "code_integrity",
            "runtime",
            "launch",
            "test_boot",
            "global_secure_access"
        ]
    );
}
