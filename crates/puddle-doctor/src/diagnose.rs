// SPDX-License-Identifier: GPL-3.0-or-later
//! From facts to findings: the order of the checks, what depends on what, and the exact text of
//! every finding and fix. Pure, so every case is tested with a faked [`Probe`].

use std::path::Path;
use std::time::{Duration, Instant};

use puddle_runtime::RuntimeError;

use crate::facts::{
    BootFacts, CodeIntegrity, GsaFacts, HypervisorApi, HypervisorFacts, JobFacts, Os,
    ProcessOutcome, RuntimeFacts, RuntimeState,
};
use crate::report::{Check, CheckId, Finding, Report, SCHEMA_VERSION, Status};

/// The exit code of the probe program the test VM runs.
pub const PROBE_EXIT_CODE: i32 = 42;

/// Where the facts come from: the real machine ([`crate::SystemProbe`]) or a test's fake.
pub trait Probe {
    /// The OS the findings are worded for.
    fn os(&self) -> Os;
    /// The CPU architecture (`x86_64`, `aarch64`).
    fn arch(&self) -> String;
    /// Hardware virtualization and the hypervisor API.
    fn hypervisor(&self) -> HypervisorFacts;
    /// Windows code integrity; `None` elsewhere or when it can't be read.
    fn code_integrity(&self) -> Option<CodeIntegrity>;
    /// The bundled runtime.
    fn runtime(&self) -> RuntimeFacts;
    /// Runs `msb --version`, killed after `limit`. Called only when [`Probe::runtime`] was ready.
    fn launch(&self, limit: Duration) -> ProcessOutcome;
    /// Boots a test VM, killed after `limit`. Called only when the hypervisor is ready and the
    /// launch succeeded.
    fn boot(&self, limit: Duration) -> BootFacts;
    /// The job object this process runs in; `None` when in none (or not on Windows).
    fn job(&self) -> Option<JobFacts>;
    /// The Global Secure Access client; `None` when not on Windows.
    fn global_secure_access(&self) -> Option<GsaFacts>;
}

/// What to run and how long it may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Boot a test VM (the slowest check).
    pub boot: bool,
    /// Time limit for `msb --version`.
    pub launch_limit: Duration,
    /// Time limit for the whole run; the test boot gets what is left.
    pub budget: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            boot: true,
            launch_limit: Duration::from_secs(10),
            budget: Duration::from_secs(28),
        }
    }
}

/// The least time worth starting a test boot with.
const MIN_BOOT_TIME: Duration = Duration::from_secs(5);

/// The most time a test boot gets.
const MAX_BOOT_TIME: Duration = Duration::from_secs(25);

/// Runs every check against `probe`.
pub fn diagnose(probe: &dyn Probe, options: &Options, puddle_version: &str) -> Report {
    let start = Instant::now();
    let os = probe.os();
    let hv = probe.hypervisor();
    let mut checks = vec![virtualization(os, &hv), hypervisor(os, &hv)];
    if let Some(ci) = probe.code_integrity() {
        checks.push(code_integrity(ci));
    }
    let job = probe.job();
    if let Some(j) = job.filter(|j| !j.breakaway_allowed) {
        checks.push(job_check(j));
    }

    let rt = probe.runtime();
    checks.push(runtime(os, &rt));
    let runtime_ready = matches!(rt.state, RuntimeState::Ready { .. });
    let launched = if runtime_ready {
        let outcome = probe.launch(options.launch_limit);
        let check = launch(os, &rt.msb, &outcome, hv.api == HypervisorApi::Ready);
        let ok = check.status == Status::Ok;
        checks.push(check);
        ok
    } else {
        checks.push(skipped(CheckId::Launch, "the bundled runtime isn't usable"));
        false
    };

    checks.push(if !options.boot {
        skipped(CheckId::TestBoot, "--no-boot")
    } else if hv.api != HypervisorApi::Ready {
        skipped(CheckId::TestBoot, "no usable hypervisor")
    } else if !launched {
        skipped(CheckId::TestBoot, "the runtime doesn't start")
    } else {
        let left = options.budget.saturating_sub(start.elapsed());
        if left < MIN_BOOT_TIME {
            skipped(CheckId::TestBoot, "out of time")
        } else {
            let facts = probe.boot(left.min(MAX_BOOT_TIME));
            test_boot(os, &rt.msb, &rt.dir, &facts, job)
        }
    });

    if let Some(gsa) = probe.global_secure_access() {
        checks.push(global_secure_access(gsa));
    }

    Report {
        schema_version: SCHEMA_VERSION,
        puddle_version: puddle_version.to_owned(),
        os: os.name().to_owned(),
        arch: probe.arch(),
        ok: checks.iter().all(|c| c.status != Status::Fail),
        checks,
        elapsed_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn skipped(id: CheckId, why: &str) -> Check {
    Check::new(id, Status::Skipped, format!("not checked: {why}"))
}

// ---- virtualization and hypervisor ----

const FIRMWARE_FIX: &str = "Turn on CPU virtualization in your PC's UEFI/BIOS setup (Intel: \"Intel Virtualization Technology\" / VT-x; \
AMD: \"SVM Mode\"), save, and start the PC again.";

fn virtualization(os: Os, hv: &HypervisorFacts) -> Check {
    let id = CheckId::Virtualization;
    if hv.api == HypervisorApi::Ready {
        return Check::new(id, Status::Ok, "on (the hypervisor uses it)");
    }
    match (hv.firmware_virtualization, &hv.hypervisor_vendor) {
        (Some(true), _) => Check::new(id, Status::Ok, "on in firmware"),
        (_, Some(vendor)) => Check::new(
            id,
            Status::Info,
            format!(
                "this {} runs in a virtual machine ({vendor}); see Hypervisor",
                os_word(os)
            ),
        ),
        (Some(false), None) => Check::new(id, Status::Fail, "off in the firmware (UEFI/BIOS)")
            .finding(Finding::FirmwareVirtualizationOff)
            .fix(FIRMWARE_FIX),
        (None, None) => Check::new(id, Status::Info, "unknown"),
    }
}

fn os_word(os: Os) -> &'static str {
    match os {
        Os::Windows => "Windows",
        Os::Linux => "Linux",
        Os::Other => "system",
    }
}

const WHP_ENABLE_FIX: &str =
    "Enable the Windows Hypervisor Platform feature in PowerShell as administrator:
  Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
then restart Windows. (Or: Settings > System > Optional features > More Windows features > \
Windows Hypervisor Platform.) Virtual Machine Platform, which WSL2 uses, is a different feature.";

const HYPERVISOR_START_FIX: &str =
    "Restart Windows: a newly enabled hypervisor only starts after a restart. If it still doesn't \
run, the boot configuration turns it off; in a terminal as administrator run
  bcdedit /set hypervisorlaunchtype auto
and restart again.";

fn nested_fix(os: Os, vendor: &str) -> String {
    format!(
        "This {} is a virtual machine ({vendor}) whose host doesn't pass CPU virtualization through. \
Turn on nested virtualization for this VM on its host, or run puddle on a physical PC. On a \
Hyper-V host, with the VM off:
  Set-VMProcessor -VMName <name> -ExposeVirtualizationExtensions $true
On VMware: \"Virtualize Intel VT-x/EPT or AMD-V/RVI\" in the VM's processor settings.",
        os_word(os)
    )
}

fn hypervisor(os: Os, hv: &HypervisorFacts) -> Check {
    let id = CheckId::Hypervisor;
    let windows = os == Os::Windows;
    match &hv.api {
        HypervisorApi::Ready if windows => Check::new(
            id,
            Status::Ok,
            "Windows Hypervisor Platform is on and the hypervisor runs",
        ),
        HypervisorApi::Ready => Check::new(id, Status::Ok, "/dev/kvm is usable"),
        HypervisorApi::NotInstalled { detail } if windows => {
            Check::new(id, Status::Fail, "Windows Hypervisor Platform is off")
                .finding(Finding::WhpNotEnabled)
                .fix(WHP_ENABLE_FIX)
                .detail(detail.clone())
        }
        HypervisorApi::NotInstalled { detail } => Check::new(id, Status::Fail, "no /dev/kvm")
            .finding(Finding::KvmMissing)
            .fix(
                "Load KVM for your CPU (sudo modprobe kvm_intel, or kvm_amd). In a virtual machine, turn on \
nested virtualization on its host first.",
            )
            .detail(detail.clone()),
        HypervisorApi::NotRunning => match (&hv.hypervisor_vendor, hv.firmware_virtualization) {
            (Some(vendor), _) => Check::new(
                id,
                Status::Fail,
                "can't run: this is a virtual machine without nested virtualization",
            )
            .finding(Finding::NestedVirtualizationOff)
            .fix(nested_fix(os, vendor)),
            (None, Some(false)) => Check::new(
                id,
                Status::Fail,
                "Windows Hypervisor Platform is on, but the hypervisor can't run: CPU virtualization is off",
            )
            .finding(Finding::FirmwareVirtualizationOff)
            .fix(FIRMWARE_FIX),
            (None, _) => Check::new(
                id,
                Status::Fail,
                "Windows Hypervisor Platform is on, but the hypervisor isn't running",
            )
            .finding(Finding::HypervisorNotRunning)
            .fix(HYPERVISOR_START_FIX),
        },
        HypervisorApi::AccessDenied { detail } => {
            Check::new(id, Status::Fail, "/dev/kvm exists but you can't open it")
                .finding(Finding::KvmAccessDenied)
                .fix(
                    "Add yourself to the group that owns /dev/kvm (usually kvm):
  sudo usermod -aG kvm \"$USER\"
then log out and in again.",
                )
                .detail(detail.clone())
        }
        HypervisorApi::QueryFailed { detail } => {
            Check::new(id, Status::Fail, "the hypervisor query failed")
                .finding(Finding::HypervisorQueryFailed)
                .fix(if windows {
                    "Restart Windows and run puddle doctor again. If this stays, include the line below when you \
report it."
                } else {
                    "Run puddle doctor again. If this stays, include the line below when you report it."
                })
                .detail(detail.clone())
        }
        HypervisorApi::Unsupported => Check::new(
            id,
            Status::Fail,
            "puddle has no hypervisor support on this operating system",
        )
        .finding(Finding::UnsupportedOs)
        .fix("Run puddle on Windows 10/11 (or Linux with KVM)."),
    }
}

// ---- code integrity ----

fn code_integrity(ci: CodeIntegrity) -> Check {
    let hvci = if ci.hvci { "on" } else { "off" };
    let app = if ci.user_mode_enforced {
        "enforced"
    } else if ci.user_mode_audit {
        "audit only"
    } else {
        "off"
    };
    let mut summary =
        format!("memory integrity (HVCI) {hvci}; App Control policy for programs {app}");
    if ci.test_signing {
        summary.push_str("; test signing on");
    }
    let check = Check::new(CheckId::CodeIntegrity, Status::Info, summary);
    if ci.user_mode_enforced {
        check.fix(
            "An App Control (WDAC) policy decides which programs may run. If it blocks puddle's runtime, \
\"Runtime starts\" says so and names the log with the rule.",
        )
    } else {
        check
    }
}

// ---- job object ----

fn job_check(_job: JobFacts) -> Check {
    Check::new(
        CheckId::JobObject,
        Status::Info,
        "puddle runs in a job object that doesn't let child processes leave it",
    )
    .finding(Finding::JobWithoutBreakaway)
    .fix(
        "Usual under CI runners and some IDE or remote shells. puddle keeps its VM processes in its own \
job, so this only matters if \"Test boot\" fails with access denied.",
    )
}

// ---- runtime ----

fn runtime(os: Os, rt: &RuntimeFacts) -> Check {
    let id = CheckId::Runtime;
    let dir = rt.dir.display();
    match &rt.state {
        RuntimeState::Ready {
            version,
            overridden: false,
        } => Check::new(
            id,
            Status::Ok,
            format!("msb {version} ({})", rt.msb.display()),
        ),
        RuntimeState::Ready {
            version,
            overridden: true,
        } => Check::new(
            id,
            Status::Warn,
            format!(
                "msb {version} accepted by the developer override; this build needs {}",
                rt.expected
            ),
        )
        .finding(Finding::RuntimeOverridden)
        .fix("Development builds only. Unset PUDDLE_DEV_ANY_RUNTIME to test the shipped combination."),
        RuntimeState::AccessDenied(denied) => Check::new(
            id,
            Status::Fail,
            format!(
                "you aren't allowed to read or run {}",
                denied.path.display()
            ),
        )
        .finding(Finding::RuntimePermissions)
        .fix(permissions_fix(os, &denied.path))
        .detail(denied.detail.clone()),
        RuntimeState::Unusable(err) => {
            let (finding, fix) = match err {
                RuntimeError::Missing { .. } => (
                    Finding::RuntimeMissing,
                    format!(
                        "Reinstall puddle: its runtime folder {dir} is incomplete. The runtime ships with puddle \
and must sit next to puddle's program file."
                    ),
                ),
                RuntimeError::Mismatch { .. } | RuntimeError::NoVersion { .. } => (
                    Finding::RuntimeVersionMismatch,
                    format!(
                        "Reinstall puddle so the runtime in {dir} matches this puddle again. Don't copy an msb \
from elsewhere into it: puddle only runs the exact msb {} it was built for.",
                        rt.expected
                    ),
                ),
                _ => (
                    Finding::RuntimeUnreadable,
                    format!("Reinstall puddle: the runtime in {dir} is damaged."),
                ),
            };
            Check::new(id, Status::Fail, err.to_string())
                .finding(finding)
                .fix(fix)
        }
    }
}

// ---- launch and test boot: process outcomes ----

/// Windows error codes and `NTSTATUS` values that say who stopped a process.
mod codes {
    pub(super) const ERROR_ACCESS_DENIED: i32 = 5;
    pub(super) const ERROR_VIRUS_INFECTED: i32 = 225;
    pub(super) const ERROR_VIRUS_DELETED: i32 = 226;
    pub(super) const ERROR_INVALID_IMAGE_HASH: i32 = 577;
    pub(super) const ERROR_ACCESS_DISABLED_BY_POLICY: i32 = 1260;
    /// `ERROR_SYSTEM_INTEGRITY_*`: App Control policy and Smart App Control reputation verdicts.
    pub(super) const SYSTEM_INTEGRITY: [std::ops::RangeInclusive<i32>; 2] =
        [4550..=4562, 4580..=4582];

    pub(super) const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    pub(super) const STATUS_DLL_NOT_FOUND: u32 = 0xC000_0135;
    pub(super) const STATUS_ORDINAL_NOT_FOUND: u32 = 0xC000_0138;
    pub(super) const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC000_0139;
    pub(super) const STATUS_INVALID_IMAGE_HASH: u32 = 0xC000_0428;
    pub(super) const STATUS_VIRUS_INFECTED: u32 = 0xC000_0906;

    /// `EACCES` on Linux.
    pub(super) const EACCES: i32 = 13;
}

/// Who refused to start msb, and the fix.
struct Blocked {
    finding: Finding,
    summary: String,
    fix: String,
}

fn applocker(msb: &Path) -> Blocked {
    Blocked {
        finding: Finding::BlockedByAppLocker,
        summary: "an AppLocker or Software Restriction policy blocks msb".into(),
        fix: format!(
            "The policy doesn't allow {}. Allow puddle's install folder (a path or publisher rule), or \
install puddle where the policy lets programs run. Event Viewer > Applications and Services \
Logs > Microsoft > Windows > AppLocker > EXE and DLL names the rule.",
            msb.display()
        ),
    }
}

fn app_control(msb: &Path) -> Blocked {
    Blocked {
        finding: Finding::BlockedByAppControl,
        summary: "App Control for Business (WDAC) or Smart App Control blocks msb".into(),
        fix: format!(
            "A code integrity policy doesn't allow {}. Allow puddle's files or signer in that policy; \
Event Viewer > Applications and Services Logs > Microsoft > Windows > CodeIntegrity > \
Operational names the rule. Smart App Control has no exceptions: it can only be turned off \
(Windows Security > App & browser control > Smart App Control).",
            msb.display()
        ),
    }
}

fn antivirus(msb: &Path) -> Blocked {
    Blocked {
        finding: Finding::BlockedByAntivirus,
        summary: "antivirus flagged msb".into(),
        fix: format!(
            "Look for {} in your antivirus's protection history or quarantine. If it is a false \
positive, restore it, exclude puddle's runtime folder, and reinstall puddle if the file is gone.",
            msb.display()
        ),
    }
}

fn edr(msb: &Path) -> Blocked {
    Blocked {
        finding: Finding::ProcessCreationDenied,
        summary: "Windows refused to start msb although its file permissions allow it".into(),
        fix: format!(
            "Endpoint security (EDR) blocking new programs is the usual cause. Check its console or log \
for {}; it must be allowed to run and to start virtual machines through the Windows \
Hypervisor Platform.",
            msb.display()
        ),
    }
}

fn file_permissions(msb: &Path) -> Blocked {
    Blocked {
        finding: Finding::RuntimePermissions,
        summary: "the file's permissions don't let you run msb".into(),
        fix: permissions_fix(Os::Linux, msb),
    }
}

/// How to give this user back the right to read and run `msb`.
fn permissions_fix(os: Os, msb: &Path) -> String {
    if os == Os::Windows {
        format!(
            "The file's permissions deny your account. Restore the inherited permissions:
  icacls \"{}\" /reset
(as administrator if puddle is installed for all users), or reinstall puddle.",
            msb.display()
        )
    } else {
        format!(
            "Make it readable and executable again:
  chmod a+rx \"{}\"
or reinstall puddle.",
            msb.display()
        )
    }
}

/// Classifies a failed `CreateProcess`/`exec`.
fn spawn_failure(os: Os, msb: &Path, os_error: Option<i32>) -> Option<Blocked> {
    let code = os_error?;
    if os == Os::Windows {
        match code {
            codes::ERROR_ACCESS_DISABLED_BY_POLICY => Some(applocker(msb)),
            codes::ERROR_INVALID_IMAGE_HASH => Some(app_control(msb)),
            c if codes::SYSTEM_INTEGRITY.iter().any(|r| r.contains(&c)) => Some(app_control(msb)),
            codes::ERROR_VIRUS_INFECTED | codes::ERROR_VIRUS_DELETED => Some(antivirus(msb)),
            // The runtime check already opened the file for running, so permissions allow it.
            codes::ERROR_ACCESS_DENIED => Some(edr(msb)),
            // Not found (2, 3) and anything else: no one to blame.
            _ => None,
        }
    } else if code == codes::EACCES {
        Some(file_permissions(msb))
    } else {
        None
    }
}

/// Classifies a Windows process that died while loading, by its `NTSTATUS` exit code.
fn load_failure(os: Os, msb: &Path, code: i32, hypervisor_ready: bool) -> Option<Blocked> {
    if os != Os::Windows {
        return None;
    }
    #[expect(
        clippy::cast_sign_loss,
        reason = "Windows reports NTSTATUS exit codes as i32; the bits are the code"
    )]
    let status = code as u32;
    match status {
        codes::STATUS_INVALID_IMAGE_HASH => Some(app_control(msb)),
        codes::STATUS_ACCESS_DENIED => Some(edr(msb)),
        codes::STATUS_VIRUS_INFECTED => Some(antivirus(msb)),
        codes::STATUS_DLL_NOT_FOUND
        | codes::STATUS_ORDINAL_NOT_FOUND
        | codes::STATUS_ENTRYPOINT_NOT_FOUND => Some(Blocked {
            finding: Finding::DllMissing,
            summary: format!("msb can't load a DLL it needs (0x{status:08X})"),
            fix: if hypervisor_ready {
                "Reinstall puddle; if that doesn't help, run Windows Update: msb needs the Windows Hypervisor \
Platform DLLs of a current Windows 10/11."
                    .into()
            } else {
                "msb links the Windows Hypervisor Platform's DLL: fix \"Hypervisor\" above first."
                    .into()
            },
        }),
        _ => None,
    }
}

fn hex_or_dec(os: Os, code: i32) -> String {
    if os == Os::Windows && code < 0 {
        #[expect(
            clippy::cast_sign_loss,
            reason = "Windows reports NTSTATUS exit codes as i32; the bits are the code"
        )]
        let status = code as u32;
        format!("0x{status:08X}")
    } else {
        code.to_string()
    }
}

fn blocked_check(id: CheckId, b: Blocked, detail: String) -> Check {
    Check::new(id, Status::Fail, b.summary)
        .finding(b.finding)
        .fix(b.fix)
        .detail(detail)
}

fn launch(os: Os, msb: &Path, outcome: &ProcessOutcome, hypervisor_ready: bool) -> Check {
    let id = CheckId::Launch;
    match outcome {
        ProcessOutcome::Exited {
            code: Some(0),
            stdout_first_line,
            elapsed,
            ..
        } => Check::new(
            id,
            Status::Ok,
            format!(
                "{} ({})",
                if stdout_first_line.is_empty() {
                    "msb answered"
                } else {
                    stdout_first_line
                },
                seconds(*elapsed)
            ),
        ),
        ProcessOutcome::SpawnFailed { os_error, detail } => {
            match spawn_failure(os, msb, *os_error) {
                Some(b) => blocked_check(id, b, detail.clone()),
                None => Check::new(id, Status::Fail, "msb could not be started")
                    .finding(Finding::LaunchFailed)
                    .fix("Reinstall puddle. If this stays, include the line below when you report it.")
                    .detail(detail.clone()),
            }
        }
        ProcessOutcome::Exited {
            code, stderr_tail, ..
        } => {
            if let Some(b) = code.and_then(|c| load_failure(os, msb, c, hypervisor_ready)) {
                return blocked_check(id, b, stderr_tail.clone());
            }
            let how = code.map_or_else(
                || "was killed by a signal".to_owned(),
                |c| format!("exited with {}", hex_or_dec(os, c)),
            );
            Check::new(id, Status::Fail, format!("msb {how} instead of answering"))
                .finding(Finding::LaunchExited)
                .fix(STOPPED_FIX)
                .detail(stderr_tail.clone())
        }
        ProcessOutcome::TimedOut { after } => Check::new(
            id,
            Status::Fail,
            format!("msb didn't answer within {}", seconds(*after)),
        )
        .finding(Finding::LaunchTimedOut)
        .fix(SLOW_FIX),
    }
}

const STOPPED_FIX: &str = "If endpoint security (EDR or antivirus) runs on this PC, check its log for msb: it may have \
stopped the process. Otherwise reinstall puddle and include the lines below when you report it.";

const SLOW_FIX: &str = "Security software scanning a program it hasn't seen before is the usual cause. Run puddle \
doctor again; if it keeps timing out, check your endpoint security's log for msb.";

fn test_boot(os: Os, msb: &Path, dir: &Path, facts: &BootFacts, job: Option<JobFacts>) -> Check {
    let id = CheckId::TestBoot;
    let (outcome, retried) = match facts {
        BootFacts::UnsupportedArch { arch } => {
            return skipped(id, &format!("no test program for {arch}"));
        }
        BootFacts::SetupFailed { detail } => {
            return Check::new(id, Status::Fail, "couldn't prepare the test VM's files")
                .finding(Finding::BootSetupFailed)
                .fix("Check that your temp folder (TEMP) exists, is writable and has free space.")
                .detail(detail.clone());
        }
        BootFacts::Ran { outcome, retried } => (outcome, *retried),
    };
    let retry_note = if retried {
        "; msb's first start lost a known boot race and was retried"
    } else {
        ""
    };
    match outcome {
        ProcessOutcome::Exited {
            code: Some(PROBE_EXIT_CODE),
            elapsed,
            ..
        } => Check::new(
            id,
            Status::Ok,
            format!(
                "a test VM booted and ran a program in {}{retry_note}",
                seconds(*elapsed)
            ),
        ),
        ProcessOutcome::SpawnFailed { os_error, detail } => {
            match spawn_failure(os, msb, *os_error) {
                Some(b) => blocked_check(id, b, detail.clone()),
                None => Check::new(id, Status::Fail, "msb could not be started")
                    .finding(Finding::BootFailed)
                    .fix(STOPPED_FIX)
                    .detail(detail.clone()),
            }
        }
        ProcessOutcome::TimedOut { after } => Check::new(
            id,
            Status::Fail,
            format!("the test VM didn't finish within {}", seconds(*after)),
        )
        .finding(Finding::BootTimedOut)
        .fix(SLOW_FIX),
        ProcessOutcome::Exited {
            code, stderr_tail, ..
        } => {
            let denied =
                stderr_tail.contains("Access is denied") || stderr_tail.contains("os error 5)");
            let restrictive_job = job.is_some_and(|j| !j.breakaway_allowed);
            let how = code.map_or_else(
                || "was killed by a signal".to_owned(),
                |c| format!("exited with {}", hex_or_dec(os, c)),
            );
            if os == Os::Windows && denied && restrictive_job {
                return Check::new(
                    id,
                    Status::Fail,
                    format!("msb {how}: access denied starting the VM process inside this job object"),
                )
                .finding(Finding::BootBlockedByJob)
                .fix(
                    "The job object puddle was started in (see \"Job object\") doesn't let the VM process leave \
it. Run puddle doctor from a normal terminal; on a CI runner, start it through a process \
outside the step's job.",
                )
                .detail(stderr_tail.clone());
            }
            if os == Os::Windows && denied {
                return blocked_check(id, edr(msb), stderr_tail.clone());
            }
            if stderr_tail.contains(RUNTIME_INCOMPLETE) {
                return Check::new(
                    id,
                    Status::Fail,
                    "msb can't find its firmware library (libkrunfw) beside it",
                )
                .finding(Finding::RuntimeMissing)
                .fix(format!(
                    "Reinstall puddle: its runtime folder {} is incomplete. msb needs the libkrunfw \
it was released with in the same folder.",
                    dir.display()
                ))
                .detail(stderr_tail.clone());
            }
            Check::new(
                id,
                Status::Fail,
                format!("msb {how} without booting the test VM"),
            )
            .finding(Finding::BootFailed)
            .fix(BOOT_FIX)
            .detail(stderr_tail.clone())
        }
    }
}

/// msb's error when the firmware library it pairs with isn't beside it.
const RUNTIME_INCOMPLETE: &str = "runtime installation is incomplete";

const BOOT_FIX: &str = "msb starts but can't boot a VM. If endpoint security runs on this PC, check its log for msb: \
it must be allowed to start virtual machines through the hypervisor. Otherwise restart the PC \
and run puddle doctor again, and include the lines below when you report it.";

// ---- Global Secure Access ----

fn global_secure_access(gsa: GsaFacts) -> Check {
    let id = CheckId::GlobalSecureAccess;
    match gsa {
        GsaFacts::NotInstalled => Check::new(id, Status::Ok, "client not installed"),
        GsaFacts::Installed { running } => Check::new(
            id,
            Status::Warn,
            format!(
                "Microsoft Entra Global Secure Access client installed ({})",
                if running { "running" } else { "not running" }
            ),
        )
        .finding(Finding::GlobalSecureAccessInstalled)
        .fix(
            "Microsoft documents that this client doesn't tunnel virtual machines' traffic and isn't \
supported on devices that host VMs. Sandboxes have no network of their own: their traffic \
leaves through puddle's proxy, an ordinary program on this PC, which the client handles like \
any other app. If company resources reached through Global Secure Access don't work from a \
sandbox, this limitation is the likely cause; puddle can't change it.",
        ),
    }
}

fn seconds(d: Duration) -> String {
    let ms = d.as_millis();
    format!("{}.{} s", ms / 1000, ms % 1000 / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_has_one_decimal() {
        assert_eq!(seconds(Duration::from_millis(2345)), "2.3 s");
        assert_eq!(seconds(Duration::from_millis(40)), "0.0 s");
    }

    #[test]
    fn hex_only_for_windows_status_codes() {
        assert_eq!(hex_or_dec(Os::Windows, -1_073_741_515), "0xC0000135");
        assert_eq!(hex_or_dec(Os::Windows, 3), "3");
        assert_eq!(hex_or_dec(Os::Linux, -1), "-1");
    }

    #[test]
    fn every_system_integrity_code_is_app_control() {
        let msb = Path::new("msb.exe");
        for code in (4550..=4562).chain(4580..=4582).chain([577]) {
            let b = spawn_failure(Os::Windows, msb, Some(code)).unwrap();
            assert_eq!(b.finding, Finding::BlockedByAppControl, "{code}");
        }
        assert!(spawn_failure(Os::Windows, msb, Some(4563)).is_none());
        assert!(spawn_failure(Os::Windows, msb, Some(2)).is_none());
        assert!(spawn_failure(Os::Windows, msb, None).is_none());
    }

    #[test]
    fn windows_codes_mean_nothing_elsewhere() {
        let msb = Path::new("msb");
        assert!(spawn_failure(Os::Linux, msb, Some(1260)).is_none());
        assert!(load_failure(Os::Linux, msb, -1_073_741_515, true).is_none());
        assert_eq!(
            spawn_failure(Os::Linux, msb, Some(13)).unwrap().finding,
            Finding::RuntimePermissions
        );
    }

    #[test]
    fn load_failures_by_status() {
        let msb = Path::new("msb.exe");
        let f = |status: u32| {
            #[expect(
                clippy::cast_possible_wrap,
                reason = "test: NTSTATUS as Windows reports it"
            )]
            let code = status as i32;
            load_failure(Os::Windows, msb, code, true).map(|b| b.finding)
        };
        assert_eq!(f(0xC000_0428), Some(Finding::BlockedByAppControl));
        assert_eq!(f(0xC000_0022), Some(Finding::ProcessCreationDenied));
        assert_eq!(f(0xC000_0906), Some(Finding::BlockedByAntivirus));
        assert_eq!(f(0xC000_0138), Some(Finding::DllMissing));
        assert_eq!(f(0xC000_0139), Some(Finding::DllMissing));
        assert_eq!(f(0xC000_0005), None);
    }
}
