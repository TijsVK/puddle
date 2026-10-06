// SPDX-License-Identifier: GPL-3.0-or-later
//! The report: one line per check, a finding code and the exact fix for each problem, as text for
//! people and as versioned JSON for tools and (later, D-18) crash reports.

use std::fmt::Write as _;

use serde::Serialize;

/// Version of the JSON layout. Bump it when a field changes meaning or disappears; adding a
/// field, a check or a finding code doesn't need a bump.
pub const SCHEMA_VERSION: u32 = 1;

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Fine.
    Ok,
    /// Worth knowing; puddle works.
    Info,
    /// puddle works, with a limitation the text explains.
    Warn,
    /// puddle can't run sandboxes until this is fixed.
    Fail,
    /// Not checked, because an earlier check failed or it doesn't apply.
    Skipped,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
            Self::Skipped => "skip",
        }
    }
}

/// Which check a line belongs to. Stable identifiers for the JSON output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// CPU virtualization in firmware.
    Virtualization,
    /// The hypervisor API (WHP / KVM).
    Hypervisor,
    /// Windows code integrity: HVCI and App Control.
    CodeIntegrity,
    /// The bundled msb runtime: present, permitted, right version.
    Runtime,
    /// Starting the bundled msb at all.
    Launch,
    /// Booting a test microVM.
    TestBoot,
    /// The job object puddle runs in.
    JobObject,
    /// Microsoft Entra Global Secure Access.
    GlobalSecureAccess,
}

impl CheckId {
    /// The title shown in the text report.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Virtualization => "CPU virtualization",
            Self::Hypervisor => "Hypervisor",
            Self::CodeIntegrity => "Code integrity",
            Self::Runtime => "Bundled runtime",
            Self::Launch => "Runtime starts",
            Self::TestBoot => "Test boot",
            Self::JobObject => "Job object",
            Self::GlobalSecureAccess => "Global Secure Access",
        }
    }
}

/// What a non-ok check found. Stable codes for the JSON output; tools match on these, never on
/// the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    /// CPU virtualization is off in the firmware.
    FirmwareVirtualizationOff,
    /// The Windows Hypervisor Platform feature is off.
    WhpNotEnabled,
    /// WHP is on but the hypervisor isn't running.
    HypervisorNotRunning,
    /// The OS is a VM whose host doesn't pass virtualization through.
    NestedVirtualizationOff,
    /// The hypervisor query failed unexpectedly.
    HypervisorQueryFailed,
    /// `/dev/kvm` doesn't exist.
    KvmMissing,
    /// `/dev/kvm` isn't accessible to this user.
    KvmAccessDenied,
    /// No hypervisor API is known for this OS.
    UnsupportedOs,
    /// The runtime's files are missing.
    RuntimeMissing,
    /// The runtime is another version than this build needs.
    RuntimeVersionMismatch,
    /// The runtime's file can't be read or isn't msb.
    RuntimeUnreadable,
    /// File permissions deny reading or running the runtime.
    RuntimePermissions,
    /// The runtime was accepted by the developer override.
    RuntimeOverridden,
    /// An `AppLocker` or Software Restriction policy blocks msb.
    BlockedByAppLocker,
    /// App Control for Business (WDAC) or Smart App Control blocks msb.
    BlockedByAppControl,
    /// Antivirus flagged msb.
    BlockedByAntivirus,
    /// Process creation was denied although the file permits it: usually EDR.
    ProcessCreationDenied,
    /// A library msb needs is missing.
    DllMissing,
    /// msb couldn't be started for another reason.
    LaunchFailed,
    /// msb exited with an error before answering.
    LaunchExited,
    /// msb didn't answer in time.
    LaunchTimedOut,
    /// The test VM didn't boot.
    BootFailed,
    /// The test VM didn't finish in time.
    BootTimedOut,
    /// The VM process couldn't leave this process's job object.
    BootBlockedByJob,
    /// The test boot couldn't be prepared on the host.
    BootSetupFailed,
    /// This process runs in a job that doesn't allow breakaway.
    JobWithoutBreakaway,
    /// The Global Secure Access client is installed.
    GlobalSecureAccessInstalled,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Which check.
    pub id: CheckId,
    /// How it came out.
    pub status: Status,
    /// One line: what was found.
    pub summary: String,
    /// The finding code when the status isn't ok.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding: Option<Finding>,
    /// The exact fix (for a failure) or what the limitation means (for a warning).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Raw evidence: an OS error, msb's last output lines.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Check {
    pub(crate) fn new(id: CheckId, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id,
            status,
            summary: summary.into(),
            finding: None,
            fix: None,
            detail: None,
        }
    }

    pub(crate) fn finding(mut self, finding: Finding) -> Self {
        self.finding = Some(finding);
        self
    }

    pub(crate) fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    pub(crate) fn detail(mut self, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        if !detail.trim().is_empty() {
            self.detail = Some(detail);
        }
        self
    }
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The puddle version that ran the checks.
    pub puddle_version: String,
    /// `windows`, `linux` or `other`.
    pub os: String,
    /// The CPU architecture.
    pub arch: String,
    /// `true` when no check failed.
    pub ok: bool,
    /// The checks, in a fixed order.
    pub checks: Vec<Check>,
    /// How long the checks took, in milliseconds.
    pub elapsed_ms: u64,
}

impl Report {
    /// The checks that failed.
    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| c.status == Status::Fail)
    }

    /// The check with this id, if the report has one.
    #[must_use]
    pub fn check(&self, id: CheckId) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    /// The report as pretty-printed JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        // A struct of strings, numbers, bools and unit enums always serializes.
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// The report as text for a terminal.
    #[must_use]
    pub fn to_text(&self) -> String {
        let width = self
            .checks
            .iter()
            .map(|c| c.id.title().len())
            .max()
            .unwrap_or(0);
        let mut out = format!(
            "puddle doctor (puddle {}, {} {})\n\n",
            self.puddle_version, self.os, self.arch
        );
        for c in &self.checks {
            // Writing to a String can't fail.
            let _ignored = writeln!(
                out,
                "{:<5} {:<width$}  {}",
                c.status.label(),
                c.id.title(),
                c.summary
            );
            if let Some(fix) = &c.fix {
                let label = if c.status == Status::Fail {
                    "fix: "
                } else {
                    "note:"
                };
                push_block(&mut out, label, fix);
            }
            if let Some(detail) = &c.detail {
                push_block(&mut out, "from:", detail);
            }
        }
        let fails = self.failures().count();
        let warns = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Warn)
            .count();
        let secs = self.elapsed_ms / 1000;
        let tenths = self.elapsed_ms % 1000 / 100;
        let verdict = match (fails, warns) {
            (0, 0) => "No problems found.".to_owned(),
            (0, w) => format!("No problems found; {} to know about.", plural(w, "warning")),
            (f, 0) => format!(
                "{} to fix before puddle can run sandboxes.",
                plural(f, "problem")
            ),
            (f, w) => format!(
                "{} to fix before puddle can run sandboxes; {}.",
                plural(f, "problem"),
                plural(w, "warning")
            ),
        };
        let _ignored = writeln!(out, "\n{verdict} ({secs}.{tenths} s)");
        out
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// How wide the text of a fix or detail block may get before it wraps.
const WRAP: usize = 84;

/// Appends `text` under a check line: the label on the first line, the rest aligned below it.
/// Prose wraps at [`WRAP`] columns; lines that start with two spaces (commands) never wrap.
fn push_block(out: &mut String, label: &str, text: &str) {
    let mut first = true;
    for line in text.lines().flat_map(wrap) {
        let prefix = if first { label } else { "" };
        first = false;
        let _ignored = writeln!(out, "      {prefix:<5} {line}");
    }
}

/// Splits one line at spaces so no piece is longer than [`WRAP`] (a longer word stays whole).
fn wrap(line: &str) -> Vec<String> {
    if line.starts_with("  ") || line.chars().count() <= WRAP {
        return vec![line.to_owned()];
    }
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in line.split(' ') {
        if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > WRAP {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    lines.push(cur);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(checks: Vec<Check>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            puddle_version: "0.0.0".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            ok: checks.iter().all(|c| c.status != Status::Fail),
            checks,
            elapsed_ms: 2345,
        }
    }

    #[test]
    fn json_carries_the_schema_version_and_omits_empty_fields() {
        let r = report(vec![Check::new(CheckId::Runtime, Status::Ok, "fine")]);
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["checks"][0]["id"], "runtime");
        assert_eq!(v["checks"][0]["status"], "ok");
        assert!(v["checks"][0].get("fix").is_none());
        assert!(v["checks"][0].get("finding").is_none());
    }

    #[test]
    fn verdict_counts_problems_and_warnings() {
        let fail = Check::new(CheckId::Runtime, Status::Fail, "x");
        let warn = Check::new(CheckId::GlobalSecureAccess, Status::Warn, "y");
        assert!(
            report(vec![])
                .to_text()
                .contains("No problems found. (2.3 s)")
        );
        assert!(
            report(vec![warn.clone()])
                .to_text()
                .contains("No problems found; 1 warning to know about.")
        );
        assert!(
            report(vec![fail.clone(), fail.clone()])
                .to_text()
                .contains("2 problems to fix before puddle can run sandboxes.")
        );
        assert!(
            report(vec![fail, warn.clone(), warn])
                .to_text()
                .contains("1 problem to fix before puddle can run sandboxes; 2 warnings.")
        );
    }

    #[test]
    fn blank_detail_is_dropped() {
        let c = Check::new(CheckId::Launch, Status::Fail, "x").detail("  \n");
        assert_eq!(c.detail, None);
    }

    #[test]
    fn prose_wraps_and_commands_do_not() {
        let long = "word ".repeat(30);
        let pieces = wrap(long.trim_end());
        assert!(pieces.len() > 1);
        assert!(pieces.iter().all(|p| p.chars().count() <= WRAP));
        assert_eq!(pieces.join(" "), long.trim_end());
        let cmd = format!("  {}", "x".repeat(120));
        assert_eq!(wrap(&cmd), std::slice::from_ref(&cmd));
        let word = "y".repeat(120);
        assert_eq!(wrap(&word), std::slice::from_ref(&word));
    }

    #[test]
    fn lookups() {
        let r = report(vec![Check::new(CheckId::Runtime, Status::Fail, "x")]);
        assert_eq!(r.failures().count(), 1);
        assert!(r.check(CheckId::Runtime).is_some());
        assert!(r.check(CheckId::TestBoot).is_none());
    }
}
