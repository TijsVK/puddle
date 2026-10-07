// SPDX-License-Identifier: GPL-3.0-or-later
//! Stale git lock files after a crash: `guest/clear-locks.sh` run after a boot, and its
//! parsed result.
//!
//! A VMM kill leaves `index.lock`, `HEAD.lock`, `refs/**.lock` and friends behind, and git then
//! refuses to work ("Another git process seems to be running"). Right after a boot no git
//! process of the user's exists, so a lock is stale; the script still checks for a running `git`
//! and removes nothing if it finds one. Its output is parsed as hostile input: bounded, unknown
//! records refused, end marker required.

use std::time::Duration;

use puddle_compute::{ExecRequest, Sandbox};
use puddle_types::WorkspaceId;

use crate::{Layout, WorkspaceError};

/// The script (POSIX sh, run as root with the mount point as `$1`).
pub const CLEAR_LOCKS_SH: &str = include_str!("../guest/clear-locks.sh");

/// How long the script may take.
pub const CLEAR_LOCKS_TIMEOUT: Duration = Duration::from_secs(60);

/// Most removed paths kept in a [`LockReport`]; the rest are counted in [`LockReport::more`].
pub const MAX_LOCKS: usize = 100;

/// Longest path or message kept.
const MAX_LINE: usize = 500;

/// What clearing the stale locks of one workspace did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockReport {
    /// A git process was running, so nothing was removed.
    pub skipped_busy: bool,
    /// Lock files removed, relative to the volume root (at most [`MAX_LOCKS`]).
    pub removed: Vec<String>,
    /// How many more were removed than listed.
    pub more: u64,
    /// Locks (or checkouts) that could not be handled, as `path: why`.
    pub errors: Vec<String>,
}

impl LockReport {
    /// How many lock files were removed.
    #[must_use]
    pub fn removed_count(&self) -> u64 {
        self.removed.len() as u64 + self.more
    }
}

/// The command: the script with the mount point, as root.
pub(crate) fn request(layout: &Layout) -> ExecRequest {
    ExecRequest::new(
        "sh",
        [
            "-c",
            CLEAR_LOCKS_SH,
            "puddle-clear-locks",
            layout.mount().as_str(),
        ]
        .map(str::to_owned),
    )
    .as_user("root")
    .with_timeout(CLEAR_LOCKS_TIMEOUT)
}

/// Runs the script for `id` in `sandbox`.
pub(crate) async fn run<S: Sandbox>(
    sandbox: &S,
    id: &WorkspaceId,
) -> Result<LockReport, WorkspaceError> {
    let layout = Layout::new(id)?;
    let out = sandbox
        .exec(request(&layout))
        .await
        .map_err(|e| WorkspaceError::runtime("clear stale git locks", id, e))?;
    let fail = |reason: String| WorkspaceError::Locks {
        workspace: id.to_string(),
        reason,
    };
    if !out.status.success() {
        return Err(fail(format!(
            "exited {}: {}",
            out.status.code,
            out.stdout_text()
                .lines()
                .find_map(|l| l.strip_prefix("E\t"))
                .unwrap_or_default()
                .replace('\t', ": ")
        )));
    }
    parse(&out.stdout_text()).map_err(fail)
}

/// Parses the script's output.
pub(crate) fn parse(stdout: &str) -> Result<LockReport, String> {
    let mut report = LockReport::default();
    let mut done = false;
    for line in stdout.lines() {
        if done {
            return Err("output after the end marker".into());
        }
        let mut fields = line.splitn(3, '\t');
        let tag = fields.next().unwrap_or_default();
        let a = fields.next();
        let b = fields.next();
        match (tag, a, b) {
            ("D", None, None) => done = true,
            ("B", None, None) => report.skipped_busy = true,
            ("L", Some(path), None) => {
                if report.removed.len() < MAX_LOCKS {
                    report.removed.push(path.chars().take(MAX_LINE).collect());
                } else {
                    report.more = report.more.saturating_add(1);
                }
            }
            ("E", Some(path), Some(why)) => {
                if report.errors.len() < MAX_LOCKS {
                    report
                        .errors
                        .push(format!("{path}: {why}").chars().take(MAX_LINE).collect());
                }
            }
            _ => {
                let shown: String = line.chars().take(80).collect();
                return Err(format!("unexpected output line {shown:?}"));
            }
        }
    }
    if done {
        Ok(report)
    } else {
        Err("the script did not finish (no end marker)".into())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn removed_locks_and_errors_are_collected() {
        let r = parse("L\tapi/.git/index.lock\nL\tapi/.git/refs/heads/a b.lock\nE\tweb/.git/x.lock\tcannot remove\nD\n")
            .unwrap();
        assert!(!r.skipped_busy);
        assert_eq!(
            r.removed,
            ["api/.git/index.lock", "api/.git/refs/heads/a b.lock"]
        );
        assert_eq!(r.errors, ["web/.git/x.lock: cannot remove"]);
        assert_eq!(r.removed_count(), 2);
    }

    #[test]
    fn a_busy_run_removes_nothing() {
        let r = parse("B\nD\n").unwrap();
        assert!(r.skipped_busy);
        assert_eq!(r.removed_count(), 0);
    }

    #[test]
    fn lists_are_bounded() {
        let mut out = String::new();
        for i in 0..MAX_LOCKS + 7 {
            writeln!(out, "L\ta/.git/{i}.lock").unwrap();
        }
        out.push_str("D\n");
        let r = parse(&out).unwrap();
        assert_eq!(r.removed.len(), MAX_LOCKS);
        assert_eq!(r.more, 7);
        assert_eq!(r.removed_count(), MAX_LOCKS as u64 + 7);
        let long = format!("L\t{}\nD\n", "x".repeat(2000));
        assert_eq!(parse(&long).unwrap().removed[0].chars().count(), MAX_LINE);
    }

    #[test]
    fn odd_output_is_refused() {
        for bad in [
            "",
            "L\ta.lock\n",
            "D\nD\n",
            "D\nL\ta.lock\n",
            "X\nD\n",
            "L\n",
            "D\textra\n",
            "B\tx\nD\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} accepted");
        }
    }
}
