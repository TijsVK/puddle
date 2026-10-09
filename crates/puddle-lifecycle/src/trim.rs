// SPDX-License-Identifier: GPL-3.0-or-later
//! `fstrim` before a stop (ADR 0006 point 7): msb mounts volumes without `discard`, so space the
//! guest freed only returns to the host's disk image when puddle trims.

use std::time::Duration;

use puddle_compute::{ExecOutput, ExecRequest};
use puddle_types::GuestPath;

/// Trims every mounted filesystem: util-linux `fstrim -a`; busybox (alpine) has no `-a`, so
/// then each mounted ext2/3/4, xfs, btrfs or f2fs filesystem from `/proc/mounts` in turn.
const TRIM_ALL: &str = r#"fstrim -a -v 2>/dev/null && exit 0
rc=0
for m in $(awk '$3 ~ /^(ext[234]|xfs|btrfs|f2fs)$/ { print $2 }' /proc/mounts); do
  fstrim -v "$m" || rc=$?
done
exit $rc"#;

/// The command that trims `paths` (one `fstrim -v` each, as root), or every mounted filesystem
/// that supports it when `paths` is empty. `timeout` bounds the whole run.
#[must_use]
pub fn trim_request(paths: &[GuestPath], timeout: Duration) -> ExecRequest {
    let request = if paths.is_empty() {
        ExecRequest::sh(TRIM_ALL)
    } else {
        // Every path is trimmed even if an earlier one fails; the exit status is the last
        // failure's. Paths are passed as arguments, never spliced into the script.
        let mut args = vec![
            "-c".to_owned(),
            r#"rc=0; for p in "$@"; do fstrim -v "$p" || rc=$?; done; exit $rc"#.to_owned(),
            "fstrim".to_owned(),
        ];
        args.extend(paths.iter().map(|p| p.as_str().to_owned()));
        ExecRequest::new("sh", args)
    };
    request.as_user("root").with_timeout(timeout)
}

/// What the trim before a stop did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrimOutcome {
    /// `fstrim` exited 0.
    Trimmed,
    /// The sandbox wasn't running, so there was nothing to trim.
    NotRunning,
    /// `fstrim` ran and failed (not installed: 127; nothing trimmable: util-linux exits 1 or 32).
    /// The stop goes ahead.
    Failed {
        /// Its exit code.
        code: i32,
        /// The end of its stderr.
        stderr: String,
    },
    /// The exec itself failed or ran out of time; the stop goes ahead.
    Error(String),
}

impl TrimOutcome {
    /// Why the trim did not work, or `None` when it did or had nothing to do.
    #[must_use]
    pub fn problem(&self) -> Option<String> {
        match self {
            Self::Trimmed | Self::NotRunning => None,
            Self::Failed { code, stderr } => Some(format!("fstrim exited {code}: {stderr}")),
            Self::Error(why) => Some(why.clone()),
        }
    }

    pub(crate) fn from_output(out: &ExecOutput) -> Self {
        if out.status.success() {
            return Self::Trimmed;
        }
        let stderr = out.stderr_text();
        let stderr = stderr.trim();
        let start = stderr
            .char_indices()
            .rev()
            .nth(STDERR_TAIL - 1)
            .map_or(0, |(i, _)| i);
        Self::Failed {
            code: out.status.code,
            stderr: stderr.get(start..).unwrap_or(stderr).to_owned(),
        }
    }
}

/// How much of `fstrim`'s stderr a [`TrimOutcome::Failed`] keeps.
const STDERR_TAIL: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    fn out(code: i32, stderr: &str) -> ExecOutput {
        ExecOutput::new(code, Vec::new(), stderr.as_bytes())
    }

    #[test]
    fn no_paths_trims_every_mounted_filesystem() {
        let r = trim_request(&[], Duration::from_secs(7));
        assert_eq!(r.program, "sh");
        assert_eq!(r.args, ["-c", TRIM_ALL]);
        assert!(TRIM_ALL.starts_with("fstrim -a -v"), "util-linux first");
        assert_eq!(r.user.as_deref(), Some("root"));
        assert_eq!(r.timeout, Duration::from_secs(7));
    }

    #[test]
    fn paths_are_arguments_not_script_text() {
        let paths = [
            GuestPath::new("/workspaces/a").unwrap(),
            GuestPath::new("/srv/$(reboot)").unwrap(),
        ];
        let r = trim_request(&paths, Duration::from_secs(1));
        assert_eq!(r.program, "sh");
        assert_eq!(r.args[0], "-c");
        assert!(!r.args[1].contains("/workspaces"));
        assert_eq!(&r.args[3..], ["/workspaces/a", "/srv/$(reboot)"]);
    }

    #[test]
    fn outcome_keeps_the_code_and_the_end_of_stderr() {
        assert_eq!(TrimOutcome::from_output(&out(0, "")), TrimOutcome::Trimmed);
        let long = format!("{}tail", "x".repeat(1000));
        let TrimOutcome::Failed { code, stderr } = TrimOutcome::from_output(&out(32, &long)) else {
            panic!("want Failed");
        };
        assert_eq!(code, 32);
        assert_eq!(stderr.chars().count(), STDERR_TAIL);
        assert!(stderr.ends_with("tail"));
    }
}
