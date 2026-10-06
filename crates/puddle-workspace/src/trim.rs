// SPDX-License-Identifier: GPL-3.0-or-later
//! `fstrim` on a workspace volume (ADR 0006 point 7): msb mounts volumes without `discard`, so
//! space freed in the guest only returns to the host image when puddle trims.

use std::time::Duration;

use puddle_compute::{ExecRequest, Sandbox};
use puddle_types::WorkspaceId;

use crate::{Layout, WorkspaceError};

/// How long one `fstrim` may take (a trim of a large, fragmented volume is slow).
pub const TRIM_TIMEOUT: Duration = Duration::from_secs(300);

/// How much of a command's stderr goes into an error.
const STDERR_TAIL: usize = 512;

/// What a trim did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrimReport {
    /// The workspace.
    pub workspace: WorkspaceId,
    /// Bytes `fstrim -v` reported as trimmed, if its output said.
    pub trimmed_bytes: Option<u64>,
}

/// The trim command: `fstrim -v <mount>` as root.
pub(crate) fn request(layout: &Layout) -> ExecRequest {
    ExecRequest::new("fstrim", ["-v", layout.mount().as_str()])
        .as_user("root")
        .with_timeout(TRIM_TIMEOUT)
}

/// Runs `fstrim` on workspace `id`'s mount point in `sandbox`.
pub(crate) async fn run<S: Sandbox>(
    sandbox: &S,
    id: &WorkspaceId,
) -> Result<TrimReport, WorkspaceError> {
    let layout = Layout::new(id)?;
    let out = sandbox
        .exec(request(&layout))
        .await
        .map_err(|e| WorkspaceError::runtime("trim", id, e))?;
    if !out.status.success() {
        let reason = match out.status.code {
            127 => "fstrim is not installed in the image".to_owned(),
            code => format!("fstrim exited {code}: {}", tail(&out.stderr_text())),
        };
        return Err(WorkspaceError::Trim {
            workspace: id.to_string(),
            reason,
        });
    }
    Ok(TrimReport {
        workspace: id.clone(),
        trimmed_bytes: trimmed_bytes(&out.stdout_text()),
    })
}

/// The byte count from `fstrim -v`: util-linux prints `/m: 1 GiB (1073741824 bytes) trimmed`,
/// busybox `/m: 1073741824 bytes trimmed`.
fn trimmed_bytes(stdout: &str) -> Option<u64> {
    let line = stdout.lines().find(|l| l.ends_with("trimmed"))?;
    let before = line.rsplit_once(" bytes")?.0;
    let digits = before.rsplit([' ', '(']).next()?;
    digits.parse().ok()
}

fn tail(text: &str) -> String {
    let text = text.trim();
    let start = text
        .char_indices()
        .rev()
        .nth(STDERR_TAIL - 1)
        .map_or(0, |(i, _)| i);
    text.get(start..).unwrap_or(text).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_parse_from_util_linux_and_busybox() {
        assert_eq!(
            trimmed_bytes("/workspaces/a: 1 GiB (1073741824 bytes) trimmed\n"),
            Some(1_073_741_824)
        );
        assert_eq!(
            trimmed_bytes("/workspaces/a: 4096 bytes trimmed\n"),
            Some(4096)
        );
        assert_eq!(
            trimmed_bytes("/workspaces/a: 0 B (0 bytes) trimmed"),
            Some(0)
        );
        assert_eq!(trimmed_bytes(""), None);
        assert_eq!(trimmed_bytes("something else"), None);
        assert_eq!(trimmed_bytes("/w: lots (x bytes) trimmed"), None);
    }

    #[test]
    fn the_request_trims_the_mount_point_as_root() {
        let l = Layout::new(&WorkspaceId::new("a").unwrap()).unwrap();
        let r = request(&l);
        assert_eq!(r.program, "fstrim");
        assert_eq!(r.args, ["-v", "/workspaces/a"]);
        assert_eq!(r.user.as_deref(), Some("root"));
        assert_eq!(r.timeout, TRIM_TIMEOUT);
    }

    #[test]
    fn tails_keep_the_end() {
        assert_eq!(tail("  short \n"), "short");
        let long = format!("{}end", "x".repeat(1000));
        let t = tail(&long);
        assert_eq!(t.chars().count(), STDERR_TAIL);
        assert!(t.ends_with("end"));
    }
}
