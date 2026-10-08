// SPDX-License-Identifier: GPL-3.0-or-later
//! The unsaved-work check before a delete (ADR 0006 point 3): `guest/delete-check.sh`
//! in a sandbox that has the workspace, and its parsed result.
//!
//! The guest owns the volume, so a hostile guest can make its own workspace look clean; the
//! check protects the user from losing work by accident, not from the guest. The parser still
//! treats the output as hostile: bounded lists and lines, unknown records refused, and an
//! output without the end marker refused (fail closed: no report, no delete).

use std::fmt;
use std::time::Duration;

use puddle_compute::{ExecRequest, Sandbox};
use puddle_types::{SandboxName, WorkspaceId};

use crate::{Layout, WorkspaceError};

/// The check script (POSIX sh, run as root with the mount point as `$1`).
pub const DELETE_CHECK_SH: &str = include_str!("../guest/delete-check.sh");

/// How long the check may take.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(300);

/// Most items kept per list; the rest are counted in [`Listing::more`].
pub const MAX_ITEMS: usize = 200;

/// Most checkouts reported; more is an error (fail closed).
pub const MAX_REPOS: usize = 100;

/// Longest line kept, in characters.
const MAX_LINE: usize = 500;

/// A bounded list of lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The first [`MAX_ITEMS`] items.
    pub items: Vec<String>,
    /// How many more there are.
    pub more: u64,
}

impl Listing {
    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.more == 0
    }

    /// How many items there are in all.
    #[must_use]
    pub fn total(&self) -> u64 {
        u64::try_from(self.items.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.more)
    }

    fn push(&mut self, item: &str) {
        if self.items.len() < MAX_ITEMS {
            self.items.push(item.chars().take(MAX_LINE).collect());
        } else {
            self.more = self.more.saturating_add(1);
        }
    }
}

/// What one checkout holds that isn't on a remote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoReport {
    /// The checkout's directory under the volume root.
    pub dir: String,
    /// Uncommitted changes and untracked files (`git status --porcelain` lines).
    pub uncommitted: Listing,
    /// Commits on no remote-tracking branch (`<hash> <subject>`).
    pub unpushed: Listing,
    /// Stashes (`git stash list` lines).
    pub stashes: Listing,
}

impl RepoReport {
    /// Whether nothing would be lost.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.uncommitted.is_empty() && self.unpushed.is_empty() && self.stashes.is_empty()
    }
}

/// What the check found on a volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Findings {
    /// Every checkout, clean or not, in directory order.
    pub repos: Vec<RepoReport>,
    /// Top-level entries that aren't checkouts (data outside any repo).
    pub other: Listing,
    /// What couldn't be checked (`<dir>: <message>`).
    pub errors: Vec<String>,
}

impl Findings {
    /// Whether deleting loses nothing that the check can see.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.repos.iter().all(RepoReport::is_clean)
            && self.other.is_empty()
            && self.errors.is_empty()
    }
}

/// What a delete would lose, for the user to confirm (see [`crate::Workspaces::check_delete`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteReport {
    /// The workspace.
    pub workspace: WorkspaceId,
    /// What the check found.
    pub findings: Findings,
    /// The sandbox the check ran in (the running holder, or a short-lived maintenance sandbox).
    pub checked_in: SandboxName,
    /// The stopped sandbox that owns the workspace: the delete removes it too.
    pub removes_sandbox: Option<SandboxName>,
    /// The workspace's volume is gone: there is nothing to inspect and nothing to lose, and the
    /// delete only drops the workspace (and the sandbox that owned it).
    pub volume_missing: bool,
}

impl DeleteReport {
    /// Whether deleting loses nothing that the check can see. A clean report still needs
    /// [`DeleteReport::confirm`].
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_clean()
    }

    /// The user's go-ahead for exactly this report. [`crate::Workspaces::delete`] checks
    /// again and refuses if anything changed.
    #[must_use]
    pub fn confirm(&self) -> DeleteConfirmation {
        DeleteConfirmation {
            workspace: self.workspace.clone(),
            findings: self.findings.clone(),
            removes_sandbox: self.removes_sandbox.clone(),
            volume_missing: self.volume_missing,
        }
    }
}

fn write_listing(f: &mut fmt::Formatter<'_>, what: &str, l: &Listing) -> fmt::Result {
    if l.is_empty() {
        return Ok(());
    }
    writeln!(f, "    {what} ({}):", l.total())?;
    for item in &l.items {
        writeln!(f, "      {item}")?;
    }
    if l.more > 0 {
        writeln!(f, "      ... and {} more", l.more)?;
    }
    Ok(())
}

impl fmt::Display for DeleteReport {
    /// A plain-text summary for the CLI and logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.volume_missing {
            writeln!(
                f,
                "workspace {}: its volume is already gone; nothing is lost by deleting it",
                self.workspace
            )?;
        } else if self.is_clean() {
            writeln!(f, "workspace {}: nothing unsaved", self.workspace)?;
        } else {
            writeln!(f, "workspace {}: deleting loses", self.workspace)?;
        }
        for r in &self.findings.repos {
            if r.is_clean() {
                writeln!(f, "  {}: clean", r.dir)?;
                continue;
            }
            writeln!(f, "  {}:", r.dir)?;
            write_listing(f, "uncommitted changes", &r.uncommitted)?;
            write_listing(f, "unpushed commits", &r.unpushed)?;
            write_listing(f, "stashes", &r.stashes)?;
        }
        if !self.findings.other.is_empty() {
            writeln!(f, "  outside any checkout:")?;
            write_listing(f, "files and directories", &self.findings.other)?;
        }
        for e in &self.findings.errors {
            writeln!(f, "  not checked: {e}")?;
        }
        if let Some(sb) = &self.removes_sandbox {
            writeln!(f, "  also removes stopped sandbox {sb}")?;
        }
        Ok(())
    }
}

/// The user's go-ahead for one [`DeleteReport`]; only [`DeleteReport::confirm`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteConfirmation {
    pub(crate) workspace: WorkspaceId,
    pub(crate) findings: Findings,
    pub(crate) removes_sandbox: Option<SandboxName>,
    pub(crate) volume_missing: bool,
}

impl DeleteConfirmation {
    /// The workspace it is for.
    #[must_use]
    pub fn workspace(&self) -> &WorkspaceId {
        &self.workspace
    }
}

/// The check command for `layout`.
pub(crate) fn request(layout: &Layout) -> ExecRequest {
    ExecRequest::new(
        "sh",
        [
            "-c",
            DELETE_CHECK_SH,
            "puddle-delete-check",
            layout.mount().as_str(),
        ]
        .map(str::to_owned),
    )
    .as_user("root")
    .with_timeout(CHECK_TIMEOUT)
}

/// Runs the check for `id` in `sandbox`.
pub(crate) async fn run<S: Sandbox>(
    sandbox: &S,
    id: &WorkspaceId,
) -> Result<Findings, WorkspaceError> {
    let layout = Layout::new(id)?;
    let out = sandbox
        .exec(request(&layout))
        .await
        .map_err(|e| WorkspaceError::runtime("check for unsaved work", id, e))?;
    let fail = |reason: String| WorkspaceError::Check {
        workspace: id.to_string(),
        reason,
    };
    if !out.status.success() {
        let stdout = out.stdout_text();
        let first_error = stdout
            .lines()
            .find_map(|l| l.strip_prefix("E\t"))
            .unwrap_or_default();
        return Err(fail(format!(
            "check exited {}: {}{}",
            out.status.code,
            first_error.replace('\t', ": "),
            out.stderr_text().trim()
        )));
    }
    parse(&out.stdout_text()).map_err(fail)
}

/// Parses the check's output (see `guest/delete-check.sh`).
pub(crate) fn parse(stdout: &str) -> Result<Findings, String> {
    let mut findings = Findings::default();
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
            ("R", Some(dir), None) => {
                if findings.repos.len() == MAX_REPOS {
                    return Err(format!("more than {MAX_REPOS} checkouts"));
                }
                findings.repos.push(RepoReport {
                    dir: dir.chars().take(MAX_LINE).collect(),
                    ..RepoReport::default()
                });
            }
            ("O", Some(name), None) => findings.other.push(name),
            ("E", Some(dir), Some(message)) => {
                if findings.errors.len() < MAX_ITEMS {
                    findings
                        .errors
                        .push(format!("{dir}: {message}").chars().take(MAX_LINE).collect());
                }
            }
            ("M", Some(kind), Some(count)) => {
                let n: u64 = count
                    .parse()
                    .map_err(|_| format!("bad count line {:?}", truncate(line)))?;
                let list = listing(&mut findings, kind)
                    .ok_or_else(|| format!("bad count line {:?}", truncate(line)))?;
                list.more = list.more.saturating_add(n);
            }
            ("U" | "C" | "S", Some(_), _) => {
                // The item is everything after the tag (status lines may hold tabs).
                let item = line.get(2..).unwrap_or_default();
                let list = listing(&mut findings, tag)
                    .ok_or_else(|| format!("{tag} line before any checkout"))?;
                list.push(item);
            }
            _ => return Err(format!("unexpected output line {:?}", truncate(line))),
        }
    }
    if !done {
        return Err("the check did not finish (no end marker)".into());
    }
    Ok(findings)
}

/// The list a `U`/`C`/`S` (current checkout) or `O` record goes to.
fn listing<'f>(findings: &'f mut Findings, kind: &str) -> Option<&'f mut Listing> {
    if kind == "O" {
        return Some(&mut findings.other);
    }
    let repo = findings.repos.last_mut()?;
    match kind {
        "U" => Some(&mut repo.uncommitted),
        "C" => Some(&mut repo.unpushed),
        "S" => Some(&mut repo.stashes),
        _ => None,
    }
}

fn truncate(line: &str) -> String {
    line.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn a_full_output_parses_into_findings() {
        let out = "R\tapi\nU\t M src/main.rs\nU\t?? notes.txt\nC\tabc1234 wip\nS\tstash@{0}: WIP on main: x\n\
                   R\tweb\nO\tscratch.txt\nE\tlib\tgit status failed: boom\nM\tO\t3\nD\n";
        let f = parse(out).unwrap();
        assert_eq!(f.repos.len(), 2);
        let api = &f.repos[0];
        assert_eq!(api.dir, "api");
        assert_eq!(api.uncommitted.items, [" M src/main.rs", "?? notes.txt"]);
        assert_eq!(api.unpushed.items, ["abc1234 wip"]);
        assert_eq!(api.stashes.items, ["stash@{0}: WIP on main: x"]);
        assert!(!api.is_clean());
        assert!(f.repos[1].is_clean());
        assert_eq!(f.other.items, ["scratch.txt"]);
        assert_eq!(f.other.more, 3);
        assert_eq!(f.other.total(), 4);
        assert_eq!(f.errors, ["lib: git status failed: boom"]);
        assert!(!f.is_clean());
    }

    #[test]
    fn an_empty_volume_is_clean() {
        let f = parse("D\n").unwrap();
        assert!(f.is_clean());
        let f = parse("R\tapi\nD\n").unwrap();
        assert!(f.is_clean());
    }

    #[test]
    fn each_kind_alone_makes_it_unclean() {
        for out in [
            "R\ta\nU\t?? x\nD\n",
            "R\ta\nC\tabc x\nD\n",
            "R\ta\nS\tstash@{0}: x\nD\n",
            "R\ta\nM\tU\t5\nD\n",
            "O\tx\nD\n",
            "E\ta\tgit is not installed in the image\nD\n",
        ] {
            assert!(!parse(out).unwrap().is_clean(), "{out:?}");
        }
    }

    #[test]
    fn malformed_or_unfinished_output_is_refused() {
        for (out, want) in [
            ("", "did not finish"),
            ("R\ta\nU\t?? x\n", "did not finish"),
            ("U\t?? x\nD\n", "before any checkout"),
            ("X\ty\nD\n", "unexpected output line"),
            ("R\nD\n", "unexpected output line"),
            ("M\tU\t1\nD\n", "bad count line"),
            ("R\ta\nM\tQ\t1\nD\n", "bad count line"),
            ("R\ta\nM\tU\tmany\nD\n", "bad count line"),
            ("D\nO\tlate\n", "after the end marker"),
        ] {
            let err = parse(out).unwrap_err();
            assert!(err.contains(want), "{out:?}: {err}");
        }
    }

    #[test]
    fn hostile_output_stays_bounded() {
        let mut out = String::from("R\ta\n");
        for i in 0..(MAX_ITEMS + 50) {
            writeln!(out, "U\t?? {i}{}", "x".repeat(2000)).unwrap();
        }
        out.push_str("M\tU\t18446744073709551615\nD\n");
        let f = parse(&out).unwrap();
        let u = &f.repos[0].uncommitted;
        assert_eq!(u.items.len(), MAX_ITEMS);
        assert!(u.items.iter().all(|i| i.chars().count() <= MAX_LINE));
        assert_eq!(u.more, u64::MAX, "saturates");
        assert_eq!(u.total(), u64::MAX);

        let mut repos = String::new();
        for i in 0..=MAX_REPOS {
            writeln!(repos, "R\tr{i}").unwrap();
        }
        assert!(
            parse(&format!("{repos}D\n"))
                .unwrap_err()
                .contains("checkouts")
        );

        let mut errors = String::new();
        for i in 0..300 {
            writeln!(errors, "E\tr{i}\tx").unwrap();
        }
        assert_eq!(
            parse(&format!("{errors}D\n")).unwrap().errors.len(),
            MAX_ITEMS
        );
    }

    #[test]
    fn the_request_runs_the_script_as_root_on_the_mount_point() {
        let l = Layout::new(&WorkspaceId::new("a").unwrap()).unwrap();
        let r = request(&l);
        assert_eq!(r.program, "sh");
        assert_eq!(
            r.args,
            [
                "-c",
                DELETE_CHECK_SH,
                "puddle-delete-check",
                "/workspaces/a"
            ]
        );
        assert_eq!(r.user.as_deref(), Some("root"));
    }

    fn report(findings: Findings) -> DeleteReport {
        DeleteReport {
            volume_missing: false,
            workspace: WorkspaceId::new("acme").unwrap(),
            findings,
            checked_in: SandboxName::new("acme").unwrap(),
            removes_sandbox: None,
        }
    }

    #[test]
    fn the_summary_lists_what_would_be_lost() {
        let clean = report(parse("R\tapi\nD\n").unwrap());
        assert_eq!(
            clean.to_string(),
            "workspace acme: nothing unsaved\n  api: clean\n"
        );
        let mut dirty = report(
            parse("R\tapi\nU\t?? a\nM\tU\t2\nC\tabc x\nS\ts\nO\tf\nE\tb\tboom\nD\n").unwrap(),
        );
        dirty.removes_sandbox = Some(SandboxName::new("old").unwrap());
        let text = dirty.to_string();
        for want in [
            "deleting loses",
            "uncommitted changes (3):",
            "      ?? a",
            "... and 2 more",
            "unpushed commits (1):",
            "stashes (1):",
            "outside any checkout:",
            "      f",
            "not checked: b: boom",
            "also removes stopped sandbox old",
        ] {
            assert!(text.contains(want), "{want:?} missing from\n{text}");
        }
        let c = dirty.confirm();
        assert_eq!(c.workspace().as_str(), "acme");
    }
}
