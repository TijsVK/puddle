// SPDX-License-Identifier: GPL-3.0-or-later
//! The runtime's NOTICE file: what is bundled, under which licence, what puddle changed in msb
//! (Apache-2.0 §4(b)), and the written offer for the firmware's source (GPL-2.0 §3(b), D-35).

use std::fmt::Write as _;

use crate::source::ForkFacts;

/// Where source requests go (D-55 contact address).
pub const SOURCE_REQUEST_CONTACT: &str = "puddle@tijsvankampen.be";

/// The NOTICE text for a runtime built from `facts`.
#[must_use]
pub fn render(facts: &ForkFacts) -> String {
    let fw = &facts.firmware;
    let kernel_series = fw.kernel_version.split('.').next().unwrap_or_default();
    let mut out = format!(
        "\
puddle bundled runtime: NOTICE
==============================

This folder contains the msb runtime that puddle runs its sandboxes with. It is not part of
puddle's own source code and keeps its own licences. The licence texts are in this folder.

1. msb (microsandbox) - Apache-2.0 (Apache-2.0.txt)
---------------------------------------------------

msb.exe is built from https://github.com/{fork} at tag {tag}, a fork of microsandbox
(https://github.com/{upstream}, tag {upstream_tag}), by the microsandbox authors. microsandbox ships
no NOTICE file of its own. \"microsandbox\" is its authors' name; puddle is not affiliated with them.

Modified files (Apache-2.0 section 4(b)): puddle changed msb. The changes are exactly these commits
on top of {upstream_tag}, each viewable at https://github.com/{fork}/commit/<sha>:
",
        fork = facts.fork_repo,
        tag = facts.tag,
        upstream = facts.upstream_repo,
        upstream_tag = facts.upstream_tag,
    );
    if facts.commits.is_empty() {
        out.push_str("\n  (none: this build is upstream's code unchanged)\n");
    } else {
        out.push('\n');
        for c in &facts.commits {
            let _ = writeln!(out, "  {} {}", c.sha, c.subject);
        }
    }
    let _ = write!(
        out,
        "
msb.exe statically links third-party Rust crates; their copyright notices and licence texts are
in THIRD-PARTY-msb.txt.

2. libkrunfw {lv} - LGPL-2.1-only (LGPL-2.1.txt), with Linux {kv} - GPL-2.0-only (GPL-2.0.txt)
----------------------------------------------------------------------------------------------

libkrunfw.dll is libkrunfw {lv} as published by microsandbox's release {upstream_tag}, unchanged. The
library code is LGPL-2.1-only; it contains a Linux {kv} kernel, with patches and a kernel
configuration, which is GPL-2.0-only. msb loads it as a separate library, which you may replace.

Source code: libkrunfw at {repo}/tree/{commit} (incl. its patches and
config-libkrunfw-windows_x86_64), and the kernel at
https://cdn.kernel.org/pub/linux/kernel/v{series}.x/linux-{kv}.tar.xz

Written offer: for at least three years after we last distribute this version of the runtime, we
will give anyone who asks a complete machine-readable copy of the corresponding source code of
libkrunfw {lv} and of the Linux {kv} kernel it contains (the libkrunfw source at commit
{commit}, the kernel source, the patches and the kernel configuration used), on a medium
customarily used for software interchange, for a charge no more than our cost of physically
performing the distribution. Ask {contact}, naming puddle and runtime {tag}.
This offer is valid for anyone in receipt of this runtime.

3. puddle
---------

puddle itself is GPL-3.0-or-later. Its third-party crates are listed in THIRD-PARTY-puddle.txt.
",
        lv = fw.libkrunfw_version,
        kv = fw.kernel_version,
        repo = fw.repo_url,
        commit = fw.commit,
        series = kernel_series,
        upstream_tag = facts.upstream_tag,
        contact = SOURCE_REQUEST_CONTACT,
        tag = facts.tag,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::{Commit, Firmware};

    fn facts(commits: Vec<Commit>) -> ForkFacts {
        ForkFacts {
            fork_repo: "TijsVK/microsandbox".into(),
            upstream_repo: "superradcompany/microsandbox".into(),
            tag: "v0.7.7-puddle.1".into(),
            upstream_tag: "v0.7.7".into(),
            commits,
            firmware: Firmware {
                libkrunfw_version: "5.6.1".into(),
                kernel_version: "6.12.109".into(),
                repo_url: "https://github.com/superradcompany/libkrunfw".into(),
                commit: "21f169f7e94798c8916315f8ac6f5999d5b88566".into(),
            },
        }
    }

    #[test]
    fn lists_every_fork_commit_and_the_offer() {
        let text = render(&facts(vec![
            Commit {
                sha: "a".repeat(40),
                subject: "fix(vsock): write queued bytes".into(),
            },
            Commit {
                sha: "b".repeat(40),
                subject: "fix(ssh): signal exit".into(),
            },
        ]));
        assert!(text.contains(&format!(
            "  {} fix(vsock): write queued bytes\n",
            "a".repeat(40)
        )));
        assert!(text.contains(&format!("  {} fix(ssh): signal exit\n", "b".repeat(40))));
        assert!(text.contains("https://github.com/TijsVK/microsandbox at tag v0.7.7-puddle.1"));
        assert!(text.contains("Apache-2.0 section 4(b)"));
        assert!(text.contains("libkrunfw 5.6.1"));
        assert!(
            text.contains("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.109.tar.xz")
        );
        assert!(text.contains("https://github.com/superradcompany/libkrunfw/tree/21f169f7e94798c8916315f8ac6f5999d5b88566"));
        assert!(text.contains("at least three years"));
        assert!(text.contains(SOURCE_REQUEST_CONTACT));
        assert!(!text.contains("(none:"));
    }

    #[test]
    fn says_so_when_there_are_no_changes() {
        assert!(render(&facts(vec![])).contains("(none: this build is upstream's code unchanged)"));
    }
}
