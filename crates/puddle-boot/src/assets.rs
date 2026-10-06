// SPDX-License-Identifier: GPL-3.0-or-later
//! The guest scripts, embedded in the binary, and the read-only mounts that put them into a
//! sandbox.

use std::io;
use std::path::Path;

use puddle_compute::{FileMount, SandboxSpec};
use puddle_types::GuestPath;

/// `guest/boot.sh`: the hook itself.
pub const BOOT_SH: &str = include_str!("../guest/boot.sh");

/// `guest/agent-supervise.sh`: restarts `puddle-agent` whenever it exits.
pub const AGENT_SUPERVISE_SH: &str = include_str!("../guest/agent-supervise.sh");

/// Where `boot.sh` is mounted in the guest.
pub const BOOT_SH_GUEST: &str = "/puddle/boot.sh";

/// Where `agent-supervise.sh` is mounted (`boot.sh` finds it next to itself).
pub const AGENT_SUPERVISE_GUEST: &str = "/puddle/agent-supervise.sh";

/// Where the `puddle-agent` binary is mounted by default (T-111 builds it).
pub const AGENT_GUEST: &str = "/puddle/puddle-agent";

/// The guest directory with puddle's read-only mounts. The plan may not write below it.
pub const MOUNT_DIR_GUEST: &str = "/puddle";

/// A guest path from one of this crate's constants.
pub(crate) fn guest_path(path: &'static str) -> GuestPath {
    // Only ever called with the constants above, which a unit test checks are valid.
    GuestPath::new(path).unwrap_or_else(|_| unreachable_guest_path(path))
}

#[cold]
#[expect(
    clippy::panic,
    reason = "invariant: every constant passed to guest_path is a valid GuestPath (unit-tested)"
)]
fn unreachable_guest_path(path: &str) -> GuestPath {
    panic!("constant guest path {path:?} is not valid")
}

/// Writes `boot.sh` and `agent-supervise.sh` into the host directory `dir` (created if needed)
/// and returns the read-only mounts that put them at [`BOOT_SH_GUEST`] and
/// [`AGENT_SUPERVISE_GUEST`]. Add them to the spec with [`with_boot_mounts`].
///
/// # Errors
///
/// When `dir` can't be created or a file can't be written.
pub fn write_assets(dir: &Path) -> io::Result<Vec<FileMount>> {
    std::fs::create_dir_all(dir)?;
    let boot = dir.join("boot.sh");
    let supervise = dir.join("agent-supervise.sh");
    std::fs::write(&boot, BOOT_SH)?;
    std::fs::write(&supervise, AGENT_SUPERVISE_SH)?;
    Ok(vec![
        FileMount::read_only(boot, guest_path(BOOT_SH_GUEST)),
        FileMount::read_only(supervise, guest_path(AGENT_SUPERVISE_GUEST)),
    ])
}

/// `spec` with the boot scripts in `assets` (from [`write_assets`]) and, if given, the agent
/// binary at [`AGENT_GUEST`] mounted read-only.
#[must_use]
pub fn with_boot_mounts(
    mut spec: SandboxSpec,
    assets: Vec<FileMount>,
    agent_binary: Option<&Path>,
) -> SandboxSpec {
    for m in assets {
        spec = spec.with_file_mount(m);
    }
    if let Some(agent) = agent_binary {
        spec = spec.with_file_mount(FileMount::read_only(agent, guest_path(AGENT_GUEST)));
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_valid_guest_paths_under_the_mount_dir() {
        let dir = guest_path(MOUNT_DIR_GUEST);
        for p in [BOOT_SH_GUEST, AGENT_SUPERVISE_GUEST, AGENT_GUEST] {
            assert!(guest_path(p).is_within(&dir), "{p}");
        }
    }

    #[test]
    #[should_panic(expected = "is not valid")]
    fn an_invalid_constant_is_a_bug() {
        let _ = guest_path("relative");
    }

    #[test]
    fn scripts_are_posix_sh_with_licence_headers() {
        for s in [BOOT_SH, AGENT_SUPERVISE_SH] {
            assert!(s.starts_with("#!/bin/sh\n# SPDX-License-Identifier: GPL-3.0-or-later\n"));
            assert!(!s.contains('\r'), "CRLF would break sh in the guest");
        }
    }

    #[test]
    fn read_only_takes_regular_files_puddle_wrote() {
        // dash's `read` takes one byte per read(2) and procfs answers a read at a non-zero
        // offset with EOF: `read x </proc/sys/...` sees "1" for 1024 (found on msb 0.7.7, T-106).
        // The fake-root tests use regular files and can't catch it, so `read` may only redirect
        // from the plan or puddle's own pid files; procfs values go through `cat`.
        for (name, script) in [
            ("boot.sh", BOOT_SH),
            ("agent-supervise.sh", AGENT_SUPERVISE_SH),
        ] {
            for line in script.lines().filter(|l| l.contains("read ")) {
                if let Some((_, target)) = line.split_once(" <") {
                    let target = target.split_whitespace().next().unwrap_or_default();
                    assert!(
                        ["\"$PLAN\"", "\"$1\""].contains(&target),
                        "{name}: `{}` reads {target} with `read`",
                        line.trim()
                    );
                }
            }
        }
    }
}
