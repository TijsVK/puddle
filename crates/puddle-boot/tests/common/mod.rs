// SPDX-License-Identifier: GPL-3.0-or-later
//! A fake guest root for running the real `boot.sh` on the test host: stubbed `sysctl`,
//! `update-ca-certificates` and `puddle-agent`, a fake `/proc` for the files the hook reads, and
//! cleanup of every process the hook started.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test harness outside #[test] fns: a failed setup fails the test"
)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use puddle_boot::{AGENT_SUPERVISE_SH, BOOT_SH, BootPlan};

const SYSCTL_STUB: &str = r#"#!/bin/sh
echo "sysctl $*" >>"$PUDDLE_ROOT/calls"
[ "$1" = -w ] && shift
key=${1%%=*}
printf '%s\n' "${1#*=}" >"$PUDDLE_ROOT/proc/sys/$(printf %s "$key" | tr . /)"
"#;

const UPDATE_CA_STUB: &str = r#"#!/bin/sh
echo "update-ca-certificates" >>"$PUDDLE_ROOT/calls"
if [ -f "$PUDDLE_ROOT/fail-update-ca" ]; then echo "boom: bad certificate" >&2; exit 1; fi
"#;

const AGENT_STUB: &str = r#"#!/bin/sh
echo $$ >>"$PUDDLE_ROOT/agent.pids"
grep -q 0C38 "$PUDDLE_ROOT/proc/net/tcp" || echo "   0: 0100007F:0C38 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1" >>"$PUDDLE_ROOT/proc/net/tcp"
exec sleep 1000
"#;

/// A temporary fake guest root, removed (with its processes) on drop.
pub(crate) struct FakeRoot {
    pub(crate) root: PathBuf,
    pub(crate) shell: PathBuf,
    stubs: PathBuf,
}

/// The POSIX shells on this host to run the hook with (dash and bash). Not busybox: Ubuntu's
/// `busybox sh` runs its own applets (`sysctl`, ...) before `PATH`, so the stubs can't stand in;
/// busybox ash is covered by the Alpine VM test.
pub(crate) fn shells() -> Vec<PathBuf> {
    let found: Vec<PathBuf> = ["/bin/dash", "/bin/bash"]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    assert!(!found.is_empty(), "no POSIX shell found");
    found
}

fn write_exec(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl FakeRoot {
    /// A fresh root, run with `shell`.
    pub(crate) fn new(shell: &Path) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let root = std::env::temp_dir().join(format!(
            "puddle-boot-test-{}-{}-{nanos}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        for d in [
            "puddle",
            "stubs",
            "etc",
            "proc/sys/fs/inotify",
            "proc/sys/kernel/random",
            "proc/net",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        write_exec(&root.join("puddle/boot.sh"), BOOT_SH);
        write_exec(&root.join("puddle/agent-supervise.sh"), AGENT_SUPERVISE_SH);
        write_exec(&root.join("puddle/puddle-agent"), AGENT_STUB);
        let stubs = root.join("stubs");
        write_exec(&stubs.join("sysctl"), SYSCTL_STUB);
        write_exec(&stubs.join("update-ca-certificates"), UPDATE_CA_STUB);
        std::fs::write(root.join("proc/sys/kernel/random/boot_id"), "boot-1\n").unwrap();
        std::fs::write(
            root.join("proc/net/tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        )
        .unwrap();
        for f in [
            "fs/inotify/max_user_instances",
            "fs/inotify/max_user_watches",
            "kernel/unprivileged_bpf_disabled",
        ] {
            std::fs::write(root.join("proc/sys").join(f), "0\n").unwrap();
        }
        Self {
            root,
            shell: shell.to_owned(),
            stubs,
        }
    }

    /// A path inside the root.
    pub(crate) fn path(&self, guest: &str) -> PathBuf {
        self.root.join(guest.trim_start_matches('/'))
    }

    /// The file at `guest`, as text.
    pub(crate) fn read(&self, guest: &str) -> String {
        std::fs::read_to_string(self.path(guest)).unwrap_or_else(|e| panic!("{guest}: {e}"))
    }

    /// Lines of the stub call log.
    pub(crate) fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// PIDs the agent stub recorded, in start order.
    pub(crate) fn agent_pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.root.join("agent.pids"))
            .unwrap_or_default()
            .lines()
            .map(|l| l.parse().unwrap())
            .collect()
    }

    /// The command that runs the hook in this root, with `PATH` limited to the stubs and
    /// `/usr/bin:/bin` (so the host's own `sysctl` in `/usr/sbin` is never used).
    pub(crate) fn command(&self, args: &[String], path_with_stubs: bool) -> Command {
        let mut cmd = Command::new(&self.shell);
        let path = if path_with_stubs {
            format!("{}:/usr/bin:/bin", self.stubs.display())
        } else {
            "/usr/bin:/bin".to_owned()
        };
        cmd.arg(self.path("/puddle/boot.sh"))
            .args(args)
            .env_clear()
            .env("PATH", path)
            .env("PUDDLE_ROOT", &self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Runs the hook with `stdin` as the plan.
    pub(crate) fn run_raw(&self, stdin: &[u8], args: &[String], path_with_stubs: bool) -> Output {
        let mut child = self.command(args, path_with_stubs).spawn().unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

    /// Runs the hook with `plan` and its ENTRYPOINT args.
    pub(crate) fn run(&self, plan: &BootPlan) -> Output {
        let args: Vec<String> = plan
            .entrypoint()
            .map(<[String]>::to_vec)
            .unwrap_or_default();
        self.run_raw(&plan.render(), &args, true)
    }

    /// The PID recorded in a `"<boot id> <pid>"` file under `/run/puddle`.
    pub(crate) fn recorded_pid(&self, name: &str) -> Option<u32> {
        let text = std::fs::read_to_string(self.path(&format!("/run/puddle/{name}"))).ok()?;
        text.split_whitespace().nth(1)?.parse().ok()
    }

    /// Waits until `cond` holds, polling every 20 ms, up to `limit`.
    pub(crate) fn wait_for(limit: Duration, mut cond: impl FnMut() -> bool) -> Option<Duration> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if cond() {
                return Some(start.elapsed());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

/// Whether process `pid` is alive (and not a zombie).
pub(crate) fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|s| s.split_whitespace().nth(2).is_none_or(|st| st != "Z"))
}

/// Sends SIGKILL to `pid`.
pub(crate) fn kill9(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}

impl Drop for FakeRoot {
    fn drop(&mut self) {
        // Supervisor first, or it restarts the agent we kill next.
        for name in ["supervisor.pid", "entrypoint.pid"] {
            if let Some(pid) = self.recorded_pid(name) {
                kill9(pid);
            }
        }
        for pid in self.agent_pids() {
            kill9(pid);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Output as text, for assertion messages.
pub(crate) fn show(out: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
