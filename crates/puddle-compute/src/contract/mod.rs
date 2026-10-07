// SPDX-License-Identifier: GPL-3.0-or-later
//! The contract suite: behaviour every [`Runtime`] must share, run against the fake (here, on
//! every push) and against the msb SDK adapter (`puddle-compute-msb`, on VMs). A difference
//! between the fake and msb shows up as a red case, not as a surprise in a later VM test
//! (feature `contract`).
//!
//! # Running it
//!
//! One test per case, named after the case:
//!
//! ```ignore
//! // tests/contract.rs of the crate that implements Runtime
//! async fn env() -> puddle_compute::contract::ContractEnv<MyRuntime> { /* ... */ }
//! puddle_compute::contract_tests!(env);
//! ```
//!
//! The macro expands to one `#[tokio::test(flavor = "multi_thread")]` per case (so the calling
//! crate needs `tokio` with `macros` and `rt-multi-thread`) plus a `CONTRACT_CASES` constant.
//! Name the file or module `vm_*` for VM runtimes so nextest runs the cases one at a time.
//! [`run_all`] runs every case in one call and returns a [`ContractReport`] instead.
//!
//! Each case names its sandboxes and volumes `<prefix>-<case number>-<tag>` and removes them
//! afterwards (also when it fails), so several runs can share one runtime as long as their
//! prefixes differ.
//!
//! # Cases and the smoke checks
//!
//! [`CASES`] lists the cases. [`SMOKE_CHECKS`] maps each of the 57 checks that passed in the
//! first SDK smoke runs on msb 0.7.6 to the case that covers it, or to the test file and test
//! elsewhere in the workspace that does; a unit test keeps the map complete and pointing at real
//! cases. The smoke runs' informational results (signal exit, second-attach leftover,
//! wrong-size leftover, image facts) and lifecycle runs (owner-handle drop, re-adoption) have
//! cases too.
//!
//! Cases marked *assumed* in [`CASE_NOTES`] pin behaviour that was not observed directly; the
//! first run against the SDK confirms or corrects them, together with the fake.

mod cases;

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use puddle_types::{ImageRef, SandboxName, VolumeName};

use crate::{Runtime, Sandbox};

/// Everything a case needs: the runtime under test and where it may put things.
#[derive(Debug)]
pub struct ContractEnv<R: Runtime> {
    /// The runtime under test.
    pub runtime: R,
    /// An image with `/bin/sh` and coreutils (`cat`, `tee`, `printenv`, `sleep`), e.g.
    /// `mcr.microsoft.com/devcontainers/base:debian`.
    pub image: ImageRef,
    /// Prefix for every sandbox and volume name: a DNS label of at most 20 characters, unique
    /// per run (see [`unique_prefix`]).
    pub prefix: String,
    /// A host directory for files the cases mount into guests (created if missing).
    pub host_dir: PathBuf,
}

impl<R: Runtime> ContractEnv<R> {
    /// An environment with a fresh [`unique_prefix`] and a host directory under the system temp
    /// dir.
    #[must_use]
    pub fn new(runtime: R, image: ImageRef) -> Self {
        let prefix = unique_prefix();
        let host_dir = std::env::temp_dir().join(format!("puddle-contract-{prefix}"));
        Self {
            runtime,
            image,
            prefix,
            host_dir,
        }
    }
}

/// `ct` plus the process id, the clock's nanoseconds and a per-process counter in base 36:
/// unique across parallel test processes on one host and across calls in one process.
#[must_use]
pub fn unique_prefix() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let count = COUNTER.fetch_add(1, Ordering::Relaxed) % 1296;
    format!(
        "ct{}{}{}",
        base36(u64::from(std::process::id())),
        base36(u64::from(nanos)),
        base36(u64::from(count)),
    )
}

fn base36(mut n: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        let digit = usize::try_from(n % 36).unwrap_or(0);
        out.push(DIGITS.get(digit).copied().unwrap_or(b'0'));
        n /= 36;
        if n == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// One case's view of the environment: names and host files scoped to the case.
pub struct Case<'a, R: Runtime> {
    env: &'a ContractEnv<R>,
    scope: String,
}

impl<R: Runtime> Case<'_, R> {
    /// The runtime under test.
    #[must_use]
    pub fn runtime(&self) -> &R {
        &self.env.runtime
    }

    /// The test image.
    #[must_use]
    pub fn image(&self) -> &ImageRef {
        &self.env.image
    }

    /// A sandbox name unique to this case.
    ///
    /// # Errors
    ///
    /// When the prefix makes the name invalid.
    pub fn sandbox(&self, tag: &str) -> Result<SandboxName, String> {
        SandboxName::new(&format!("{}-{tag}", self.scope)).map_err(|e| e.to_string())
    }

    /// A volume name unique to this case.
    ///
    /// # Errors
    ///
    /// When the prefix makes the name invalid.
    pub fn volume(&self, tag: &str) -> Result<VolumeName, String> {
        VolumeName::new(&format!("{}-{tag}", self.scope)).map_err(|e| e.to_string())
    }

    /// Writes `contents` to a host file unique to this case and returns its path.
    ///
    /// # Errors
    ///
    /// When the file can't be written.
    pub fn host_file(&self, tag: &str, contents: &[u8]) -> Result<PathBuf, String> {
        std::fs::create_dir_all(&self.env.host_dir).map_err(|e| e.to_string())?;
        let path = self.env.host_dir.join(format!("{}-{tag}", self.scope));
        std::fs::write(&path, contents).map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// A host endpoint for a vsock route: a named pipe path on Windows, a socket path elsewhere.
    #[must_use]
    pub fn route_endpoint(&self, tag: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\{}-{tag}", self.scope))
        } else {
            self.env.host_dir.join(format!("{}-{tag}.sock", self.scope))
        }
    }

    /// Removes every sandbox, stale directory and volume this case created, and its host
    /// files. Best effort: errors are ignored, since cleanup also runs after a failure.
    async fn cleanup(&self) {
        let rt = self.runtime();
        let mine = |name: &str| name.starts_with(&format!("{}-", self.scope));
        if let Ok(list) = rt.list().await {
            for info in list.into_iter().filter(|i| mine(&i.name)) {
                let Some(name) = info.sandbox_name() else {
                    continue;
                };
                if let Ok(handle) = rt.get(&name).await {
                    // Ignored: cleanup is best effort and the remove below reports nothing.
                    let _ = handle.stop().await;
                }
                let _ = rt.remove(&name).await;
            }
        }
        if let Ok(dirs) = rt.stale_dirs().await {
            for dir in dirs.iter().filter(|d| mine(d)) {
                if let Ok(name) = SandboxName::new(dir) {
                    let _ = rt.remove_stale_dir(&name).await;
                }
            }
        }
        if let Ok(volumes) = rt.list_volumes().await {
            for v in volumes.iter().filter(|v| mine(&v.name)) {
                if let Some(name) = v.volume_name() {
                    let _ = rt.remove_volume(&name).await;
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&self.env.host_dir) {
            for entry in entries.flatten() {
                if mine(&entry.file_name().to_string_lossy()) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// A failed case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractFailure {
    /// The case.
    pub case: String,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for ContractFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "contract case {} failed: {}", self.case, self.message)
    }
}

/// The result of [`run_all`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContractReport {
    /// Cases that passed.
    pub passed: Vec<String>,
    /// Cases that failed.
    pub failed: Vec<ContractFailure>,
}

impl ContractReport {
    /// Whether every case passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Runs case `name` (one of [`CASES`]) with its cleanup.
///
/// # Errors
///
/// [`ContractFailure`] when the case fails or `name` isn't a case.
pub async fn run_case<R: Runtime>(name: &str, env: &ContractEnv<R>) -> Result<(), ContractFailure> {
    let index = CASES
        .iter()
        .position(|c| *c == name)
        .ok_or_else(|| ContractFailure {
            case: name.to_owned(),
            message: "no such contract case".into(),
        })?;
    let case = Case {
        env,
        scope: format!("{}-{index}", env.prefix),
    };
    case.cleanup().await;
    let result = cases::dispatch(&case, name).await;
    case.cleanup().await;
    result.map_err(|message| ContractFailure {
        case: name.to_owned(),
        message,
    })
}

/// Runs every case in [`CASES`] order.
pub async fn run_all<R: Runtime>(env: &ContractEnv<R>) -> ContractReport {
    let mut report = ContractReport::default();
    for name in CASES {
        match run_case(name, env).await {
            Ok(()) => report.passed.push((*name).to_owned()),
            Err(failure) => report.failed.push(failure),
        }
    }
    report
}

/// Runs case `name` in a test: panics with the failure message. Used by
/// [`contract_tests!`](crate::contract_tests).
///
/// # Panics
///
/// When the case fails; that is how the test fails.
#[expect(
    clippy::panic,
    reason = "a panic is how a generated test reports its failure"
)]
pub async fn assert_case<R: Runtime>(name: &str, env: ContractEnv<R>) {
    if let Err(failure) = run_case(name, &env).await {
        panic!("{failure}");
    }
}

/// How long a case waits for a runtime call that should be quick before failing.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(180);

/// Where a smoke check is covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// By this contract case (on the fake and on every runtime).
    Case(&'static str),
    /// Outside this suite: by the named test in the named test file (a path under `crates/`).
    Elsewhere {
        /// The test file, such as `puddle-boot/tests/vm_boot.rs`.
        file: &'static str,
        /// What that test checks.
        test: &'static str,
    },
}

/// One of the 57 checks that passed in the SDK smoke runs, and where it is covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmokeCheck {
    /// The check's name in the smoke run's log.
    pub check: &'static str,
    /// Where it is covered.
    pub coverage: Coverage,
}

const fn case(check: &'static str, case: &'static str) -> SmokeCheck {
    SmokeCheck {
        check,
        coverage: Coverage::Case(case),
    }
}

const fn elsewhere(check: &'static str, file: &'static str, test: &'static str) -> SmokeCheck {
    SmokeCheck {
        check,
        coverage: Coverage::Elsewhere { file, test },
    }
}

/// Boot-hook checks the smoke run made after first boot (`boot1.*`) and after a restart
/// (`boot2.*`): the hook's effects, covered by the boot hook's VM tests.
const BOOT_HOOK_TEST: &str = "boot hook effects after create and after restart (K/W)";

const VM_BOOT: &str = "puddle-boot/tests/vm_boot.rs";
const VM_MSB: &str = "puddle-compute-msb/tests/vm_msb.rs";
const VM_WORKSPACE: &str = "puddle-workspace/tests/vm_workspace.rs";

/// Every check that passed in the SDK smoke runs, in log order.
pub const SMOKE_CHECKS: [SmokeCheck; 57] = [
    elsewhere(
        "runtime.bundled_pair",
        "puddle-runtime/tests/bundled.rs",
        "bundled msb + libkrunfw pair is the one used",
    ),
    case("runtime.version_pin", "probe_reports_runtime_version"),
    elsewhere(
        "runtime.private_home",
        "puddle-runtime/tests/isolation.rs",
        "private MSB_HOME, user's MSB_* ignored",
    ),
    case("volume.capacity_readback", "volume_capacity_reads_back"),
    case("sdk.create_owned", "create_boots_and_returns_owning_handle"),
    elsewhere("boot.hook_rc", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.sysctl_inotify_watches", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.sysctl_inotify_instances", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.unpriv_bpf_off", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.git_fsync", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.git_identity", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot1.path_fix_login_shell", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere(
        "boot1.proxy_env_login_shell",
        "puddle-vm-tests/tests/vm_guest_env.rs",
        "proxy env visible in login shells",
    ),
    elsewhere(
        "boot1.ca_in_bundle",
        "puddle-vm-tests/tests/vm_root_sync.rs",
        "synced roots in the guest bundle",
    ),
    elsewhere(
        "boot1.ca_env_node",
        "puddle-vm-tests/tests/vm_root_sync.rs",
        "NODE_EXTRA_CA_CERTS points at the bundle",
    ),
    elsewhere("boot1.agent_listening", VM_BOOT, BOOT_HOOK_TEST),
    case("exec.exit0", "exec_exit_codes_are_exact"),
    case("exec.exit3", "exec_exit_codes_are_exact"),
    case("exec.exit127", "exec_exit_codes_are_exact"),
    case("env.create_env_in_exec", "create_env_reaches_exec"),
    elsewhere(
        "net.proxy_allowed_github",
        "puddle-e2e/tests/proxy_agent_store.rs",
        "allowed host reachable through the route",
    ),
    elsewhere(
        "net.proxy_denied_example",
        "puddle-e2e/tests/proxy_agent_store.rs",
        "denied host gets 403 through the route",
    ),
    elsewhere(
        "net.direct_egress_blocked",
        VM_MSB,
        "direct DNS fails in the guest",
    ),
    elsewhere(
        "net.direct_ip_blocked",
        VM_MSB,
        "direct IP fails in the guest",
    ),
    elsewhere(
        "net.unrouted_vsock_port_unreachable",
        VM_MSB,
        "only routed vsock ports accept",
    ),
    case("mount_file.readonly", "file_mount_is_read_only"),
    elsewhere("volume.ext4", VM_MSB, "named volume is ext4 in the guest"),
    elsewhere("owned_disk.ext4", VM_MSB, "owned disk is ext4 in the guest"),
    case(
        "volume.write_repo",
        "named_volume_survives_restart_and_remove",
    ),
    case("owned_disk.write", "owned_disk_survives_restart_not_remove"),
    elsewhere(
        "agent.restarted_after_kill",
        VM_BOOT,
        "agent back within 1 s after kill -9",
    ),
    elsewhere(
        "agent.proxy_after_restart",
        VM_BOOT,
        "agent proxies again after a restart",
    ),
    case("ssh.serve_connection_exec", "ssh_server_speaks_first"),
    case("sdk.list", "create_boots_and_returns_owning_handle"),
    case("sdk.stopped_status", "stop_then_start_boots_again"),
    elsewhere("restart.boot_hook_rc", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.sysctl_inotify_watches", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.sysctl_inotify_instances", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.unpriv_bpf_off", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.git_fsync", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.git_identity", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere("boot2.path_fix_login_shell", VM_BOOT, BOOT_HOOK_TEST),
    elsewhere(
        "boot2.proxy_env_login_shell",
        "puddle-vm-tests/tests/vm_guest_env.rs",
        "proxy env visible in login shells",
    ),
    elsewhere(
        "boot2.ca_in_bundle",
        "puddle-vm-tests/tests/vm_root_sync.rs",
        "synced roots in the guest bundle",
    ),
    elsewhere(
        "boot2.ca_env_node",
        "puddle-vm-tests/tests/vm_root_sync.rs",
        "NODE_EXTRA_CA_CERTS points at the bundle",
    ),
    elsewhere("boot2.agent_listening", VM_BOOT, BOOT_HOOK_TEST),
    case(
        "restart.volume_marker",
        "named_volume_survives_restart_and_remove",
    ),
    case(
        "restart.owned_disk_kept",
        "owned_disk_survives_restart_not_remove",
    ),
    case(
        "volume.second_attach_refused",
        "second_attach_is_refused_naming_the_holder",
    ),
    case(
        "sdk.removed",
        "remove_needs_a_stopped_sandbox_and_frees_the_name",
    ),
    case(
        "owned_disk.gone_with_sandbox",
        "owned_disk_survives_restart_not_remove",
    ),
    case(
        "volume.survives_remove",
        "named_volume_survives_restart_and_remove",
    ),
    case(
        "volume.reattach_plain_named",
        "named_volume_survives_restart_and_remove",
    ),
    elsewhere("recreate.boot_hook_rc", VM_BOOT, BOOT_HOOK_TEST),
    case(
        "recreate.volume_marker",
        "named_volume_survives_restart_and_remove",
    ),
    elsewhere(
        "recreate.repo_head",
        VM_WORKSPACE,
        "clone, stop, recreate: HEAD and marker intact",
    ),
    elsewhere(
        "recreate.repo_fsck",
        VM_WORKSPACE,
        "git fsck clean after recreate and after VMM kill",
    ),
];

pub use cases::{CASE_NOTES, CASES};

/// Expands to one test per contract case for the runtime built by `$env`, an `async fn() ->
/// ContractEnv<R>` (or any path callable like one), plus `CONTRACT_CASES`, the list the macro
/// covered (compare it with [`contract::CASES`](crate::contract::CASES) in a test).
///
/// Needs `tokio` with `macros` and `rt-multi-thread` in the calling crate.
#[macro_export]
macro_rules! contract_tests {
    ($env:path) => {
        $crate::contract_tests!(@cases $env;
            probe_reports_runtime_version,
            pull_image_returns_its_config,
            unknown_image_fails_create_cleanly,
            create_boots_and_returns_owning_handle,
            create_refuses_a_taken_name,
            invalid_spec_is_refused_before_anything_exists,
            stop_then_start_boots_again,
            dropping_the_owning_handle_stops_the_vm,
            get_readopts_a_running_sandbox_without_owning_it,
            unknown_names_are_not_found,
            remove_needs_a_stopped_sandbox_and_frees_the_name,
            exec_exit_codes_are_exact,
            signal_killed_exec_is_a_failure,
            exec_timeout_is_enforced,
            exec_needs_a_running_sandbox,
            create_env_reaches_exec,
            stdin_reaches_exec,
            file_mount_is_read_only,
            root_disk_survives_restart_not_remove,
            owned_disk_survives_restart_not_remove,
            named_volume_survives_restart_and_remove,
            volume_capacity_reads_back,
            second_attach_is_refused_naming_the_holder,
            failed_create_leaves_a_stale_dir_unless_fixed,
            missing_volume_fails_create,
            ssh_server_speaks_first,
            routes_and_no_network_are_accepted,
            memory_change_applies_at_next_start,
        );
    };
    (@cases $env:path; $($case:ident),* $(,)?) => {
        /// The contract cases this expansion runs.
        pub const CONTRACT_CASES: &[&str] = &[$(stringify!($case)),*];
        $(
            #[::tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $case() {
                $crate::contract::assert_case(stringify!($case), $env().await).await;
            }
        )*
    };
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn smoke_map_is_complete_and_points_at_real_cases() {
        let checks: BTreeSet<_> = SMOKE_CHECKS.iter().map(|c| c.check).collect();
        assert_eq!(checks.len(), 57, "a check is listed twice");
        for c in &SMOKE_CHECKS {
            match c.coverage {
                Coverage::Case(name) => {
                    assert!(CASES.contains(&name), "{}: no case {name}", c.check);
                }
                Coverage::Elsewhere { file, test } => {
                    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("..")
                        .join(file);
                    assert!(path.is_file(), "{}: no file {file}", c.check);
                    assert!(!test.is_empty(), "{}: no description", c.check);
                }
            }
        }
    }

    #[test]
    fn every_case_has_a_note_and_a_unique_name() {
        let names: BTreeSet<_> = CASES.iter().collect();
        assert_eq!(names.len(), CASES.len());
        assert_eq!(CASE_NOTES.len(), CASES.len());
        for (case, note) in CASES.iter().zip(CASE_NOTES.iter()) {
            assert_eq!(*case, note.0, "CASE_NOTES order differs from CASES");
            assert_ne!(note.1, "");
        }
    }

    #[test]
    fn prefixes_are_short_dns_labels() {
        let p = unique_prefix();
        assert!(p.len() <= 20, "{p}");
        assert!(SandboxName::new(&format!("{p}-26-second")).is_ok(), "{p}");
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(36), "10");
    }

    #[test]
    fn failure_display_names_the_case() {
        let f = ContractFailure {
            case: "x".into(),
            message: "boom".into(),
        };
        assert_eq!(f.to_string(), "contract case x failed: boom");
        let mut r = ContractReport::default();
        assert!(r.all_passed());
        r.failed.push(f);
        assert!(!r.all_passed());
    }
}
