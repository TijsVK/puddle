// SPDX-License-Identifier: GPL-3.0-or-later
//! The boot hook and the readiness gate (W1, T-108; design from T-028 §1.1).
//!
//! msb's `create()` and `start()` run no image workload, so puddle sets every sandbox up itself:
//! after every create, start and re-adoption it runs `guest/boot.sh` as root through exec, and it
//! serves no SSH and no exec to anyone until the hook returns 0.
//!
//! | Piece | What |
//! |---|---|
//! | [`BOOT_SH`], [`AGENT_SUPERVISE_SH`], [`write_assets`], [`with_boot_mounts`] | the guest scripts and the read-only mounts that carry them |
//! | [`BootPlan`] | what one run applies: provider [`puddle_types::GuestFile`]s and env, the image `PATH` fix, git settings, VS Code Machine settings, the agent, the image ENTRYPOINT |
//! | [`BootHook`] | create/start/adopt + hook run; a failed hook stops the sandbox and reports its stderr |
//! | [`Gate`], [`GatedSandbox`] | the readiness gate and the handle whose exec/SSH pass through it |
//!
//! What `boot.sh` does, in order: inotify limits and `kernel.unprivileged_bpf_disabled=1`
//! (every boot: the guest resets them); the plan's files (atomic, unchanged files detected, files
//! dropped from the plan removed); one include of `/etc/puddle/gitconfig` in `/etc/gitconfig`;
//! `update-ca-certificates` only when a file under `/usr/local/share/ca-certificates` changed;
//! provider steps (scripts the plan wrote, every boot); `puddle-agent` under a restarting supervisor, waiting until it listens; `boot.d/*.sh`
//! extension steps; the image ENTRYPOINT (+CMD) when the image declares one.
//!
//! ```
//! # tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
//! use puddle_boot::{BootHook, BootPlan, Gate, GateState};
//! use puddle_compute::fake::{ExecContext, FakeRuntime};
//! use puddle_compute::{ExecOutput, ExecRequest, FileMount, Runtime, SandboxSpec};
//! use puddle_types::{GuestPath, ImageRef, SandboxName};
//!
//! let rt = FakeRuntime::new();
//! // The fake can't run shell scripts: answer the hook's exec as boot.sh would.
//! fn fake_boot_sh(_: &mut ExecContext<'_>, r: &ExecRequest) -> Option<ExecOutput> {
//!     (r.args.first().map(String::as_str) == Some("/puddle/boot.sh"))
//!         .then(|| ExecOutput::new(0, "puddle-boot: ready\n", ""))
//! }
//! rt.on_exec(fake_boot_sh);
//! let image = ImageRef::new(FakeRuntime::DEBIAN).unwrap();
//! let config = rt.pull_image(&image).await.unwrap();
//! let plan = BootPlan::builder(&config).no_agent().build().unwrap();
//! let mounts = ["/puddle/boot.sh", "/puddle/agent-supervise.sh"]
//!     .map(|g| FileMount::read_only("unused", GuestPath::new(g).unwrap()));
//! let spec = puddle_boot::with_boot_mounts(
//!     SandboxSpec::new(SandboxName::new("demo").unwrap(), image),
//!     mounts.to_vec(),
//!     // Every plan merges VS Code's Machine settings, so the agent binary (the merge tool) is mounted.
//!     Some(std::path::Path::new("unused")),
//! );
//! let gate = Gate::new();
//! let sandbox = BootHook::new().create(&rt, spec, &plan, &gate).await.unwrap();
//! assert_eq!(gate.state(), GateState::Ready);
//! assert!(sandbox.exec(ExecRequest::sh("exit 0")).await.unwrap().status.success());
//! # });
//! ```
#![forbid(unsafe_code)]

mod assets;
mod gate;
mod hook;
mod machine;
mod plan;
mod quote;

pub use assets::{
    AGENT_GUEST, AGENT_SUPERVISE_GUEST, AGENT_SUPERVISE_SH, BOOT_SH, BOOT_SH_GUEST,
    MOUNT_DIR_GUEST, with_boot_mounts, write_assets,
};
pub use gate::{Gate, GateState, GatedError, GatedSandbox, NotReady};
pub use hook::{BootError, BootFailure, BootHook, BootReport, STDERR_LIMIT};
pub use machine::{MACHINE_SETTINGS_GUEST, machine_settings};
pub use plan::{
    AgentConfig, BootPlan, BootPlanBuilder, CA_DIR_GUEST, DEFAULT_AGENT_PORT, ENV_FILE_GUEST,
    GIT_CONFIG_GUEST, GitIdentity, PATH_FILE_GUEST, PLAN_HEADER, PlanError,
};
pub use puddle_types::ApplyKind;
