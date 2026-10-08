// SPDX-License-Identifier: GPL-3.0-or-later
//! [`FakeRuntime`]: an in-memory [`Runtime`] that behaves like msb as observed on msb 0.7.6, for
//! unit tests of everything above the compute plane (feature `fake`).
//!
//! What it reproduces (each pinned by a case in [`crate::contract`]):
//!
//! - `create` boots the sandbox and returns an owning handle; dropping it without `stop` leaves
//!   the sandbox `Stopped`, as msb 0.7.7 does (0.7.6 said `Crashed`). `get`
//!   re-adopts a running sandbox without owning it.
//! - Exit codes come through exactly; a signal-killed command reports `-1`.
//! - File mounts are read-only (`tee` reports `Read-only file system`).
//! - Root disk and owned disks survive stop/start and die with `remove`; named volumes survive
//!   `remove` and reattach with a plain `named()` mount.
//! - A second attach of a volume held by a running sandbox is refused naming the holder, and
//!   leaves the refused sandbox behind as a `Stopped` record.
//! - A create that fails its volume check (missing volume, size mismatch) leaves a stale
//!   directory that blocks the name, unless [`FakeConfig::stale_dir_fixed`] (an upstream msb bug).
//! - The SSH server writes an `SSH-2.0-` identification line first.
//! - Every boot writes `/proc/meminfo` with `MemTotal` = the spec's memory, so a
//!   [`Runtime::set_memory`] shows only after the next start.
//!
//! Test controls: [`FakeRuntime::inject`] makes the next matching call(s) fail
//! ([`Fault`]), [`FakeRuntime::calls`] returns every call in order, [`FakeRuntime::on_exec`]
//! adds command handlers, [`FakeRuntime::crash`] kills a VM, [`FakeRuntime::add_image`] adds
//! pullable images.
//!
//! ```
//! # tokio_test_block_on(async {
//! use puddle_compute::fake::{FakeRuntime, Fault, Op};
//! use puddle_compute::{ComputeError, ExecRequest, Runtime, Sandbox, SandboxSpec};
//! use puddle_types::{ImageRef, SandboxName};
//!
//! let rt = FakeRuntime::new();
//! let spec = SandboxSpec::new(SandboxName::new("demo").unwrap(), ImageRef::new(FakeRuntime::DEBIAN).unwrap());
//! let sb = rt.create(spec).await.unwrap();
//! assert_eq!(sb.exec(ExecRequest::sh("exit 3")).await.unwrap().status.code, 3);
//!
//! rt.inject(Op::Stop, Fault::once(ComputeError::Runtime { op: "stop", message: "injected".into() }));
//! assert!(sb.stop().await.is_err());
//! sb.stop().await.unwrap();
//! # });
//! # fn tokio_test_block_on<F: std::future::Future>(f: F) -> F::Output {
//! #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
//! # }
//! ```

mod exec;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use puddle_types::{ImageRef, MemoryMib, SandboxName, VolumeName, WorkspaceStatus};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use self::exec::{ExecContext, ExecHandler, FsError};
use self::exec::{Files, builtin};
use crate::{
    Capabilities, ComputeError, DiskSize, ExecOutput, ExecRequest, ImageConfig, Runtime, Sandbox,
    SandboxInfo, SandboxSpec, SshStream, VolumeInfo, VolumeSpec,
};

/// The identification line the fake SSH server sends.
pub const SSH_BANNER: &str = "SSH-2.0-puddle_fake\r\n";

/// Every operation of the [`Runtime`] and [`Sandbox`] traits, for [`FakeRuntime::inject`] and
/// [`FakeRuntime::calls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Op {
    /// [`Runtime::probe`].
    Probe,
    /// [`Runtime::pull_image`].
    PullImage,
    /// [`Runtime::create`].
    Create,
    /// [`Runtime::start`].
    Start,
    /// [`Runtime::get`].
    Get,
    /// [`Runtime::set_memory`].
    SetMemory,
    /// [`Runtime::list`].
    List,
    /// [`Runtime::remove`].
    Remove,
    /// [`Runtime::stale_dirs`].
    StaleDirs,
    /// [`Runtime::remove_stale_dir`].
    RemoveStaleDir,
    /// [`Runtime::create_volume`].
    CreateVolume,
    /// [`Runtime::volume`].
    Volume,
    /// [`Runtime::list_volumes`].
    ListVolumes,
    /// [`Runtime::remove_volume`].
    RemoveVolume,
    /// [`Sandbox::status`].
    Status,
    /// [`Sandbox::stop`].
    Stop,
    /// [`Sandbox::exec`].
    Exec,
    /// [`Sandbox::serve_ssh`].
    ServeSsh,
}

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The operation.
    pub op: Op,
    /// The sandbox, volume or image it was about, if any.
    pub target: Option<String>,
    /// For [`Op::Exec`]: the program and its arguments, space-separated.
    pub detail: Option<String>,
}

/// A failure to inject: which error, for which target, how many calls to let through first and
/// how many to fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    error: ComputeError,
    target: Option<String>,
    skip: u32,
    remaining: Option<u32>,
}

impl Fault {
    /// Fails the next matching call with `error`.
    #[must_use]
    pub fn once(error: ComputeError) -> Self {
        Self {
            error,
            target: None,
            skip: 0,
            remaining: Some(1),
        }
    }

    /// Fails every matching call with `error` until [`FakeRuntime::clear_faults`].
    #[must_use]
    pub fn always(error: ComputeError) -> Self {
        Self {
            remaining: None,
            ..Self::once(error)
        }
    }

    /// Lets `n` matching calls succeed first.
    #[must_use]
    pub fn after(mut self, n: u32) -> Self {
        self.skip = n;
        self
    }

    /// Fails `n` matching calls (instead of one).
    #[must_use]
    pub fn times(mut self, n: u32) -> Self {
        self.remaining = Some(n);
        self
    }

    /// Only matches calls about this sandbox, volume or image.
    #[must_use]
    pub fn only_for(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

/// How the fake behaves where msb versions differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeConfig {
    /// Reported by [`Runtime::probe`].
    pub runtime_version: String,
    /// When `true`, a failed create leaves no stale directory (the upstream msb bug fixed).
    pub stale_dir_fixed: bool,
    /// Reported by [`Runtime::probe`]; the fake's SSH server runs no commands either way.
    pub ssh_reports_signal_exit: bool,
}

impl Default for FakeConfig {
    /// msb 0.7.6 as observed: stale directories, signal exit lost over SSH.
    fn default() -> Self {
        Self {
            runtime_version: "fake".into(),
            stale_dir_fixed: false,
            ssh_reports_signal_exit: false,
        }
    }
}

pub(crate) struct VolumeRecord {
    size: DiskSize,
    files: Files,
}

struct SandboxRecord {
    spec: SandboxSpec,
    status: WorkspaceStatus,
    boot: u64,
    files: Files,
}

impl SandboxRecord {
    /// The guest's view of its memory at boot, like the kernel's `/proc/meminfo`.
    fn boot(&mut self, boot: u64) {
        self.status = WorkspaceStatus::Running;
        self.boot = boot;
        let kib = u64::from(self.spec.memory.get()) * 1024;
        self.files.insert(
            MEMINFO.to_owned(),
            format!("MemTotal:       {kib} kB\n").into_bytes(),
        );
    }
}

/// Where the fake writes `MemTotal` at every boot.
const MEMINFO: &str = "/proc/meminfo";

#[derive(Default)]
struct State {
    images: BTreeMap<String, ImageConfig>,
    sandboxes: BTreeMap<String, SandboxRecord>,
    /// Sandboxes puddle didn't create ([`FakeRuntime::add_foreign_sandbox`]): listed only.
    foreign: BTreeMap<String, WorkspaceStatus>,
    stale_dirs: BTreeSet<String>,
    volumes: BTreeMap<String, VolumeRecord>,
    faults: Vec<(Op, Fault)>,
    calls: Vec<Call>,
    handlers: Vec<Arc<dyn ExecHandler>>,
    boots: u64,
}

impl State {
    /// Records the call, then fires the first matching fault, if any.
    fn enter(
        &mut self,
        op: Op,
        target: Option<&str>,
        detail: Option<String>,
    ) -> Result<(), ComputeError> {
        self.calls.push(Call {
            op,
            target: target.map(str::to_owned),
            detail,
        });
        let hit = self.faults.iter_mut().position(|(fop, f)| {
            *fop == op && (f.target.is_none() || f.target.as_deref() == target)
        });
        let Some(i) = hit else { return Ok(()) };
        let Some((_, fault)) = self.faults.get_mut(i) else {
            return Ok(());
        };
        if fault.skip > 0 {
            fault.skip -= 1;
            return Ok(());
        }
        let error = fault.error.clone();
        match &mut fault.remaining {
            Some(1) => {
                self.faults.remove(i);
            }
            Some(n) => *n -= 1,
            None => {}
        }
        Err(error)
    }

    fn holder_of(&self, volume: &str) -> Option<String> {
        self.sandboxes
            .iter()
            .find(|(_, r)| {
                r.status == WorkspaceStatus::Running
                    && r.spec.volumes.iter().any(|m| m.volume.as_str() == volume)
            })
            .map(|(name, _)| name.clone())
    }

    fn volume_info(&self, name: &str, v: &VolumeRecord) -> VolumeInfo {
        VolumeInfo {
            name: name.to_owned(),
            size: v.size,
            holder: self.holder_of(name),
        }
    }

    /// The holder check every boot runs: a volume attached to another running sandbox.
    fn check_holders(&self, spec: &SandboxSpec) -> Result<(), ComputeError> {
        for m in &spec.volumes {
            if let Some(holder) = self.holder_of(m.volume.as_str())
                && holder != spec.name.as_str()
            {
                return Err(ComputeError::VolumeInUse {
                    volume: m.volume.to_string(),
                    holder,
                });
            }
        }
        Ok(())
    }

    fn next_boot(&mut self) -> u64 {
        self.boots += 1;
        self.boots
    }
}

struct Inner {
    config: FakeConfig,
    state: Mutex<State>,
}

/// An in-memory msb. Cloning gives another handle to the same fake, so a test can keep one for
/// [`FakeRuntime::inject`] while code under test owns another.
#[derive(Clone)]
pub struct FakeRuntime {
    inner: Arc<Inner>,
}

impl Default for FakeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FakeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeRuntime")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl FakeRuntime {
    /// `mcr.microsoft.com/devcontainers/base:debian`: no ENTRYPOINT, CMD `bash`.
    pub const DEBIAN: &'static str = "mcr.microsoft.com/devcontainers/base:debian";
    /// `docker:dind`: ENTRYPOINT `dockerd-entrypoint.sh`.
    pub const DIND: &'static str = "docker:dind";
    /// `alpine:3`: CMD `/bin/sh`.
    pub const ALPINE: &'static str = "alpine:3";

    /// A fake with [`FakeConfig::default`] (msb 0.7.6 behaviour).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FakeConfig::default())
    }

    /// A fake with `config`. Knows the images [`FakeRuntime::DEBIAN`], [`FakeRuntime::DIND`]
    /// and [`FakeRuntime::ALPINE`].
    #[must_use]
    pub fn with_config(config: FakeConfig) -> Self {
        let path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        let mut state = State::default();
        let image = |entrypoint: &[&str], cmd: &[&str]| ImageConfig {
            entrypoint: entrypoint.iter().map(|s| (*s).to_owned()).collect(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            env: vec![("PATH".into(), path.into())],
            ..ImageConfig::default()
        };
        state
            .images
            .insert(Self::DEBIAN.into(), image(&[], &["bash"]));
        state
            .images
            .insert(Self::DIND.into(), image(&["dockerd-entrypoint.sh"], &[]));
        state
            .images
            .insert(Self::ALPINE.into(), image(&[], &["/bin/sh"]));
        Self {
            inner: Arc::new(Inner {
                config,
                state: Mutex::new(state),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `image` pullable with `config`.
    pub fn add_image(&self, image: &ImageRef, config: ImageConfig) {
        self.lock().images.insert(image.to_string(), config);
    }

    /// Arms `fault` for calls of `op`. Faults are checked in the order they were added; the
    /// first one that matches the call decides.
    pub fn inject(&self, op: Op, fault: Fault) {
        self.lock().faults.push((op, fault));
    }

    /// Disarms every fault.
    pub fn clear_faults(&self) {
        self.lock().faults.clear();
    }

    /// Every call so far, in order (including failed ones).
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// Adds a command handler, tried before earlier handlers and before the built-ins.
    pub fn on_exec(&self, handler: impl ExecHandler) {
        self.lock().handlers.insert(0, Arc::new(handler));
    }

    /// Simulates the VM dying: a running sandbox becomes `Crashed`. Returns whether it was
    /// running.
    #[must_use = "false means the sandbox wasn't running"]
    pub fn crash(&self, name: &SandboxName) -> bool {
        let mut state = self.lock();
        match state.sandboxes.get_mut(name.as_str()) {
            Some(r) if r.status == WorkspaceStatus::Running => {
                r.status = WorkspaceStatus::Crashed;
                true
            }
            _ => false,
        }
    }

    /// Simulates a VM that outlives its dead owner: the sandbox runs, whatever its handle's
    /// drop did (dropping a handle stops the fake VM, as in the SDK, but a killed process never
    /// gets to drop it). Returns whether the sandbox exists.
    #[must_use = "false means there is no such sandbox"]
    pub fn outlive_owner(&self, name: &SandboxName) -> bool {
        let mut state = self.lock();
        match state.sandboxes.get_mut(name.as_str()) {
            Some(r) => {
                r.status = WorkspaceStatus::Running;
                true
            }
            None => false,
        }
    }

    /// Adds a sandbox puddle didn't create (another tool's, or one without puddle's owner label).
    /// [`Runtime::list`] shows it with `puddle_owned: false`; no other operation sees it, so a
    /// test can check through [`FakeRuntime::calls`] that nothing touched it. `name` need not be
    /// a valid [`SandboxName`].
    pub fn add_foreign_sandbox(&self, name: &str, status: WorkspaceStatus) {
        self.lock().foreign.insert(name.to_owned(), status);
    }

    /// Adds a sandbox directory without a record, as a failed create leaves it or as
    /// another tool might; `name` need not be a valid [`SandboxName`].
    pub fn add_stale_dir(&self, name: &str) {
        self.lock().stale_dirs.insert(name.to_owned());
    }

    /// Adds an empty volume under any name, including names that aren't a valid [`VolumeName`]
    /// (another tool's volume).
    pub fn add_foreign_volume(&self, name: &str, size: DiskSize) {
        self.lock().volumes.insert(
            name.to_owned(),
            VolumeRecord {
                size,
                files: Files::new(),
            },
        );
    }

    fn handle(&self, name: &SandboxName, boot: u64, owned: bool) -> FakeSandbox {
        FakeSandbox {
            runtime: self.clone(),
            name: name.clone(),
            boot,
            owned,
        }
    }

    /// Marks a failed create's leftover directory, as msb does until the upstream bug is fixed.
    fn leave_stale_dir(&self, state: &mut State, name: &SandboxName) {
        if !self.inner.config.stale_dir_fixed {
            state.stale_dirs.insert(name.to_string());
        }
    }
}

impl Runtime for FakeRuntime {
    type Sandbox = FakeSandbox;

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn probe(&self) -> Result<Capabilities, ComputeError> {
        self.lock().enter(Op::Probe, None, None)?;
        let c = &self.inner.config;
        Ok(Capabilities {
            runtime_version: c.runtime_version.clone(),
            stale_dir_fixed: c.stale_dir_fixed,
            ssh_reports_signal_exit: c.ssh_reports_signal_exit,
        })
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn pull_image(&self, image: &ImageRef) -> Result<ImageConfig, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::PullImage, Some(image.as_str()), None)?;
        state
            .images
            .get(image.as_str())
            .cloned()
            .ok_or_else(|| ComputeError::ImagePull {
                image: image.to_string(),
                reason: "manifest unknown".into(),
            })
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn create(&self, spec: SandboxSpec) -> Result<FakeSandbox, ComputeError> {
        let mut state = self.lock();
        let name = spec.name.clone();
        state.enter(Op::Create, Some(name.as_str()), None)?;
        spec.validate()?;
        if state.sandboxes.contains_key(name.as_str()) {
            return Err(ComputeError::AlreadyExists {
                sandbox: name.to_string(),
            });
        }
        if state.stale_dirs.contains(name.as_str()) {
            return Err(ComputeError::StaleDir {
                sandbox: name.to_string(),
            });
        }
        if !state.images.contains_key(spec.image.as_str()) {
            return Err(ComputeError::ImagePull {
                image: spec.image.to_string(),
                reason: "manifest unknown".into(),
            });
        }
        for m in &spec.volumes {
            let failure = match (state.volumes.get(m.volume.as_str()), m.ensure_size) {
                (None, None) => Some(ComputeError::VolumeNotFound {
                    volume: m.volume.to_string(),
                }),
                (Some(v), Some(want)) if v.size != want => Some(ComputeError::VolumeSizeMismatch {
                    volume: m.volume.to_string(),
                    existing_mib: v.size.as_mib(),
                    requested_mib: want.as_mib(),
                }),
                _ => None,
            };
            if let Some(e) = failure {
                self.leave_stale_dir(&mut state, &name);
                return Err(e);
            }
        }
        if let Err(e) = state.check_holders(&spec) {
            // msb records the sandbox before the VMM refuses the disk.
            state.sandboxes.insert(
                name.to_string(),
                SandboxRecord {
                    spec,
                    status: WorkspaceStatus::Stopped,
                    boot: 0,
                    files: Files::new(),
                },
            );
            return Err(e);
        }
        for m in &spec.volumes {
            if let Some(size) = m.ensure_size {
                state
                    .volumes
                    .entry(m.volume.to_string())
                    .or_insert_with(|| VolumeRecord {
                        size,
                        files: Files::new(),
                    });
            }
        }
        let boot = state.next_boot();
        let mut record = SandboxRecord {
            spec,
            status: WorkspaceStatus::Created,
            boot: 0,
            files: Files::new(),
        };
        record.boot(boot);
        state.sandboxes.insert(name.to_string(), record);
        Ok(self.handle(&name, boot, true))
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn start(&self, name: &SandboxName) -> Result<FakeSandbox, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::Start, Some(name.as_str()), None)?;
        let record = state
            .sandboxes
            .get(name.as_str())
            .ok_or_else(|| ComputeError::NotFound {
                sandbox: name.to_string(),
            })?;
        if !record.status.is_down() {
            return Err(ComputeError::InvalidState {
                sandbox: name.to_string(),
                op: "start",
                status: record.status,
            });
        }
        if let Some(m) = record
            .spec
            .volumes
            .iter()
            .find(|m| !state.volumes.contains_key(m.volume.as_str()))
        {
            return Err(ComputeError::VolumeNotFound {
                volume: m.volume.to_string(),
            });
        }
        state.check_holders(&record.spec)?;
        let boot = state.next_boot();
        if let Some(r) = state.sandboxes.get_mut(name.as_str()) {
            r.boot(boot);
        }
        Ok(self.handle(name, boot, true))
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn get(&self, name: &SandboxName) -> Result<FakeSandbox, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::Get, Some(name.as_str()), None)?;
        match state.sandboxes.get(name.as_str()) {
            None => Err(ComputeError::NotFound {
                sandbox: name.to_string(),
            }),
            Some(r) if r.status != WorkspaceStatus::Running => Err(ComputeError::InvalidState {
                sandbox: name.to_string(),
                op: "connect to",
                status: r.status,
            }),
            Some(r) => Ok(self.handle(name, r.boot, false)),
        }
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn set_memory(&self, name: &SandboxName, memory: MemoryMib) -> Result<(), ComputeError> {
        let mut state = self.lock();
        state.enter(Op::SetMemory, Some(name.as_str()), None)?;
        let record =
            state
                .sandboxes
                .get_mut(name.as_str())
                .ok_or_else(|| ComputeError::NotFound {
                    sandbox: name.to_string(),
                })?;
        record.spec.memory = memory;
        Ok(())
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn list(&self) -> Result<Vec<SandboxInfo>, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::List, None, None)?;
        let mut out: Vec<SandboxInfo> = state
            .sandboxes
            .iter()
            .map(|(name, r)| SandboxInfo {
                name: name.clone(),
                status: r.status,
                puddle_owned: true,
            })
            .chain(state.foreign.iter().map(|(name, status)| SandboxInfo {
                name: name.clone(),
                status: *status,
                puddle_owned: false,
            }))
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn remove(&self, name: &SandboxName) -> Result<(), ComputeError> {
        let mut state = self.lock();
        state.enter(Op::Remove, Some(name.as_str()), None)?;
        match state.sandboxes.get(name.as_str()) {
            None => Err(ComputeError::NotFound {
                sandbox: name.to_string(),
            }),
            Some(r) if !r.status.is_down() => Err(ComputeError::InvalidState {
                sandbox: name.to_string(),
                op: "remove",
                status: r.status,
            }),
            Some(_) => {
                state.sandboxes.remove(name.as_str());
                Ok(())
            }
        }
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn stale_dirs(&self) -> Result<Vec<String>, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::StaleDirs, None, None)?;
        Ok(state.stale_dirs.iter().cloned().collect())
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn remove_stale_dir(&self, name: &SandboxName) -> Result<(), ComputeError> {
        let mut state = self.lock();
        state.enter(Op::RemoveStaleDir, Some(name.as_str()), None)?;
        if state.stale_dirs.remove(name.as_str()) {
            Ok(())
        } else {
            Err(ComputeError::NotFound {
                sandbox: name.to_string(),
            })
        }
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn create_volume(&self, spec: VolumeSpec) -> Result<VolumeInfo, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::CreateVolume, Some(spec.name.as_str()), None)?;
        if spec.size.as_mib() == 0 {
            return Err(ComputeError::InvalidSpec {
                reason: format!("volume {:?} has size 0", spec.name.as_str()),
            });
        }
        if state.volumes.contains_key(spec.name.as_str()) {
            return Err(ComputeError::VolumeExists {
                volume: spec.name.to_string(),
            });
        }
        let record = VolumeRecord {
            size: spec.size,
            files: Files::new(),
        };
        let info = state.volume_info(spec.name.as_str(), &record);
        state.volumes.insert(spec.name.to_string(), record);
        Ok(info)
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn volume(&self, name: &VolumeName) -> Result<Option<VolumeInfo>, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::Volume, Some(name.as_str()), None)?;
        Ok(state
            .volumes
            .get(name.as_str())
            .map(|v| state.volume_info(name.as_str(), v)))
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn list_volumes(&self) -> Result<Vec<VolumeInfo>, ComputeError> {
        let mut state = self.lock();
        state.enter(Op::ListVolumes, None, None)?;
        Ok(state
            .volumes
            .iter()
            .map(|(name, v)| state.volume_info(name, v))
            .collect())
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn remove_volume(&self, name: &VolumeName) -> Result<(), ComputeError> {
        let mut state = self.lock();
        state.enter(Op::RemoveVolume, Some(name.as_str()), None)?;
        if !state.volumes.contains_key(name.as_str()) {
            return Err(ComputeError::VolumeNotFound {
                volume: name.to_string(),
            });
        }
        if let Some(holder) = state.holder_of(name.as_str()) {
            return Err(ComputeError::VolumeInUse {
                volume: name.to_string(),
                holder,
            });
        }
        state.volumes.remove(name.as_str());
        Ok(())
    }
}

/// A handle to a sandbox in a [`FakeRuntime`].
#[derive(Debug)]
pub struct FakeSandbox {
    runtime: FakeRuntime,
    name: SandboxName,
    boot: u64,
    owned: bool,
}

impl FakeSandbox {
    /// Checks that this handle's boot is the running one, for exec and SSH.
    fn check_running(&self, state: &State, op: &'static str) -> Result<(), ComputeError> {
        let r = state
            .sandboxes
            .get(self.name.as_str())
            .ok_or_else(|| ComputeError::NotFound {
                sandbox: self.name.to_string(),
            })?;
        if r.status != WorkspaceStatus::Running {
            return Err(ComputeError::InvalidState {
                sandbox: self.name.to_string(),
                op,
                status: r.status,
            });
        }
        if r.boot != self.boot {
            return Err(ComputeError::StaleHandle {
                sandbox: self.name.to_string(),
            });
        }
        Ok(())
    }

    fn run(&self, state: &mut State, request: &ExecRequest) -> Result<ExecOutput, ComputeError> {
        let handlers = state.handlers.clone();
        let State {
            sandboxes, volumes, ..
        } = state;
        let record =
            sandboxes
                .get_mut(self.name.as_str())
                .ok_or_else(|| ComputeError::NotFound {
                    sandbox: self.name.to_string(),
                })?;
        let mut env = record.spec.env.clone();
        env.extend(&request.env);
        let mut ctx = ExecContext {
            sandbox: &self.name,
            env,
            spec: &record.spec,
            root: &mut record.files,
            volumes,
        };
        if let Some(output) = handlers.iter().find_map(|h| h.handle(&mut ctx, request)) {
            return Ok(output);
        }
        builtin(&mut ctx, request)
    }
}

impl Sandbox for FakeSandbox {
    fn name(&self) -> &SandboxName {
        &self.name
    }

    fn owns_lifecycle(&self) -> bool {
        self.owned
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn status(&self) -> Result<WorkspaceStatus, ComputeError> {
        let mut state = self.runtime.lock();
        state.enter(Op::Status, Some(self.name.as_str()), None)?;
        state
            .sandboxes
            .get(self.name.as_str())
            .map(|r| r.status)
            .ok_or_else(|| ComputeError::NotFound {
                sandbox: self.name.to_string(),
            })
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn stop(&self) -> Result<(), ComputeError> {
        let mut state = self.runtime.lock();
        state.enter(Op::Stop, Some(self.name.as_str()), None)?;
        let r =
            state
                .sandboxes
                .get_mut(self.name.as_str())
                .ok_or_else(|| ComputeError::NotFound {
                    sandbox: self.name.to_string(),
                })?;
        if r.status.is_down() {
            return Ok(());
        }
        if r.boot != self.boot {
            return Err(ComputeError::StaleHandle {
                sandbox: self.name.to_string(),
            });
        }
        r.status = WorkspaceStatus::Stopped;
        Ok(())
    }

    #[expect(clippy::unused_async_trait_impl, reason = "the fake answers at once")]
    async fn exec(&self, request: ExecRequest) -> Result<ExecOutput, ComputeError> {
        let mut state = self.runtime.lock();
        let detail = std::iter::once(request.program.as_str())
            .chain(request.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        state.enter(Op::Exec, Some(self.name.as_str()), Some(detail))?;
        self.check_running(&state, "exec")?;
        self.run(&mut state, &request)
    }

    async fn serve_ssh<S: SshStream>(&self, mut stream: S) -> Result<(), ComputeError> {
        {
            let mut state = self.runtime.lock();
            state.enter(Op::ServeSsh, Some(self.name.as_str()), None)?;
            self.check_running(&state, "serve ssh for")?;
        }
        let io = |e: std::io::Error| ComputeError::Runtime {
            op: "serve ssh",
            message: e.to_string(),
        };
        stream.write_all(SSH_BANNER.as_bytes()).await.map_err(io)?;
        stream.flush().await.map_err(io)?;
        let mut sink = [0_u8; 4096];
        while stream.read(&mut sink).await.map_err(io)? > 0 {}
        Ok(())
    }
}

impl Drop for FakeSandbox {
    /// Like the SDK (msb 0.7.7): dropping an owning handle shuts the VM down; the record says
    /// `Stopped`.
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        let mut state = self.runtime.lock();
        if let Some(r) = state.sandboxes.get_mut(self.name.as_str())
            && r.boot == self.boot
            && r.status == WorkspaceStatus::Running
        {
            r.status = WorkspaceStatus::Stopped;
        }
    }
}

#[cfg(test)]
mod tests;
