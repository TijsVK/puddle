// SPDX-License-Identifier: GPL-3.0-or-later
//! The compute-plane traits: [`Runtime`] (sandboxes, volumes, images) and [`Sandbox`] (one
//! running VM).

use std::collections::BTreeMap;
use std::future::Future;

use puddle_types::{ImageRef, MemoryMib, SandboxName, SandboxStatus, VolumeName};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{ComputeError, DiskSize, ExecOutput, ExecRequest, SandboxSpec};

/// What a runtime can do, from [`Runtime::probe`]. Code that works around a runtime bug checks
/// the matching flag instead of the version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// The runtime's version (`0.7.7`, `0.7.7-puddle.1`, `fake`).
    pub runtime_version: String,
    /// A failed create leaves no stale directory behind (the upstream msb bug is fixed). When
    /// `false`, a failed create blocks its name until [`Runtime::remove_stale_dir`].
    pub stale_dir_fixed: bool,
    /// SSH sessions report a signal-killed command as a failure. msb 0.7.6 reports exit 0.
    pub ssh_reports_signal_exit: bool,
}

/// A sandbox as [`Runtime::list`] sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInfo {
    /// The name as the runtime reports it; may be a name puddle didn't create.
    pub name: String,
    /// Its state.
    pub status: SandboxStatus,
    /// Whether puddle created it (msb: the sandbox carries puddle's owner label). Shutdown and
    /// reconcile only ever touch sandboxes with this set and a valid [`SandboxName`].
    pub puddle_owned: bool,
}

impl SandboxInfo {
    /// The name as a [`SandboxName`], or `None` if it isn't a valid puddle name.
    #[must_use]
    pub fn sandbox_name(&self) -> Option<SandboxName> {
        SandboxName::new(&self.name).ok()
    }
}

/// A new named disk volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    /// Its name.
    pub name: VolumeName,
    /// Its capacity.
    pub size: DiskSize,
}

/// A named volume as the runtime reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// The name as the runtime reports it; may be a name puddle didn't create.
    pub name: String,
    /// Its capacity, read back from the runtime's catalog.
    pub size: DiskSize,
    /// The running sandbox it is attached to, if any (ADR 0006 point 8: single writer).
    pub holder: Option<String>,
}

impl VolumeInfo {
    /// The name as a [`VolumeName`], or `None` if it isn't a valid puddle name.
    #[must_use]
    pub fn volume_name(&self) -> Option<VolumeName> {
        VolumeName::new(&self.name).ok()
    }
}

/// An image's OCI config, as far as puddle needs it (the boot hook chains `entrypoint` and uses
/// the image `PATH`; `user` and `labels` carry the image's `USER` and `devcontainer.metadata`).
/// All values come from the image and are untrusted. Build it with
/// `..ImageConfig::default()` so new fields don't break callers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// `ENTRYPOINT`; empty if the image declares none.
    pub entrypoint: Vec<String>,
    /// `CMD`.
    pub cmd: Vec<String>,
    /// `ENV`, as `(name, value)` in image order.
    pub env: Vec<(String, String)>,
    /// `WORKDIR`, if set.
    pub working_dir: Option<String>,
    /// `USER`, if set (`uid`, `uid:gid`, `name` or `name:group`).
    pub user: Option<String>,
    /// `LABEL`s, sorted by key.
    pub labels: BTreeMap<String, String>,
}

impl ImageConfig {
    /// The value of `name` in the image env (last one wins).
    #[must_use]
    pub fn env_var(&self, name: &str) -> Option<&str> {
        self.env
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A byte stream an SSH client is on (a named pipe or Unix socket connection, or an in-memory
/// duplex in tests). Implemented for every type with the listed bounds.
pub trait SshStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> SshStream for T {}

/// A microVM runtime: msb through its SDK (`puddle-compute-msb`), or `FakeRuntime` (feature `fake`).
///
/// Every method is a cancel-safe async call that may block on the runtime; callers put their own
/// timeouts around them where a hang would hurt. Behaviour that every implementation must share
/// is pinned by the `contract` module (feature `contract`); read its table for what is observed on msb and what is only
/// assumed until the SDK adapter runs it.
///
/// Sandbox lifecycle:
///
/// ```text
///  create ──► Running ──stop / owning handle dropped (msb 0.7.7)──► Stopped ──start──► Running
///                │                                                  │
///                │ VM died (owning handle dropped on msb 0.7.6)     └──remove──► (gone; owned
///                ▼                                                     disks gone, named volumes kept)
///             Crashed ──start──► Running        Crashed ──remove──► (gone)
/// ```
pub trait Runtime: Send + Sync + 'static {
    /// A handle to one sandbox.
    type Sandbox: Sandbox;

    /// Reports the runtime's version and the behaviours puddle works around.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`] when the runtime can't be reached.
    fn probe(&self) -> impl Future<Output = Result<Capabilities, ComputeError>> + Send;

    /// Makes sure `image` is in the local cache (pulling it if needed) and returns its config.
    ///
    /// # Errors
    ///
    /// [`ComputeError::ImagePull`] when it can't be pulled or has no config.
    fn pull_image(
        &self,
        image: &ImageRef,
    ) -> impl Future<Output = Result<ImageConfig, ComputeError>> + Send;

    /// Creates a sandbox and boots it; returns an **owning** handle (`Running`). Dropping that
    /// handle without [`Sandbox::stop`] shuts the VM down: the record reads `Stopped` on msb 0.7.7
    /// and read `Crashed` on 0.7.6. puddle still stops every sandbox itself at
    /// shutdown (`fstrim` first, ADR 0006). Pulls the image if needed. Named volumes with
    /// [`crate::VolumeMount::ensure_size`] are created if missing.
    ///
    /// On failure nothing is created, except that, without
    /// [`Capabilities::stale_dir_fixed`], a failed volume check leaves a stale directory that
    /// blocks the name; and a refused volume attach leaves a `Stopped` record, which
    /// [`Runtime::remove`] clears.
    ///
    /// # Errors
    ///
    /// - [`ComputeError::InvalidSpec`]: [`SandboxSpec::validate`] failed;
    /// - [`ComputeError::AlreadyExists`], [`ComputeError::StaleDir`]: the name is taken;
    /// - [`ComputeError::ImagePull`];
    /// - [`ComputeError::VolumeNotFound`], [`ComputeError::VolumeSizeMismatch`],
    ///   [`ComputeError::VolumeInUse`] (names the holder).
    fn create(
        &self,
        spec: SandboxSpec,
    ) -> impl Future<Output = Result<Self::Sandbox, ComputeError>> + Send;

    /// Boots a `Stopped` or `Crashed` sandbox again with its create-time spec; returns an
    /// owning handle. Named volumes are attached again, so the holder check runs again.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`]; [`ComputeError::InvalidState`] when it isn't down;
    /// [`ComputeError::VolumeInUse`].
    fn start(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<Self::Sandbox, ComputeError>> + Send;

    /// Connects to a `Running` sandbox, e.g. one a previous puddle left behind (re-adoption). The
    /// handle does **not** own the VM: dropping it does nothing.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`]; [`ComputeError::InvalidState`] when it isn't running.
    fn get(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<Self::Sandbox, ComputeError>> + Send;

    /// Sets the guest memory a sandbox boots with from its **next** start on (the memory setting,
    /// `--memory`). A running sandbox keeps its current size until it is stopped and started
    /// again; puddle never sets a max-memory.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`].
    fn set_memory(
        &self,
        name: &SandboxName,
        memory: MemoryMib,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send;

    /// Every sandbox the runtime knows, in name order, including ones puddle didn't create.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`].
    fn list(&self) -> impl Future<Output = Result<Vec<SandboxInfo>, ComputeError>> + Send;

    /// Deletes a sandbox that is down (`Created`, `Stopped`, `Crashed`), with its root disk and
    /// owned disks. Named volumes stay.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`]; [`ComputeError::InvalidState`] when it is running.
    fn remove(&self, name: &SandboxName) -> impl Future<Output = Result<(), ComputeError>> + Send;

    /// Names whose sandbox directory exists without a sandbox record (left by a failed create
    /// while the upstream msb bug is unfixed), in name order. May include names puddle didn't
    /// create.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`].
    fn stale_dirs(&self) -> impl Future<Output = Result<Vec<String>, ComputeError>> + Send;

    /// Deletes the stale directory of `name`, unblocking the name.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`] when there is no stale directory for `name` (a directory that
    /// belongs to a live sandbox is never touched).
    fn remove_stale_dir(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send;

    /// Creates an empty named disk volume (ext4).
    ///
    /// # Errors
    ///
    /// [`ComputeError::VolumeExists`]; [`ComputeError::InvalidSpec`] for size 0.
    fn create_volume(
        &self,
        spec: VolumeSpec,
    ) -> impl Future<Output = Result<VolumeInfo, ComputeError>> + Send;

    /// One volume, or `None`.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`].
    fn volume(
        &self,
        name: &VolumeName,
    ) -> impl Future<Output = Result<Option<VolumeInfo>, ComputeError>> + Send;

    /// Every volume, in name order, including ones puddle didn't create.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`].
    fn list_volumes(&self) -> impl Future<Output = Result<Vec<VolumeInfo>, ComputeError>> + Send;

    /// Deletes a volume and its data.
    ///
    /// # Errors
    ///
    /// [`ComputeError::VolumeNotFound`]; [`ComputeError::VolumeInUse`] while a running sandbox
    /// holds it.
    fn remove_volume(
        &self,
        name: &VolumeName,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send;
}

/// A handle to one sandbox. Handles from [`Runtime::create`] and [`Runtime::start`] own the VM
/// (dropping them kills it); handles from [`Runtime::get`] don't. A handle belongs to one boot:
/// after a stop and start, use the new handle.
pub trait Sandbox: Send + Sync + 'static {
    /// The sandbox's name.
    fn name(&self) -> &SandboxName;

    /// Whether dropping this handle kills the VM.
    fn owns_lifecycle(&self) -> bool;

    /// The sandbox's current state.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`] if it was removed.
    fn status(&self) -> impl Future<Output = Result<SandboxStatus, ComputeError>> + Send;

    /// Stops the VM gracefully; the sandbox becomes `Stopped`. Stopping a sandbox that is
    /// already down is a no-op.
    ///
    /// # Errors
    ///
    /// [`ComputeError::NotFound`]; [`ComputeError::StaleHandle`] if the sandbox was restarted
    /// through another handle.
    fn stop(&self) -> impl Future<Output = Result<(), ComputeError>> + Send;

    /// Runs a command to completion and returns its exit status and output. Exit codes come
    /// through exactly; a signal-killed command reports a non-zero code (`-1` on msb).
    ///
    /// # Errors
    ///
    /// [`ComputeError::InvalidState`] when the sandbox isn't running;
    /// [`ComputeError::StaleHandle`]; [`ComputeError::ExecTimeout`].
    fn exec(
        &self,
        request: ExecRequest,
    ) -> impl Future<Output = Result<ExecOutput, ComputeError>> + Send;

    /// Serves one SSH connection on `stream` (msb's in-process SSH server,
    /// `serve_connection`), returning when the client disconnects. The server speaks first:
    /// its `SSH-2.0-` identification line.
    ///
    /// # Errors
    ///
    /// [`ComputeError::InvalidState`] when the sandbox isn't running; [`ComputeError::Runtime`]
    /// for protocol failures.
    fn serve_ssh<S: SshStream>(
        &self,
        stream: S,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_names_parse_only_when_valid() {
        let ours = SandboxInfo {
            name: "box".into(),
            status: SandboxStatus::Running,
            puddle_owned: true,
        };
        assert_eq!(ours.sandbox_name().unwrap().as_str(), "box");
        let foreign = SandboxInfo {
            name: "Foreign_Box".into(),
            status: SandboxStatus::Stopped,
            puddle_owned: false,
        };
        assert!(foreign.sandbox_name().is_none());
        let vol = VolumeInfo {
            name: "ws-a".into(),
            size: DiskSize::mib(1),
            holder: None,
        };
        assert_eq!(vol.volume_name().unwrap().as_str(), "ws-a");
        let vol = VolumeInfo {
            name: "Bad".into(),
            ..vol
        };
        assert!(vol.volume_name().is_none());
    }

    #[test]
    fn image_env_last_value_wins() {
        let c = ImageConfig {
            env: vec![
                ("PATH".into(), "/a".into()),
                ("X".into(), "1".into()),
                ("PATH".into(), "/b".into()),
            ],
            ..ImageConfig::default()
        };
        assert_eq!(c.env_var("PATH"), Some("/b"));
        assert_eq!(c.env_var("NOPE"), None);
    }
}
