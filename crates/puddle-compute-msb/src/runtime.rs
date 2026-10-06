// SPDX-License-Identifier: GPL-3.0-or-later
//! [`MsbRuntime`]: [`puddle_compute::Runtime`] over the msb SDK.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use microsandbox::sandbox::{SandboxHandle, SandboxStatus as SdkStatus};
use microsandbox::volume::Volume;
use microsandbox::{Backend, LocalBackend, MicrosandboxError, Sandbox};
use puddle_compute::{
    Capabilities, ComputeError, ImageConfig, Runtime, SandboxInfo, SandboxSpec, VolumeInfo,
    VolumeSpec,
};
use puddle_types::{ImageRef, MemoryMib, SandboxName, SandboxStatus, VolumeName};

use crate::error::{map, runtime};
use crate::sandbox::{MsbSandbox, boot_id};
use crate::volume::{Mounter, holders, info, named_volumes};
use crate::{MsbConfig, image, spec};

struct Inner {
    config: MsbConfig,
    backend: Arc<dyn Backend>,
    local: Arc<LocalBackend>,
    sandboxes_dir: PathBuf,
}

/// The msb SDK as a [`Runtime`]. Cloning gives another handle to the same runtime.
#[derive(Clone)]
pub struct MsbRuntime {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for MsbRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MsbRuntime")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// msb's status as puddle's.
pub(crate) fn status(s: SdkStatus) -> SandboxStatus {
    match s {
        SdkStatus::Created => SandboxStatus::Created,
        SdkStatus::Starting => SandboxStatus::Starting,
        SdkStatus::Running => SandboxStatus::Running,
        SdkStatus::Draining => SandboxStatus::Draining,
        SdkStatus::Paused => SandboxStatus::Paused,
        SdkStatus::Stopped => SandboxStatus::Stopped,
        SdkStatus::Crashed => SandboxStatus::Crashed,
    }
}

impl MsbRuntime {
    /// Opens msb's database in `config.home` (created if missing), after writing its
    /// `config.json` with the runtime pair. Also creates the guest-share root.
    ///
    /// # Errors
    ///
    /// [`ComputeError::Runtime`] when a directory or `config.json` can't be written or the
    /// database can't be opened.
    pub async fn open(config: MsbConfig) -> Result<Self, ComputeError> {
        for dir in [&config.home, &config.guest_share] {
            std::fs::create_dir_all(dir).map_err(|e| runtime("open", &e))?;
        }
        std::fs::write(config.config_path(), config.config_json())
            .map_err(|e| runtime("open", &e))?;
        let mut attempt = 1;
        let local = loop {
            let opened = Box::pin(
                LocalBackend::builder()
                    .home(&config.home)
                    .config_path(config.config_path())
                    .build(),
            )
            .await;
            match opened {
                Ok(local) => break local,
                // SQLite on Windows: an msb process that is just exiting can still hold the
                // database, and the open fails with "disk I/O error" (T-106, hosted runner).
                Err(e) if attempt < OPEN_ATTEMPTS => {
                    tracing::warn!(error = %e, attempt, "msb database busy at open; retrying");
                    tokio::time::sleep(OPEN_BACKOFF).await;
                    attempt += 1;
                }
                Err(e) => return Err(runtime("open", &e)),
            }
        };
        let local = Arc::new(local);
        let sandboxes_dir = local.sandboxes_dir();
        let backend: Arc<dyn Backend> = local.clone();
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                backend,
                local,
                sandboxes_dir,
            }),
        })
    }

    /// The config this runtime was opened with.
    #[must_use]
    pub fn config(&self) -> &MsbConfig {
        &self.inner.config
    }

    /// Runs an SDK future with this runtime's backend (task-local, so other runtimes in the
    /// process are unaffected). Boxed: the SDK's futures are large.
    pub(crate) async fn sdk<F: Future>(&self, future: F) -> F::Output {
        microsandbox::with_backend(Arc::clone(&self.inner.backend), Box::pin(future)).await
    }

    /// The persisted record of `name`, or `None`.
    pub(crate) async fn record(&self, name: &str) -> Result<Option<SandboxHandle>, ComputeError> {
        match self.sdk(Sandbox::get(name)).await {
            Ok(handle) => Ok(Some(handle)),
            Err(MicrosandboxError::SandboxNotFound(_)) => Ok(None),
            Err(e) => Err(map("look up", name, e)),
        }
    }

    async fn existing(&self, name: &SandboxName) -> Result<SandboxHandle, ComputeError> {
        self.record(name.as_str())
            .await?
            .ok_or_else(|| ComputeError::NotFound {
                sandbox: name.to_string(),
            })
    }

    /// Every sandbox record, across all pages.
    async fn records(&self) -> Result<Vec<SandboxHandle>, ComputeError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let next = cursor.clone();
            let page = self
                .sdk(Sandbox::list_with(move |l| {
                    let l = l.limit(microsandbox::sandbox::MAX_SANDBOX_LIST_LIMIT);
                    match next {
                        Some(c) => l.cursor(c),
                        None => l,
                    }
                }))
                .await
                .map_err(|e| map("list", "", e))?;
            out.extend(page.sandboxes);
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(out),
            }
        }
    }

    /// Volume name → the running sandbox that holds it.
    async fn volume_holders(&self) -> Result<BTreeMap<String, String>, ComputeError> {
        let mounters: Vec<Mounter> = self
            .records()
            .await?
            .iter()
            .map(|h| Mounter {
                name: h.name().to_owned(),
                status: status(h.status_snapshot()),
                volumes: h.config().map(|c| named_volumes(&c)).unwrap_or_default(),
            })
            .collect();
        Ok(holders(&mounters))
    }

    /// The checks msb does at boot, done first so the error names the volume, the sizes and the
    /// holder (and a refused attach leaves no record behind).
    async fn check_volumes(
        &self,
        sandbox: &str,
        mounts: &[(String, Option<u32>)],
    ) -> Result<(), ComputeError> {
        if mounts.is_empty() {
            return Ok(());
        }
        let held = self.volume_holders().await?;
        for (volume, ensure_mib) in mounts {
            match self.sdk(Volume::get(volume)).await {
                Ok(handle) => {
                    let existing =
                        crate::volume::size_mib(handle.capacity_bytes(), handle.quota_mib());
                    if let Some(want) = ensure_mib
                        && existing.as_mib() != *want
                    {
                        return Err(ComputeError::VolumeSizeMismatch {
                            volume: volume.clone(),
                            existing_mib: existing.as_mib(),
                            requested_mib: *want,
                        });
                    }
                }
                Err(MicrosandboxError::VolumeNotFound(_)) if ensure_mib.is_none() => {
                    return Err(ComputeError::VolumeNotFound {
                        volume: volume.clone(),
                    });
                }
                Err(MicrosandboxError::VolumeNotFound(_)) => {}
                Err(e) => return Err(map("look up volume", volume, e)),
            }
            if let Some(holder) = held.get(volume)
                && holder != sandbox
            {
                return Err(ComputeError::VolumeInUse {
                    volume: volume.clone(),
                    holder: holder.clone(),
                });
            }
        }
        Ok(())
    }

    fn sandbox_dir(&self, name: &str) -> PathBuf {
        self.inner.sandboxes_dir.join(name)
    }

    /// msb T-039: a create that fails after making the sandbox directory leaves it behind and
    /// the name stays blocked. Remove it when this create made it and no record exists.
    async fn remove_leftover_dir(&self, name: &SandboxName) {
        let dir = self.sandbox_dir(name.as_str());
        if !dir.exists() {
            return;
        }
        if let Ok(None) = self.record(name.as_str()).await
            && let Err(e) = std::fs::remove_dir_all(&dir)
        {
            tracing::warn!(sandbox = %name, dir = %dir.display(), error = %e,
                "failed create left a directory that can't be removed; the name stays blocked");
        }
    }

    /// After a create lost the boot race: the record it may have left (down) and its directory
    /// go, so the retry finds the name free, as it was before this create.
    async fn discard_failed_create(&self, name: &SandboxName) {
        if let Ok(Some(record)) = self.record(name.as_str()).await
            && status(record.status_snapshot()).is_down()
            && let Err(e) = self.sdk(Sandbox::remove(name.as_str())).await
        {
            tracing::warn!(sandbox = %name, error = %e, "can't remove the record of a failed boot");
        }
        self.remove_leftover_dir(name).await;
    }

    /// Logs a lost boot race with the tail of msb's logs for the sandbox: the evidence for the
    /// upstream fix (T-106 follow-up).
    fn log_boot_race(&self, op: &str, name: &SandboxName, attempt: u32, error: &MicrosandboxError) {
        let logs = log_tail(
            &self.sandbox_dir(name.as_str()).join("logs"),
            LOG_TAIL_BYTES,
        );
        tracing::warn!(sandbox = %name, op, attempt, error = %error, logs = %logs,
            "msb's VM exited before its agent relay was up; trying once more");
    }

    async fn handle_for(
        &self,
        name: &SandboxName,
        sdk: Sandbox,
    ) -> Result<MsbSandbox, ComputeError> {
        let record = self.existing(name).await?;
        Ok(MsbSandbox::new(
            self.clone(),
            name.clone(),
            sdk,
            boot_id(&record),
        ))
    }
}

/// How often [`MsbRuntime::open`] tries to open msb's database, and how long it waits between.
const OPEN_ATTEMPTS: u32 = 5;
const OPEN_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// How often create and start try when msb loses its boot race (see [`is_boot_race`]).
const BOOT_ATTEMPTS: u32 = 2;

/// How much of each msb log file a lost boot race logs.
const LOG_TAIL_BYTES: usize = 4096;

/// msb on Windows sometimes loses the race between the guest's bootstrap and the host's agent
/// relay: the VM exits 0 before the relay is up, and the SDK reports a synthetic boot error. Seen
/// on 4 of ~45 creates on the hosted windows-2025 runner (T-106); the 0.6.10 regression in
/// `docs/upstream/microsandbox-windows-bootstrap-regression.md` (workspace) has the same symptom.
/// A second attempt boots. Never seen on Linux.
pub(crate) fn is_boot_race(error: &MicrosandboxError) -> bool {
    matches!(error, MicrosandboxError::BootStart { err, .. }
        if err.message.contains("before agent relay became available"))
}

/// The last `max` bytes of every file in `dir`, each under its name; empty if there are none.
pub(crate) fn log_tail(dir: &std::path::Path, max: usize) -> String {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return String::new();
    };
    let mut files: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    files.sort();
    let mut out = String::new();
    for file in files.iter().filter(|f| f.is_file()) {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let tail = bytes
            .get(bytes.len().saturating_sub(max)..)
            .unwrap_or_default();
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let _ = writeln!(out, "--- {name}\n{}", String::from_utf8_lossy(tail));
    }
    out
}

/// `(volume, ensure size)` for every named volume in `spec`.
fn spec_mounts(spec: &SandboxSpec) -> Vec<(String, Option<u32>)> {
    spec.volumes
        .iter()
        .map(|m| {
            (
                m.volume.to_string(),
                m.ensure_size.map(puddle_compute::DiskSize::as_mib),
            )
        })
        .collect()
}

// Every method boxes its future: the SDK's futures are large, and callers nest them (the
// contract suite overflowed a test thread's stack with them inline).
impl Runtime for MsbRuntime {
    type Sandbox = MsbSandbox;

    fn probe(&self) -> impl Future<Output = Result<Capabilities, ComputeError>> + Send {
        Box::pin(async move {
            let msb = &self.inner.config.msb;
            let version = puddle_runtime::read_embedded_version(msb)
                .map_err(|e| runtime("probe", &e))?
                .ok_or_else(|| ComputeError::Runtime {
                    op: "probe",
                    message: format!("{} has no embedded version", msb.display()),
                })?;
            Ok(Capabilities {
                runtime_version: version,
                // The adapter removes what a failed create leaves (remove_leftover_dir).
                stale_dir_fixed: true,
                // The fork's SSH server sends no exit status for a signal-killed command, so
                // clients see a failure (fork `359f1585`; stock 0.7.7 sent 0).
                // `vm_ssh_reports_a_signal_killed_command_as_a_failure` checks it.
                ssh_reports_signal_exit: true,
            })
        })
    }

    fn pull_image(
        &self,
        image: &ImageRef,
    ) -> impl Future<Output = Result<ImageConfig, ComputeError>> + Send {
        Box::pin(async move { Box::pin(image::pull(&self.inner.local, image)).await })
    }

    fn create(
        &self,
        spec: SandboxSpec,
    ) -> impl Future<Output = Result<MsbSandbox, ComputeError>> + Send {
        Box::pin(async move {
            spec.validate()?;
            for mount in &spec.file_mounts {
                self.inner.config.check_mount_source(&mount.host)?;
            }
            let name = spec.name.clone();
            if self.record(name.as_str()).await?.is_some() {
                return Err(ComputeError::AlreadyExists {
                    sandbox: name.to_string(),
                });
            }
            if self.sandbox_dir(name.as_str()).exists() {
                return Err(ComputeError::StaleDir {
                    sandbox: name.to_string(),
                });
            }
            self.check_volumes(name.as_str(), &spec_mounts(&spec))
                .await?;
            self.pull_image(&spec.image).await?;
            let mut attempt = 1;
            loop {
                match self.sdk(spec::builder(&spec).create()).await {
                    Ok(sdk) => return self.handle_for(&name, sdk).await,
                    Err(e) if attempt < BOOT_ATTEMPTS && is_boot_race(&e) => {
                        self.log_boot_race("create", &name, attempt, &e);
                        self.discard_failed_create(&name).await;
                        attempt += 1;
                    }
                    Err(e) => {
                        self.remove_leftover_dir(&name).await;
                        return Err(match e {
                            e @ (MicrosandboxError::ImageNotFound(_)
                            | MicrosandboxError::Image(_)) => map("create", spec.image.as_str(), e),
                            e => map("create", name.as_str(), e),
                        });
                    }
                }
            }
        })
    }

    fn start(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<MsbSandbox, ComputeError>> + Send {
        Box::pin(async move {
            let record = self.existing(name).await?;
            let current = status(record.status_snapshot());
            if !current.is_down() {
                return Err(ComputeError::InvalidState {
                    sandbox: name.to_string(),
                    op: "start",
                    status: current,
                });
            }
            let mounts: Vec<(String, Option<u32>)> = record
                .config()
                .map(|c| named_volumes(&c))
                .unwrap_or_default()
                .into_iter()
                .map(|v| (v, None))
                .collect();
            self.check_volumes(name.as_str(), &mounts).await?;
            let mut attempt = 1;
            loop {
                match self.sdk(Sandbox::start(name.as_str())).await {
                    Ok(sdk) => return self.handle_for(name, sdk).await,
                    Err(e) if attempt < BOOT_ATTEMPTS && is_boot_race(&e) => {
                        self.log_boot_race("start", name, attempt, &e);
                        attempt += 1;
                    }
                    Err(e) => return Err(map("start", name.as_str(), e)),
                }
            }
        })
    }

    fn get(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<MsbSandbox, ComputeError>> + Send {
        Box::pin(async move {
            let record = self.existing(name).await?;
            let current = status(record.status_snapshot());
            if current != SandboxStatus::Running {
                return Err(ComputeError::InvalidState {
                    sandbox: name.to_string(),
                    op: "connect to",
                    status: current,
                });
            }
            let sdk = self
                .sdk(record.connect())
                .await
                .map_err(|e| map("connect to", name.as_str(), e))?;
            Ok(MsbSandbox::new(
                self.clone(),
                name.clone(),
                sdk,
                boot_id(&record),
            ))
        })
    }

    fn set_memory(
        &self,
        name: &SandboxName,
        memory: MemoryMib,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            let record = self.existing(name).await?;
            let mib = memory.get();
            // The SDK keeps max-memory at least at memory, but a decrease would leave the old size
            // as a hotplug reserve; pinning it to the new size keeps "no max-memory" (max == memory).
            let change = record.modify().memory(mib).max_memory(mib).next_start();
            self.sdk(change.apply())
                .await
                .map_err(|e| map("set memory of", name.as_str(), e))?;
            Ok(())
        })
    }

    fn list(&self) -> impl Future<Output = Result<Vec<SandboxInfo>, ComputeError>> + Send {
        Box::pin(async move {
            let mut out: Vec<SandboxInfo> = self
                .records()
                .await?
                .iter()
                .map(|h| SandboxInfo {
                    name: h.name().to_owned(),
                    status: status(h.status_snapshot()),
                })
                .collect();
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
    }

    fn remove(&self, name: &SandboxName) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            let record = self.existing(name).await?;
            let current = status(record.status_snapshot());
            if !current.is_down() {
                return Err(ComputeError::InvalidState {
                    sandbox: name.to_string(),
                    op: "remove",
                    status: current,
                });
            }
            self.sdk(Sandbox::remove(name.as_str()))
                .await
                .map_err(|e| map("remove", name.as_str(), e))
        })
    }

    fn stale_dirs(&self) -> impl Future<Output = Result<Vec<String>, ComputeError>> + Send {
        Box::pin(async move {
            let dirs = match std::fs::read_dir(&self.inner.sandboxes_dir) {
                Ok(entries) => entries
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect::<BTreeSet<String>>(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeSet::new(),
                Err(e) => return Err(runtime("list stale dirs", &e)),
            };
            if dirs.is_empty() {
                return Ok(Vec::new());
            }
            let live: BTreeSet<String> = self
                .records()
                .await?
                .iter()
                .map(|h| h.name().to_owned())
                .collect();
            Ok(dirs.difference(&live).cloned().collect())
        })
    }

    fn remove_stale_dir(
        &self,
        name: &SandboxName,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            let dir = self.sandbox_dir(name.as_str());
            let not_found = || ComputeError::NotFound {
                sandbox: name.to_string(),
            };
            if self.record(name.as_str()).await?.is_some() || !dir.is_dir() {
                return Err(not_found());
            }
            std::fs::remove_dir_all(&dir).map_err(|e| runtime("remove stale dir", &e))
        })
    }

    fn create_volume(
        &self,
        spec: VolumeSpec,
    ) -> impl Future<Output = Result<VolumeInfo, ComputeError>> + Send {
        Box::pin(async move {
            if spec.size.as_mib() == 0 {
                return Err(ComputeError::InvalidSpec {
                    reason: format!("volume {:?} has size 0", spec.name.as_str()),
                });
            }
            let name = spec.name.as_str();
            let created = self
                .sdk(
                    Volume::builder(name)
                        .disk()
                        .size(spec.size.as_mib())
                        .create(),
                )
                .await
                .map_err(|e| match e {
                    MicrosandboxError::VolumeAlreadyExists(_) => ComputeError::VolumeExists {
                        volume: name.to_owned(),
                    },
                    e => map("create volume", name, e),
                })?;
            Ok(VolumeInfo {
                name: created.name().to_owned(),
                size: crate::volume::size_mib(created.capacity_bytes(), None),
                holder: None,
            })
        })
    }

    fn volume(
        &self,
        name: &VolumeName,
    ) -> impl Future<Output = Result<Option<VolumeInfo>, ComputeError>> + Send {
        Box::pin(async move {
            match self.sdk(Volume::get(name.as_str())).await {
                Ok(handle) => Ok(Some(info(&handle, &self.volume_holders().await?))),
                Err(MicrosandboxError::VolumeNotFound(_)) => Ok(None),
                Err(e) => Err(map("look up volume", name.as_str(), e)),
            }
        })
    }

    fn list_volumes(&self) -> impl Future<Output = Result<Vec<VolumeInfo>, ComputeError>> + Send {
        Box::pin(async move {
            let handles = self
                .sdk(Volume::list())
                .await
                .map_err(|e| map("list volumes", "", e))?;
            let held = self.volume_holders().await?;
            let mut out: Vec<VolumeInfo> = handles.iter().map(|h| info(h, &held)).collect();
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
    }

    fn remove_volume(
        &self,
        name: &VolumeName,
    ) -> impl Future<Output = Result<(), ComputeError>> + Send {
        Box::pin(async move {
            let volume = name.as_str();
            match self.sdk(Volume::get(volume)).await {
                Ok(_) => {}
                Err(MicrosandboxError::VolumeNotFound(_)) => {
                    return Err(ComputeError::VolumeNotFound {
                        volume: volume.to_owned(),
                    });
                }
                Err(e) => return Err(map("look up volume", volume, e)),
            }
            if let Some(holder) = self.volume_holders().await?.remove(volume) {
                return Err(ComputeError::VolumeInUse {
                    volume: volume.to_owned(),
                    holder,
                });
            }
            self.sdk(Volume::remove(volume))
                .await
                .map_err(|e| map("remove volume", volume, e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_relay_race_counts_as_a_boot_race() {
        let boot = |message: &str| MicrosandboxError::BootStart {
            name: "a".into(),
            err: microsandbox_runtime::boot_error::BootError {
                t: "2026-10-06T00:00:00.000Z".into(),
                stage: microsandbox_runtime::boot_error::BootErrorStage::Other,
                reason: None,
                errno: None,
                message: message.into(),
            },
        };
        assert!(is_boot_race(&boot(
            "sandbox process exited (exit code: 0) before agent relay became available"
        )));
        assert!(!is_boot_race(&boot("rootfs mount failed")));
        assert!(!is_boot_race(&MicrosandboxError::Runtime(
            "before agent relay became available".into()
        )));
    }

    #[test]
    fn log_tails_name_each_file_and_keep_the_end() {
        let dir = std::env::temp_dir().join(format!("puddle-msb-logtail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("b.log"), "0123456789").unwrap();
        std::fs::write(dir.join("a.log"), "hello").unwrap();
        let tail = log_tail(&dir, 4);
        assert_eq!(tail, "--- a.log\nello\n--- b.log\n6789\n");
        assert_eq!(log_tail(&dir.join("missing"), 4), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_sdk_status_maps_one_to_one() {
        let pairs = [
            (SdkStatus::Created, SandboxStatus::Created),
            (SdkStatus::Starting, SandboxStatus::Starting),
            (SdkStatus::Running, SandboxStatus::Running),
            (SdkStatus::Draining, SandboxStatus::Draining),
            (SdkStatus::Paused, SandboxStatus::Paused),
            (SdkStatus::Stopped, SandboxStatus::Stopped),
            (SdkStatus::Crashed, SandboxStatus::Crashed),
        ];
        for (sdk, ours) in pairs {
            assert_eq!(status(sdk), ours);
        }
    }
}
