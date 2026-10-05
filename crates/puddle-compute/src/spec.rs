// SPDX-License-Identifier: GPL-3.0-or-later
//! What a sandbox is made of: [`SandboxSpec`] and its parts.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

use puddle_types::{GuestEnv, GuestPath, ImageRef, MemoryMib, SandboxName, VolumeName};

use crate::ComputeError;

/// The guest's network. puddle only ever uses [`NetworkPolicy::None`]: the guest has no network
/// interface at all, and its only way out is the vsock routes in [`SandboxSpec::routes`] (D-1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkPolicy {
    /// No guest network (msb `NetworkPolicy::none()`, CLI `--no-net`).
    #[default]
    None,
}

impl NetworkPolicy {
    /// The only policy puddle uses: no network.
    #[must_use]
    pub fn none() -> Self {
        Self::None
    }
}

/// A vsock port in the guest that the runtime connects to a host endpoint: a named pipe on
/// Windows (`\\.\pipe\…`), a Unix socket elsewhere. Only routed ports are reachable from the
/// guest (T-029 HG-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockRoute {
    /// The guest-side vsock port (non-zero).
    pub guest_port: u32,
    /// The host endpoint the runtime connects each guest connection to.
    pub host: PathBuf,
}

impl VsockRoute {
    /// A route from guest vsock port `guest_port` to the host endpoint `host`.
    #[must_use]
    pub fn new(guest_port: u32, host: impl Into<PathBuf>) -> Self {
        Self {
            guest_port,
            host: host.into(),
        }
    }
}

/// A host file mounted **read-only** at a guest path (virtiofs; a guest write gets `EROFS`,
/// T-029 HO-6). puddle uses these for the agent binary, the boot hook and its inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMount {
    /// The file on the host.
    pub host: PathBuf,
    /// Where it appears in the guest.
    pub guest: GuestPath,
}

impl FileMount {
    /// Mounts host file `host` read-only at `guest`.
    #[must_use]
    pub fn read_only(host: impl Into<PathBuf>, guest: GuestPath) -> Self {
        Self {
            host: host.into(),
            guest,
        }
    }
}

/// A disk size in MiB (what msb's `.disk().size(n)` takes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiskSize(u32);

impl DiskSize {
    /// `mib` MiB.
    #[must_use]
    pub const fn mib(mib: u32) -> Self {
        Self(mib)
    }

    /// `gib` GiB (saturating at `u32::MAX` MiB).
    #[must_use]
    pub const fn gib(gib: u32) -> Self {
        Self(gib.saturating_mul(1024))
    }

    /// The size in MiB.
    #[must_use]
    pub const fn as_mib(self) -> u32 {
        self.0
    }

    /// The size in bytes.
    #[must_use]
    pub const fn as_bytes(self) -> u64 {
        // Lossless widening; `u64::from` isn't const.
        (self.0 as u64) * 1024 * 1024
    }
}

impl fmt::Display for DiskSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} MiB", self.0)
    }
}

/// A named disk volume attached at a guest path. The volume outlives the sandbox (ADR 0006).
///
/// Without [`VolumeMount::ensure_size`] the volume must exist and is reattached as it is (msb
/// reads kind and size from its catalog, T-028). With it, a missing volume is created with that
/// size, and an existing one must have exactly that size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    /// The volume.
    pub volume: VolumeName,
    /// Where it is mounted in the guest.
    pub guest: GuestPath,
    /// Create-if-missing with this size; `None` = must already exist.
    pub ensure_size: Option<DiskSize>,
}

impl VolumeMount {
    /// Attaches existing volume `volume` at `guest` (msb `.named(volume)`).
    #[must_use]
    pub fn named(volume: VolumeName, guest: GuestPath) -> Self {
        Self {
            volume,
            guest,
            ensure_size: None,
        }
    }

    /// The same mount, creating the volume with `size` if it doesn't exist (msb
    /// `named_with(.., ensure_exists().disk().size(n))`).
    #[must_use]
    pub fn ensure_size(mut self, size: DiskSize) -> Self {
        self.ensure_size = Some(size);
        self
    }
}

/// A disk that belongs to the sandbox: it survives stop/start and is deleted with the sandbox
/// (msb `owned_with(|v| v.disk().size(n))`). For data that must not sit on the root overlay, such
/// as `/var/lib/docker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedDisk {
    /// Where it is mounted in the guest.
    pub guest: GuestPath,
    /// Its size.
    pub size: DiskSize,
}

/// Everything needed to create a sandbox. Build it with [`SandboxSpec::new`] and the `with_*`
/// methods; the fields are public so runtimes can read them.
///
/// ```
/// use puddle_compute::{FileMount, SandboxSpec, VolumeMount, VsockRoute, DiskSize};
/// use puddle_types::{GuestPath, ImageRef, SandboxName, WorkspaceId};
///
/// let ws = WorkspaceId::new("acme").unwrap();
/// let spec = SandboxSpec::new(
///     SandboxName::new("acme").unwrap(),
///     ImageRef::new("mcr.microsoft.com/devcontainers/base:debian").unwrap(),
/// )
/// .with_route(VsockRoute::new(5000, r"\\.\pipe\puddle-acme-proxy"))
/// .with_file_mount(FileMount::read_only("/opt/puddle/boot.sh", GuestPath::new("/puddle/boot.sh").unwrap()))
/// .with_volume(
///     VolumeMount::named(ws.volume_name(), GuestPath::new("/workspaces/acme").unwrap())
///         .ensure_size(DiskSize::gib(20)),
/// );
/// spec.validate().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The sandbox's name.
    pub name: SandboxName,
    /// The OCI image.
    pub image: ImageRef,
    /// Guest memory (`--memory`; puddle never sets a max-memory).
    pub memory: MemoryMib,
    /// Virtual CPUs; `None` = the runtime's default.
    pub cpus: Option<u8>,
    /// Environment for every process: exec, SSH sessions and the boot hook.
    pub env: GuestEnv,
    /// The guest network: always none.
    pub network: NetworkPolicy,
    /// vsock routes to host endpoints.
    pub routes: Vec<VsockRoute>,
    /// Read-only host file mounts.
    pub file_mounts: Vec<FileMount>,
    /// Named disk volumes.
    pub volumes: Vec<VolumeMount>,
    /// Disks owned by the sandbox.
    pub owned_disks: Vec<OwnedDisk>,
}

impl SandboxSpec {
    /// A sandbox `name` from `image` with default memory, no network and nothing attached.
    #[must_use]
    pub fn new(name: SandboxName, image: ImageRef) -> Self {
        Self {
            name,
            image,
            memory: MemoryMib::DEFAULT,
            cpus: None,
            env: GuestEnv::new(),
            network: NetworkPolicy::none(),
            routes: Vec::new(),
            file_mounts: Vec::new(),
            volumes: Vec::new(),
            owned_disks: Vec::new(),
        }
    }

    /// Sets the guest memory.
    #[must_use]
    pub fn with_memory(mut self, memory: MemoryMib) -> Self {
        self.memory = memory;
        self
    }

    /// Sets the number of virtual CPUs.
    #[must_use]
    pub fn with_cpus(mut self, cpus: u8) -> Self {
        self.cpus = Some(cpus);
        self
    }

    /// Adds environment variables (later ones win).
    #[must_use]
    pub fn with_env(mut self, env: &GuestEnv) -> Self {
        self.env.extend(env);
        self
    }

    /// Adds a vsock route.
    #[must_use]
    pub fn with_route(mut self, route: VsockRoute) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a read-only file mount.
    #[must_use]
    pub fn with_file_mount(mut self, mount: FileMount) -> Self {
        self.file_mounts.push(mount);
        self
    }

    /// Adds a named volume.
    #[must_use]
    pub fn with_volume(mut self, mount: VolumeMount) -> Self {
        self.volumes.push(mount);
        self
    }

    /// Adds an owned disk.
    #[must_use]
    pub fn with_owned_disk(mut self, disk: OwnedDisk) -> Self {
        self.owned_disks.push(disk);
        self
    }

    /// Checks what the types can't: routes use distinct non-zero ports, no two mounts share a
    /// guest path or nest, a volume is attached once, CPUs and disk sizes are non-zero.
    /// Runtimes call this at the start of [`crate::Runtime::create`].
    ///
    /// # Errors
    ///
    /// [`ComputeError::InvalidSpec`] naming the first problem found.
    pub fn validate(&self) -> Result<(), ComputeError> {
        let invalid = |reason: String| Err(ComputeError::InvalidSpec { reason });
        if self.cpus == Some(0) {
            return invalid("cpus must be at least 1".into());
        }
        let mut ports = BTreeSet::new();
        for route in &self.routes {
            if route.guest_port == 0 {
                return invalid("vsock route port must not be 0".into());
            }
            if !ports.insert(route.guest_port) {
                return invalid(format!("vsock port {} is routed twice", route.guest_port));
            }
        }
        let mut volumes = BTreeSet::new();
        for mount in &self.volumes {
            if !volumes.insert(&mount.volume) {
                return invalid(format!(
                    "volume {:?} is attached twice",
                    mount.volume.as_str()
                ));
            }
            if mount.ensure_size.is_some_and(|s| s.as_mib() == 0) {
                return invalid(format!("volume {:?} has size 0", mount.volume.as_str()));
            }
        }
        if let Some(d) = self.owned_disks.iter().find(|d| d.size.as_mib() == 0) {
            return invalid(format!("owned disk at {} has size 0", d.guest));
        }
        let guests: Vec<&GuestPath> = self
            .file_mounts
            .iter()
            .map(|m| &m.guest)
            .chain(self.volumes.iter().map(|m| &m.guest))
            .chain(self.owned_disks.iter().map(|d| &d.guest))
            .collect();
        for (i, a) in guests.iter().enumerate() {
            for b in guests.iter().skip(i + 1) {
                if a.is_within(b) || b.is_within(a) {
                    return invalid(format!("mounts at {a} and {b} overlap"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> GuestPath {
        GuestPath::new(s).unwrap()
    }

    fn v(s: &str) -> VolumeName {
        VolumeName::new(s).unwrap()
    }

    fn base() -> SandboxSpec {
        SandboxSpec::new(
            SandboxName::new("box").unwrap(),
            ImageRef::new("alpine").unwrap(),
        )
    }

    fn reason(spec: &SandboxSpec) -> String {
        match spec.validate() {
            Err(ComputeError::InvalidSpec { reason }) => reason,
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_no_network_default_memory_nothing_attached() {
        let s = base();
        assert_eq!(s.network, NetworkPolicy::None);
        assert_eq!(s.memory, MemoryMib::DEFAULT);
        assert_eq!(s.cpus, None);
        assert!(s.env.is_empty() && s.routes.is_empty() && s.file_mounts.is_empty());
        assert!(s.volumes.is_empty() && s.owned_disks.is_empty());
        s.validate().unwrap();
    }

    #[test]
    fn builders_fill_the_fields() {
        let mut env = GuestEnv::new();
        env.set("A", "1").unwrap();
        let s = base()
            .with_memory(MemoryMib::MIN)
            .with_cpus(2)
            .with_env(&env)
            .with_route(VsockRoute::new(5000, "/run/p.sock"))
            .with_file_mount(FileMount::read_only("/h/boot.sh", p("/puddle/boot.sh")))
            .with_volume(
                VolumeMount::named(v("ws-a"), p("/workspaces/a")).ensure_size(DiskSize::mib(64)),
            )
            .with_owned_disk(OwnedDisk {
                guest: p("/var/lib/docker"),
                size: DiskSize::gib(1),
            });
        assert_eq!(s.memory, MemoryMib::MIN);
        assert_eq!(s.cpus, Some(2));
        assert_eq!(s.env.get("A"), Some("1"));
        assert_eq!(s.routes[0].guest_port, 5000);
        assert_eq!(s.file_mounts[0].host, PathBuf::from("/h/boot.sh"));
        assert_eq!(s.volumes[0].ensure_size, Some(DiskSize::mib(64)));
        assert_eq!(s.owned_disks[0].size.as_mib(), 1024);
        s.validate().unwrap();
    }

    #[test]
    fn disk_size_units() {
        assert_eq!(DiskSize::gib(2).as_mib(), 2048);
        assert_eq!(DiskSize::mib(2048).as_bytes(), 2_147_483_648);
        assert_eq!(DiskSize::gib(u32::MAX).as_mib(), u32::MAX);
        assert_eq!(DiskSize::mib(5).to_string(), "5 MiB");
    }

    #[test]
    fn validate_rejects_bad_routes() {
        assert!(
            reason(&base().with_route(VsockRoute::new(0, "/x"))).contains("port must not be 0")
        );
        let twice = base()
            .with_route(VsockRoute::new(5000, "/x"))
            .with_route(VsockRoute::new(5000, "/y"));
        assert!(reason(&twice).contains("routed twice"));
    }

    #[test]
    fn validate_rejects_overlapping_mounts() {
        let nested = base()
            .with_file_mount(FileMount::read_only("/h", p("/puddle/boot.sh")))
            .with_volume(VolumeMount::named(v("ws-a"), p("/puddle")));
        assert!(reason(&nested).contains("overlap"));
        let same = base()
            .with_volume(VolumeMount::named(v("ws-a"), p("/w")))
            .with_owned_disk(OwnedDisk {
                guest: p("/w"),
                size: DiskSize::mib(1),
            });
        assert!(reason(&same).contains("overlap"));
        let siblings = base()
            .with_volume(VolumeMount::named(v("ws-a"), p("/w/a")))
            .with_volume(VolumeMount::named(v("ws-b"), p("/w/ab")));
        siblings.validate().unwrap();
    }

    #[test]
    fn validate_rejects_double_volumes_zero_sizes_and_zero_cpus() {
        let twice = base()
            .with_volume(VolumeMount::named(v("ws-a"), p("/a")))
            .with_volume(VolumeMount::named(v("ws-a"), p("/b")));
        assert!(reason(&twice).contains("attached twice"));
        let zero = base()
            .with_volume(VolumeMount::named(v("ws-a"), p("/a")).ensure_size(DiskSize::mib(0)));
        assert!(reason(&zero).contains("size 0"));
        let zero_owned = base().with_owned_disk(OwnedDisk {
            guest: p("/d"),
            size: DiskSize::mib(0),
        });
        assert!(reason(&zero_owned).contains("size 0"));
        assert!(reason(&base().with_cpus(0)).contains("cpus"));
    }
}
