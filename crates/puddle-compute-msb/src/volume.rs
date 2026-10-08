// SPDX-License-Identifier: GPL-3.0-or-later
//! Named volumes: who holds one, and the catalog view as [`VolumeInfo`].
//!
//! msb's own refusal of a second attach doesn't name the holder, so puddle works it out:
//! the holder is the running sandbox whose configuration mounts the volume (ADR 0006 point 8).

use std::collections::BTreeMap;

use microsandbox::sandbox::{SandboxConfig, VolumeMount};
use microsandbox::volume::VolumeHandle;
use puddle_compute::{ComputeError, DiskSize, VolumeInfo};
use puddle_types::WorkspaceStatus;

/// One sandbox as the holder lookup needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mounter {
    /// The sandbox.
    pub name: String,
    /// Its state.
    pub status: WorkspaceStatus,
    /// The named volumes its configuration mounts.
    pub volumes: Vec<String>,
}

/// The named volumes a sandbox configuration mounts.
pub(crate) fn named_volumes(config: &SandboxConfig) -> Vec<String> {
    config
        .spec
        .mounts
        .iter()
        .filter_map(|m| match m {
            VolumeMount::Named { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// The named volumes of the sandbox `name`, from its stored configuration. A configuration that
/// cannot be read is an error: reading it as "no volumes" would let a second writer attach a
/// volume that is in use.
pub(crate) fn mounted_volumes<E: std::fmt::Display>(
    name: &str,
    config: Result<SandboxConfig, E>,
) -> Result<Vec<String>, ComputeError> {
    match config {
        Ok(c) => Ok(named_volumes(&c)),
        Err(e) => Err(crate::error::runtime(
            "read the sandbox configuration",
            &format!(
                "the configuration stored for sandbox `{name}` in msb's database cannot be read ({e}), \
                 so its volumes are unknown and the single-writer check cannot run; remove the \
                 sandbox (its volumes are kept) and create it again"
            ),
        )),
    }
}

/// `name` as a [`Mounter`]. A sandbox that is down holds nothing, so an unreadable configuration
/// only matters (and fails) for one that is up or coming up.
pub(crate) fn mounter<E: std::fmt::Display>(
    name: &str,
    status: WorkspaceStatus,
    config: Result<SandboxConfig, E>,
) -> Result<Mounter, ComputeError> {
    let volumes = if status.is_down() {
        config.map_or_else(
            |e| {
                tracing::warn!(sandbox = name, error = %e, "the stored configuration of a stopped sandbox cannot be read; starting it will refuse");
                Vec::new()
            },
            |c| named_volumes(&c),
        )
    } else {
        mounted_volumes(name, config)?
    };
    Ok(Mounter {
        name: name.to_owned(),
        status,
        volumes,
    })
}

/// Volume name → the running sandbox that holds it. With two running holders (which msb
/// shouldn't allow), the first in name order is reported.
pub(crate) fn holders(mounters: &[Mounter]) -> BTreeMap<String, String> {
    let mut sorted: Vec<&Mounter> = mounters
        .iter()
        .filter(|m| m.status == WorkspaceStatus::Running)
        .collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = BTreeMap::new();
    for m in sorted {
        for v in &m.volumes {
            out.entry(v.clone()).or_insert_with(|| m.name.clone());
        }
    }
    out
}

/// Capacity in MiB from the catalog: the disk size, else the directory quota, else 0.
pub(crate) fn size_mib(capacity_bytes: Option<u64>, quota_mib: Option<u32>) -> DiskSize {
    let mib = capacity_bytes
        .map(|b| u32::try_from(b / (1024 * 1024)).unwrap_or(u32::MAX))
        .or(quota_mib)
        .unwrap_or(0);
    DiskSize::mib(mib)
}

/// The catalog entry as a [`VolumeInfo`].
pub(crate) fn info(handle: &VolumeHandle, holders: &BTreeMap<String, String>) -> VolumeInfo {
    VolumeInfo {
        name: handle.name().to_owned(),
        size: size_mib(handle.capacity_bytes(), handle.quota_mib()),
        holder: holders.get(handle.name()).cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, status: WorkspaceStatus, volumes: &[&str]) -> Mounter {
        Mounter {
            name: name.into(),
            status,
            volumes: volumes.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    #[test]
    fn only_running_sandboxes_hold_volumes() {
        let h = holders(&[
            m("stopped", WorkspaceStatus::Stopped, &["ws-a"]),
            m("crashed", WorkspaceStatus::Crashed, &["ws-b"]),
            m("running", WorkspaceStatus::Running, &["ws-a", "ws-c"]),
        ]);
        assert_eq!(h.get("ws-a").map(String::as_str), Some("running"));
        assert_eq!(h.get("ws-c").map(String::as_str), Some("running"));
        assert_eq!(h.get("ws-b"), None);
    }

    #[test]
    fn two_running_holders_report_the_first_by_name() {
        let h = holders(&[
            m("zeta", WorkspaceStatus::Running, &["ws-a"]),
            m("alpha", WorkspaceStatus::Running, &["ws-a"]),
        ]);
        assert_eq!(h.get("ws-a").map(String::as_str), Some("alpha"));
    }

    #[test]
    fn sizes_come_from_capacity_then_quota() {
        assert_eq!(size_mib(Some(256 * 1024 * 1024), None), DiskSize::mib(256));
        assert_eq!(
            size_mib(Some(256 * 1024 * 1024 + 5), Some(7)),
            DiskSize::mib(256)
        );
        assert_eq!(size_mib(None, Some(7)), DiskSize::mib(7));
        assert_eq!(size_mib(None, None), DiskSize::mib(0));
        assert_eq!(size_mib(Some(u64::MAX), None), DiskSize::mib(u32::MAX));
    }

    fn bad_config() -> Result<SandboxConfig, String> {
        Err("missing field `spec`".to_owned())
    }

    #[test]
    fn an_unreadable_config_of_a_running_sandbox_is_an_error_naming_it() {
        for status in [WorkspaceStatus::Running, WorkspaceStatus::Starting] {
            let err = mounter("ws-a", status, bad_config())
                .unwrap_err()
                .to_string();
            assert!(err.contains("`ws-a`"), "{err}");
            assert!(err.contains("missing field `spec`"), "{err}");
            assert!(err.contains("remove the sandbox"), "{err}");
        }
    }

    #[test]
    fn an_unreadable_config_of_a_stopped_sandbox_holds_nothing() {
        let m = mounter("ws-a", WorkspaceStatus::Stopped, bad_config()).unwrap();
        assert_eq!(m.volumes, Vec::<String>::new());
    }

    #[test]
    fn a_readable_config_of_a_stopped_sandbox_keeps_its_volumes() {
        let mut config = SandboxConfig::default();
        config.spec.mounts = vec![VolumeMount::Named {
            name: "ws-a".into(),
            guest: "/w".into(),
            create: None,
            options: microsandbox::sandbox::MountOptions::default(),
            stat_virtualization: microsandbox::sandbox::StatVirtualization::Strict,
            host_permissions: microsandbox::sandbox::HostPermissions::Private,
            follow_root_symlinks: false,
        }];
        let m = mounter("s", WorkspaceStatus::Stopped, Ok::<_, String>(config)).unwrap();
        assert_eq!(m.volumes, ["ws-a"]);
    }

    #[test]
    fn mounted_volumes_fail_on_an_unreadable_config() {
        let err = mounted_volumes("ws-a", bad_config())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`ws-a`") && err.contains("single-writer"),
            "{err}"
        );
        assert_eq!(
            mounted_volumes("ws-a", Ok::<_, String>(SandboxConfig::default())).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn named_volumes_are_read_from_the_config() {
        let mut config = SandboxConfig::default();
        config.spec.mounts = vec![
            VolumeMount::Named {
                name: "ws-a".into(),
                guest: "/w".into(),
                create: None,
                options: microsandbox::sandbox::MountOptions::default(),
                stat_virtualization: microsandbox::sandbox::StatVirtualization::Strict,
                host_permissions: microsandbox::sandbox::HostPermissions::Private,
                follow_root_symlinks: false,
            },
            VolumeMount::Bind {
                host: "/h".into(),
                guest: "/b".into(),
                options: microsandbox::sandbox::MountOptions::default(),
                stat_virtualization: microsandbox::sandbox::StatVirtualization::Strict,
                host_permissions: microsandbox::sandbox::HostPermissions::Private,
                follow_root_symlinks: false,
                quota_mib: None,
            },
        ];
        assert_eq!(named_volumes(&config), ["ws-a"]);
    }
}
