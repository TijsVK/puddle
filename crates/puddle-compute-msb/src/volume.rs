// SPDX-License-Identifier: GPL-3.0-or-later
//! Named volumes: who holds one, and the catalog view as [`VolumeInfo`].
//!
//! msb's own refusal of a second attach doesn't name the holder (T-028), so puddle works it out:
//! the holder is the running sandbox whose configuration mounts the volume (ADR 0006 point 8).

use std::collections::BTreeMap;

use microsandbox::sandbox::{SandboxConfig, VolumeMount};
use microsandbox::volume::VolumeHandle;
use puddle_compute::{DiskSize, VolumeInfo};
use puddle_types::SandboxStatus;

/// One sandbox as the holder lookup needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mounter {
    /// The sandbox.
    pub name: String,
    /// Its state.
    pub status: SandboxStatus,
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

/// Volume name → the running sandbox that holds it. With two running holders (which msb
/// shouldn't allow), the first in name order is reported.
pub(crate) fn holders(mounters: &[Mounter]) -> BTreeMap<String, String> {
    let mut sorted: Vec<&Mounter> = mounters
        .iter()
        .filter(|m| m.status == SandboxStatus::Running)
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

    fn m(name: &str, status: SandboxStatus, volumes: &[&str]) -> Mounter {
        Mounter {
            name: name.into(),
            status,
            volumes: volumes.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    #[test]
    fn only_running_sandboxes_hold_volumes() {
        let h = holders(&[
            m("stopped", SandboxStatus::Stopped, &["ws-a"]),
            m("crashed", SandboxStatus::Crashed, &["ws-b"]),
            m("running", SandboxStatus::Running, &["ws-a", "ws-c"]),
        ]);
        assert_eq!(h.get("ws-a").map(String::as_str), Some("running"));
        assert_eq!(h.get("ws-c").map(String::as_str), Some("running"));
        assert_eq!(h.get("ws-b"), None);
    }

    #[test]
    fn two_running_holders_report_the_first_by_name() {
        let h = holders(&[
            m("zeta", SandboxStatus::Running, &["ws-a"]),
            m("alpha", SandboxStatus::Running, &["ws-a"]),
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
