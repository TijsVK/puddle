// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux probes: KVM and the CPU's virtualization flags.

use std::io;
use std::path::Path;

use crate::facts::{HypervisorApi, HypervisorFacts};

const KVM: &str = "/dev/kvm";

pub(crate) fn hypervisor() -> HypervisorFacts {
    let firmware_virtualization = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|info| cpu_has_virtualization(&info));
    HypervisorFacts {
        api: kvm_state(Path::new(KVM)),
        firmware_virtualization,
        hypervisor_vendor: super::hypervisor_vendor(),
    }
}

fn kvm_state(dev: &Path) -> HypervisorApi {
    match std::fs::OpenOptions::new().read(true).write(true).open(dev) {
        Ok(_) => HypervisorApi::Ready,
        Err(e) if e.kind() == io::ErrorKind::NotFound => HypervisorApi::NotInstalled {
            detail: format!("{}: {e}", dev.display()),
        },
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => HypervisorApi::AccessDenied {
            detail: format!("{}: {e}", dev.display()),
        },
        Err(e) => HypervisorApi::QueryFailed {
            detail: format!("{}: {e}", dev.display()),
        },
    }
}

/// Whether `/proc/cpuinfo` lists the VT-x (`vmx`) or AMD-V (`svm`) flag.
fn cpu_has_virtualization(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .filter(|l| l.starts_with("flags"))
        .flat_map(str::split_whitespace)
        .any(|f| f == "vmx" || f == "svm")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_flags() {
        assert!(cpu_has_virtualization(
            "processor: 0\nflags\t\t: fpu vmx sse\n"
        ));
        assert!(cpu_has_virtualization("flags : svm"));
        assert!(!cpu_has_virtualization(
            "flags : fpu sse\nvmx: listed elsewhere\n"
        ));
        assert!(!cpu_has_virtualization(""));
    }

    #[test]
    fn kvm_states() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            kvm_state(&dir.path().join("kvm")),
            HypervisorApi::NotInstalled { .. }
        ));
        let dev = dir.path().join("dev");
        std::fs::write(&dev, b"").unwrap();
        assert_eq!(kvm_state(&dev), HypervisorApi::Ready);
        assert!(matches!(
            kvm_state(dir.path()),
            HypervisorApi::QueryFailed { .. }
        ));
    }

    #[test]
    fn the_probe_names_kvm_and_does_not_panic() {
        let _facts = hypervisor();
    }
}
