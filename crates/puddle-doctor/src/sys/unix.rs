// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux (and other unix) probes: KVM, file permissions. The Windows-only checks report nothing.

use std::io;
use std::path::Path;

use crate::facts::{CodeIntegrity, GsaFacts, HypervisorApi, HypervisorFacts, JobFacts};

const KVM: &str = "/dev/kvm";

pub(crate) fn hypervisor() -> HypervisorFacts {
    let api = if cfg!(target_os = "linux") {
        kvm_state(Path::new(KVM))
    } else {
        HypervisorApi::Unsupported
    };
    let firmware_virtualization = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|info| cpu_has_virtualization(&info));
    HypervisorFacts {
        api,
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

pub(crate) fn code_integrity() -> Option<CodeIntegrity> {
    None
}

pub(crate) fn job() -> Option<JobFacts> {
    None
}

pub(crate) fn global_secure_access() -> Option<GsaFacts> {
    None
}

/// Whether this user may read and run `path`.
pub(crate) fn file_access(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let file = std::fs::File::open(path)?;
    if file.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not executable",
        ));
    }
    Ok(())
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
    fn file_access_needs_read_and_execute() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("msb");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            file_access(&f).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        file_access(&f).unwrap();
        assert!(file_access(&dir.path().join("none")).is_err());
    }

    #[test]
    fn windows_only_checks_are_absent() {
        assert_eq!(code_integrity(), None);
        assert_eq!(job(), None);
        assert_eq!(global_secure_access(), None);
        let _facts = hypervisor();
    }
}
