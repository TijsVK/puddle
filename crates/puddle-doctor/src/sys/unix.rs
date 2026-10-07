// SPDX-License-Identifier: GPL-3.0-or-later
//! What every Unix shares: file permissions, and the Windows-only checks reporting nothing.
//! `linux.rs` and `macos.rs` hold the hypervisor probes.

use std::io;
use std::path::Path;

use crate::facts::{CodeIntegrity, GsaFacts, JobFacts};

/// Hypervisor facts for a Unix that is neither Linux nor macOS: no API is known.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn hypervisor() -> crate::facts::HypervisorFacts {
    use crate::facts::{HypervisorApi, HypervisorFacts};
    HypervisorFacts {
        api: HypervisorApi::Unsupported,
        firmware_virtualization: None,
        hypervisor_vendor: super::hypervisor_vendor(),
    }
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
    }
}
