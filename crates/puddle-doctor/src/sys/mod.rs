// SPDX-License-Identifier: GPL-3.0-or-later
//! The platform probes behind [`crate::SystemProbe`]: the same functions on every OS, the OS
//! calls in `windows.rs` (the crate's only `unsafe`), `linux.rs` and `macos.rs`; `unix.rs` holds
//! what the Unixes share.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::hypervisor;
#[cfg(target_os = "macos")]
pub(crate) use macos::hypervisor;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) use unix::hypervisor;
#[cfg(unix)]
pub(crate) use unix::{code_integrity, file_access, global_secure_access, job};
#[cfg(windows)]
pub(crate) use windows::{code_integrity, file_access, global_secure_access, hypervisor, job};

#[cfg(not(any(unix, windows)))]
compile_error!("puddle-doctor supports unix and windows hosts");

/// The vendor of the hypervisor this OS runs under or beside, from CPUID (`None` when the
/// hypervisor-present bit is clear or the CPU isn't x86-64).
#[must_use]
pub(crate) fn hypervisor_vendor() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::__cpuid;
        // Leaf 1, ECX bit 31: a hypervisor is present.
        if __cpuid(1).ecx & (1 << 31) == 0 {
            return None;
        }
        let r = __cpuid(0x4000_0000);
        let mut bytes = Vec::with_capacity(12);
        for reg in [r.ebx, r.ecx, r.edx] {
            bytes.extend_from_slice(&reg.to_le_bytes());
        }
        Some(vendor_name(&bytes))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// The printable part of a CPUID vendor signature, or `unknown`.
fn vendor_name(bytes: &[u8]) -> String {
    let s: String = bytes
        .iter()
        .take_while(|b| **b != 0)
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| char::from(*b))
        .collect();
    let s = s.trim();
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_names() {
        assert_eq!(vendor_name(b"Microsoft Hv"), "Microsoft Hv");
        assert_eq!(vendor_name(b"KVMKVMKVM\0\0\0"), "KVMKVMKVM");
        assert_eq!(vendor_name(b"\0\0\0\0"), "unknown");
        assert_eq!(vendor_name(b"\x01\x02"), "unknown");
    }

    #[test]
    fn vendor_probe_does_not_panic() {
        let _any = hypervisor_vendor();
    }
}
