// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows probes. Every call works without administrator rights. This module holds the crate's
//! only `unsafe` code: plain Win32 calls with stack buffers whose sizes are passed alongside.

use std::ffi::c_void;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemCodeIntegrityInformation,
};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, FreeLibrary, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{FILE_EXECUTE, FILE_READ_DATA, SYNCHRONIZE};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    QueryInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, IsProcessorFeaturePresent, PF_VIRT_FIRMWARE_ENABLED,
};
use windows_sys::Win32::System::WindowsProgramming::{
    CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED, CODEINTEGRITY_OPTION_TESTSIGN,
    CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED, CODEINTEGRITY_OPTION_UMCI_ENABLED,
    SYSTEM_CODEINTEGRITY_INFORMATION,
};

use crate::facts::{CodeIntegrity, GsaFacts, HypervisorApi, HypervisorFacts, JobFacts};

/// The services of the Microsoft Entra Global Secure Access client.
pub(crate) const GSA_SERVICES: [&str; 4] = [
    "GlobalSecureAccessEngineService",
    "GlobalSecureAccessTunnelingService",
    "GlobalSecureAccessPolicyRetrieverService",
    "GlobalSecureAccessClientManagerService",
];

/// `WHvCapabilityCodeHypervisorPresent`.
const WHV_CAPABILITY_HYPERVISOR_PRESENT: i32 = 0;

type WhvGetCapability = unsafe extern "system" fn(i32, *mut c_void, u32, *mut u32) -> i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub(crate) fn hypervisor() -> HypervisorFacts {
    // SAFETY: no arguments besides a constant; returns a BOOL.
    #[expect(unsafe_code, reason = "Win32 call")]
    let firmware = unsafe { IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED) } != 0;
    HypervisorFacts {
        api: whp(),
        firmware_virtualization: Some(firmware),
        hypervisor_vendor: super::hypervisor_vendor(),
    }
}

/// Loads `WinHvPlatform.dll` from System32 only (never the working directory) and asks whether a
/// hypervisor is present. msb links that DLL statically, so it must not be missing.
#[expect(
    unsafe_code,
    reason = "loading WinHvPlatform.dll and calling WHvGetCapability"
)]
fn whp() -> HypervisorApi {
    let name = wide("WinHvPlatform.dll");
    // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the call; no file handle.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return HypervisorApi::NotInstalled {
            detail: format!("WinHvPlatform.dll: {}", io::Error::last_os_error()),
        };
    }
    // SAFETY: `module` is the handle just loaded; the name is a NUL-terminated ASCII string.
    let proc = unsafe { GetProcAddress(module, c"WHvGetCapability".as_ptr().cast()) };
    let result = match proc {
        None => HypervisorApi::QueryFailed {
            detail: format!("WHvGetCapability: {}", io::Error::last_os_error()),
        },
        Some(proc) => {
            // SAFETY: the export of that name has this signature (WinHvPlatform.h).
            let get: WhvGetCapability = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, WhvGetCapability>(proc)
            };
            // WHV_CAPABILITY is a union of at most a few dozen bytes; 1 KiB, 8-aligned, holds it.
            let mut buf = [0_u64; 128];
            let mut written = 0_u32;
            // SAFETY: the buffer and its byte length match; `written` is a valid out pointer.
            let hr = unsafe {
                get(
                    WHV_CAPABILITY_HYPERVISOR_PRESENT,
                    buf.as_mut_ptr().cast(),
                    1024,
                    &raw mut written,
                )
            };
            if hr < 0 {
                HypervisorApi::QueryFailed {
                    detail: format!("WHvGetCapability failed: HRESULT 0x{hr:08X}"),
                }
            } else if written < 4 {
                HypervisorApi::QueryFailed {
                    detail: format!("WHvGetCapability returned {written} bytes"),
                }
            } else if hypervisor_present(buf[0]) {
                HypervisorApi::Ready
            } else {
                HypervisorApi::NotRunning
            }
        }
    };
    // SAFETY: `module` came from LoadLibraryExW and is freed once; nothing from it is kept.
    unsafe { FreeLibrary(module) };
    result
}

/// `WHV_CAPABILITY.HypervisorPresent`: a `BOOL` in the first four bytes of the union.
fn hypervisor_present(first: u64) -> bool {
    let [a, b, c, d, ..] = first.to_ne_bytes();
    u32::from_ne_bytes([a, b, c, d]) != 0
}

#[expect(unsafe_code, reason = "NtQuerySystemInformation")]
pub(crate) fn code_integrity() -> Option<CodeIntegrity> {
    let mut info = SYSTEM_CODEINTEGRITY_INFORMATION {
        Length: u32::try_from(size_of::<SYSTEM_CODEINTEGRITY_INFORMATION>()).ok()?,
        CodeIntegrityOptions: 0,
    };
    let mut len = 0_u32;
    // SAFETY: `info` is the documented struct for this class, its size passed alongside.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemCodeIntegrityInformation,
            (&raw mut info).cast(),
            info.Length,
            &raw mut len,
        )
    };
    if status < 0 {
        return None;
    }
    let o = info.CodeIntegrityOptions;
    Some(CodeIntegrity {
        hvci: o & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED != 0,
        user_mode_enforced: o & CODEINTEGRITY_OPTION_UMCI_ENABLED != 0
            && o & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED == 0,
        user_mode_audit: o & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED != 0,
        test_signing: o & CODEINTEGRITY_OPTION_TESTSIGN != 0,
    })
}

#[expect(unsafe_code, reason = "IsProcessInJob and QueryInformationJobObject")]
pub(crate) fn job() -> Option<JobFacts> {
    let mut in_job = 0;
    // SAFETY: the pseudo handle of this process, no job handle (any job), a valid out pointer.
    let ok = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &raw mut in_job) };
    if ok == 0 || in_job == 0 {
        return None;
    }
    // SAFETY: all-zero is a valid value of this plain-data struct.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).ok()?;
    // SAFETY: a null job handle means this process's own (innermost) job; buffer and size match.
    let ok = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            size,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    let flags = info.BasicLimitInformation.LimitFlags;
    Some(JobFacts {
        breakaway_allowed: flags
            & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            != 0,
    })
}

#[expect(unsafe_code, reason = "Service Control Manager queries")]
pub(crate) fn global_secure_access() -> Option<GsaFacts> {
    // SAFETY: local machine, default database, connect right only (no admin needed).
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return None;
    }
    let mut installed = false;
    let mut running = false;
    for name in GSA_SERVICES {
        let w = wide(name);
        // SAFETY: `scm` is open; `w` is NUL-terminated and outlives the call.
        let svc = unsafe { OpenServiceW(scm, w.as_ptr(), SERVICE_QUERY_STATUS) };
        if svc.is_null() {
            // SAFETY: reads this thread's last error, set by OpenServiceW just above.
            // Access denied: it exists, we just may not ask about it. Anything else (usually
            // ERROR_SERVICE_DOES_NOT_EXIST): not installed.
            if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
                installed = true;
            }
            continue;
        }
        installed = true;
        // SAFETY: all-zero is a valid value of this plain-data struct.
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        // SAFETY: `svc` is open with SERVICE_QUERY_STATUS; `status` is a valid out pointer.
        if unsafe { QueryServiceStatus(svc, &raw mut status) } != 0
            && status.dwCurrentState == SERVICE_RUNNING
        {
            running = true;
        }
        // SAFETY: closes the handle opened above, once.
        unsafe { CloseServiceHandle(svc) };
    }
    // SAFETY: closes the manager handle opened above, once.
    unsafe { CloseServiceHandle(scm) };
    Some(if installed {
        GsaFacts::Installed { running }
    } else {
        GsaFacts::NotInstalled
    })
}

/// Whether this user may read and run `path`: opens it with read-data and execute rights, which
/// is what process creation needs, so a deny ACE on either shows here.
pub(crate) fn file_access(path: &Path) -> io::Result<()> {
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE)
        .open(path)
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_answer_without_admin_rights() {
        // Values depend on the machine; each call must return without failing.
        let _hv = hypervisor();
        let _ci = code_integrity();
        let _job = job();
        assert!(global_secure_access().is_some());
    }

    #[test]
    fn hypervisor_present_reads_the_first_bool() {
        assert!(!hypervisor_present(0));
        assert!(hypervisor_present(1));
        assert!(!hypervisor_present(0xFFFF_FFFF_0000_0000));
    }

    #[test]
    fn wide_strings_are_nul_terminated() {
        assert_eq!(wide("ab"), [97, 98, 0]);
    }
}
