// SPDX-License-Identifier: GPL-3.0-or-later
//! The Win32 calls: job objects and the console control handler. Every `unsafe` block of the
//! crate is here.
#![expect(unsafe_code, reason = "Win32 job object and console handler calls")]

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::BOOL;

/// An owned job object handle.
#[derive(Debug)]
pub(crate) struct Job {
    handle: HANDLE,
}

// SAFETY: a job handle is a kernel handle; Win32 job calls may be made from any thread.
unsafe impl Send for Job {}
// SAFETY: as above; `Job` has no interior state besides the handle value.
unsafe impl Sync for Job {}

impl Job {
    /// A new, unnamed job with `limits` as its limit flags. The handle is not inheritable.
    pub(crate) fn create(limits: JOB_OBJECT_LIMIT) -> io::Result<Self> {
        // SAFETY: null attributes (default security, not inheritable) and a null name are valid.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Self { handle };
        job.set_limits(limits)?;
        Ok(job)
    }

    /// Replaces the job's limit flags.
    pub(crate) fn set_limits(&self, limits: JOB_OBJECT_LIMIT) -> io::Result<()> {
        // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid value (no limits).
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = limits;
        let size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(io::Error::other)?;
        // SAFETY: `info` is a live, correctly sized value of the type the class expects.
        let ok = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size,
            )
        };
        check(ok)
    }

    /// Puts the current process in the job.
    pub(crate) fn assign_current_process(&self) -> io::Result<()> {
        // SAFETY: the pseudo handle of the current process needs no closing; `self.handle` is
        // a live job handle.
        let ok = unsafe { AssignProcessToJobObject(self.handle, GetCurrentProcess()) };
        check(ok)
    }

    /// Whether the current process is in the job.
    pub(crate) fn contains_current_process(&self) -> io::Result<bool> {
        // SAFETY: the pseudo handle of the current process is always valid.
        self.contains_raw(unsafe { GetCurrentProcess() })
    }

    /// Whether `process` is in the job.
    #[cfg(test)]
    pub(crate) fn contains(
        &self,
        process: std::os::windows::io::BorrowedHandle<'_>,
    ) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        self.contains_raw(process.as_raw_handle())
    }

    fn contains_raw(&self, process: HANDLE) -> io::Result<bool> {
        let mut result: BOOL = 0;
        // SAFETY: `process` and `self.handle` are live handles; `result` is a live out pointer.
        let ok = unsafe { IsProcessInJob(process, self.handle, &raw mut result) };
        check(ok)?;
        Ok(result != 0)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed exactly once.
        let _closed = unsafe { CloseHandle(self.handle) };
    }
}

/// The console control handler: forwards every event to [`super::front::on_console_event`].
/// Windows runs it on a thread of its own.
unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
    BOOL::from(super::front::on_console_event(ctrl_type))
}

/// Installs [`handler`] in front of the default one (which ends the process).
pub(crate) fn install_console_handler() -> io::Result<()> {
    // SAFETY: `handler` is a valid `extern "system"` function for the whole process lifetime.
    let ok = unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
    check(ok)
}

fn check(ok: BOOL) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
