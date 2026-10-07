// SPDX-License-Identifier: GPL-3.0-or-later
//! Test helpers for code that sets owner-only ACLs: read a handle's DACL back as the OS reports
//! it, and open files from a thread impersonating a restricted copy of this process's token.
//! Behind the `testing` feature; never in product code.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test helpers fail the test by panicking"
)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateRestrictedToken,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, ImpersonateLoggedOnUser, LOGON32_LOGON_NETWORK,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSECURITY_DESCRIPTOR, RevertToSelf, SE_DACL_PROTECTED,
    SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
    WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid, WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use super::{LocalBox, TokenUserBuf, process_token, wide_nul};

/// Broad groups the user belongs to: a token restricted to these can do what "everyone logged
/// on" may do, but nothing granted to the user's own SID.
const BROAD_GROUPS: [WELL_KNOWN_SID_TYPE; 4] = [
    WinWorldSid,
    WinAuthenticatedUserSid,
    WinBuiltinUsersSid,
    WinInteractiveSid,
];

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Vec<u64> {
    let mut buf = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `buf` holds SECURITY_MAX_SID_SIZE bytes; no domain SID is needed for these.
    let ok =
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buf.as_mut_ptr().cast(), &raw mut len) };
    assert_ne!(
        ok,
        0,
        "CreateWellKnownSid({kind}): {}",
        io::Error::last_os_error()
    );
    buf
}

/// Opens `path` with `access` from a thread impersonating a restricted copy of this process's
/// token whose restricting SIDs are the broad groups, plus the user's SID when `include_user`.
///
/// # Errors
///
/// The OS error of the open, if any.
pub fn open_restricted(path: &Path, access: u32, include_user: bool) -> io::Result<()> {
    let path = wide_nul(path.as_os_str());
    std::thread::spawn(move || {
        let token = process_token(TOKEN_DUPLICATE | TOKEN_QUERY)?;
        let user = TokenUserBuf::read(&token)?;
        let groups: Vec<Vec<u64>> = BROAD_GROUPS.iter().map(|k| well_known_sid(*k)).collect();
        let mut restrict: Vec<SID_AND_ATTRIBUTES> = groups
            .iter()
            .map(|g| SID_AND_ATTRIBUTES {
                Sid: g.as_ptr().cast_mut().cast(),
                Attributes: 0,
            })
            .collect();
        if include_user {
            restrict.push(SID_AND_ATTRIBUTES {
                Sid: user.sid(),
                Attributes: 0,
            });
        }
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: `token` is valid with TOKEN_DUPLICATE; `restrict` points at SIDs that outlive
        // the call; `raw` is a valid out-pointer.
        let ok = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                0,
                0,
                ptr::null(),
                0,
                ptr::null(),
                u32::try_from(restrict.len()).unwrap(),
                restrict.as_ptr(),
                &raw mut raw,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh token handle that nothing else owns.
        let restricted = unsafe { OwnedHandle::from_raw_handle(raw) };
        open_impersonating(&restricted, &path, access)
    })
    .join()
    .unwrap()
}

/// Opens the NUL-terminated `path` with `access` while this thread impersonates `token`.
///
/// # Errors
///
/// The OS error of the impersonation or the open.
pub fn open_impersonating(token: &OwnedHandle, path: &[u16], access: u32) -> io::Result<()> {
    // SAFETY: impersonation is undone below on this same thread, before it returns.
    if unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `path` is NUL-terminated; null security attributes and template are allowed.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    let result = if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a fresh file handle that nothing else owns; dropping it closes it.
        drop(unsafe { OwnedHandle::from_raw_handle(handle) });
        Ok(())
    };
    // SAFETY: ends this thread's impersonation.
    let reverted = unsafe { RevertToSelf() };
    assert_ne!(reverted, 0, "RevertToSelf failed");
    result
}

/// Asserts `result` is an access-denied error.
pub fn assert_access_denied(result: io::Result<()>) {
    let err = result.expect_err("the open should have been refused");
    assert_eq!(
        err.raw_os_error(),
        Some(i32::try_from(ERROR_ACCESS_DENIED).unwrap()),
        "{err}"
    );
}

/// Asserts that the DACL of the open object `object` (a file, folder or pipe) is protected from
/// inheritance and holds exactly one ACE: an allow entry for the current user with `mask`.
pub fn assert_owner_only_dacl(object: &impl AsRawHandle, mask: u32) {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL; the out pointers are valid; `descriptor` is
    // freed by `_owned`.
    let rc = unsafe {
        GetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    assert_eq!(
        rc,
        0,
        "GetSecurityInfo: {}",
        io::Error::from_raw_os_error(rc.cast_signed())
    );
    // SAFETY: GetSecurityInfo allocated `descriptor` with LocalAlloc.
    let _owned = unsafe { LocalBox::from_raw(descriptor) };
    assert!(!dacl.is_null(), "a null DACL grants everyone everything");

    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: `descriptor` is valid; both out-pointers are valid.
    let ok =
        unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) };
    assert_ne!(
        ok,
        0,
        "GetSecurityDescriptorControl: {}",
        io::Error::last_os_error()
    );
    assert_ne!(
        u32::from(control) & u32::from(SE_DACL_PROTECTED),
        0,
        "the DACL still inherits from the parent"
    );

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into `descriptor`; `info` is the right size for the class.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap(),
            AclSizeInformation,
        )
    };
    assert_ne!(ok, 0, "GetAclInformation: {}", io::Error::last_os_error());
    assert_eq!(info.AceCount, 1, "the DACL must hold only the user's ACE");

    let mut ace: *mut c_void = ptr::null_mut();
    // SAFETY: index 0 exists (AceCount is 1); `ace` points into the DACL.
    let ok = unsafe { GetAce(dacl, 0, &raw mut ace) };
    assert_ne!(ok, 0, "GetAce: {}", io::Error::last_os_error());
    // SAFETY: the ACE type is checked before the ACE is read as ACCESS_ALLOWED_ACE.
    let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    assert_eq!(u32::from(ace.Header.AceType), ACCESS_ALLOWED_ACE_TYPE);
    assert_eq!(ace.Mask, mask);

    let token = process_token(TOKEN_QUERY).unwrap();
    let user = TokenUserBuf::read(&token).unwrap();
    // SAFETY: both are valid SIDs; the ACE's SID starts at SidStart.
    let same = unsafe { EqualSid((&raw const ace.SidStart).cast_mut().cast(), user.sid()) };
    assert_ne!(same, 0, "the ACE is not for the current user");
}

/// Logs the local account `name` on over the network (no "log on locally" right needed) and
/// returns its token, or `None` if the logon fails.
#[must_use]
pub fn logon_local_user(name: &str, password: &str) -> Option<OwnedHandle> {
    let (name, password) = (wide_nul(name.as_ref()), wide_nul(password.as_ref()));
    let local = wide_nul(".".as_ref());
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: the three strings are NUL-terminated and outlive the call; `raw` is a valid
    // out-pointer.
    let ok = unsafe {
        LogonUserW(
            name.as_ptr(),
            local.as_ptr(),
            password.as_ptr(),
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            &raw mut raw,
        )
    };
    // SAFETY: on success `raw` is a fresh token handle that nothing else owns.
    (ok != 0).then(|| unsafe { OwnedHandle::from_raw_handle(raw) })
}
