// SPDX-License-Identifier: GPL-3.0-or-later
//! The crate's only unsafe code: reading the current user's SID and creating a pipe instance with
//! an explicit security descriptor. Every raw resource is owned by a guard that frees it.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_ACCESS_MASK,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The current user's SID in string form (`S-1-5-21-...`).
pub(super) fn current_user_sid() -> io::Result<String> {
    let token = process_token(TOKEN_QUERY)?;
    let user = TokenUserBuf::read(&token)?;
    sid_to_string(user.sid())
}

/// Creates one pipe instance whose security descriptor is `sddl`.
pub(super) fn create_pipe(
    options: &ServerOptions,
    path: &OsStr,
    sddl: &str,
) -> io::Result<NamedPipeServer> {
    let descriptor = LocalBox::security_descriptor(sddl)?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: SECURITY_ATTRIBUTES_LEN,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES for the whole call, and the descriptor it
    // points at (`descriptor`) is freed only after the call returns.
    unsafe { options.create_with_security_attributes_raw(path, (&raw mut attrs).cast::<c_void>()) }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "SECURITY_ATTRIBUTES is 24 bytes"
)]
const SECURITY_ATTRIBUTES_LEN: u32 = size_of::<SECURITY_ATTRIBUTES>() as u32;

/// Opens this process's token with `access`.
fn process_token(access: TOKEN_ACCESS_MASK) -> io::Result<OwnedHandle> {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing; `raw` is a valid
    // out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &raw mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `raw` is a fresh token handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// A `TOKEN_USER` read from a token, in a buffer aligned for it.
struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    fn read(token: &OwnedHandle) -> io::Result<Self> {
        let mut len = 0u32;
        // SAFETY: a null buffer of length 0 is allowed; the call only writes the needed size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &raw mut len,
            );
        }
        let words = usize::try_from(len)
            .map_err(io::Error::other)?
            .div_ceil(8)
            .max(size_of::<TOKEN_USER>().div_ceil(8));
        let mut buf = vec![0u64; words];
        let cap = u32::try_from(words * 8).map_err(io::Error::other)?;
        // SAFETY: `buf` is writable for `cap` bytes and 8-byte aligned (enough for TOKEN_USER).
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buf.as_mut_ptr().cast::<c_void>(),
                cap,
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buf))
    }

    /// The user's SID; valid while `self` lives.
    fn sid(&self) -> PSID {
        // SAFETY: `read` filled the buffer with a TOKEN_USER at its start (the buffer is at least
        // that large and aligned for it); the SID it points at lies inside the same buffer.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut wide: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `wide` receives a LocalAlloc'd string we free below.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = LocalBox(wide.cast::<c_void>());
    // SAFETY: the call above returned a NUL-terminated UTF-16 string at `wide`, alive until
    // `owned` drops at the end of this function.
    let text = unsafe {
        let mut len = 0usize;
        while *wide.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(wide, len))
    };
    drop(owned);
    Ok(text)
}

fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Memory the OS allocated with `LocalAlloc`, freed on drop.
struct LocalBox(*mut c_void);

impl LocalBox {
    fn security_descriptor(sddl: &str) -> io::Result<Self> {
        let text = wide_nul(OsStr::new(sddl));
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated and outlives the call; `descriptor` is a valid
        // out-pointer; the size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that allocates with LocalAlloc, and is freed
            // exactly once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    //! HO-1 on a real pipe: the DACL as the OS reports it, and clients under restricted tokens.

    use super::*;
    use crate::IpcRoot;
    use std::path::Path;
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateRestrictedToken,
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        ImpersonateLoggedOnUser, RevertToSelf, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES,
        TOKEN_DUPLICATE, WELL_KNOWN_SID_TYPE, WinAuthenticatedUserSid, WinBuiltinUsersSid,
        WinInteractiveSid, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_ALL_ACCESS, OPEN_EXISTING};
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    /// Broad groups the user belongs to: a token restricted to these can do what "everyone
    /// logged on" may do, but nothing granted to the user's own SID.
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
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), buf.as_mut_ptr().cast(), &raw mut len)
        };
        assert_ne!(
            ok,
            0,
            "CreateWellKnownSid({kind}): {}",
            io::Error::last_os_error()
        );
        buf
    }

    /// Opens `path` with `access` from a thread impersonating a restricted copy of this
    /// process's token whose restricting SIDs are `BROAD_GROUPS`, plus the user's SID when
    /// `include_user`. Returns the OS error of the open, if any.
    fn open_restricted(path: &Path, access: u32, include_user: bool) -> io::Result<()> {
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
            // SAFETY: `token` is valid with TOKEN_DUPLICATE; `restrict` points at SIDs that
            // outlive the call; `raw` is a valid out-pointer.
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
            // SAFETY: impersonation is undone below on this same thread, before it ends.
            if unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) } == 0 {
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
        })
        .join()
        .unwrap()
    }

    fn assert_access_denied(result: io::Result<()>) {
        let err = result.expect_err("a restricted client opened the pipe");
        assert_eq!(
            err.raw_os_error(),
            Some(i32::try_from(ERROR_ACCESS_DENIED).unwrap()),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_restricted_token_client_is_refused() {
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        let path = listener.endpoint().path().to_path_buf();
        assert_access_denied(open_restricted(&path, GENERIC_READ | GENERIC_WRITE, false));
        // Read alone is what the default DACL gives Everyone; ours must not.
        assert_access_denied(open_restricted(&path, GENERIC_READ, false));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_restricted_token_with_the_user_sid_gets_in() {
        // Positive control: the same restricted token plus the user's SID opens the pipe, so the
        // refusal above comes from the DACL, not from the restricted-token setup.
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        open_restricted(
            listener.endpoint().path(),
            GENERIC_READ | GENERIC_WRITE,
            true,
        )
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_default_dacl_would_let_the_restricted_client_read() {
        // Negative control: a pipe with Windows' default DACL (what the PoC had) lets the same
        // restricted client open it for reading, so the tests above can tell the difference.
        let path = format!(
            r"\\.\pipe\puddle-t105-control-{}",
            crate::name::random_name::<16>().unwrap()
        );
        let _server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        open_restricted(Path::new(&path), GENERIC_READ, false).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ho1_dacl_has_exactly_one_ace_for_the_current_user() {
        let root = IpcRoot::new().unwrap();
        let listener = root.listen().unwrap();
        let client = ClientOptions::new()
            .open(listener.endpoint().path())
            .unwrap();

        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the client handle is open with READ_CONTROL (part of GENERIC_READ); the out
        // pointers are valid; `descriptor` is freed by `_owned`.
        let rc = unsafe {
            GetSecurityInfo(
                client.as_raw_handle(),
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
        let _owned = LocalBox(descriptor);
        assert!(!dacl.is_null(), "a null DACL grants everyone everything");

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
        assert_eq!(ace.Mask, FILE_ALL_ACCESS);

        let token = process_token(TOKEN_QUERY).unwrap();
        let user = TokenUserBuf::read(&token).unwrap();
        // SAFETY: both are valid SIDs; the ACE's SID starts at SidStart.
        let same = unsafe { EqualSid((&raw const ace.SidStart).cast_mut().cast(), user.sid()) };
        assert_ne!(same, 0, "the ACE is not for the current user");
    }

    #[test]
    fn current_user_sid_is_a_string_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    #[test]
    fn a_malformed_sddl_is_an_error_not_a_null_descriptor() {
        assert!(LocalBox::security_descriptor("D:P(not sddl").is_err());
    }
}
