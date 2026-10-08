// SPDX-License-Identifier: GPL-3.0-or-later
//! Win32 security helpers: the current user's SID, security descriptors built from SDDL, and
//! owner-only files and folders. The crate's only unsafe code; every raw resource is owned by a
//! guard that frees it.
//!
//! No maintained crate sets a protected, explicit DACL at creation time (`windows-acl` was last
//! released in 2021), so this calls `windows-sys` directly. `puddle-ipc` builds its named-pipe
//! descriptor from the same pieces.

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_ACCESS_MASK, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The current user's SID in string form (`S-1-5-21-...`).
///
/// # Errors
///
/// The OS error if the process token can't be read.
pub fn current_user_sid() -> io::Result<String> {
    let token = process_token(TOKEN_QUERY)?;
    let user = TokenUserBuf::read(&token)?;
    sid_to_string(user.sid())
}

/// A DACL that grants the user `sid` `rights` (an SDDL right such as `GA` or `FA`) and nobody
/// else anything. `P` blocks inheritance, so no default ACEs (Everyone, anonymous) come back;
/// `inherit` adds the container and object inherit flags, for folders.
#[must_use]
pub fn owner_only_sddl(sid: &str, rights: &str, inherit: bool) -> String {
    let flags = if inherit { "OICI" } else { "" };
    format!("D:P(A;{flags};{rights};;;{sid})")
}

/// Creates `path` for writing, failing if it exists, with an owner-only protected DACL set at
/// creation (there is no window in which the file has inherited access).
///
/// # Errors
///
/// The OS error, `AlreadyExists` included.
pub fn create_owner_only_file(path: &Path) -> io::Result<File> {
    let descriptor = owner_only_descriptor("FA", false)?;
    let attrs = descriptor.attributes();
    let wide = wide_nul(path.as_os_str());
    // SAFETY: `wide` is NUL-terminated and outlives the call; `attrs` points at a descriptor
    // that `descriptor` keeps alive; a null template handle is allowed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attrs,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh file handle that nothing else owns.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Creates the folder `dir` (its parent must exist) with an owner-only protected DACL that new
/// children inherit.
///
/// # Errors
///
/// The OS error, `AlreadyExists` included.
pub fn create_owner_only_dir(dir: &Path) -> io::Result<()> {
    let descriptor = owner_only_descriptor("FA", true)?;
    let attrs = descriptor.attributes();
    let wide = wide_nul(dir.as_os_str());
    // SAFETY: as for `create_owner_only_file`.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attrs) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces the access list of the existing file or folder `path` with the owner-only protected
/// one (see [`create_owner_only_file`]). For a folder (`inherit`), entries that inherit from it
/// are rewritten too, so its existing children lose the inherited entries for administrators and
/// `SYSTEM`; children with their own protected list keep it.
///
/// # Errors
///
/// The OS error, for example when the current user may not change the list.
pub fn set_owner_only_acl(path: &Path, inherit: bool) -> io::Result<()> {
    let descriptor = owner_only_descriptor("FA", inherit)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is a valid descriptor that it keeps alive; the out-pointers are valid
    // and `dacl` points into the descriptor.
    let ok = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.as_ptr(),
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::other("the owner-only descriptor has no DACL"));
    }
    let wide = wide_nul(path.as_os_str());
    // SAFETY: `wide` is NUL-terminated and outlives the call; `dacl` stays valid while
    // `descriptor` lives; null owner, group and SACL are allowed with only the DACL bits set.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    Ok(())
}

fn owner_only_descriptor(rights: &str, inherit: bool) -> io::Result<LocalBox> {
    let sid = current_user_sid()?;
    LocalBox::security_descriptor(&owner_only_sddl(&sid, rights, inherit))
}

/// Reads the DACL of an open file: `Ok(())` if it is non-null and every ACE allows only the
/// current user, otherwise `Err(reason)`. Needs the handle opened with `READ_CONTROL`, which any
/// read open has.
///
/// # Errors
///
/// The outer error is an OS failure reading the DACL or the user's SID; the inner one says why
/// the file is not owner-only.
pub fn dacl_is_owner_only(file: &File) -> io::Result<Result<(), String>> {
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: the handle is open for the call; the out-pointers are valid; `descriptor` is freed
    // by `_owned` below, and `dacl` points into it.
    let rc = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    // SAFETY: `descriptor` came from GetSecurityInfo, which allocates with LocalAlloc.
    let _owned = unsafe { LocalBox::from_raw(descriptor) };
    if dacl.is_null() {
        return Ok(Err(
            "it has no access list, which grants everyone access".to_owned()
        ));
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a valid ACL inside `descriptor`; `info` is the size the class needs.
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(io::Error::other)?,
            AclSizeInformation,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = process_token(TOKEN_QUERY)?;
    let user = TokenUserBuf::read(&token)?;
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = ptr::null_mut();
        // SAFETY: `index` is below AceCount; `ace` receives a pointer into the ACL.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE starts with an ACE_HEADER, which ACCESS_ALLOWED_ACE begins with.
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(Err(format!("entry {index} is not a plain allow entry")));
        }
        // SAFETY: the type check above makes this an ACCESS_ALLOWED_ACE, whose SID starts at
        // SidStart; the user's SID is valid while `user` lives.
        let same = unsafe { EqualSid((&raw const ace.SidStart).cast_mut().cast(), user.sid()) };
        if same == 0 {
            return Ok(Err(format!(
                "entry {index} grants access to another account"
            )));
        }
    }
    Ok(Ok(()))
}

/// Opens this process's token with `access`.
///
/// # Errors
///
/// The OS error.
pub fn process_token(access: TOKEN_ACCESS_MASK) -> io::Result<OwnedHandle> {
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
pub struct TokenUserBuf(Vec<u64>);

impl TokenUserBuf {
    /// Reads the user of `token` (opened with `TOKEN_QUERY`).
    ///
    /// # Errors
    ///
    /// The OS error.
    pub fn read(token: &OwnedHandle) -> io::Result<Self> {
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
    #[must_use]
    pub fn sid(&self) -> PSID {
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
    // SAFETY: the call above allocated `wide` with LocalAlloc.
    let owned = unsafe { LocalBox::from_raw(wide.cast::<c_void>()) };
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

/// `s` as UTF-16 with a terminating NUL.
#[must_use]
pub fn wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Memory the OS allocated with `LocalAlloc`, freed on drop.
pub struct LocalBox(*mut c_void);

impl LocalBox {
    /// Takes ownership of `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr` is null or was allocated with `LocalAlloc`, and nothing else frees it.
    #[must_use]
    pub unsafe fn from_raw(ptr: *mut c_void) -> Self {
        Self(ptr)
    }

    /// The security descriptor `sddl` describes.
    ///
    /// # Errors
    ///
    /// The OS error for malformed SDDL.
    pub fn security_descriptor(sddl: &str) -> io::Result<Self> {
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

    /// The pointer, valid while `self` lives.
    #[must_use]
    pub fn as_ptr(&self) -> *mut c_void {
        self.0
    }

    /// `SECURITY_ATTRIBUTES` pointing at this descriptor (not inheritable); valid while `self`
    /// lives.
    #[must_use]
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: SECURITY_ATTRIBUTES_LEN,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "SECURITY_ATTRIBUTES is 24 bytes"
)]
const SECURITY_ATTRIBUTES_LEN: u32 = size_of::<SECURITY_ATTRIBUTES>() as u32;

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: by the constructors' contracts the pointer came from an API that allocates
            // with LocalAlloc, and is freed exactly once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_is_a_string_sid() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-"), "{sid}");
    }

    #[test]
    fn a_malformed_sddl_is_an_error_not_a_null_descriptor() {
        assert!(LocalBox::security_descriptor("D:P(not sddl").is_err());
    }

    #[test]
    fn sddl_grants_only_the_given_sid_and_blocks_inheritance() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001", "GA", false),
            "D:P(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001", "FA", true),
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
    }
}
