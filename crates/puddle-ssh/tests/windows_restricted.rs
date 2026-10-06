// SPDX-License-Identifier: GPL-3.0-or-later
//! HO-1 at the SSH endpoint (Windows): a bridge running under a restricted token (another
//! process of the same user that dropped its user SID, e.g. a sandboxed browser or a low-rights
//! helper) is refused, with a message that says why; the same token with the user SID gets in.
#![cfg(windows)]
#![expect(
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only FFI to build a restricted token; a failed setup fails the test"
)]

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;

use puddle_compute::SshStream;
use puddle_ipc::IpcRoot;
use puddle_ssh::bridge::{self, BridgeError, Report};
use puddle_ssh::{SshEndpoint, SshTarget};
use tokio::io::AsyncWriteExt as _;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE, WinAuthenticatedUserSid, WinBuiltinUsersSid,
    WinInteractiveSid, WinWorldSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Sends a banner and closes.
struct Banner;

impl SshTarget for Banner {
    type Error = io::Error;

    fn label(&self) -> String {
        "banner".into()
    }

    fn admit(&self) -> impl Future<Output = Result<(), String>> {
        std::future::ready(Ok(()))
    }

    async fn serve<S: SshStream>(&self, mut stream: S) -> Result<(), io::Error> {
        stream.write_all(b"SSH-2.0-banner\r\n").await
    }
}

/// Broad groups the user belongs to: a token restricted to these may do what "everyone logged
/// on" may, but nothing granted to the user's own SID.
const BROAD_GROUPS: [WELL_KNOWN_SID_TYPE; 4] = [
    WinWorldSid,
    WinAuthenticatedUserSid,
    WinBuiltinUsersSid,
    WinInteractiveSid,
];

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Vec<u64> {
    let mut buf = vec![0_u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `buf` holds SECURITY_MAX_SID_SIZE bytes; these SIDs need no domain SID.
    let ok =
        unsafe { CreateWellKnownSid(kind, ptr::null_mut(), buf.as_mut_ptr().cast(), &raw mut len) };
    assert_ne!(ok, 0, "CreateWellKnownSid: {}", io::Error::last_os_error());
    buf
}

fn process_token() -> OwnedHandle {
    let mut raw: HANDLE = ptr::null_mut();
    // SAFETY: a pseudo-handle for this process and a valid out-pointer.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut raw,
        )
    };
    assert_ne!(ok, 0, "OpenProcessToken: {}", io::Error::last_os_error());
    // SAFETY: a fresh token handle that nothing else owns.
    unsafe { OwnedHandle::from_raw_handle(raw) }
}

/// The token's `TOKEN_USER`, in a buffer aligned for it.
fn token_user(token: &OwnedHandle) -> Vec<u64> {
    let mut len = 0_u32;
    // SAFETY: a null buffer of length 0 only asks for the size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &raw mut len,
        );
    }
    let words = (len as usize)
        .div_ceil(8)
        .max(size_of::<TOKEN_USER>().div_ceil(8));
    let mut buf = vec![0_u64; words];
    // SAFETY: `buf` is writable for `words * 8` bytes and 8-byte aligned.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            u32::try_from(words * 8).unwrap(),
            &raw mut len,
        )
    };
    assert_ne!(ok, 0, "GetTokenInformation: {}", io::Error::last_os_error());
    buf
}

/// Runs `puddle_ssh::bridge::run` against `endpoint` on a thread impersonating a restricted copy
/// of this process's token (restricting SIDs: the broad groups, plus the user's SID when
/// `include_user`).
fn bridge_restricted(endpoint: &Path, include_user: bool) -> Result<Report, BridgeError> {
    let endpoint: PathBuf = endpoint.to_path_buf();
    std::thread::spawn(move || {
        let token = process_token();
        let user = token_user(&token);
        let groups: Vec<Vec<u64>> = BROAD_GROUPS.iter().map(|k| well_known_sid(*k)).collect();
        let mut restrict: Vec<SID_AND_ATTRIBUTES> = groups
            .iter()
            .map(|g| SID_AND_ATTRIBUTES {
                Sid: g.as_ptr().cast_mut().cast(),
                Attributes: 0,
            })
            .collect();
        if include_user {
            // SAFETY: `user` holds the TOKEN_USER that `token_user` read; its SID lies inside
            // the same buffer, which outlives this use.
            let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
            restrict.push(SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0,
            });
        }
        let mut raw: HANDLE = ptr::null_mut();
        // SAFETY: `token` has TOKEN_DUPLICATE; `restrict` points at SIDs that outlive the
        // call; `raw` is a valid out-pointer.
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
        assert_ne!(
            ok,
            0,
            "CreateRestrictedToken: {}",
            io::Error::last_os_error()
        );
        // SAFETY: a fresh token handle that nothing else owns.
        let restricted = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: impersonation ends below on this same thread, before it returns.
        let ok = unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) };
        assert_ne!(
            ok,
            0,
            "ImpersonateLoggedOnUser: {}",
            io::Error::last_os_error()
        );
        // The pipe is opened while this thread polls: a current-thread runtime keeps it here.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (_stdin, input) = tokio::io::duplex(1024);
        let (output, _stdout) = tokio::io::duplex(1024);
        let result = rt.block_on(bridge::run(&endpoint, input, output));
        // SAFETY: ends this thread's impersonation.
        let reverted = unsafe { RevertToSelf() };
        assert_ne!(reverted, 0, "RevertToSelf failed");
        result
    })
    .join()
    .expect("the impersonating thread finished")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ho1_a_restricted_bridge_is_refused_with_a_reason() {
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), Arc::new(Banner)).unwrap();
    let path = endpoint.endpoint().path().to_path_buf();
    let err = tokio::task::spawn_blocking(move || bridge_restricted(&path, false))
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(err, BridgeError::AccessDenied { .. }), "{err:?}");
    assert!(
        err.to_string()
            .contains("only the user running puddle, from an unrestricted process, may connect"),
        "{err}"
    );
    endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ho1_the_same_token_with_the_user_sid_gets_in() {
    // Positive control: the refusal above comes from the endpoint's DACL, not from the setup.
    let root = IpcRoot::new().unwrap();
    let endpoint = SshEndpoint::start(root.listen().unwrap(), Arc::new(Banner)).unwrap();
    let path = endpoint.endpoint().path().to_path_buf();
    let report = tokio::task::spawn_blocking(move || bridge_restricted(&path, true))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(report.received, 16);
    endpoint.close().await;
}
