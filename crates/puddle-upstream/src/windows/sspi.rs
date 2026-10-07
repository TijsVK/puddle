// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows SSPI as a [`TokenSource`] (T-135): `Negotiate` and `NTLM` contexts for the logged-on
//! user. The credential handle is acquired with no identity (`pAuthData = NULL`), which makes
//! Windows use the user's own sign-in: no password is read, stored or asked for, and no flag
//! that could show a prompt is ever passed.
//!
//! Every SSPI call runs under one process-wide lock: in the T-033 lab, parallel NTLM handshakes
//! without it had 12 of 30 well-formed challenges rejected with `SEC_E_INVALID_TOKEN` (serial: 0
//! of 30; locked: 0 of 60). The calls take microseconds, so the lock costs nothing measurable.

use std::ffi::c_void;
use std::fmt;
use std::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows_sys::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows_sys::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeContextBuffer, FreeCredentialsHandle,
    ISC_REQ_ALLOCATE_MEMORY, ISC_REQ_CONNECTION, InitializeSecurityContextW, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP, SecBuffer, SecBufferDesc,
};
use windows_sys::Win32::Security::Credentials::SecHandle;

use crate::auth::AuthError;
use crate::negotiate::{Leg, Package, SecurityContext, TokenSource};

static LOCK: Mutex<()> = Mutex::new(());

fn locked() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The user's own sign-in, through Windows SSPI.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SspiSource;

impl TokenSource for SspiSource {
    fn open(&self, package: Package, spn: &str) -> Result<Box<dyn SecurityContext>, AuthError> {
        let name = wide(match package {
            Package::Negotiate => "Negotiate",
            Package::Ntlm => "NTLM",
        });
        let mut credential = SecHandle {
            dwLower: 0,
            dwUpper: 0,
        };
        let mut expiry = 0i64;
        let _guard = locked();
        // SAFETY: `name` is NUL terminated and outlives the call; `credential` and `expiry` are
        // valid out-pointers; the identity is NULL (the logged-on user) and no key callback.
        let status = unsafe {
            AcquireCredentialsHandleW(
                ptr::null(),
                name.as_ptr(),
                SECPKG_CRED_OUTBOUND,
                ptr::null(),
                ptr::null(),
                None,
                ptr::null(),
                &raw mut credential,
                &raw mut expiry,
            )
        };
        if status != SEC_E_OK {
            return Err(AuthError::Failed(format!(
                "Windows sign-in unavailable for {}: AcquireCredentialsHandle 0x{:08x}",
                package.word(),
                status.cast_unsigned()
            )));
        }
        Ok(Box::new(Context {
            credential,
            security: SecHandle {
                dwLower: 0,
                dwUpper: 0,
            },
            started: false,
            target: wide(spn),
        }))
    }
}

/// One SSPI context. Owns its credential handle and (once started) the security context.
struct Context {
    credential: SecHandle,
    security: SecHandle,
    started: bool,
    target: Vec<u16>,
}

// SAFETY: the handles are plain values owned by this struct and used by one caller at a time
// (`&mut self`); SSPI contexts may be used from any thread.
unsafe impl Send for Context {}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SspiContext")
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

impl SecurityContext for Context {
    fn step(&mut self, input: Option<&[u8]>) -> Result<Leg, AuthError> {
        let mut in_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        if let Some(bytes) = input {
            in_buffer.cbBuffer = u32::try_from(bytes.len())
                .map_err(|_| AuthError::Failed("proxy challenge too large".into()))?;
            in_buffer.pvBuffer = bytes.as_ptr().cast_mut().cast::<c_void>();
        }
        let in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &raw mut in_buffer,
        };
        let mut out_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &raw mut out_buffer,
        };
        let mut attributes = 0u32;
        let mut expiry = 0i64;
        let context: *mut SecHandle = &raw mut self.security;
        let _guard = locked();
        // SAFETY: every pointer is to a live local or to `self`; the input buffer points into
        // `input`, which outlives the call and is only read; the output buffer is allocated by
        // SSPI (`ISC_REQ_ALLOCATE_MEMORY`) and freed below. The same handle is passed as the
        // existing and the new context after the first call, as the API requires. No flag asks
        // for a credential prompt.
        let status = unsafe {
            InitializeSecurityContextW(
                &raw const self.credential,
                if self.started { context } else { ptr::null() },
                self.target.as_ptr(),
                ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION,
                0,
                SECURITY_NATIVE_DREP,
                if input.is_some() {
                    &raw const in_desc
                } else {
                    ptr::null()
                },
                0,
                context,
                &raw mut out_desc,
                &raw mut attributes,
                &raw mut expiry,
            )
        };
        let token = if out_buffer.pvBuffer.is_null() {
            Vec::new()
        } else {
            // SAFETY: SSPI returned `cbBuffer` readable bytes at `pvBuffer`.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    out_buffer.pvBuffer.cast::<u8>(),
                    out_buffer.cbBuffer as usize,
                )
            }
            .to_vec();
            // SAFETY: the buffer came from SSPI's allocator and is freed exactly once.
            unsafe { FreeContextBuffer(out_buffer.pvBuffer) };
            bytes
        };
        if status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED {
            return Err(AuthError::Failed(format!(
                "InitializeSecurityContext 0x{:08x}",
                status.cast_unsigned()
            )));
        }
        self.started = true;
        Ok(Leg {
            token,
            complete: status == SEC_E_OK,
        })
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let _guard = locked();
        // SAFETY: both handles belong to this value and are released once; the context only if
        // the first `InitializeSecurityContext` call succeeded.
        unsafe {
            if self.started {
                DeleteSecurityContext(&raw const self.security);
            }
            FreeCredentialsHandle(&raw const self.credential);
        }
    }
}
