// SPDX-License-Identifier: GPL-3.0-or-later
//! PAC and WPAD evaluation by Windows' own engine (`WinHttpGetProxyForUrlEx`): out of process,
//! cancellable, and it returns the whole list including `DIRECT` and failover entries.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use std::ffi::c_void;

use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_AUTODETECTION_FAILED, ERROR_WINHTTP_LOGIN_FAILURE,
    ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_ASYNC_RESULT,
    WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A, WINHTTP_AUTOPROXY_AUTO_DETECT,
    WINHTTP_AUTOPROXY_CONFIG_URL, WINHTTP_AUTOPROXY_OPTIONS,
    WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE, WINHTTP_CALLBACK_FLAG_REQUEST_ERROR,
    WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE, WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
    WINHTTP_FLAG_ASYNC, WINHTTP_INTERNET_SCHEME_HTTP, WINHTTP_PROXY_RESULT, WinHttpCloseHandle,
    WinHttpCreateProxyResolver, WinHttpFreeProxyResult, WinHttpGetProxyForUrlEx,
    WinHttpGetProxyResult, WinHttpOpen, WinHttpSetStatusCallback,
};

use super::{read_wide, wide};
use crate::hop::{Hop, ProxyAddr};
use crate::os::{PacError, PacQuery};

const ERROR_IO_PENDING: u32 = 997;
const ERROR_WINHTTP_TIMEOUT: u32 = 12002;
const ERROR_WINHTTP_OPERATION_CANCELLED: u32 = 12017;

/// The result slot the WinHTTP callback fills and the caller waits on.
#[derive(Default)]
struct Slot {
    outcome: Mutex<Option<Result<(), u32>>>,
    ready: Condvar,
}

impl Slot {
    fn finish(&self, outcome: Result<(), u32>) {
        let mut guard = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = Some(outcome);
        // Notified while the lock is held, so the waiter cannot free the slot before this returns.
        self.ready.notify_all();
    }

    fn wait(&self, timeout: Duration) -> Option<Result<(), u32>> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some(outcome) = guard.take() {
                return Some(outcome);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            guard = self
                .ready
                .wait_timeout(guard, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

unsafe extern "system" fn callback(
    _handle: *mut c_void,
    context: usize,
    status: u32,
    info: *mut c_void,
    _len: u32,
) {
    // SAFETY: `context` is the pointer `resolve_once` passed in `Arc::into_raw`; the caller never
    // frees that reference while a callback may still run (see the timeout path there).
    let slot = unsafe { &*(context as *const Slot) };
    match status {
        WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE => slot.finish(Ok(())),
        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR if !info.is_null() => {
            // SAFETY: for this status `info` points at a WINHTTP_ASYNC_RESULT.
            slot.finish(Err(unsafe {
                (*info.cast::<WINHTTP_ASYNC_RESULT>()).dwError
            }));
        }
        _ => {}
    }
}

/// Closes a WinHTTP handle on drop.
struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from WinHTTP and is closed once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

pub(super) fn resolve(query: &PacQuery) -> Result<Vec<Hop>, PacError> {
    match resolve_once(query, false) {
        Err(PacError::Failed(ref message))
            if message.contains(&format!("({ERROR_WINHTTP_LOGIN_FAILURE})")) =>
        {
            // A PAC behind authentication: retry once as the signed-in user.
            resolve_once(query, true)
        }
        other => other,
    }
}

fn failure(code: u32) -> PacError {
    let detail = format!("WinHTTP error ({code})");
    match code {
        ERROR_WINHTTP_AUTODETECTION_FAILED | ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT => {
            PacError::Unavailable(detail)
        }
        ERROR_WINHTTP_TIMEOUT => PacError::Timeout,
        _ => PacError::Failed(detail),
    }
}

fn resolve_once(query: &PacQuery, auto_logon: bool) -> Result<Vec<Hop>, PacError> {
    let agent = wide("puddle");
    // SAFETY: valid terminated agent name; null proxy arguments are allowed for NO_PROXY.
    let session = Handle(unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_ASYNC,
        )
    });
    if session.0.is_null() {
        return Err(PacError::Failed(format!(
            "WinHttpOpen: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut raw_resolver = std::ptr::null_mut();
    // SAFETY: `session` is a live session handle; `raw_resolver` receives a new handle.
    let code = unsafe { WinHttpCreateProxyResolver(session.0, &raw mut raw_resolver) };
    if code != 0 {
        return Err(failure(code));
    }
    let resolver = Handle(raw_resolver);

    let slot = Arc::new(Slot::default());
    let context = Arc::into_raw(Arc::clone(&slot)) as usize;
    // SAFETY: `callback` matches WINHTTP_STATUS_CALLBACK; flags name only the two statuses it handles.
    unsafe {
        WinHttpSetStatusCallback(
            resolver.0,
            Some(callback),
            WINHTTP_CALLBACK_FLAG_REQUEST_ERROR | WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE,
            0,
        );
    }

    let pac_url = query.pac_url.as_deref().map(wide);
    let mut flags = 0;
    if pac_url.is_some() {
        flags |= WINHTTP_AUTOPROXY_CONFIG_URL;
    }
    if query.auto_detect {
        flags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
    }
    let options = WINHTTP_AUTOPROXY_OPTIONS {
        dwFlags: flags,
        dwAutoDetectFlags: if query.auto_detect {
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A
        } else {
            0
        },
        lpszAutoConfigUrl: pac_url.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
        lpvReserved: std::ptr::null_mut(),
        dwReserved: 0,
        fAutoLogonIfChallenged: i32::from(auto_logon),
    };
    let url = wide(&query.url);
    // SAFETY: the resolver is live; `url` and `options` (and the PAC URL it points at) outlive the
    // call, and WinHTTP copies them before returning ERROR_IO_PENDING.
    let code =
        unsafe { WinHttpGetProxyForUrlEx(resolver.0, url.as_ptr(), &raw const options, context) };
    let outcome = match code {
        0 => Some(Ok(())),
        ERROR_IO_PENDING => slot.wait(query.timeout),
        other => Some(Err(other)),
    };
    let Some(outcome) = outcome else {
        // Timed out: closing the resolver cancels the request. A callback may still arrive after
        // that, and it dereferences `context`, so the raw reference is deliberately leaked
        // (one small allocation) rather than freed.
        drop(resolver);
        return Err(PacError::Timeout);
    };
    // SAFETY: the only callback that can use `context` has run (or the call completed inline), so
    // the reference passed to WinHTTP is ours to release.
    unsafe { drop(Arc::from_raw(context as *const Slot)) };
    if let Err(code) = outcome {
        return Err(if code == ERROR_WINHTTP_OPERATION_CANCELLED {
            PacError::Timeout
        } else {
            failure(code)
        });
    }
    collect(&resolver)
}

fn collect(resolver: &Handle) -> Result<Vec<Hop>, PacError> {
    let mut result = WINHTTP_PROXY_RESULT {
        cEntries: 0,
        pEntries: std::ptr::null_mut(),
    };
    // SAFETY: the resolver completed successfully; `result` is a valid out-structure.
    let code = unsafe { WinHttpGetProxyResult(resolver.0, &raw mut result) };
    if code != 0 {
        return Err(failure(code));
    }
    let mut hops = Vec::new();
    for index in 0..result.cEntries as usize {
        // SAFETY: WinHTTP returned `cEntries` entries starting at `pEntries`.
        let entry = unsafe { &*result.pEntries.add(index) };
        if entry.fProxy == 0 {
            hops.push(Hop::Direct);
        } else if entry.ProxyScheme == WINHTTP_INTERNET_SCHEME_HTTP {
            // SAFETY: `pwszProxy` is null or a terminated string owned by `result`.
            if let Some(host) = unsafe { read_wide(entry.pwszProxy) } {
                hops.push(Hop::Proxy(ProxyAddr::new(&host, entry.ProxyPort)));
            }
        }
    }
    // SAFETY: `result` was filled by WinHttpGetProxyResult and is freed once.
    unsafe { WinHttpFreeProxyResult(&raw mut result) };
    Ok(hops)
}
