// SPDX-License-Identifier: GPL-3.0-or-later
//! The user's WinINet settings, the machine WinHTTP proxy and the proxy policy.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GlobalFree};
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
    WinHttpGetDefaultProxyConfiguration, WinHttpGetIEProxyConfigForCurrentUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW,
};

use super::{read_wide, wide};
use crate::os::{OsSettings, SettingsError};

pub(super) const INTERNET_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const POLICY_SETTINGS: &str =
    r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

pub(super) fn read() -> Result<OsSettings, SettingsError> {
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
        fAutoDetect: 0,
        lpszAutoConfigUrl: std::ptr::null_mut(),
        lpszProxy: std::ptr::null_mut(),
        lpszProxyBypass: std::ptr::null_mut(),
    };
    // SAFETY: `config` is a valid out-structure; on success WinHTTP fills it with strings we free.
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&raw mut config) } == 0 {
        return Err(SettingsError(format!(
            "WinHttpGetIEProxyConfigForCurrentUser: {}",
            std::io::Error::last_os_error()
        )));
    }
    let (pac_url, mut proxy_server, bypass) = (
        take(config.lpszAutoConfigUrl),
        take(config.lpszProxy),
        take(config.lpszProxyBypass),
    );
    // WinHTTP reports a `ProxyServer` value even when "use a proxy server" is off; honour the switch.
    if registry_dword(HKEY_CURRENT_USER, INTERNET_SETTINGS, "ProxyEnable") == Some(0) {
        proxy_server = None;
    }
    let (machine_proxy, machine_bypass) = machine_proxy();
    Ok(OsSettings {
        auto_detect: config.fAutoDetect != 0,
        pac_url,
        proxy_server,
        bypass,
        machine_proxy,
        machine_bypass,
        per_machine_policy: registry_dword(
            HKEY_LOCAL_MACHINE,
            POLICY_SETTINGS,
            "ProxySettingsPerUser",
        ) == Some(0),
    })
}

/// Copies and frees a string WinHTTP allocated with `GlobalAlloc`.
fn take(ptr: *mut u16) -> Option<String> {
    // SAFETY: WinHTTP hands out null or a terminated string.
    let text = unsafe { read_wide(ptr) };
    if !ptr.is_null() {
        // SAFETY: the string was allocated by WinHTTP with GlobalAlloc, as documented, and is not
        // used again.
        unsafe { GlobalFree(ptr.cast::<c_void>()) };
    }
    text
}

fn machine_proxy() -> (Option<String>, Option<String>) {
    let mut info = WINHTTP_PROXY_INFO {
        dwAccessType: 0,
        lpszProxy: std::ptr::null_mut(),
        lpszProxyBypass: std::ptr::null_mut(),
    };
    // SAFETY: `info` is a valid out-structure; its strings are freed below.
    if unsafe { WinHttpGetDefaultProxyConfiguration(&raw mut info) } == 0 {
        return (None, None);
    }
    let (proxy, bypass) = (take(info.lpszProxy), take(info.lpszProxyBypass));
    if info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
        (proxy, bypass)
    } else {
        (None, None)
    }
}

pub(super) fn registry_dword(
    root: windows_sys::Win32::System::Registry::HKEY,
    key: &str,
    value: &str,
) -> Option<u32> {
    let (key, value) = (wide(key), wide(value));
    let mut data = 0u32;
    let mut size = 4u32;
    // SAFETY: both names are NUL-terminated; `data` has the 4 bytes `size` promises.
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&raw mut data).cast::<c_void>(),
            &raw mut size,
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}
