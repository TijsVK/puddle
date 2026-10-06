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
use crate::os::{Origin, ProxyConfig, SettingsError};
use crate::parse::{BypassList, ProxyRules};

pub(super) const INTERNET_SETTINGS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const POLICY_SETTINGS: &str =
    r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

/// The settings as WinINet and WinHTTP name them. Never leaves this module: [`read`] turns it into
/// the neutral [`ProxyConfig`].
#[derive(Debug, Default, PartialEq, Eq)]
struct WinSettings {
    /// "Automatically detect settings" (WPAD).
    auto_detect: bool,
    /// `AutoConfigURL`.
    auto_config_url: Option<String>,
    /// `ProxyServer`, already dropped when `ProxyEnable` is off.
    proxy_server: Option<String>,
    /// `ProxyOverride`.
    proxy_override: Option<String>,
    /// The machine-wide WinHTTP proxy list and bypass (`netsh winhttp`).
    machine_proxy: Option<String>,
    machine_bypass: Option<String>,
    /// Group policy `ProxySettingsPerUser=0`: WinINet should read the machine's settings.
    per_machine_policy: bool,
}

/// The user's proxy first (WinINet), the machine's WinHTTP proxy when the user has none.
fn to_config(win: WinSettings) -> ProxyConfig {
    if win.per_machine_policy {
        tracing::debug!(
            "ProxySettingsPerUser=0 is set; the user's WinINet settings are used as WinHTTP reports them"
        );
    }
    let (list, bypass) = match (win.proxy_server, win.machine_proxy) {
        (Some(user), _) => (Some(user), win.proxy_override),
        (None, Some(machine)) => (Some(machine), win.machine_bypass),
        (None, None) => (None, None),
    };
    ProxyConfig {
        auto_detect: win.auto_detect,
        pac_url: win.auto_config_url,
        rules: list.as_deref().map(ProxyRules::parse).unwrap_or_default(),
        bypass: bypass.as_deref().map(BypassList::parse).unwrap_or_default(),
        origin: Origin::System,
    }
}

pub(super) fn read() -> Result<ProxyConfig, SettingsError> {
    read_win().map(to_config)
}

fn read_win() -> Result<WinSettings, SettingsError> {
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
    Ok(WinSettings {
        auto_detect: config.fAutoDetect != 0,
        auto_config_url: pac_url,
        proxy_server,
        proxy_override: bypass,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hop::{Destination, ProxyAddr, Scheme};

    #[test]
    fn the_users_proxy_wins_over_the_machines_and_keeps_its_own_bypass() {
        let config = to_config(WinSettings {
            proxy_server: Some("http=a:1;https=b:2".into()),
            proxy_override: Some("*.corp.test;<local>".into()),
            machine_proxy: Some("m:9".into()),
            machine_bypass: Some("*.m.test".into()),
            auto_config_url: Some("http://pac/p.pac".into()),
            auto_detect: true,
            per_machine_policy: true,
        });
        assert_eq!(config.pac_url.as_deref(), Some("http://pac/p.pac"));
        assert!(config.auto_detect);
        assert_eq!(
            config.rules.for_scheme(Scheme::Https),
            Some(&ProxyAddr::new("b", 2))
        );
        assert!(
            config
                .bypass
                .matches(&Destination::new(Scheme::Https, "wiki.corp.test", 443))
        );
        assert!(
            !config
                .bypass
                .matches(&Destination::new(Scheme::Https, "a.m.test", 443))
        );
    }

    #[test]
    fn the_machine_proxy_is_used_when_the_user_has_none() {
        let config = to_config(WinSettings {
            machine_proxy: Some("m:9".into()),
            machine_bypass: Some("*.m.test".into()),
            ..WinSettings::default()
        });
        assert_eq!(
            config.rules.for_scheme(Scheme::Http),
            Some(&ProxyAddr::new("m", 9))
        );
        assert!(
            config
                .bypass
                .matches(&Destination::new(Scheme::Https, "a.m.test", 443))
        );
        assert!(to_config(WinSettings::default()).rules.is_empty());
    }
}
