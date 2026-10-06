// SPDX-License-Identifier: GPL-3.0-or-later
//! Change notification: WinHTTP's proxy-change registration (loaded at run time, because its
//! minimum Windows version is undocumented) plus a registry watch on the Internet Settings key,
//! which every Windows version supports and which catches group policy and user edits.

use std::ffi::c_void;
use std::sync::Arc;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_THREAD_AGNOSTIC,
    RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};

use super::settings::INTERNET_SETTINGS;
use super::wide;
use crate::os::{ChangeCallback, WatchGuard};

type Register = unsafe extern "system" fn(
    u64,
    Option<unsafe extern "system" fn(u64, *const c_void)>,
    *const c_void,
    *mut *mut c_void,
) -> u32;
type Unregister = unsafe extern "system" fn(*const c_void) -> u32;

/// What the WinHTTP callback needs; leaked on purpose until the registration is removed.
struct Context(ChangeCallback);

unsafe extern "system" fn proxy_changed(_flags: u64, context: *const c_void) {
    // SAFETY: `context` is the `Context` registered in `WinHttpWatch::register`, alive until the
    // registration is removed (and unregistration waits for running callbacks).
    let context = unsafe { &*context.cast::<Context>() };
    (context.0)();
}

struct WinHttpWatch {
    registration: *mut c_void,
    unregister: Unregister,
    context: *mut Context,
}

// SAFETY: the registration handle and context are only used to unregister and free, from the
// thread that drops the guard; the callback side only reads the context.
unsafe impl Send for WinHttpWatch {}
// SAFETY: see above; no shared mutation.
unsafe impl Sync for WinHttpWatch {}

impl WinHttpWatch {
    fn register(on_change: &ChangeCallback) -> Option<Self> {
        let library = wide("winhttp.dll");
        // SAFETY: valid terminated name; winhttp.dll is a system library already loaded by the crate.
        let module = unsafe { LoadLibraryW(library.as_ptr()) };
        if module.is_null() {
            return None;
        }
        // SAFETY: valid module and NUL-terminated ASCII names.
        let (register, unregister) = unsafe {
            (
                GetProcAddress(
                    module,
                    c"WinHttpRegisterProxyChangeNotification".as_ptr().cast(),
                ),
                GetProcAddress(
                    module,
                    c"WinHttpUnregisterProxyChangeNotification".as_ptr().cast(),
                ),
            )
        };
        let (register, unregister) = (register?, unregister?);
        // SAFETY: the exports have exactly these signatures (winhttp.h).
        let (register, unregister): (Register, Unregister) = unsafe {
            (
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Register>(register),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Unregister>(unregister),
            )
        };
        let context = Box::into_raw(Box::new(Context(Arc::clone(on_change))));
        let mut registration = std::ptr::null_mut();
        // SAFETY: the callback matches the signature; `context` lives until unregistered.
        let code = unsafe {
            register(
                1,
                Some(proxy_changed),
                context.cast::<c_void>(),
                &raw mut registration,
            )
        };
        if code != 0 {
            // SAFETY: registration failed, so nothing else holds the context.
            drop(unsafe { Box::from_raw(context) });
            return None;
        }
        Some(Self {
            registration,
            unregister,
            context,
        })
    }
}

impl Drop for WinHttpWatch {
    fn drop(&mut self) {
        // SAFETY: the registration is live; unregistering waits for running callbacks, after which
        // nothing uses the context.
        unsafe {
            (self.unregister)(self.registration);
            drop(Box::from_raw(self.context));
        }
    }
}

/// A thread blocked on `RegNotifyChangeKeyValue` for the Internet Settings key.
struct RegistryWatch {
    stop: HANDLE,
    thread: Option<JoinHandle<()>>,
}

// SAFETY: `stop` is an event handle, which any thread may signal.
unsafe impl Send for RegistryWatch {}
// SAFETY: see above.
unsafe impl Sync for RegistryWatch {}

struct SendHandle(HANDLE);

impl SendHandle {
    /// Takes the handle out whole, so a closure captures the `Send` wrapper and not its field.
    fn take(self) -> HANDLE {
        self.0
    }
}
// SAFETY: event handles may be waited on from any thread.
unsafe impl Send for SendHandle {}

impl RegistryWatch {
    fn start(on_change: ChangeCallback) -> Option<Self> {
        let key_name = wide(INTERNET_SETTINGS);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: valid terminated key name and out-pointer.
        if unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                key_name.as_ptr(),
                0,
                KEY_NOTIFY,
                &raw mut key,
            )
        } != ERROR_SUCCESS
        {
            return None;
        }
        // SAFETY: anonymous auto-reset event for the registry, manual-reset for stop.
        let (changed, stop) = unsafe {
            (
                CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()),
                CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()),
            )
        };
        if changed.is_null() || stop.is_null() {
            // SAFETY: closing handles we just opened or created.
            unsafe {
                RegCloseKey(key);
                if !changed.is_null() {
                    CloseHandle(changed);
                }
                if !stop.is_null() {
                    CloseHandle(stop);
                }
            }
            return None;
        }
        let (key, changed, stop_for_thread) =
            (SendHandle(key), SendHandle(changed), SendHandle(stop));
        let thread = std::thread::Builder::new()
            .name("puddle-proxy-registry-watch".into())
            .spawn(move || {
                let (key, changed, stop) = (key.take(), changed.take(), stop_for_thread.take());
                let handles = [changed, stop];
                loop {
                    // SAFETY: live key and event; asynchronous, thread-agnostic notification.
                    let armed = unsafe {
                        RegNotifyChangeKeyValue(
                            key,
                            1,
                            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                            changed,
                            1,
                        )
                    };
                    if armed != ERROR_SUCCESS {
                        break;
                    }
                    // SAFETY: two live handles.
                    let woke = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if woke != WAIT_OBJECT_0 {
                        break; // stop signalled, or the wait failed
                    }
                    on_change();
                }
                // SAFETY: the thread owns the key and the change event; `stop` is closed by the owner.
                unsafe {
                    RegCloseKey(key);
                    CloseHandle(changed);
                }
            });
        let Ok(thread) = thread else {
            // The closure (and its handles) was dropped unrun: the handles leak, once, on a failure
            // to create a thread.
            // SAFETY: `stop` is ours alone here.
            unsafe { CloseHandle(stop) };
            return None;
        };
        Some(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for RegistryWatch {
    fn drop(&mut self) {
        // SAFETY: `stop` is a live event; the thread is joined before the handle is closed.
        unsafe { SetEvent(self.stop) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join(); // a panicked watcher has nothing left to report
        }
        // SAFETY: the only user of `stop` has finished.
        unsafe { CloseHandle(self.stop) };
    }
}

#[derive(Debug)]
struct Guard {
    _winhttp: Option<WinHttpWatch>,
    _registry: Option<RegistryWatch>,
}

impl std::fmt::Debug for WinHttpWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WinHttpWatch")
    }
}

impl std::fmt::Debug for RegistryWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistryWatch")
    }
}

impl WatchGuard for Guard {}

pub(super) fn start(on_change: ChangeCallback) -> Option<Box<dyn WatchGuard>> {
    let winhttp = WinHttpWatch::register(&on_change);
    let registry = RegistryWatch::start(on_change);
    if winhttp.is_none() && registry.is_none() {
        return None;
    }
    Some(Box::new(Guard {
        _winhttp: winhttp,
        _registry: registry,
    }))
}
