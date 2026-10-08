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
use crate::os::{ChangeCallback, ProblemCallback, WatchGuard};

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
    /// Registers `on_change` with WinHTTP, or says why it could not.
    fn register(on_change: &ChangeCallback) -> Result<Self, String> {
        let library = wide("winhttp.dll");
        // SAFETY: valid terminated name; winhttp.dll is a system library already loaded by the crate.
        let module = unsafe { LoadLibraryW(library.as_ptr()) };
        if module.is_null() {
            return Err(format!(
                "winhttp.dll could not be loaded: {}",
                std::io::Error::last_os_error()
            ));
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
        let (Some(register), Some(unregister)) = (register, unregister) else {
            return Err(
                "WinHTTP's proxy change notification is not available on this Windows version"
                    .to_owned(),
            );
        };
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
            return Err(format!(
                "WinHTTP refused the proxy change registration (error {code})"
            ));
        }
        Ok(Self {
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

/// How one wait of the registry watcher ended.
#[derive(Debug, PartialEq, Eq)]
enum Wake {
    /// The key changed.
    Changed,
    /// The owner asked the watcher to stop.
    Stop,
    /// The wait itself failed, with the wait result code.
    Failed(u32),
}

impl Wake {
    /// The meaning of a `WaitForMultipleObjects` result over `[changed, stop]`.
    fn of(code: u32) -> Self {
        if code == WAIT_OBJECT_0 {
            Self::Changed
        } else if code == WAIT_OBJECT_0 + 1 {
            Self::Stop
        } else {
            Self::Failed(code)
        }
    }
}

/// The registry watcher's loop: arm the notification, wait, tell `on_change`; ends when asked to
/// stop, or, saying why to `on_problem`, when arming or waiting fails (changes are not seen after
/// that). `arm` returns a Win32 error code, `wait` a wait result code.
fn watch_loop(
    mut arm: impl FnMut() -> u32,
    mut wait: impl FnMut() -> u32,
    on_change: &dyn Fn(),
    on_problem: &dyn Fn(String),
) {
    loop {
        let armed = arm();
        if armed != ERROR_SUCCESS {
            on_problem(format!(
                "the registry watch for the Internet Settings key stopped: RegNotifyChangeKeyValue failed (error {armed})"
            ));
            return;
        }
        match Wake::of(wait()) {
            Wake::Changed => on_change(),
            Wake::Stop => return,
            Wake::Failed(code) => {
                on_problem(format!(
                    "the registry watch for the Internet Settings key stopped: waiting for it failed (result {code:#x})"
                ));
                return;
            }
        }
    }
}

impl RegistryWatch {
    fn start(on_change: ChangeCallback, on_problem: &ProblemCallback) -> Result<Self, String> {
        Self::start_at(INTERNET_SETTINGS, on_change, on_problem)
    }

    /// Watches `key_name` under `HKEY_CURRENT_USER`.
    fn start_at(
        key_name: &str,
        on_change: ChangeCallback,
        on_problem: &ProblemCallback,
    ) -> Result<Self, String> {
        let wide_name = wide(key_name);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: valid terminated key name and out-pointer.
        let opened = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide_name.as_ptr(),
                0,
                KEY_NOTIFY,
                &raw mut key,
            )
        };
        if opened != ERROR_SUCCESS {
            return Err(format!(
                "the registry key HKCU\\{key_name} could not be opened for change notification (error {opened})"
            ));
        }
        // SAFETY: anonymous auto-reset event for the registry, manual-reset for stop.
        let (changed, stop) = unsafe {
            (
                CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()),
                CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()),
            )
        };
        if changed.is_null() || stop.is_null() {
            let why = std::io::Error::last_os_error();
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
            return Err(format!(
                "the registry watch could not create its events: {why}"
            ));
        }
        let (key, changed, stop_for_thread) =
            (SendHandle(key), SendHandle(changed), SendHandle(stop));
        let on_problem = Arc::clone(on_problem);
        let thread = std::thread::Builder::new()
            .name("puddle-proxy-registry-watch".into())
            .spawn(move || {
                let (key, changed, stop) = (key.take(), changed.take(), stop_for_thread.take());
                let handles = [changed, stop];
                watch_loop(
                    // SAFETY: live key and event; asynchronous, thread-agnostic notification.
                    || unsafe {
                        RegNotifyChangeKeyValue(
                            key,
                            1,
                            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                            changed,
                            1,
                        )
                    },
                    // SAFETY: two live handles.
                    || unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) },
                    &*on_change,
                    &*on_problem,
                );
                // SAFETY: the thread owns the key and the change event; `stop` is closed by the owner.
                unsafe {
                    RegCloseKey(key);
                    CloseHandle(changed);
                }
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(err) => {
                // The closure (and its handles) was dropped unrun: the handles leak, once, on a
                // failure to create a thread.
                // SAFETY: `stop` is ours alone here.
                unsafe { CloseHandle(stop) };
                return Err(format!("the registry watch thread could not start: {err}"));
            }
        };
        Ok(Self {
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

/// The guard for what could be registered, reporting each part that could not be to
/// `on_problem`. `None` when neither part works: nothing would ever call `on_change`.
fn assemble(
    winhttp: Result<WinHttpWatch, String>,
    registry: Result<RegistryWatch, String>,
    on_problem: &ProblemCallback,
) -> Option<Box<dyn WatchGuard>> {
    let winhttp = winhttp.map_err(|why| on_problem(why)).ok();
    let registry = registry.map_err(|why| on_problem(why)).ok();
    if winhttp.is_none() && registry.is_none() {
        return None;
    }
    Some(Box::new(Guard {
        _winhttp: winhttp,
        _registry: registry,
    }))
}

pub(super) fn start(
    on_change: ChangeCallback,
    on_problem: &ProblemCallback,
) -> Option<Box<dyn WatchGuard>> {
    let winhttp = WinHttpWatch::register(&on_change);
    let registry = RegistryWatch::start(on_change, on_problem);
    assemble(winhttp, registry, on_problem)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Mutex;

    use super::*;

    fn problems() -> (ProblemCallback, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let callback: ProblemCallback = Arc::new(move |why| sink.lock().unwrap().push(why));
        (callback, seen)
    }

    /// The wait results `WaitForMultipleObjects` gives over `[changed, stop]`.
    const CHANGED: u32 = WAIT_OBJECT_0;
    const STOP: u32 = WAIT_OBJECT_0 + 1;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;

    #[test]
    fn wait_results_mean_a_change_a_stop_or_a_failure() {
        assert_eq!(Wake::of(CHANGED), Wake::Changed);
        assert_eq!(Wake::of(STOP), Wake::Stop);
        assert_eq!(Wake::of(WAIT_FAILED), Wake::Failed(WAIT_FAILED));
        assert_eq!(Wake::of(0x102), Wake::Failed(0x102));
    }

    #[test]
    fn the_loop_reports_each_change_and_ends_quietly_when_asked_to_stop() {
        let waits = Cell::new(0);
        let changes = Cell::new(0);
        let (_, seen) = problems();
        let sink = Arc::clone(&seen);
        watch_loop(
            || ERROR_SUCCESS,
            || {
                waits.set(waits.get() + 1);
                if waits.get() < 3 { CHANGED } else { STOP }
            },
            &|| changes.set(changes.get() + 1),
            &move |why| sink.lock().unwrap().push(why),
        );
        assert_eq!((waits.get(), changes.get()), (3, 2));
        assert!(seen.lock().unwrap().is_empty(), "a stop is not a problem");
    }

    #[test]
    fn a_notification_that_cannot_be_armed_ends_the_loop_and_says_so() {
        let arms = Cell::new(0);
        let (_, seen) = problems();
        let sink = Arc::clone(&seen);
        watch_loop(
            || {
                arms.set(arms.get() + 1);
                if arms.get() == 1 { ERROR_SUCCESS } else { 6 }
            },
            || CHANGED,
            &|| {},
            &move |why| sink.lock().unwrap().push(why),
        );
        assert_eq!(arms.get(), 2);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(
            seen[0].contains("RegNotifyChangeKeyValue failed (error 6)"),
            "{seen:?}"
        );
    }

    #[test]
    fn a_failed_wait_ends_the_loop_and_says_so() {
        let (_, seen) = problems();
        let sink = Arc::clone(&seen);
        watch_loop(|| ERROR_SUCCESS, || WAIT_FAILED, &|| {}, &move |why| {
            sink.lock().unwrap().push(why)
        });
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains("waiting for it failed"), "{seen:?}");
    }

    #[test]
    fn a_key_that_cannot_be_opened_says_which_and_why() {
        let (on_problem, _) = problems();
        let missing = r"Software\puddle-test-no-such-internet-settings-key";
        let Err(why) = RegistryWatch::start_at(missing, Arc::new(|| {}), &on_problem) else {
            panic!("a key that does not exist cannot be watched");
        };
        assert!(why.contains(missing) && why.contains("error 2"), "{why}");
    }

    #[test]
    fn no_working_part_gives_no_watch_and_every_part_that_failed_is_reported() {
        let (on_problem, seen) = problems();
        let none = assemble(
            Err("winhttp part failed".into()),
            Err("registry part failed".into()),
            &on_problem,
        );
        assert!(none.is_none());
        assert_eq!(
            *seen.lock().unwrap(),
            ["winhttp part failed", "registry part failed"]
        );
    }

    #[test]
    fn one_working_part_is_a_watch_and_the_other_is_still_reported() {
        let (on_problem, seen) = problems();
        let registry = RegistryWatch::start(Arc::new(|| {}), &on_problem)
            .expect("the Internet Settings key can be watched on every Windows");
        let guard = assemble(Err("winhttp part failed".into()), Ok(registry), &on_problem);
        assert!(guard.is_some());
        assert_eq!(*seen.lock().unwrap(), ["winhttp part failed"]);
    }
}
