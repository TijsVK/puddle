// SPDX-License-Identifier: GPL-3.0-or-later
//! The front process: starts the worker with a hidden console, relays its output, and turns
//! console events into a shutdown request on the worker's stdin.

use std::io::Write as _;
use std::os::windows::process::CommandExt as _;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Condvar, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

use super::sys;
use crate::supervise::ROLE_VAR;
use crate::{LifecycleError, Role, ShutdownCause};

/// How long the handler of a deadline event (console close, logoff, shutdown) waits for the
/// worker before returning; Windows ends the front within about 5 s anyway.
const DEADLINE_WAIT: Duration = Duration::from_secs(10);

/// What the console handler needs: the worker's control pipe and whether it has exited.
struct Front {
    control: Mutex<Option<ChildStdin>>,
    exited: Mutex<bool>,
    exited_cv: Condvar,
}

static FRONT: OnceLock<Front> = OnceLock::new();

fn worker_error(op: &'static str) -> impl FnOnce(std::io::Error) -> LifecycleError {
    move |source| LifecycleError::Worker { op, source }
}

pub(crate) fn run() -> Result<Role, LifecycleError> {
    crate::job::contain_this_process()?;
    let exe = std::env::current_exe().map_err(worker_error("find own executable"))?;
    let mut child = Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(ROLE_VAR, "worker")
        // A console of its own that has no window: no keypress or window close reaches the
        // worker or the VMs it starts.
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(worker_error("start"))?;
    let relays = [
        child.stdout.take().map(|mut out| {
            std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::stdout()))
        }),
        child.stderr.take().map(|mut err| {
            std::thread::spawn(move || std::io::copy(&mut err, &mut std::io::stderr()))
        }),
    ];
    let front = FRONT.get_or_init(|| Front {
        control: Mutex::new(None),
        exited: Mutex::new(false),
        exited_cv: Condvar::new(),
    });
    *front.control.lock().unwrap_or_else(PoisonError::into_inner) = child.stdin.take();
    sys::install_console_handler().map_err(worker_error("install console handler"))?;
    tracing::debug!(worker = child.id(), "front: worker started");

    let status = child.wait().map_err(worker_error("wait"));
    *front.exited.lock().unwrap_or_else(PoisonError::into_inner) = true;
    front.exited_cv.notify_all();
    for relay in relays.into_iter().flatten() {
        // The relay ends at the worker's EOF; a failed write to our own console is not worth
        // failing the exit for.
        let _ = relay.join();
    }
    let status = status?;
    Ok(Role::Front {
        exit_code: status.code().unwrap_or(1),
    })
}

/// Maps a console control event to a shutdown cause.
fn cause(ctrl_type: u32) -> Option<ShutdownCause> {
    match ctrl_type {
        CTRL_C_EVENT => Some(ShutdownCause::Interrupt),
        CTRL_BREAK_EVENT => Some(ShutdownCause::Break),
        CTRL_CLOSE_EVENT => Some(ShutdownCause::ConsoleClose),
        CTRL_LOGOFF_EVENT => Some(ShutdownCause::Logoff),
        CTRL_SHUTDOWN_EVENT => Some(ShutdownCause::SystemShutdown),
        _ => None,
    }
}

/// The console handler's work (on a thread Windows creates for it). Returns whether the event
/// was handled; `false` lets the default handler end the front.
pub(crate) fn on_console_event(ctrl_type: u32) -> bool {
    tracing::info!(ctrl_type, "front: console event");
    let (Some(cause), Some(front)) = (cause(ctrl_type), FRONT.get()) else {
        return false;
    };
    if cause.is_deadline() {
        // Windows ends the front shortly whatever it does; without kill-on-close the worker
        // outlives it and finishes stopping the VMs.
        if let Err(e) = crate::job::release_kill_on_close() {
            tracing::warn!(error = %e, "front: kill-on-close stays; VMs may not stop cleanly");
        }
    }
    let control = front
        .control
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(mut control) = control {
        // Closing the pipe right after is the request too, so a failed write changes nothing.
        let _ = writeln!(control, "{cause}");
        drop(control);
        tracing::info!(%cause, "front: shutdown requested");
    }
    if cause.is_deadline() {
        let exited = front.exited.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = front
            .exited_cv
            .wait_timeout_while(exited, DEADLINE_WAIT, |exited| !*exited);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_console_event_is_a_shutdown_cause() {
        assert_eq!(cause(CTRL_C_EVENT), Some(ShutdownCause::Interrupt));
        assert_eq!(cause(CTRL_BREAK_EVENT), Some(ShutdownCause::Break));
        assert_eq!(cause(CTRL_CLOSE_EVENT), Some(ShutdownCause::ConsoleClose));
        assert_eq!(cause(CTRL_LOGOFF_EVENT), Some(ShutdownCause::Logoff));
        assert_eq!(
            cause(CTRL_SHUTDOWN_EVENT),
            Some(ShutdownCause::SystemShutdown)
        );
        assert_eq!(cause(99), None);
    }

    #[test]
    fn without_a_front_events_go_to_the_default_handler() {
        assert!(!on_console_event(CTRL_C_EVENT));
    }
}
