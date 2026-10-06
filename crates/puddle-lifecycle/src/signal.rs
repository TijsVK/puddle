// SPDX-License-Identifier: GPL-3.0-or-later
//! What tells puddle to shut down.

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

/// Why puddle is shutting down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShutdownCause {
    /// Ctrl-C, or `SIGINT`.
    Interrupt,
    /// Ctrl-Break.
    Break,
    /// `SIGTERM`.
    Terminate,
    /// `SIGHUP` (the terminal went away).
    Hangup,
    /// The console window was closed. Windows ends the front process about 5 s later; the worker
    /// finishes the shutdown on its own (see [`crate::supervise`]).
    ConsoleClose,
    /// The user is logging off.
    Logoff,
    /// The system is shutting down.
    SystemShutdown,
    /// The worker's control pipe closed without a request: the front process is gone.
    FrontGone,
}

impl ShutdownCause {
    const ALL: [Self; 8] = [
        Self::Interrupt,
        Self::Break,
        Self::Terminate,
        Self::Hangup,
        Self::ConsoleClose,
        Self::Logoff,
        Self::SystemShutdown,
        Self::FrontGone,
    ];

    /// A short name for logs and the front-to-worker control line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Break => "break",
            Self::Terminate => "terminate",
            Self::Hangup => "hangup",
            Self::ConsoleClose => "console-close",
            Self::Logoff => "logoff",
            Self::SystemShutdown => "system-shutdown",
            Self::FrontGone => "front-gone",
        }
    }

    /// Whether Windows ends the process shortly after this event, whatever it does: the
    /// shutdown has seconds, not minutes.
    #[must_use]
    pub fn is_deadline(self) -> bool {
        matches!(
            self,
            Self::ConsoleClose | Self::Logoff | Self::SystemShutdown
        )
    }

    fn parse(line: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == line)
    }
}

impl std::fmt::Display for ShutdownCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The front's request on the worker's control pipe: one line naming the cause. EOF, an unknown
/// line or a read error all mean the front is gone, which is also a reason to shut down.
#[cfg_attr(
    all(not(windows), not(test)),
    expect(dead_code, reason = "the worker reads it on Windows only")
)]
pub(crate) async fn read_request<R: AsyncRead + Unpin>(control: R) -> ShutdownCause {
    let mut line = String::new();
    match BufReader::new(control).read_line(&mut line).await {
        Ok(n) if n > 0 => ShutdownCause::parse(line.trim_end()).unwrap_or(ShutdownCause::FrontGone),
        _ => ShutdownCause::FrontGone,
    }
}

/// The shutdown triggers, installed. Install them early (a `SIGTERM` that arrives before
/// installation ends the process the default way), inside a tokio runtime.
///
/// - Windows worker (under [`crate::supervise`]): the front's request on stdin, or the front
///   going away.
/// - Windows otherwise: Ctrl-C, Ctrl-Break, console close, logoff, system shutdown. A console
///   close leaves this process about 5 s, and VMs sharing its console get the event too; use
///   [`crate::supervise`].
/// - Unix: `SIGINT`, `SIGTERM`, `SIGHUP`.
#[derive(Debug)]
pub struct ShutdownSignals(imp::Signals);

impl ShutdownSignals {
    /// Installs the handlers.
    ///
    /// # Errors
    ///
    /// When a signal handler can't be installed.
    pub fn install() -> std::io::Result<Self> {
        imp::Signals::install().map(Self)
    }

    /// Resolves at the first trigger.
    pub async fn recv(&mut self) -> ShutdownCause {
        self.0.recv().await
    }
}

/// [`ShutdownSignals::install`], then [`ShutdownSignals::recv`].
///
/// # Errors
///
/// When a signal handler can't be installed.
pub async fn wait_for_shutdown() -> std::io::Result<ShutdownCause> {
    Ok(ShutdownSignals::install()?.recv().await)
}

#[cfg(unix)]
mod imp {
    use tokio::signal::unix::{Signal, SignalKind, signal};

    use super::ShutdownCause;

    #[derive(Debug)]
    pub(super) struct Signals {
        int: Signal,
        term: Signal,
        hup: Signal,
    }

    impl Signals {
        pub(super) fn install() -> std::io::Result<Self> {
            Ok(Self {
                int: signal(SignalKind::interrupt())?,
                term: signal(SignalKind::terminate())?,
                hup: signal(SignalKind::hangup())?,
            })
        }

        pub(super) async fn recv(&mut self) -> ShutdownCause {
            tokio::select! {
                _ = self.int.recv() => ShutdownCause::Interrupt,
                _ = self.term.recv() => ShutdownCause::Terminate,
                _ = self.hup.recv() => ShutdownCause::Hangup,
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use tokio::signal::windows::{
        CtrlBreak, CtrlC, CtrlClose, CtrlLogoff, CtrlShutdown, ctrl_break, ctrl_c, ctrl_close,
        ctrl_logoff, ctrl_shutdown,
    };

    use super::{ShutdownCause, read_request};

    #[derive(Debug)]
    pub(super) enum Signals {
        /// Under the front: its request arrives on stdin.
        Worker(Option<tokio::io::Stdin>),
        Console {
            c: CtrlC,
            brk: CtrlBreak,
            close: CtrlClose,
            logoff: CtrlLogoff,
            shutdown: CtrlShutdown,
        },
    }

    impl Signals {
        pub(super) fn install() -> std::io::Result<Self> {
            if crate::supervise::is_worker() {
                return Ok(Self::Worker(Some(tokio::io::stdin())));
            }
            Ok(Self::Console {
                c: ctrl_c()?,
                brk: ctrl_break()?,
                close: ctrl_close()?,
                logoff: ctrl_logoff()?,
                shutdown: ctrl_shutdown()?,
            })
        }

        pub(super) async fn recv(&mut self) -> ShutdownCause {
            match self {
                Self::Worker(stdin) => match stdin.take() {
                    Some(stdin) => read_request(stdin).await,
                    // The pipe was read to its end by an earlier call.
                    None => ShutdownCause::FrontGone,
                },
                Self::Console {
                    c,
                    brk,
                    close,
                    logoff,
                    shutdown,
                } => tokio::select! {
                    _ = c.recv() => ShutdownCause::Interrupt,
                    _ = brk.recv() => ShutdownCause::Break,
                    _ = close.recv() => ShutdownCause::ConsoleClose,
                    _ = logoff.recv() => ShutdownCause::Logoff,
                    _ = shutdown.recv() => ShutdownCause::SystemShutdown,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_line_names_the_cause() {
        for cause in ShutdownCause::ALL {
            let line = format!("{cause}\n");
            assert_eq!(read_request(line.as_bytes()).await, cause);
        }
        assert_eq!(
            read_request(&b"console-close"[..]).await,
            ShutdownCause::ConsoleClose,
            "no newline needed"
        );
    }

    #[tokio::test]
    async fn eof_or_garbage_means_the_front_is_gone() {
        assert_eq!(read_request(&b""[..]).await, ShutdownCause::FrontGone);
        assert_eq!(
            read_request(&b"reboot\n"[..]).await,
            ShutdownCause::FrontGone
        );
        assert_eq!(
            read_request(&b"\xff\xfe\n"[..]).await,
            ShutdownCause::FrontGone
        );
    }

    #[test]
    fn only_window_close_logoff_and_system_shutdown_have_a_deadline() {
        let deadline: Vec<_> = ShutdownCause::ALL
            .into_iter()
            .filter(|c| c.is_deadline())
            .collect();
        assert_eq!(
            deadline,
            [
                ShutdownCause::ConsoleClose,
                ShutdownCause::Logoff,
                ShutdownCause::SystemShutdown
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_is_a_terminate_request() {
        let mut signals = ShutdownSignals::install().unwrap();
        let pid = std::process::id().to_string();
        let status = std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap();
        assert!(status.success());
        let cause = tokio::time::timeout(std::time::Duration::from_secs(5), signals.recv())
            .await
            .unwrap();
        assert_eq!(cause, ShutdownCause::Terminate);
    }
}
