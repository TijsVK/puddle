// SPDX-License-Identifier: GPL-3.0-or-later
//! Running a command in a sandbox: [`ExecRequest`] in, [`ExecOutput`] out.

use std::borrow::Cow;
use std::time::Duration;

use puddle_types::{GuestEnv, GuestPath};

/// A command to run in a running sandbox, without a shell: `program` gets `args` as they are.
/// For shell syntax, run `sh` with `["-c", script]` (see [`ExecRequest::sh`]).
///
/// ```
/// use std::time::Duration;
/// use puddle_compute::ExecRequest;
/// let r = ExecRequest::sh("exit 3").as_user("root").with_timeout(Duration::from_secs(5));
/// assert_eq!(r.program, "sh");
/// assert_eq!(r.args, ["-c", "exit 3"]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// The program (looked up on the guest's `PATH` if it has no `/`).
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// Extra environment on top of the sandbox's create-time env.
    pub env: GuestEnv,
    /// Working directory; `None` = the image's.
    pub cwd: Option<GuestPath>,
    /// User to run as; `None` = the image's default user.
    pub user: Option<String>,
    /// Bytes fed to the command's stdin, which is then closed.
    pub stdin: Vec<u8>,
    /// How long the command may run. On expiry the runtime returns
    /// [`crate::ComputeError::ExecTimeout`].
    pub timeout: Duration,
}

impl ExecRequest {
    /// Default [`ExecRequest::timeout`]: 5 minutes.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

    /// `program` with `args`, default timeout, nothing else set.
    #[must_use]
    pub fn new<I, S>(program: impl Into<String>, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: GuestEnv::new(),
            cwd: None,
            user: None,
            stdin: Vec::new(),
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    /// `sh -c <script>`.
    #[must_use]
    pub fn sh(script: impl Into<String>) -> Self {
        Self::new("sh", ["-c".to_owned(), script.into()])
    }

    /// Runs as `user`.
    #[must_use]
    pub fn as_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Adds environment variables.
    #[must_use]
    pub fn with_env(mut self, env: &GuestEnv) -> Self {
        self.env.extend(env);
        self
    }

    /// Sets the working directory.
    #[must_use]
    pub fn in_dir(mut self, cwd: GuestPath) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Feeds `stdin` to the command.
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = stdin.into();
        self
    }

    /// Sets the timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// How a command ended. msb reports a command killed by a signal as code `-1` (T-028; the CLI
/// says 0, the SDK doesn't), so a signal is always a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExitStatus {
    /// The exit code, or [`ExitStatus::SIGNALLED`] for a signal.
    pub code: i32,
}

impl ExitStatus {
    /// The code msb reports for a command killed by a signal.
    pub const SIGNALLED: i32 = -1;

    /// Exit code `code`.
    #[must_use]
    pub const fn code(code: i32) -> Self {
        Self { code }
    }

    /// A command killed by a signal.
    #[must_use]
    pub const fn signalled() -> Self {
        Self {
            code: Self::SIGNALLED,
        }
    }

    /// Whether the command exited with 0.
    #[must_use]
    pub const fn success(self) -> bool {
        self.code == 0
    }
}

/// A finished command: exit status and captured output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// How it ended.
    pub status: ExitStatus,
    /// Everything it wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything it wrote to stderr.
    pub stderr: Vec<u8>,
}

impl ExecOutput {
    /// An output with `code` and the given streams.
    #[must_use]
    pub fn new(code: i32, stdout: impl Into<Vec<u8>>, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            status: ExitStatus::code(code),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// stdout as text (invalid UTF-8 replaced).
    #[must_use]
    pub fn stdout_text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// stderr as text (invalid UTF-8 replaced).
    #[must_use]
    pub fn stderr_text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builders() {
        let mut env = GuestEnv::new();
        env.set("A", "1").unwrap();
        let r = ExecRequest::new("printenv", ["A"])
            .with_env(&env)
            .in_dir(GuestPath::new("/tmp").unwrap())
            .with_stdin(b"in".to_vec())
            .as_user("root");
        assert_eq!(r.program, "printenv");
        assert_eq!(r.args, ["A"]);
        assert_eq!(r.env.get("A"), Some("1"));
        assert_eq!(r.cwd.as_ref().map(GuestPath::as_str), Some("/tmp"));
        assert_eq!(r.stdin, b"in");
        assert_eq!(r.user.as_deref(), Some("root"));
        assert_eq!(r.timeout, ExecRequest::DEFAULT_TIMEOUT);
        assert_eq!(
            r.with_timeout(Duration::from_secs(1)).timeout,
            Duration::from_secs(1)
        );
    }

    #[test]
    fn exit_status_success_and_signal() {
        assert!(ExitStatus::code(0).success());
        assert!(!ExitStatus::code(3).success());
        assert!(!ExitStatus::signalled().success());
        assert_eq!(ExitStatus::signalled().code, -1);
    }

    #[test]
    fn output_text_is_lossy() {
        let o = ExecOutput::new(0, b"ok\xff".to_vec(), b"err".to_vec());
        assert_eq!(o.stdout_text(), "ok\u{fffd}");
        assert_eq!(o.stderr_text(), "err");
        assert!(o.status.success());
    }
}
