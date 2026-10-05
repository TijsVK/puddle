// SPDX-License-Identifier: GPL-3.0-or-later
//! The fake's command interpreter: a handful of built-in commands over an in-memory file
//! system, plus test-supplied handlers.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use puddle_types::{GuestEnv, GuestPath, SandboxName};

use crate::{ComputeError, ExecOutput, ExecRequest, ExitStatus, SandboxSpec};

/// Files by path: a sandbox's root disk and owned disks (keyed by absolute guest path), or a
/// volume's contents (keyed by path relative to the volume root).
pub(super) type Files = BTreeMap<String, Vec<u8>>;

/// Why a fake file operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsError {
    /// No such file.
    NotFound,
    /// The path is on a read-only mount (`EROFS`).
    ReadOnly,
    /// Reading a mounted host file failed.
    Host(String),
}

/// A test-supplied command implementation. Return `None` to fall through to the next handler
/// and finally to the built-ins.
///
/// Handlers run while the fake's state is locked: they must not call back into the
/// [`super::FakeRuntime`].
pub trait ExecHandler: Send + Sync + 'static {
    /// Runs `request`, or returns `None` if this handler doesn't know it.
    fn handle(&self, ctx: &mut ExecContext<'_>, request: &ExecRequest) -> Option<ExecOutput>;
}

impl<F> ExecHandler for F
where
    F: Fn(&mut ExecContext<'_>, &ExecRequest) -> Option<ExecOutput> + Send + Sync + 'static,
{
    fn handle(&self, ctx: &mut ExecContext<'_>, request: &ExecRequest) -> Option<ExecOutput> {
        self(ctx, request)
    }
}

/// What a command sees: its sandbox, its environment and the sandbox's files.
pub struct ExecContext<'a> {
    pub(super) sandbox: &'a SandboxName,
    pub(super) env: GuestEnv,
    pub(super) spec: &'a SandboxSpec,
    pub(super) root: &'a mut Files,
    pub(super) volumes: &'a mut BTreeMap<String, super::VolumeRecord>,
}

/// Where a guest path lives.
enum Location<'p> {
    /// A read-only host file mount.
    HostFile(&'p Path),
    /// Inside a named volume, at this relative path (`""` = the mount point).
    Volume(&'p str, String),
    /// The root disk or an owned disk.
    Root,
    /// Below a file mount: nothing can exist there.
    Nowhere,
}

impl ExecContext<'_> {
    /// The sandbox the command runs in.
    #[must_use]
    pub fn sandbox(&self) -> &SandboxName {
        self.sandbox
    }

    /// The command's environment: the sandbox's create-time env plus the request's.
    #[must_use]
    pub fn env(&self) -> &GuestEnv {
        &self.env
    }

    fn locate<'p>(spec: &'p SandboxSpec, path: &GuestPath) -> Location<'p> {
        for m in &spec.file_mounts {
            if path == &m.guest {
                return Location::HostFile(&m.host);
            }
            if path.is_within(&m.guest) {
                return Location::Nowhere;
            }
        }
        for m in &spec.volumes {
            if let Some(rel) = path.relative_to(&m.guest) {
                return Location::Volume(m.volume.as_str(), rel.to_owned());
            }
        }
        Location::Root
    }

    /// Reads a file.
    ///
    /// # Errors
    ///
    /// [`FsError::NotFound`]; [`FsError::Host`] when a mounted host file can't be read.
    pub fn read(&self, path: &GuestPath) -> Result<Vec<u8>, FsError> {
        match Self::locate(self.spec, path) {
            // A blocking read in async code: acceptable in the test fake, files are tiny.
            Location::HostFile(host) => std::fs::read(host).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    FsError::NotFound
                } else {
                    FsError::Host(e.to_string())
                }
            }),
            Location::Volume(vol, rel) => self
                .volumes
                .get(vol)
                .and_then(|v| v.files.get(&rel))
                .cloned()
                .ok_or(FsError::NotFound),
            Location::Root => self
                .root
                .get(path.as_str())
                .cloned()
                .ok_or(FsError::NotFound),
            Location::Nowhere => Err(FsError::NotFound),
        }
    }

    /// Writes (creates or replaces) a file.
    ///
    /// # Errors
    ///
    /// [`FsError::ReadOnly`] on a file mount; [`FsError::NotFound`] below a file mount, at a
    /// volume's mount point, or in a volume that no longer exists.
    pub fn write(&mut self, path: &GuestPath, data: Vec<u8>) -> Result<(), FsError> {
        match Self::locate(self.spec, path) {
            Location::HostFile(_) => Err(FsError::ReadOnly),
            Location::Volume(_, rel) if rel.is_empty() => Err(FsError::NotFound),
            Location::Volume(vol, rel) => {
                let v = self.volumes.get_mut(vol).ok_or(FsError::NotFound)?;
                v.files.insert(rel, data);
                Ok(())
            }
            Location::Root => {
                self.root.insert(path.as_str().to_owned(), data);
                Ok(())
            }
            Location::Nowhere => Err(FsError::NotFound),
        }
    }

    /// Whether a file or directory exists (directories exist implicitly when a file lies below
    /// them, and mount points always exist).
    #[must_use]
    pub fn exists(&self, path: &GuestPath) -> bool {
        let below = |files: &Files, prefix: &str| {
            files.contains_key(prefix)
                || files.keys().any(|k| {
                    k.strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/') || prefix.is_empty())
                })
        };
        match Self::locate(self.spec, path) {
            Location::HostFile(host) => host.exists(),
            Location::Volume(_, rel) if rel.is_empty() => true,
            Location::Volume(vol, rel) => {
                self.volumes.get(vol).is_some_and(|v| below(&v.files, &rel))
            }
            Location::Root => {
                path.as_str() == "/"
                    || below(self.root, path.as_str())
                    || self
                        .spec
                        .owned_disks
                        .iter()
                        .any(|d| d.guest.is_within(path))
                    || self.spec.volumes.iter().any(|m| m.guest.is_within(path))
                    || self
                        .spec
                        .file_mounts
                        .iter()
                        .any(|m| m.guest.is_within(path))
            }
            Location::Nowhere => false,
        }
    }
}

fn out(code: i32, stdout: impl Into<Vec<u8>>, stderr: impl Into<Vec<u8>>) -> ExecOutput {
    ExecOutput::new(code, stdout, stderr)
}

fn not_found(program: &str) -> ExecOutput {
    out(127, Vec::new(), format!("sh: 1: {program}: not found\n"))
}

/// Runs `request` with the built-in commands:
///
/// | Command | Behaviour |
/// |---|---|
/// | `true`, `false` | exit 0 / 1 |
/// | `sh -c <script>` (also `bash`) | `exit N`; `kill -9 $$` (signal ⇒ [`ExitStatus::signalled`]); otherwise the script is split on whitespace and run as one built-in command (no quoting, pipes or `;`) |
/// | `echo args…` | prints the args |
/// | `printenv [NAME]` | prints one variable (exit 1 if unset) or all |
/// | `cat [PATH…]` | prints files, or stdin without arguments |
/// | `tee PATH` | writes stdin to PATH and echoes it; `EROFS` on a file mount |
/// | `test -e/-f PATH` | exit 0 if it exists |
/// | `sleep SECS` | takes no real time; fails with [`ComputeError::ExecTimeout`] if SECS exceeds the request's timeout |
///
/// Anything else exits 127 like `sh` does for an unknown command.
pub(super) fn builtin(
    ctx: &mut ExecContext<'_>,
    request: &ExecRequest,
) -> Result<ExecOutput, ComputeError> {
    let program = request
        .program
        .rsplit('/')
        .next()
        .unwrap_or(&request.program);
    let args: Vec<&str> = request.args.iter().map(String::as_str).collect();
    run(ctx, request, program, &args)
}

fn run(
    ctx: &mut ExecContext<'_>,
    request: &ExecRequest,
    program: &str,
    args: &[&str],
) -> Result<ExecOutput, ComputeError> {
    Ok(match (program, args) {
        ("true", _) => out(0, "", ""),
        ("false", _) => out(1, "", ""),
        ("sh" | "bash", ["-c", script, ..]) => return shell(ctx, request, script),
        ("echo", words) => out(0, format!("{}\n", words.join(" ")), ""),
        ("printenv", []) => {
            let mut all = String::new();
            for (k, v) in ctx.env.iter() {
                // Writing to a String can't fail.
                let _ = writeln!(all, "{k}={v}");
            }
            out(0, all, "")
        }
        ("printenv", [name, ..]) => match ctx.env.get(name) {
            Some(v) => out(0, format!("{v}\n"), ""),
            None => out(1, "", ""),
        },
        ("cat", []) => out(0, request.stdin.clone(), ""),
        ("cat", paths) => cat(ctx, paths),
        ("tee", [path]) => tee(ctx, request, path),
        ("test", ["-e" | "-f", path]) => {
            let found = GuestPath::new(path).is_ok_and(|p| ctx.exists(&p));
            out(i32::from(!found), "", "")
        }
        ("sleep", [secs]) => return sleep(ctx, request, secs),
        _ => not_found(program),
    })
}

fn shell(
    ctx: &mut ExecContext<'_>,
    request: &ExecRequest,
    script: &str,
) -> Result<ExecOutput, ComputeError> {
    let words: Vec<&str> = script.split_whitespace().collect();
    Ok(match words.as_slice() {
        [] | ["exit"] => out(0, "", ""),
        ["exit", code] => out(code.parse().unwrap_or(2), "", ""),
        ["kill", "-9" | "-KILL", "$$"] => ExecOutput {
            status: ExitStatus::signalled(),
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
        [program, args @ ..] => return run(ctx, request, program, args),
    })
}

fn cat(ctx: &ExecContext<'_>, paths: &[&str]) -> ExecOutput {
    let mut stdout = Vec::new();
    let mut stderr = String::new();
    for path in paths {
        match GuestPath::new(path).map(|p| ctx.read(&p)) {
            Ok(Ok(data)) => stdout.extend(data),
            // Writing to a String can't fail.
            Ok(Err(FsError::Host(e))) => {
                let _ = writeln!(stderr, "cat: {path}: {e}");
            }
            _ => {
                let _ = writeln!(stderr, "cat: {path}: No such file or directory");
            }
        }
    }
    let code = i32::from(!stderr.is_empty());
    out(code, stdout, stderr)
}

fn tee(ctx: &mut ExecContext<'_>, request: &ExecRequest, path: &str) -> ExecOutput {
    let Ok(p) = GuestPath::new(path) else {
        return out(1, "", format!("tee: {path}: No such file or directory\n"));
    };
    match ctx.write(&p, request.stdin.clone()) {
        Ok(()) => out(0, request.stdin.clone(), ""),
        Err(FsError::ReadOnly) => out(
            1,
            request.stdin.clone(),
            format!("tee: {path}: Read-only file system\n"),
        ),
        Err(_) => out(
            1,
            request.stdin.clone(),
            format!("tee: {path}: No such file or directory\n"),
        ),
    }
}

fn sleep(
    ctx: &ExecContext<'_>,
    request: &ExecRequest,
    secs: &str,
) -> Result<ExecOutput, ComputeError> {
    let Some(wanted) = secs
        .parse::<f64>()
        .ok()
        .and_then(|s| Duration::try_from_secs_f64(s).ok())
    else {
        return Ok(out(
            1,
            "",
            format!("sleep: invalid time interval '{secs}'\n"),
        ));
    };
    if wanted > request.timeout {
        return Err(ComputeError::ExecTimeout {
            sandbox: ctx.sandbox.to_string(),
            program: request.program.clone(),
            timeout: request.timeout,
        });
    }
    Ok(out(0, "", ""))
}
