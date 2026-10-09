// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle serve [--port <n>] [--connection-file <path>]`: runs the host process (store,
//! proxies, sandbox runtime, workspaces, API) until Ctrl-C, a termination signal or the end of
//! the console session, then stops every workspace cleanly.
//!
//! The work is in [`puddle_host`]; this file is the process around it: the Windows
//! front/worker split, logging, the order "prepare before the first thread", and the exit code.

use std::path::PathBuf;
use std::process::ExitCode;

use puddle_host::{Host, HostConfig, HostOptions, MsbFactory, SystemPlatform, prepare};
use puddle_lifecycle::{Role, supervise, wait_for_shutdown};
use tracing_subscriber::filter::LevelFilter;

use crate::cli::{Command, UsageError};

/// The environment variable that overrides the guest agent's location (development builds).
pub const AGENT_VAR: &str = "PUDDLE_AGENT_BIN";

/// The environment variable that sets the log level (`error`..`trace`, default `info`).
pub const LOG_VAR: &str = "PUDDLE_LOG";

/// How `puddle serve` should run.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServeArgs {
    /// The API's port on 127.0.0.1 (a free one when absent).
    pub port: Option<u16>,
    /// Where to write the connection file instead of the data folder's `api.json`.
    pub connection_file: Option<PathBuf>,
}

/// Parses the arguments after `serve`.
///
/// # Errors
///
/// [`UsageError`] for an unknown or repeated option or a missing or invalid value.
pub fn parse<I, S>(args: I) -> Result<Command, UsageError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = ServeArgs::default();
    let mut args = args;
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "--port" if parsed.port.is_none() => {
                let value = args
                    .next()
                    .ok_or(UsageError::MissingArgument("--port <n>"))?;
                parsed.port = Some(
                    value
                        .as_ref()
                        .parse()
                        .map_err(|_| UsageError::UnknownArgument(value.as_ref().to_owned()))?,
                );
            }
            "--connection-file" if parsed.connection_file.is_none() => {
                let value = args
                    .next()
                    .ok_or(UsageError::MissingArgument("--connection-file <path>"))?;
                parsed.connection_file = Some(PathBuf::from(value.as_ref()));
            }
            other => return Err(UsageError::UnknownArgument(other.to_owned())),
        }
    }
    Ok(Command::Serve(parsed))
}

/// The host configuration for this machine and these arguments.
///
/// # Errors
///
/// [`puddle_host::HostError`] when the data folder or runtime folder cannot be found.
pub fn config(
    args: &ServeArgs,
    exe: &std::path::Path,
) -> Result<HostConfig, puddle_host::HostError> {
    let mut config = HostConfig::installed_for_user(exe)?;
    if let Some(agent) = std::env::var_os(AGENT_VAR) {
        config.guest = puddle_host::GuestSettings::new(agent);
    }
    if let Some(port) = args.port {
        config.api.port = port;
    }
    if let Some(file) = &args.connection_file {
        config.api.connection_file = Some(file.clone());
    }
    Ok(config)
}

fn log_level() -> LevelFilter {
    std::env::var(LOG_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(LevelFilter::INFO)
}

/// Runs the host. Exit code 0 after a clean stop, 1 when it could not start or a workspace did
/// not stop.
#[must_use]
#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a daemon's start-up line and fatal errors go to the console"
)]
pub fn run(args: &ServeArgs) -> ExitCode {
    // On Windows this is the front process, which only relays; the worker runs the host.
    match supervise() {
        Ok(Role::Front { exit_code }) => {
            return ExitCode::from(u8::try_from(exit_code).unwrap_or(1));
        }
        Ok(Role::Worker) => {}
        Err(e) => {
            eprintln!("puddle: {e}");
            return ExitCode::FAILURE;
        }
    }
    tracing_subscriber::fmt()
        .with_max_level(log_level())
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    // Everything up to the async runtime happens while this is the only thread.
    let prepared = match std::env::current_exe()
        .map_err(|e| puddle_host::HostError::DataDir(e.to_string()))
        .and_then(|exe| config(args, &exe))
        .and_then(|config| prepare(config, &SystemPlatform::new().with_dev_override_from_env()))
    {
        Ok(prepared) => prepared,
        Err(e) => {
            eprintln!("puddle: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("puddle: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let host = match Host::start(prepared, &MsbFactory, HostOptions::default()).await {
            Ok(host) => host,
            Err(e) => {
                eprintln!("puddle: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!("puddle is up at {}", host.url());
        match wait_for_shutdown().await {
            Ok(cause) => tracing::info!(cause = cause.as_str(), "shutting down"),
            Err(e) => tracing::error!(error = %e, "cannot wait for a shutdown request; stopping"),
        }
        exit_after(&host.shutdown().await.sandboxes)
    })
}

/// Prints what is wrong with the sandboxes at exit, and picks the exit code.
#[expect(
    clippy::print_stderr,
    reason = "the daemon's last words go to the console"
)]
fn exit_after(report: &puddle_lifecycle::ShutdownReport) -> ExitCode {
    for line in shutdown_lines(report) {
        eprintln!("{line}");
    }
    if report.all_stopped() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// What puddle tells the user at exit about sandboxes that did not stop or trim cleanly:
/// nothing when all did.
fn shutdown_lines(report: &puddle_lifecycle::ShutdownReport) -> Vec<String> {
    let mut lines: Vec<String> = report
        .untrimmed()
        .into_iter()
        .map(|(sandbox, why)| {
            format!(
                "puddle: the disk of {sandbox} was not trimmed: {why}; Reclaim space trims it later"
            )
        })
        .collect();
    let unstopped = report.unstopped();
    if !unstopped.is_empty() {
        lines.push("puddle: not every sandbox stopped cleanly:".to_owned());
        lines.extend(
            unstopped
                .into_iter()
                .map(|(sandbox, why)| format!("puddle:   {sandbox}: {why}")),
        );
        lines.push(
            "puddle: the machines end with puddle; check the workspace volumes if a tool was writing"
                .to_owned(),
        );
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_names_each_sandbox_that_did_not_stop_or_trim_cleanly_and_why() {
        use puddle_lifecycle::{ShutdownReport, StopOutcome, TrimOutcome, WorkspaceOutcome};
        let outcome = |name: &str, trim, stop| WorkspaceOutcome {
            sandbox: puddle_types::SandboxName::new(name).unwrap(),
            trim,
            stop,
        };
        let clean = ShutdownReport {
            sandboxes: vec![outcome("fine", TrimOutcome::Trimmed, StopOutcome::Stopped)],
        };
        assert_eq!(shutdown_lines(&clean).len(), 0);
        assert_eq!(
            format!("{:?}", exit_after(&clean)),
            format!("{:?}", ExitCode::SUCCESS)
        );
        let report = ShutdownReport {
            sandboxes: vec![
                outcome("fine", TrimOutcome::Trimmed, StopOutcome::Stopped),
                outcome(
                    "slow",
                    TrimOutcome::Error("no answer".to_owned()),
                    StopOutcome::Forced,
                ),
            ],
        };
        let lines = shutdown_lines(&report);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains("disk of slow was not trimmed: no answer"));
        assert!(lines[2].contains("slow: it did not shut down in time"));
        assert!(lines[3].contains("check the workspace volumes"));
        assert_eq!(
            format!("{:?}", exit_after(&report)),
            format!("{:?}", ExitCode::FAILURE)
        );
    }

    fn serve(args: &[&str]) -> Result<ServeArgs, UsageError> {
        match parse(args.iter()) {
            Ok(Command::Serve(a)) => Ok(a),
            Ok(other) => panic!("{other:?}"),
            Err(e) => Err(e),
        }
    }

    #[test]
    fn no_options_is_the_default() {
        assert_eq!(serve(&[]), Ok(ServeArgs::default()));
    }

    #[test]
    fn port_and_connection_file() {
        let a = serve(&["--port", "4000", "--connection-file", "/tmp/c.json"]).unwrap();
        assert_eq!(a.port, Some(4000));
        assert_eq!(a.connection_file, Some(PathBuf::from("/tmp/c.json")));
    }

    #[test]
    fn bad_input_is_a_usage_error() {
        assert!(serve(&["--port"]).is_err());
        assert!(serve(&["--port", "x"]).is_err());
        assert!(serve(&["--port", "70000"]).is_err());
        assert!(serve(&["--port", "1", "--port", "2"]).is_err());
        assert!(serve(&["--connection-file"]).is_err());
        assert!(serve(&["--wat"]).is_err());
    }

    #[test]
    fn the_arguments_reach_the_configuration() {
        let args = ServeArgs {
            port: Some(4123),
            connection_file: Some(PathBuf::from("/x/api.json")),
        };
        let exe = std::env::current_exe().unwrap();
        if let Ok(config) = config(&args, &exe) {
            assert_eq!(config.api.port, 4123);
            assert_eq!(
                config.api.connection_file,
                Some(PathBuf::from("/x/api.json"))
            );
        }
    }

    #[test]
    fn the_log_level_defaults_to_info() {
        // The variable is not set by the test environment; an invalid value would also give info.
        assert_eq!(log_level(), LevelFilter::INFO);
    }
}
