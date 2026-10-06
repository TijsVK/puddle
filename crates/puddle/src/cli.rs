// SPDX-License-Identifier: GPL-3.0-or-later
//! Command-line parsing for the host program, kept apart from `main` so it is unit-testable.

/// What the program should do, decided from its arguments.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Print the version line.
    Version,
    /// Print usage.
    Help,
    /// Relay stdio to a sandbox's SSH endpoint (`ProxyCommand`), see [`crate::cmd::ssh_bridge`].
    SshBridge {
        /// The sandbox's endpoint (named pipe or Unix socket path).
        endpoint: std::path::PathBuf,
    },
    /// Check this machine's prerequisites, see [`crate::cmd::doctor`].
    Doctor(crate::cmd::doctor::DoctorArgs),
}

/// Arguments that don't form a valid command.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// An argument puddle doesn't know.
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
    /// No command given.
    #[error("no command given")]
    Missing,
    /// A command lacks its argument; holds the usage of that command.
    #[error("missing argument: {0}")]
    MissingArgument(&'static str),
}

/// Usage text for `--help` and for usage errors.
pub const USAGE: &str =
    "usage: puddle [--version | --help | doctor [--json] [--no-boot] | ssh-bridge <endpoint>]";

/// Parse the arguments after the program name.
///
/// # Errors
///
/// [`UsageError`] when the arguments are empty or contain anything other than one known flag.
pub fn parse<I, S>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let command = match args.next() {
        None => return Err(UsageError::Missing),
        Some(arg) => match arg.as_ref() {
            "--version" | "-V" => Command::Version,
            "--help" | "-h" => Command::Help,
            "ssh-bridge" => return crate::cmd::ssh_bridge::parse(args),
            "doctor" => return crate::cmd::doctor::parse(args),
            other => return Err(UsageError::UnknownArgument(other.to_owned())),
        },
    };
    match args.next() {
        None => Ok(command),
        Some(extra) => Err(UsageError::UnknownArgument(extra.as_ref().to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flags() {
        assert_eq!(parse(["--version"]), Ok(Command::Version));
        assert_eq!(parse(["-V"]), Ok(Command::Version));
    }

    #[test]
    fn help_flags() {
        assert_eq!(parse(["--help"]), Ok(Command::Help));
        assert_eq!(parse(["-h"]), Ok(Command::Help));
    }

    #[test]
    fn no_arguments_is_an_error() {
        assert_eq!(parse(Vec::<String>::new()), Err(UsageError::Missing));
    }

    #[test]
    fn unknown_and_extra_arguments_are_errors() {
        assert_eq!(
            parse(["--bogus"]),
            Err(UsageError::UnknownArgument("--bogus".into()))
        );
        assert_eq!(
            parse(["--version", "extra"]),
            Err(UsageError::UnknownArgument("extra".into()))
        );
    }
}
