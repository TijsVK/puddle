// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle ssh-bridge <endpoint>`: the `ProxyCommand` that connects `ssh` (or VS Code) to a
//! sandbox's SSH endpoint. puddle's ssh config file (W6) names the endpoint; the relay rules are
//! in [`puddle_ssh::bridge`].

use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::{Command, UsageError};

/// Parses the arguments after `ssh-bridge`: exactly one endpoint path.
///
/// # Errors
///
/// [`UsageError::MissingArgument`] without one, [`UsageError::UnknownArgument`] for more.
pub fn parse<I, S>(mut args: I) -> Result<Command, UsageError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    let endpoint = args
        .next()
        .ok_or(UsageError::MissingArgument("ssh-bridge <endpoint>"))?;
    if let Some(extra) = args.next() {
        return Err(UsageError::UnknownArgument(extra.as_ref().to_owned()));
    }
    Ok(Command::SshBridge {
        endpoint: PathBuf::from(endpoint.as_ref()),
    })
}

/// Relays this process's stdin and stdout to `endpoint` until the session ends.
#[must_use]
#[expect(
    clippy::print_stderr,
    reason = "a ProxyCommand's only channel to the user is stderr, which ssh shows"
)]
pub fn run(endpoint: &Path) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("puddle: could not start the ssh bridge: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = rt.block_on(puddle_ssh::bridge::run(
        endpoint,
        tokio::io::stdin(),
        tokio::io::stdout(),
    ));
    // tokio reads stdin on a blocking thread that may sit in a read nobody will finish (ssh can
    // keep the pipe open): don't wait for it.
    rt.shutdown_background();
    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("puddle: {}", with_causes(&e));
            ExitCode::FAILURE
        }
    }
}

/// `e` followed by each of its sources, `: `-separated.
fn with_causes(e: &dyn Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        // Writing to a String can't fail.
        let _ignored = write!(text, ": {s}");
        source = s.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli;

    #[test]
    fn takes_exactly_one_endpoint() {
        assert_eq!(
            cli::parse(["ssh-bridge", r"\\.\pipe\puddle-0123"]),
            Ok(Command::SshBridge {
                endpoint: PathBuf::from(r"\\.\pipe\puddle-0123")
            })
        );
        assert_eq!(
            cli::parse(["ssh-bridge"]),
            Err(UsageError::MissingArgument("ssh-bridge <endpoint>"))
        );
        assert_eq!(
            cli::parse(["ssh-bridge", "a", "b"]),
            Err(UsageError::UnknownArgument("b".into()))
        );
    }

    #[test]
    fn causes_are_chained() {
        let io = std::io::Error::other("os said no");
        let err = puddle_ssh::bridge::BridgeError::ServerRead(io);
        assert_eq!(
            with_causes(&err),
            "the connection to the sandbox broke: os said no"
        );
    }
}
