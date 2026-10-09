// SPDX-License-Identifier: GPL-3.0-or-later
//! The command line: `puddle-agent` runs the agent, `puddle-agent --version` prints the version.
//! `puddle-agent merge-file ...` applies a merged guest file for the boot hook
//! ([`crate::merge_file`]). `puddle-agent connect <host> <port> [<name>]` is the ssh
//! `ProxyCommand` ([`crate::connect`]).

use crate::{connect, merge_file};

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the agent.
    Run,
    /// Print the version line.
    Version,
    /// Apply, remove or forget a merged guest file.
    MergeFile(merge_file::Request),
    /// Carry stdin and stdout to a destination through the proxy (the ssh `ProxyCommand`).
    Connect(connect::Request),
    /// Anything else: print this usage error, exit 2.
    Usage(String),
}

/// Usage text.
pub const USAGE: &str =
    "usage: puddle-agent [--version]  (settings come from PUDDLE_AGENT_* variables)";

/// Parses the arguments after the program name.
#[must_use]
pub fn parse<S: AsRef<str>>(args: &[S]) -> Command {
    match args {
        [] => Command::Run,
        [one] if matches!(one.as_ref(), "--version" | "-V") => Command::Version,
        [first, rest @ ..] if first.as_ref() == "connect" => {
            connect::Request::parse(rest).map_or_else(Command::Usage, Command::Connect)
        }
        [first, rest @ ..] if first.as_ref() == "merge-file" => {
            merge_file::Request::parse(rest).map_or_else(Command::Usage, Command::MergeFile)
        }
        [first, ..] => Command::Usage(format!(
            "unknown argument {:?}\n{USAGE}",
            first.as_ref().chars().take(64).collect::<String>()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_map_to_commands() {
        assert_eq!(parse::<&str>(&[]), Command::Run);
        assert_eq!(parse(&["--version"]), Command::Version);
        assert_eq!(parse(&["-V"]), Command::Version);
        assert!(matches!(
            parse(&["connect", "h", "22"]),
            Command::Connect(_)
        ));
        assert!(matches!(
            parse(&["connect", "h", "22", "alias"]),
            Command::Connect(_)
        ));
        for bad in [
            &["connect"][..],
            &["connect", "h"],
            &["connect", "h", "0"],
            &["connect", "h", "x"],
        ] {
            assert!(matches!(parse(bad), Command::Usage(_)), "{bad:?}");
        }
        let Command::Usage(msg) = parse(&["--help"]) else {
            panic!("not usage");
        };
        assert!(msg.contains("--help") && msg.contains(USAGE));
        assert!(matches!(parse(&["--version", "x"]), Command::Usage(_)));
        assert!(matches!(
            parse(&["merge-file", "forget", "/s", "/g"]),
            Command::MergeFile(_)
        ));
        assert!(matches!(parse(&["merge-file"]), Command::Usage(_)));
    }
}
