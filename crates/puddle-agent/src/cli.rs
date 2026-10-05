// SPDX-License-Identifier: GPL-3.0-or-later
//! The command line: `puddle-agent` runs the agent, `puddle-agent --version` prints the version.
//! `puddle-agent connect` is reserved for the ssh `ProxyCommand` (T-021, a `connect` stream).

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Run the agent.
    Run,
    /// Print the version line.
    Version,
    /// A subcommand that is reserved but not built yet.
    Reserved(&'static str),
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
        [first, ..] if first.as_ref() == "connect" => Command::Reserved("connect"),
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
        assert_eq!(parse(&["connect", "h", "22"]), Command::Reserved("connect"));
        let Command::Usage(msg) = parse(&["--help"]) else {
            panic!("not usage");
        };
        assert!(msg.contains("--help") && msg.contains(USAGE));
        assert!(matches!(parse(&["--version", "x"]), Command::Usage(_)));
    }
}
