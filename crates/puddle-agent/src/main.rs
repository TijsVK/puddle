// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle-agent`: see the library docs. This file only wires the command line, logging and the
//! runtime.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use puddle_agent::cli::{self, Command};
use puddle_agent::{Agent, Config};

#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI output and start-up errors before logging is set up"
)]
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&args) {
        Command::Version => {
            println!("{}", puddle_types::version_line("puddle-agent"));
            ExitCode::SUCCESS
        }
        Command::Reserved(name) => {
            eprintln!("puddle-agent {name}: not available in this version");
            ExitCode::from(2)
        }
        Command::Usage(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
        Command::Run => {
            let config = match Config::from_lookup(|k| std::env::var(k).ok()) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("puddle-agent: {err}");
                    return ExitCode::from(2);
                }
            };
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_max_level(config.log)
                .init();
            match run(config) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    tracing::error!(error = %err, "puddle-agent stopped");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run(config: Config) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        Agent::start(config).await?.run().await;
        Ok(())
    })
}
