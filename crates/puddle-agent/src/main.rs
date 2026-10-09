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
        Command::MergeFile(request) => {
            match puddle_agent::merge_file::run(&request, std::io::stdin().lock()) {
                Ok(outcome) => {
                    println!("{outcome}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("puddle-agent merge-file: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Connect(request) => connect(&request),
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

/// The ssh `ProxyCommand`: stdin and stdout are the ssh client's connection.
#[expect(
    clippy::print_stderr,
    reason = "CLI output before logging is set up; the refusal itself goes to stderr"
)]
fn connect(request: &puddle_agent::connect::Request) -> ExitCode {
    let ready = Config::from_lookup(|k| std::env::var(k).ok())
        .map_err(|err| err.to_string())
        .and_then(|config| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| err.to_string())?;
            Ok((
                puddle_agent::connect::Settings::from_config(&config),
                runtime,
            ))
        });
    let (settings, runtime) = match ready {
        Ok(ready) => ready,
        Err(err) => {
            eprintln!("puddle-agent connect: {err}");
            return ExitCode::from(puddle_agent::connect::Exit::Failed.code());
        }
    };
    let exit = runtime.block_on(puddle_agent::connect::run(
        &settings,
        request,
        tokio::io::stdin(),
        tokio::io::stdout(),
        &mut tokio::io::stderr(),
    ));
    // A read of stdin may still be waiting on its thread; don't wait for it.
    runtime.shutdown_background();
    ExitCode::from(exit.code())
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
