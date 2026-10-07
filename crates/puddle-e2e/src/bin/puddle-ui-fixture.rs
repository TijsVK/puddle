// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle-ui-fixture`: the real API on fake services, for UI development and end-to-end tests.
//! See `puddle_e2e::ui_fixture` and `puddle-ui-fixture --help`.
#![expect(
    clippy::print_stderr,
    reason = "a command line tool: it reports its error on stderr"
)]

use std::process::ExitCode;

use puddle_e2e::ui_fixture::cli;

#[tokio::main]
async fn main() -> ExitCode {
    match cli::run(std::env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("puddle-ui-fixture: {message}");
            ExitCode::from(2)
        }
    }
}
