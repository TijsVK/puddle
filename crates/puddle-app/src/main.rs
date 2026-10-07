// SPDX-License-Identifier: GPL-3.0-or-later
//! The `puddle-app` program: all logic is in the library.
#![forbid(unsafe_code)]
// No console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::ExitCode;

#[expect(
    clippy::print_stderr,
    reason = "the process is ending: this is the one place a start-up failure can be reported"
)]
fn main() -> ExitCode {
    match puddle_app::run(&puddle_app::Options::from_env()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("puddle-app: {err}");
            ExitCode::FAILURE
        }
    }
}
