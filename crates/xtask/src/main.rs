// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask`: see the library docs.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match xtask::run(std::env::args_os().skip(1)) {
        Ok(message) => {
            #[expect(clippy::print_stdout, reason = "a command-line tool reports on stdout")]
            {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            #[expect(
                clippy::print_stderr,
                reason = "a command-line tool reports errors on stderr"
            )]
            {
                eprintln!("xtask: {err}");
            }
            ExitCode::FAILURE
        }
    }
}
