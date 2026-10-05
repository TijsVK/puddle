// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest agent (`puddle-agent`): a static musl binary inside each sandbox that carries the guest's
//! traffic to puddle's proxy over vsock (ADR 0005). Placeholder: today it only prints its version.
#![forbid(unsafe_code)]

#[expect(
    clippy::print_stdout,
    reason = "a CLI's user-facing output goes to stdout, not to tracing"
)]
fn main() {
    println!("{}", puddle_types::version_line("puddle-agent"));
}
